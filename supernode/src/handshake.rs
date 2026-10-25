// SPDX-License-Identifier: MIT
//! Portable bookkeeping shared by the production handshake path and tests.

use crate::ip::{IpManager, IpReservation};
use std::{collections::HashMap, net::SocketAddr};
use vault_core::{Buffer, CryptoCore, HandshakeRequest, PeerId, Time, TimeSource, protocol};

use crate::limiter::MAX_TRACKED_ENTRIES;

// Store confirmation time, not the client's clock. This exceeds the full
// 240s validity span of a request accepted at the clock-skew boundary.
const REPLAY_RETENTION_SECS: Time = 600;

/// ring may overwrite ciphertext even when authentication fails. Preserve it
/// only when another (pending) session key may need to try the same packet.
pub fn decrypt_preserving_packet(
    crypto: &CryptoCore,
    buffer: &mut Buffer,
    packet_type: u8,
) -> anyhow::Result<()> {
    let ciphertext = buffer.as_ref().to_vec();
    match crypto.decrypt(buffer, packet_type) {
        Ok(()) => Ok(()),
        Err(error) => {
            buffer.message_mut().copy_from_slice(&ciphertext);
            Err(error)
        }
    }
}

/// Owns only this attempt's temporary resources until authenticated commit.
pub struct PendingHandshake {
    pub id: PeerId,
    pub crypto: CryptoCore,
    pub reservation: IpReservation,
    pub created: Time,
    pub device_name: String,
    pub platform: String,
    pub failed_decrypts: u8,
    request_key: [u8; 32],
    timestamp: Time,
    authenticated: bool,
}

impl PendingHandshake {
    pub fn new(
        request: &HandshakeRequest,
        request_key: [u8; 32],
        crypto: CryptoCore,
        reservation: IpReservation,
        created: Time,
    ) -> Self {
        Self {
            id: request.id,
            crypto,
            reservation,
            created,
            device_name: request.device_name.clone(),
            platform: request.platform.clone(),
            failed_decrypts: 0,
            request_key,
            timestamp: request.timestamp,
            authenticated: false,
        }
    }

    pub fn authenticate(&mut self, buffer: &mut Buffer, packet_type: u8) -> anyhow::Result<()> {
        self.crypto.decrypt(buffer, packet_type)?;
        self.authenticated = true;
        Ok(())
    }

    pub fn commit<T: TimeSource>(
        &mut self,
        leases: &mut IpManager<T>,
        replay: &mut HandshakeReplay,
        now: Time,
    ) -> anyhow::Result<()> {
        anyhow::ensure!(self.authenticated, "handshake key not confirmed");
        // Recheck at promotion because a competing pending may have confirmed
        // since this INIT arrived. Neither state changes on rejection.
        replay.check(self.id, self.request_key, self.timestamp, now)?;
        leases.commit(&mut self.reservation)?;
        replay.confirm(self.id, self.request_key, self.timestamp, now)?;
        Ok(())
    }
}

/// Expiry alone does not prove a bad password: responses can be lost and
/// Happy-Eyeballs losers are deliberately abandoned. Reclaim resources without
/// charging a failure to every client sharing the source's NAT address.
pub fn expire_pending<T: TimeSource>(
    pending: &mut HashMap<SocketAddr, PendingHandshake>,
    leases: &mut IpManager<T>,
    cutoff: Time,
) {
    let expired: Vec<_> = pending
        .iter()
        .filter(|(_, attempt)| attempt.created < cutoff)
        .map(|(addr, _)| *addr)
        .collect();
    for addr in expired {
        if let Some(attempt) = pending.remove(&addr) {
            tracing::debug!(
                "Pending handshake from {addr} expired, reservation cancelled (no authentication failure charged)"
            );
            if let Err(error) = leases.cancel(attempt.reservation) {
                tracing::error!("Cancel expired IP reservation error: {error:#}");
            }
        }
    }
}

pub struct HandshakeReplay {
    confirmed: HashMap<(PeerId, [u8; 32]), Time>,
    limit: usize,
}

impl Default for HandshakeReplay {
    fn default() -> Self {
        Self {
            confirmed: HashMap::new(),
            limit: MAX_TRACKED_ENTRIES,
        }
    }
}

impl HandshakeReplay {
    pub fn check(
        &self,
        id: PeerId,
        key: [u8; 32],
        timestamp: Time,
        now: Time,
    ) -> anyhow::Result<()> {
        protocol::check_handshake_ts(timestamp, now)?;
        anyhow::ensure!(
            !self.confirmed.contains_key(&(id, key)),
            "replayed handshake"
        );
        // Fail closed: accepting new sessions without remembering them would
        // silently disable replay protection under load.
        anyhow::ensure!(
            self.confirmed.len() < self.limit,
            "handshake replay cache full"
        );
        Ok(())
    }

    /// Call only after decrypting the first client packet. Recheck here since
    /// other pending handshakes may have confirmed since the INIT arrived.
    pub fn confirm(
        &mut self,
        id: PeerId,
        key: [u8; 32],
        timestamp: Time,
        now: Time,
    ) -> anyhow::Result<()> {
        self.check(id, key, timestamp, now)?;
        self.confirmed.insert((id, key), now);
        Ok(())
    }

    pub fn sweep(&mut self, now: Time) {
        self.confirmed
            .retain(|_, confirmed| now.saturating_sub(*confirmed) <= REPLAY_RETENTION_SECS);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ip::{Ipv4Cidr, Ipv4Pool};
    use crate::mock_time::{MockTime, lock_clock};
    use std::io::Write;
    use vault_core::{AlgorithmType, Role, create_ecdh_keypair, pake};

    fn manager() -> IpManager<MockTime> {
        IpManager::new(
            Some(Ipv4Pool::new(Ipv4Cidr::from_str("10.0.0.0/24").unwrap())),
            None,
        )
        .unwrap()
    }

    fn attempt(
        leases: &mut IpManager<MockTime>,
        id: PeerId,
        password: &[u8],
        timestamp: Time,
    ) -> (PendingHandshake, Vec<u8>) {
        let (client_state, client_message) = pake::start_client(password, &id.0);
        let (server_state, server_message) = pake::start_server(b"correct", &id.0);
        let client_key = client_state.finish(&server_message).unwrap();
        let server_key = server_state.finish(&client_message).unwrap();
        let (client_private, client_public) = create_ecdh_keypair().unwrap();
        let (server_private, server_public) = create_ecdh_keypair().unwrap();
        let sender = CryptoCore::new(
            client_private,
            &AlgorithmType::Aes128Gcm,
            server_public.bytes(),
            Role::Initiator,
            &client_key,
        )
        .unwrap();
        let receiver = CryptoCore::new(
            server_private,
            &AlgorithmType::Aes128Gcm,
            client_public.bytes(),
            Role::Responder,
            &server_key,
        )
        .unwrap();
        let request = HandshakeRequest {
            id,
            pake_message: client_message,
            public_key_data: client_public.bytes().to_vec(),
            algorithms: Vec::new(),
            timestamp,
            version: vault_core::PROTOCOL_VERSION,
            device_name: "test".into(),
            platform: "test".into(),
        };
        let request_key = client_public.bytes().as_slice().try_into().unwrap();
        let pending = PendingHandshake::new(
            &request,
            request_key,
            receiver,
            leases.reserve(&id).unwrap(),
            1_000,
        );
        let mut packet = Buffer::new(vault_core::EXTRA_LEN + 1);
        packet.write_all(b"confirmation").unwrap();
        protocol::build_data_interface(&mut packet, &sender).unwrap();
        packet.take_prefix();
        (pending, packet.as_ref().to_vec())
    }

    fn authenticate(pending: &mut PendingHandshake, packet: &[u8]) -> anyhow::Result<()> {
        let mut buffer = Buffer::new(0);
        buffer.write_all(packet).unwrap();
        pending.authenticate(&mut buffer, protocol::DATA_INTERFACE)
    }

    #[test]
    fn abandoned_reconnect() {
        use crate::{limiter::InitLimiter, mock_time::advance};
        let _clock = lock_clock(1_000);
        let mut leases = manager();
        let mut pending = HashMap::new();
        let mut limiter = InitLimiter::<MockTime>::default();
        let mut replay = HandshakeReplay::default();
        let ip = "192.0.2.1".parse().unwrap();
        let id = PeerId([1; 16]);
        let mut first_address = None;
        // More abandoned attempts than the former per-IP ban threshold.
        // A live peer behind the same NAT must still be able to reconnect.
        for port in 10_000..10_020 {
            assert!(limiter.check_init_allowed(ip));
            let (mut attempt, _) = attempt(&mut leases, id, b"correct", MockTime::now());
            attempt.created = MockTime::now();
            first_address.get_or_insert(attempt.reservation.ipv4);
            assert_eq!(attempt.reservation.ipv4, first_address.unwrap());
            pending.insert(SocketAddr::new(ip, port), attempt);
            advance(16);
            expire_pending(&mut pending, &mut leases, MockTime::now() - 15);
            assert!(pending.is_empty());
        }
        assert!(limiter.check_init_allowed(ip));
        let (mut valid, packet) = attempt(&mut leases, id, b"correct", MockTime::now());
        authenticate(&mut valid, &packet).unwrap();
        valid
            .commit(&mut leases, &mut replay, MockTime::now())
            .unwrap();
        assert_eq!(valid.reservation.ipv4, first_address.unwrap());
    }

    #[test]
    fn reconnect_key_confirmation() {
        let _clock = lock_clock(1_000);
        let mut leases = manager();
        let mut replay = HandshakeReplay::default();
        let id = PeerId([1; 16]);
        let (mut established, old_packet) = attempt(&mut leases, id, b"correct", 1_000);
        authenticate(&mut established, &old_packet).unwrap();
        established.commit(&mut leases, &mut replay, 1_000).unwrap();
        let (mut pending, new_packet) = attempt(&mut leases, id, b"correct", 1_000);
        let mut buffer = Buffer::new(0);
        buffer.write_all(&new_packet).unwrap();
        assert!(
            decrypt_preserving_packet(&established.crypto, &mut buffer, protocol::DATA_INTERFACE)
                .is_err()
        );
        assert_eq!(buffer.as_ref(), new_packet);
        pending
            .authenticate(&mut buffer, protocol::DATA_INTERFACE)
            .unwrap();
        pending.commit(&mut leases, &mut replay, 1_000).unwrap();
        assert_eq!(buffer.as_ref(), b"confirmation");
        assert_eq!(pending.reservation.ipv4, established.reservation.ipv4);
    }

    #[test]
    fn failed_confirmation_keeps_peer() {
        let _clock = lock_clock(1_000);
        let mut leases = manager();
        let id = PeerId([1; 16]);
        let (established, old_packet) = attempt(&mut leases, id, b"correct", 1_000);
        let (mut pending, _) = attempt(&mut leases, id, b"wrong", 1_000);
        let mut replay = HandshakeReplay::default();
        let mut buffer = Buffer::new(0);
        buffer.write_all(b"invalid packet").unwrap();
        assert!(
            decrypt_preserving_packet(&established.crypto, &mut buffer, protocol::DATA_INTERFACE)
                .is_err()
        );
        assert!(
            pending
                .authenticate(&mut buffer, protocol::DATA_INTERFACE)
                .is_err()
        );
        assert!(pending.commit(&mut leases, &mut replay, 1_000).is_err());
        buffer.clear();
        buffer.write_all(&old_packet).unwrap();
        decrypt_preserving_packet(&established.crypto, &mut buffer, protocol::DATA_INTERFACE)
            .unwrap();
        assert_eq!(buffer.as_ref(), b"confirmation");
    }

    #[test]
    fn wrong_password_commits_nothing() {
        let _clock = lock_clock(1_000);
        let mut leases = manager();
        let mut replay = HandshakeReplay::default();
        let id = PeerId([1; 16]);
        let online = leases.assign(&id).unwrap();
        let (mut attacker, packet) = attempt(&mut leases, id, b"wrong", 1_120);
        assert_eq!((attacker.created, attacker.failed_decrypts), (1_000, 0));
        assert_eq!(
            (&*attacker.device_name, &*attacker.platform),
            ("test", "test")
        );
        assert!(attacker.commit(&mut leases, &mut replay, 1_000).is_err());
        assert!(authenticate(&mut attacker, &packet).is_err());
        assert!(attacker.commit(&mut leases, &mut replay, 1_000).is_err());
        leases.cancel(attacker.reservation).unwrap();
        assert_eq!(leases.assign(&id).unwrap(), online);
        assert_ne!(leases.assign(&PeerId([2; 16])).unwrap().0, online.0);
        let (mut legitimate, packet) = attempt(&mut leases, id, b"correct", 1_000);
        authenticate(&mut legitimate, &packet).unwrap();
        legitimate.commit(&mut leases, &mut replay, 1_000).unwrap();
        assert_eq!(
            (legitimate.reservation.ipv4, legitimate.reservation.ipv6),
            online
        );
        assert!(
            replay
                .check(id, legitimate.request_key, 1_000, 1_000)
                .is_err()
        );
    }

    #[test]
    fn competing_attempt_keeps_lease() {
        let _clock = lock_clock(1_000);
        let mut leases = manager();
        let mut replay = HandshakeReplay::default();
        let id = PeerId([1; 16]);
        let (mut loser, loser_packet) = attempt(&mut leases, id, b"correct", 1_000);
        let (mut winner, winner_packet) = attempt(&mut leases, id, b"correct", 1_000);
        authenticate(&mut winner, &winner_packet).unwrap();
        winner.commit(&mut leases, &mut replay, 1_000).unwrap();
        authenticate(&mut loser, &loser_packet).unwrap();
        assert!(loser.commit(&mut leases, &mut replay, 1_000).is_err());
        assert!(replay.check(id, loser.request_key, 1_000, 1_000).is_ok());
        leases.cancel(loser.reservation).unwrap();
        assert_eq!(leases.assign(&id).unwrap().0, winner.reservation.ipv4);
    }

    #[test]
    fn unconfirmed_requests_leave_no_state() {
        let mut replay = HandshakeReplay::default();
        let id = PeerId([1; 16]);
        replay.check(id, [1; 32], 1_120, 1_000).unwrap();
        // No confirmation, hence no permanent state change.
        replay.confirm(id, [2; 32], 1_000, 1_000).unwrap();
        replay.check(id, [3; 32], 1_000, 1_000).unwrap();
    }

    #[test]
    fn same_second_reconnect_no_key_replay() {
        let mut replay = HandshakeReplay::default();
        let id = PeerId([1; 16]);
        replay.confirm(id, [1; 32], 1_000, 1_000).unwrap();
        replay.confirm(id, [2; 32], 1_000, 1_000).unwrap();
        assert!(replay.check(id, [1; 32], 1_000, 1_000).is_err());
        // Editing the unauthenticated timestamp cannot revive a used key.
        assert!(replay.check(id, [1; 32], 1_010, 1_010).is_err());
    }

    #[test]
    fn dup_confirm_fails_closed() {
        let mut replay = HandshakeReplay {
            confirmed: HashMap::new(),
            limit: 2,
        };
        let id = PeerId([1; 16]);
        replay.check(id, [1; 32], 1_000, 1_000).unwrap();
        replay.check(id, [1; 32], 1_000, 1_000).unwrap();
        replay.confirm(id, [1; 32], 1_000, 1_000).unwrap();
        assert!(replay.confirm(id, [1; 32], 1_000, 1_000).is_err());
        replay.confirm(id, [2; 32], 1_000, 1_000).unwrap();
        assert!(replay.check(id, [3; 32], 1_000, 1_000).is_err());
        replay.sweep(1_601);
        // Evicted requests are now outside their original validity window.
        assert!(replay.check(id, [1; 32], 1_000, 1_601).is_err());
        replay.confirm(id, [3; 32], 1_601, 1_601).unwrap();
    }
}
