// SPDX-License-Identifier: MIT
use std::{
    cmp,
    sync::{
        Mutex,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};

use ring::{
    aead::{self, LessSafeKey, NONCE_LEN, UnboundKey},
    agreement::{EphemeralPrivateKey, UnparsedPublicKey, X25519, agree_ephemeral},
    hkdf,
    rand::SystemRandom,
};
use tracing::debug;

use crate::{Algorithm, AlgorithmType, EXTRA_LEN, TAG_LEN, buf::Buffer};

/// Domain-separation label in the session-key HKDF info string, alongside
/// both ephemeral public keys.
const HKDF_INFO: &[u8] = b"vault session key v2";

/// Which side of the handshake a [`CryptoCore`] belongs to. The packet
/// counter space is split by the top bit so the two directions of a session
/// never reuse a (key, nonce) pair.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    /// The side that sent the handshake request (client).
    Initiator,
    /// The side that answered it (supernode).
    Responder,
}

impl Role {
    fn counter_flag(self) -> u64 {
        match self {
            Role::Initiator => 0,
            Role::Responder => 1 << 63,
        }
    }

    fn peer(self) -> Role {
        match self {
            Role::Initiator => Role::Responder,
            Role::Responder => Role::Initiator,
        }
    }
}

/// Sliding replay window (IPsec/WireGuard style): bit 0 of `bitmap[0]`
/// always corresponds to `highest`, lower counters sit further left.
struct ReplayWindow {
    highest: u64,
    initialized: bool,
    bitmap: [u64; Self::BITS / 64],
}

impl ReplayWindow {
    const BITS: usize = 2048;

    fn new() -> Self {
        Self {
            highest: 0,
            initialized: false,
            bitmap: [0; Self::BITS / 64],
        }
    }

    /// Cheap pre-authentication check: packets that are certainly replays
    /// can be dropped without spending an AEAD verification on them.
    fn is_certainly_replayed(&self, counter: u64) -> bool {
        if !self.initialized || counter > self.highest {
            return false;
        }
        let diff = self.highest - counter;
        if diff >= Self::BITS as u64 {
            return true;
        }
        self.bitmap[(diff / 64) as usize] & (1 << (diff % 64)) != 0
    }

    /// Record an authenticated counter. Returns false for replays.
    fn check_and_set(&mut self, counter: u64) -> bool {
        if !self.initialized {
            self.initialized = true;
            self.highest = counter;
            self.bitmap[0] = 1;
            return true;
        }
        if counter > self.highest {
            let diff = counter - self.highest;
            if diff >= Self::BITS as u64 {
                self.bitmap = [0; Self::BITS / 64];
            } else {
                let word_shift = (diff / 64) as usize;
                let bit_shift = (diff % 64) as u32;
                for i in (0..Self::BITS / 64).rev() {
                    let mut v = if i >= word_shift {
                        self.bitmap[i - word_shift]
                    } else {
                        0
                    };
                    v <<= bit_shift;
                    if bit_shift > 0 && i > word_shift {
                        v |= self.bitmap[i - word_shift - 1] >> (64 - bit_shift);
                    }
                    self.bitmap[i] = v;
                }
            }
            self.highest = counter;
            self.bitmap[0] |= 1;
            return true;
        }
        let diff = self.highest - counter;
        if diff >= Self::BITS as u64 {
            return false;
        }
        let word = (diff / 64) as usize;
        let mask = 1u64 << (diff % 64);
        if self.bitmap[word] & mask != 0 {
            return false;
        }
        self.bitmap[word] |= mask;
        true
    }
}

pub struct CryptoCore {
    // ring's LessSafeKey holds key material internally with no API to
    // zeroize it, so it stays in memory for the session's lifetime by
    // design.
    key: LessSafeKey,
    role: Role,
    send_counter: AtomicU64,
    recv_window: Mutex<ReplayWindow>,
}

impl CryptoCore {
    /// `pake_key` is the SPAKE2 handshake output: the session key is bound
    /// to the password-authenticated exchange, so a man in the middle
    /// without the password cannot derive matching session keys even with a
    /// successful X25519 relay.
    pub fn new(
        private_key: EphemeralPrivateKey,
        algorithm_type: &AlgorithmType,
        public_key: &[u8],
        role: Role,
        pake_key: &[u8],
    ) -> anyhow::Result<Self> {
        let ecdh_public_key = UnparsedPublicKey::new(&X25519, public_key.into());
        let master_key = CryptoCore::derive_master_key(
            algorithm_type.into(),
            private_key,
            &ecdh_public_key,
            role,
            pake_key,
        )?;
        Ok(Self {
            key: master_key,
            role,
            send_counter: AtomicU64::new(role.counter_flag()),
            recv_window: Mutex::new(ReplayWindow::new()),
        })
    }

    /// Authenticate the outer wire type as AEAD associated data.
    pub fn encrypt(&self, buf: &mut Buffer, packet_type: u8) -> anyhow::Result<()> {
        let data_start = buf.get_start();
        let data_length = buf.len();
        assert!(buf.get_start() >= EXTRA_LEN);

        let counter = self.send_counter.fetch_add(1, Ordering::Relaxed);
        // The counter must stay inside this role's half of the u64 space;
        // crossing the top bit would collide with the peer's nonce space.
        // Practically unreachable (2^63 packets), checked defensively.
        if counter & (1 << 63) != self.role.counter_flag() {
            anyhow::bail!("packet counter exhausted for this session, re-handshake required");
        }

        buf.set_start(data_start - EXTRA_LEN);
        buf.set_length(data_length + EXTRA_LEN + TAG_LEN);

        let (extra, data_and_tag) = buf.message_mut().split_at_mut(EXTRA_LEN);
        let (data, tag_space) = data_and_tag.split_at_mut(data_length);

        // The 8 header bytes ARE the counter (little-endian); the AEAD nonce
        // is 4 zero bytes followed by that counter.
        let mut nonce = [0; NONCE_LEN];
        nonce[4..].copy_from_slice(&counter.to_le_bytes());
        extra.copy_from_slice(&counter.to_le_bytes());

        let nonce = aead::Nonce::assume_unique_for_key(nonce);

        let tag = self
            .key
            .seal_in_place_separate_tag(nonce, aead::Aad::from([packet_type]), data)
            .map_err(|_| anyhow::anyhow!("AEAD seal failed"))?;
        tag_space.clone_from_slice(tag.as_ref());
        Ok(())
    }

    pub fn decrypt(&self, buf: &mut Buffer, packet_type: u8) -> anyhow::Result<()> {
        // Return an error instead of panicking: this buffer can contain
        // arbitrary network input, and a panic here kills the client's run
        // loop (and the whole supernode process on the server side).
        if buf.len() < EXTRA_LEN + TAG_LEN {
            anyhow::bail!("packet too short: {} < {}", buf.len(), EXTRA_LEN + TAG_LEN);
        }
        let (extra, data_and_tag) = buf.message_mut().split_at_mut(EXTRA_LEN);
        // Provably infallible: split_at_mut(EXTRA_LEN) yields an `extra` of
        // exactly EXTRA_LEN (8) bytes.
        let counter = u64::from_le_bytes(extra.try_into().expect("EXTRA_LEN is 8"));

        // The direction bit must match the sender's role; this also stops
        // reflected own packets.
        if counter & (1 << 63) != self.role.peer().counter_flag() {
            anyhow::bail!("packet counter belongs to the wrong direction");
        }

        // Cheap replay pre-check before spending an AEAD verification.
        {
            // Recover from poisoning instead of panicking: the window is a
            // plain data structure whose critical sections cannot leave it
            // inconsistent, and a poisoned lock must not kill the session.
            let window = self.recv_window.lock().unwrap_or_else(|e| e.into_inner());
            if window.is_certainly_replayed(counter) {
                anyhow::bail!("replay detected (counter {counter})");
            }
        }

        let mut nonce = [0; NONCE_LEN];
        nonce[4..].copy_from_slice(&counter.to_le_bytes());

        let crypto_nonce = aead::Nonce::assume_unique_for_key(nonce);
        self.key
            .open_in_place(crypto_nonce, aead::Aad::from([packet_type]), data_and_tag)
            .map_err(|e| anyhow::anyhow!(e))?;

        // Mark the counter only after successful authentication so forged
        // packets cannot burn window slots.
        {
            let mut window = self.recv_window.lock().unwrap_or_else(|e| e.into_inner());
            if !window.check_and_set(counter) {
                anyhow::bail!("replay detected (counter {counter})");
            }
        }

        buf.set_start(buf.get_start() + EXTRA_LEN);
        buf.set_length(buf.len() - TAG_LEN);
        Ok(())
    }

    fn derive_master_key(
        algo: &'static ring::aead::Algorithm,
        privk: EphemeralPrivateKey,
        pubk: &UnparsedPublicKey<Vec<u8>>,
        role: Role,
        pake_key: &[u8],
    ) -> anyhow::Result<LessSafeKey> {
        // Own ephemeral public key, needed to bind the session key to both
        // sides of the handshake transcript.
        let own_public_key = privk
            .compute_public_key()
            .map_err(|_| anyhow::anyhow!("failed to compute own public key"))?;
        let peer_public_key: &[u8] = pubk.bytes();
        let key = agree_ephemeral(privk, pubk, |shared_secret| {
            // HKDF-SHA256 over the raw X25519 output. The PAKE handshake key
            // is the salt, binding the session key to the
            // password-authenticated exchange; the info string adds domain
            // separation and mixes in both ephemeral public keys
            // (role-ordered) so the key is bound to this exact
            // (initiator, responder) pair.
            let (initiator, responder) = match role {
                Role::Initiator => (own_public_key.as_ref(), peer_public_key),
                Role::Responder => (peer_public_key, own_public_key.as_ref()),
            };
            let salt = hkdf::Salt::new(hkdf::HKDF_SHA256, pake_key);
            let prk = salt.extract(shared_secret);
            // The expects below cannot fail: an AEAD algorithm's key length
            // is always a valid HKDF output length and matches the key slice.
            let info_slices = [HKDF_INFO, initiator, responder];
            let okm = prk.expand(&info_slices, algo).expect("HKDF expand");
            let mut key_bytes = vec![0u8; algo.key_len()];
            okm.fill(&mut key_bytes).expect("HKDF fill");
            LessSafeKey::new(UnboundKey::new(algo, &key_bytes).expect("AEAD key length"))
        })
        // ring rejects low-order peer public keys (e.g. all-zero) here.
        // Propagate instead of panicking: the peer key comes straight from a
        // network handshake, and a panic would kill the whole process.
        .map_err(|_| anyhow::anyhow!("ECDH failed: invalid peer public key"))?;
        Ok(key)
    }
}

/// Create an ephemeral ECDH keypair.
pub fn create_ecdh_keypair() -> anyhow::Result<(EphemeralPrivateKey, UnparsedPublicKey<Vec<u8>>)> {
    let rand = SystemRandom::new();
    // Propagate instead of panicking: this is called on the network data
    // path (handshake handling), where a panic would kill the whole process.
    let ecdh_private_key = EphemeralPrivateKey::generate(&X25519, &rand)
        .map_err(|_| anyhow::anyhow!("failed to generate ECDH private key"))?;
    let public_key = ecdh_private_key
        .compute_public_key()
        .map_err(|_| anyhow::anyhow!("failed to compute ECDH public key"))?;
    let mut vec = vec![];
    vec.extend_from_slice(public_key.as_ref());
    let ecdh_public_key = UnparsedPublicKey::new(&X25519, vec);
    Ok((ecdh_private_key, ecdh_public_key))
}

pub fn select_algorithm(
    local_algos: &[Algorithm],
    peer_algos: &[Algorithm],
) -> anyhow::Result<Option<Algorithm>> {
    // For each supported algorithm, find the algorithm in the list of the peer (ignore algorithm if not found).
    // Take the minimal speed reported by either us or the peer.
    // Select the algorithm with the greatest minimal speed.
    let algo = local_algos
        .iter()
        .filter_map(|a1| {
            peer_algos
                .iter()
                .find(|a2| a1.algorithm_type == a2.algorithm_type)
                .map(|a2| {
                    (
                        *a1,
                        if a1.speed < a2.speed {
                            a1.speed
                        } else {
                            a2.speed
                        },
                    )
                })
        })
        .max_by(|(_, s1), (_, s2)| {
            if s1 < s2 {
                cmp::Ordering::Less
            } else {
                cmp::Ordering::Greater
            }
        });
    if let Some(algo) = algo {
        debug!(
            "Handshake: best algorithm is {:?} with speed {}",
            algo.0, algo.1
        );
        Ok(Some(Algorithm {
            algorithm_type: algo.0.algorithm_type,
            speed: algo.1,
        }))
    } else {
        Err(anyhow::anyhow!("No common algorithms"))
    }
}

pub fn supported_algorithms() -> Vec<Algorithm> {
    let duration = Duration::from_secs_f32(0.1);
    let a1 = Algorithm {
        algorithm_type: AlgorithmType::Aes128Gcm,
        speed: test_speed(AlgorithmType::Aes128Gcm, &duration),
    };
    let a2 = Algorithm {
        algorithm_type: AlgorithmType::Aes256Gcm,
        speed: test_speed(AlgorithmType::Aes256Gcm, &duration),
    };
    let a3 = Algorithm {
        algorithm_type: AlgorithmType::Chacha20Poly1305,
        speed: test_speed(AlgorithmType::Chacha20Poly1305, &duration),
    };

    debug!(
        "Aes128Gcm: {:.1} MiB/s, Aes256Gcm: {:.1} MiB/s, Chacha20Poly1305: {:.1} MiB/s",
        a1.speed, a2.speed, a3.speed
    );

    vec![a1, a2, a3]
}

/// Benchmark an AEAD algorithm's throughput.
fn test_speed(algorithm_type: AlgorithmType, max_time: &Duration) -> f64 {
    let mut buffer = Buffer::new(EXTRA_LEN);
    buffer.set_length(1000);

    let (private_key1, pub_key1) = create_ecdh_keypair().unwrap();
    let (private_key2, pub_key2) = create_ecdh_keypair().unwrap();

    let sender = CryptoCore::new(
        private_key1,
        &algorithm_type,
        pub_key2.bytes(),
        Role::Initiator,
        // The PAKE key only salts the session-key HKDF; a fixed value is
        // fine for a throughput benchmark.
        &[0u8; 32],
    )
    .unwrap();
    let receiver = CryptoCore::new(
        private_key2,
        &algorithm_type,
        pub_key1.bytes(),
        Role::Responder,
        &[0u8; 32],
    )
    .unwrap();

    let mut iterations = 0;
    let start = Instant::now();
    while (Instant::now() - start).as_nanos() < max_time.as_nanos() {
        for _ in 0..1000 {
            sender
                .encrypt(&mut buffer, crate::protocol::DATA_INTERFACE)
                .unwrap();
            receiver
                .decrypt(&mut buffer, crate::protocol::DATA_INTERFACE)
                .unwrap();
        }
        iterations += 1000;
    }
    let duration = (Instant::now() - start).as_secs_f64();
    let data = iterations * 1000 * 2;
    data as f64 / duration / 1_000_000.0
}

#[cfg(test)]
mod tests {
    use std::io::Write;

    use crate::Buffer;

    use super::*;

    fn crypto_pair() -> (CryptoCore, CryptoCore) {
        let (privk1, pubk1) = create_ecdh_keypair().unwrap();
        let (privk2, pubk2) = create_ecdh_keypair().unwrap();
        (
            CryptoCore::new(
                privk1,
                &AlgorithmType::Aes128Gcm,
                pubk2.bytes(),
                Role::Initiator,
                b"test-pake-key",
            )
            .unwrap(),
            CryptoCore::new(
                privk2,
                &AlgorithmType::Aes128Gcm,
                pubk1.bytes(),
                Role::Responder,
                b"test-pake-key",
            )
            .unwrap(),
        )
    }

    fn encrypt_to_vec(sender: &CryptoCore, data: &[u8]) -> Vec<u8> {
        let mut buf = Buffer::new(EXTRA_LEN);
        buf.write_all(data).unwrap();
        sender
            .encrypt(&mut buf, crate::protocol::DATA_INTERFACE)
            .unwrap();
        buf.as_ref().to_vec()
    }

    fn decrypt_bytes(receiver: &CryptoCore, packet: &[u8]) -> anyhow::Result<Vec<u8>> {
        let mut buf = Buffer::new(0);
        buf.write_all(packet).unwrap();
        receiver.decrypt(&mut buf, crate::protocol::DATA_INTERFACE)?;
        Ok(buf.as_ref().to_vec())
    }

    #[test]
    fn encrypt_decrypt_roundtrip() {
        let (sender, receiver) = crypto_pair();

        let origin_data = "abc".as_bytes();
        let packet = encrypt_to_vec(&sender, origin_data);
        let plain = decrypt_bytes(&receiver, &packet).unwrap();
        assert!(plain.eq(origin_data))
    }

    #[test]
    fn packet_types_are_authenticated_for_every_cipher() {
        use crate::protocol::{CLOSE, DATA_INTERFACE, HEARTBEAT};
        for algorithm in [
            AlgorithmType::Aes128Gcm,
            AlgorithmType::Aes256Gcm,
            AlgorithmType::Chacha20Poly1305,
        ] {
            let (a, ap) = create_ecdh_keypair().unwrap();
            let (b, bp) = create_ecdh_keypair().unwrap();
            let sender =
                CryptoCore::new(a, &algorithm, bp.bytes(), Role::Initiator, b"test").unwrap();
            let receiver =
                CryptoCore::new(b, &algorithm, ap.bytes(), Role::Responder, b"test").unwrap();
            for original_type in [HEARTBEAT, DATA_INTERFACE, CLOSE] {
                let mut packet = Buffer::new(EXTRA_LEN);
                packet.write_all(b"payload").unwrap();
                sender.encrypt(&mut packet, original_type).unwrap();
                let bytes = packet.as_ref().to_vec();
                for changed_type in [HEARTBEAT, DATA_INTERFACE, CLOSE] {
                    if changed_type == original_type {
                        continue;
                    }
                    let mut forged = Buffer::new(0);
                    forged.write_all(&bytes).unwrap();
                    assert!(receiver.decrypt(&mut forged, changed_type).is_err());
                }
                let mut genuine = Buffer::new(0);
                genuine.write_all(&bytes).unwrap();
                receiver.decrypt(&mut genuine, original_type).unwrap();
                assert_eq!(genuine.as_ref(), b"payload");
            }
        }
    }

    #[test]
    fn replayed_packet_rejected() {
        let (sender, receiver) = crypto_pair();
        let packet = encrypt_to_vec(&sender, b"hello");
        decrypt_bytes(&receiver, &packet).unwrap();
        let err = decrypt_bytes(&receiver, &packet).unwrap_err();
        assert!(err.to_string().contains("replay"), "unexpected: {err}");
    }

    #[test]
    fn wrong_direction_rejected() {
        let (privk1, pubk1) = create_ecdh_keypair().unwrap();
        let (privk2, pubk2) = create_ecdh_keypair().unwrap();
        // Both sides configured as initiator: each expects responder-flagged
        // counters, so packets from the other initiator must be refused.
        let a = CryptoCore::new(
            privk1,
            &AlgorithmType::Aes128Gcm,
            pubk2.bytes(),
            Role::Initiator,
            b"test-pake-key",
        )
        .unwrap();
        let b = CryptoCore::new(
            privk2,
            &AlgorithmType::Aes128Gcm,
            pubk1.bytes(),
            Role::Initiator,
            b"test-pake-key",
        )
        .unwrap();
        let packet = encrypt_to_vec(&a, b"hello");
        let err = decrypt_bytes(&b, &packet).unwrap_err();
        assert!(err.to_string().contains("direction"), "unexpected: {err}");
    }

    #[test]
    fn in_window_reorder_accepted() {
        let (sender, receiver) = crypto_pair();
        let p0 = encrypt_to_vec(&sender, b"p0");
        let p1 = encrypt_to_vec(&sender, b"p1");
        let p2 = encrypt_to_vec(&sender, b"p2");
        decrypt_bytes(&receiver, &p0).unwrap();
        decrypt_bytes(&receiver, &p2).unwrap();
        // p1 arrives late but is inside the window.
        let plain = decrypt_bytes(&receiver, &p1).unwrap();
        assert_eq!(plain, b"p1");
    }

    #[test]
    fn replay_window_tracks_counters() {
        let mut w = ReplayWindow::new();
        assert!(w.check_and_set(10));
        assert!(w.check_and_set(12)); // advance
        assert!(!w.check_and_set(12)); // duplicate of highest
        assert!(w.check_and_set(11)); // late but in-window
        assert!(!w.check_and_set(11)); // duplicate
        assert!(!w.check_and_set(10)); // duplicate
        // Jump beyond the window size: everything before is forgotten.
        assert!(w.check_and_set(10 + ReplayWindow::BITS as u64 + 1));
        assert!(w.check_and_set(10 + ReplayWindow::BITS as u64 + 2));
        // Gradual advance past the window edge invalidates old counters.
        let base = w.highest;
        for c in base + 1..=base + ReplayWindow::BITS as u64 {
            assert!(w.check_and_set(c));
        }
        assert!(w.is_certainly_replayed(base));
        assert!(!w.check_and_set(base));
    }
}
