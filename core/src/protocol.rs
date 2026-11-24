// SPDX-License-Identifier: MIT
use crate::{
    Algorithm, Buffer, CryptoCore, Handshake, HandshakeResponse, PROTOCOL_VERSION, PeerId, Ping,
    Pong, Time, pb,
};
use prost::Message;
use ring::{digest, hmac};
use std::{
    io::Write,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
};

pub use pb::{
    Endpoint, FindPeerMessage, FindPeerRequest, FindPeerResponse, IpAddress, PeerInfo, PeerMapping,
    PeerPunch,
};
pub use pb::{PeerRegisterMessage, PeerRegisterRequest, PeerRegisterResponse};
pub use pb::{find_peer_message, find_peer_request, peer_register_message};

pub const INIT: u8 = 0x02;
pub const REJECTED: u8 = 0x03;
pub const HEARTBEAT: u8 = 0x05;
pub const DATA_INTERFACE: u8 = 0x09;
pub const PEER_REGISTER: u8 = 0x0b;
pub const FIND_PEER: u8 = 0x0c;
pub const CLOSE: u8 = 0xff;

pub const MAX_FIND_PEER_PLAINTEXT: usize = 512;

pub fn random_pair_id() -> anyhow::Result<[u8; 16]> {
    let mut id = [0; 16];
    ring::rand::SecureRandom::fill(&ring::rand::SystemRandom::new(), &mut id)
        .map_err(|_| anyhow::anyhow!("could not generate pair ID"))?;
    Ok(id)
}

impl From<IpAddr> for IpAddress {
    fn from(value: IpAddr) -> Self {
        use pb::ip_address::Address;
        let address = match value.to_canonical() {
            IpAddr::V4(ip) => Address::Ipv4(ip.octets().to_vec()),
            IpAddr::V6(ip) => Address::Ipv6(ip.octets().to_vec()),
        };
        Self {
            address: Some(address),
        }
    }
}

impl TryFrom<&IpAddress> for IpAddr {
    type Error = anyhow::Error;

    fn try_from(value: &IpAddress) -> anyhow::Result<Self> {
        use pb::ip_address::Address;
        match value.address.as_ref() {
            Some(Address::Ipv4(bytes)) => {
                let octets: [u8; 4] = bytes.as_slice().try_into()?;
                Ok(Ipv4Addr::from(octets).into())
            }
            Some(Address::Ipv6(bytes)) => {
                let octets: [u8; 16] = bytes.as_slice().try_into()?;
                Ok(IpAddr::V6(Ipv6Addr::from(octets)).to_canonical())
            }
            None => anyhow::bail!("missing IP address"),
        }
    }
}

impl From<SocketAddr> for Endpoint {
    fn from(value: SocketAddr) -> Self {
        Self {
            ip: Some(value.ip().into()),
            port: value.port().into(),
        }
    }
}

impl TryFrom<&Endpoint> for SocketAddr {
    type Error = anyhow::Error;

    fn try_from(value: &Endpoint) -> anyhow::Result<Self> {
        let port = u16::try_from(value.port)?;
        anyhow::ensure!(port != 0, "zero endpoint port");
        let ip = value
            .ip
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("missing endpoint IP"))?;
        Ok(Self::new(ip.try_into()?, port))
    }
}

/// Handshake timestamps are accepted within this clock-skew window.
pub const HANDSHAKE_TS_TOLERANCE_SECS: i64 = 120;

/// Context label for the server's handshake confirmation MAC, keyed by the
/// PAKE-derived key.
const CONFIRM_LABEL: &[u8] = b"vault handshake confirm v2";

/// Reject handshake messages whose timestamp is too far from the receiver's
/// clock. The server separately remembers authenticated handshake public
/// keys to reject replays while permitting fresh requests in the same second.
pub fn check_handshake_ts(ts: i64, now: i64) -> anyhow::Result<()> {
    if now.abs_diff(ts) > HANDSHAKE_TS_TOLERANCE_SECS as u64 {
        anyhow::bail!("handshake timestamp out of tolerance: {ts} vs local {now}");
    }
    Ok(())
}

fn build_handshake(handshake_data: pb::handshake_message::Data) -> anyhow::Result<Buffer> {
    let handshake = pb::HandshakeMessage {
        data: Some(handshake_data),
    };

    let mut buf = Buffer::new(128);
    buf.write_all(&handshake.encode_to_vec())?;
    buf.prepend_byte(INIT);
    Ok(buf)
}

#[allow(clippy::too_many_arguments)]
pub fn build_handshake_request(
    id: &PeerId,
    pake_message: &[u8],
    algorithms: &[Algorithm],
    ecdh_public_key: &[u8],
    timestamp: Time,
    device_name: &str,
    platform: &str,
    registration: Option<([u8; 32], Option<pb::Endpoint>)>,
) -> anyhow::Result<Buffer> {
    let mut algos = vec![];
    for a in algorithms {
        algos.push(pb::Algorithm {
            algorithm_type: a.algorithm_type.code(),
            speed: a.speed as f32,
        });
    }

    let (peer_public_key, peer_lan_endpoint) = registration
        .map(|(key, endpoint)| (key.to_vec(), endpoint))
        .unwrap_or_default();
    let request = pb::HandshakeRequest {
        id: id.0.to_vec(),
        pake_message: pake_message.to_vec(),
        public_key_data: ecdh_public_key.to_vec(),
        algorithms: algos,
        timestamp,
        version: PROTOCOL_VERSION,
        device_name: device_name.to_string(),
        platform: platform.to_string(),
        peer_public_key,
        peer_lan_endpoint,
    };

    build_handshake(pb::handshake_message::Data::Request(request))
}

#[allow(clippy::too_many_arguments)]
pub fn build_handshake_response(
    id: &PeerId,
    pake_message: &[u8],
    algorithm: &Algorithm,
    ecdh_public_key: &[u8],
    ipv4: String,
    ipv4_mask: String,
    ipv6: String,
    ipv6_prefixlen: i32,
    public_ip: std::net::IpAddr,
    peer_session_epoch: u64,
    timestamp: Time,
    request_public_key: &[u8],
    pake_key: &[u8],
    request_payload: &[u8],
) -> anyhow::Result<Buffer> {
    let mut response = pb::HandshakeResponse {
        id: id.0.to_vec(),
        pake_message: pake_message.to_vec(),
        public_key_data: ecdh_public_key.to_vec(),
        algorithm: Some(algorithm.try_into()?),
        ipv4,
        ipv4_mask,
        ipv6,
        ipv6_prefixlen,
        timestamp,
        request_public_key: request_public_key.to_vec(),
        confirm_mac: vec![],
        public_ip: public_ip.to_canonical().to_string(),
        peer_session_epoch,
    };
    // MAC the response with confirm_mac empty, then fill it in. proto3
    // drops empty bytes fields on the wire, so the client can recompute the
    // MAC over the re-encoded response after clearing the field.
    let key = hmac::Key::new(hmac::HMAC_SHA256, pake_key);
    response.confirm_mac = hmac::sign(&key, &confirmation_input(request_payload, &response))
        .as_ref()
        .to_vec();
    build_handshake(pb::handshake_message::Data::Response(response))
}

fn confirmation_input(request_payload: &[u8], response: &pb::HandshakeResponse) -> Vec<u8> {
    let request_digest = digest::digest(&digest::SHA256, request_payload);
    let mut input = Vec::with_capacity(
        CONFIRM_LABEL.len() + request_digest.as_ref().len() + response.encoded_len(),
    );
    input.extend_from_slice(CONFIRM_LABEL);
    input.extend_from_slice(request_digest.as_ref());
    input.extend_from_slice(&response.encode_to_vec());
    input
}

/// Verify the server's confirmation MAC with the PAKE key the client
/// derived. Fails when the two sides configured different passwords (or the
/// response was tampered with), which is how the client learns its password
/// is wrong before sending any traffic.
pub fn verify_response_confirm(
    response: &HandshakeResponse,
    pake_key: &[u8],
    request_payload: &[u8],
) -> anyhow::Result<()> {
    let proto = pb::HandshakeResponse {
        id: response.id.0.to_vec(),
        pake_message: response.pake_message.clone(),
        public_key_data: response.public_key_data.clone(),
        algorithm: Some((&response.algorithm).try_into()?),
        ipv4: response.ipv4.clone(),
        ipv4_mask: response.ipv4_mask.clone(),
        ipv6: response.ipv6.clone(),
        ipv6_prefixlen: response.ipv6_prefixlen,
        timestamp: response.timestamp,
        request_public_key: response.request_public_key.clone(),
        confirm_mac: vec![],
        public_ip: response.public_ip.clone(),
        peer_session_epoch: response.peer_session_epoch,
    };
    let key = hmac::Key::new(hmac::HMAC_SHA256, pake_key);
    hmac::verify(
        &key,
        &confirmation_input(request_payload, &proto),
        &response.confirm_mac,
    )
    .map_err(|_| anyhow::anyhow!("invalid handshake confirmation MAC (wrong password?)"))?;
    response.public_ip.parse::<std::net::IpAddr>()?;
    Ok(())
}

pub fn build_rejected(buffer: &mut Buffer) {
    buffer.clear();
    buffer.prepend_byte(REJECTED);
}

fn build_control_message(
    buffer: &mut Buffer,
    core: &CryptoCore,
    packet_type: u8,
    message: impl Message,
) -> anyhow::Result<()> {
    buffer.clear();
    buffer.write_all(&message.encode_to_vec())?;
    // The authenticated type and the outer wire byte must always agree.
    core.encrypt(buffer, packet_type)?;
    buffer.prepend_byte(packet_type);
    Ok(())
}

pub(crate) const REGISTER_HEADER: usize = 33;
pub(crate) const REGISTER_MIN: usize = 64;
pub(crate) const REGISTER_MAX: usize = 1472;
pub(crate) const DATA_OVERHEAD: usize = 1 + crate::EXTRA_LEN + crate::TAG_LEN;
const REGISTER_MESSAGE_LEN: usize = 7;

pub(crate) fn register_header(source: PeerId, destination: PeerId) -> [u8; REGISTER_HEADER] {
    let mut header = [PEER_REGISTER; REGISTER_HEADER];
    header[1..17].copy_from_slice(&source.0);
    header[17..33].copy_from_slice(&destination.0);
    header
}

pub(crate) fn build_peer_register(
    buffer: &mut Buffer,
    crypto: &CryptoCore,
    header: &[u8; REGISTER_HEADER],
    message: peer_register_message::Data,
    size: usize,
) -> anyhow::Result<()> {
    use peer_register_message::Data;
    anyhow::ensure!(
        (REGISTER_MIN..=REGISTER_MAX).contains(&size),
        "invalid probe size"
    );
    let cookie = match &message {
        Data::Request(request) => request.cookie,
        Data::Response(response) => {
            anyhow::ensure!(size == REGISTER_MIN, "padded probe response");
            response.cookie
        }
    };
    anyhow::ensure!(cookie != 0, "zero probe cookie");
    buffer.clear();
    let encoded = PeerRegisterMessage {
        data: Some(message),
    }
    .encode_to_vec();
    debug_assert_eq!(encoded.len(), REGISTER_MESSAGE_LEN);
    let len = REGISTER_MESSAGE_LEN + size - REGISTER_MIN;
    buffer.buffer()[..len].fill(0);
    buffer.buffer()[..encoded.len()].copy_from_slice(&encoded);
    buffer.set_length(len);
    crypto.encrypt_with_aad(buffer, header)?;
    let len = buffer.len();
    let start = buffer.get_start() - REGISTER_HEADER;
    buffer.set_start(start);
    buffer.set_length(len + REGISTER_HEADER);
    buffer.message_mut()[..REGISTER_HEADER].copy_from_slice(header);
    Ok(())
}

pub(crate) fn parse_peer_register(
    packet: &mut [u8],
    crypto: &CryptoCore,
) -> anyhow::Result<peer_register_message::Data> {
    use peer_register_message::Data;
    anyhow::ensure!(
        (REGISTER_MIN..=REGISTER_MAX).contains(&packet.len()),
        "invalid probe size"
    );
    let size = packet.len();
    let (header, payload) = packet.split_at_mut(REGISTER_HEADER);
    let plaintext = crypto.decrypt_with_aad(payload, header)?;
    anyhow::ensure!(
        plaintext[REGISTER_MESSAGE_LEN..]
            .iter()
            .all(|&byte| byte == 0),
        "invalid probe padding"
    );
    match PeerRegisterMessage::decode(&plaintext[..REGISTER_MESSAGE_LEN])?.data {
        Some(Data::Request(request)) if request.cookie != 0 => Ok(Data::Request(request)),
        Some(Data::Response(response)) if size == REGISTER_MIN && response.cookie != 0 => {
            Ok(Data::Response(response))
        }
        _ => anyhow::bail!("invalid registration message"),
    }
}

pub fn build_find_peer(
    buffer: &mut Buffer,
    core: &CryptoCore,
    data: find_peer_message::Data,
) -> anyhow::Result<()> {
    let message = FindPeerMessage { data: Some(data) };
    anyhow::ensure!(
        message.encoded_len() <= MAX_FIND_PEER_PLAINTEXT,
        "FIND_PEER message too large"
    );
    build_control_message(buffer, core, FIND_PEER, message)
}

/// Decrypt a FIND_PEER payload after removing the UDP type byte.
pub fn parse_find_peer(
    buffer: &mut Buffer,
    core: &CryptoCore,
) -> anyhow::Result<find_peer_message::Data> {
    anyhow::ensure!(
        buffer.len() <= MAX_FIND_PEER_PLAINTEXT + crate::EXTRA_LEN + crate::TAG_LEN,
        "FIND_PEER message too large"
    );
    core.decrypt(buffer, FIND_PEER)?;
    FindPeerMessage::decode(buffer.as_ref())?
        .data
        .ok_or_else(|| anyhow::anyhow!("missing FIND_PEER message"))
}

pub fn build_heartbeat_ping(
    buffer: &mut Buffer,
    core: &CryptoCore,
    id: &PeerId,
    ts: Time,
) -> anyhow::Result<()> {
    let ping = pb::Ping {
        ts,
        id: id.0.to_vec(),
    };
    build_control_message(buffer, core, HEARTBEAT, ping)
}

pub fn build_heartbeat_pong(
    buffer: &mut Buffer,
    core: &CryptoCore,
    id: &PeerId,
    ts: Time,
) -> anyhow::Result<()> {
    let pong = pb::Pong {
        ts,
        id: id.0.to_vec(),
    };
    build_control_message(buffer, core, HEARTBEAT, pong)
}

pub fn build_data_interface(buffer: &mut Buffer, core: &CryptoCore) -> anyhow::Result<()> {
    core.encrypt(buffer, DATA_INTERFACE)?;
    buffer.prepend_byte(DATA_INTERFACE);
    Ok(())
}

pub fn build_close(buffer: &mut Buffer, core: &CryptoCore, id: &PeerId) -> anyhow::Result<()> {
    let close = pb::Close { id: id.0.to_vec() };
    build_control_message(buffer, core, CLOSE, close)
}

/// Handshake messages are not authenticated at parse time: the PAKE
/// exchange and the confirmation MAC authenticate them afterwards.
pub fn parse_handshake(data: &[u8]) -> anyhow::Result<Handshake> {
    let handshake = pb::HandshakeMessage::decode(data)?;
    match handshake.data {
        Some(pb::handshake_message::Data::Request(r)) => Ok(Handshake::Request(r.try_into()?)),
        Some(pb::handshake_message::Data::Response(r)) => Ok(Handshake::Response(r.try_into()?)),
        None => Err(anyhow::anyhow!("Parse handshake data error.")),
    }
}

/// Decode an already-decrypted ping payload.
pub fn decode_ping(buffer: &Buffer) -> anyhow::Result<Ping> {
    let data = pb::Ping::decode(buffer.as_ref())?;
    Ok(Ping { ts: data.ts })
}

pub fn parse_ping(buffer: &mut Buffer, core: &CryptoCore) -> anyhow::Result<Ping> {
    core.decrypt(buffer, HEARTBEAT)?;
    decode_ping(buffer)
}

pub fn parse_pong(buffer: &mut Buffer, core: &CryptoCore) -> anyhow::Result<Pong> {
    core.decrypt(buffer, HEARTBEAT)?;
    let data = pb::Pong::decode(buffer.as_ref())?;
    Ok(Pong { ts: data.ts })
}

pub fn parse_close(buffer: &mut Buffer, core: &CryptoCore) -> anyhow::Result<PeerId> {
    core.decrypt(buffer, CLOSE)?;
    let data = pb::Close::decode(buffer.as_ref())?;
    PeerId::try_from(data.id)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{AlgorithmType, create_ecdh_keypair, pake, supported_algorithms};

    fn crypto_pair() -> (CryptoCore, CryptoCore) {
        crate::crypto::test_crypto_pair(&AlgorithmType::Aes128Gcm, b"test-pake-key")
    }

    #[test]
    fn shared_replay_window() {
        use crate::crypto::PeerKeyPair;
        use peer_register_message::Data;
        let aid = PeerId([1; 16]);
        let bid = PeerId([2; 16]);
        let a = PeerKeyPair::generate().unwrap();
        let b = PeerKeyPair::generate().unwrap();
        let ac = a.derive([3; 16], (aid, 33), (bid, 34, b.public)).unwrap();
        let bc = b.derive([3; 16], (bid, 34), (aid, 33, a.public)).unwrap();
        let replacement = b.derive([4; 16], (bid, 34), (aid, 33, a.public)).unwrap();
        let mut register = Buffer::new(REGISTER_HEADER + crate::EXTRA_LEN);
        let header = register_header(aid, bid);
        let request = Data::Request(PeerRegisterRequest { cookie: 0x12345678 });
        build_peer_register(&mut register, &ac, &header, request, 1452).unwrap();
        assert_eq!(register.len(), 1452);
        assert_eq!(&register.as_ref()[..33], &header);
        assert_eq!(&register.as_ref()[33..41], &[0; 8]);
        let mut tampered = register.as_ref().to_vec();
        tampered[1] ^= 1;
        assert!(parse_peer_register(&mut tampered, &bc).is_err());
        assert!(parse_peer_register(&mut register.as_ref().to_vec(), &replacement).is_err());
        assert_eq!(
            parse_peer_register(&mut register.as_ref().to_vec(), &bc).unwrap(),
            request
        );
        assert!(parse_peer_register(&mut register.as_ref().to_vec(), &bc).is_err());

        let mut data = Buffer::new(crate::EXTRA_LEN + 1);
        data.write_all(b"vpn data").unwrap();
        build_data_interface(&mut data, &ac).unwrap();
        assert_eq!(&data.as_ref()[1..9], &1u64.to_le_bytes());
        assert_eq!(
            bc.decrypt_slice(&mut data.message_mut()[1..], DATA_INTERFACE)
                .unwrap(),
            b"vpn data"
        );

        let reply = Data::Response(PeerRegisterResponse { cookie: 0x12345678 });
        let reverse = register_header(bid, aid);
        assert!(build_peer_register(&mut register, &bc, &reverse, reply, 65).is_err());
        build_peer_register(&mut register, &bc, &reverse, reply, REGISTER_MIN).unwrap();
        assert_eq!(&register.as_ref()[33..41], &(1u64 << 63).to_le_bytes());
        assert_eq!(
            parse_peer_register(register.message_mut(), &ac).unwrap(),
            reply
        );
    }

    #[test]
    fn ping_pong_roundtrip() {
        let (sender, receiver) = crypto_pair();
        let id = PeerId([7u8; 16]);

        let mut buf = Buffer::new(128);
        build_heartbeat_ping(&mut buf, &sender, &id, 42).unwrap();
        assert_eq!(buf.as_ref()[0], HEARTBEAT);
        let mut ping_buf = Buffer::new(0);
        ping_buf.write_all(&buf.as_ref()[1..]).unwrap();
        assert_eq!(parse_ping(&mut ping_buf, &receiver).unwrap().ts, 42);

        // pong goes the other direction: the responder encrypts, the
        // initiator decrypts.
        let mut buf = Buffer::new(128);
        build_heartbeat_pong(&mut buf, &receiver, &id, 43).unwrap();
        let mut pong_buf = Buffer::new(0);
        pong_buf.write_all(&buf.as_ref()[1..]).unwrap();
        assert_eq!(parse_pong(&mut pong_buf, &sender).unwrap().ts, 43);
    }

    #[test]
    fn close_roundtrip() {
        let (sender, receiver) = crypto_pair();
        let id = PeerId([9u8; 16]);

        let mut buf = Buffer::new(128);
        build_close(&mut buf, &sender, &id).unwrap();
        assert_eq!(buf.as_ref()[0], CLOSE);
        let mut close_buf = Buffer::new(0);
        close_buf.write_all(&buf.as_ref()[1..]).unwrap();
        assert_eq!(parse_close(&mut close_buf, &receiver).unwrap(), id);
    }

    #[test]
    fn heartbeat_type_auth() {
        let (sender, receiver) = crypto_pair();
        let id = PeerId([7; 16]);
        let mut packet = Buffer::new(128);
        build_heartbeat_ping(&mut packet, &sender, &id, 42).unwrap();
        let original = packet.as_ref().to_vec();
        packet.message_mut()[0] = CLOSE;
        assert_eq!(packet.take_prefix(), CLOSE);
        assert!(parse_close(&mut packet, &receiver).is_err());

        // Failed type authentication must not consume the genuine counter.
        let mut genuine = Buffer::new(0);
        genuine.write_all(&original[1..]).unwrap();
        assert_eq!(parse_ping(&mut genuine, &receiver).unwrap().ts, 42);
    }

    #[test]
    fn timestamp_tolerance() {
        let now = 1_000_000;
        assert!(check_handshake_ts(now, now).is_ok());
        assert!(check_handshake_ts(now - HANDSHAKE_TS_TOLERANCE_SECS, now).is_ok());
        assert!(check_handshake_ts(now - HANDSHAKE_TS_TOLERANCE_SECS - 1, now).is_err());
        assert!(check_handshake_ts(now + HANDSHAKE_TS_TOLERANCE_SECS + 1, now).is_err());
        assert!(check_handshake_ts(i64::MIN, now).is_err());
        assert!(check_handshake_ts(i64::MAX, i64::MIN).is_err());
    }

    /// A full request/response exchange: both PAKE sides derive the same
    /// key and the confirmation MAC verifies.
    fn run_handshake(
        client_password: &[u8],
        server_password: &[u8],
        public_ip: &str,
    ) -> (HandshakeResponse, zeroize::Zeroizing<Vec<u8>>, Vec<u8>) {
        let client_id = PeerId([1u8; 16]);
        let server_id = PeerId([2u8; 16]);
        let (_client_priv, client_pub) = create_ecdh_keypair().unwrap();
        let (_server_priv, server_pub) = create_ecdh_keypair().unwrap();

        let (client_pake, msg_a) = pake::start_client(client_password, &client_id.0);
        let request_buf = build_handshake_request(
            &client_id,
            &msg_a,
            &supported_algorithms(),
            client_pub.bytes(),
            42,
            "test-device",
            "linux",
            Some((
                [7; 32],
                Some(
                    "192.168.1.2:1234"
                        .parse::<std::net::SocketAddr>()
                        .unwrap()
                        .into(),
                ),
            )),
        )
        .unwrap();
        assert_eq!(request_buf.as_ref()[0], INIT);
        let request = match parse_handshake(&request_buf.as_ref()[1..]).unwrap() {
            Handshake::Request(r) => r,
            _ => panic!("expected request"),
        };
        assert_eq!(request.device_name, "test-device");
        assert_eq!(request.platform, "linux");
        assert_eq!(request.peer_public_key, [7; 32]);
        let payload = request_buf.as_ref()[1..].to_vec();

        let (server_pake, msg_b) = pake::start_server(server_password, &request.id.0);
        let pake_key_server = server_pake.finish(&request.pake_message).unwrap();

        let algorithm = Algorithm {
            algorithm_type: AlgorithmType::Aes128Gcm,
            speed: 1.0,
        };
        let response_buf = build_handshake_response(
            &server_id,
            &msg_b,
            &algorithm,
            server_pub.bytes(),
            "10.0.0.2".to_string(),
            "255.255.255.0".to_string(),
            "fd00::2".to_string(),
            64,
            public_ip.parse().unwrap(),
            5,
            43,
            &request.public_key_data,
            &pake_key_server,
            &payload,
        )
        .unwrap();
        let response = match parse_handshake(&response_buf.as_ref()[1..]).unwrap() {
            Handshake::Response(r) => r,
            _ => panic!("expected response"),
        };
        assert_eq!(response.public_ip, public_ip);

        let pake_key_client = client_pake.finish(&response.pake_message).unwrap();
        (response, pake_key_client, payload)
    }

    #[test]
    fn handshake_pake_roundtrip() {
        let (response, pake_key_client, payload) =
            run_handshake(b"shared-password", b"shared-password", "2001:db8::1");
        verify_response_confirm(&response, &pake_key_client, &payload).unwrap();
    }

    #[test]
    fn raw_request_binding() {
        let (response, key, mut payload) = run_handshake(b"pw", b"pw", "192.0.2.1");
        // A top-level unknown field survives transit but is discarded by decode.
        payload.extend_from_slice(&[0x78, 1]);
        assert!(parse_handshake(&payload).is_ok());
        assert!(verify_response_confirm(&response, &key, &payload).is_err());
        let payload = &payload[..payload.len() - 2];
        let mut request = pb::HandshakeMessage::decode(payload).unwrap();
        let Some(pb::handshake_message::Data::Request(request_fields)) = request.data.as_mut()
        else {
            panic!("expected request");
        };
        request_fields.peer_lan_endpoint = None;
        assert!(verify_response_confirm(&response, &key, &request.encode_to_vec()).is_err());
        let Some(pb::handshake_message::Data::Request(request_fields)) = request.data.as_mut()
        else {
            panic!("expected request");
        };
        request_fields.peer_public_key.clear();
        assert!(verify_response_confirm(&response, &key, &request.encode_to_vec()).is_err());
    }

    #[test]
    fn wrong_password_rejected() {
        // The server used a different password, so its confirm_mac was
        // keyed differently than the client's PAKE key.
        let (response, pake_key_client, payload) =
            run_handshake(b"client-password", b"server-password", "192.0.2.1");
        assert!(verify_response_confirm(&response, &pake_key_client, &payload).is_err());
    }

    #[test]
    fn tampered_response_rejected() {
        let (mut response, pake_key_client, payload) = run_handshake(b"pw", b"pw", "192.0.2.1");
        response.ipv4 = "10.0.0.99".to_string();
        assert!(verify_response_confirm(&response, &pake_key_client, &payload).is_err());

        let (mut response, pake_key_client, payload) = run_handshake(b"pw", b"pw", "192.0.2.1");
        response.public_ip = "192.0.2.99".to_string();
        assert!(verify_response_confirm(&response, &pake_key_client, &payload).is_err());

        let (mut response, pake_key_client, payload) = run_handshake(b"pw", b"pw", "192.0.2.1");
        response.peer_session_epoch += 1;
        assert!(verify_response_confirm(&response, &pake_key_client, &payload).is_err());

        let (mut response, pake_key_client, payload) = run_handshake(b"pw", b"pw", "192.0.2.1");
        response.confirm_mac[0] ^= 0xff;
        assert!(verify_response_confirm(&response, &pake_key_client, &payload).is_err());
    }
}
