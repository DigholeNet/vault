// SPDX-License-Identifier: MIT
use crate::{
    Algorithm, Buffer, CryptoCore, Handshake, HandshakeResponse, PROTOCOL_VERSION, PeerId, Ping,
    Pong, Time, pb,
};
use prost::Message;
use ring::hmac;
use std::io::Write;

pub const INIT: u8 = 0x02;
pub const REJECTED: u8 = 0x03;
pub const HEARTBEAT: u8 = 0x05;
pub const DATA_INTERFACE: u8 = 0x09;
pub const CLOSE: u8 = 0xff;

/// Handshake timestamps are accepted within this clock-skew window.
pub const HANDSHAKE_TS_TOLERANCE_SECS: i64 = 120;

/// Context label for the server's handshake confirmation MAC, keyed by the
/// PAKE-derived key.
const CONFIRM_LABEL: &[u8] = b"vault handshake confirm v1";

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

pub fn build_handshake_request(
    id: &PeerId,
    pake_message: &[u8],
    algorithms: &[Algorithm],
    ecdh_public_key: &[u8],
    timestamp: Time,
    device_name: &str,
    platform: &str,
) -> anyhow::Result<Buffer> {
    let mut algos = vec![];
    for a in algorithms {
        algos.push(pb::Algorithm {
            algorithm_type: a.algorithm_type.code(),
            speed: a.speed as f32,
        });
    }

    let request = pb::HandshakeRequest {
        id: id.0.to_vec(),
        pake_message: pake_message.to_vec(),
        public_key_data: ecdh_public_key.to_vec(),
        algorithms: algos,
        timestamp,
        version: PROTOCOL_VERSION,
        device_name: device_name.to_string(),
        platform: platform.to_string(),
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
    timestamp: Time,
    request_public_key: &[u8],
    pake_key: &[u8],
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
    };
    // MAC the response with confirm_mac empty, then fill it in. proto3
    // drops empty bytes fields on the wire, so the client can recompute the
    // MAC over the re-encoded response after clearing the field.
    let mac = confirm_mac(pake_key, &response.encode_to_vec());
    response.confirm_mac = mac;
    build_handshake(pb::handshake_message::Data::Response(response))
}

fn confirm_mac(pake_key: &[u8], encoded_response: &[u8]) -> Vec<u8> {
    let key = hmac::Key::new(hmac::HMAC_SHA256, pake_key);
    let mut ctx = hmac::Context::with_key(&key);
    ctx.update(CONFIRM_LABEL);
    ctx.update(encoded_response);
    ctx.sign().as_ref().to_vec()
}

/// Verify the server's confirmation MAC with the PAKE key the client
/// derived. Fails when the two sides configured different passwords (or the
/// response was tampered with), which is how the client learns its password
/// is wrong before sending any traffic.
pub fn verify_response_confirm(
    response: &HandshakeResponse,
    pake_key: &[u8],
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
    };
    let mut msg = Vec::with_capacity(CONFIRM_LABEL.len() + 256);
    msg.extend_from_slice(CONFIRM_LABEL);
    msg.extend_from_slice(&proto.encode_to_vec());
    let key = hmac::Key::new(hmac::HMAC_SHA256, pake_key);
    // hmac::verify compares in constant time.
    hmac::verify(&key, &msg, &response.confirm_mac)
        .map_err(|_| anyhow::anyhow!("invalid handshake confirmation MAC (wrong password?)"))
}

pub fn build_rejected(buffer: &mut Buffer) {
    buffer.clear();
    buffer.prepend_byte(REJECTED);
}

pub fn build_heartbeat_ping(
    buffer: &mut Buffer,
    core: &CryptoCore,
    id: &PeerId,
    ts: Time,
) -> anyhow::Result<()> {
    buffer.clear();
    let ping = pb::Ping {
        ts,
        id: id.0.to_vec(),
    };
    buffer.write_all(&ping.encode_to_vec())?;
    core.encrypt(buffer, HEARTBEAT)?;
    buffer.prepend_byte(HEARTBEAT);
    Ok(())
}

pub fn build_heartbeat_pong(
    buffer: &mut Buffer,
    core: &CryptoCore,
    id: &PeerId,
    ts: Time,
) -> anyhow::Result<()> {
    buffer.clear();
    let pong = pb::Pong {
        ts,
        id: id.0.to_vec(),
    };
    buffer.write_all(&pong.encode_to_vec())?;
    core.encrypt(buffer, HEARTBEAT)?;
    buffer.prepend_byte(HEARTBEAT);
    Ok(())
}

pub fn build_data_interface(buffer: &mut Buffer, core: &CryptoCore) -> anyhow::Result<()> {
    core.encrypt(buffer, DATA_INTERFACE)?;
    buffer.prepend_byte(DATA_INTERFACE);
    Ok(())
}

pub fn build_close(buffer: &mut Buffer, core: &CryptoCore, id: &PeerId) -> anyhow::Result<()> {
    let close = pb::Close { id: id.0.to_vec() };
    buffer.clear();
    buffer.write_all(&close.encode_to_vec())?;
    core.encrypt(buffer, CLOSE)?;
    buffer.prepend_byte(CLOSE);
    Ok(())
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
    use crate::{AlgorithmType, Role, create_ecdh_keypair, pake, supported_algorithms};

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
    ) -> (HandshakeResponse, zeroize::Zeroizing<Vec<u8>>) {
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
        )
        .unwrap();
        assert_eq!(request_buf.as_ref()[0], INIT);
        let request = match parse_handshake(&request_buf.as_ref()[1..]).unwrap() {
            Handshake::Request(r) => r,
            _ => panic!("expected request"),
        };
        assert_eq!(request.device_name, "test-device");
        assert_eq!(request.platform, "linux");

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
            43,
            &request.public_key_data,
            &pake_key_server,
        )
        .unwrap();
        let response = match parse_handshake(&response_buf.as_ref()[1..]).unwrap() {
            Handshake::Response(r) => r,
            _ => panic!("expected response"),
        };

        let pake_key_client = client_pake.finish(&response.pake_message).unwrap();
        (response, pake_key_client)
    }

    #[test]
    fn handshake_pake_roundtrip() {
        let (response, pake_key_client) = run_handshake(b"shared-password", b"shared-password");
        verify_response_confirm(&response, &pake_key_client).unwrap();
    }

    #[test]
    fn wrong_password_rejected() {
        // The server used a different password, so its confirm_mac was
        // keyed differently than the client's PAKE key.
        let (response, pake_key_client) = run_handshake(b"client-password", b"server-password");
        assert!(verify_response_confirm(&response, &pake_key_client).is_err());
    }

    #[test]
    fn tampered_response_rejected() {
        let (mut response, pake_key_client) = run_handshake(b"pw", b"pw");
        response.ipv4 = "10.0.0.99".to_string();
        assert!(verify_response_confirm(&response, &pake_key_client).is_err());

        let (mut response, pake_key_client) = run_handshake(b"pw", b"pw");
        response.confirm_mac[0] ^= 0xff;
        assert!(verify_response_confirm(&response, &pake_key_client).is_err());
    }
}
