// SPDX-License-Identifier: MIT
//! Mock server for the integration tests of vault-core and vault-bridge.

use std::io::Write;
use std::net::SocketAddr;
use std::time::Duration;

use tokio::net::UdpSocket;
use tokio::time::{sleep, timeout};

use crate::{
    Buffer, CryptoCore, Handshake, PeerId, Role, create_ecdh_keypair, pake, protocol,
    select_algorithm, supported_algorithms,
};

fn now_secs() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// A minimal mock server that speaks the vault-core handshake/heartbeat
/// protocol.
pub async fn run_mock_server(password: &str) -> (SocketAddr, tokio::task::JoinHandle<()>) {
    let server_socket = UdpSocket::bind("127.0.0.1:0")
        .await
        .expect("bind server socket");
    let server_addr = server_socket.local_addr().expect("server local addr");
    let password = password.to_string();

    let handle = tokio::spawn(async move {
        let mut buf = vec![0u8; 65535];

        // PAKE-authenticated handshake.
        let (len, client_addr) = server_socket
            .recv_from(&mut buf)
            .await
            .expect("recv handshake");
        let packet = &buf[..len];
        assert!(!packet.is_empty(), "empty handshake packet");
        assert_eq!(packet[0], protocol::INIT, "expected INIT packet");

        let handshake = protocol::parse_handshake(&packet[1..]).expect("parse handshake");
        let request = match handshake {
            Handshake::Request(r) => r,
            _ => panic!("expected handshake request"),
        };
        protocol::check_handshake_ts(request.timestamp, now_secs()).expect("handshake ts");

        let (pake_state, pake_message) = pake::start_server(password.as_bytes(), &request.id.0);
        let pake_key = pake_state
            .finish(&request.pake_message)
            .expect("pake finish");

        let chosen = select_algorithm(&supported_algorithms(), &request.algorithms)
            .expect("select algorithm")
            .expect("no common algorithm");

        let (server_priv, server_pub) = create_ecdh_keypair().expect("keypair");
        let server_id = PeerId::default();
        let response = protocol::build_handshake_response(
            &server_id,
            &pake_message,
            &chosen,
            server_pub.bytes(),
            "10.0.0.2".to_string(),
            "255.255.255.0".to_string(),
            "fd00::2".to_string(),
            64,
            now_secs(),
            &request.public_key_data,
            &pake_key,
        )
        .expect("build response");

        server_socket
            .send_to(response.as_ref(), client_addr)
            .await
            .expect("send response");

        // Derive crypto so we can decrypt heartbeats / data from the client.
        let crypto = CryptoCore::new(
            server_priv,
            &chosen.algorithm_type,
            &request.public_key_data,
            Role::Responder,
            &pake_key,
        )
        .expect("crypto");

        // Wait for a heartbeat ping (ignore data packets if they arrive first).
        let mut got_ping = false;
        while !got_ping {
            let (len, from) = timeout(Duration::from_secs(15), server_socket.recv_from(&mut buf))
                .await
                .expect("heartbeat receive timeout")
                .expect("heartbeat recv");
            let packet = &buf[..len];
            if packet.is_empty() {
                continue;
            }
            match packet[0] {
                protocol::HEARTBEAT => {
                    let mut hb_buf = Buffer::new(0);
                    hb_buf
                        .write_all(&packet[1..])
                        .expect("write heartbeat payload");
                    let ping = protocol::parse_ping(&mut hb_buf, &crypto).expect("decrypt ping");

                    let mut pong_buf = Buffer::new(9);
                    protocol::build_heartbeat_pong(&mut pong_buf, &crypto, &server_id, ping.ts)
                        .expect("build pong");
                    server_socket
                        .send_to(pong_buf.as_ref(), from)
                        .await
                        .expect("send pong");
                    got_ping = true;
                }
                protocol::DATA_INTERFACE => {
                    // Data packets are accepted but not validated in this test.
                    let mut data_buf = Buffer::new(0);
                    let _ = data_buf.write_all(&packet[1..]);
                    let _ = crypto.decrypt(&mut data_buf);
                }
                _ => {}
            }
        }

        // Give the client a moment to process the pong before the test shuts down.
        sleep(Duration::from_millis(200)).await;
    });

    (server_addr, handle)
}
