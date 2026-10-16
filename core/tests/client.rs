// SPDX-License-Identifier: MIT
//! Integration test: handshake, heartbeat and data flow against the shared
//! mock server (vault_core::test_utils).

use std::sync::Arc;
use std::time::Duration;

use tokio::sync::mpsc::UnboundedSender;
use tokio::time::timeout;
use vault_core::PeerId;
use vault_core::client::{ClientCallbacks, ClientConfig, ClientSession};
use vault_core::test_utils::run_mock_server;

#[derive(Debug)]
enum Event {
    Data,
    IpAssigned(String, String, String, i32),
    Error(String),
}

struct TestCallbacks {
    events: UnboundedSender<Event>,
}

impl ClientCallbacks for TestCallbacks {
    fn on_packets(&self, packets: Vec<Vec<u8>>) {
        for _ in &packets {
            let _ = self.events.send(Event::Data);
        }
    }

    fn on_ip_assigned(&self, ipv4: String, ipv4_mask: String, ipv6: String, ipv6_prefixlen: i32) {
        let _ = self
            .events
            .send(Event::IpAssigned(ipv4, ipv4_mask, ipv6, ipv6_prefixlen));
    }

    fn on_error(&self, error: String) {
        let _ = self.events.send(Event::Error(error));
    }
}

#[tokio::test]
async fn full_handshake_heartbeat_and_data() {
    let password = "test-password";
    let (server_addr, server_handle) = run_mock_server(password).await;

    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
    let callbacks: Arc<dyn ClientCallbacks> = Arc::new(TestCallbacks { events: tx });

    let session = ClientSession::start(
        ClientConfig {
            password: password.to_string(),
            host: "127.0.0.1".to_string(),
            port: server_addr.port(),
            id: PeerId([1u8; 16]),
            device_name: "test-device".to_string(),
            platform: "linux".to_string(),
            socket_protect: None,
        },
        callbacks,
    )
    .expect("start session");

    // Wait for IP assignment from the handshake response.
    let event = timeout(Duration::from_secs(15), rx.recv())
        .await
        .expect("timeout waiting for IP assignment")
        .expect("callback channel closed");

    match event {
        Event::IpAssigned(ipv4, mask, ipv6, prefixlen) => {
            assert_eq!(ipv4, "10.0.0.2");
            assert_eq!(mask, "255.255.255.0");
            assert_eq!(ipv6, "fd00::2");
            assert_eq!(prefixlen, 64);
        }
        Event::Error(e) => panic!("unexpected error: {}", e),
        other => panic!("unexpected event: {:?}", other),
    }

    assert!(session.is_active());

    // Send an encrypted data packet through the tunnel.
    session
        .write_packet(b"hello rust".to_vec())
        .expect("write data");

    // Ensure the mock server saw the heartbeat and completed cleanly.
    timeout(Duration::from_secs(20), server_handle)
        .await
        .expect("server timeout")
        .expect("server task panicked");

    session.shutdown().expect("shutdown");
    assert!(!session.is_active());
}
