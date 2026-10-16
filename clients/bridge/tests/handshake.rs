// SPDX-License-Identifier: MIT
//! Integration test for the UniFFI-facing RustEdge API against the shared
//! mock server (vault_core::test_utils).

use std::time::Duration;

use tokio::sync::mpsc::UnboundedSender;
use tokio::time::timeout;
use vault_bridge::{EdgeCallbacks, RustEdge};
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

impl EdgeCallbacks for TestCallbacks {
    fn on_data(&self, _data: Vec<u8>) {
        let _ = self.events.send(Event::Data);
    }

    fn on_data_batch(&self, packets: Vec<Vec<u8>>) {
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

    fn protect_socket(&self, _fd: i32) -> bool {
        true
    }
}

#[tokio::test]
async fn full_handshake_heartbeat_and_data() {
    let password = "test-password";
    let (server_addr, server_handle) = run_mock_server(password).await;

    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
    let callbacks = Box::new(TestCallbacks { events: tx });
    let id = vec![1u8; 16];

    let edge = RustEdge::new(
        password.to_string(),
        "127.0.0.1".to_string(),
        server_addr.port() as i32,
        id,
        "test-device".to_string(),
        "linux".to_string(),
        callbacks,
    )
    .expect("create RustEdge");

    edge.connect().expect("start connect");

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

    // Send an encrypted data packet through the tunnel.
    edge.write_data(b"hello rust".to_vec()).expect("write data");

    // Ensure the mock server saw the heartbeat and completed cleanly.
    timeout(Duration::from_secs(20), server_handle)
        .await
        .expect("server timeout")
        .expect("server task panicked");

    edge.shutdown().expect("shutdown");
}
