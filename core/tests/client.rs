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

    fn on_ip_assigned(
        &self,
        ipv4: String,
        ipv4_mask: String,
        ipv6: String,
        ipv6_prefixlen: i32,
    ) -> Result<(), String> {
        let _ = self
            .events
            .send(Event::IpAssigned(ipv4, ipv4_mask, ipv6, ipv6_prefixlen));
        Ok(())
    }

    fn on_error(&self, error: String) {
        let _ = self.events.send(Event::Error(error));
    }
}

#[tokio::test]
async fn handshake_heartbeat_data() {
    let password = "test-password";
    let (server_addr, server_handle) = run_mock_server(password).await;

    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
    let callbacks: Arc<dyn ClientCallbacks> = Arc::new(TestCallbacks { events: tx });

    let session = ClientSession::start(
        ClientConfig {
            password: password.to_string(),
            hosts: vec!["127.0.0.1".to_string()],
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

    timeout(Duration::from_secs(1), async {
        while !session.is_active() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("session becomes active after platform setup");

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

struct RejectConfiguration {
    errors: UnboundedSender<String>,
}

impl ClientCallbacks for RejectConfiguration {
    fn on_packets(&self, _: Vec<Vec<u8>>) {
        panic!("data delivered after rejected configuration");
    }
    fn on_ip_assigned(&self, _: String, _: String, _: String, _: i32) -> Result<(), String> {
        Err("injected route configuration failure".into())
    }
    fn on_error(&self, error: String) {
        let _ = self.errors.send(error);
    }
}

#[tokio::test]
async fn failed_config_never_activates() {
    let (server, handle) = run_mock_server("password").await;
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
    let session = ClientSession::start(
        ClientConfig {
            password: "password".into(),
            hosts: vec!["127.0.0.1".into()],
            port: server.port(),
            id: PeerId([2; 16]),
            device_name: String::new(),
            platform: "linux".into(),
            socket_protect: None,
        },
        Arc::new(RejectConfiguration { errors: tx }),
    )
    .unwrap();
    let error = timeout(Duration::from_secs(15), rx.recv())
        .await
        .unwrap()
        .unwrap();
    assert!(
        error.contains("injected route configuration failure"),
        "{error}"
    );
    assert!(!session.is_active());
    assert!(session.write_packet(vec![1; 20]).is_err());
    tokio::task::spawn_blocking(move || session.shutdown().unwrap())
        .await
        .unwrap();
    handle.abort();
    let _ = handle.await;
}

#[tokio::test]
async fn reconnect_session() {
    let (server, handle) = vault_core::test_utils::run_mock_server_sessions("password", 3).await;
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
    let session = ClientSession::start(
        ClientConfig {
            password: "password".into(),
            hosts: vec!["127.0.0.1".into()],
            port: server.port(),
            id: PeerId([3; 16]),
            device_name: String::new(),
            platform: "test".into(),
            socket_protect: None,
        },
        Arc::new(TestCallbacks { events: tx }),
    )
    .unwrap();
    assert!(matches!(
        timeout(Duration::from_secs(5), rx.recv()).await.unwrap(),
        Some(Event::IpAssigned(..))
    ));
    session.write_packet(b"before recovery".to_vec()).unwrap();
    timeout(Duration::from_secs(2), async {
        while session.traffic_stats().bytes_sent == 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    assert!(matches!(
        timeout(Duration::from_secs(5), rx.recv()).await.unwrap(),
        Some(Event::Data)
    ));
    let bytes = session.traffic_stats().bytes_sent;
    let mut generation = session.connection_status().generation;
    assert!(generation > 0);
    for _ in 0..2 {
        session.reconnect().unwrap();
        // Each authenticated session resumes data without another IP callback.
        assert!(matches!(
            timeout(Duration::from_secs(5), rx.recv()).await.unwrap(),
            Some(Event::Data)
        ));
        let status = session.connection_status();
        assert!(status.connected);
        assert!(status.generation > generation);
        generation = status.generation;
        assert!(session.traffic_stats().bytes_sent >= bytes);
    }
    timeout(Duration::from_secs(5), handle)
        .await
        .unwrap()
        .unwrap();
    session.shutdown().unwrap();
}

/// Happy-Eyeballs race: the first candidate (127.0.0.2, nothing listening)
/// would take the full handshake timeout to fail, but the second candidate
/// is staggered by 300ms and must win long before that.
#[tokio::test]
async fn handshake_race_fallback() {
    let password = "test-password";
    let (server_addr, server_handle) = run_mock_server(password).await;

    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
    let callbacks: Arc<dyn ClientCallbacks> = Arc::new(TestCallbacks { events: tx });

    let session = ClientSession::start(
        ClientConfig {
            password: password.to_string(),
            hosts: vec!["127.0.0.2".into(), "127.0.0.1".into()],
            port: server_addr.port(),
            id: PeerId([4u8; 16]),
            device_name: "test-device".to_string(),
            platform: "test".to_string(),
            socket_protect: None,
        },
        callbacks,
    )
    .expect("start session");

    // Well under the 5s single-candidate handshake timeout.
    let event = timeout(Duration::from_secs(4), rx.recv())
        .await
        .expect("timeout waiting for raced handshake")
        .expect("callback channel closed");
    match event {
        Event::IpAssigned(ipv4, ..) => assert_eq!(ipv4, "10.0.0.2"),
        Event::Error(e) => panic!("unexpected error: {}", e),
        other => panic!("unexpected event: {:?}", other),
    }

    server_handle.abort();
    let _ = server_handle.await;
    session.shutdown().expect("shutdown");
}

/// A real lease change notifies the platform once; transport retries alone do not.
#[tokio::test]
async fn reconnect_reports_changed_lease() {
    let (server, handle) = vault_core::test_utils::run_mock_server_leases(
        "password",
        vec!["10.0.0.2".into(), "10.0.0.3".into(), "10.0.0.3".into()],
    )
    .await;
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
    let session = ClientSession::start(
        ClientConfig {
            password: "password".into(),
            hosts: vec!["127.0.0.1".into()],
            port: server.port(),
            id: PeerId([5; 16]),
            device_name: String::new(),
            platform: "test".into(),
            socket_protect: None,
        },
        Arc::new(TestCallbacks { events: tx }),
    )
    .unwrap();
    assert!(matches!(
        timeout(Duration::from_secs(5), rx.recv()).await.unwrap(),
        Some(Event::IpAssigned(..))
    ));
    assert!(matches!(
        timeout(Duration::from_secs(5), rx.recv()).await.unwrap(),
        Some(Event::Data)
    ));
    session.reconnect().unwrap();
    match timeout(Duration::from_secs(5), rx.recv()).await.unwrap() {
        Some(Event::IpAssigned(ipv4, ..)) => assert_eq!(ipv4, "10.0.0.3"),
        other => panic!("expected updated lease, got {other:?}"),
    }
    assert!(matches!(
        timeout(Duration::from_secs(5), rx.recv()).await.unwrap(),
        Some(Event::Data)
    ));
    assert!(session.is_active());
    session.reconnect().unwrap();
    // The updated lease is cached too: it must not be reported again.
    assert!(matches!(
        timeout(Duration::from_secs(5), rx.recv()).await.unwrap(),
        Some(Event::Data)
    ));
    session.shutdown().unwrap();
    handle.abort();
    let _ = handle.await;
}
