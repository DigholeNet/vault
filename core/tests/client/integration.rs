// SPDX-License-Identifier: MIT
//! Public API integration tests: handshake, heartbeat and data flow against the shared
//! mock server (vault_core::test_utils).

use std::sync::Arc;
use std::time::Duration;

use tokio::sync::mpsc::UnboundedSender;
use tokio::time::timeout;
use vault_core::PeerId;
use vault_core::client::{ClientCallbacks, ClientConfig, ClientSession, TunnelSetup};
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
        assignment: vault_core::settings::TunnelAssignment,
        setup: Arc<TunnelSetup>,
    ) {
        let ipv4 = assignment.ipv4.expect("IPv4 assignment");
        let ipv6 = assignment.ipv6.expect("IPv6 assignment");
        let _ = self.events.send(Event::IpAssigned(
            ipv4.address.to_string(),
            ipv4.netmask.to_string(),
            ipv6.address.to_string(),
            ipv6.prefix_len.into(),
        ));
        setup.complete(Ok(()));
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
            managed_transport: false,
            peer_socket_setup: None,
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
    assert_eq!(session.connection_status().public_ip, "127.0.0.1");

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
    assert!(session.connection_status().public_ip.is_empty());
}

struct RejectConfiguration {
    errors: UnboundedSender<String>,
}

struct HoldSetup(UnboundedSender<Arc<TunnelSetup>>);

impl ClientCallbacks for HoldSetup {
    fn on_packets(&self, _: Vec<Vec<u8>>) {
        panic!("data delivered before configuration");
    }

    fn on_ip_assigned(&self, _: vault_core::settings::TunnelAssignment, setup: Arc<TunnelSetup>) {
        self.0.send(setup).unwrap();
    }

    fn on_error(&self, _: String) {}
}

#[tokio::test]
async fn late_setup() {
    let (server, handle) = run_mock_server("password").await;
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
    let session = ClientSession::start(
        ClientConfig {
            password: "password".into(),
            hosts: vec!["127.0.0.1".into()],
            port: server.port(),
            id: PeerId([6; 16]),
            device_name: String::new(),
            platform: "test".into(),
            managed_transport: false,
            peer_socket_setup: None,
            socket_protect: None,
        },
        Arc::new(HoldSetup(tx)),
    )
    .unwrap();
    let setup = timeout(Duration::from_secs(5), rx.recv())
        .await
        .unwrap()
        .unwrap();
    assert!(setup.is_pending());
    assert!(!session.is_active());
    session.reconnect().unwrap();
    timeout(Duration::from_secs(2), async {
        while setup.is_pending() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    assert!(!setup.complete(Ok(())));
    assert!(!session.is_active());
    session.shutdown().unwrap();
    handle.abort();
}

impl ClientCallbacks for RejectConfiguration {
    fn on_packets(&self, _: Vec<Vec<u8>>) {
        panic!("data delivered after rejected configuration");
    }
    fn on_ip_assigned(&self, _: vault_core::settings::TunnelAssignment, setup: Arc<TunnelSetup>) {
        setup.complete(Err("injected route configuration failure".into()));
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
            managed_transport: false,
            peer_socket_setup: None,
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
            managed_transport: false,
            peer_socket_setup: None,
            socket_protect: None,
        },
        Arc::new(TestCallbacks { events: tx }),
    )
    .unwrap();
    assert!(matches!(
        timeout(Duration::from_secs(5), rx.recv()).await.unwrap(),
        Some(Event::IpAssigned(..))
    ));
    timeout(Duration::from_secs(1), async {
        while !session.is_active() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
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
    session.reconnect().unwrap();
    for pause in [false, true] {
        if pause {
            session.pause_transport().unwrap();
            assert!(!session.is_active());
            assert!(matches!(
                session.write_packet(b"paused".to_vec()),
                Err(vault_core::client::ClientError::NotConnected)
            ));
            session.resume_transport().unwrap();
        }
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
            managed_transport: false,
            peer_socket_setup: None,
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
            managed_transport: false,
            peer_socket_setup: None,
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

#[tokio::test]
async fn routes_after_reconnect() {
    use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
    use vault_core::client::{PeerSocket, TransportPath, TransportRoutes};
    use vault_core::test_utils::run_mock_server_sessions;

    struct Platform {
        generation: AtomicU64,
        binds: Arc<AtomicUsize>,
        routes: UnboundedSender<TransportRoutes>,
        data: UnboundedSender<()>,
    }
    impl ClientCallbacks for Platform {
        fn resolve_transport(
            &self,
        ) -> Option<Result<TransportPath, vault_core::client::ClientError>> {
            let binds = self.binds.clone();
            Some(Ok(TransportPath {
                hosts: vec!["127.0.0.1".into()],
                generation: self.generation.load(Ordering::Acquire),
                prepare_socket: Arc::new(move |_, _, _| {
                    binds.fetch_add(1, Ordering::Relaxed);
                    Some(PeerSocket {
                        mtu: Arc::new(AtomicUsize::new(1427)),
                        lan_endpoint: None,
                        allow_lan: Arc::new(|_| false),
                        gateway: None,
                    })
                }),
            }))
        }

        fn on_transport_assigned(
            &self,
            assignment: vault_core::settings::TunnelAssignment,
            routes: Option<TransportRoutes>,
            setup: Arc<TunnelSetup>,
        ) {
            assert_eq!(assignment.ipv4.unwrap().address.to_string(), "10.0.0.2");
            self.routes.send(routes.unwrap()).unwrap();
            setup.complete(Ok(()));
        }

        fn on_ip_assigned(&self, _: vault_core::settings::TunnelAssignment, _: Arc<TunnelSetup>) {
            panic!("managed transports need route metadata");
        }

        fn on_packets(&self, _: Vec<Vec<u8>>) {
            self.data.send(()).unwrap();
        }

        fn on_error(&self, error: String) {
            panic!("{error}");
        }
    }

    let (server, handle) = run_mock_server_sessions("test-password", 3).await;
    let (routes, mut route_events) = tokio::sync::mpsc::unbounded_channel();
    let (data, mut data_events) = tokio::sync::mpsc::unbounded_channel();
    let platform = Arc::new(Platform {
        generation: AtomicU64::new(1),
        binds: Arc::new(AtomicUsize::new(0)),
        routes,
        data,
    });
    let session = ClientSession::start(
        ClientConfig {
            password: "test-password".into(),
            hosts: vec!["unresolvable.invalid".into()],
            port: server.port(),
            id: PeerId([4; 16]),
            device_name: String::new(),
            platform: "test".into(),
            managed_transport: true,
            peer_socket_setup: None,
            socket_protect: None,
        },
        platform.clone(),
    )
    .unwrap();
    for generation in [1, 2] {
        if generation == 2 {
            platform.generation.store(generation, Ordering::Release);
            session.reconnect().unwrap();
        }
        let routes = timeout(Duration::from_secs(5), route_events.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(routes.generation, generation);
        assert_eq!(routes.addresses, ["127.0.0.1"]);
        timeout(Duration::from_secs(5), data_events.recv())
            .await
            .unwrap()
            .unwrap();
    }
    // A retry on the same physical generation still binds the replacement
    // socket, while the applied routes can be reused.
    session.reconnect().unwrap();
    timeout(Duration::from_secs(5), data_events.recv())
        .await
        .unwrap()
        .unwrap();
    assert!(route_events.try_recv().is_err());
    assert_eq!(platform.binds.load(Ordering::Relaxed), 3);
    session.shutdown().unwrap();
    timeout(Duration::from_secs(5), handle)
        .await
        .unwrap()
        .unwrap();
}
