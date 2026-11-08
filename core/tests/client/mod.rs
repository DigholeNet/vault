// SPDX-License-Identifier: MIT
//! Unit tests loaded inside the client module to retain access to its internals.
mod metrics;

use super::*;

struct NoCallbacks;
impl ClientCallbacks for NoCallbacks {
    fn on_packets(&self, _: Vec<Vec<u8>>) {}
    fn on_ip_assigned(&self, _: String, _: String, _: String, _: i32) -> Result<(), String> {
        Ok(())
    }
    fn on_error(&self, _: String) {}
}

fn idle_session() -> ClientSession {
    ClientSession {
        inner: Arc::new(ClientInner {
            uplink: Arc::new(UplinkCounters::default()),
            config: ClientConfig {
                password: "test".into(),
                hosts: vec!["127.0.0.1".into()],
                port: 1,
                id: PeerId([1; 16]),
                device_name: String::new(),
                platform: String::new(),
                socket_protect: None,
            },
            callbacks: Arc::new(NoCallbacks),
            runtime: Arc::new(SessionRuntime::new().unwrap()),
            algorithms: Vec::new(),
            state: Arc::new(Mutex::new(ClientState::new())),
        }),
    }
}

#[tokio::test]
async fn network_change_shutdown() {
    let (stop_tx, mut stop_rx) = mpsc::channel(1);
    let (change_tx, mut change_rx) = mpsc::channel(1);
    let settling = ClientInner::settle_network_changes(&mut stop_rx, &mut change_rx);
    tokio::pin!(settling);
    assert!(
        tokio::time::timeout(Duration::from_millis(100), &mut settling)
            .await
            .is_err()
    );
    change_tx.send(()).await.unwrap();
    // This would have settled after another 200ms without the new event.
    assert!(
        tokio::time::timeout(Duration::from_millis(250), &mut settling)
            .await
            .is_err()
    );
    stop_tx.send(()).await.unwrap();
    assert!(
        !tokio::time::timeout(Duration::from_millis(100), &mut settling)
            .await
            .unwrap()
    );
}

#[test]
fn ipv6_multicast_filter() {
    let session = idle_session();
    let (tx, mut rx) = mpsc::channel(4);
    session.lock_state().unwrap().uplink_tx = Some(tx);
    let mut packet = vec![0; 40];
    packet[0] = 0x60;
    packet[24] = 0xff;
    session.write_packet(packet.clone()).unwrap();
    assert!(rx.try_recv().is_err());
    packet[24] = 0xfd;
    session.write_packet(packet.clone()).unwrap();
    assert_eq!(rx.try_recv().unwrap(), packet);
    packet[0] = 0x45;
    packet[24] = 0xff;
    session.write_packet(packet.clone()).unwrap();
    assert_eq!(rx.try_recv().unwrap(), packet);
}

#[test]
fn ipv6_resolution_order() {
    let mut session = idle_session();
    Arc::get_mut(&mut session.inner).unwrap().config.hosts =
        vec!["127.0.0.1".into(), "::1".into(), "[::1]".into()];
    let candidates = session
        .inner
        .runtime
        .block_on(session.inner.resolve_candidates())
        .unwrap();
    assert_eq!(
        candidates,
        vec![
            "[::1]:1".parse::<SocketAddr>().unwrap(),
            "127.0.0.1:1".parse().unwrap()
        ]
    );
}

#[test]
fn reconnect_handshake() {
    let server = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    server
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    let session = ClientSession::start(
        ClientConfig {
            password: "password".into(),
            hosts: vec!["127.0.0.1".into()],
            port: server.local_addr().unwrap().port(),
            id: PeerId([1; 16]),
            device_name: String::new(),
            platform: String::new(),
            socket_protect: None,
        },
        Arc::new(NoCallbacks),
    )
    .unwrap();
    let mut packet = [0u8; 4096];
    let (len, _) = server.recv_from(&mut packet).unwrap();
    let first = packet[..len].to_vec();
    session.reconnect().unwrap();
    let (len, _) = server.recv_from(&mut packet).unwrap();
    assert_eq!(packet[0], protocol::INIT);
    assert_ne!(first, packet[..len]); // Fresh PAKE/key material, no timeout wait.
    session.reconnect().unwrap();
    session.shutdown().unwrap();
    assert!(matches!(
        session.reconnect(),
        Err(ClientError::NotConnected)
    ));
    assert!(!session.is_active());
}

#[test]
fn reconnect_backoff() {
    let (attempt_tx, attempt_rx) = std::sync::mpsc::channel();
    let session = ClientSession::start(
        ClientConfig {
            password: "password".into(),
            hosts: vec!["127.0.0.1".into()],
            port: 1,
            id: PeerId([1; 16]),
            device_name: String::new(),
            platform: String::new(),
            socket_protect: Some(Arc::new(move |_| {
                let _ = attempt_tx.send(());
                false
            })),
        },
        Arc::new(NoCallbacks),
    )
    .unwrap();
    attempt_rx.recv_timeout(Duration::from_secs(2)).unwrap();
    attempt_rx.recv_timeout(Duration::from_secs(2)).unwrap();
    // The next ordinary attempt would wait two seconds.
    session.reconnect().unwrap();
    attempt_rx
        .recv_timeout(Duration::from_millis(750))
        .expect("network recovery bypasses backoff");
    session.shutdown().unwrap();
}

#[test]
fn cross_runtime_shutdown() {
    use std::sync::atomic::AtomicBool;
    let session = idle_session();
    let completed = Arc::new(AtomicBool::new(false));
    let done = completed.clone();
    let (started_tx, started_rx) = std::sync::mpsc::channel();
    let (release_tx, release_rx) = std::sync::mpsc::channel();
    let handle = session.inner.runtime.spawn(async move {
        started_tx.send(()).unwrap();
        // Model a synchronous platform callback already executing.
        release_rx.recv().unwrap();
        done.store(true, Ordering::SeqCst);
    });
    session.lock_state().unwrap().run_handle = Some(handle);
    started_rx.recv_timeout(Duration::from_secs(5)).unwrap();
    let state = session.inner.state.clone();
    let release = std::thread::spawn(move || {
        let deadline = Instant::now() + Duration::from_secs(5);
        while !state.lock().unwrap().is_closing && Instant::now() < deadline {
            std::thread::yield_now();
        }
        release_tx.send(()).unwrap();
    });
    let outer = Runtime::new().unwrap();
    outer.block_on(async {
        session.shutdown().unwrap();
    });
    assert!(completed.load(Ordering::SeqCst));
    assert!(!session.is_active());
    release.join().unwrap();
}

#[test]
fn unsent_packets() {
    let session = idle_session();
    assert!(matches!(
        session.write_packet(vec![1; 10]),
        Err(ClientError::NotConnected)
    ));
    let (tx, rx) = mpsc::channel(1);
    let queue_metrics = Arc::new(UplinkQueueMetrics::new(&tx));
    session.lock_state().unwrap().uplink_queue_metrics = Some(queue_metrics.clone());
    session.lock_state().unwrap().uplink_tx = Some(tx);
    session.write_packet(vec![1; 10]).unwrap();
    session.write_packet(vec![1; 10]).unwrap();
    let queue = queue_metrics.queue.snapshot();
    assert_eq!((queue.depth, queue.peak, queue.capacity), (1, 1, 1));
    drop(rx);
    assert!(matches!(
        session.write_packet(vec![1; 10]),
        Err(ClientError::NotConnected)
    ));
    let stats = session.traffic_stats();
    assert_eq!((stats.bytes_sent, stats.packets_sent), (0, 0));
    assert_eq!(session.inner.uplink.queue_drops.load(Ordering::Relaxed), 1);
    assert_eq!(
        session.inner.uplink.not_connected.load(Ordering::Relaxed),
        2
    );
}

fn crypto() -> Arc<CryptoCore> {
    Arc::new(crypto_pair().0)
}

fn crypto_pair() -> (CryptoCore, CryptoCore) {
    let (private, public) = create_ecdh_keypair().unwrap();
    let (peer_private, peer_public) = create_ecdh_keypair().unwrap();
    (
        CryptoCore::new(
            private,
            &crate::AlgorithmType::Aes128Gcm,
            peer_public.bytes(),
            Role::Initiator,
            b"test",
        )
        .unwrap(),
        CryptoCore::new(
            peer_private,
            &crate::AlgorithmType::Aes128Gcm,
            public.bytes(),
            Role::Responder,
            b"test",
        )
        .unwrap(),
    )
}

#[test]
fn packet_reuse() {
    let (sender, receiver) = crypto_pair();
    let mut wire = Buffer::new(EXTRA_LEN + 1);
    for len in [0, 1, 64, 1_400, 65_507 - 1 - EXTRA_LEN - crate::TAG_LEN] {
        let expected: Vec<u8> = (0..len).map(|index| index as u8).collect();
        wire.clear();
        wire.write_all(&expected).unwrap();
        protocol::build_data_interface(&mut wire, &sender).unwrap();
        let mut packet = wire.as_ref().to_vec();
        let pointer = packet.as_ptr();
        let capacity = packet.capacity();

        decrypt_packet(&receiver, &mut packet).unwrap();

        assert_eq!(packet, expected);
        assert_eq!(
            packet.as_ptr(),
            pointer,
            "delivery must retain the receive allocation"
        );
        assert_eq!(packet.capacity(), capacity);
    }
    assert!(decrypt_packet(&receiver, &mut Vec::new()).is_err());
}

#[tokio::test]
async fn uplink_accounting() {
    let destination = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let counters = Arc::new(UplinkCounters::default());
    let (tx, rx) = mpsc::channel(2);
    let queue_metrics = Arc::new(UplinkQueueMetrics::new(&tx));
    tx.send(vec![1; 10]).await.unwrap();
    tx.send(vec![1; 65_535]).await.unwrap();
    drop(tx);
    ClientInner::run_uplink_loop(
        socket,
        crypto(),
        destination.local_addr().unwrap(),
        rx,
        counters.clone(),
        queue_metrics,
        1,
    )
    .await;
    let mut buf = [0; 128];
    tokio::time::timeout(Duration::from_secs(1), destination.recv_from(&mut buf))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(counters.bytes_sent.load(Ordering::Relaxed), 10);
    assert_eq!(counters.packets_sent.load(Ordering::Relaxed), 1);
    assert_eq!(counters.build_failures.load(Ordering::Relaxed), 1);
}

#[tokio::test]
async fn udp_send_failure() {
    let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let counters = Arc::new(UplinkCounters::default());
    let (tx, rx) = mpsc::channel(1);
    let queue_metrics = Arc::new(UplinkQueueMetrics::new(&tx));
    tx.send(vec![1; 10]).await.unwrap();
    drop(tx);
    // IPv6 destination on an IPv4 socket fails without external traffic.
    ClientInner::run_uplink_loop(
        socket,
        crypto(),
        "[::1]:1".parse().unwrap(),
        rx,
        counters.clone(),
        queue_metrics,
        1,
    )
    .await;
    assert_eq!(counters.bytes_sent.load(Ordering::Relaxed), 0);
    assert_eq!(counters.packets_sent.load(Ordering::Relaxed), 0);
    assert_eq!(counters.send_failures.load(Ordering::Relaxed), 1);
}
