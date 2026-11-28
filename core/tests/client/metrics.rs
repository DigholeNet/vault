// SPDX-License-Identifier: MIT
//! Exercise metrics through actual UDP receive/decrypt/callback work, not
//! just the counter helpers. Subscribers are scoped to each data-loop future.

use crate::client::*;
use std::collections::BTreeMap;
use std::fmt;
use tracing::field::{Field, Visit};
use tracing::instrument::WithSubscriber;
use tracing_subscriber::layer::{Context, SubscriberExt};
use tracing_subscriber::{Layer, Registry};

type Fields = BTreeMap<String, String>;

#[derive(Clone, Default)]
struct DownlinkEvents(Arc<Mutex<Vec<Fields>>>);

impl Layer<Registry> for DownlinkEvents {
    fn on_event(&self, event: &tracing::Event<'_>, _: Context<'_, Registry>) {
        #[derive(Default)]
        struct FieldsVisitor(Fields);
        impl Visit for FieldsVisitor {
            fn record_debug(&mut self, field: &Field, value: &dyn fmt::Debug) {
                self.0.insert(field.name().to_owned(), format!("{value:?}"));
            }
        }
        let mut fields = FieldsVisitor::default();
        event.record(&mut fields);
        if fields.0.get("message").map(String::as_str) == Some("VPN downlink metrics") {
            self.0.lock().unwrap().push(fields.0);
        }
    }
}

impl DownlinkEvents {
    fn snapshots(&self) -> Vec<Fields> {
        self.0.lock().unwrap().clone()
    }
}

struct DeliveryCallbacks {
    delivered: mpsc::UnboundedSender<Vec<Vec<u8>>>,
    delay: Duration,
    errors: Option<mpsc::UnboundedSender<String>>,
}

impl ClientCallbacks for DeliveryCallbacks {
    fn on_packets(&self, packets: Vec<Vec<u8>>) {
        // Model synchronous platform TUN work, whose cost should appear in
        // callback metrics rather than in cryptographic failure counters.
        std::thread::sleep(self.delay);
        self.delivered.send(packets).unwrap();
    }

    fn on_ip_assigned(&self, _: crate::settings::TunnelAssignment, setup: Arc<TunnelSetup>) {
        setup.complete(Ok(()));
    }

    fn on_error(&self, error: String) {
        if let Some(errors) = &self.errors {
            errors.send(error).unwrap();
        } else {
            panic!("unexpected data-loop error: {error}");
        }
    }
}

struct DataLoop {
    inner: Arc<ClientInner>,
    task: JoinHandle<()>,
    stop: Option<tokio::sync::oneshot::Sender<()>>,
    server: UdpSocket,
    client_address: SocketAddr,
    sender_crypto: CryptoCore,
    delivered: mpsc::UnboundedReceiver<Vec<Vec<u8>>>,
    events: DownlinkEvents,
}

impl DataLoop {
    async fn start() -> Self {
        Self::start_with_errors(None).await
    }

    async fn start_with_errors(errors: Option<mpsc::UnboundedSender<String>>) -> Self {
        let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let client_address = socket.local_addr().unwrap();
        let server_address = server.local_addr().unwrap();
        let (receiver_crypto, sender_crypto) =
            crate::crypto::test_crypto_pair(&crate::AlgorithmType::Aes128Gcm, b"metrics-test-key");
        let receiver_crypto = Arc::new(receiver_crypto);
        let (delivered_tx, delivered) = mpsc::unbounded_channel();
        let inner = Arc::new(ClientInner {
            uplink: Arc::new(UplinkCounters::default()),
            resolving_transport: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            config: ClientConfig {
                password: String::new(),
                hosts: vec!["127.0.0.1".into()],
                port: server_address.port(),
                id: PeerId([3; 16]),
                device_name: String::new(),
                platform: String::new(),
                managed_transport: false,
                peer_socket_setup: None,
                socket_protect: None,
            },
            callbacks: Arc::new(DeliveryCallbacks {
                delivered: delivered_tx,
                delay: Duration::from_millis(2),
                errors,
            }),
            runtime: Arc::new(SessionRuntime::new().unwrap()),
            algorithms: Vec::new(),
            state: Arc::new(Mutex::new(ClientState::new())),
        });
        let events = DownlinkEvents::default();
        let subscriber = tracing_subscriber::registry().with(events.clone());
        let running = inner.clone();
        let (stop_tx, stop_rx) = tokio::sync::oneshot::channel();
        let task = tokio::spawn(
            async move {
                // Drop the data future while the scoped subscriber is still
                // entered. Tokio task.abort drops outside WithSubscriber's
                // poll scope; production uses a global subscriber instead.
                tokio::select! {
                    _ = running.run_data_loop(socket, receiver_crypto, server_address, 17, None) => {}
                    _ = stop_rx => {}
                }
            }
            .with_subscriber(subscriber),
        );
        Self {
            inner,
            task,
            stop: Some(stop_tx),
            server,
            client_address,
            sender_crypto,
            delivered,
            events,
        }
    }

    fn data_packet(&self, data: &[u8]) -> Vec<u8> {
        let mut packet = Buffer::new(EXTRA_LEN + 1);
        packet.write_all(data).unwrap();
        protocol::build_data_interface(&mut packet, &self.sender_crypto).unwrap();
        packet.as_ref().to_vec()
    }

    async fn send(&self, corrupt: bool) {
        let mut packet = self.data_packet(&[0x45; 64]);
        if corrupt {
            // Invalid AEAD tag with a fresh nonce: must be counted as a
            // decryption failure and never delivered to the platform.
            *packet.last_mut().unwrap() ^= 1;
        }
        self.send_raw(&packet).await;
    }

    async fn send_raw(&self, packet: &[u8]) {
        self.server
            .send_to(packet, self.client_address)
            .await
            .unwrap();
    }

    async fn wait_for_delivery(&mut self) {
        assert_eq!(
            tokio::time::timeout(Duration::from_millis(500), self.delivered.recv())
                .await
                .expect("local UDP packet should be delivered promptly"),
            Some(vec![vec![0x45; 64]])
        );
    }

    async fn stop(mut self) -> Vec<Fields> {
        self.stop.take().unwrap().send(()).unwrap();
        let _ = (&mut self.task).await;
        self.inner.clear_connection().await;
        self.events.snapshots()
    }
}

impl Drop for DataLoop {
    fn drop(&mut self) {
        self.task.abort();
        let inner = self.inner.clone();
        self.inner
            .runtime
            .spawn(async move { inner.clear_connection().await });
    }
}

fn number(fields: &Fields, name: &str) -> f64 {
    fields
        .get(name)
        .unwrap_or_else(|| panic!("missing metric {name}: {fields:?}"))
        .parse()
        .unwrap()
}

async fn rejection_timeout(keep_receiving: bool) {
    let (errors_tx, mut errors) = mpsc::unbounded_channel();
    let mut data_loop = DataLoop::start_with_errors(Some(errors_tx)).await;
    let started = Instant::now();
    data_loop.send_raw(&[protocol::REJECTED]).await;
    let mut traffic = interval(Duration::from_millis(10));
    let error = tokio::time::timeout(Duration::from_secs(6), async {
        loop {
            tokio::select! {
                error = errors.recv() => break error,
                _ = traffic.tick(), if keep_receiving => {
                    // Repeated unauthenticated packets must neither refresh
                    // liveness nor restart the three-second rejection window.
                    data_loop.send_raw(&[protocol::REJECTED]).await;
                }
            }
        }
    })
    .await
    .expect("rejected sessions must exit even while UDP packets keep arriving");
    assert_eq!(error.as_deref(), Some("session rejected by server"));
    assert!(started.elapsed() >= Duration::from_secs(3));
    tokio::time::timeout(Duration::from_secs(1), &mut data_loop.task)
        .await
        .expect("data loop should finish after reporting rejection")
        .unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rejected_idle() {
    rejection_timeout(false).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rejected_busy() {
    rejection_timeout(true).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rejection_cleared() {
    let (errors_tx, mut errors) = mpsc::unbounded_channel();
    let mut data_loop = DataLoop::start_with_errors(Some(errors_tx)).await;
    data_loop.send_raw(&[protocol::REJECTED]).await;
    data_loop.send(false).await;
    data_loop.wait_for_delivery().await;
    // Wait beyond the rejection deadline. Authenticated traffic proves the
    // existing session is alive even if the server previously sent REJECTED.
    assert!(
        tokio::time::timeout(Duration::from_secs(4), errors.recv())
            .await
            .is_err()
    );
    data_loop.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn periodic_report() {
    let mut data_loop = DataLoop::start().await;
    let started = Instant::now();
    // Failures retain the short reporting window even though healthy
    // traffic now emits only a thirty-second summary.
    data_loop.send(true).await;
    // There is never a one-second idle gap: the old sleep recreated inside
    // select would not fire until after this entire stream had ended.
    for _ in 0..65 {
        data_loop.send(false).await;
        data_loop.wait_for_delivery().await;
        sleep(Duration::from_millis(100)).await;
    }
    assert!(started.elapsed() >= Duration::from_secs(6));
    let periodic = data_loop.events.snapshots();
    let report = periodic
        .iter()
        .find(|fields| fields.get("final_window").map(String::as_str) == Some("false"))
        .expect("metrics must be emitted while packets keep arriving, before cancellation");
    assert_eq!(number(report, "generation"), 17.0);
    assert!(number(report, "elapsed_s") >= 5.0);
    assert!(number(report, "decrypted_packets") > 0.0);
    assert!(number(report, "batches") > 0.0);
    assert_eq!(number(report, "decrypt_failures"), 1.0);
    assert!(number(report, "callback_avg_ms") >= 1.0);
    assert!(number(report, "callback_max_ms") >= number(report, "callback_avg_ms"));

    let reports = data_loop.stop().await;
    let packets: f64 = reports
        .iter()
        .map(|fields| number(fields, "decrypted_packets"))
        .sum();
    assert_eq!(
        packets, 65.0,
        "periodic and final windows must not lose or recount packets"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn final_report() {
    let mut data_loop = DataLoop::start().await;
    data_loop.send(true).await;
    data_loop.send(false).await;
    data_loop.wait_for_delivery().await;
    // The one-packet successful callback proves both datagrams have been
    // processed by the serial receive/decrypt path before cancellation.
    let reports = data_loop.stop().await;
    assert_eq!(
        reports.len(),
        1,
        "short sessions should have one final window"
    );
    let report = &reports[0];
    assert_eq!(report.get("final_window").map(String::as_str), Some("true"));
    assert_eq!(number(report, "decrypted_packets"), 1.0);
    assert_eq!(number(report, "payload_bytes"), 64.0);
    assert_eq!(number(report, "decrypt_failures"), 1.0);
    assert_eq!(number(report, "batches"), 1.0);
    assert_eq!(number(report, "batch_packets_max"), 1.0);
    assert!(number(report, "callback_avg_ms") >= 1.0);
}

#[tokio::test]
async fn center_queue_reserve() {
    let (sender, mut receiver) = mpsc::channel(DOWNLINK_CENTER_RESERVE + 1);
    let metrics = ReceiveMetrics::new(&sender);
    assert!(try_enqueue_peer(&sender, &metrics, || 1));
    assert!(try_enqueue_peer(&sender, &metrics, || panic!(
        "peer queue full"
    )));
    assert_eq!(sender.capacity(), DOWNLINK_CENTER_RESERVE);
    assert!(enqueue_downlink(&sender, &metrics, 2).await);
    assert_eq!(receiver.recv().await, Some(1));
    assert_eq!(receiver.recv().await, Some(2));
    drop(receiver);
    assert!(!try_enqueue_peer(&sender, &metrics, || 3));
}

#[tokio::test]
async fn queue_backpressure() {
    use std::future::{Future, poll_fn};
    use std::task::Poll;

    let (sender, mut receiver) = mpsc::channel(1);
    let metrics = ReceiveMetrics::new(&sender);
    assert!(enqueue_downlink(&sender, &metrics, vec![1]).await);
    let pending = enqueue_downlink(&sender, &metrics, vec![2, 3, 4]);
    tokio::pin!(pending);
    assert!(poll_fn(|cx| Poll::Ready(pending.as_mut().poll(cx).is_pending())).await);
    // Waiting has started, but completed-wait counters must not increment
    // until channel space is available and the original packet is enqueued.
    assert_eq!(metrics.snapshot().waits, 0);
    assert_eq!(receiver.recv().await, Some(vec![1]));
    assert!(pending.await);
    assert_eq!(receiver.recv().await, Some(vec![2, 3, 4]));

    let report = metrics.snapshot();
    assert_eq!(report.waits, 1);
    assert_eq!(report.queue.peak, 1);
    assert_eq!(report.queue.depth, 0);
    assert_eq!(report.receive_errors, 0);
    assert_eq!(report.wait_max_ms, report.wait_total_ms);
    let next = metrics.snapshot();
    assert_eq!(next.waits, 0);
    assert_eq!(next.wait_total_ms, 0.0);
    assert_eq!(next.wait_max_ms, 0.0);
    assert_eq!(next.queue.peak, 0);

    drop(receiver);
    assert!(!enqueue_downlink(&sender, &metrics, vec![5]).await);
    assert_eq!(metrics.snapshot().receive_errors, 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mixed_delivery() {
    let mut data_loop = DataLoop::start().await;

    // A pong must still use the control-packet parser and refresh liveness,
    // without being delivered as IP data by the new in-place data path.
    let before_pong = Instant::now() - Duration::from_secs(1);
    data_loop.inner.state.lock().unwrap().last_pong = before_pong;
    let mut pong = Buffer::new(EXTRA_LEN + 1);
    protocol::build_heartbeat_pong(
        &mut pong,
        &data_loop.sender_crypto,
        &PeerId([3; 16]),
        current_ts(),
        None,
    )
    .unwrap();
    data_loop.send_raw(pong.as_ref()).await;
    tokio::time::timeout(Duration::from_secs(1), async {
        while data_loop.inner.state.lock().unwrap().last_pong == before_pong {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("authenticated pong should refresh liveness");
    assert!(data_loop.delivered.try_recv().is_err());

    // More than a full batch, with distinct lengths and contents. Include
    // empty plaintext to check that trimming the wire header/tag is exact.
    let expected: Vec<_> = (0..=DATA_BATCH_CAPACITY)
        .map(|index| vec![index as u8; index * 13])
        .collect();
    let first = data_loop.data_packet(&expected[0]);
    data_loop.send_raw(&first).await;
    data_loop.send_raw(&first).await; // Replay must not reach the callback.
    data_loop.send_raw(&[protocol::DATA_INTERFACE]).await;

    let genuine = data_loop.data_packet(&expected[1]);
    let mut forged = genuine.clone();
    *forged.last_mut().unwrap() ^= 1;
    data_loop.send_raw(&forged).await;
    // Authentication failure must not consume the genuine packet's nonce.
    data_loop.send_raw(&genuine).await;
    for data in &expected[2..] {
        data_loop.send_raw(&data_loop.data_packet(data)).await;
    }

    let mut delivered = Vec::new();
    tokio::time::timeout(Duration::from_secs(2), async {
        while delivered.len() < expected.len() {
            let batch = data_loop.delivered.recv().await.unwrap();
            assert!(!batch.is_empty() && batch.len() <= DATA_BATCH_CAPACITY);
            delivered.extend(batch);
        }
    })
    .await
    .expect("all authenticated data should be delivered");
    assert_eq!(delivered, expected);

    let reports = data_loop.stop().await;
    let total = |field| {
        reports
            .iter()
            .map(|report| number(report, field))
            .sum::<f64>()
    };
    assert_eq!(total("decrypted_packets"), expected.len() as f64);
    assert_eq!(
        total("payload_bytes"),
        expected.iter().map(Vec::len).sum::<usize>() as f64
    );
    assert_eq!(total("decrypt_failures"), 3.0);
    assert!(
        reports
            .iter()
            .all(|report| number(report, "batch_packets_max") <= DATA_BATCH_CAPACITY as f64)
    );
}

#[tokio::test]
async fn mixed_path_batch() {
    use crate::protocol::{
        FindPeerRequest, PeerInfo, find_peer_message::Data, find_peer_request::Target,
    };

    let local = PeerKeyPair::generate().unwrap();
    let local_public = local.public;
    let local_id = PeerId([3; 16]);
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let endpoint = socket.local_addr().unwrap();
    let mut discovery = Discovery::new(
        crate::settings::TunnelAssignment::new("10.0.0.2", "255.255.255.0", "", 0).unwrap(),
        local_id,
        1,
        local,
        "192.0.2.1:9527".parse().unwrap(),
    );
    discovery.enable_direct(PeerSocket {
        mtu: Arc::new(AtomicUsize::new(1427)),
        lan_endpoint: None,
        allow_lan: Arc::new(|_| false),
        gateway: None,
    });
    discovery.confirm();
    let peer = PeerId([4; 16]);
    let key = PeerKeyPair::generate().unwrap();
    let introduce = |discovery: &mut Discovery, revision: u64, pair: [u8; 16]| {
        let info = PeerInfo {
            pair_id: pair.to_vec(),
            revision,
            local_session_epoch: 1,
            peer_session_epoch: 2,
            peer_id: peer.0.to_vec(),
            peer_public_key: key.public.to_vec(),
            peer_vpn_ips: vec!["10.0.0.3".parse::<std::net::IpAddr>().unwrap().into()],
            observed_endpoint: Some(endpoint.into()),
            valid_for_ms: 60_000,
            ..Default::default()
        };
        assert!(
            discovery
                .receive(
                    Data::Request(FindPeerRequest {
                        request_id: revision,
                        target: Some(Target::Peer(info)),
                        ..Default::default()
                    }),
                    Instant::now()
                )
                .unwrap()
                .is_some()
        );
        let crypto = key
            .derive(pair, (peer, 2), (local_id, 1, local_public))
            .unwrap();
        let mut buffer = Buffer::new(EXTRA_LEN + protocol::REGISTER_HEADER);
        protocol::build_peer_register(
            &mut buffer,
            &crypto,
            &protocol::register_header(peer, local_id),
            protocol::peer_register_message::Data::Request(protocol::PeerRegisterRequest {
                cookie: 1,
            }),
            protocol::REGISTER_MIN,
        )
        .unwrap();
        let mut packet = buffer.as_ref().to_vec();
        discovery.receive_direct(&socket, &mut buffer, endpoint, &mut packet, Instant::now());
    };
    introduce(&mut discovery, 1, [1; 16]);
    let discovery = Arc::new(Mutex::new(discovery));
    let mut state = ClientState::new();
    state.discovery = Some(discovery.clone());
    let packets = vec![vec![1], vec![2, 2], vec![3]];
    let direct = [
        None,
        Some(DirectAuthorization {
            peer,
            pair: [1; 16],
            endpoint,
        }),
        None,
    ];
    let mut batch = packets.clone();
    state.commit_downlink(&mut batch, &direct, Some(&discovery));
    assert_eq!(batch, packets);
    assert_eq!(state.direct_bytes_received.load(Ordering::Relaxed), 2);

    introduce(&mut discovery.lock().unwrap(), 2, [2; 16]);
    state.commit_downlink(&mut batch, &direct, Some(&discovery));
    assert_eq!(batch, [vec![1], vec![3]]);

    let current = [
        None,
        Some(DirectAuthorization {
            peer,
            pair: [2; 16],
            endpoint,
        }),
        None,
    ];
    state.network_changed();
    let mut batch = packets;
    state.commit_downlink(&mut batch, &current, Some(&discovery));
    assert_eq!(batch, [vec![1], vec![3]]);
    assert_eq!(state.direct_bytes_received.load(Ordering::Relaxed), 2);
    assert_eq!(state.bytes_received.load(Ordering::Relaxed), 8);
    assert_eq!(state.packets_received.load(Ordering::Relaxed), 7);
}
