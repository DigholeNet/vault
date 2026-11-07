// SPDX-License-Identifier: MIT
//! Exercise metrics through actual UDP receive/decrypt/callback work, not
//! just the counter helpers. Subscribers are scoped to each data-loop future.

use super::*;
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
    delivered: mpsc::UnboundedSender<usize>,
    delay: Duration,
}

impl ClientCallbacks for DeliveryCallbacks {
    fn on_packets(&self, packets: Vec<Vec<u8>>) {
        // Model synchronous platform TUN work, whose cost should appear in
        // callback metrics rather than in cryptographic failure counters.
        std::thread::sleep(self.delay);
        self.delivered.send(packets.len()).unwrap();
    }

    fn on_ip_assigned(&self, _: String, _: String, _: String, _: i32) -> Result<(), String> {
        Ok(())
    }

    fn on_error(&self, error: String) {
        panic!("unexpected data-loop error: {error}");
    }
}

struct DataLoop {
    inner: Arc<ClientInner>,
    task: JoinHandle<()>,
    stop: Option<tokio::sync::oneshot::Sender<()>>,
    server: UdpSocket,
    client_address: SocketAddr,
    sender_crypto: CryptoCore,
    delivered: mpsc::UnboundedReceiver<usize>,
    events: DownlinkEvents,
}

impl DataLoop {
    async fn start() -> Self {
        let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let client_address = socket.local_addr().unwrap();
        let server_address = server.local_addr().unwrap();
        let (client_private, client_public) = create_ecdh_keypair().unwrap();
        let (server_private, server_public) = create_ecdh_keypair().unwrap();
        let receiver_crypto = Arc::new(
            CryptoCore::new(
                client_private,
                &crate::AlgorithmType::Aes128Gcm,
                server_public.bytes(),
                Role::Initiator,
                b"metrics-test-key",
            )
            .unwrap(),
        );
        let sender_crypto = CryptoCore::new(
            server_private,
            &crate::AlgorithmType::Aes128Gcm,
            client_public.bytes(),
            Role::Responder,
            b"metrics-test-key",
        )
        .unwrap();
        let (delivered_tx, delivered) = mpsc::unbounded_channel();
        let inner = Arc::new(ClientInner {
            uplink: Arc::new(UplinkCounters::default()),
            config: ClientConfig {
                password: String::new(),
                hosts: vec!["127.0.0.1".into()],
                port: server_address.port(),
                id: PeerId([3; 16]),
                device_name: String::new(),
                platform: String::new(),
                socket_protect: None,
            },
            callbacks: Arc::new(DeliveryCallbacks {
                delivered: delivered_tx,
                delay: Duration::from_millis(2),
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
                    _ = running.run_data_loop(socket, receiver_crypto, server_address, 17) => {}
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

    async fn send(&self, corrupt: bool) {
        let mut packet = Buffer::new(EXTRA_LEN + 1);
        packet.write_all(&[0x45; 64]).unwrap();
        protocol::build_data_interface(&mut packet, &self.sender_crypto).unwrap();
        if corrupt {
            // Invalid AEAD tag with a fresh nonce: must be counted as a
            // decryption failure and never delivered to the platform.
            *packet.message_mut().last_mut().unwrap() ^= 1;
        }
        self.server
            .send_to(packet.as_ref(), self.client_address)
            .await
            .unwrap();
    }

    async fn wait_for_delivery(&mut self) {
        assert_eq!(
            tokio::time::timeout(Duration::from_millis(500), self.delivered.recv())
                .await
                .expect("local UDP packet should be delivered promptly"),
            Some(1)
        );
    }

    async fn stop(mut self) -> Vec<Fields> {
        self.stop.take().unwrap().send(()).unwrap();
        let _ = (&mut self.task).await;
        self.inner.clear_connection();
        self.events.snapshots()
    }
}

impl Drop for DataLoop {
    fn drop(&mut self) {
        self.task.abort();
        self.inner.clear_connection();
    }
}

fn number(fields: &Fields, name: &str) -> f64 {
    fields
        .get(name)
        .unwrap_or_else(|| panic!("missing metric {name}: {fields:?}"))
        .parse()
        .unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn periodic_report() {
    let mut data_loop = DataLoop::start().await;
    let started = Instant::now();
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
    assert_eq!(number(report, "decrypt_failures"), 0.0);
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
