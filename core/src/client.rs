// SPDX-License-Identifier: MIT
//! Platform-independent VPN client session.
//!
//! Implements the edge/client side of the vault protocol: handshake,
//! heartbeat, exponential-backoff reconnect and the packet data pump.
//! Platform bindings (Android `vaultcore`, Apple `VaultCore`; both going
//! through the shared `vault-bridge` Rust layer) wrap this
//! module and only provide platform glue (TUN fd handling, FFI, logging).
//!
//! Hot-path properties (measured on Android):
//! - a single uplink sender task with a bounded queue (no per-packet spawn);
//! - a single reused `Buffer` on both directions (no per-packet 64KB alloc);
//! - downlink packets are delivered in opportunistic batches (drain without
//!   waiting, so no latency is added) to amortize FFI callback costs.

use std::io::Write;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use tokio::net::UdpSocket;
use tokio::runtime::Runtime;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tokio::time::{interval, sleep};
use tracing::{debug, info, warn};

#[cfg(test)]
#[path = "../tests/client/mod.rs"]
mod tests;

use crate::metrics::transport::{
    DownlinkReport, ReceiveMetrics, UplinkQueueMetrics, UplinkReport, maintenance_interval,
};

use crate::{
    Algorithm, Buffer, CryptoCore, EXTRA_LEN, Handshake, HandshakeResponse, PeerId, Role,
    create_ecdh_keypair, pake, protocol, supported_algorithms,
};

pub const HANDSHAKE_TIMEOUT_SECS: u64 = 5;
pub const DNS_TIMEOUT_SECS: u64 = 5;
/// Delay between launching racing handshake attempts (RFC 8305 style Happy
/// Eyeballs): the preferred candidate gets this much of a head start.
pub const HANDSHAKE_RACE_STAGGER_MS: u64 = 300;
pub const HEARTBEAT_INTERVAL_SECS: u64 = 10;
pub const HEARTBEAT_TIMEOUT_MS: u64 = 30_000;
pub const INITIAL_RECONNECT_DELAY_MS: u64 = 1_000;
/// Coalesce bursts of OS path notifications before opening another socket.
pub const NETWORK_CHANGE_DEBOUNCE_MS: u64 = 300;
pub const MAX_RECONNECT_DELAY_MS: u64 = 60_000;
/// Max packets delivered per `on_packets` callback. Bigger batches amortize
/// the (expensive) FFI callback; the bound keeps latency flat.
pub const DATA_BATCH_CAPACITY: usize = 32;
/// Bounded uplink queue; packets are dropped when full (UDP semantics).
pub const UPLINK_QUEUE_CAPACITY: usize = 1024;
pub const DOWNLINK_QUEUE_CAPACITY: usize = 256;
const UDP_RECEIVE_BUFFER_BYTES: usize = 2 * 1024 * 1024;

fn configure_udp_receive_buffer(socket: &UdpSocket) {
    let socket = socket2::SockRef::from(socket);
    // Linux/Android report twice the requested size; Apple reports it directly.
    let target_bytes = UDP_RECEIVE_BUFFER_BYTES
        * if cfg!(any(target_os = "linux", target_os = "android")) {
            2
        } else {
            1
        };
    let set_error = if socket
        .recv_buffer_size()
        .is_ok_and(|bytes| bytes >= target_bytes)
    {
        None
    } else {
        socket.set_recv_buffer_size(UDP_RECEIVE_BUFFER_BYTES).err()
    };
    // Buffer tuning must not prevent a connection on a constrained device.
    // Read back even after a failed set so the log shows the retained capacity.
    match socket.recv_buffer_size() {
        Ok(recv_bytes) if set_error.is_none() && recv_bytes >= target_bytes => info!(
            requested_bytes = UDP_RECEIVE_BUFFER_BYTES,
            recv_bytes, "VPN UDP receive buffer configured"
        ),
        Ok(recv_bytes) => warn!(
            requested_bytes = UDP_RECEIVE_BUFFER_BYTES,
            recv_bytes,
            error = ?set_error,
            "VPN UDP receive buffer limited; continuing with effective capacity"
        ),
        Err(error) => warn!(
            requested_bytes = UDP_RECEIVE_BUFFER_BYTES,
            set_error = ?set_error,
            %error,
            "Cannot read VPN UDP receive buffer; continuing connection"
        ),
    }
}

#[derive(Debug)]
pub enum ClientError {
    AlreadyConnected,
    NotConnected,
    DnsFailed(String),
    BindFailed(String),
    ProtectFailed,
    HandshakeFailed(String),
    IoError(String),
    InternalError(String),
}

impl std::fmt::Display for ClientError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ClientError::AlreadyConnected => write!(f, "Already connected"),
            ClientError::NotConnected => write!(f, "Not connected"),
            ClientError::DnsFailed(e) => write!(f, "DNS resolution failed: {e}"),
            ClientError::BindFailed(e) => write!(f, "Socket bind failed: {e}"),
            ClientError::ProtectFailed => write!(f, "Socket protect failed"),
            ClientError::HandshakeFailed(e) => write!(f, "Handshake failed: {e}"),
            ClientError::IoError(e) => write!(f, "IO error: {e}"),
            ClientError::InternalError(e) => write!(f, "Internal error: {e}"),
        }
    }
}

impl std::error::Error for ClientError {}

impl From<anyhow::Error> for ClientError {
    fn from(e: anyhow::Error) -> Self {
        ClientError::InternalError(e.to_string())
    }
}

/// Client-side callbacks delivered by the session. All callbacks fire on
/// internal worker threads; implementations must be cheap and non-blocking.
pub trait ClientCallbacks: Send + Sync {
    /// A batch of decrypted IP packets from the tunnel.
    fn on_packets(&self, packets: Vec<Vec<u8>>);
    /// Apply addresses and platform routes on initial assignment or a real
    /// address/mask/prefix change. Reconnects with the same configuration do
    /// not repeat this callback. Failed setup may be retried.
    fn on_ip_assigned(
        &self,
        ipv4: String,
        ipv4_mask: String,
        ipv6: String,
        ipv6_prefixlen: i32,
    ) -> Result<(), String>;
    /// Runtime error notification. The session keeps retrying reconnects on
    /// its own; this is informational (e.g. for UI status updates).
    fn on_error(&self, error: String);
}

pub struct ClientConfig {
    pub password: String,
    /// Candidate supernode addresses (usually literal IPs resolved by the
    /// platform before the tunnel comes up). Every (re)connect prefers IPv6
    /// and races candidates Happy-Eyeballs style: each candidate's
    /// handshake starts HANDSHAKE_RACE_STAGGER_MS after the previous one
    /// and the first to complete wins. Must not be empty.
    pub hosts: Vec<String>,
    pub port: u16,
    pub id: PeerId,
    /// Client-reported device name, sent in the handshake. May be empty.
    pub device_name: String,
    /// Client platform (android/ios/macos/linux), sent in the handshake.
    pub platform: String,
    /// Optional platform hook called once per (re)connect with the UDP socket
    /// fd. Android uses it to call `VpnService.protect(fd)`; iOS/macOS pass a
    /// hook that just returns true (the system manages the tunnel socket).
    pub socket_protect: Option<Arc<dyn Fn(i32) -> bool + Send + Sync>>,
}

/// Atomic snapshot of transport readiness and its attempt generation.
#[derive(Debug, Clone, Default)]
pub struct ConnectionStatus {
    pub connected: bool,
    pub generation: u64,
    /// Server-observed outer source IP from the current authenticated handshake.
    pub public_ip: String,
}

#[derive(Debug, Clone, Copy, Default)]
pub struct TrafficStats {
    /// Payload bytes accepted by the UDP socket (not peer delivery acknowledgements).
    pub bytes_sent: i64,
    pub bytes_received: i64,
    pub packets_sent: i64,
    pub packets_received: i64,
    pub send_speed: i64,
    pub receive_speed: i64,
}

#[derive(Default)]
struct UplinkCounters {
    bytes_sent: AtomicU64,
    packets_sent: AtomicU64,
    queue_drops: AtomicU64,
    not_connected: AtomicU64,
    build_failures: AtomicU64,
    send_failures: AtomicU64,
}

impl UplinkCounters {
    fn failures(&self) -> [u64; 4] {
        [
            self.queue_drops.load(Ordering::Relaxed),
            self.not_connected.load(Ordering::Relaxed),
            self.build_failures.load(Ordering::Relaxed),
            self.send_failures.load(Ordering::Relaxed),
        ]
    }
}

struct ClientState {
    is_active: bool,
    connection_generation: u64,
    assigned_addresses: Option<(String, String, String, i32)>,
    public_ip: String,
    is_closing: bool,
    last_pong: Instant,
    receive_handle: Option<JoinHandle<()>>,
    heartbeat_handle: Option<JoinHandle<()>>,
    uplink_handle: Option<JoinHandle<()>>,
    uplink_tx: Option<mpsc::Sender<Vec<u8>>>,
    uplink_queue_metrics: Option<Arc<UplinkQueueMetrics>>,
    run_handle: Option<JoinHandle<()>>,
    shutdown_tx: Option<mpsc::Sender<()>>,
    reconnect_tx: Option<mpsc::Sender<()>>,
    bytes_received: AtomicU64,
    packets_received: AtomicU64,
    decrypt_failures: AtomicU64,
    last_bytes_sent: AtomicU64,
    last_bytes_received: AtomicU64,
    last_stats_time: Mutex<Instant>,
}

struct ClientInner {
    uplink: Arc<UplinkCounters>,
    config: ClientConfig,
    callbacks: Arc<dyn ClientCallbacks>,
    runtime: Arc<SessionRuntime>,
    algorithms: Vec<Algorithm>,
    state: Arc<Mutex<ClientState>>,
}

/// The last owner can be dropped from a platform callback or a foreign
/// async runtime. Tokio's ordinary Runtime destructor would panic there.
struct SessionRuntime(Option<Runtime>);

impl SessionRuntime {
    fn new() -> std::io::Result<Self> {
        Ok(Self(Some(Runtime::new()?)))
    }
}

impl std::ops::Deref for SessionRuntime {
    type Target = Runtime;
    fn deref(&self) -> &Runtime {
        self.0
            .as_ref()
            .expect("session runtime is alive until drop")
    }
}

impl Drop for SessionRuntime {
    fn drop(&mut self) {
        if let Some(runtime) = self.0.take() {
            runtime.shutdown_background();
        }
    }
}

/// A running VPN client session. Owns the tokio runtime and all tasks;
/// dropping the session shuts everything down.
pub struct ClientSession {
    inner: Arc<ClientInner>,
}

impl ClientSession {
    /// Creates the session and starts the connection loop in the background.
    /// IP assignment is reported via `ClientCallbacks::on_ip_assigned` once
    /// the handshake completes.
    pub fn start(
        config: ClientConfig,
        callbacks: Arc<dyn ClientCallbacks>,
    ) -> Result<Self, ClientError> {
        let runtime =
            Arc::new(SessionRuntime::new().map_err(|e| ClientError::InternalError(e.to_string()))?);

        let inner = Arc::new(ClientInner {
            uplink: Arc::new(UplinkCounters::default()),
            config,
            callbacks,
            runtime,
            algorithms: supported_algorithms(),
            state: Arc::new(Mutex::new(ClientState::new())),
        });

        let session = Self { inner };
        session.spawn_run_loop()?;
        Ok(session)
    }

    fn spawn_run_loop(&self) -> Result<(), ClientError> {
        let mut state = self.lock_state()?;

        if state.run_handle.is_some() {
            return Err(ClientError::AlreadyConnected);
        }

        let (shutdown_tx, shutdown_rx) = mpsc::channel(1);
        let (reconnect_tx, reconnect_rx) = mpsc::channel(1);
        state.reconnect_tx = Some(reconnect_tx);
        state.shutdown_tx = Some(shutdown_tx);

        let inner = self.inner.clone();
        let handle = self.inner.runtime.spawn(async move {
            if let Err(e) = inner.run(shutdown_rx, reconnect_rx).await {
                warn!("Client run loop failed: {e}");
                inner.callbacks.on_error(e.to_string());
            }
        });

        state.run_handle = Some(handle);
        Ok(())
    }

    /// Queues an outgoing packet for the uplink sender task.
    ///
    /// Never spawns per-packet work: a single task with a reused buffer
    /// drains the queue, encrypts and sends. When the queue is full the
    /// packet is dropped (UDP semantics) instead of growing memory.
    pub fn write_packet(&self, data: Vec<u8>) -> Result<(), ClientError> {
        // This unicast VPN does not carry IPv6 multicast control traffic.
        // Apply the same policy for every platform before queueing packets.
        if data.len() >= 40 && data[0] >> 4 == 6 && data[24] == 0xff {
            return Ok(());
        }
        let state = self.lock_state()?;

        let counters = &self.inner.uplink;
        let Some(tx) = state.uplink_tx.as_ref() else {
            counters.not_connected.fetch_add(1, Ordering::Relaxed);
            return Err(ClientError::NotConnected);
        };
        let result = tx.try_send(data);
        if let Some(metrics) = &state.uplink_queue_metrics {
            let depth = if matches!(&result, Err(mpsc::error::TrySendError::Full(_))) {
                tx.max_capacity()
            } else {
                tx.max_capacity() - tx.capacity()
            };
            metrics.queue.observe(depth);
        }
        match result {
            Ok(()) => Ok(()),
            Err(mpsc::error::TrySendError::Full(_)) => {
                counters.queue_drops.fetch_add(1, Ordering::Relaxed);
                if let Some(metrics) = &state.uplink_queue_metrics {
                    metrics.full_drops.fetch_add(1, Ordering::Relaxed);
                }
                Ok(())
            }
            Err(mpsc::error::TrySendError::Closed(_)) => {
                counters.not_connected.fetch_add(1, Ordering::Relaxed);
                if let Some(metrics) = &state.uplink_queue_metrics {
                    metrics.closed_drops.fetch_add(1, Ordering::Relaxed);
                }
                Err(ClientError::NotConnected)
            }
        }
    }

    pub fn traffic_stats(&self) -> TrafficStats {
        let state = self.inner.state.lock().unwrap_or_else(|e| e.into_inner());
        let bytes_sent = self.inner.uplink.bytes_sent.load(Ordering::Relaxed);
        let bytes_received = state.bytes_received.load(Ordering::Relaxed);
        let last_bytes_sent = state.last_bytes_sent.load(Ordering::Relaxed);
        let last_bytes_received = state.last_bytes_received.load(Ordering::Relaxed);

        let now = Instant::now();
        let mut last_time = state
            .last_stats_time
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let elapsed_secs = now.duration_since(*last_time).as_secs_f64().max(1e-6);
        let send_speed = ((bytes_sent - last_bytes_sent) as f64 / elapsed_secs) as i64;
        let receive_speed = ((bytes_received - last_bytes_received) as f64 / elapsed_secs) as i64;

        state.last_bytes_sent.store(bytes_sent, Ordering::Relaxed);
        state
            .last_bytes_received
            .store(bytes_received, Ordering::Relaxed);
        *last_time = now;

        TrafficStats {
            bytes_sent: bytes_sent as i64,
            bytes_received: bytes_received as i64,
            packets_sent: self.inner.uplink.packets_sent.load(Ordering::Relaxed) as i64,
            packets_received: state.packets_received.load(Ordering::Relaxed) as i64,
            send_speed,
            receive_speed,
        }
    }

    pub fn connection_status(&self) -> ConnectionStatus {
        let state = self.inner.state.lock().unwrap_or_else(|e| e.into_inner());
        ConnectionStatus {
            connected: state.is_active,
            generation: state.connection_generation,
            public_ip: state.public_ip.clone(),
        }
    }

    pub fn is_active(&self) -> bool {
        self.connection_status().connected
    }

    /// Wake the existing connection loop after an underlying network change.
    /// A bounded channel coalesces requests; shutdown always takes priority.
    pub fn reconnect(&self) -> Result<(), ClientError> {
        let state = self.lock_state()?;
        if state.is_closing {
            return Err(ClientError::NotConnected);
        }
        let tx = state
            .reconnect_tx
            .as_ref()
            .ok_or(ClientError::NotConnected)?;
        match tx.try_send(()) {
            Ok(()) | Err(mpsc::error::TrySendError::Full(_)) => Ok(()),
            Err(mpsc::error::TrySendError::Closed(_)) => Err(ClientError::NotConnected),
        }
    }

    pub fn shutdown(&self) -> Result<(), ClientError> {
        let (mut handles, report_totals) = {
            let mut state = self.lock_state()?;

            let report_totals = !state.is_closing;
            state.is_closing = true;
            state.reconnect_tx = None;

            if let Some(tx) = state.shutdown_tx.take() {
                let _ = tx.try_send(());
            }
            let mut handles = Vec::new();
            if let Some(handle) = state.receive_handle.take() {
                handle.abort();
                handles.push(handle);
            }
            if let Some(handle) = state.heartbeat_handle.take() {
                handle.abort();
                handles.push(handle);
            }
            if let Some(handle) = state.uplink_handle.take() {
                handle.abort();
                handles.push(handle);
            }
            state.uplink_tx = None;
            state.uplink_queue_metrics = None;
            if let Some(handle) = state.run_handle.take() {
                handle.abort();
                handles.push(handle);
            }

            state.is_active = false;
            state.public_ip.clear();
            (handles, report_totals)
        };

        // Finish callbacks before platform guards restore DNS/routes. A
        // different runtime (e.g. app_main's runtime) does not prevent us
        // joining these tasks, but block_on must then run on a helper thread.
        let current = tokio::runtime::Handle::try_current().ok();
        let on_own_runtime = current
            .as_ref()
            .is_some_and(|handle| handle.id() == self.inner.runtime.handle().id());
        if !on_own_runtime {
            let rt = self.inner.runtime.clone();
            let wait = move || {
                rt.block_on(async move {
                    for handle in handles.drain(..) {
                        let _ = handle.await;
                    }
                })
            };
            if current.is_some() {
                std::thread::scope(|scope| scope.spawn(wait).join())
                    .map_err(|_| ClientError::InternalError("shutdown waiter panicked".into()))?;
            } else {
                wait();
            }
        }

        if report_totals {
            let failures = self.inner.uplink.failures();
            info!(
                target: "metrics",
                workers_joined = !on_own_runtime,
                queue_full_drops = failures[0],
                not_connected = failures[1],
                build_failures = failures[2],
                send_failures = failures[3],
                "VPN session uplink failure totals"
            );
        }
        Ok(())
    }

    fn lock_state(&self) -> Result<std::sync::MutexGuard<'_, ClientState>, ClientError> {
        self.inner
            .state
            .lock()
            .map_err(|_| ClientError::InternalError("lock poisoned".to_string()))
    }
}

impl Drop for ClientSession {
    fn drop(&mut self) {
        let _ = self.shutdown();
    }
}

impl ClientState {
    fn new() -> Self {
        Self {
            is_active: false,
            connection_generation: 0,
            assigned_addresses: None,
            public_ip: String::new(),
            is_closing: false,
            last_pong: Instant::now(),
            receive_handle: None,
            heartbeat_handle: None,
            uplink_handle: None,
            uplink_tx: None,
            uplink_queue_metrics: None,
            run_handle: None,
            shutdown_tx: None,
            reconnect_tx: None,
            bytes_received: AtomicU64::new(0),
            packets_received: AtomicU64::new(0),
            decrypt_failures: AtomicU64::new(0),
            last_bytes_sent: AtomicU64::new(0),
            last_bytes_received: AtomicU64::new(0),
            last_stats_time: Mutex::new(Instant::now()),
        }
    }
}

impl ClientInner {
    async fn run(
        self: &Arc<Self>,
        mut shutdown_rx: mpsc::Receiver<()>,
        mut reconnect_rx: mpsc::Receiver<()>,
    ) -> Result<(), ClientError> {
        let mut reconnect_delay = INITIAL_RECONNECT_DELAY_MS;
        loop {
            let result = tokio::select! {
                biased;
                _ = shutdown_rx.recv() => break,
                _ = reconnect_rx.recv() => {
                    info!("Underlying network changed, reconnecting");
                    reconnect_delay = INITIAL_RECONNECT_DELAY_MS;
                    None
                }
                result = self.try_connect() => Some(result),
            };
            // try_connect may have been cancelled with live data-pump tasks.
            // Tear them down before opening another socket; keep statistics.
            self.clear_connection();
            if self
                .state
                .lock()
                .map_err(|_| ClientError::InternalError("lock poisoned".into()))?
                .is_closing
            {
                break;
            }
            if result.is_none()
                && !Self::settle_network_changes(&mut shutdown_rx, &mut reconnect_rx).await
            {
                break;
            }
            match result {
                Some(Err(e)) => {
                    warn!("Connection attempt failed: {e}; retrying in {reconnect_delay}ms");
                    self.callbacks.on_error(e.to_string());
                    tokio::select! {
                        biased;
                        _ = shutdown_rx.recv() => break,
                        _ = reconnect_rx.recv() => {
                            reconnect_delay = INITIAL_RECONNECT_DELAY_MS;
                            if !Self::settle_network_changes(&mut shutdown_rx, &mut reconnect_rx).await {
                                break;
                            }
                            continue;
                        }
                        _ = sleep(Duration::from_millis(reconnect_delay)) => {}
                    }
                    reconnect_delay = (reconnect_delay * 2).min(MAX_RECONNECT_DELAY_MS);
                }
                _ => reconnect_delay = INITIAL_RECONNECT_DELAY_MS,
            }
        }
        self.clear_connection();
        Ok(())
    }

    /// OS bridges only report events; coalescing and transport restart stay here.
    async fn settle_network_changes(
        shutdown_rx: &mut mpsc::Receiver<()>,
        reconnect_rx: &mut mpsc::Receiver<()>,
    ) -> bool {
        loop {
            tokio::select! {
                biased;
                _ = shutdown_rx.recv() => return false,
                _ = reconnect_rx.recv() => continue,
                _ = sleep(Duration::from_millis(NETWORK_CHANGE_DEBOUNCE_MS)) => return true,
            }
        }
    }

    fn clear_connection(&self) {
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        for handle in [
            state.receive_handle.take(),
            state.heartbeat_handle.take(),
            state.uplink_handle.take(),
        ]
        .into_iter()
        .flatten()
        {
            handle.abort();
        }
        state.uplink_tx = None;
        state.uplink_queue_metrics = None;
        state.is_active = false;
        state.public_ip.clear();
    }

    async fn try_connect(self: &Arc<Self>) -> Result<(), ClientError> {
        let generation = {
            let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
            // A generation identifies an attempt even when it fails or keeps
            // the same IP. Consumers must not infer transport identity from IP.
            state.connection_generation = state.connection_generation.saturating_add(1);
            state.connection_generation
        };
        let candidates = self.resolve_candidates().await?;
        info!(
            "Racing {} supernode candidate(s): {candidates:?}",
            candidates.len()
        );
        let (socket, crypto, remote_addr, response) = self.race_handshakes(candidates).await?;
        info!("Handshake race won by {remote_addr}");

        let addresses = (
            response.ipv4,
            response.ipv4_mask,
            response.ipv6,
            response.ipv6_prefixlen,
        );
        let assigned = self
            .state
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .assigned_addresses
            .clone();
        // Start the uplink sender BEFORE notifying the platform, so that
        // write_packet works as soon as on_ip_assigned fires.
        let (uplink_tx, uplink_rx) = mpsc::channel::<Vec<u8>>(UPLINK_QUEUE_CAPACITY);
        let queue_metrics = Arc::new(UplinkQueueMetrics::new(&uplink_tx));
        {
            let mut state = self
                .state
                .lock()
                .map_err(|_| ClientError::InternalError("lock poisoned".to_string()))?;
            if state.is_closing {
                return Err(ClientError::NotConnected);
            }
            let uplink_handle = self.runtime.spawn(Self::run_uplink_loop(
                socket.clone(),
                crypto.clone(),
                remote_addr,
                uplink_rx,
                self.uplink.clone(),
                queue_metrics.clone(),
                generation,
            ));
            state.last_pong = Instant::now();
            state.uplink_tx = Some(uplink_tx);
            state.uplink_queue_metrics = Some(queue_metrics);
            state.uplink_handle = Some(uplink_handle);
        }

        if assigned.as_ref() != Some(&addresses) {
            self.callbacks
                .on_ip_assigned(
                    addresses.0.clone(),
                    addresses.1.clone(),
                    addresses.2.clone(),
                    addresses.3,
                )
                .map_err(|e| {
                    ClientError::InternalError(format!("platform configuration failed: {e}"))
                })?;
            self.state
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .assigned_addresses = Some(addresses);
        }
        {
            let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
            if state.is_closing {
                return Err(ClientError::NotConnected);
            }
            state.public_ip = response.public_ip;
            state.is_active = true;
        }

        info!(
            "Transport ready: generation={generation} peer={remote_addr} outer_ip={} uplink_capacity={UPLINK_QUEUE_CAPACITY} downlink_capacity={DOWNLINK_QUEUE_CAPACITY} session_not_connected_total={}",
            if remote_addr.ip().to_canonical().is_ipv4() {
                "IPv4"
            } else {
                "IPv6"
            },
            self.uplink.not_connected.load(Ordering::Relaxed)
        );

        self.run_data_loop(socket, crypto, remote_addr, generation)
            .await;

        Ok(())
    }

    /// Resolve every configured host and concatenate the addresses in
    /// preference order, deduplicated. Hosts are usually IP literals (the
    /// platform resolves before the tunnel comes up); a lookup failure for
    /// one host does not discard the others.
    async fn resolve_candidates(&self) -> Result<Vec<SocketAddr>, ClientError> {
        let mut candidates: Vec<SocketAddr> = Vec::new();
        let mut last_error = String::new();
        for host in &self.config.hosts {
            let lookup = tokio::time::timeout(
                Duration::from_secs(DNS_TIMEOUT_SECS),
                tokio::net::lookup_host((
                    host.trim_start_matches('[').trim_end_matches(']'),
                    self.config.port,
                )),
            )
            .await;
            match lookup {
                Ok(Ok(addrs)) => {
                    for addr in addrs {
                        if !candidates.contains(&addr) {
                            candidates.push(addr);
                        }
                    }
                }
                Ok(Err(e)) => {
                    warn!("Resolving {host} failed: {e}");
                    last_error = e.to_string();
                }
                Err(_) => {
                    warn!("Resolving {host} timed out");
                    last_error = "timeout".to_string();
                }
            }
        }
        if candidates.is_empty() {
            return Err(ClientError::DnsFailed(if last_error.is_empty() {
                "no addresses".to_string()
            } else {
                last_error
            }));
        }
        // Address-family preference belongs to the client, not platform glue.
        candidates.sort_by_key(SocketAddr::is_ipv4);
        Ok(candidates)
    }

    /// Race the candidates Happy-Eyeballs style: each attempt starts
    /// HANDSHAKE_RACE_STAGGER_MS after the previous one and the first
    /// completed handshake wins. Losing attempts are aborted during the
    /// handshake phase — before they have sent a single encrypted packet —
    /// so the supernode never promotes (and therefore never evicts) a
    /// losing session. When every attempt fails, the most preferred
    /// candidate's error is returned.
    async fn race_handshakes(
        self: &Arc<Self>,
        candidates: Vec<SocketAddr>,
    ) -> Result<
        (
            Arc<UdpSocket>,
            Arc<CryptoCore>,
            SocketAddr,
            HandshakeResponse,
        ),
        ClientError,
    > {
        let mut errors: Vec<Option<ClientError>> = (0..candidates.len()).map(|_| None).collect();
        let mut attempts = tokio::task::JoinSet::new();
        for (index, addr) in candidates.into_iter().enumerate() {
            let inner = Arc::clone(self);
            attempts.spawn(async move {
                if index > 0 {
                    sleep(Duration::from_millis(
                        HANDSHAKE_RACE_STAGGER_MS * index as u64,
                    ))
                    .await;
                }
                (index, addr, inner.handshake_attempt(addr).await)
            });
        }
        while let Some(joined) = attempts.join_next().await {
            let (index, remote_addr, result) = match joined {
                Ok(v) => v,
                // A panicked attempt must not take down the whole race.
                Err(e) => {
                    warn!("Handshake attempt task failed: {e}");
                    continue;
                }
            };
            match result {
                Ok(winner) => {
                    attempts.abort_all();
                    return Ok(winner);
                }
                Err(e) => {
                    warn!("Handshake attempt #{index} to {remote_addr} failed: {e}");
                    errors[index] = Some(e);
                }
            }
        }
        Err(errors
            .into_iter()
            .flatten()
            .next()
            .unwrap_or_else(|| ClientError::HandshakeFailed("all candidates failed".to_string())))
    }

    /// One racing attempt: bind a socket matching the address family and
    /// run the full SPAKE2/X25519 handshake against a single candidate.
    /// Cancellation-safe: the attempt owns no shared state, so aborting it
    /// mid-handshake is a plain drop of its socket.
    async fn handshake_attempt(
        &self,
        remote_addr: SocketAddr,
    ) -> Result<
        (
            Arc<UdpSocket>,
            Arc<CryptoCore>,
            SocketAddr,
            HandshakeResponse,
        ),
        ClientError,
    > {
        info!("Connecting to {remote_addr}");

        let (private_key, public_key) =
            create_ecdh_keypair().map_err(|e| ClientError::HandshakeFailed(e.to_string()))?;
        let public_key_bytes = public_key.as_ref().to_vec();

        let bind_addr: SocketAddr = if remote_addr.is_ipv6() {
            "[::]:0".parse().unwrap()
        } else {
            "0.0.0.0:0".parse().unwrap()
        };
        let socket = UdpSocket::bind(bind_addr)
            .await
            .map_err(|e| ClientError::BindFailed(e.to_string()))?;
        configure_udp_receive_buffer(&socket);

        #[cfg(unix)]
        {
            use std::os::unix::io::AsRawFd;
            if let Some(protect) = &self.config.socket_protect
                && !protect(socket.as_raw_fd())
            {
                return Err(ClientError::ProtectFailed);
            }
        }

        let socket = Arc::new(socket);
        let mut recv_buf = vec![0u8; 65535];

        // SPAKE2 authenticates the shared password without putting any
        // password-derived verifier on the wire: a passive observer cannot
        // verify password guesses offline, and an active attacker gets one
        // guess per handshake.
        let (pake_state, pake_message) =
            pake::start_client(self.config.password.as_bytes(), &self.config.id.0);

        let handshake_buf = protocol::build_handshake_request(
            &self.config.id,
            &pake_message,
            &self.algorithms,
            &public_key_bytes,
            current_ts_secs(),
            &self.config.device_name,
            &self.config.platform,
        )
        .map_err(|e| ClientError::HandshakeFailed(e.to_string()))?;

        socket
            .send_to(handshake_buf.as_ref(), remote_addr)
            .await
            .map_err(|e| ClientError::IoError(e.to_string()))?;

        // Wait for the handshake response, ignoring packets from other
        // senders and duplicate/stray packets from the server itself.
        let len = tokio::time::timeout(Duration::from_secs(HANDSHAKE_TIMEOUT_SECS), async {
            loop {
                let (len, from) = socket
                    .recv_from(&mut recv_buf)
                    .await
                    .map_err(|e| ClientError::IoError(e.to_string()))?;
                if from == remote_addr && len > 0 && recv_buf[0] == protocol::INIT {
                    break Ok::<usize, ClientError>(len);
                }
                debug!("Ignoring handshake-phase packet from {from}");
            }
        })
        .await
        .map_err(|_| ClientError::HandshakeFailed("handshake response timeout".to_string()))??;

        recv_buf.truncate(len);

        let handshake = protocol::parse_handshake(&recv_buf[1..])
            .map_err(|e| ClientError::HandshakeFailed(e.to_string()))?;

        let response = match handshake {
            Handshake::Response(r) => r,
            Handshake::Request(_) => {
                return Err(ClientError::HandshakeFailed(
                    "received request instead of response".to_string(),
                ));
            }
        };

        // The server's confirmation MAC proves it holds the same password
        // (and that the response was not tampered with) before we send any
        // traffic.
        let pake_key = pake_state
            .finish(&response.pake_message)
            .map_err(|e| ClientError::HandshakeFailed(e.to_string()))?;
        protocol::verify_response_confirm(&response, &pake_key)
            .map_err(|e| ClientError::HandshakeFailed(e.to_string()))?;

        // Freshness + binding: the timestamp must be near our clock, and
        // the response must echo this attempt's ephemeral public key, so
        // captured responses cannot be replayed into a later session.
        protocol::check_handshake_ts(response.timestamp, current_ts_secs())
            .map_err(|e| ClientError::HandshakeFailed(e.to_string()))?;
        if response.request_public_key != public_key_bytes {
            return Err(ClientError::HandshakeFailed(
                "response not bound to this handshake request".to_string(),
            ));
        }

        let algorithm_type = response.algorithm.algorithm_type;

        // The session key is bound to the PAKE exchange via the HKDF salt.
        let crypto = Arc::new(
            CryptoCore::new(
                private_key,
                &algorithm_type,
                &response.public_key_data,
                Role::Initiator,
                &pake_key,
            )
            .map_err(|e| ClientError::HandshakeFailed(e.to_string()))?,
        );

        Ok((socket, crypto, remote_addr, response))
    }

    /// Drains the uplink queue: encrypts each queued packet and sends it to
    /// the peer. Reuses a single Buffer across packets so the hot path does
    /// not allocate/zero 64KB per packet.
    async fn run_uplink_loop(
        socket: Arc<UdpSocket>,
        crypto: Arc<CryptoCore>,
        remote_addr: SocketAddr,
        mut rx: mpsc::Receiver<Vec<u8>>,
        counters: Arc<UplinkCounters>,
        queue_metrics: Arc<UplinkQueueMetrics>,
        generation: u64,
    ) {
        let mut buf = Buffer::new(EXTRA_LEN + 1);
        let mut report = UplinkReport::new(queue_metrics.clone(), remote_addr, generation);
        let mut ticker = maintenance_interval();
        loop {
            tokio::select! {
                packet = rx.recv() => {
                    let Some(data) = packet else { break; };
                    queue_metrics.queue.observe(rx.len().saturating_add(1));
                    buf.clear();
                    // Bound both the fixed backing buffer and IPv4 UDP's
                    // maximum payload before copying/encrypting FFI input.
                    if data.len() > 65_507 - EXTRA_LEN - 1 - crate::TAG_LEN
                        || buf.write_all(&data).is_err()
                        || protocol::build_data_interface(&mut buf, &crypto).is_err() {
                        counters.build_failures.fetch_add(1, Ordering::Relaxed);
                        report.build_failure();
                        continue;
                    }
                    match socket.send_to(buf.as_ref(), remote_addr).await {
                        Ok(_) => {
                            counters.bytes_sent.fetch_add(data.len() as u64, Ordering::Relaxed);
                            counters.packets_sent.fetch_add(1, Ordering::Relaxed);
                            report.sent(data.len());
                        }
                        Err(error) => {
                            counters.send_failures.fetch_add(1, Ordering::Relaxed);
                            report.send_error(&error);
                        }
                    }
                }
                _ = ticker.tick() => {
                    report.report_if_due();
                }
            }
        }
    }

    async fn run_data_loop(
        &self,
        socket: Arc<UdpSocket>,
        crypto: Arc<CryptoCore>,
        remote_addr: SocketAddr,
        generation: u64,
    ) {
        info!("Data loop started for {remote_addr}");
        let (packet_tx, mut packet_rx) = mpsc::channel::<Vec<u8>>(DOWNLINK_QUEUE_CAPACITY);
        let receive_metrics = Arc::new(ReceiveMetrics::new(&packet_tx));

        {
            let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
            if state.is_closing {
                return;
            }
            let receive_socket = socket.clone();
            let metrics = receive_metrics.clone();
            let receive_handle = tokio::spawn(async move {
                let mut buf = vec![0u8; 65535];
                loop {
                    match receive_socket.recv_from(&mut buf).await {
                        Ok((len, from)) => {
                            // Drop packets from anyone but the supernode: random
                            // internet noise hitting this ephemeral port must not
                            // reach the protocol parser.
                            if from != remote_addr {
                                continue;
                            }
                            let packet = buf[..len].to_vec();
                            if !enqueue_downlink(&packet_tx, &metrics, packet).await {
                                break;
                            }
                        }
                        Err(e) => {
                            metrics.record_receive_error(&e);
                            warn!("Receive error: {e}");
                            break;
                        }
                    }
                }
            });

            let heartbeat_socket = socket.clone();
            let heartbeat_crypto = crypto.clone();
            let heartbeat_id = self.config.id;
            let heartbeat_handle = tokio::spawn(async move {
                let mut ticker = interval(Duration::from_secs(HEARTBEAT_INTERVAL_SECS));
                info!("Heartbeat loop started (interval={HEARTBEAT_INTERVAL_SECS}s)");
                loop {
                    ticker.tick().await;
                    let mut buf = Buffer::new(EXTRA_LEN + 1);
                    if let Err(e) = protocol::build_heartbeat_ping(
                        &mut buf,
                        &heartbeat_crypto,
                        &heartbeat_id,
                        current_ts(),
                    ) {
                        warn!("Failed to build ping: {e}");
                        continue;
                    }
                    match heartbeat_socket.send_to(buf.as_ref(), remote_addr).await {
                        Ok(bytes) => {
                            debug!("Heartbeat ping sent ({bytes} bytes to {remote_addr})")
                        }
                        Err(e) => warn!("Failed to send heartbeat: {e}"),
                    }
                }
            });

            state.receive_handle = Some(receive_handle);
            state.heartbeat_handle = Some(heartbeat_handle);
        }

        let mut last_pong = Instant::now();
        let timeout = Duration::from_millis(HEARTBEAT_TIMEOUT_MS);

        // Reused for heartbeat parsing. Data packets decrypt in their own Vec.
        let mut heartbeat_buf = Buffer::new(0);
        // Raw-packet staging is reused. Delivery transfers ownership of batch,
        // so reserve its next allocation once, when the first data packet arrives.
        let mut pending: Vec<Vec<u8>> = Vec::with_capacity(DATA_BATCH_CAPACITY);
        let mut batch: Vec<Vec<u8>> = Vec::new();

        // Keep the timer outside select: recreating sleep(1s) per packet
        // postpones maintenance indefinitely while traffic keeps arriving.
        let mut report = DownlinkReport::new(receive_metrics.clone(), remote_addr, generation);
        let mut ticker = maintenance_interval();
        // Counts packets that are neither HEARTBEAT nor DATA_INTERFACE
        // (e.g. REJECTED after a NAT mapping change, or random internet
        // noise hitting this ephemeral port). Throttled to avoid log spam.
        let mut unknown_packets: u64 = 0;
        // REJECTED is a single unauthenticated byte, so anyone on the path
        // can forge it. Instead of tearing the session down immediately we
        // probe the server with a ping and only reconnect if no
        // authenticated packet arrives within a few seconds.
        let mut rejected_since: Option<Instant> = None;

        loop {
            tokio::select! {
                packet = packet_rx.recv() => {
                    let Some(first) = packet else {
                        warn!("Receiver ended for {remote_addr}, exiting data loop");
                        break;
                    };
                    receive_metrics.queue.observe(packet_rx.len().saturating_add(1));
                    // Opportunistically drain queued packets (non-blocking) so a
                    // burst is processed and delivered with a single callback.
                    pending.clear();
                    pending.push(first);
                    while pending.len() < DATA_BATCH_CAPACITY {
                        match packet_rx.try_recv() {
                            Ok(p) => pending.push(p),
                            Err(_) => break,
                        }
                    }

                    batch.clear();
                    let pending_packets = pending.len();
                    for mut packet in pending.drain(..) {
                        if packet.is_empty() {
                            continue;
                        }
                        let packet_type = packet[0];

                        match packet_type {
                            protocol::HEARTBEAT => {
                                heartbeat_buf.clear();
                                if heartbeat_buf.write_all(&packet[1..]).is_ok() {
                                    match protocol::parse_pong(&mut heartbeat_buf, &crypto) {
                                        Ok(_pong) => {
                                            debug!("Pong received from {remote_addr}");
                                            last_pong = Instant::now();
                                            rejected_since = None;
                                            let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
                                            state.last_pong = last_pong;
                                        }
                                        Err(e) => {
                                            warn!("Pong parse failed: {e}");
                                        }
                                    }
                                }
                            }
                            protocol::DATA_INTERFACE => {
                                if decrypt_packet(&crypto, &mut packet).is_ok() {
                                    report.packet(packet.len());
                                    // Any successfully authenticated
                                    // packet proves the session is alive;
                                    // refresh the liveness timestamp so
                                    // lost pongs during active traffic do
                                    // not cause a spurious reconnect.
                                    last_pong = Instant::now();
                                    rejected_since = None;
                                    {
                                        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
                                        state.last_pong = last_pong;
                                        state.bytes_received.fetch_add(packet.len() as u64, Ordering::Relaxed);
                                        state.packets_received.fetch_add(1, Ordering::Relaxed);
                                    }
                                    if batch.is_empty() {
                                        batch.reserve_exact(pending_packets);
                                    }
                                    batch.push(packet);
                                } else {
                                    report.decrypt_failure();
                                    {
                                        let state = self.state.lock().unwrap_or_else(|e| e.into_inner());
                                        state.decrypt_failures.fetch_add(1, Ordering::Relaxed);
                                    }
                                    debug!("Downlink packet decrypt failed");
                                }
                            }
                            protocol::REJECTED => {
                                // The supernode claims it no longer recognizes
                                // this socket address (NAT mapping changed, or
                                // the server restarted). REJECTED itself is
                                // unauthenticated, so confirm with a ping
                                // before reconnecting.
                                if rejected_since.is_none() {
                                    rejected_since = Some(Instant::now());
                                    warn!(
                                        "REJECTED received from {remote_addr}, probing session liveness"
                                    );
                                    let mut buf = Buffer::new(EXTRA_LEN + 1);
                                    match protocol::build_heartbeat_ping(
                                        &mut buf,
                                        &crypto,
                                        &self.config.id,
                                        current_ts(),
                                    ) {
                                        Ok(()) => {
                                            if let Err(e) =
                                                socket.send_to(buf.as_ref(), remote_addr).await
                                            {
                                                warn!("Failed to send liveness ping: {e}");
                                            }
                                        }
                                        Err(e) => warn!("Failed to build liveness ping: {e}"),
                                    }
                                }
                            }
                            _ => {
                                unknown_packets += 1;
                                if unknown_packets <= 10 || unknown_packets.is_multiple_of(100) {
                                    warn!(
                                        "Unknown packet type 0x{packet_type:02x} ({} bytes) from {remote_addr}; total={unknown_packets}",
                                        packet.len()
                                    );
                                }
                            }
                        }
                    }

                    if !batch.is_empty() {
                        let packet_count = batch.len();
                        let callback_started = Instant::now();
                        self.callbacks.on_packets(std::mem::take(&mut batch));
                        report.batch(packet_count, callback_started.elapsed());
                    }
                }
                _ = ticker.tick() => {
                    report.report_if_due();
                }
            }
            // Check after either event so sustained incoming traffic cannot
            // postpone liveness decisions until the maintenance tick.
            if let Some(since) = rejected_since
                && since.elapsed() > Duration::from_secs(3)
            {
                warn!("Session still rejected by {remote_addr} after liveness probe, reconnecting");
                self.callbacks
                    .on_error("session rejected by server".to_string());
                break;
            }
            if last_pong.elapsed() > timeout {
                warn!("Heartbeat timeout for {remote_addr}, exiting data loop");
                self.callbacks.on_error("heartbeat timeout".to_string());
                break;
            }
        }

        info!("Data loop ended for {remote_addr}");

        self.clear_connection();
    }
}

/// Keep the received allocation through delivery. Compact only after AEAD
/// authentication and replay checks succeed; the header/tag stay out of FFI.
fn decrypt_packet(crypto: &CryptoCore, packet: &mut Vec<u8>) -> anyhow::Result<()> {
    let (packet_type, payload) = packet
        .split_first_mut()
        .ok_or_else(|| anyhow::anyhow!("empty packet"))?;
    let plaintext_len = crypto.decrypt_slice(payload, *packet_type)?.len();
    let plaintext_start = 1 + EXTRA_LEN;
    packet.copy_within(plaintext_start..plaintext_start + plaintext_len, 0);
    packet.truncate(plaintext_len);
    Ok(())
}

async fn enqueue_downlink(
    sender: &mpsc::Sender<Vec<u8>>,
    metrics: &ReceiveMetrics,
    packet: Vec<u8>,
) -> bool {
    match sender.try_send(packet) {
        Ok(()) => {
            metrics
                .queue
                .observe(sender.max_capacity() - sender.capacity());
            true
        }
        Err(mpsc::error::TrySendError::Full(packet)) => {
            metrics.queue.observe(sender.max_capacity());
            let started = Instant::now();
            let result = sender.send(packet).await;
            // The packet is retained while waiting for space. This measures
            // completed backpressure, not packet loss or kernel UDP overflow.
            metrics.record_wait(started.elapsed());
            result.is_ok()
        }
        Err(mpsc::error::TrySendError::Closed(_)) => false,
    }
}

fn current_ts() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

fn current_ts_secs() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}
