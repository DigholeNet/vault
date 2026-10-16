// SPDX-License-Identifier: MIT
//! Platform-independent VPN client session.
//!
//! Implements the edge/client side of the vault protocol: handshake,
//! heartbeat, exponential-backoff reconnect and the packet data pump.
//! Platform bindings (Android `vpncore`, iOS `vaultcore-ios`) wrap this
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
use tracing::{info, warn};

use crate::{
    Algorithm, Buffer, CryptoCore, EXTRA_LEN, Handshake, PeerId, Role, create_ecdh_keypair, pake,
    protocol, supported_algorithms,
};

pub const HANDSHAKE_TIMEOUT_SECS: u64 = 5;
pub const DNS_TIMEOUT_SECS: u64 = 5;
pub const HEARTBEAT_INTERVAL_SECS: u64 = 10;
pub const HEARTBEAT_TIMEOUT_MS: u64 = 30_000;
pub const INITIAL_RECONNECT_DELAY_MS: u64 = 1_000;
pub const MAX_RECONNECT_DELAY_MS: u64 = 60_000;
/// Max packets delivered per `on_packets` callback. Bigger batches amortize
/// the (expensive) FFI callback; the bound keeps latency flat.
pub const DATA_BATCH_CAPACITY: usize = 32;
/// Bounded uplink queue; packets are dropped when full (UDP semantics).
pub const UPLINK_QUEUE_CAPACITY: usize = 1024;

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
    /// The server assigned tunnel addresses after a successful handshake.
    fn on_ip_assigned(&self, ipv4: String, ipv4_mask: String, ipv6: String, ipv6_prefixlen: i32);
    /// Runtime error notification. The session keeps retrying reconnects on
    /// its own; this is informational (e.g. for UI status updates).
    fn on_error(&self, error: String);
}

pub struct ClientConfig {
    pub password: String,
    pub host: String,
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

#[derive(Debug, Clone, Copy, Default)]
pub struct TrafficStats {
    pub bytes_sent: i64,
    pub bytes_received: i64,
    pub packets_sent: i64,
    pub packets_received: i64,
    pub send_speed: i64,
    pub receive_speed: i64,
}

struct ClientState {
    is_active: bool,
    is_closing: bool,
    last_pong: Instant,
    receive_handle: Option<JoinHandle<()>>,
    heartbeat_handle: Option<JoinHandle<()>>,
    uplink_handle: Option<JoinHandle<()>>,
    uplink_tx: Option<mpsc::Sender<Vec<u8>>>,
    run_handle: Option<JoinHandle<()>>,
    shutdown_tx: Option<mpsc::Sender<()>>,
    bytes_sent: AtomicU64,
    bytes_received: AtomicU64,
    packets_sent: AtomicU64,
    packets_received: AtomicU64,
    decrypt_failures: AtomicU64,
    last_bytes_sent: AtomicU64,
    last_bytes_received: AtomicU64,
    last_stats_time: Mutex<Instant>,
}

struct ClientInner {
    config: ClientConfig,
    callbacks: Arc<dyn ClientCallbacks>,
    runtime: Arc<Runtime>,
    algorithms: Vec<Algorithm>,
    state: Arc<Mutex<ClientState>>,
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
            Arc::new(Runtime::new().map_err(|e| ClientError::InternalError(e.to_string()))?);

        let inner = Arc::new(ClientInner {
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
        state.shutdown_tx = Some(shutdown_tx);

        let inner = self.inner.clone();
        let handle = self.inner.runtime.spawn(async move {
            if let Err(e) = inner.run(shutdown_rx).await {
                log::warn!("Client run loop failed: {e}");
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
        let state = self.lock_state()?;

        state
            .bytes_sent
            .fetch_add(data.len() as u64, Ordering::Relaxed);
        state.packets_sent.fetch_add(1, Ordering::Relaxed);
        let tx = state.uplink_tx.as_ref().ok_or(ClientError::NotConnected)?;
        match tx.try_send(data) {
            Ok(()) => Ok(()),
            Err(mpsc::error::TrySendError::Full(_)) => {
                log::warn!("Uplink channel full, dropping packet");
                Ok(())
            }
            Err(mpsc::error::TrySendError::Closed(_)) => Err(ClientError::NotConnected),
        }
    }

    pub fn traffic_stats(&self) -> TrafficStats {
        let state = self.inner.state.lock().unwrap_or_else(|e| e.into_inner());
        let bytes_sent = state.bytes_sent.load(Ordering::Relaxed);
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
            packets_sent: state.packets_sent.load(Ordering::Relaxed) as i64,
            packets_received: state.packets_received.load(Ordering::Relaxed) as i64,
            send_speed,
            receive_speed,
        }
    }

    pub fn is_active(&self) -> bool {
        self.inner
            .state
            .lock()
            .map(|s| s.is_active)
            .unwrap_or(false)
    }

    /// Seconds since the last authenticated packet from the server (pong or
    /// decrypted data); platform watchdogs use this to detect a dead server.
    pub fn last_activity_age_secs(&self) -> u64 {
        self.inner
            .state
            .lock()
            .map(|s| s.last_pong.elapsed().as_secs())
            .unwrap_or(0)
    }

    pub fn shutdown(&self) -> Result<(), ClientError> {
        let mut handles = {
            let mut state = self.lock_state()?;

            state.is_closing = true;

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
            if let Some(handle) = state.run_handle.take() {
                handle.abort();
                handles.push(handle);
            }

            state.is_active = false;
            state.is_closing = false;
            handles
        };

        // Wait for aborted tasks to finish while `self` still holds an
        // Arc<ClientInner>, or the last Arc drops on a runtime worker and
        // dropping the Runtime there panics. Skip when called on-runtime.
        if tokio::runtime::Handle::try_current().is_err() {
            let rt = self.inner.runtime.clone();
            rt.block_on(async move {
                for handle in handles.drain(..) {
                    let _ = handle.await;
                }
            });
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
            is_closing: false,
            last_pong: Instant::now(),
            receive_handle: None,
            heartbeat_handle: None,
            uplink_handle: None,
            uplink_tx: None,
            run_handle: None,
            shutdown_tx: None,
            bytes_sent: AtomicU64::new(0),
            bytes_received: AtomicU64::new(0),
            packets_sent: AtomicU64::new(0),
            packets_received: AtomicU64::new(0),
            decrypt_failures: AtomicU64::new(0),
            last_bytes_sent: AtomicU64::new(0),
            last_bytes_received: AtomicU64::new(0),
            last_stats_time: Mutex::new(Instant::now()),
        }
    }
}

impl ClientInner {
    async fn run(&self, mut shutdown_rx: mpsc::Receiver<()>) -> Result<(), ClientError> {
        let mut reconnect_delay = INITIAL_RECONNECT_DELAY_MS;

        loop {
            tokio::select! {
                _ = shutdown_rx.recv() => {
                    break;
                }
                result = self.try_connect() => {
                    match result {
                        Ok(()) => {
                            reconnect_delay = INITIAL_RECONNECT_DELAY_MS;
                            let is_closing = {
                                let state = self.state.lock().map_err(|_| {
                                    ClientError::InternalError("lock poisoned".to_string())
                                })?;
                                state.is_closing
                            };
                            if is_closing {
                                break;
                            }
                        }
                        Err(e) => {
                            log::warn!(
                                "Connection attempt failed: {e}; retrying in {reconnect_delay}ms"
                            );
                            self.callbacks.on_error(e.to_string());
                            let is_closing = {
                                let state = self.state.lock().map_err(|_| {
                                    ClientError::InternalError("lock poisoned".to_string())
                                })?;
                                state.is_closing
                            };
                            if is_closing {
                                break;
                            }
                            sleep(Duration::from_millis(reconnect_delay)).await;
                            reconnect_delay = (reconnect_delay * 2).min(MAX_RECONNECT_DELAY_MS);
                        }
                    }
                }
            };
        }

        Ok(())
    }

    async fn try_connect(&self) -> Result<(), ClientError> {
        log::info!("Connecting to {}:{}", self.config.host, self.config.port);

        let remote_addr = tokio::time::timeout(
            Duration::from_secs(DNS_TIMEOUT_SECS),
            tokio::net::lookup_host(format!("{}:{}", self.config.host, self.config.port)),
        )
        .await
        .map_err(|_| ClientError::DnsFailed("timeout".to_string()))?
        .map_err(|e| ClientError::DnsFailed(e.to_string()))?
        .next()
        .ok_or_else(|| ClientError::DnsFailed("no addresses".to_string()))?;

        log::info!(
            "Resolved {}:{} -> {remote_addr}",
            self.config.host,
            self.config.port
        );

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
                log::debug!("Ignoring handshake-phase packet from {from}");
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

        // Start the uplink sender BEFORE notifying the platform, so that
        // write_packet works as soon as on_ip_assigned fires.
        let (uplink_tx, uplink_rx) = mpsc::channel::<Vec<u8>>(UPLINK_QUEUE_CAPACITY);
        let uplink_handle = self.runtime.spawn(Self::run_uplink_loop(
            socket.clone(),
            crypto.clone(),
            remote_addr,
            uplink_rx,
        ));

        {
            let mut state = self
                .state
                .lock()
                .map_err(|_| ClientError::InternalError("lock poisoned".to_string()))?;
            state.is_active = true;
            state.last_pong = Instant::now();
            state.uplink_tx = Some(uplink_tx);
            state.uplink_handle = Some(uplink_handle);
        }

        self.callbacks.on_ip_assigned(
            response.ipv4,
            response.ipv4_mask,
            response.ipv6,
            response.ipv6_prefixlen,
        );

        log::info!("Handshake complete (peer={remote_addr}), starting data/heartbeat loops");

        self.run_data_loop(socket, crypto, remote_addr).await;

        Ok(())
    }

    /// Drains the uplink queue: encrypts each queued packet and sends it to
    /// the peer. Reuses a single Buffer across packets so the hot path does
    /// not allocate/zero 64KB per packet.
    async fn run_uplink_loop(
        socket: Arc<UdpSocket>,
        crypto: Arc<CryptoCore>,
        remote_addr: SocketAddr,
        mut rx: mpsc::Receiver<Vec<u8>>,
    ) {
        // EXTRA_LEN bytes for the crypto header plus 1 byte for the packet type.
        let mut buf = Buffer::new(EXTRA_LEN + 1);
        while let Some(data) = rx.recv().await {
            buf.clear();
            if buf.write_all(&data).is_err() {
                log::warn!("Failed to write data to buffer");
                continue;
            }
            if let Err(e) = protocol::build_data_interface(&mut buf, &crypto) {
                log::warn!("Failed to build data packet: {e}");
                continue;
            }
            if let Err(e) = socket.send_to(buf.as_ref(), remote_addr).await {
                log::warn!("Failed to send data packet: {e}");
            }
        }
    }

    async fn run_data_loop(
        &self,
        socket: Arc<UdpSocket>,
        crypto: Arc<CryptoCore>,
        remote_addr: SocketAddr,
    ) {
        log::info!("Data loop started for {remote_addr}");
        let (packet_tx, mut packet_rx) = mpsc::channel::<Vec<u8>>(256);

        let receive_socket = socket.clone();
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
                        if packet_tx.send(packet).await.is_err() {
                            break;
                        }
                    }
                    Err(e) => {
                        log::warn!("Receive error: {e}");
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
            log::info!("Heartbeat loop started (interval={HEARTBEAT_INTERVAL_SECS}s)");
            loop {
                ticker.tick().await;
                let mut buf = Buffer::new(EXTRA_LEN + 1);
                if let Err(e) = protocol::build_heartbeat_ping(
                    &mut buf,
                    &heartbeat_crypto,
                    &heartbeat_id,
                    current_ts(),
                ) {
                    log::warn!("Failed to build ping: {e}");
                    continue;
                }
                match heartbeat_socket.send_to(buf.as_ref(), remote_addr).await {
                    Ok(bytes) => log::info!("Heartbeat ping sent ({bytes} bytes to {remote_addr})"),
                    Err(e) => log::warn!("Failed to send heartbeat: {e}"),
                }
            }
        });

        {
            let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
            state.receive_handle = Some(receive_handle);
            state.heartbeat_handle = Some(heartbeat_handle);
        }

        let mut last_pong = Instant::now();
        let timeout = Duration::from_millis(HEARTBEAT_TIMEOUT_MS);

        // Reused across packets: avoids allocating and zeroing a fresh 64KB
        // Buffer for every incoming packet on the hot path.
        let mut pkt_buf = Buffer::new(0);
        // Reused raw/decrypted packet collections for batching.
        let mut pending: Vec<Vec<u8>> = Vec::with_capacity(DATA_BATCH_CAPACITY);
        let mut batch: Vec<Vec<u8>> = Vec::with_capacity(DATA_BATCH_CAPACITY);

        // Per-second local counters for downlink statistics (do not touch speed-calculation state)
        let mut dl_packets_1s: u64 = 0;
        let mut dl_bytes_1s: u64 = 0;
        let mut dl_decrypt_fail_1s: u64 = 0;
        // Counts packets that are neither HEARTBEAT nor DATA_INTERFACE
        // (e.g. REJECTED after a NAT mapping change, or random internet
        // noise hitting this ephemeral port). Throttled to avoid log spam.
        let mut unknown_packets: u64 = 0;
        // REJECTED is a single unauthenticated byte, so anyone on the path
        // can forge it. Instead of tearing the session down immediately we
        // probe the server with a ping and only reconnect if no
        // authenticated packet arrives within a few seconds.
        let mut rejected_since: Option<Instant> = None;

        'outer: loop {
            tokio::select! {
                Some(first) = packet_rx.recv() => {
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
                    for packet in pending.drain(..) {
                        if packet.is_empty() {
                            continue;
                        }
                        let packet_type = packet[0];
                        let payload = &packet[1..];

                        match packet_type {
                            protocol::HEARTBEAT => {
                                pkt_buf.clear();
                                if pkt_buf.write_all(payload).is_ok() {
                                    match protocol::parse_pong(&mut pkt_buf, &crypto) {
                                        Ok(_pong) => {
                                            info!("Pong received from {remote_addr}");
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
                                pkt_buf.clear();
                                if pkt_buf.write_all(payload).is_ok() {
                                    if crypto.decrypt(&mut pkt_buf).is_ok() {
                                        let data = pkt_buf.as_ref().to_vec();
                                        dl_packets_1s += 1;
                                        dl_bytes_1s += data.len() as u64;
                                        // Any successfully authenticated
                                        // packet proves the session is alive;
                                        // refresh the liveness timestamp so
                                        // lost pongs during active traffic do
                                        // not cause a spurious reconnect.
                                        last_pong = Instant::now();
                                        rejected_since = None;
                                        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
                                        state.last_pong = last_pong;
                                        state.bytes_received.fetch_add(data.len() as u64, Ordering::Relaxed);
                                        state.packets_received.fetch_add(1, Ordering::Relaxed);
                                        batch.push(data);
                                    } else {
                                        dl_decrypt_fail_1s += 1;
                                        {
                                            let state = self.state.lock().unwrap_or_else(|e| e.into_inner());
                                            state.decrypt_failures.fetch_add(1, Ordering::Relaxed);
                                        }
                                        log::debug!("Downlink packet decrypt failed");
                                    }
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
                        self.callbacks.on_packets(std::mem::take(&mut batch));
                    }

                    if let Some(since) = rejected_since
                        && since.elapsed() > Duration::from_secs(3)
                    {
                        warn!("Session still rejected by {remote_addr} after liveness probe, reconnecting");
                        self.callbacks.on_error("session rejected by server".to_string());
                        break 'outer;
                    }

                    if last_pong.elapsed() > timeout {
                        warn!("Heartbeat timeout for {remote_addr}, exiting data loop");
                        self.callbacks.on_error("heartbeat timeout".to_string());
                        break 'outer;
                    }
                }
                _ = sleep(Duration::from_secs(1)) => {
                    if dl_packets_1s > 0 || dl_decrypt_fail_1s > 0 {
                        log::info!(
                            "Downlink last 1s: {} pkts / {} bytes, decrypt_failures={}",
                            dl_packets_1s, dl_bytes_1s, dl_decrypt_fail_1s
                        );
                    }
                    dl_packets_1s = 0;
                    dl_bytes_1s = 0;
                    dl_decrypt_fail_1s = 0;
                    if let Some(since) = rejected_since
                        && since.elapsed() > Duration::from_secs(3)
                    {
                        warn!("Session still rejected by {remote_addr} after liveness probe, reconnecting");
                        self.callbacks.on_error("session rejected by server".to_string());
                        break;
                    }
                    if last_pong.elapsed() > timeout {
                        warn!("Heartbeat timeout for {remote_addr}, exiting data loop");
                        self.callbacks.on_error("heartbeat timeout".to_string());
                        break;
                    }
                }
            }
        }

        log::info!("Data loop ended for {remote_addr}");

        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(h) = state.receive_handle.take() {
            h.abort();
        }
        if let Some(h) = state.heartbeat_handle.take() {
            h.abort();
        }
        if let Some(h) = state.uplink_handle.take() {
            h.abort();
        }
        state.uplink_tx = None;
        state.is_active = false;
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
