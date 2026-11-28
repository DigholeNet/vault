// SPDX-License-Identifier: MIT
//! Thin UniFFI adapter over `vault_core::client::ClientSession`, shared by
//! the Android (Kotlin/JNA) and Apple (Swift) clients.
//!
//! All VPN client logic (handshake, heartbeat, reconnect, data pump, stats)
//! lives in vault-core; this crate only maps it to UniFFI and provides the
//! small bits of platform glue (logger init, TUN fd blocking mode).

use std::any::Any;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, Once};

use vault_core::PeerId;
use vault_core::client::{
    ClientCallbacks, ClientConfig, ClientError, ClientSession, TrafficStats as CoreTrafficStats,
    TunnelSetup,
};
#[cfg(any(target_os = "android", target_vendor = "apple"))]
use vault_core::client::{Gateway, PeerSocket, TransportPath, TransportRoutes};
use vault_core::logger::shared;

pub mod diagnostics;
pub mod logging;
#[cfg(any(target_os = "android", target_vendor = "apple"))]
mod network;
pub mod settings;

uniffi::setup_scaffolding!();

static LOGGER_INIT: Once = Once::new();

#[derive(uniffi::Record)]
pub struct TunnelParameters {
    pub mtu_min: u16,
    pub mtu_max: u16,
    pub overhead: u16,
    pub dns_ipv4: Vec<String>,
    pub dns_ipv6: Vec<String>,
}

/// MTU limits and default resolvers shared by Android and Apple clients.
#[uniffi::export]
pub fn tunnel_parameters() -> TunnelParameters {
    TunnelParameters {
        mtu_min: vault_core::TUNNEL_MTU_MIN,
        mtu_max: vault_core::TUNNEL_MTU_MAX,
        overhead: vault_core::TUNNEL_OVERHEAD as u16,
        dns_ipv4: vault_core::DEFAULT_DNS_IPV4.map(str::to_owned).into(),
        dns_ipv6: vault_core::DEFAULT_DNS_IPV6.map(str::to_owned).into(),
    }
}

/// Resolve server candidates before the platform tunnel is enabled. Call on a worker thread.
#[uniffi::export]
pub fn resolve_server_candidates(host: String, port: i32) -> Result<Vec<String>, VpnError> {
    let port = u16::try_from(port).map_err(|_| VpnError::InternalError("invalid port".into()))?;
    let candidates = vault_core::client::resolve_server_candidates(&host, port)?;
    Ok(candidates
        .iter()
        .map(|address| address.ip().to_string())
        .collect())
}

/// Point the Rust file logger at the app's shared vault.log so core/bridge
/// records land in the same file as the Kotlin/Swift-side logs. Call before
/// the first `RustEdge` is created; safe to call again to change the path.
#[uniffi::export]
pub fn set_log_file_path(path: String) {
    init_platform_logger();
    shared::set_path(&path);
}

fn init_platform_logger() {
    LOGGER_INIT.call_once(|| {
        shared::install_panic_hook();

        // vault-core logs via `tracing` only; third-party crates may still
        // emit through the `log` facade, so bridge those records into
        // tracing and let the single subscriber pipeline below cover both.
        let _ = tracing_log::LogTracer::init();

        use tracing_subscriber::prelude::*;
        // File layer: every record at INFO and above lands in the app's
        // shared vault.log.
        let file_layer = tracing_subscriber::fmt::layer()
            .with_writer(shared::TraceLogWriter)
            .without_time() // shared::append adds the timestamp
            .with_ansi(false)
            .with_target(false)
            .compact();

        let registry = tracing_subscriber::registry()
            .with(tracing_subscriber::filter::LevelFilter::INFO)
            .with(file_layer);

        // Platform layer: mirror records to the OS log facility.
        #[cfg(target_os = "android")]
        let registry = registry.with(
            tracing_subscriber::fmt::layer()
                .with_writer(AndroidLogMakeWriter)
                .without_time() // logcat timestamps entries itself
                .with_ansi(false)
                .with_target(false)
                .compact(),
        );
        // Visible in Console.app, alongside the shared vault.log file.
        #[cfg(target_vendor = "apple")]
        let registry = registry.with(tracing_oslog::OsLogger::new(
            "net.dighole.vault",
            "vault-bridge",
        ));

        let _ = tracing::subscriber::set_global_default(registry);
    });
}

/// Writes formatted tracing records to logcat via `__android_log_write`,
/// with the priority mapped from the record's level.
#[cfg(target_os = "android")]
struct AndroidLogMakeWriter;

#[cfg(target_os = "android")]
impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for AndroidLogMakeWriter {
    type Writer = AndroidLogWriter;

    fn make_writer_for(&'a self, meta: &tracing::Metadata<'_>) -> Self::Writer {
        use android_log_sys::LogPriority;
        let level = meta.level();
        let priority = if *level == tracing::Level::ERROR {
            LogPriority::ERROR
        } else if *level == tracing::Level::WARN {
            LogPriority::WARN
        } else if *level == tracing::Level::INFO {
            LogPriority::INFO
        } else if *level == tracing::Level::DEBUG {
            LogPriority::DEBUG
        } else {
            LogPriority::VERBOSE
        };
        AndroidLogWriter { priority }
    }

    fn make_writer(&'a self) -> Self::Writer {
        AndroidLogWriter {
            priority: android_log_sys::LogPriority::INFO,
        }
    }
}

#[cfg(target_os = "android")]
struct AndroidLogWriter {
    priority: android_log_sys::LogPriority,
}

#[cfg(target_os = "android")]
impl std::io::Write for AndroidLogWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        // The fmt layer hands each event over in a single write; logcat
        // prints one line per call, so strip the trailing newline.
        let line = String::from_utf8_lossy(buf);
        let text = std::ffi::CString::new(line.trim_end())
            .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidData, "NUL in log line"))?;
        // SAFETY: both pointers are valid NUL-terminated strings that
        // outlive the call; __android_log_write does not retain them.
        unsafe {
            android_log_sys::__android_log_write(
                self.priority as std::os::raw::c_int,
                c"vault-bridge".as_ptr(),
                text.as_ptr(),
            );
        }
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[derive(Debug, thiserror::Error, uniffi::Error)]
#[uniffi(flat_error)]
pub enum VpnError {
    #[error("Already connected")]
    AlreadyConnected,
    #[error("Not connected")]
    NotConnected,
    #[error("DNS resolution failed: {0}")]
    DnsFailed(String),
    #[error("Socket bind failed: {0}")]
    BindFailed(String),
    #[error("Socket protect failed")]
    ProtectFailed,
    #[error("Handshake failed: {0}")]
    HandshakeFailed(String),
    #[error("IO error: {0}")]
    IoError(String),
    #[error("Internal error: {0}")]
    InternalError(String),
}

impl From<ClientError> for VpnError {
    fn from(e: ClientError) -> Self {
        match e {
            ClientError::AlreadyConnected => VpnError::AlreadyConnected,
            ClientError::NotConnected => VpnError::NotConnected,
            ClientError::DnsFailed(m) => VpnError::DnsFailed(m),
            ClientError::BindFailed(m) => VpnError::BindFailed(m),
            ClientError::ProtectFailed => VpnError::ProtectFailed,
            ClientError::HandshakeFailed(m) => VpnError::HandshakeFailed(m),
            ClientError::IoError(m) => VpnError::IoError(m),
            ClientError::InternalError(m) => VpnError::InternalError(m),
        }
    }
}

/// Resolver results and the physical network identity are captured together.
#[derive(uniffi::Record)]
pub struct MobileTransport {
    pub addresses: Vec<String>,
    /// Android Network handle or Apple interface index.
    pub network: u64,
    pub generation: u64,
    pub gateway_ipv4: Option<String>,
    /// Interface addresses with prefix lengths, supplied only on Wi-Fi or Ethernet.
    pub lan_addresses: Vec<String>,
}

#[derive(uniffi::Record)]
pub struct MobileRoutes {
    pub addresses: Vec<String>,
    pub generation: u64,
}

#[uniffi::export(callback_interface)]
pub trait EdgeCallbacks: Send + Sync {
    /// Delivers several decrypted packets in one call. Crosses the FFI
    /// boundary far less often than one callback per packet, which matters
    /// because each FFI callback has a fixed cost.
    fn on_data_batch(&self, packets: Vec<Vec<u8>>);
    /// Configure the TUN initially or when addresses change, never for same-IP reconnects.
    fn on_ip_assigned(&self, assignment: settings::TunnelAssignment, setup: Arc<RustTunnelSetup>);
    fn resolve_transport(&self) -> Option<MobileTransport>;
    fn on_transport_assigned(
        &self,
        assignment: settings::TunnelAssignment,
        routes: MobileRoutes,
        setup: Arc<RustTunnelSetup>,
    );
    fn on_error(&self, error: String);
    /// Android `VpnService.protect(fd)` hook, invoked once per (re)connect.
    /// Apple platforms do not need it (traffic from the Network Extension
    /// process bypasses the tunnel by default) and should just return true.
    fn protect_socket(&self, fd: i32) -> bool;
}

#[derive(Debug, uniffi::Object)]
pub struct RustTunnelSetup(Arc<TunnelSetup>);

#[uniffi::export]
impl RustTunnelSetup {
    pub fn is_pending(&self) -> bool {
        self.0.is_pending()
    }

    /// Returns false if this attempt has already been completed or cancelled.
    pub fn complete(&self, error: Option<String>) -> bool {
        self.0.complete(error.map_or(Ok(()), Err))
    }
}

/// Adapts the UniFFI `EdgeCallbacks` to vault-core's `ClientCallbacks`.
struct CallbackAdapter {
    #[cfg(any(target_os = "android", target_vendor = "apple"))]
    peer_mtu: Arc<AtomicUsize>,
    inner: Arc<Box<dyn EdgeCallbacks>>,
}

/// Extracts a printable message from a caught panic payload.
fn panic_payload_message(payload: &Box<dyn Any + Send>) -> &str {
    if let Some(s) = payload.downcast_ref::<&str>() {
        s
    } else if let Some(s) = payload.downcast_ref::<String>() {
        s
    } else {
        "non-string panic payload"
    }
}

// A Kotlin/Swift callback throwing an exception crosses back into Rust as a
// panic (UniFFI `handle_callback_unexpected_error`). These callbacks run on
// the session's tokio worker threads, where tokio silently swallows the
// panicking task — the run loop dies with `is_active` stuck true, no
// `on_error`, and no recovery. Catch the panic at the FFI boundary instead:
// log it, and for `on_ip_assigned` also report failure to the core so the
// connection attempt aborts and the run loop retries instead of running
// with an unconfigured TUN. `on_error` is NOT re-invoked from these handlers
// to avoid a recursive panic loop against an already-faulting callback.
impl ClientCallbacks for CallbackAdapter {
    fn on_packets(&self, packets: Vec<Vec<u8>>) {
        if let Err(payload) = catch_unwind(AssertUnwindSafe(|| self.inner.on_data_batch(packets))) {
            tracing::error!(
                "EdgeCallbacks::on_data_batch panicked: {}",
                panic_payload_message(&payload)
            );
        }
    }

    fn on_ip_assigned(
        &self,
        assignment: vault_core::settings::TunnelAssignment,
        setup: Arc<TunnelSetup>,
    ) {
        let setup = Arc::new(RustTunnelSetup(setup));
        if let Err(payload) = catch_unwind(AssertUnwindSafe(|| {
            self.inner.on_ip_assigned(assignment.into(), setup.clone())
        })) {
            let message = panic_payload_message(&payload);
            tracing::error!("EdgeCallbacks::on_ip_assigned panicked: {message}");
            setup.complete(Some(format!("on_ip_assigned callback panicked: {message}")));
        }
    }

    #[cfg(any(target_os = "android", target_vendor = "apple"))]
    fn resolve_transport(&self) -> Option<Result<TransportPath, ClientError>> {
        let result = catch_unwind(AssertUnwindSafe(|| self.inner.resolve_transport()));
        let transport = match result {
            Ok(Some(transport)) => transport,
            Ok(None) => return None,
            Err(payload) => {
                return Some(Err(ClientError::DnsFailed(
                    panic_payload_message(&payload).into(),
                )));
            }
        };
        if transport.network == 0
            || transport.addresses.is_empty()
            || transport
                .addresses
                .iter()
                .any(|ip| ip.parse::<std::net::IpAddr>().is_err())
        {
            return Some(Err(ClientError::DnsFailed(
                "invalid physical network resolver result".into(),
            )));
        }
        let mtu = self.peer_mtu.clone();
        let network = transport.network;
        let gateway = transport
            .gateway_ipv4
            .as_deref()
            .and_then(|gateway| gateway.parse::<std::net::Ipv4Addr>().ok());
        let callbacks = self.inner.clone();
        let lan = network::LanAddresses::new(&transport.lan_addresses);
        Some(Ok(TransportPath {
            hosts: transport.addresses,
            generation: transport.generation,
            prepare_socket: Arc::new(move |fd, addr, bound| {
                bind_mobile_socket(network, fd, addr.is_ipv6())
                    .inspect_err(|error| {
                        tracing::warn!(%addr, %error, "Could not bind mobile transport socket");
                    })
                    .ok()?;
                let lan_endpoint = lan.endpoint(addr, bound.port(), |probe_fd| {
                    if !callbacks.protect_socket(probe_fd) {
                        return Err(std::io::ErrorKind::PermissionDenied.into());
                    }
                    bind_mobile_socket(network, probe_fd, addr.is_ipv6())
                });
                let lan = lan.clone();
                Some(PeerSocket {
                    mtu: mtu.clone(),
                    lan_endpoint,
                    allow_lan: Arc::new(move |remote| {
                        lan_endpoint.is_some_and(|local| {
                            remote.port() != 0 && lan.allows(local.ip(), remote.ip())
                        })
                    }),
                    gateway: gateway.map(|gateway| {
                        let callbacks = callbacks.clone();
                        Gateway::new(gateway, move |fd| {
                            if !callbacks.protect_socket(fd) {
                                return Err(std::io::ErrorKind::PermissionDenied.into());
                            }
                            bind_mobile_socket(network, fd, false)
                        })
                    }),
                })
            }),
        }))
    }

    #[cfg(any(target_os = "android", target_vendor = "apple"))]
    fn on_transport_assigned(
        &self,
        assignment: vault_core::settings::TunnelAssignment,
        routes: Option<TransportRoutes>,
        setup: Arc<TunnelSetup>,
    ) {
        let Some(routes) = routes else {
            return self.on_ip_assigned(assignment, setup);
        };
        let setup = Arc::new(RustTunnelSetup(setup));
        let routes = MobileRoutes {
            addresses: routes.addresses,
            generation: routes.generation,
        };
        if let Err(payload) = catch_unwind(AssertUnwindSafe(|| {
            self.inner
                .on_transport_assigned(assignment.into(), routes, setup.clone());
        })) {
            let message = panic_payload_message(&payload);
            tracing::error!("EdgeCallbacks::on_transport_assigned panicked: {message}");
            setup.complete(Some(format!(
                "on_transport_assigned callback panicked: {message}"
            )));
        }
    }

    fn on_error(&self, error: String) {
        if let Err(payload) = catch_unwind(AssertUnwindSafe(|| self.inner.on_error(error))) {
            tracing::error!(
                "EdgeCallbacks::on_error panicked: {}",
                panic_payload_message(&payload)
            );
        }
    }
}

#[cfg(any(target_os = "android", target_vendor = "apple"))]
fn bind_mobile_socket(network: u64, fd: i32, ipv6: bool) -> std::io::Result<()> {
    #[cfg(target_os = "android")]
    {
        use vault_core::diagnostics::transport::NetworkBinding;
        crate::network::AndroidNetworkBinding(network).bind(fd, ipv6)
    }
    #[cfg(target_vendor = "apple")]
    {
        use vault_core::diagnostics::transport::NetworkBinding;
        let index = u32::try_from(network).map_err(std::io::Error::other)?;
        crate::network::AppleInterfaceBinding(index).bind(fd, ipv6)
    }
}

#[derive(uniffi::Record, Clone, Default)]
pub struct ConnectionStatus {
    pub connected: bool,
    pub generation: u64,
    pub public_ip: String,
    pub network_rtt_ms: Option<u64>,
    pub network_rtt_generation: Option<u64>,
}

#[derive(uniffi::Record, Clone, Default)]
pub struct TrafficStats {
    pub bytes_sent: i64,
    pub bytes_received: i64,
    pub packets_sent: i64,
    pub packets_received: i64,
    pub send_speed: i64,
    pub receive_speed: i64,
}

impl From<CoreTrafficStats> for TrafficStats {
    fn from(s: CoreTrafficStats) -> Self {
        Self {
            bytes_sent: s.bytes_sent,
            bytes_received: s.bytes_received,
            packets_sent: s.packets_sent,
            packets_received: s.packets_received,
            send_speed: s.send_speed,
            receive_speed: s.receive_speed,
        }
    }
}

#[derive(uniffi::Object)]
pub struct RustEdge {
    password: String,
    hosts: Vec<String>,
    port: u16,
    id: PeerId,
    device_name: String,
    platform: String,
    callbacks: Arc<Box<dyn EdgeCallbacks>>,
    session: Mutex<Option<ClientSession>>,
    closing: AtomicBool,
    managed_transport: AtomicBool,
    peer_mtu: Arc<AtomicUsize>,
}

#[uniffi::export]
impl RustEdge {
    #[uniffi::constructor]
    pub fn new(
        password: String,
        hosts: Vec<String>,
        port: i32,
        id: Vec<u8>,
        device_name: String,
        platform: String,
        callbacks: Box<dyn EdgeCallbacks>,
    ) -> Result<Arc<Self>, VpnError> {
        init_platform_logger();
        if hosts.is_empty() {
            return Err(VpnError::InternalError(
                "hosts must not be empty".to_string(),
            ));
        }
        let id: PeerId = id
            .try_into()
            .map_err(|_| VpnError::InternalError("Peer id must be 16 bytes".to_string()))?;
        let port =
            u16::try_from(port).map_err(|_| VpnError::InternalError("invalid port".to_string()))?;
        Ok(Arc::new(Self {
            password,
            hosts,
            port,
            id,
            device_name,
            platform,
            callbacks: Arc::new(callbacks),
            session: Mutex::new(None),
            closing: AtomicBool::new(false),
            managed_transport: AtomicBool::new(false),
            peer_mtu: Arc::new(AtomicUsize::new(0)),
        }))
    }

    /// Enable network-aware transport on Android and Apple before connecting.
    pub fn enable_managed_transport(&self) {
        self.managed_transport.store(true, Ordering::Release);
    }

    pub fn set_peer_mtu(&self, mtu: u32) {
        self.peer_mtu.store(mtu as usize, Ordering::Release);
    }

    pub fn connect(&self) -> Result<(), VpnError> {
        let mut guard = self
            .session
            .lock()
            .map_err(|_| VpnError::InternalError("lock poisoned".to_string()))?;
        if guard.is_some() || self.closing.load(Ordering::Acquire) {
            return Err(VpnError::AlreadyConnected);
        }

        let callbacks = self.callbacks.clone();
        let socket_protect: Arc<dyn Fn(i32) -> bool + Send + Sync> =
            Arc::new(move |fd| callbacks.protect_socket(fd));

        let managed_transport = cfg!(any(target_os = "android", target_vendor = "apple"))
            && self.managed_transport.load(Ordering::Acquire);
        let config = ClientConfig {
            password: self.password.clone(),
            hosts: self.hosts.clone(),
            port: self.port,
            id: self.id,
            device_name: self.device_name.clone(),
            platform: self.platform.clone(),
            managed_transport,
            peer_socket_setup: None,
            socket_protect: Some(socket_protect),
        };
        let callbacks: Arc<dyn ClientCallbacks> = Arc::new(CallbackAdapter {
            #[cfg(any(target_os = "android", target_vendor = "apple"))]
            peer_mtu: self.peer_mtu.clone(),
            inner: self.callbacks.clone(),
        });

        let session = ClientSession::start(config, callbacks)?;
        *guard = Some(session);
        Ok(())
    }

    pub fn reconnect(&self) -> Result<(), VpnError> {
        let guard = self
            .session
            .lock()
            .map_err(|_| VpnError::InternalError("lock poisoned".into()))?;
        guard.as_ref().ok_or(VpnError::NotConnected)?.reconnect()?;
        Ok(())
    }

    /// Read transport readiness and latency in one core snapshot.
    pub fn get_connection_status(&self) -> ConnectionStatus {
        self.session
            .lock()
            .ok()
            .and_then(|session| {
                session.as_ref().map(|session| {
                    let status = session.connection_status();
                    ConnectionStatus {
                        connected: status.connected,
                        generation: status.generation,
                        public_ip: status.public_ip,
                        network_rtt_ms: status.network_rtt_ms,
                        network_rtt_generation: status.network_rtt_generation,
                    }
                })
            })
            .unwrap_or_default()
    }

    pub fn is_connected(&self) -> bool {
        self.get_connection_status().connected
    }

    pub fn get_traffic_stats(&self) -> TrafficStats {
        let Ok(guard) = self.session.lock() else {
            return TrafficStats::default();
        };
        guard
            .as_ref()
            .map(|s| s.traffic_stats().into())
            .unwrap_or_default()
    }

    /// Queues an outgoing packet for the tunnel.
    pub fn write_data(&self, data: Vec<u8>) -> Result<(), VpnError> {
        let guard = self
            .session
            .lock()
            .map_err(|_| VpnError::InternalError("lock poisoned".to_string()))?;
        let session = guard.as_ref().ok_or(VpnError::NotConnected)?;
        session.write_packet(data).map_err(VpnError::from)
    }

    pub fn shutdown(&self) -> Result<(), VpnError> {
        let session = {
            let mut guard = self
                .session
                .lock()
                .map_err(|_| VpnError::InternalError("lock poisoned".to_string()))?;
            let session = guard.take();
            if session.is_some() {
                self.closing.store(true, Ordering::Release);
            }
            session
        };
        // Callbacks may read statistics while shutdown waits for them. Drop
        // the session mutex before joining any background tasks.
        if let Some(session) = session {
            let result = session.shutdown();
            drop(session);
            self.closing.store(false, Ordering::Release);
            result?;
        }
        Ok(())
    }
}

impl Drop for RustEdge {
    fn drop(&mut self) {
        let _ = self.shutdown();
    }
}

/// Clears O_NONBLOCK on the given file descriptor so that read() blocks.
///
/// Some OEM ROMs hand the VpnService TUN fd to the app with O_NONBLOCK set.
/// `FileInputStream.read()` on such an fd returns 0 (EAGAIN) instead of
/// blocking when no packet is queued, which makes the TUN read loop spin at
/// 100% CPU (and pay a JNI exception for every empty read). Call this once
/// right after the TUN interface is established to restore blocking mode.
#[uniffi::export]
pub fn set_fd_blocking(fd: i32) {
    // SAFETY: `fd` is a valid open file descriptor supplied by the caller
    // (the platform VPN API); fcntl only reads/updates file status flags and
    // does not access memory.
    unsafe {
        let flags = libc::fcntl(fd, libc::F_GETFL);
        if flags >= 0 {
            libc::fcntl(fd, libc::F_SETFL, flags & !libc::O_NONBLOCK);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Weak, mpsc};
    use std::time::{Duration, Instant};

    struct ReentrantCallbacks {
        edge: Arc<Mutex<Weak<RustEdge>>>,
        entered: mpsc::Sender<()>,
        release: Mutex<mpsc::Receiver<bool>>,
        completed: Arc<AtomicBool>,
    }

    impl EdgeCallbacks for ReentrantCallbacks {
        fn on_data_batch(&self, _: Vec<Vec<u8>>) {}
        fn resolve_transport(&self) -> Option<MobileTransport> {
            None
        }
        fn on_transport_assigned(
            &self,
            assignment: settings::TunnelAssignment,
            _: MobileRoutes,
            setup: Arc<RustTunnelSetup>,
        ) {
            self.on_ip_assigned(assignment, setup);
        }

        fn on_error(&self, _: String) {}
        fn protect_socket(&self, _: i32) -> bool {
            true
        }
        fn on_ip_assigned(&self, _: settings::TunnelAssignment, _: Arc<RustTunnelSetup>) {
            self.entered.send(()).unwrap();
            // On a failed lock probe, skip re-entry so the test can fail
            // cleanly rather than leaving a permanently deadlocked worker.
            if self.release.lock().unwrap().recv().unwrap() {
                let edge = self.edge.lock().unwrap().upgrade().unwrap();
                let _ = edge.get_traffic_stats();
                let _ = edge.is_connected();
                assert!(matches!(
                    edge.write_data(vec![1]),
                    Err(VpnError::NotConnected)
                ));
                self.completed.store(true, Ordering::Release);
            }
        }
    }

    #[test]
    fn reentrant_callback_no_deadlock() {
        let runtime = tokio::runtime::Runtime::new().unwrap();
        let (server, server_task) =
            runtime.block_on(vault_core::test_utils::run_mock_server("test"));
        let (entered_tx, entered_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();
        let weak = Arc::new(Mutex::new(Weak::new()));
        let completed = Arc::new(AtomicBool::new(false));
        let edge = RustEdge::new(
            "test".into(),
            vec!["127.0.0.1".into()],
            server.port().into(),
            vec![1; 16],
            String::new(),
            "test".into(),
            Box::new(ReentrantCallbacks {
                edge: weak.clone(),
                entered: entered_tx,
                release: Mutex::new(release_rx),
                completed: completed.clone(),
            }),
        )
        .unwrap();
        *weak.lock().unwrap() = Arc::downgrade(&edge);
        edge.connect().unwrap();
        entered_rx.recv_timeout(Duration::from_secs(10)).unwrap();

        let closer = edge.clone();
        let (done_tx, done_rx) = mpsc::channel();
        let closing_thread = std::thread::spawn(move || {
            let foreign = tokio::runtime::Runtime::new().unwrap();
            foreign.block_on(async {
                done_tx.send(closer.shutdown()).unwrap();
            });
        });
        let deadline = Instant::now() + Duration::from_secs(5);
        let unlocked = loop {
            if let Ok(guard) = edge.session.try_lock()
                && guard.is_none()
                && edge.closing.load(Ordering::Acquire)
            {
                break true;
            }
            if Instant::now() >= deadline {
                break false;
            }
            std::thread::yield_now();
        };
        // While callbacks are draining, connect must not start a new session.
        let connect_blocked = unlocked && matches!(edge.connect(), Err(VpnError::AlreadyConnected));
        if unlocked {
            edge.shutdown().unwrap();
            assert!(edge.closing.load(Ordering::Acquire));
        }
        release_tx.send(unlocked).unwrap();
        done_rx
            .recv_timeout(Duration::from_secs(5))
            .unwrap()
            .unwrap();
        closing_thread.join().unwrap();
        server_task.abort();
        runtime.block_on(async {
            let _ = server_task.await;
        });
        assert!(unlocked, "shutdown held the session mutex while waiting");
        assert!(connect_blocked);
        assert!(completed.load(Ordering::Acquire));
        assert!(!edge.closing.load(Ordering::Acquire));
    }
}
