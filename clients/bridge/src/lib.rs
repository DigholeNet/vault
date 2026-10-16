// SPDX-License-Identifier: MIT
//! Thin UniFFI adapter over `vault_core::client::ClientSession`, shared by
//! the Android (Kotlin/JNA) and Apple (Swift) clients.
//!
//! All VPN client logic (handshake, heartbeat, reconnect, data pump, stats)
//! lives in vault-core; this crate only maps it to UniFFI and provides the
//! small bits of platform glue (logger init, TUN fd blocking mode).

use std::fs::OpenOptions;
use std::path::PathBuf;
use std::sync::{Arc, Mutex, Once, OnceLock};
use std::time::{SystemTime, UNIX_EPOCH};

use vault_core::PeerId;
use vault_core::client::{
    ClientCallbacks, ClientConfig, ClientError, ClientSession, TrafficStats as CoreTrafficStats,
};

uniffi::setup_scaffolding!();

static LOGGER_INIT: Once = Once::new();
static LOG_FILE_PATH: OnceLock<Mutex<Option<PathBuf>>> = OnceLock::new();

fn log_file_path() -> &'static Mutex<Option<PathBuf>> {
    LOG_FILE_PATH.get_or_init(|| Mutex::new(None))
}

/// Point the Rust file logger at the app's shared vault.log so core/bridge
/// records land in the same file as the Swift-side logs. Call before the
/// first `RustEdge` is created; safe to call again to change the path.
#[uniffi::export]
pub fn set_log_file_path(path: String) {
    init_platform_logger();
    if let Ok(mut guard) = log_file_path().lock() {
        *guard = Some(PathBuf::from(path));
    }
}

/// Append one line to the shared log file. Never blocks: if the path lock
/// is held (e.g. by a panicking thread that died mid-write) the line is
/// dropped rather than risking a deadlock.
fn append_file_log(line: &str) {
    let Some(mutex) = LOG_FILE_PATH.get() else {
        return;
    };
    let Ok(guard) = mutex.try_lock() else { return };
    let Some(path) = guard.as_ref() else { return };
    let Ok(mut file) = OpenOptions::new().create(true).append(true).open(path) else {
        return;
    };
    use std::io::Write;
    let _ = writeln!(file, "[{}] [rust] {line}", utc_timestamp());
}

/// UTC timestamp matching the Swift FileLogger line format (which uses local
/// time); the trailing Z marks these lines as UTC.
fn utc_timestamp() -> String {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    let secs = now.as_secs() as i64;
    let days = secs.div_euclid(86_400);
    let secs_of_day = secs.rem_euclid(86_400);
    let (h, m, s) = (
        secs_of_day / 3600,
        (secs_of_day % 3600) / 60,
        secs_of_day % 60,
    );
    // Howard Hinnant's civil_from_days.
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let year = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = if month <= 2 { year + 1 } else { year };
    format!(
        "{year:04}-{month:02}-{d:02} {h:02}:{m:02}:{s:02}.{:03}Z",
        now.subsec_millis()
    )
}

/// Log every panic (message + location) to the shared log file before the
/// default handling, so a crash that kills the extension process leaves a
/// trace instead of a silently truncated log.
fn install_panic_hook() {
    let default_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        let message = if let Some(s) = info.payload().downcast_ref::<&str>() {
            (*s).to_string()
        } else if let Some(s) = info.payload().downcast_ref::<String>() {
            s.clone()
        } else {
            "unknown panic payload".to_string()
        };
        let location = info
            .location()
            .map(|l| format!("{}:{}", l.file(), l.line()))
            .unwrap_or_else(|| "unknown location".to_string());
        append_file_log(&format!("[PANIC] {message} at {location}"));
        default_hook(info);
    }));
}

/// `log` facade implementation duplicating every record to os_log (visible
/// in Console.app) and to the shared vault.log file.
#[cfg(target_vendor = "apple")]
struct FileAndOsLogger {
    inner: oslog::OsLogger,
}

#[cfg(target_vendor = "apple")]
impl log::Log for FileAndOsLogger {
    fn enabled(&self, metadata: &log::Metadata) -> bool {
        self.inner.enabled(metadata)
    }

    fn log(&self, record: &log::Record) {
        if self.enabled(record.metadata()) {
            self.inner.log(record);
            append_file_log(&format!("[{}] {}", record.level(), record.args()));
        }
    }

    fn flush(&self) {}
}

fn init_platform_logger() {
    LOGGER_INIT.call_once(|| {
        install_panic_hook();

        // vault-core emits through both `log` and `tracing`. The log facade
        // below covers `log`; this subscriber routes tracing records into
        // the same shared file, otherwise they are silently dropped.
        // Note: set_global_default, not try_init — the latter also installs
        // a log logger (LogTracer), which conflicts with the facade below.
        let subscriber = tracing_subscriber::fmt()
            .with_writer(TraceLogWriter)
            .without_time() // append_file_log adds the timestamp
            .with_ansi(false)
            .with_target(false)
            .compact()
            .with_max_level(tracing::Level::INFO)
            .finish();
        let _ = tracing::subscriber::set_global_default(subscriber);

        #[cfg(target_os = "android")]
        android_logger::init_once(
            android_logger::Config::default()
                .with_max_level(log::LevelFilter::Info)
                .with_tag("vault-bridge"),
        );

        // Routes Rust `log` records to Apple's unified logging (os_log) and
        // to the shared vault.log file, so core logs show up both in
        // Console.app and in the in-app log view.
        #[cfg(target_vendor = "apple")]
        {
            let logger = FileAndOsLogger {
                inner: oslog::OsLogger::new("net.dighole.vault")
                    .level_filter(log::LevelFilter::Info),
            };
            if log::set_boxed_logger(Box::new(logger)).is_ok() {
                log::set_max_level(log::LevelFilter::Info);
            }
        }
    });
}

/// Routes tracing records into the shared vault.log.
struct TraceLogWriter;

impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for TraceLogWriter {
    type Writer = TraceLineWriter;

    fn make_writer(&'a self) -> Self::Writer {
        TraceLineWriter
    }
}

struct TraceLineWriter;

impl std::io::Write for TraceLineWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let line = String::from_utf8_lossy(buf);
        let line = line.trim_end();
        if !line.is_empty() {
            append_file_log(line);
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
    #[error("Crypto error: {0}")]
    CryptoError(String),
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

#[uniffi::export(callback_interface)]
pub trait EdgeCallbacks: Send + Sync {
    fn on_data(&self, data: Vec<u8>);
    /// Batched variant of `on_data`: delivers several decrypted packets in one
    /// call. Crosses the FFI boundary far less often under load, which matters
    /// because each FFI callback has a fixed cost.
    fn on_data_batch(&self, packets: Vec<Vec<u8>>);
    fn on_ip_assigned(&self, ipv4: String, ipv4_mask: String, ipv6: String, ipv6_prefixlen: i32);
    fn on_error(&self, error: String);
    /// Android `VpnService.protect(fd)` hook, invoked once per (re)connect.
    /// Apple platforms do not need it (traffic from the Network Extension
    /// process bypasses the tunnel by default) and should just return true.
    fn protect_socket(&self, fd: i32) -> bool;
}

/// Adapts the UniFFI `EdgeCallbacks` to vault-core's `ClientCallbacks`.
struct CallbackAdapter {
    inner: Arc<Box<dyn EdgeCallbacks>>,
}

impl ClientCallbacks for CallbackAdapter {
    fn on_packets(&self, packets: Vec<Vec<u8>>) {
        self.inner.on_data_batch(packets);
    }

    fn on_ip_assigned(&self, ipv4: String, ipv4_mask: String, ipv6: String, ipv6_prefixlen: i32) {
        self.inner
            .on_ip_assigned(ipv4, ipv4_mask, ipv6, ipv6_prefixlen);
    }

    fn on_error(&self, error: String) {
        self.inner.on_error(error);
    }
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
    host: String,
    port: u16,
    id: PeerId,
    device_name: String,
    platform: String,
    callbacks: Arc<Box<dyn EdgeCallbacks>>,
    session: Mutex<Option<ClientSession>>,
}

#[uniffi::export]
impl RustEdge {
    #[uniffi::constructor]
    pub fn new(
        password: String,
        host: String,
        port: i32,
        id: Vec<u8>,
        device_name: String,
        platform: String,
        callbacks: Box<dyn EdgeCallbacks>,
    ) -> Result<Arc<Self>, VpnError> {
        init_platform_logger();
        let id: PeerId = id
            .try_into()
            .map_err(|_| VpnError::InternalError("Peer id must be 16 bytes".to_string()))?;
        let port =
            u16::try_from(port).map_err(|_| VpnError::InternalError("invalid port".to_string()))?;
        Ok(Arc::new(Self {
            password,
            host,
            port,
            id,
            device_name,
            platform,
            callbacks: Arc::new(callbacks),
            session: Mutex::new(None),
        }))
    }

    pub fn connect(&self) -> Result<(), VpnError> {
        let mut guard = self
            .session
            .lock()
            .map_err(|_| VpnError::InternalError("lock poisoned".to_string()))?;
        if guard.is_some() {
            return Err(VpnError::AlreadyConnected);
        }

        let callbacks = self.callbacks.clone();
        let socket_protect: Arc<dyn Fn(i32) -> bool + Send + Sync> =
            Arc::new(move |fd| callbacks.protect_socket(fd));

        let config = ClientConfig {
            password: self.password.clone(),
            host: self.host.clone(),
            port: self.port,
            id: self.id,
            device_name: self.device_name.clone(),
            platform: self.platform.clone(),
            socket_protect: Some(socket_protect),
        };
        let callbacks: Arc<dyn ClientCallbacks> = Arc::new(CallbackAdapter {
            inner: self.callbacks.clone(),
        });

        let session = ClientSession::start(config, callbacks)?;
        *guard = Some(session);
        Ok(())
    }

    pub fn reconnect(&self) -> Result<(), VpnError> {
        self.shutdown()?;
        self.connect()
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

    /// Seconds since the last authenticated packet from the server; the
    /// Apple watchdog uses this to tear down a tunnel whose server died.
    pub fn get_last_activity_age_secs(&self) -> u64 {
        self.session
            .lock()
            .ok()
            .and_then(|g| g.as_ref().map(|s| s.last_activity_age_secs()))
            .unwrap_or(0)
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
        let mut guard = self
            .session
            .lock()
            .map_err(|_| VpnError::InternalError("lock poisoned".to_string()))?;
        if let Some(session) = guard.take() {
            session.shutdown()?;
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
