// SPDX-License-Identifier: MIT
//! Per-transport counters and log windows for client diagnostics.
//! Independent of the application's traffic-speed polling and platform records.
//!
//! Shared counters use relaxed atomics: snapshots are observations, not a
//! transaction across tasks. Activity concurrent with a snapshot can land in
//! adjacent reporting windows. Queue peaks are observed samples, not a claim
//! to capture every transient occupancy change.

use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicI64, AtomicU64, AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use tokio::sync::mpsc;
use tokio::time::{Interval, MissedTickBehavior, interval_at};
use tracing::{info, warn};

const REPORT_INTERVAL: Duration = Duration::from_secs(30);
// Failures/backpressure keep the shorter window; only healthy summaries slow down.
const ERROR_REPORT_INTERVAL: Duration = Duration::from_secs(5);
const NO_ERRNO: i64 = i64::MIN;

/// Keep the one-second liveness cadence without recreating a sleep whenever
/// traffic arrives. Missed ticks must not produce a burst of log reports.
pub(super) fn maintenance_interval() -> Interval {
    let period = Duration::from_secs(1);
    let mut ticker = interval_at(tokio::time::Instant::now() + period, period);
    ticker.set_missed_tick_behavior(MissedTickBehavior::Skip);
    ticker
}

pub(super) struct QueueMetrics {
    sender: mpsc::WeakSender<Vec<u8>>,
    capacity: usize,
    peak: AtomicUsize,
}

#[derive(Debug, Default, Clone, Copy)]
pub(super) struct QueueSnapshot {
    pub depth: usize,
    pub peak: usize,
    pub capacity: usize,
}

impl QueueMetrics {
    pub fn new(sender: &mpsc::Sender<Vec<u8>>) -> Self {
        Self {
            sender: sender.downgrade(),
            capacity: sender.max_capacity(),
            peak: AtomicUsize::new(sender.max_capacity() - sender.capacity()),
        }
    }

    pub fn observe(&self, depth: usize) {
        self.peak
            .fetch_max(depth.min(self.capacity), Ordering::Relaxed);
    }

    pub fn snapshot(&self) -> QueueSnapshot {
        let depth = self
            .sender
            .upgrade()
            .map(|sender| self.capacity - sender.capacity())
            .unwrap_or(0);
        // Carry current occupancy into the next window even if no packet
        // arrives to trigger another observe() call while the queue is stuck.
        let peak = self.peak.swap(depth, Ordering::Relaxed).max(depth);
        QueueSnapshot {
            depth,
            peak,
            capacity: self.capacity,
        }
    }
}

pub(super) struct ReceiveMetrics {
    pub queue: QueueMetrics,
    waits: AtomicU64,
    wait_total_ns: AtomicU64,
    wait_max_ns: AtomicU64,
    receive_errors: AtomicU64,
    last_errno: AtomicI64,
}

#[derive(Debug, Default, Clone, Copy)]
pub(super) struct ReceiveSnapshot {
    pub queue: QueueSnapshot,
    pub waits: u64,
    pub wait_total_ms: f64,
    pub wait_max_ms: f64,
    pub receive_errors: u64,
    pub last_errno: Option<i32>,
}

impl ReceiveMetrics {
    pub fn new(sender: &mpsc::Sender<Vec<u8>>) -> Self {
        Self {
            queue: QueueMetrics::new(sender),
            waits: AtomicU64::new(0),
            wait_total_ns: AtomicU64::new(0),
            wait_max_ns: AtomicU64::new(0),
            receive_errors: AtomicU64::new(0),
            last_errno: AtomicI64::new(NO_ERRNO),
        }
    }

    /// A completed wait for channel space, not a dropped UDP datagram.
    pub fn record_wait(&self, elapsed: Duration) {
        let ns = duration_ns(elapsed);
        self.waits.fetch_add(1, Ordering::Relaxed);
        self.wait_total_ns.fetch_add(ns, Ordering::Relaxed);
        self.wait_max_ns.fetch_max(ns, Ordering::Relaxed);
    }

    pub fn record_receive_error(&self, error: &io::Error) {
        self.receive_errors.fetch_add(1, Ordering::Relaxed);
        self.last_errno.store(
            error.raw_os_error().map(i64::from).unwrap_or(NO_ERRNO),
            Ordering::Relaxed,
        );
    }

    pub fn snapshot(&self) -> ReceiveSnapshot {
        let errno = self.last_errno.swap(NO_ERRNO, Ordering::Relaxed);
        ReceiveSnapshot {
            queue: self.queue.snapshot(),
            waits: self.waits.swap(0, Ordering::Relaxed),
            wait_total_ms: self.wait_total_ns.swap(0, Ordering::Relaxed) as f64 / 1_000_000.0,
            wait_max_ms: self.wait_max_ns.swap(0, Ordering::Relaxed) as f64 / 1_000_000.0,
            receive_errors: self.receive_errors.swap(0, Ordering::Relaxed),
            last_errno: (errno != NO_ERRNO).then_some(errno as i32),
        }
    }
}

/// Local to the single uplink task; no atomics or per-error allocations.
#[derive(Debug, Default)]
struct UdpSendErrors {
    pub total: u64,
    pub message_too_large: u64,
    pub would_block: u64,
    pub no_buffer_space: u64,
    pub unreachable: u64,
    pub other: u64,
    pub last_errno: Option<i32>,
}

impl UdpSendErrors {
    fn record(&mut self, error: &io::Error) {
        self.total += 1;
        self.last_errno = error.raw_os_error();
        // These errno values are platform-specific, so compare the target's
        // libc constants before the portable ErrorKind fallback.
        #[cfg(unix)]
        match error.raw_os_error() {
            Some(libc::EMSGSIZE) => {
                self.message_too_large += 1;
                return;
            }
            Some(libc::ENOBUFS) => {
                self.no_buffer_space += 1;
                return;
            }
            Some(libc::ENETUNREACH | libc::EHOSTUNREACH) => {
                self.unreachable += 1;
                return;
            }
            _ => {}
        }
        match error.kind() {
            io::ErrorKind::WouldBlock => self.would_block += 1,
            io::ErrorKind::NetworkUnreachable | io::ErrorKind::HostUnreachable => {
                self.unreachable += 1;
            }
            _ => self.other += 1,
        }
    }
}

/// Local to the data loop. Durations cover the synchronous callback itself,
/// not delivery acknowledgements from the destination or the OS network stack.
#[derive(Debug, Default)]
struct BatchMetrics {
    pub batches: u64,
    pub packets: u64,
    pub max_packets: usize,
    pub total_callback_ns: u64,
    pub max_callback_ns: u64,
}

impl BatchMetrics {
    fn record(&mut self, packets: usize, elapsed: Duration) {
        let ns = duration_ns(elapsed);
        self.batches += 1;
        self.packets += packets as u64;
        self.max_packets = self.max_packets.max(packets);
        self.total_callback_ns = self.total_callback_ns.saturating_add(ns);
        self.max_callback_ns = self.max_callback_ns.max(ns);
    }

    fn avg_packets(&self) -> f64 {
        if self.batches == 0 {
            0.0
        } else {
            self.packets as f64 / self.batches as f64
        }
    }

    fn callback_avg_ms(&self) -> f64 {
        if self.batches == 0 {
            0.0
        } else {
            self.total_callback_ns as f64 / self.batches as f64 / 1_000_000.0
        }
    }

    fn callback_max_ms(&self) -> f64 {
        self.max_callback_ns as f64 / 1_000_000.0
    }
}

fn duration_ns(duration: Duration) -> u64 {
    duration.as_nanos().min(u64::MAX as u128) as u64
}

/// Queue failures belong to one transport, unlike the session-wide UI totals.
/// An aborted task may finish dropping after its replacement has already run.
pub(super) struct UplinkQueueMetrics {
    pub queue: QueueMetrics,
    pub full_drops: AtomicU64,
    pub closed_drops: AtomicU64,
}

impl UplinkQueueMetrics {
    pub(super) fn new(sender: &mpsc::Sender<Vec<u8>>) -> Self {
        Self {
            queue: QueueMetrics::new(sender),
            full_drops: AtomicU64::new(0),
            closed_drops: AtomicU64::new(0),
        }
    }
}

pub(super) struct UplinkReport {
    queue: Arc<UplinkQueueMetrics>,
    peer: SocketAddr,
    generation: u64,
    started: Instant,
    bytes: u64,
    packets: u64,
    build_failures: u64,
    errors: UdpSendErrors,
}

impl UplinkReport {
    pub(super) fn new(queue: Arc<UplinkQueueMetrics>, peer: SocketAddr, generation: u64) -> Self {
        Self {
            queue,
            peer,
            generation,
            started: Instant::now(),
            bytes: 0,
            packets: 0,
            build_failures: 0,
            errors: UdpSendErrors::default(),
        }
    }

    pub(super) fn sent(&mut self, bytes: usize) {
        self.bytes += bytes as u64;
        self.packets += 1;
    }

    pub(super) fn build_failure(&mut self) {
        self.build_failures += 1;
    }

    pub(super) fn send_error(&mut self, error: &io::Error) {
        self.errors.record(error);
    }

    pub(super) fn report_if_due(&mut self) {
        let elapsed = self.started.elapsed();
        let has_failures = self.build_failures > 0
            || self.errors.total > 0
            || self.queue.full_drops.load(Ordering::Relaxed) > 0
            || self.queue.closed_drops.load(Ordering::Relaxed) > 0;
        if elapsed >= REPORT_INTERVAL || (has_failures && elapsed >= ERROR_REPORT_INTERVAL) {
            self.report(false);
        }
    }

    fn report(&mut self, final_window: bool) {
        let now = Instant::now();
        let elapsed = now.duration_since(self.started).as_secs_f64();
        self.started = now;
        let bytes = std::mem::take(&mut self.bytes);
        let packets = std::mem::take(&mut self.packets);
        let build_failures = std::mem::take(&mut self.build_failures);
        let queue = self.queue.queue.snapshot();
        let queue_full_drops = self.queue.full_drops.swap(0, Ordering::Relaxed);
        let queue_closed_drops = self.queue.closed_drops.swap(0, Ordering::Relaxed);
        let errors = std::mem::take(&mut self.errors);
        if packets == 0
            && build_failures == 0
            && queue_full_drops == 0
            && queue_closed_drops == 0
            && queue.peak == 0
            && errors.total == 0
        {
            return;
        }
        if queue_full_drops > 0 || queue_closed_drops > 0 || build_failures > 0 || errors.total > 0
        {
            // Keep failures visible and detailed even with warning-only filters.
            warn!(
                generation = self.generation,
                peer = %self.peer,
                final_window,
                elapsed_s = elapsed,
                packets,
                payload_bytes = bytes,
                payload_Bps = bytes as f64 / elapsed.max(1e-6),
                queue_depth = queue.depth,
                queue_peak = queue.peak,
                queue_capacity = queue.capacity,
                queue_full_drops,
                queue_closed_drops,
                build_failures,
                send_failures = errors.total,
                send_emsgsize = errors.message_too_large,
                send_would_block = errors.would_block,
                send_enobufs = errors.no_buffer_space,
                send_unreachable = errors.unreachable,
                send_other = errors.other,
                last_errno = ?errors.last_errno,
                "VPN uplink metrics"
            );
        } else {
            info!(
                generation = self.generation,
                final_window,
                elapsed_s = format_args!("{elapsed:.3}"),
                packets,
                payload_bytes = bytes,
                payload_Bps = (bytes as f64 / elapsed.max(1e-6)).round(),
                queue_depth = queue.depth,
                queue_peak = queue.peak,
                "VPN uplink metrics"
            );
        }
    }
}

impl Drop for UplinkReport {
    fn drop(&mut self) {
        // Task cancellation on reconnect/shutdown also flushes the partial
        // window; otherwise short failures disappear before the first tick.
        self.report(true);
    }
}

pub(super) struct DownlinkReport {
    receive: Arc<ReceiveMetrics>,
    peer: SocketAddr,
    generation: u64,
    started: Instant,
    packets: u64,
    bytes: u64,
    decrypt_failures: u64,
    batches: BatchMetrics,
}

impl DownlinkReport {
    pub(super) fn new(receive: Arc<ReceiveMetrics>, peer: SocketAddr, generation: u64) -> Self {
        Self {
            receive,
            peer,
            generation,
            started: Instant::now(),
            packets: 0,
            bytes: 0,
            decrypt_failures: 0,
            batches: BatchMetrics::default(),
        }
    }

    pub(super) fn packet(&mut self, bytes: usize) {
        self.packets += 1;
        self.bytes += bytes as u64;
    }

    pub(super) fn decrypt_failure(&mut self) {
        self.decrypt_failures += 1;
    }

    pub(super) fn batch(&mut self, packets: usize, duration: Duration) {
        self.batches.record(packets, duration);
    }

    pub(super) fn report_if_due(&mut self) {
        let elapsed = self.started.elapsed();
        let has_anomalies = self.decrypt_failures > 0
            || self.receive.waits.load(Ordering::Relaxed) > 0
            || self.receive.receive_errors.load(Ordering::Relaxed) > 0;
        if elapsed >= REPORT_INTERVAL || (has_anomalies && elapsed >= ERROR_REPORT_INTERVAL) {
            self.report(false);
        }
    }

    fn report(&mut self, final_window: bool) {
        let now = Instant::now();
        let elapsed = now.duration_since(self.started).as_secs_f64();
        self.started = now;
        let packets = std::mem::take(&mut self.packets);
        let bytes = std::mem::take(&mut self.bytes);
        let decrypt_failures = std::mem::take(&mut self.decrypt_failures);
        let batches = std::mem::take(&mut self.batches);
        let receive = self.receive.snapshot();
        if packets == 0
            && decrypt_failures == 0
            && receive.waits == 0
            && receive.receive_errors == 0
        {
            // Heartbeats also cross the receive queue; its peak alone is not data traffic.
            return;
        }
        if decrypt_failures > 0 || receive.waits > 0 || receive.receive_errors > 0 {
            warn!(
                generation = self.generation,
                peer = %self.peer,
                final_window,
                elapsed_s = elapsed,
                decrypted_packets = packets,
                payload_bytes = bytes,
                payload_Bps = bytes as f64 / elapsed.max(1e-6),
                decrypt_failures,
                queue_depth = receive.queue.depth,
                queue_peak = receive.queue.peak,
                queue_capacity = receive.queue.capacity,
                queue_waits = receive.waits,
                queue_wait_total_ms = receive.wait_total_ms,
                queue_wait_max_ms = receive.wait_max_ms,
                receive_errors = receive.receive_errors,
                last_receive_errno = ?receive.last_errno,
                batches = batches.batches,
                batch_packets_avg = batches.avg_packets(),
                batch_packets_max = batches.max_packets,
                callback_avg_ms = batches.callback_avg_ms(),
                callback_max_ms = batches.callback_max_ms(),
                "VPN downlink metrics"
            );
        } else {
            info!(
                generation = self.generation,
                final_window,
                elapsed_s = format_args!("{elapsed:.3}"),
                decrypted_packets = packets,
                payload_bytes = bytes,
                payload_Bps = (bytes as f64 / elapsed.max(1e-6)).round(),
                queue_depth = receive.queue.depth,
                queue_peak = receive.queue.peak,
                batch_packets_avg = format_args!("{:.2}", batches.avg_packets()),
                batch_packets_max = batches.max_packets,
                callback_avg_ms = format_args!("{:.3}", batches.callback_avg_ms()),
                callback_max_ms = format_args!("{:.3}", batches.callback_max_ms()),
                "VPN downlink metrics"
            );
        }
    }
}

impl Drop for DownlinkReport {
    fn drop(&mut self) {
        self.report(true);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::sync::Mutex;

    #[test]
    fn queue_window() {
        let (sender, mut receiver) = mpsc::channel(2);
        let metrics = QueueMetrics::new(&sender);
        sender.try_send(vec![1]).unwrap();
        metrics.observe(1);
        sender.try_send(vec![2]).unwrap();
        metrics.observe(2);
        assert!(matches!(
            sender.try_send(vec![3]),
            Err(mpsc::error::TrySendError::Full(_))
        ));
        receiver.try_recv().unwrap();
        let first = metrics.snapshot();
        assert_eq!((first.depth, first.peak, first.capacity), (1, 2, 2));
        receiver.try_recv().unwrap();
        let second = metrics.snapshot();
        assert_eq!((second.depth, second.peak), (0, 1));
        let third = metrics.snapshot();
        assert_eq!((third.depth, third.peak), (0, 0));
    }

    #[test]
    fn channel_lifetime() {
        let (sender, mut receiver) = mpsc::channel(2);
        let metrics = ReceiveMetrics::new(&sender);
        drop(sender);
        assert!(matches!(
            receiver.try_recv(),
            Err(mpsc::error::TryRecvError::Disconnected)
        ));
        assert_eq!(metrics.snapshot().queue.depth, 0);
    }

    #[test]
    fn receive_window() {
        let (sender, _receiver) = mpsc::channel(2);
        let metrics = ReceiveMetrics::new(&sender);
        metrics.record_wait(Duration::from_micros(250));
        metrics.record_wait(Duration::from_micros(750));
        metrics.record_receive_error(&io::Error::from_raw_os_error(42));
        let first = metrics.snapshot();
        assert_eq!(first.waits, 2);
        assert_eq!(first.wait_total_ms, 1.0);
        assert_eq!(first.wait_max_ms, 0.75);
        assert_eq!(first.receive_errors, 1);
        assert_eq!(first.last_errno, Some(42));
        let second = metrics.snapshot();
        assert_eq!(second.waits, 0);
        assert_eq!(second.wait_total_ms, 0.0);
        assert_eq!(second.wait_max_ms, 0.0);
        assert_eq!(second.receive_errors, 0);
        assert_eq!(second.last_errno, None);
        metrics.record_receive_error(&io::Error::other("no raw errno"));
        let third = metrics.snapshot();
        assert_eq!(third.receive_errors, 1);
        assert_eq!(third.last_errno, None);
    }

    #[test]
    fn batch_window() {
        let mut metrics = BatchMetrics::default();
        assert_eq!(metrics.avg_packets(), 0.0);
        assert_eq!(metrics.callback_avg_ms(), 0.0);
        metrics.record(2, Duration::from_micros(500));
        metrics.record(6, Duration::from_micros(1_500));
        let window = std::mem::take(&mut metrics);
        assert_eq!(
            (window.batches, window.packets, window.max_packets),
            (2, 8, 6)
        );
        assert_eq!(window.avg_packets(), 4.0);
        assert_eq!(window.callback_avg_ms(), 1.0);
        assert_eq!(window.callback_max_ms(), 1.5);
        assert_eq!(
            (metrics.batches, metrics.packets, metrics.max_packets),
            (0, 0, 0)
        );
        assert_eq!(metrics.callback_max_ms(), 0.0);
        metrics.record(1, Duration::from_micros(10));
        assert_eq!(metrics.callback_avg_ms(), 0.01);
    }

    #[cfg(unix)]
    #[test]
    fn udp_error_categories() {
        let mut metrics = UdpSendErrors::default();
        for errno in [
            libc::EMSGSIZE,
            libc::ENOBUFS,
            libc::ENETUNREACH,
            libc::EHOSTUNREACH,
            libc::EAGAIN,
            libc::EACCES,
        ] {
            metrics.record(&io::Error::from_raw_os_error(errno));
        }
        for kind in [
            io::ErrorKind::WouldBlock,
            io::ErrorKind::NetworkUnreachable,
            io::ErrorKind::HostUnreachable,
            io::ErrorKind::Other,
        ] {
            metrics.record(&io::Error::from(kind));
        }
        let window = std::mem::take(&mut metrics);
        assert_eq!(window.total, 10);
        assert_eq!(window.message_too_large, 1);
        assert_eq!(window.would_block, 2);
        assert_eq!(window.no_buffer_space, 1);
        assert_eq!(window.unreachable, 4);
        assert_eq!(window.other, 2);
        assert_eq!(window.last_errno, None);
        assert_eq!(metrics.total, 0);
        assert_eq!(metrics.last_errno, None);
        metrics.record(&io::Error::from_raw_os_error(libc::EMSGSIZE));
        assert_eq!(metrics.last_errno, Some(libc::EMSGSIZE));
    }

    #[derive(Clone, Default)]
    struct CapturedLogs(Arc<Mutex<Vec<u8>>>);

    impl Write for CapturedLogs {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(bytes);
            Ok(bytes.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn healthy_windows() {
        let logs = CapturedLogs::default();
        let output = logs.clone();
        let subscriber = tracing_subscriber::fmt()
            .without_time()
            .with_ansi(false)
            .with_writer(move || output.clone())
            .finish();
        tracing::subscriber::with_default(subscriber, || {
            let (sender, _receiver) = mpsc::channel(2);
            let mut uplink = UplinkReport::new(
                Arc::new(UplinkQueueMetrics::new(&sender)),
                "127.0.0.1:1001".parse().unwrap(),
                1,
            );
            let mut downlink = DownlinkReport::new(
                Arc::new(ReceiveMetrics::new(&sender)),
                "127.0.0.1:1001".parse().unwrap(),
                1,
            );
            uplink.sent(128);
            downlink.packet(128);
            downlink.batch(1, Duration::from_millis(2));
            uplink.started = Instant::now() - Duration::from_secs(6);
            downlink.started = uplink.started;
            uplink.report_if_due();
            downlink.report_if_due();
            assert!(logs.0.lock().unwrap().is_empty());

            // Waiting for the longer window must not clear its counters.
            uplink.started = Instant::now() - REPORT_INTERVAL;
            downlink.started = uplink.started;
            uplink.report_if_due();
            downlink.report_if_due();
        });
        let output = String::from_utf8(logs.0.lock().unwrap().clone()).unwrap();
        let lines: Vec<_> = output.lines().collect();
        assert_eq!(lines.len(), 2, "{output}");
        for line in lines {
            assert!(line.contains("INFO"), "{line}");
            assert!(line.contains("payload_bytes=128 "), "{line}");
            assert!(!line.contains("failures="), "{line}");
            assert!(!line.contains("queue_capacity="), "{line}");
        }
        assert!(output.contains("callback_max_ms=2.000"), "{output}");
    }

    #[test]
    fn failure_windows() {
        let logs = CapturedLogs::default();
        let output = logs.clone();
        let subscriber = tracing_subscriber::fmt()
            .with_max_level(tracing::Level::WARN)
            .without_time()
            .with_ansi(false)
            .with_writer(move || output.clone())
            .finish();
        tracing::subscriber::with_default(subscriber, || {
            let (sender, _receiver) = mpsc::channel(2);
            let queue = Arc::new(UplinkQueueMetrics::new(&sender));
            let receive = Arc::new(ReceiveMetrics::new(&sender));
            let mut uplink = UplinkReport::new(queue.clone(), "127.0.0.1:1001".parse().unwrap(), 1);
            let mut downlink =
                DownlinkReport::new(receive.clone(), "127.0.0.1:1001".parse().unwrap(), 1);
            queue.full_drops.store(2, Ordering::Relaxed);
            uplink.send_error(&io::Error::from(io::ErrorKind::WouldBlock));
            receive.record_wait(Duration::from_millis(2));
            receive.record_receive_error(&io::Error::other("receive failed"));
            downlink.decrypt_failure();
            uplink.started = Instant::now() - Duration::from_secs(4);
            downlink.started = uplink.started;
            uplink.report_if_due();
            downlink.report_if_due();
            assert!(logs.0.lock().unwrap().is_empty());
            uplink.started = Instant::now() - ERROR_REPORT_INTERVAL;
            downlink.started = uplink.started;
            uplink.report_if_due();
            downlink.report_if_due();
        });
        let output = String::from_utf8(logs.0.lock().unwrap().clone()).unwrap();
        assert_eq!(output.lines().count(), 2, "{output}");
        for field in [
            "queue_full_drops=2 ",
            "send_would_block=1 ",
            "decrypt_failures=1 ",
            "queue_waits=1 ",
            "receive_errors=1 ",
        ] {
            assert!(output.contains(field), "missing {field}: {output}");
        }
    }

    #[test]
    fn heartbeat_quiet() {
        let logs = CapturedLogs::default();
        let output = logs.clone();
        let subscriber = tracing_subscriber::fmt()
            .without_time()
            .with_ansi(false)
            .with_writer(move || output.clone())
            .finish();
        tracing::subscriber::with_default(subscriber, || {
            let (sender, _receiver) = mpsc::channel(2);
            let receive = Arc::new(ReceiveMetrics::new(&sender));
            let mut report =
                DownlinkReport::new(receive.clone(), "127.0.0.1:1001".parse().unwrap(), 1);
            receive.queue.observe(1);
            report.started = Instant::now() - REPORT_INTERVAL;
            report.report_if_due();
        });
        assert!(logs.0.lock().unwrap().is_empty());
    }

    #[test]
    fn generation_isolation() {
        let logs = CapturedLogs::default();
        let output = logs.clone();
        let subscriber = tracing_subscriber::fmt()
            .with_max_level(tracing::Level::WARN)
            .without_time()
            .with_ansi(false)
            .with_writer(move || output.clone())
            .finish();
        tracing::subscriber::with_default(subscriber, || {
            let (old_sender, _old_receiver) = tokio::sync::mpsc::channel(2);
            let old_queue = Arc::new(UplinkQueueMetrics::new(&old_sender));
            let mut old =
                UplinkReport::new(old_queue.clone(), "127.0.0.1:1001".parse().unwrap(), 41);
            old.sent(11);
            old_queue.full_drops.store(2, Ordering::Relaxed);
            old.send_error(&std::io::Error::from(std::io::ErrorKind::WouldBlock));

            // A replacement can already have sent traffic when cancellation
            // finally drops the previous task and flushes its last window.
            let (new_sender, _new_receiver) = tokio::sync::mpsc::channel(2);
            let new_queue = Arc::new(UplinkQueueMetrics::new(&new_sender));
            let mut new =
                UplinkReport::new(new_queue.clone(), "127.0.0.1:1002".parse().unwrap(), 42);
            new.sent(22);
            new_queue.full_drops.store(3, Ordering::Relaxed);
            drop(old);
            assert_eq!(new_queue.full_drops.load(Ordering::Relaxed), 3);
            drop(new);
        });
        let output = String::from_utf8(logs.0.lock().unwrap().clone()).unwrap();
        let lines: Vec<_> = output.lines().collect();
        assert_eq!(lines.len(), 2, "{output}");
        let old = lines
            .iter()
            .find(|line| line.contains("generation=41 "))
            .unwrap();
        let new = lines
            .iter()
            .find(|line| line.contains("generation=42 "))
            .unwrap();
        for (line, bytes, drops, failures) in [(old, 11, 2, 1), (new, 22, 3, 0)] {
            assert!(line.contains("final_window=true"), "{line}");
            assert!(line.contains(&format!("payload_bytes={bytes} ")), "{line}");
            assert!(
                line.contains(&format!("queue_full_drops={drops} ")),
                "{line}"
            );
            assert!(
                line.contains(&format!("send_failures={failures} ")),
                "{line}"
            );
        }
    }
}
