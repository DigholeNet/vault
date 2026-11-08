// SPDX-License-Identifier: MIT
//! Data-path counters, reporting windows and log output. Callers own I/O and
//! supply events/samples; client transports and server peers have separate lifetimes.

pub mod forwarding;
pub(crate) mod transport;

use std::io;
use std::time::{Duration, Instant};

const REPORT_INTERVAL: Duration = Duration::from_secs(30);
const ERROR_REPORT_INTERVAL: Duration = Duration::from_secs(5);

/// One stage's packet totals. Owners decide what counts as an accepted packet.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
struct PacketCounters {
    packets: u64,
    bytes: u64,
}

impl PacketCounters {
    fn record(&mut self, bytes: usize) {
        self.packets += 1;
        self.bytes += bytes as u64;
    }

    /// Return and reset this window's counts.
    fn take(&mut self) -> Self {
        std::mem::take(self)
    }

    fn bytes_per_second(&self, elapsed_s: f64) -> f64 {
        self.bytes as f64 / elapsed_s.max(1e-6)
    }
}

/// Mutually exclusive write-failure categories, owned by one reporting loop.
#[derive(Debug, Default, Clone, Copy)]
struct IoErrors {
    total: u64,
    short: u64,
    message_too_large: u64,
    would_block: u64,
    no_buffer_space: u64,
    unreachable: u64,
    other: u64,
    last_errno: Option<i32>,
}

impl IoErrors {
    fn record(&mut self, error: &io::Error) {
        self.total += 1;
        self.last_errno = error.raw_os_error();
        match classify_error(error) {
            ErrorClass::MessageTooLarge => self.message_too_large += 1,
            ErrorClass::WouldBlock => self.would_block += 1,
            ErrorClass::NoBufferSpace => self.no_buffer_space += 1,
            ErrorClass::Unreachable => self.unreachable += 1,
            ErrorClass::Other => self.other += 1,
        }
    }

    fn record_short(&mut self) {
        self.total += 1;
        self.short += 1;
        self.last_errno = None;
    }

    /// A failure without an underlying I/O error has no errno to report.
    fn record_other(&mut self) {
        self.total += 1;
        self.other += 1;
        self.last_errno = None;
    }

    fn take(&mut self) -> Self {
        std::mem::take(self)
    }
}

#[derive(Debug)]
struct ReportWindow {
    started: Instant,
}

impl Default for ReportWindow {
    fn default() -> Self {
        Self::new(Instant::now())
    }
}

#[derive(Debug, Clone, Copy)]
struct WindowSnapshot {
    at: Instant,
    elapsed_s: f64,
    final_window: bool,
}

impl ReportWindow {
    fn new(started: Instant) -> Self {
        Self { started }
    }

    fn elapsed(&self, at: Instant) -> Duration {
        at.saturating_duration_since(self.started)
    }

    /// Do not scan anomaly counters before the shortest reporting interval.
    fn is_due(&self, at: Instant, fast: impl FnOnce() -> bool) -> bool {
        let elapsed = self.elapsed(at);
        elapsed >= REPORT_INTERVAL || (elapsed >= ERROR_REPORT_INTERVAL && fast())
    }

    fn take(&mut self, at: Instant, final_window: bool) -> WindowSnapshot {
        let elapsed_s = self.elapsed(at).as_secs_f64();
        self.started = at;
        WindowSnapshot {
            at,
            elapsed_s,
            final_window,
        }
    }
}

/// Common report lifecycle. Implementations drain their own counters in `emit`;
/// samples are supplied lazily by the caller, with no I/O or dynamic dispatch here.
trait Metrics {
    type Sample;

    fn window(&self) -> &ReportWindow;
    fn window_mut(&mut self) -> &mut ReportWindow;
    fn has_anomalies(&self) -> bool;
    fn diagnostic_mode(&self) -> bool {
        false
    }
    fn emit(&mut self, window: WindowSnapshot, sample: Self::Sample);

    fn report_if_due(&mut self, sample: impl FnOnce() -> Self::Sample) {
        let at = Instant::now();
        if self
            .window()
            .is_due(at, || self.diagnostic_mode() || self.has_anomalies())
        {
            self.report_at(at, false, sample());
        }
    }

    fn finish(&mut self, sample: Self::Sample) {
        self.report_at(Instant::now(), true, sample);
    }

    fn report_at(&mut self, at: Instant, final_window: bool, sample: Self::Sample) {
        let window = self.window_mut().take(at, final_window);
        self.emit(window, sample);
    }
}

enum ErrorClass {
    MessageTooLarge,
    WouldBlock,
    NoBufferSpace,
    Unreachable,
    Other,
}

fn classify_error(error: &io::Error) -> ErrorClass {
    // Raw errno values belong to the running OS; ErrorKind also handles
    // synthetic errors and platforms without these Unix constants.
    #[cfg(unix)]
    match error.raw_os_error() {
        Some(libc::EMSGSIZE) => return ErrorClass::MessageTooLarge,
        Some(libc::ENOBUFS) => return ErrorClass::NoBufferSpace,
        Some(libc::ENETUNREACH | libc::EHOSTUNREACH) => return ErrorClass::Unreachable,
        _ => {}
    }
    match error.kind() {
        io::ErrorKind::WouldBlock => ErrorClass::WouldBlock,
        io::ErrorKind::NetworkUnreachable | io::ErrorKind::HostUnreachable => {
            ErrorClass::Unreachable
        }
        _ => ErrorClass::Other,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn counts() {
        let mut counts = PacketCounters::default();
        counts.record(100);
        counts.record(300);
        let snapshot = counts.take();
        assert_eq!(
            snapshot,
            PacketCounters {
                packets: 2,
                bytes: 400
            }
        );
        assert_eq!(snapshot.bytes_per_second(2.0), 200.0);
        assert_eq!(counts, PacketCounters::default());
        assert_eq!(counts.bytes_per_second(0.0), 0.0);
    }

    #[test]
    fn errors() {
        let mut errors = IoErrors::default();
        errors.record(&io::Error::from(io::ErrorKind::WouldBlock));
        errors.record_short();
        errors.record_other();
        let snapshot = errors.take();
        assert_eq!(snapshot.total, 3);
        assert_eq!(
            (snapshot.would_block, snapshot.short, snapshot.other),
            (1, 1, 1)
        );
        assert_eq!(errors.total, 0);
        assert_eq!(errors.last_errno, None);
    }

    #[test]
    fn cadence() {
        let start = Instant::now();
        let mut window = ReportWindow::new(start);
        assert!(!window.is_due(start + Duration::from_secs(4), || panic!("too early")));
        assert!(!window.is_due(start + Duration::from_secs(5), || false));
        assert!(window.is_due(start + Duration::from_secs(5), || true));
        assert!(window.is_due(start + Duration::from_secs(30), || false));
        let snapshot = window.take(start + Duration::from_secs(31), false);
        assert_eq!(snapshot.elapsed_s, 31.0);
        assert!(!window.is_due(start + Duration::from_secs(32), || true));
    }

    #[derive(Default)]
    struct Probe {
        window: ReportWindow,
        packets: PacketCounters,
        reports: Vec<(WindowSnapshot, PacketCounters, u8)>,
    }

    impl Metrics for Probe {
        type Sample = u8;
        fn window(&self) -> &ReportWindow {
            &self.window
        }
        fn window_mut(&mut self) -> &mut ReportWindow {
            &mut self.window
        }
        fn has_anomalies(&self) -> bool {
            false
        }
        fn emit(&mut self, window: WindowSnapshot, sample: u8) {
            self.reports.push((window, self.packets.take(), sample));
        }
    }

    #[test]
    fn lifecycle() {
        let mut metrics = Probe::default();
        metrics.packets.record(100);
        metrics.report_if_due(|| panic!("not due: sample must stay lazy"));
        assert_eq!(metrics.packets.bytes, 100);
        metrics.window = ReportWindow::new(Instant::now() - REPORT_INTERVAL);
        let mut samples = 0;
        metrics.report_if_due(|| {
            samples += 1;
            1
        });
        metrics.packets.record(200);
        metrics.finish(2);
        assert_eq!(samples, 1);
        assert_eq!(metrics.reports.len(), 2);
        assert!(!metrics.reports[0].0.final_window);
        assert!(metrics.reports[1].0.final_window);
        assert_eq!(metrics.reports[0].1.bytes, 100);
        assert_eq!(metrics.reports[1].1.bytes, 200);
        assert_eq!(metrics.reports[1].2, 2);
        assert_eq!(metrics.packets.packets, 0);
    }
}
