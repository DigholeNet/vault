// SPDX-License-Identifier: MIT
//! Server forwarding diagnostics: authenticated peers' UDP↔TUN boundaries,
//! the shared UDP socket, and the single forwarding loop. No client queues or UI stats.
//! Successful writes mean kernel acceptance, not delivery.
use super::{IoErrors, Metrics, PacketCounters, ReportWindow, WindowSnapshot};
use crate::PeerId;
use std::collections::HashMap;
use std::io;
use std::net::SocketAddr;
use std::time::{Duration, Instant};

/// Server I/O observations. Error payloads are borrowed and never retained.
pub enum IoEvent<'a> {
    UdpReceived(usize),
    UdpReceiveError(&'a io::Error),
    TunRead(usize),
    TunReadError(&'a anyhow::Error),
    NetError(&'a anyhow::Error),
    InvalidNetPacket,
    InvalidTunPacket,
    AuthenticationFailure,
    UnknownPeer,
    UnknownDestination,
    PollError,
}

/// Rejected data attributable to one authenticated peer.
pub enum PeerEvent {
    InvalidPacket,
    SpoofedSource,
    BuildFailure,
}

#[derive(Default)]
struct PeerWindow {
    up: PacketCounters,
    tun: PacketCounters,
    down: PacketCounters,
    sent: PacketCounters,
    sent_wire_bytes: u64,
    heartbeats: u64,
    invalid_packets: u64,
    spoofed_source: u64,
    build_failures: u64,
    tun_errors: IoErrors,
    send_errors: IoErrors,
}

pub struct PeerMetrics {
    address: SocketAddr,
    report_window: ReportWindow,
    last_up: Option<Instant>,
    last_down: Option<Instant>,
    last_heartbeat: Option<Instant>,
    window: PeerWindow,
}

impl PeerMetrics {
    fn new(address: SocketAddr, now: Instant) -> Self {
        Self {
            address,
            report_window: ReportWindow::new(now),
            last_up: None,
            last_down: None,
            last_heartbeat: None,
            window: PeerWindow::default(),
        }
    }

    pub fn observe(&mut self, event: PeerEvent) {
        match event {
            PeerEvent::InvalidPacket => self.window.invalid_packets += 1,
            PeerEvent::SpoofedSource => self.window.spoofed_source += 1,
            PeerEvent::BuildFailure => self.window.build_failures += 1,
        }
    }

    pub fn decrypted(&mut self, bytes: usize) {
        self.window.up.record(bytes);
        self.last_up = Some(Instant::now());
    }

    pub fn tun_read(&mut self, bytes: usize) {
        self.window.down.record(bytes);
    }

    pub fn heartbeat(&mut self) {
        self.window.heartbeats += 1;
        self.last_heartbeat = Some(Instant::now());
    }

    pub fn tun_write(&mut self, expected: usize, result: &anyhow::Result<usize>) {
        match result {
            Ok(written) if *written == expected => {
                self.window.tun.record(expected);
            }
            Ok(_) => self.window.tun_errors.record_short(),
            Err(error) => {
                if let Some(error) = error.downcast_ref::<io::Error>() {
                    self.window.tun_errors.record(error);
                } else {
                    self.window.tun_errors.record_other();
                }
            }
        }
    }

    pub fn udp_send(&mut self, payload_len: usize, wire_len: usize, result: &io::Result<usize>) {
        match result {
            Ok(written) if *written == wire_len => {
                self.window.sent.record(payload_len);
                self.window.sent_wire_bytes += wire_len as u64;
                self.last_down = Some(Instant::now());
            }
            Ok(_) => self.window.send_errors.record_short(),
            Err(error) => self.window.send_errors.record(error),
        }
    }

    fn has_errors(&self) -> bool {
        self.window.invalid_packets > 0
            || self.window.spoofed_source > 0
            || self.window.build_failures > 0
            || self.window.tun_errors.total > 0
            || self.window.send_errors.total > 0
    }

    fn report(&mut self, id: &PeerId, now: Instant, final_window: bool) {
        let snapshot = self.report_window.take(now, final_window);
        let elapsed = snapshot.elapsed_s;
        let window = &self.window;
        macro_rules! emit {
            ($level:ident $(, $($extra:tt)*)?) => {
                tracing::$level!(target: "metrics",
                    peer = %hex::encode(id.0), address = %self.address, final_window,
                    elapsed_s = elapsed,
                    up_packets = window.up.packets, up_bytes = window.up.bytes,
                    up_Bps = window.up.bytes_per_second(elapsed),
                    tun_written_packets = window.tun.packets, tun_written_bytes = window.tun.bytes,
                    down_packets = window.down.packets, down_bytes = window.down.bytes,
                    down_Bps = window.down.bytes_per_second(elapsed),
                    udp_sent_packets = window.sent.packets,
                    udp_sent_payload_bytes = window.sent.bytes,
                    udp_sent_wire_bytes = window.sent_wire_bytes,
                    heartbeats = window.heartbeats,
                    last_up_s = ?age(now, self.last_up), last_down_s = ?age(now, self.last_down),
                    last_heartbeat_s = ?age(now, self.last_heartbeat),
                    $($($extra)*)?
                    "Supernode peer metrics"
                );
            };
        }
        if self.has_errors() {
            let tun = &window.tun_errors;
            let send = &window.send_errors;
            emit!(warn,
                invalid_packets = window.invalid_packets, spoofed_source = window.spoofed_source,
                build_failures = window.build_failures,
                tun_failures = tun.total, tun_short = tun.short,
                tun_would_block = tun.would_block, tun_emsgsize = tun.message_too_large,
                tun_enobufs = tun.no_buffer_space, tun_unreachable = tun.unreachable,
                tun_other = tun.other, tun_last_errno = ?tun.last_errno,
                send_failures = send.total, send_short = send.short,
                send_would_block = send.would_block, send_emsgsize = send.message_too_large,
                send_enobufs = send.no_buffer_space, send_unreachable = send.unreachable,
                send_other = send.other, send_last_errno = ?send.last_errno,
            );
        } else {
            emit!(info);
        }
        self.window = PeerWindow::default();
    }
}

fn age(now: Instant, previous: Option<Instant>) -> Option<f64> {
    previous.map(|previous| now.saturating_duration_since(previous).as_secs_f64())
}

#[derive(Default)]
struct IoMetrics {
    udp_received: PacketCounters,
    udp_receive_errors: u64,
    last_udp_receive_errno: Option<i32>,
    tun_read: PacketCounters,
    tun_read_errors: u64,
    last_tun_read_errno: Option<i32>,
    net_processing_errors: u64,
    first_net_error: Option<String>,
    invalid_tun_packets: u64,
    auth_failures: u64,
    unknown_peer: u64,
    unknown_destination: u64,
    poll_errors: u64,
    handlers: Timing,
    maintenance: Timing,
}

impl IoMetrics {
    fn has_errors(&self) -> bool {
        self.udp_receive_errors > 0
            || self.tun_read_errors > 0
            || self.net_processing_errors > 0
            || self.invalid_tun_packets > 0
            || self.auth_failures > 0
            || self.unknown_peer > 0
            || self.unknown_destination > 0
            || self.poll_errors > 0
    }
}

#[derive(Default)]
struct Timing {
    count: u64,
    total: Duration,
    max: Duration,
}

impl Timing {
    fn record(&mut self, elapsed: Duration) {
        self.count += 1;
        self.total = self.total.saturating_add(elapsed);
        self.max = self.max.max(elapsed);
    }
}

pub struct ForwardingMetrics {
    io: IoMetrics,
    peers: HashMap<PeerId, PeerMetrics>,
    report_window: ReportWindow,
    socket_drops: Option<u64>,
}

impl Default for ForwardingMetrics {
    fn default() -> Self {
        Self::new(None)
    }
}

impl ForwardingMetrics {
    /// Supply a baseline once the listening socket exists. The caller owns sampling.
    pub fn new(initial_socket: Option<SocketSample>) -> Self {
        Self {
            io: IoMetrics::default(),
            peers: HashMap::new(),
            report_window: ReportWindow::default(),
            socket_drops: initial_socket.map(|sample| sample.drops),
        }
    }

    pub fn observe(&mut self, event: IoEvent<'_>) {
        match event {
            IoEvent::UdpReceived(bytes) => self.io.udp_received.record(bytes),
            IoEvent::UdpReceiveError(error) => {
                self.io.udp_receive_errors += 1;
                self.io.last_udp_receive_errno = error.raw_os_error();
            }
            IoEvent::TunRead(bytes) => self.io.tun_read.record(bytes),
            IoEvent::TunReadError(error) => {
                self.io.tun_read_errors += 1;
                self.io.last_tun_read_errno = error
                    .downcast_ref::<io::Error>()
                    .and_then(io::Error::raw_os_error);
            }
            IoEvent::NetError(error) => {
                self.io.net_processing_errors += 1;
                if self.io.first_net_error.is_none() {
                    self.io.first_net_error = Some(error.to_string().chars().take(256).collect());
                }
            }
            IoEvent::InvalidNetPacket => self.io.net_processing_errors += 1,
            IoEvent::InvalidTunPacket => self.io.invalid_tun_packets += 1,
            IoEvent::AuthenticationFailure => self.io.auth_failures += 1,
            IoEvent::UnknownPeer => self.io.unknown_peer += 1,
            IoEvent::UnknownDestination => self.io.unknown_destination += 1,
            IoEvent::PollError => self.io.poll_errors += 1,
        }
    }

    pub fn register(&mut self, id: PeerId, address: SocketAddr) {
        self.remove(&id);
        self.peers
            .insert(id, PeerMetrics::new(address, Instant::now()));
    }

    pub fn remove(&mut self, id: &PeerId) {
        if let Some(mut peer) = self.peers.remove(id) {
            peer.report(id, Instant::now(), true);
        }
    }

    pub fn peer(&mut self, id: &PeerId) -> Option<&mut PeerMetrics> {
        self.peers.get_mut(id)
    }

    pub fn handled(&mut self, elapsed: Duration) {
        self.io.handlers.record(elapsed);
    }

    pub fn maintained(&mut self, elapsed: Duration) {
        self.io.maintenance.record(elapsed);
    }

    /// Invoke the caller's sampler only when a reporting window is due.
    pub fn report_if_due(&mut self, sample_socket: impl FnOnce() -> Option<SocketSample>) {
        Metrics::report_if_due(self, sample_socket);
    }

    pub fn finish(&mut self, sample: Option<SocketSample>) {
        Metrics::finish(self, sample);
    }
}

impl Metrics for ForwardingMetrics {
    type Sample = Option<SocketSample>;

    fn window(&self) -> &ReportWindow {
        &self.report_window
    }

    fn window_mut(&mut self) -> &mut ReportWindow {
        &mut self.report_window
    }

    fn has_anomalies(&self) -> bool {
        self.io.has_errors() || self.peers.values().any(PeerMetrics::has_errors)
    }

    fn diagnostic_mode(&self) -> bool {
        tracing::enabled!(target: "metrics", tracing::Level::DEBUG)
    }

    fn emit(&mut self, snapshot: WindowSnapshot, sample: Self::Sample) {
        let WindowSnapshot {
            at: now,
            elapsed_s: elapsed,
            final_window,
        } = snapshot;
        let drops = socket_drop_delta(&mut self.socket_drops, sample);
        let io = &self.io;
        macro_rules! emit {
            ($level:ident $(, $($extra:tt)*)?) => {
                tracing::$level!(target: "metrics",
                    final_window, elapsed_s = elapsed, peers = self.peers.len(),
                    udp_received_packets = io.udp_received.packets,
                    udp_received_bytes = io.udp_received.bytes,
                    tun_read_packets = io.tun_read.packets, tun_read_bytes = io.tun_read.bytes,
                    handler_count = io.handlers.count,
                    handler_total_ms = io.handlers.total.as_secs_f64() * 1000.0,
                    handler_max_ms = io.handlers.max.as_secs_f64() * 1000.0,
                    maintenance_count = io.maintenance.count,
                    maintenance_total_ms = io.maintenance.total.as_secs_f64() * 1000.0,
                    maintenance_max_ms = io.maintenance.max.as_secs_f64() * 1000.0,
                    socket_rx_drops_delta = ?drops,
                    socket_rx_queue_bytes = ?sample.map(|sample| sample.rx_queue),
                    socket_tx_queue_bytes = ?sample.map(|sample| sample.tx_queue),
                    $($($extra)*)?
                    "Supernode I/O metrics"
                );
            };
        }
        if io.has_errors() || drops.is_some_and(|drops| drops > 0) {
            emit!(
                warn,
                udp_receive_errors = io.udp_receive_errors,
                last_udp_receive_errno = ?io.last_udp_receive_errno,
                tun_read_errors = io.tun_read_errors,
                last_tun_read_errno = ?io.last_tun_read_errno,
                net_processing_errors = io.net_processing_errors,
                first_net_error = ?io.first_net_error,
                invalid_tun_packets = io.invalid_tun_packets,
                auth_failures = io.auth_failures,
                unknown_peer = io.unknown_peer,
                unknown_destination = io.unknown_destination,
                poll_errors = io.poll_errors,
            );
        } else if !self.peers.is_empty() || io.udp_received.packets > 0 || io.tun_read.packets > 0 {
            emit!(info);
        }
        for (id, peer) in &mut self.peers {
            peer.report(id, now, final_window);
        }
        if final_window {
            self.peers.clear();
        }
        self.io = IoMetrics::default();
    }
}

#[derive(Clone, Copy, Debug, PartialEq)]
/// Cumulative socket drops and sampled memory accounting, supplied by the server.
pub struct SocketSample {
    pub drops: u64,
    pub rx_queue: u64,
    pub tx_queue: u64,
}

fn socket_drop_delta(previous: &mut Option<u64>, sample: Option<SocketSample>) -> Option<u64> {
    let current = sample.map(|sample| sample.drops);
    let delta = current
        .zip(*previous)
        .and_then(|(current, previous)| current.checked_sub(previous));
    *previous = current;
    delta
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::metrics::REPORT_INTERVAL;

    #[test]
    fn target_filter() {
        use std::sync::{Arc, Mutex};
        use tracing::{Event, Level, Subscriber};
        use tracing_subscriber::{EnvFilter, Layer, layer::Context, prelude::*};

        struct Targets(Arc<Mutex<Vec<(String, Level)>>>);
        impl<S: Subscriber> Layer<S> for Targets {
            fn on_event(&self, event: &Event<'_>, _: Context<'_, S>) {
                let metadata = event.metadata();
                self.0
                    .lock()
                    .unwrap()
                    .push((metadata.target().into(), *metadata.level()));
            }
        }

        // Parse the same directives as RUST_LOG without changing process-wide env.
        for (directive, diagnostic) in [("off,metrics=info", false), ("off,metrics=debug", true)] {
            let targets = Arc::new(Mutex::new(Vec::new()));
            let subscriber = tracing_subscriber::registry()
                .with(EnvFilter::new(directive))
                .with(Targets(targets.clone()));
            tracing::subscriber::with_default(subscriber, || {
                let mut metrics = ForwardingMetrics::default();
                let id = PeerId([1; 16]);
                metrics.register(id, "127.0.0.1:1234".parse().unwrap());
                assert_eq!(metrics.diagnostic_mode(), diagnostic);
                metrics.report_window = ReportWindow::new(Instant::now() - Duration::from_secs(6));
                let mut samples = 0;
                metrics.report_if_due(|| {
                    samples += 1;
                    None
                });
                assert_eq!(samples, usize::from(diagnostic));
                if !diagnostic {
                    Metrics::report_at(&mut metrics, Instant::now(), false, None);
                }
                metrics.observe(IoEvent::AuthenticationFailure);
                metrics.peer(&id).unwrap().observe(PeerEvent::BuildFailure);
                Metrics::report_at(&mut metrics, Instant::now(), false, None);
            });
            let targets = targets.lock().unwrap();
            assert_eq!(targets.len(), 4, "{targets:?}");
            assert!(targets.iter().all(|(target, _)| target == "metrics"));
            assert_eq!(
                targets.iter().map(|(_, level)| *level).collect::<Vec<_>>(),
                [Level::INFO, Level::INFO, Level::WARN, Level::WARN]
            );
        }
    }

    fn peer() -> PeerMetrics {
        PeerMetrics::new("127.0.0.1:1234".parse().unwrap(), Instant::now())
    }

    #[test]
    fn stages() {
        let mut peer = peer();
        peer.decrypted(100);
        peer.tun_write(100, &Ok(100));
        peer.tun_read(200);
        peer.udp_send(200, 225, &Ok(225));
        peer.tun_write(100, &Ok(99));
        peer.udp_send(200, 225, &Ok(224));
        assert_eq!((peer.window.up.packets, peer.window.up.bytes), (1, 100));
        assert_eq!((peer.window.tun.packets, peer.window.tun.bytes), (1, 100));
        assert_eq!((peer.window.down.packets, peer.window.down.bytes), (1, 200));
        assert_eq!(
            (
                peer.window.sent.packets,
                peer.window.sent.bytes,
                peer.window.sent_wire_bytes
            ),
            (1, 200, 225)
        );
        assert_eq!(peer.window.tun_errors.short, 1);
        assert_eq!(peer.window.send_errors.short, 1);
    }

    #[test]
    fn errors() {
        let mut peer = peer();
        for errno in [
            libc::EMSGSIZE,
            libc::ENOBUFS,
            libc::EHOSTUNREACH,
            libc::EAGAIN,
            libc::EIO,
        ] {
            peer.udp_send(100, 125, &Err(io::Error::from_raw_os_error(errno)));
        }
        peer.tun_write(100, &Err(io::Error::from_raw_os_error(libc::EAGAIN).into()));
        peer.tun_write(100, &Err(anyhow::anyhow!("other")));
        let errors = &peer.window.send_errors;
        assert_eq!(
            (
                errors.total,
                errors.message_too_large,
                errors.no_buffer_space,
                errors.unreachable,
                errors.would_block,
                errors.other
            ),
            (5, 1, 1, 1, 1, 1)
        );
        assert_eq!(errors.last_errno, Some(libc::EIO));
        assert_eq!(
            (
                peer.window.tun_errors.total,
                peer.window.tun_errors.would_block,
                peer.window.tun_errors.other
            ),
            (2, 1, 1)
        );
        assert_eq!(peer.window.sent.packets, 0);
        peer.udp_send(100, 125, &Ok(124));
        assert_eq!(peer.window.send_errors.last_errno, None);
        assert_eq!(peer.window.send_errors.short, 1);
    }

    #[test]
    fn windows() {
        let mut peer = peer();
        peer.decrypted(100);
        peer.heartbeat();
        peer.udp_send(100, 125, &Ok(125));
        peer.udp_send(100, 125, &Err(io::Error::from_raw_os_error(libc::EMSGSIZE)));
        peer.tun_write(100, &Err(io::Error::from_raw_os_error(libc::EAGAIN).into()));
        let up = peer.last_up;
        let down = peer.last_down;
        let heartbeat = peer.last_heartbeat;
        peer.observe(PeerEvent::InvalidPacket);
        peer.observe(PeerEvent::SpoofedSource);
        peer.observe(PeerEvent::BuildFailure);
        assert_eq!(peer.window.invalid_packets, 1);
        assert_eq!(peer.window.spoofed_source, 1);
        assert_eq!(peer.window.build_failures, 1);
        assert_eq!(peer.window.send_errors.last_errno, Some(libc::EMSGSIZE));
        assert_eq!(peer.window.tun_errors.last_errno, Some(libc::EAGAIN));
        peer.report(&PeerId([0; 16]), Instant::now(), false);
        assert_eq!(peer.window.up.packets, 0);
        assert_eq!(peer.window.sent.packets, 0);
        assert_eq!(peer.window.send_errors.last_errno, None);
        assert_eq!(peer.window.tun_errors.last_errno, None);
        assert!(!peer.has_errors());
        assert_eq!(peer.last_up, up);
        assert_eq!(peer.last_down, down);
        assert_eq!(peer.last_heartbeat, heartbeat);
    }

    #[test]
    fn lifecycle() {
        let mut metrics = ForwardingMetrics::new(None);
        let id = PeerId([1; 16]);
        let address = "127.0.0.1:1234".parse().unwrap();
        let moved = "127.0.0.1:5678".parse().unwrap();
        metrics.register(id, address);
        metrics.peer(&id).unwrap().decrypted(100);
        metrics.peer(&id).unwrap().observe(PeerEvent::BuildFailure);
        metrics.register(id, moved);
        assert_eq!(metrics.peers.len(), 1);
        let peer = metrics.peer(&id).unwrap();
        assert_eq!(peer.address, moved);
        assert_eq!(peer.window.up.packets, 0);
        assert_eq!(peer.last_up, None);
        assert!(!peer.has_errors());

        metrics.peer(&id).unwrap().decrypted(200);
        metrics.handled(Duration::from_millis(3));
        metrics.maintained(Duration::from_millis(2));
        assert_eq!(metrics.io.handlers.count, 1);
        assert_eq!(metrics.io.handlers.total, Duration::from_millis(3));
        assert_eq!(metrics.io.maintenance.max, Duration::from_millis(2));
        metrics.report_window = ReportWindow::new(Instant::now() - REPORT_INTERVAL);
        metrics.report_if_due(|| None);
        assert_eq!(metrics.io.handlers.count, 0);
        assert_eq!(metrics.io.maintenance.count, 0);
        assert_eq!(metrics.peer(&id).unwrap().window.up.packets, 0);
        assert!(metrics.peer(&id).unwrap().last_up.is_some());

        metrics.remove(&id);
        assert!(metrics.peer(&id).is_none());
        metrics.register(id, address);
        metrics.peer(&id).unwrap().tun_read(100);
        metrics.io.unknown_destination = 1;
        metrics.finish(None);
        assert!(metrics.peers.is_empty());
        assert!(!metrics.io.has_errors());

        metrics.register(id, address);
        metrics.peer(&id).unwrap().tun_read(100);
        Metrics::finish(&mut metrics, None);
        assert!(metrics.peers.is_empty());
        assert!(!metrics.io.has_errors());
    }

    #[test]
    fn anomalies() {
        let mut metrics = ForwardingMetrics::default();
        assert!(!metrics.has_anomalies());
        metrics.observe(IoEvent::AuthenticationFailure);
        assert!(metrics.has_anomalies());
        metrics.finish(None);
        assert!(!metrics.has_anomalies());
        let id = PeerId([1; 16]);
        metrics.register(id, "127.0.0.1:1234".parse().unwrap());
        metrics.peer(&id).unwrap().observe(PeerEvent::BuildFailure);
        assert!(metrics.has_anomalies());
    }

    #[test]
    fn socket_deltas() {
        let sample = |drops| {
            Some(SocketSample {
                drops,
                rx_queue: 0,
                tx_queue: 0,
            })
        };
        let mut previous = None;
        assert_eq!(socket_drop_delta(&mut previous, sample(50)), None);
        assert_eq!(socket_drop_delta(&mut previous, sample(53)), Some(3));
        assert_eq!(socket_drop_delta(&mut previous, sample(2)), None);
        assert_eq!(socket_drop_delta(&mut previous, None), None);
        assert_eq!(socket_drop_delta(&mut previous, sample(5)), None);
        assert_eq!(socket_drop_delta(&mut previous, sample(5)), Some(0));
    }

    #[test]
    fn sampling() {
        let mut metrics = ForwardingMetrics::default();
        metrics.report_if_due(|| panic!("not due: no I/O"));
        let mut calls = 0;
        metrics.report_window = ReportWindow::new(Instant::now() - REPORT_INTERVAL);
        let sample_delay = Duration::from_millis(2);
        let started = Instant::now();
        metrics.report_if_due(|| {
            calls += 1;
            std::thread::sleep(sample_delay);
            Some(SocketSample {
                drops: 7,
                rx_queue: 0,
                tx_queue: 0,
            })
        });
        // The loop records the completed cycle after reporting resets the window.
        metrics.maintained(started.elapsed());
        assert_eq!(calls, 1);
        assert_eq!(metrics.socket_drops, Some(7));
        assert_eq!(metrics.io.maintenance.count, 1);
        assert!(metrics.io.maintenance.total >= sample_delay);
        assert_eq!(metrics.io.maintenance.max, metrics.io.maintenance.total);
        metrics.finish(None);
        assert_eq!(metrics.io.maintenance.count, 0);
    }

    #[test]
    fn events() {
        let mut metrics = ForwardingMetrics::default();
        metrics.observe(IoEvent::UdpReceived(200));
        metrics.observe(IoEvent::TunRead(100));
        let first = anyhow::anyhow!("a".repeat(300));
        metrics.observe(IoEvent::NetError(&first));
        metrics.observe(IoEvent::NetError(&anyhow::anyhow!("second")));
        assert_eq!(metrics.io.udp_received.bytes, 200);
        assert_eq!(metrics.io.tun_read.bytes, 100);
        assert_eq!(metrics.io.net_processing_errors, 2);
        assert_eq!(
            metrics.io.first_net_error.as_deref(),
            Some("a".repeat(256).as_str())
        );
        metrics.finish(None);
        assert!(metrics.io.first_net_error.is_none());
        assert!(!metrics.io.has_errors());
    }
}
