// SPDX-License-Identifier: MIT
use std::{
    net::{IpAddr, SocketAddr},
    time::{Duration, Instant},
};

use ring::rand::{SecureRandom, SystemRandom};

use crate::{
    CryptoCore,
    protocol::{self, PeerRegisterRequest, peer_register_message::Data},
};

const PROBE_PERIOD: Duration = Duration::from_secs(2);
const VALIDATION_RETRY: Duration = Duration::from_millis(400);
const VALIDATION_ROUND: Duration = Duration::from_secs(5);
const PATH_IDLE: Duration = Duration::from_secs(30);
pub(crate) const UPLINK_ACTIVE: Duration = Duration::from_secs(5);

pub(crate) struct Probe {
    pub cookie: u32,
    pub size: usize,
    pub deadline: Instant,
}

pub(crate) struct Candidate {
    pub endpoint: SocketAddr,
    pub registered: bool,
    pub waiting: Option<Probe>,
    pub validated_size: usize,
    pub mtu_failure: Option<usize>,
    // Out-of-order authenticated packets cannot move a candidate backwards.
    pub latest_registration: Option<u64>,
    small_probe_confirmed: bool,
}

impl Candidate {
    pub fn new(endpoint: SocketAddr) -> Self {
        Self {
            endpoint,
            registered: false,
            waiting: None,
            validated_size: 0,
            mtu_failure: None,
            latest_registration: None,
            small_probe_confirmed: false,
        }
    }

    fn probe_due(&self, now: Instant) -> bool {
        self.waiting
            .as_ref()
            .is_none_or(|probe| now >= probe.deadline)
    }

    pub fn awaiting_ack(&self, cookie: u32, now: Instant) -> bool {
        self.waiting
            .as_ref()
            .is_some_and(|probe| probe.cookie == cookie && now < probe.deadline)
    }
}

pub(crate) struct PeerPath {
    pub crypto: CryptoCore,
    pub candidates: Vec<Candidate>,
    pub selected: Option<usize>,
    pub last_uplink: Option<Instant>,
    mapped: Option<MappedCandidate>,
    withdrawn_mapping: Option<(SocketAddr, SocketAddr)>,
    last_direct: Instant,
    due: Instant,
    validation: Validation,
    retries: usize,
    misses: u8,
    need_full: bool,
    repeat_small_probe: bool,
}

struct MappedCandidate {
    index: usize,
    advertised: SocketAddr,
    expires: u64,
}

enum Validation {
    Ready,
    Running(Instant),
    Waiting,
}

impl PeerPath {
    pub fn new(
        crypto: CryptoCore,
        endpoint: SocketAddr,
        lan: Option<SocketAddr>,
        now: Instant,
    ) -> Self {
        let mut candidates = vec![Candidate::new(endpoint)];
        if let Some(lan) = lan.filter(|lan| *lan != endpoint) {
            candidates.push(Candidate::new(lan));
        }
        Self {
            crypto,
            candidates,
            selected: None,
            last_uplink: None,
            mapped: None,
            withdrawn_mapping: None,
            last_direct: now,
            due: now,
            validation: Validation::Ready,
            retries: 0,
            misses: 0,
            need_full: false,
            repeat_small_probe: false,
        }
    }

    pub fn update_mtu(&mut self, size: usize, increased: bool, now: Instant) {
        for candidate in &mut self.candidates {
            if let Some(failed_size) = candidate.mtu_failure
                && failed_size != size
            {
                candidate.mtu_failure = None;
            }
            candidate.waiting = None;
            if increased {
                candidate.validated_size = 0;
            }
        }
        if increased && self.selected.take().is_some() {
            self.misses = 0;
            self.due = now;
            self.validation = Validation::Ready;
        }
    }

    pub fn on_direct_traffic(&mut self, now: Instant, outgoing_wire_size: usize) {
        self.last_direct = now;
        self.need_full |= outgoing_wire_size > protocol::REGISTER_MIN;
    }

    pub fn uplink_active(&self, now: Instant) -> bool {
        self.last_uplink
            .is_some_and(|last| now - last < UPLINK_ACTIVE)
    }

    pub fn observe(&mut self, now: Instant) {
        self.last_uplink = Some(now);
    }

    pub fn on_punch_notice(&mut self, now: Instant) {
        if self.selected.is_none()
            && !self.candidates[0]
                .waiting
                .as_ref()
                .is_some_and(|probe| probe.size > protocol::REGISTER_MIN && now < probe.deadline)
        {
            self.observe(now);
            self.due = now;
            self.repeat_small_probe = true;
        }
    }

    pub fn registration_candidate(&self, from: SocketAddr) -> Option<usize> {
        self.candidates
            .iter()
            .position(|candidate| candidate.endpoint == from)
            .or_else(|| {
                if self.mapping_only(from) {
                    return None;
                }
                self.candidates
                    .iter()
                    .position(|candidate| candidate.endpoint.ip() == from.ip())
            })
    }

    pub fn ack_candidate(&self, from: SocketAddr, cookie: u32, now: Instant) -> Option<usize> {
        if let Some(index) = self
            .candidates
            .iter()
            .position(|candidate| candidate.endpoint == from)
        {
            return self.candidates[index]
                .awaiting_ack(cookie, now)
                .then_some(index);
        }
        self.candidates
            .iter()
            .enumerate()
            .find_map(|(index, candidate)| {
                (candidate.endpoint.ip() == from.ip()
                    && candidate.awaiting_ack(cookie, now)
                    && (!self.mapping_only(from)
                        || self
                            .mapped
                            .as_ref()
                            .is_some_and(|mapping| mapping.index == index)))
                .then_some(index)
            })
    }

    fn mapping_only(&self, endpoint: SocketAddr) -> bool {
        self.mapped
            .as_ref()
            .is_some_and(|mapping| mapping.advertised == endpoint)
            || self
                .withdrawn_mapping
                .is_some_and(|(advertised, learned)| endpoint == advertised || endpoint == learned)
    }

    pub fn rebind(&mut self, index: usize, endpoint: SocketAddr, now: Instant) {
        self.candidates[index] = Candidate::new(endpoint);
        if self.selected == Some(index) {
            self.selected = None;
            self.misses = 0;
            self.need_full = false;
        }
        if self.selected.is_none() {
            self.due = now;
        }
        if !matches!(self.validation, Validation::Running(deadline) if now < deadline) {
            self.validation = Validation::Ready;
        }
        self.last_direct = now;
    }

    pub fn fallback(&mut self, now: Instant, mtu_failure: Option<usize>) {
        if let Some(index) = self.selected.take() {
            self.candidates[index].mtu_failure = mtu_failure;
            self.candidates[index].validated_size = 0;
        }
        for candidate in &mut self.candidates {
            candidate.waiting = None;
            candidate.small_probe_confirmed = false;
        }
        self.due = now + VALIDATION_ROUND;
        self.validation = Validation::Waiting;
        self.misses = 0;
        self.need_full = false;
    }

    pub fn lan_check_due(&self, now: Instant) -> bool {
        self.has_lan()
            && (self.lan_validation_due(now)
                || (now >= self.due && (self.selected.is_some() || self.validation_due(now))))
    }

    pub fn validating(&self, now: Instant) -> bool {
        matches!(self.validation, Validation::Running(deadline) if now < deadline)
            && (self.selected.is_none() || (self.has_lan() && self.selected != Some(1)))
    }

    fn validation_due(&self, now: Instant) -> bool {
        match self.validation {
            Validation::Ready => true,
            Validation::Running(deadline) => now < deadline,
            Validation::Waiting => self.retries < 2 && self.uplink_active(now),
        }
    }

    pub fn is_lan(&self, index: usize) -> bool {
        index == 1 && self.has_lan()
    }

    fn has_lan(&self) -> bool {
        self.candidates.len() > 1
            && self
                .mapped
                .as_ref()
                .is_none_or(|mapping| mapping.index != 1)
    }

    pub fn set_mapping(
        &mut self,
        mapping: Option<(SocketAddr, u64)>,
        now: Instant,
        lease_now: u64,
    ) -> Option<SocketAddr> {
        if let Some(current) = self.mapped.as_mut()
            && let Some((endpoint, deadline)) = mapping
            && current.advertised == endpoint
            && lease_now < current.expires
        {
            current.expires = deadline;
            return None;
        }
        let removed = self.remove_mapping(now);
        if let Some((endpoint, expires)) = mapping
            && !self
                .candidates
                .iter()
                .any(|candidate| candidate.endpoint == endpoint)
        {
            self.mapped = Some(MappedCandidate {
                index: self.candidates.len(),
                advertised: endpoint,
                expires,
            });
            self.candidates.push(Candidate::new(endpoint));
            if self.selected.is_none() {
                self.retries = 0;
                self.due = now;
                self.validation = Validation::Ready;
            }
        }
        removed
    }

    pub fn mapping_expired(&self, endpoint: SocketAddr, lease_now: u64) -> bool {
        self.mapped.as_ref().is_some_and(|mapping| {
            lease_now >= mapping.expires && self.candidates[mapping.index].endpoint == endpoint
        })
    }

    pub fn expire_mapping(&mut self, now: Instant, lease_now: u64) -> Option<SocketAddr> {
        if self
            .mapped
            .as_ref()
            .is_some_and(|mapping| lease_now >= mapping.expires)
        {
            self.remove_mapping(now)
        } else {
            None
        }
    }

    fn remove_mapping(&mut self, now: Instant) -> Option<SocketAddr> {
        let mapping = self.mapped.take()?;
        let index = mapping.index;
        if self.selected == Some(index) {
            self.fallback(now, None);
            self.due = now;
        }
        let learned = self.candidates.remove(index).endpoint;
        // A late register must not turn the withdrawn mapping into a
        // rebinding of the ordinary observed endpoint.
        self.withdrawn_mapping = Some((mapping.advertised, learned));
        Some(learned)
    }

    fn lan_validation_due(&self, now: Instant) -> bool {
        self.selected.is_some_and(|index| !self.is_lan(index))
            && self.has_lan()
            && match self.validation {
                Validation::Ready => true,
                Validation::Running(deadline) => now < deadline,
                Validation::Waiting => false,
            }
            && self.uplink_active(now)
            && self.candidates[1].probe_due(now)
    }

    pub fn remove_lan(&mut self, now: Instant, size: usize) {
        if self.selected == Some(1) {
            self.fallback(now, None);
            if self.candidates[0].validated_size >= size {
                self.selected = Some(0);
                self.due = now;
            }
        }
        self.candidates.remove(1);
        if let Some(mapping) = self.mapped.as_mut() {
            mapping.index -= 1;
        }
        if let Some(index) = self.selected.as_mut()
            && *index > 1
        {
            *index -= 1;
        }
    }

    /// Returns false when the current pair has used all validation rounds.
    pub fn poll(
        &mut self,
        now: Instant,
        size: usize,
        can_validate: bool,
        mut send: impl FnMut(&CryptoCore, SocketAddr, Data, usize),
    ) -> bool {
        if now - self.last_direct >= PATH_IDLE && !self.uplink_active(now) {
            for candidate in &mut self.candidates {
                candidate.registered = false;
                candidate.validated_size = 0;
                candidate.waiting = None;
                candidate.small_probe_confirmed = false;
            }
            self.selected = None;
            self.validation = Validation::Waiting;
            self.last_direct = now;
            return true;
        }
        if !(protocol::REGISTER_MIN..=protocol::REGISTER_MAX).contains(&size) {
            return true;
        }
        // Keep validating the preferred LAN candidate while the observed
        // address is active, independently of its keepalive.
        if can_validate && self.lan_validation_due(now) {
            if matches!(self.validation, Validation::Ready) {
                self.validation = Validation::Running(now + VALIDATION_ROUND);
            }
            self.validate_candidate(1, now, size, false, &mut send);
        }
        if now < self.due {
            return true;
        }
        if let Some(active) = self.selected {
            let candidate = &mut self.candidates[active];
            if let Some(previous) = candidate.waiting.take() {
                self.need_full |= previous.size == size;
                self.misses += 1;
                if self.misses >= 3 {
                    self.fallback(now, None);
                    return true;
                }
            }
            if self.uplink_active(now) {
                let wire_size = if self.need_full {
                    size
                } else {
                    protocol::REGISTER_MIN
                };
                self.send_probe(active, now, wire_size, PROBE_PERIOD, &mut send);
                self.need_full = false;
            }
            self.due = now + PROBE_PERIOD;
            return true;
        }
        if matches!(self.validation, Validation::Running(deadline) if now >= deadline) {
            self.validation = Validation::Waiting;
            for candidate in &mut self.candidates {
                candidate.waiting = None;
                candidate.small_probe_confirmed = false;
            }
            if self.retries >= 2 {
                return !self.uplink_active(now);
            }
            self.due = now + Duration::from_secs(if self.retries == 0 { 5 } else { 15 });
            return true;
        }
        if matches!(self.validation, Validation::Waiting) {
            if !self.uplink_active(now) {
                return true;
            }
            if self.retries >= 2 {
                return false;
            }
        }
        if !can_validate {
            return true;
        }
        if matches!(self.validation, Validation::Waiting) {
            self.retries += 1;
        }
        if !matches!(self.validation, Validation::Running(_)) {
            self.validation = Validation::Running(now + VALIDATION_ROUND);
        }
        let repeat_small = std::mem::take(&mut self.repeat_small_probe);
        for index in 0..self.candidates.len() {
            self.validate_candidate(index, now, size, repeat_small && index == 0, &mut send);
        }
        self.due = now + VALIDATION_RETRY;
        true
    }

    fn validate_candidate(
        &mut self,
        index: usize,
        now: Instant,
        size: usize,
        repeat_small: bool,
        send: &mut impl FnMut(&CryptoCore, SocketAddr, Data, usize),
    ) {
        let candidate = &mut self.candidates[index];
        if candidate.mtu_failure == Some(size) {
            return;
        }
        if repeat_small
            && let Some(probe) = candidate.waiting.as_mut()
            && now < probe.deadline
            && probe.size == protocol::REGISTER_MIN
        {
            // Keep accepting an ACK for the first probe after sending it again.
            probe.deadline = now + VALIDATION_RETRY;
            send(
                &self.crypto,
                candidate.endpoint,
                Data::Request(PeerRegisterRequest {
                    cookie: probe.cookie,
                }),
                probe.size,
            );
        } else if candidate.probe_due(now) {
            let probe_size = if candidate.small_probe_confirmed {
                size
            } else {
                protocol::REGISTER_MIN
            };
            self.send_probe(index, now, probe_size, VALIDATION_RETRY, send);
        }
    }

    fn send_probe(
        &mut self,
        index: usize,
        now: Instant,
        size: usize,
        timeout: Duration,
        send: &mut impl FnMut(&CryptoCore, SocketAddr, Data, usize),
    ) {
        let candidate = &mut self.candidates[index];
        if candidate.mtu_failure == Some(size) {
            return;
        }
        let mut cookie = [0; 4];
        if SystemRandom::new().fill(&mut cookie).is_err() {
            return;
        }
        let cookie = u32::from_ne_bytes(cookie);
        if cookie != 0 {
            candidate.waiting = Some(Probe {
                cookie,
                size,
                deadline: now + timeout,
            });
            send(
                &self.crypto,
                candidate.endpoint,
                Data::Request(PeerRegisterRequest { cookie }),
                size,
            );
        }
    }

    pub fn acknowledge(&mut self, index: usize, cookie: u32, size: usize, now: Instant) -> bool {
        let candidate = &mut self.candidates[index];
        if !candidate.awaiting_ack(cookie, now) {
            return false;
        }
        let probe = candidate.waiting.take().unwrap();
        candidate.registered = true;
        if !candidate.small_probe_confirmed {
            candidate.small_probe_confirmed = true;
            if probe.size == protocol::REGISTER_MIN && size > protocol::REGISTER_MIN {
                tracing::debug!(endpoint = %candidate.endpoint, "Small peer probe verified");
                if self.selected.is_none() {
                    self.due = now;
                }
            }
        }
        if self.selected == Some(index) {
            self.misses = 0;
        }
        if probe.size == size && candidate.mtu_failure != Some(size) {
            candidate.validated_size = probe.size;
            if self.selected.is_none() || (self.is_lan(index) && self.selected != Some(index)) {
                self.selected = Some(index);
                self.misses = 0;
                self.due = now
                    + if !self.is_lan(index) && self.has_lan() {
                        VALIDATION_RETRY
                    } else {
                        PROBE_PERIOD
                    };
                self.retries = 0;
                if self.is_lan(index) || !self.has_lan() {
                    self.validation = Validation::Waiting;
                }
                self.repeat_small_probe = false;
                self.last_direct = now;
                return true;
            }
        }
        false
    }
}

pub(crate) fn canonical(endpoint: SocketAddr) -> SocketAddr {
    match endpoint {
        SocketAddr::V6(addr) if let Some(ip) = addr.ip().to_ipv4_mapped() => {
            SocketAddr::new(IpAddr::V4(ip), addr.port())
        }
        other => other,
    }
}

pub(crate) fn wire_endpoint(endpoint: SocketAddr, center: SocketAddr) -> SocketAddr {
    match endpoint {
        SocketAddr::V4(addr) if center.is_ipv6() => {
            SocketAddr::new(addr.ip().to_ipv6_mapped().into(), addr.port())
        }
        other => other,
    }
}

pub(crate) fn lease_clock() -> Option<u64> {
    #[cfg(any(target_os = "linux", target_os = "android"))]
    {
        let mut time = libc::timespec {
            tv_sec: 0,
            tv_nsec: 0,
        };
        // SAFETY: time points at writable storage for one timespec.
        if unsafe { libc::clock_gettime(libc::CLOCK_BOOTTIME, &mut time) } != 0 {
            return None;
        }
        let seconds = u64::try_from(time.tv_sec).ok()?;
        seconds
            .checked_mul(1_000_000_000)?
            .checked_add(u64::try_from(time.tv_nsec).ok()?)
    }
    #[cfg(target_vendor = "apple")]
    {
        #[repr(C)]
        struct Timebase {
            numer: u32,
            denom: u32,
        }
        unsafe extern "C" {
            fn mach_continuous_time() -> u64;
            fn mach_timebase_info(info: *mut Timebase) -> std::ffi::c_int;
        }
        static TIMEBASE: std::sync::OnceLock<Option<(u32, u32)>> = std::sync::OnceLock::new();
        let (numer, denom) = (*TIMEBASE.get_or_init(|| {
            let mut info = Timebase { numer: 0, denom: 0 };
            // SAFETY: info is writable and the API initializes its two fields.
            let result = unsafe { mach_timebase_info(&mut info) };
            (result == 0 && info.denom != 0).then_some((info.numer, info.denom))
        }))?;
        // SAFETY: mach_continuous_time takes no inputs and returns a counter.
        let ticks = unsafe { mach_continuous_time() };
        u64::try_from(u128::from(ticks) * u128::from(numer) / u128::from(denom)).ok()
    }
    #[cfg(not(any(target_os = "linux", target_os = "android", target_vendor = "apple")))]
    {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{PeerId, crypto::PeerKeyPair};

    fn path(now: Instant) -> PeerPath {
        let a = PeerKeyPair::generate().unwrap();
        let b = PeerKeyPair::generate().unwrap();
        let crypto = a
            .derive(
                [3; 16],
                (PeerId([1; 16]), 1),
                (PeerId([2; 16]), 2, b.public),
            )
            .unwrap();
        PeerPath::new(crypto, "192.0.2.1:3000".parse().unwrap(), None, now)
    }

    #[test]
    fn full_probe_fallback() {
        let now = Instant::now();
        let mut path = path(now);
        path.observe(now);
        let mut probes = Vec::new();
        assert!(path.poll(now, 1452, true, |_, _, data, size| {
            probes.push((data, size))
        }));
        assert_eq!(probes[0].1, protocol::REGISTER_MIN);
        let cookie = path.candidates[0].waiting.as_ref().unwrap().cookie;
        assert!(!path.acknowledge(0, cookie.wrapping_add(1), 1452, now));
        assert!(!path.acknowledge(0, cookie, 1452, now));
        assert_eq!(path.selected, None);
        let reachable = now + Duration::from_millis(1);
        assert!(path.poll(reachable, 1452, true, |_, _, data, size| {
            probes.push((data, size))
        }));
        assert_eq!(probes[1].1, 1452);
        let cookie = path.candidates[0].waiting.as_ref().unwrap().cookie;
        assert!(path.acknowledge(0, cookie, 1452, reachable));
        assert_eq!(path.selected, Some(0));

        let larger = now + Duration::from_millis(10);
        path.update_mtu(1305, false, larger);
        assert_eq!(path.selected, Some(0));
        path.update_mtu(1400, true, larger);
        assert_eq!(path.selected, None);
        assert!(!path.acknowledge(0, cookie, 1400, larger));
        path.poll(larger, 1400, true, |_, _, data, size| {
            probes.push((data, size))
        });
        let cookie = path.candidates[0].waiting.as_ref().unwrap().cookie;
        assert!(path.acknowledge(0, cookie, 1400, larger));
        path.update_mtu(1390, false, larger);
        assert_eq!(path.selected, Some(0));

        path.on_direct_traffic(larger, 700);
        let mut sent = Vec::new();
        for step in 1..=4 {
            let timestamp = larger + PROBE_PERIOD * step;
            path.observe(timestamp);
            path.poll(timestamp, 1390, true, |_, _, _, size| sent.push(size));
        }
        assert_eq!(sent, [1390; 3]);
        assert_eq!(path.selected, None);
        assert_eq!(path.due, larger + PROBE_PERIOD * 4 + VALIDATION_ROUND);
        let retry_at = path.due;
        path.observe(retry_at);
        sent.clear();
        assert!(path.poll(retry_at, 1390, true, |_, _, _, size| sent.push(size)));
        assert_eq!(sent, [protocol::REGISTER_MIN]);
    }

    #[test]
    fn mapped_ack() {
        let now = Instant::now();
        let mut path = path(now);
        let mapped = SocketAddr::new(path.candidates[0].endpoint.ip(), 4000);
        path.set_mapping(Some((mapped, 2_000_000_000)), now, 0);
        for (index, candidate) in path.candidates.iter_mut().enumerate() {
            candidate.waiting = Some(Probe {
                cookie: index as u32 + 1,
                size: protocol::REGISTER_MIN,
                deadline: now + VALIDATION_RETRY,
            });
        }
        let rebound = SocketAddr::new(mapped.ip(), 5000);
        assert_eq!(path.ack_candidate(rebound, 2, now), Some(1));
        assert_eq!(path.ack_candidate(rebound, 3, now), None);
        assert_eq!(
            path.ack_candidate(path.candidates[0].endpoint, 2, now),
            None
        );
        path.rebind(1, rebound, now);
        assert_eq!(path.registration_candidate(mapped), None);
        assert_eq!(path.expire_mapping(now, 2_000_000_000), Some(rebound));
        assert_eq!(path.ack_candidate(rebound, 1, now), None);

        path.set_mapping(Some((mapped, 3_000_000_000)), now, 2_000_000_000);
        path.candidates[1].waiting = Some(Probe {
            cookie: 4,
            size: protocol::REGISTER_MIN,
            deadline: now + VALIDATION_RETRY,
        });
        assert_eq!(path.registration_candidate(mapped), Some(1));
        assert_eq!(path.ack_candidate(rebound, 4, now), Some(1));
    }

    #[test]
    fn lan_after_public() {
        let now = Instant::now();
        let mut path = path(now);
        let observed = path.candidates[0].endpoint;
        let lan = "192.168.1.2:3000".parse().unwrap();
        path.candidates.push(Candidate::new(lan));
        path.observe(now);

        let mut sent = Vec::new();
        let wire_size = 1452;
        path.poll(now, wire_size, true, |_, endpoint, _, size| {
            sent.push((endpoint, size))
        });
        assert_eq!(
            sent,
            [
                (observed, protocol::REGISTER_MIN),
                (lan, protocol::REGISTER_MIN)
            ]
        );
        let observed_cookie = path.candidates[0].waiting.as_ref().unwrap().cookie;
        let lan_cookie = path.candidates[1].waiting.as_ref().unwrap().cookie;

        let observed_ack = now + Duration::from_millis(10);
        assert!(!path.acknowledge(0, observed_cookie, wire_size, observed_ack));
        sent.clear();
        path.poll(observed_ack, wire_size, true, |_, endpoint, _, size| {
            sent.push((endpoint, size))
        });
        assert_eq!(sent, [(observed, wire_size)]);
        let full_cookie = path.candidates[0].waiting.as_ref().unwrap().cookie;
        assert!(path.acknowledge(0, full_cookie, wire_size, observed_ack));
        assert_eq!(path.selected, Some(0));

        let lan_ack = now + Duration::from_millis(30);
        assert!(!path.acknowledge(1, lan_cookie, wire_size, lan_ack));
        assert!(path.lan_check_due(lan_ack));
        sent.clear();
        path.poll(lan_ack, wire_size, true, |_, endpoint, _, size| {
            sent.push((endpoint, size))
        });
        assert_eq!(sent, [(lan, wire_size)]);
        assert_eq!(path.selected, Some(0));
        let full_cookie = path.candidates[1].waiting.as_ref().unwrap().cookie;
        path.misses = 2;
        assert!(path.acknowledge(1, full_cookie, wire_size, lan_ack));
        assert_eq!(path.selected, Some(1));
        assert_eq!(path.misses, 0);
    }

    #[test]
    fn punch_retry() {
        let now = Instant::now();
        let mut path = path(now);
        let mut probes = Vec::new();
        let notice = now + Duration::from_millis(10);
        path.poll(now, 1452, true, |_, _, data, size| {
            probes.push((data, size))
        });
        path.on_punch_notice(notice);
        path.poll(notice, 1452, true, |_, _, data, size| {
            probes.push((data, size))
        });
        assert_eq!(probes.len(), 2);
        assert_eq!(probes[0], probes[1]);
        assert_eq!(probes[0].1, protocol::REGISTER_MIN);
        let ack_at = now + VALIDATION_RETRY;
        let cookie = path.candidates[0].waiting.as_ref().unwrap().cookie;
        assert!(!path.acknowledge(0, cookie, 1452, ack_at));
        assert!(path.candidates[0].waiting.is_none());
        path.poll(ack_at, 1452, true, |_, _, data, size| {
            probes.push((data, size))
        });
        assert_eq!(probes[2].1, 1452);
        assert!(path.selected.is_none());
    }

    #[test]
    fn rediscover_after_retries() {
        let now = Instant::now();
        let mut path = path(now);
        let mut send = |_: &CryptoCore, _, _, _| {};
        for (seconds, expected) in [
            (0, true),
            (5, true),
            (9, true),
            (10, true),
            (15, true),
            (29, true),
            (30, true),
            (35, false),
        ] {
            let tick = now + Duration::from_secs(seconds);
            path.observe(tick);
            assert_eq!(
                path.poll(tick, 1452, true, &mut send),
                expected,
                "at {seconds}s"
            );
        }
    }
}
