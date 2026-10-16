// SPDX-License-Identifier: MIT
use std::collections::HashMap;
use std::marker::PhantomData;
use std::net::IpAddr;

use tracing::warn;
use vault_core::{Time, TimeSource};

/// Wide per-IP INIT attempt guard — CPU protection only. The anti-guessing
/// mechanism is failure-based banning below, so legitimate clients sharing
/// a NAT egress IP never come near this limit.
const INIT_ATTEMPT_LIMIT: u32 = 60;
const INIT_ATTEMPT_WINDOW_SECS: Time = 60;
/// Failed handshakes (pending expiry or failed confirmation) from one
/// source IP before it is temporarily banned. SPAKE2 gives an active
/// attacker exactly one password guess per handshake; banning after a few
/// failures is what makes online guessing impractical. Legitimate clients
/// essentially never fail, so NAT-sharers are unaffected.
const MAX_INIT_FAILURES: u32 = 10;
/// Ban duration, and also the decay window for failure counters.
const INIT_BAN_SECS: Time = 300;
/// Cap on maps keyed by attacker-controlled values (source IP, peer id),
/// bounding memory under spoofed-source floods. When full, new keys are
/// simply not tracked (degraded limiting, bounded memory).
pub(crate) const MAX_TRACKED_ENTRIES: usize = 100_000;

/// Per-IP handshake failure tracking for the temporary INIT ban.
struct FailureState {
    failures: u32,
    last_failure: Time,
    banned_until: Time,
}

/// Per-source-IP INIT rate limiting: a wide attempt counter (CPU guard)
/// plus a failure counter that temporarily bans IPs with repeated failed
/// handshakes.
pub struct InitLimiter<TS: TimeSource> {
    /// Per-source-IP INIT attempt counters (CPU guard): (count, window start).
    init_requests: HashMap<IpAddr, (u32, Time)>,
    /// Per-source-IP failed-handshake counters driving the temporary ban.
    init_failures: HashMap<IpAddr, FailureState>,
    _ts: PhantomData<TS>,
}

impl<TS: TimeSource> Default for InitLimiter<TS> {
    fn default() -> Self {
        Self {
            init_requests: HashMap::new(),
            init_failures: HashMap::new(),
            _ts: PhantomData,
        }
    }
}

impl<TS: TimeSource> InitLimiter<TS> {
    /// Whether an INIT from `ip` is allowed: false while the IP is banned
    /// for repeated handshake failures, or over the wide per-IP attempt
    /// guard (CPU protection only).
    pub fn check_init_allowed(&mut self, ip: IpAddr) -> bool {
        let now = TS::now();
        if let Some(state) = self.init_failures.get(&ip)
            && state.banned_until > now
        {
            return false;
        }
        if !self.init_requests.contains_key(&ip) && self.init_requests.len() >= MAX_TRACKED_ENTRIES
        {
            // Tracking map full (spoofed-source flood): allow without
            // counting rather than growing memory forever.
            return true;
        }
        let entry = self.init_requests.entry(ip).or_insert((0, now));
        if now - entry.1 >= INIT_ATTEMPT_WINDOW_SECS {
            *entry = (0, now);
        }
        entry.0 += 1;
        entry.0 <= INIT_ATTEMPT_LIMIT
    }

    /// Count a failed handshake (pending expiry or failed confirmation)
    /// against the source IP; ban it after too many. Counters decay after
    /// INIT_BAN_SECS without failures.
    pub fn record_init_failure(&mut self, ip: IpAddr) {
        let now = TS::now();
        if !self.init_failures.contains_key(&ip) && self.init_failures.len() >= MAX_TRACKED_ENTRIES
        {
            return;
        }
        let state = self.init_failures.entry(ip).or_insert(FailureState {
            failures: 0,
            last_failure: 0,
            banned_until: 0,
        });
        if state.banned_until > now {
            return;
        }
        if now - state.last_failure > INIT_BAN_SECS {
            state.failures = 0;
        }
        state.last_failure = now;
        state.failures += 1;
        if state.failures >= MAX_INIT_FAILURES {
            state.banned_until = now + INIT_BAN_SECS;
            state.failures = 0;
            warn!(
                "Too many failed handshakes from {}, banning INIT for {}s",
                ip, INIT_BAN_SECS
            );
        }
    }

    /// A successful confirmation clears the IP's failure history.
    pub fn record_init_success(&mut self, ip: IpAddr) {
        self.init_failures.remove(&ip);
    }

    /// Drop rate-limit entries well past their window, expired bans and
    /// fully decayed failure counters.
    pub fn sweep(&mut self) {
        let cutoff = TS::now() - INIT_ATTEMPT_WINDOW_SECS * 2;
        self.init_requests.retain(|_, (_, start)| *start > cutoff);
        let now = TS::now();
        let cutoff = now - INIT_BAN_SECS;
        self.init_failures
            .retain(|_, s| s.banned_until > now || s.last_failure > cutoff);
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use super::*;
    use crate::mock_time::{MockTime, advance, lock_clock};

    fn ip(n: u32) -> IpAddr {
        IpAddr::V4(Ipv4Addr::from(n))
    }

    #[test]
    fn test_attempt_limit_within_window() {
        let _guard = lock_clock(1_000);
        let mut limiter = InitLimiter::<MockTime>::default();

        for _ in 0..INIT_ATTEMPT_LIMIT {
            assert!(limiter.check_init_allowed(ip(1)));
        }
        assert!(!limiter.check_init_allowed(ip(1)));
        // Other IPs are unaffected.
        assert!(limiter.check_init_allowed(ip(2)));
    }

    #[test]
    fn test_attempt_window_expiry_resets_count() {
        let _guard = lock_clock(1_000);
        let mut limiter = InitLimiter::<MockTime>::default();

        for _ in 0..INIT_ATTEMPT_LIMIT {
            assert!(limiter.check_init_allowed(ip(1)));
        }
        assert!(!limiter.check_init_allowed(ip(1)));

        advance(INIT_ATTEMPT_WINDOW_SECS);
        assert!(limiter.check_init_allowed(ip(1)));
    }

    #[test]
    fn test_ban_after_max_failures() {
        let _guard = lock_clock(1_000);
        let mut limiter = InitLimiter::<MockTime>::default();

        for _ in 0..MAX_INIT_FAILURES - 1 {
            limiter.record_init_failure(ip(1));
        }
        assert!(limiter.check_init_allowed(ip(1)));

        limiter.record_init_failure(ip(1));
        assert!(!limiter.check_init_allowed(ip(1)));
    }

    #[test]
    fn test_ban_expires_after_ban_secs() {
        let _guard = lock_clock(1_000);
        let mut limiter = InitLimiter::<MockTime>::default();

        for _ in 0..MAX_INIT_FAILURES {
            limiter.record_init_failure(ip(1));
        }
        assert!(!limiter.check_init_allowed(ip(1)));

        advance(INIT_BAN_SECS - 1);
        assert!(!limiter.check_init_allowed(ip(1)));

        advance(1);
        assert!(limiter.check_init_allowed(ip(1)));
    }

    #[test]
    fn test_failure_counter_decays_after_ban_secs() {
        let _guard = lock_clock(1_000);
        let mut limiter = InitLimiter::<MockTime>::default();

        for _ in 0..MAX_INIT_FAILURES - 1 {
            limiter.record_init_failure(ip(1));
        }
        // No failures for INIT_BAN_SECS: the counter resets, so one more
        // failure must not trigger a ban.
        advance(INIT_BAN_SECS + 1);
        limiter.record_init_failure(ip(1));
        assert!(limiter.check_init_allowed(ip(1)));

        // The decayed counter restarts from zero: it takes a full
        // MAX_INIT_FAILURES fresh failures to ban again.
        for _ in 0..MAX_INIT_FAILURES - 1 {
            limiter.record_init_failure(ip(1));
        }
        assert!(!limiter.check_init_allowed(ip(1)));
    }

    #[test]
    fn test_record_success_clears_failure_history() {
        let _guard = lock_clock(1_000);
        let mut limiter = InitLimiter::<MockTime>::default();

        for _ in 0..MAX_INIT_FAILURES - 1 {
            limiter.record_init_failure(ip(1));
        }
        limiter.record_init_success(ip(1));
        assert!(limiter.init_failures.is_empty());

        // History cleared: another MAX_INIT_FAILURES - 1 failures do not ban.
        for _ in 0..MAX_INIT_FAILURES - 1 {
            limiter.record_init_failure(ip(1));
        }
        assert!(limiter.check_init_allowed(ip(1)));

        limiter.record_init_failure(ip(1));
        assert!(!limiter.check_init_allowed(ip(1)));
    }

    #[test]
    fn test_full_requests_map_degrades_to_allow() {
        let _guard = lock_clock(1_000);
        let mut limiter = InitLimiter::<MockTime>::default();

        for n in 0..MAX_TRACKED_ENTRIES as u32 {
            limiter.init_requests.insert(ip(n), (1, 1_000));
        }
        // A new source IP is allowed without being tracked.
        let new_ip = ip(MAX_TRACKED_ENTRIES as u32);
        assert!(limiter.check_init_allowed(new_ip));
        assert_eq!(limiter.init_requests.len(), MAX_TRACKED_ENTRIES);
    }

    #[test]
    fn test_full_failures_map_degrades_to_no_ban() {
        let _guard = lock_clock(1_000);
        let mut limiter = InitLimiter::<MockTime>::default();

        for n in 0..MAX_TRACKED_ENTRIES as u32 {
            limiter.record_init_failure(ip(n));
        }
        assert_eq!(limiter.init_failures.len(), MAX_TRACKED_ENTRIES);
        // Failures from a new source IP are dropped: it can never be banned.
        let new_ip = ip(MAX_TRACKED_ENTRIES as u32);
        for _ in 0..MAX_INIT_FAILURES {
            limiter.record_init_failure(new_ip);
        }
        assert_eq!(limiter.init_failures.len(), MAX_TRACKED_ENTRIES);
        assert!(limiter.check_init_allowed(new_ip));
    }

    #[test]
    fn test_sweep_removes_stale_entries() {
        let _guard = lock_clock(1_000);
        let mut limiter = InitLimiter::<MockTime>::default();

        assert!(limiter.check_init_allowed(ip(1)));
        limiter.record_init_failure(ip(2));
        assert_eq!(limiter.init_requests.len(), 1);
        assert_eq!(limiter.init_failures.len(), 1);

        // Past both the attempt retention and the failure decay window.
        advance(INIT_BAN_SECS + 1);
        limiter.sweep();
        assert!(limiter.init_requests.is_empty());
        assert!(limiter.init_failures.is_empty());
    }

    #[test]
    fn test_sweep_keeps_active_ban() {
        let _guard = lock_clock(1_000);
        let mut limiter = InitLimiter::<MockTime>::default();

        for _ in 0..MAX_INIT_FAILURES {
            limiter.record_init_failure(ip(1));
        }
        limiter.sweep();
        assert_eq!(limiter.init_failures.len(), 1);
        assert!(!limiter.check_init_allowed(ip(1)));
    }
}
