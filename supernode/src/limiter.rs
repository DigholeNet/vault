// SPDX-License-Identifier: MIT
use std::collections::HashMap;
use std::marker::PhantomData;
use std::net::IpAddr;

use tracing::warn;
use vault_core::{Time, TimeSource};

/// Wide per-IP INIT attempt guard — CPU protection only. The counter does
/// not distinguish success from failure, so after a server restart a burst
/// of legitimate clients sharing a NAT egress IP can still exceed it and
/// get dropped. Rejections are logged once per window so NAT-wide limiting
/// can be diagnosed without per-packet log spam.
const INIT_ATTEMPT_LIMIT: u32 = 60;
const INIT_ATTEMPT_WINDOW_SECS: Time = 60;
/// Repeated invalid encrypted confirmations from one source IP before it
/// is temporarily banned. Expired/abandoned handshakes are not evidence of
/// a password failure and are never counted here. This remains a shared-IP
/// restriction: only observed invalid confirmation packets count toward it.
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
    last_block_log: Option<Time>,
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
        if let Some(state) = self.init_failures.get_mut(&ip)
            && state.banned_until > now
        {
            if state
                .last_block_log
                .is_none_or(|last| now.saturating_sub(last) >= 30)
            {
                warn!(
                    "INIT from {ip} blocked by authentication-failure ban; retry in {}s (shared NAT clients are also affected)",
                    state.banned_until - now
                );
                state.last_block_log = Some(now);
            }
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
        entry.0 = entry.0.saturating_add(1);
        if entry.0 == INIT_ATTEMPT_LIMIT + 1 {
            warn!(
                "INIT from {ip} blocked by shared-IP rate limit ({INIT_ATTEMPT_LIMIT} attempts/{INIT_ATTEMPT_WINDOW_SECS}s); window resets in {}s",
                INIT_ATTEMPT_WINDOW_SECS - (now - entry.1)
            );
        }
        entry.0 <= INIT_ATTEMPT_LIMIT
    }

    /// Count repeated invalid encrypted confirmations against the source IP;
    /// never call this for timeouts or abandoned attempts. Ban after too many;
    /// counters decay after INIT_BAN_SECS without failures.
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
            last_block_log: None,
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
    fn attempt_limit_in_window() {
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
    fn window_expiry_resets_count() {
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
    fn ban_after_max_failures() {
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
    fn ban_expires() {
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
    fn counter_decays_after_ban() {
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
    fn success_clears_failures() {
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
    fn full_map_degrades_to_allow() {
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
    fn full_map_degrades_to_no_ban() {
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
    fn sweep_removes_stale() {
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
    fn sweep_keeps_active_ban() {
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
