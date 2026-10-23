// SPDX-License-Identifier: MIT
//! Shared test clock. `TimeSource::now` is a static method, so tests drive
//! a global counter and serialize on a mutex to stay independent of each
//! other under parallel `cargo test` execution.
use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::{Mutex, MutexGuard};

use vault_core::{Time, TimeSource};

static NOW: AtomicI64 = AtomicI64::new(0);
static CLOCK_MUTEX: Mutex<()> = Mutex::new(());

#[derive(Default, Clone, Copy)]
pub struct MockTime;

impl TimeSource for MockTime {
    fn now() -> Time {
        NOW.load(Ordering::SeqCst)
    }
}

/// Lock the shared clock for the duration of a test and set it to `now`.
pub fn lock_clock(now: Time) -> MutexGuard<'static, ()> {
    let guard = CLOCK_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
    NOW.store(now, Ordering::SeqCst);
    guard
}

pub fn advance(secs: Time) {
    NOW.fetch_add(secs, Ordering::SeqCst);
}
