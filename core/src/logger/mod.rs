// SPDX-License-Identifier: MIT
//! Logging facilities for the two deployment shapes of vault-core:
//!
//! - [`shared`] (all platforms): mobile clients via vault-bridge. A single
//!   log file owned and rotated by the platform app, appended line-by-line
//!   without holding an fd; also home of the panic hook.
//! - `rolling` (not on iOS): server and standalone edge daemons. Per-target
//!   daily rolling files via tracing-appender; entry point is
//!   [`rolling::init_logger`].

#[cfg(not(target_os = "ios"))]
pub mod rolling;
pub mod shared;
