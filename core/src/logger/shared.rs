// SPDX-License-Identifier: MIT
//! Shared single-file logger for the mobile clients.
//!
//! Unlike [`super::rolling`] (per-target daily rolling files for the server
//! and standalone edge binaries), this module appends everything to one
//! file owned by the platform app (the same `vault.log` the Kotlin/Swift
//! side writes to), so a field diagnostic capture contains both platform
//! and core/bridge records in order. The platform side owns rotation, so
//! writes open + append per line and never hold an fd.

use std::fs::OpenOptions;
use std::path::PathBuf;
use std::sync::{Mutex, OnceLock};
use std::time::{SystemTime, UNIX_EPOCH};

static LOG_FILE_PATH: OnceLock<Mutex<Option<PathBuf>>> = OnceLock::new();

fn log_file_path() -> &'static Mutex<Option<PathBuf>> {
    LOG_FILE_PATH.get_or_init(|| Mutex::new(None))
}

/// Point the file logger at the platform app's shared log file. Safe to
/// call again to change the path.
pub fn set_path(path: &str) {
    if let Ok(mut guard) = log_file_path().lock() {
        *guard = Some(PathBuf::from(path));
    }
}

/// Append one line to the shared log file. Never blocks: if the path lock
/// is held (e.g. by a panicking thread that died mid-write) the line is
/// dropped rather than risking a deadlock.
pub fn append(line: &str) {
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

/// UTC timestamp matching the platform file loggers' line format (which use
/// local time); the trailing Z marks these lines as UTC.
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
/// default handling, so a crash that kills the process leaves a trace
/// instead of a silently truncated log.
pub fn install_panic_hook() {
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
        append(&format!("[PANIC] {message} at {location}"));
        default_hook(info);
    }));
}

/// Routes tracing records into the shared log file.
pub struct TraceLogWriter;

impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for TraceLogWriter {
    type Writer = TraceLineWriter;

    fn make_writer(&'a self) -> Self::Writer {
        TraceLineWriter
    }
}

/// Line-oriented so partially written records do not produce half lines.
pub struct TraceLineWriter;

impl std::io::Write for TraceLineWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let line = String::from_utf8_lossy(buf);
        let line = line.trim_end();
        if !line.is_empty() {
            append(line);
        }
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn appended_line_is_timestamped() {
        // Per-process path: concurrent `cargo test` processes must not race
        // on a shared temp file.
        let dir = std::env::temp_dir().join(format!("vault-file-log-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("shared.log");
        let _ = std::fs::remove_file(&path);
        set_path(path.to_str().unwrap());
        append("hello from test");
        let content = std::fs::read_to_string(&path).unwrap();
        assert!(content.contains("[rust] hello from test"));
        assert!(content.contains("Z] [rust]"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn utc_timestamp_shape() {
        let ts = utc_timestamp();
        // "YYYY-MM-DD HH:MM:SS.mmmZ"
        assert_eq!(ts.len(), 24);
        assert!(ts.ends_with('Z'));
        assert_eq!(&ts[4..5], "-");
        assert_eq!(&ts[10..11], " ");
    }
}
