// SPDX-License-Identifier: MIT
//! Shared single-file logger for the mobile clients.
//!
//! All writers append whole records with O_APPEND. One previous generation is
//! retained, and every writer participates in rotation so Rust-only traffic
//! cannot grow the current file without bound.

use std::fs::OpenOptions;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};
use std::time::{SystemTime, UNIX_EPOCH};

const MAX_LOG_SIZE: u64 = 1024 * 1024;

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

fn previous_path(path: &Path) -> PathBuf {
    let stem = path
        .file_stem()
        .and_then(|stem| stem.to_str())
        .unwrap_or("vault");
    path.with_file_name(format!("{stem}.prev.log"))
}

/// Append one tracing line synchronously. The path mutex is never waited on:
/// a busy mutex drops the record rather than blocking a network worker.
pub fn append(line: &str) {
    append_formatted(&format_record(&utc_timestamp(), line));
}

/// Append a platform record using the same format and rotation as Rust
/// records. `timestamp_ms` is the event time in epoch milliseconds captured
/// by the platform at its call site; `None` falls back to the write time.
pub fn append_record(level: &str, source: &str, message: &str, timestamp_ms: Option<u64>) {
    let level = if level == "WARN" { "WARNING" } else { level };
    let timestamp = timestamp_ms.map_or_else(utc_timestamp, |milliseconds| {
        let seconds = (milliseconds / 1000) as i64;
        let millis = (milliseconds % 1000) as u32;
        format!("{}Z", format_timestamp(seconds, millis))
    });
    let record: String = message
        .lines()
        .map(|message| format!("[{timestamp}] [{level}] [{source}] {message}\n"))
        .collect();
    append_formatted(&record);
}

fn append_formatted(record: &str) {
    let Some(mutex) = LOG_FILE_PATH.get() else {
        return;
    };
    let Ok(guard) = mutex.try_lock() else { return };
    let Some(path) = guard.as_ref() else { return };
    let _ = rotate_if_needed(path);
    let Ok(mut file) = OpenOptions::new().create(true).append(true).open(path) else {
        return;
    };
    use std::io::Write;
    let _ = file.write_all(record.as_bytes());
}

fn rotate_if_needed(path: &Path) -> io::Result<()> {
    if std::fs::metadata(path)
        .map(|metadata| metadata.len() <= MAX_LOG_SIZE)
        .unwrap_or(true)
    {
        return Ok(());
    }
    rotate(path)
}

/// Preserve the current file as the single previous generation.
pub fn rotate_for_new_session() -> io::Result<()> {
    let guard = log_file_path()
        .lock()
        .map_err(|_| io::Error::other("log path lock poisoned"))?;
    let Some(path) = guard.as_ref() else {
        return Ok(());
    };
    if path.exists() {
        rotate(path)?;
    }
    Ok(())
}

fn rotate(path: &Path) -> io::Result<()> {
    let previous = previous_path(path);
    match std::fs::remove_file(&previous) {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error),
    }
    std::fs::rename(path, previous)
}

/// Truncate both generations in place. O_APPEND writers can continue afterwards.
pub fn clear() -> io::Result<()> {
    let guard = log_file_path()
        .lock()
        .map_err(|_| io::Error::other("log path lock poisoned"))?;
    let Some(path) = guard.as_ref() else {
        return Ok(());
    };
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    for path in [path.clone(), previous_path(path)] {
        OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(path)?;
    }
    Ok(())
}

/// Read previous and current logs in chronological order.
pub fn read(legacy_timezone_offset_seconds: i32) -> io::Result<String> {
    let guard = log_file_path()
        .lock()
        .map_err(|_| io::Error::other("log path lock poisoned"))?;
    let Some(path) = guard.as_ref() else {
        return Ok(String::new());
    };
    let mut parts = Vec::new();
    for path in [previous_path(path), path.clone()] {
        match std::fs::read_to_string(path) {
            Ok(part) => parts.push(part),
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }
    }
    Ok(merge_chronologically(
        &parts,
        legacy_timezone_offset_seconds,
    ))
}

fn format_record(timestamp: &str, line: &str) -> String {
    let line = line.trim();
    let (level, message) = match line.split_once(char::is_whitespace) {
        Some(("WARN", message)) => ("WARNING", message.trim_start()),
        Some((level @ ("TRACE" | "DEBUG" | "INFO" | "ERROR"), message)) => {
            (level, message.trim_start())
        }
        Some(("[PANIC]", message)) => ("ERROR", message.trim_start()),
        _ => ("INFO", line),
    };
    message
        .lines()
        .map(|message| format!("[{timestamp}] [{level}] [rust] {message}\n"))
        .collect()
}

/// Merge records by timestamp while retaining input order for equal timestamps.
/// Legacy local timestamps are converted only for their sort keys; original
/// record text is preserved apart from the historical Rust severity fixup.
pub fn merge_chronologically(parts: &[String], legacy_timezone_offset_seconds: i32) -> String {
    struct Entry {
        index: usize,
        line: String,
        key: String,
    }
    let mut entries = Vec::new();
    let mut index = 0;
    for part in parts {
        for raw in part.lines().filter(|line| !line.is_empty()) {
            let line = normalize_legacy_record(raw);
            let key = line
                .strip_prefix('[')
                .and_then(|line| line.split_once(']').map(|(timestamp, _)| timestamp))
                .map(|timestamp| timestamp_key(timestamp, legacy_timezone_offset_seconds))
                .unwrap_or_default();
            entries.push(Entry { index, line, key });
            index += 1;
        }
    }
    entries.sort_by(|left, right| {
        left.key
            .cmp(&right.key)
            .then_with(|| left.index.cmp(&right.index))
    });
    entries
        .into_iter()
        .map(|entry| entry.line)
        .collect::<Vec<_>>()
        .join("\n")
}

fn normalize_legacy_record(raw: &str) -> String {
    if raw.starts_with("[[") {
        return normalize_legacy_record(raw.strip_prefix('[').unwrap_or(raw));
    }
    let Some(end) = raw.find(']') else {
        return raw.to_string();
    };
    let tail = raw[end + 1..].trim_start();
    let Some(rest) = tail.strip_prefix("[rust] ") else {
        return raw.to_string();
    };
    let rest = rest.trim_start();
    let Some((level, message)) = rest.split_once(char::is_whitespace) else {
        return raw.to_string();
    };
    if !matches!(level, "TRACE" | "DEBUG" | "INFO" | "WARN" | "ERROR") {
        return raw.to_string();
    }
    let level = if level == "WARN" { "WARNING" } else { level };
    format!("{} [{level}] [rust] {}", &raw[..=end], message.trim_start())
}

fn timestamp_key(timestamp: &str, legacy_timezone_offset_seconds: i32) -> String {
    let (value, offset) = match timestamp.strip_suffix('Z') {
        Some(value) => (value, 0),
        None => (timestamp, legacy_timezone_offset_seconds as i64),
    };
    parse_timestamp(value)
        .map(|(seconds, millis)| format_timestamp(seconds - offset, millis))
        .unwrap_or_else(|| value.to_string())
}

fn parse_timestamp(value: &str) -> Option<(i64, u32)> {
    if value.len() != 23
        || value.as_bytes()[4] != b'-'
        || value.as_bytes()[7] != b'-'
        || value.as_bytes()[10] != b' '
        || value.as_bytes()[13] != b':'
        || value.as_bytes()[16] != b':'
        || value.as_bytes()[19] != b'.'
    {
        return None;
    }
    let number = |range: std::ops::Range<usize>| value.get(range)?.parse::<u32>().ok();
    let year = number(0..4)? as i32;
    let month = number(5..7)?;
    let day = number(8..10)?;
    if !(1..=12).contains(&month) || !(1..=31).contains(&day) {
        return None;
    }
    let hour = number(11..13)?;
    let minute = number(14..16)?;
    let second = number(17..19)?;
    let millis = number(20..23)?;
    if hour > 23 || minute > 59 || second > 59 {
        return None;
    }
    let days = days_from_civil(year, month, day);
    Some((
        days * 86_400 + (hour * 3600 + minute * 60 + second) as i64,
        millis,
    ))
}

fn days_from_civil(year: i32, month: u32, day: u32) -> i64 {
    let year = year - i32::from(month <= 2);
    let era = year.div_euclid(400);
    let year_of_era = year - era * 400;
    let adjusted_month = month as i32 + if month > 2 { -3 } else { 9 };
    let day_of_year = (153 * adjusted_month + 2) / 5 + day as i32 - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    (era * 146_097 + day_of_era - 719_468) as i64
}

fn format_timestamp(seconds: i64, millis: u32) -> String {
    let days = seconds.div_euclid(86_400);
    let seconds_of_day = seconds.rem_euclid(86_400);
    let (year, month, day) = civil_from_days(days);
    let (hour, minute, second) = (
        seconds_of_day / 3600,
        (seconds_of_day % 3600) / 60,
        seconds_of_day % 60,
    );
    format!("{year:04}-{month:02}-{day:02} {hour:02}:{minute:02}:{second:02}.{millis:03}")
}

/// UTC timestamp matching the shared record format.
fn utc_timestamp() -> String {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    format!(
        "{}Z",
        format_timestamp(now.as_secs() as i64, now.subsec_millis())
    )
}

fn civil_from_days(days: i64) -> (i64, u32, u32) {
    // Howard Hinnant's civil_from_days.
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let day_of_era = z.rem_euclid(146_097);
    let year_of_era =
        (day_of_era - day_of_era / 1460 + day_of_era / 36524 - day_of_era / 146_096) / 365;
    let mut year = year_of_era + era * 400;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_prime = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * month_prime + 2) / 5 + 1;
    let month = if month_prime < 10 {
        month_prime + 3
    } else {
        month_prime - 9
    };
    year += i64::from(month <= 2);
    (year, month as u32, day as u32)
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
        TraceLineWriter::default()
    }
}

/// Buffer fragmented formatter writes until a complete record is available.
#[derive(Default)]
pub struct TraceLineWriter {
    buffer: Vec<u8>,
}

impl std::io::Write for TraceLineWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.buffer.extend_from_slice(buf);
        while let Some(end) = self.buffer.iter().position(|byte| *byte == b'\n') {
            let bytes: Vec<u8> = self.buffer.drain(..=end).collect();
            let line = String::from_utf8_lossy(&bytes);
            if !line.trim().is_empty() {
                append(line.trim_end());
            }
        }
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl Drop for TraceLineWriter {
    fn drop(&mut self) {
        if !self.buffer.is_empty() {
            let line = String::from_utf8_lossy(&self.buffer);
            if !line.trim().is_empty() {
                append(line.trim_end());
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    static TEST_PATH_LOCK: Mutex<()> = Mutex::new(());

    #[test]
    fn appended_line_is_timestamped() {
        let _lock = TEST_PATH_LOCK.lock().unwrap();
        let dir = std::env::temp_dir().join(format!("vault-file-log-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("shared.log");
        let _ = std::fs::remove_file(&path);
        set_path(path.to_str().unwrap());
        append("hello from test");
        use std::io::Write;
        let mut writer = TraceLineWriter::default();
        writer.write_all(b" WA").unwrap();
        writer.write_all(b"RN fragmented ").unwrap();
        writer.write_all(b"record\n").unwrap();
        let content = std::fs::read_to_string(&path).unwrap();
        assert_eq!(content.lines().count(), 2);
        assert!(content.contains("[WARNING] [rust] fragmented record"));
        assert!(content.contains("[INFO] [rust] hello from test"));
        assert!(content.contains("Z] [INFO] [rust]"));
        let swift_path = path.clone();
        let swift = std::thread::spawn(move || {
            let mut file = OpenOptions::new().append(true).open(swift_path).unwrap();
            for _ in 0..200 {
                file.write_all(b"[2026-10-24 11:07:49.001Z] [NOTICE] [ne] Swift record\n")
                    .unwrap();
            }
        });
        for _ in 0..200 {
            append("INFO Rust record");
        }
        swift.join().unwrap();
        let content = std::fs::read_to_string(&path).unwrap();
        assert_eq!(content.lines().count(), 402);
        for line in content.lines().skip(2) {
            assert!(
                line.ends_with("[NOTICE] [ne] Swift record")
                    || line.ends_with("[INFO] [rust] Rust record")
            );
            assert!(!line.starts_with("[["));
            assert_eq!(line.matches("Z]").count(), 1);
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn multiline_log_format() {
        let timestamp = "2026-10-24 11:07:49.001Z";
        assert_eq!(
            format_record(timestamp, " INFO Heartbeat ping sent"),
            "[2026-10-24 11:07:49.001Z] [INFO] [rust] Heartbeat ping sent\n"
        );
        assert_eq!(
            format_record(timestamp, "WARN failed\ndetails"),
            "[2026-10-24 11:07:49.001Z] [WARNING] [rust] failed\n[2026-10-24 11:07:49.001Z] [WARNING] [rust] details\n"
        );
        assert!(
            format_record(timestamp, "[PANIC] test panic").contains("[ERROR] [rust] test panic")
        );
    }

    #[test]
    fn utc_timestamp_shape() {
        let ts = utc_timestamp();
        assert_eq!(ts.len(), 24);
        assert!(ts.ends_with('Z'));
        assert_eq!(&ts[4..5], "-");
        assert_eq!(&ts[10..11], " ");
    }

    #[test]
    fn merge_legacy() {
        let app = "[2026-10-23 13:00:00.000] [INFO] [app] local\n".to_string();
        let rust = "[2026-10-23 05:00:00.000Z] [rust]  WARN remote\n".to_string();
        let merged = merge_chronologically(&[app, rust], 8 * 3600);
        assert_eq!(
            merged,
            "[2026-10-23 13:00:00.000] [INFO] [app] local\n[2026-10-23 05:00:00.000Z] [WARNING] [rust] remote"
        );
    }

    #[test]
    fn platform_record_uses_call_site_timestamp() {
        let _lock = TEST_PATH_LOCK.lock().unwrap();
        let dir = std::env::temp_dir().join(format!("vault-file-log-ts-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("vault.log");
        set_path(path.to_str().unwrap());
        let seconds = days_from_civil(2026, 10, 24) * 86_400 + 11 * 3600 + 7 * 60 + 49;
        append_record("INFO", "app", "call-site", Some(seconds as u64 * 1000 + 1));
        let content = std::fs::read_to_string(&path).unwrap();
        assert_eq!(
            content,
            "[2026-10-24 11:07:49.001Z] [INFO] [app] call-site\n"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn read_rotate_and_clear() {
        let _lock = TEST_PATH_LOCK.lock().unwrap();
        let dir =
            std::env::temp_dir().join(format!("vault-file-log-read-test-{}", std::process::id()));
        let path = dir.join("vault.log");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        set_path(path.to_str().unwrap());
        append_record("INFO", "app", "current", None);
        rotate_for_new_session().unwrap();
        append_record("INFO", "rust", "next", None);
        let content = read(0).unwrap();
        assert!(content.contains("current") && content.contains("next"));
        clear().unwrap();
        assert_eq!(read(0).unwrap(), "");
        assert!(path.exists() && previous_path(&path).exists());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
