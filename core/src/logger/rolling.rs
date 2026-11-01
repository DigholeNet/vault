// SPDX-License-Identifier: MIT
use dashmap::DashMap;
use std::{
    collections::HashMap,
    io,
    sync::{Arc, Mutex},
};
use time::format_description::FormatItem;
use tracing::{Level, level_filters::LevelFilter};
use tracing_appender::non_blocking::{NonBlocking, WorkerGuard};
use tracing_subscriber::{
    EnvFilter,
    fmt::{self, MakeWriter},
};

#[derive(Default)]
struct Writers {
    cache: HashMap<String, NonBlocking>,
    guards: Vec<WorkerGuard>,
    closed: bool,
}

/// Keep alive until all daemon cleanup and runtime shutdown have completed.
#[must_use = "dropping the logger guard shuts down file logging"]
pub struct LoggerGuard(Arc<Mutex<Writers>>);

impl Drop for LoggerGuard {
    fn drop(&mut self) {
        let guards = {
            let mut writers = self.0.lock().unwrap_or_else(|error| error.into_inner());
            writers.closed = true;
            writers.cache.clear();
            std::mem::take(&mut writers.guards)
        };
        // WorkerGuard drains its queue. Do not hold the state lock while waiting.
        drop(guards);
    }
}

fn daily_appender(log_dir: &str, key: &str) -> super::daily::DailyFileWriter {
    super::daily::DailyFileWriter::new(log_dir, key).expect("failed to initialize daily log file")
}

pub static LOGGER_TIME_FORMAT: &[FormatItem] = time::macros::format_description!(
    "[year]-[month]-[day] [hour]:[minute]:[second].[subsecond digits:3]"
);

struct MultiFileWriter {
    log_dir: Arc<String>,
    targets: DashMap<&'static str, &'static str>,
    writers: Arc<Mutex<Writers>>,
}

impl MultiFileWriter {
    fn get_writer(&self, key: &str) -> Box<dyn io::Write + Send> {
        let mut writers = self
            .writers
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        if writers.closed {
            return Box::new(io::sink());
        }
        if let Some(writer) = writers.cache.get(key) {
            return Box::new(writer.clone());
        }

        let file_appender = daily_appender(&self.log_dir, key);
        let (non_blocking, guard) = tracing_appender::non_blocking(file_appender);
        writers.cache.insert(key.to_string(), non_blocking.clone());
        writers.guards.push(guard);
        Box::new(non_blocking)
    }
}

impl<'a> MakeWriter<'a> for MultiFileWriter {
    type Writer = Box<dyn io::Write + 'a>;

    fn make_writer_for(&'a self, meta: &tracing::Metadata<'_>) -> Self::Writer {
        let key = if *meta.level() == Level::ERROR {
            "error"
        } else {
            self.targets.get(meta.target()).map_or("default", |s| *s)
        };

        self.get_writer(key)
    }

    fn make_writer(&'a self) -> Self::Writer {
        self.get_writer("default")
    }
}

pub fn init_logger(
    log_dir: &str,
    targets: DashMap<&'static str, &'static str>,
    log_levels: &[&str],
) -> LoggerGuard {
    // fmt().init() also installs LogTracer (default "tracing-log" feature),
    // bridging `log` records into tracing; a second install would panic.
    let environment = EnvFilter::builder()
        .with_default_directive(LevelFilter::INFO.into())
        .from_env_lossy();
    let filter = apply_log_levels(environment, log_levels);

    let timer = fmt::time::OffsetTime::new(
        time::UtcOffset::current_local_offset().unwrap_or(time::UtcOffset::UTC),
        LOGGER_TIME_FORMAT,
    );

    let writers = Arc::new(Mutex::new(Writers::default()));
    let guard = LoggerGuard(writers.clone());
    tracing_subscriber::fmt()
        .with_timer(timer)
        .with_writer(MultiFileWriter {
            log_dir: Arc::new(log_dir.to_string()),
            targets,
            writers,
        })
        .with_env_filter(filter)
        .init();
    guard
}

/// Explicit CLI modes take precedence over RUST_LOG; no flag preserves it.
pub fn cli_log_levels(verbose: bool, quiet: bool) -> &'static [&'static str] {
    if verbose {
        &["debug"]
    } else if quiet {
        &["warn"]
    } else {
        &[]
    }
}

fn apply_log_levels(environment: EnvFilter, levels: &[&str]) -> EnvFilter {
    if levels.is_empty() {
        return environment;
    }
    let mut filter = EnvFilter::default();
    for level in levels {
        filter = filter.add_directive((*level).parse().unwrap());
    }
    filter
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn normal_exit_drains_all_log_streams() {
        const CHILD_DIR: &str = "VAULT_LOG_SHUTDOWN_TEST_DIR";
        if let Some(directory) = std::env::var_os(CHILD_DIR) {
            let targets = DashMap::new();
            targets.insert("client", "client");
            let _guard = init_logger(directory.to_str().unwrap(), targets, &["info"]);
            for index in 0..5000 {
                tracing::info!("default record {index}");
                tracing::info!(target: "client", "client record {index}");
            }
            tracing::error!("shutdown completed");
            return;
        }
        let directory = std::env::temp_dir().join(format!("vault-exit-{}", uuid::Uuid::new_v4()));
        let status = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "logger::rolling::tests::normal_exit_drains_all_log_streams",
            ])
            .env(CHILD_DIR, &directory)
            .status()
            .unwrap();
        assert!(status.success());
        assert_eq!(
            fs::read_to_string(directory.join("default.log"))
                .unwrap()
                .lines()
                .count(),
            5000
        );
        assert_eq!(
            fs::read_to_string(directory.join("client.log"))
                .unwrap()
                .lines()
                .count(),
            5000
        );
        assert!(
            fs::read_to_string(directory.join("error.log"))
                .unwrap()
                .contains("shutdown completed")
        );
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn daily_logs_prune_existing_history_per_stream() {
        use std::io::Write;

        let dir = std::env::temp_dir().join(format!("vault-logs-{}", uuid::Uuid::new_v4()));
        fs::create_dir_all(&dir).unwrap();
        let today = time::OffsetDateTime::now_utc().date();
        for age in 1..=35 {
            let date = today - time::Duration::days(age);
            fs::write(dir.join(format!("default.log.{date}")), "old log").unwrap();
            fs::write(dir.join(format!("client.log.{date}")), "other stream").unwrap();
        }
        fs::write(dir.join("unrelated.txt"), "keep").unwrap();
        fs::write(dir.join("default.log.backup"), "keep backup").unwrap();

        let mut appender = daily_appender(dir.to_str().unwrap(), "default");
        appender.write_all(b"current log").unwrap();
        appender.flush().unwrap();
        drop(appender);

        let names: Vec<_> = fs::read_dir(&dir)
            .unwrap()
            .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        assert_eq!(
            names
                .iter()
                .filter(|name| name.starts_with("default.log.")
                    && name.as_str() != "default.log.backup")
                .count(),
            29
        );
        assert_eq!(
            names
                .iter()
                .filter(|name| name.starts_with("client.log."))
                .count(),
            35
        );
        assert_eq!(
            fs::read_to_string(dir.join("unrelated.txt")).unwrap(),
            "keep"
        );
        assert_eq!(
            fs::read_to_string(dir.join("default.log.backup")).unwrap(),
            "keep backup"
        );
        assert_eq!(
            fs::read_to_string(dir.join("default.log")).unwrap(),
            "current log"
        );
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn cli_log_overrides() {
        for (verbose, quiet, expected) in [(true, false, "debug"), (false, true, "warn")] {
            let filter = apply_log_levels(
                EnvFilter::new("trace,vault_core=trace"),
                cli_log_levels(verbose, quiet),
            );
            assert_eq!(filter.to_string(), expected);
        }
        let filter = apply_log_levels(EnvFilter::new("debug"), cli_log_levels(false, false));
        assert_eq!(filter.to_string(), "debug");
    }
}
