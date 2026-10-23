// SPDX-License-Identifier: MIT
use dashmap::DashMap;
use once_cell::sync::Lazy;
use std::{
    fs, io,
    sync::{Arc, Mutex},
};
use time::format_description::FormatItem;
use tracing::{Level, level_filters::LevelFilter};
use tracing_appender::non_blocking::{NonBlocking, WorkerGuard};
use tracing_subscriber::{
    EnvFilter,
    fmt::{self, MakeWriter},
};

static WRITER_CACHE: Lazy<DashMap<String, NonBlocking>> = Lazy::new(DashMap::new);
static GUARD_CACHE: Lazy<Mutex<Vec<WorkerGuard>>> = Lazy::new(|| Mutex::new(Vec::new()));

pub static LOGGER_TIME_FORMAT: &[FormatItem] = time::macros::format_description!(
    "[year]-[month]-[day] [hour]:[minute]:[second].[subsecond digits:3]"
);

struct MultiFileWriter {
    log_dir: Arc<String>,
    targets: DashMap<&'static str, &'static str>,
}

impl MultiFileWriter {
    fn get_writer(&self, key: &str) -> tracing_appender::non_blocking::NonBlocking {
        if let Some(writer) = WRITER_CACHE.get(key) {
            return writer.clone();
        }

        fs::create_dir_all(&*self.log_dir).ok();

        let file_appender =
            tracing_appender::rolling::daily(&*self.log_dir, format!("{}.log", key));
        let (non_blocking, guard) = tracing_appender::non_blocking(file_appender);

        WRITER_CACHE.insert(key.to_string(), non_blocking.clone());
        GUARD_CACHE
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push(guard);

        non_blocking
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

        Box::new(self.get_writer(key))
    }

    fn make_writer(&'a self) -> Self::Writer {
        Box::new(self.get_writer("default"))
    }
}

pub fn init_logger(
    log_dir: &str,
    targets: DashMap<&'static str, &'static str>,
    log_levels: &[&str],
) {
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

    tracing_subscriber::fmt()
        .with_timer(timer)
        .with_writer(MultiFileWriter {
            log_dir: Arc::new(log_dir.to_string()),
            targets,
        })
        .with_env_filter(filter)
        .init();
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

    #[test]
    fn cli_modes_override_environment_only_when_requested() {
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
