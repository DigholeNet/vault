// SPDX-License-Identifier: MIT
//! Entry point; the server needs TUN + epoll, so non-Linux platforms get a
//! stub main and `cargo check -p supernode` works everywhere.

#[cfg(target_os = "linux")]
mod imp {
    use crate::config::SuperNodeConfig;
    use crate::supernode::SuperNode;
    use dashmap::DashMap;
    use vault_core::{
        SystemTimeSource, app_main,
        logger::rolling::{LoggerGuard, cli_log_levels, init_logger},
    };

    pub fn run() -> anyhow::Result<()> {
        app_main::<SuperNodeConfig, _, _>("supernode", logger_init, |signal, config| {
            let node = SuperNode::<SystemTimeSource>::new(config, signal).inspect_err(|error| {
                tracing::error!("Supernode initialization failed: {error:#}");
            })?;
            node.run()
        })
    }

    fn logger_init(
        verbose: bool,
        quiet: bool,
        log_dir: Option<&String>,
    ) -> anyhow::Result<LoggerGuard> {
        let targets = DashMap::new();
        targets.insert("client", "client");
        targets.insert("metrics", "metrics");
        Ok(init_logger(
            log_dir.map_or("/var/log/vault/", |d| d),
            targets,
            cli_log_levels(verbose, quiet),
        ))
    }
}

#[cfg(any(target_os = "linux", test))]
mod config;
// Pure-logic modules also build under `cfg(test)` on any OS so their unit
// tests can run off-Linux; supernode.rs itself stays Linux-only.
#[cfg(any(target_os = "linux", test))]
mod error;
#[cfg(any(target_os = "linux", test))]
mod handshake;
#[cfg(any(target_os = "linux", test))]
mod ip;
#[cfg(any(target_os = "linux", test))]
mod limiter;
#[cfg(test)]
mod mock_time;
#[cfg(any(target_os = "linux", test))]
mod network;
#[cfg(target_os = "linux")]
mod supernode;

#[cfg(target_os = "linux")]
fn main() -> anyhow::Result<()> {
    imp::run()
}

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("supernode only runs on Linux");
    std::process::exit(1);
}
