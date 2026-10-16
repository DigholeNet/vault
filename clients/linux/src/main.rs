// SPDX-License-Identifier: MIT
//! Entry point; the client uses Linux-only mechanisms (/proc, `ip`,
//! resolv.conf), so other platforms get a stub main.

#[cfg(target_os = "linux")]
mod config;
#[cfg(target_os = "linux")]
mod edge;
#[cfg(target_os = "linux")]
mod interface;
#[cfg(target_os = "linux")]
mod runner;
#[cfg(target_os = "linux")]
mod storage;

#[cfg(target_os = "linux")]
fn main() -> anyhow::Result<()> {
    runner::run()
}

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("edge only runs on Linux");
    std::process::exit(1);
}
