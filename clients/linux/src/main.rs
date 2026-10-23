// SPDX-License-Identifier: MIT
//! Entry point; the client uses Linux-only mechanisms (/proc, `ip`,
//! resolv.conf), so other platforms get a stub main.

#[cfg(target_os = "linux")]
mod config;
#[cfg(any(target_os = "linux", test))]
mod dns;
#[cfg(target_os = "linux")]
mod edge;
#[cfg(any(target_os = "linux", test))]
mod interface;
#[cfg(any(target_os = "linux", test))]
mod routes;
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
