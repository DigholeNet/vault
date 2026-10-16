// SPDX-License-Identifier: MIT
use std::net::{IpAddr, SocketAddr};
use std::process;

use log::{debug, error};
#[cfg(not(target_os = "ios"))]
use pnet::datalink::NetworkInterface;

/// Name of the interface owning the default route. Returns an error
/// instead of panicking because hosts without a physical NIC (containers)
/// would otherwise crash at startup.
#[cfg(not(target_os = "ios"))]
pub fn default_interface() -> anyhow::Result<String> {
    get_default_physical_iface()
        .ok_or_else(|| anyhow::anyhow!("no running non-loopback network interface found"))
}

/// Run `program` with `args` directly (no shell), logging failures.
/// Returns true when the command ran and exited successfully. Arguments are
/// passed as an argv array so no shell injection is possible; used for
/// root-privileged network configuration.
pub fn run_command(program: &str, args: &[&str]) -> bool {
    run_command_inner(program, args, true)
}

/// Like [`run_command`], but a non-zero exit only logs at debug level. For
/// probes such as `iptables -C`, where failure just means "rule absent".
pub fn check_command(program: &str, args: &[&str]) -> bool {
    run_command_inner(program, args, false)
}

fn run_command_inner(program: &str, args: &[&str], log_failure: bool) -> bool {
    let mut cmd = process::Command::new(program);
    cmd.args(args);
    debug!("Running command: {:?}", cmd);
    match cmd.output() {
        Ok(output) if output.status.success() => true,
        Ok(output) => {
            let stderr = String::from_utf8_lossy(&output.stderr);
            if log_failure {
                error!(
                    "Command {:?} failed with {:?}: {}",
                    cmd,
                    output.status.code(),
                    stderr.trim()
                );
            } else {
                debug!(
                    "Command {:?} exited with {:?}: {}",
                    cmd,
                    output.status.code(),
                    stderr.trim()
                );
            }
            false
        }
        Err(e) => {
            error!("Failed to execute {:?}: {}", cmd, e);
            false
        }
    }
}

pub fn mapped_addr(addr: SocketAddr) -> SocketAddr {
    match addr {
        SocketAddr::V4(addr4) => {
            SocketAddr::new(IpAddr::V6(addr4.ip().to_ipv6_mapped()), addr4.port())
        }
        _ => addr,
    }
}

#[cfg(not(target_os = "ios"))]
fn get_default_physical_iface() -> Option<String> {
    // Prefer the interface owning the default route: the tunnel MTU is
    // derived from it, and picking any other running interface (docker0, a
    // jumbo-frame NIC) would yield a wrong MTU.
    if let Ok(routes) = std::fs::read_to_string("/proc/net/route") {
        for line in routes.lines().skip(1) {
            let mut fields = line.split_whitespace();
            let (Some(iface), Some(destination), _, Some(flags)) =
                (fields.next(), fields.next(), fields.next(), fields.next())
            else {
                continue;
            };
            // Default route (00000000) that is up (RTF_UP, 0x1).
            if destination == "00000000"
                && u32::from_str_radix(flags, 16).is_ok_and(|f| f & 0x1 != 0)
            {
                return Some(iface.to_string());
            }
        }
    }
    // No IPv4 default route (IPv6-only host, or /proc unavailable): fall
    // back to the first running non-loopback interface.
    let interfaces = pnet::datalink::interfaces();
    for interface in interfaces {
        if interface.is_running() && !interface.is_loopback() {
            return Some(interface.name);
        }
    }

    None
}

#[cfg(not(target_os = "ios"))]
pub fn get_iface(iface: &str) -> Option<NetworkInterface> {
    let interfaces = pnet::datalink::interfaces();
    interfaces
        .into_iter()
        .find(|interface| interface.name.eq(iface))
}
