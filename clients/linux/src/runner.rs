// SPDX-License-Identifier: MIT
use std::{
    net::{IpAddr, SocketAddr, ToSocketAddrs as _},
    path::Path,
    process::Command,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use dashmap::DashMap;
use tracing::{error, info, warn};
use vault_core::{
    PrivDropRequest, SysSignal, app_main,
    device::{Ipv4, Ipv6, TunTapDevice},
    logger::rolling::{cli_log_levels, init_logger},
    util,
};

use crate::config::EdgeConfig;
use crate::dns::DnsGuard;
use crate::edge::Edge;
use crate::interface::{self, FamilyExits};
use crate::routes::{RouteGuard, RouteState};

const RESOLV_CONF_PATH: &str = "/etc/resolv.conf";
/// Backup of the original resolv.conf on a tmpfs: survives a SIGKILL/OOM
/// crash so the next start can self-heal, yet is cleaned up by a reboot.
const RESOLV_CONF_BACKUP_PATH: &str = "/run/edge/resolv.conf.backup";

pub fn run() -> anyhow::Result<()> {
    app_main::<EdgeConfig, _, _>("edge", logger_init, |signal, config, privdrop| {
        // Log errors explicitly: in daemon mode stderr is /dev/null, so an
        // error returned from here would otherwise be lost.
        if let Err(e) = run_inner(signal, config, privdrop) {
            error!("edge exited with error: {:#}", e);
            return Err(e);
        }
        Ok(())
    })
}

fn run_inner(
    signal: Arc<SysSignal>,
    config: EdgeConfig,
    privdrop: PrivDropRequest,
) -> anyhow::Result<()> {
    // Recover before DNS lookup: the previous process may have left DNS
    // pointing into a tunnel that no longer exists.
    DnsGuard::restore_backup(
        Path::new(RESOLV_CONF_PATH),
        Path::new(RESOLV_CONF_BACKUP_PATH),
    )?;
    let server_addr = format!("{}:{}", config.get_host(), config.get_port());
    info!("Resolving server address: {}", server_addr);
    let hosts: Vec<_> = server_addr.to_socket_addrs()?.collect();
    if hosts.is_empty() {
        return Err(anyhow::anyhow!("Could not resolve server address"));
    }
    let tun = config.get_iface().to_string();
    // Probe each address family's physical exit independently: IPv4 and
    // IPv6 default routes may live on different interfaces with different
    // gateways. A family without a default route contributes no exit; its
    // candidates simply lose the core's handshake race.
    let physical_exits = Arc::new(Mutex::new(probe_exits(&hosts, &tun)?));
    let mut dns = DnsGuard::setup_for_interface(
        Path::new(RESOLV_CONF_PATH),
        Path::new(RESOLV_CONF_BACKUP_PATH),
        config.get_dns(),
        &tun,
    )?;
    let routes = RouteGuard::new(
        config.get_iface(),
        hosts.iter().map(|addr| addr.ip()).collect(),
    );
    let route_state = routes.shared();
    // The server must bypass the VPN before the first handshake, and after
    // every exit change, rather than waiting for on_ip_assigned.
    {
        let exits = physical_exits.lock().unwrap();
        set_server_routes(&exits, &mut route_state.lock().unwrap())?;
    }
    let assignment_routes = route_state.clone();

    let mut edge = Edge::new(
        config,
        physical_exits.clone(),
        hosts.clone(),
        move |exits, device, _, ipv4, ipv6| {
            let mut routes = assignment_routes
                .lock()
                .map_err(|_| anyhow::anyhow!("route state lock poisoned"))?;
            if let Err(e) = on_ip_assigned(exits, device, ipv4, ipv6, &mut routes) {
                if let Err(rollback) = routes.restore() {
                    return Err(e.context(format!("route rollback also failed: {rollback:#}")));
                }
                return Err(e);
            }
            Ok(())
        },
    )?;

    // TUN creation is complete; retain network capabilities for the async
    // assignment callback and cleanup, and drop privileges before entering
    // the wait loop. The exit-time route/DNS rollback below relies on the
    // retained capabilities.
    privdrop.apply()?;

    // Wait for the quit signal; log traffic stats periodically. The
    // session reconnects itself with exponential backoff on failures.
    let mut last_stats = Instant::now();
    let mut last_network_check = Instant::now();
    let mut network_available = true;
    while !signal.is_exited() {
        std::thread::sleep(Duration::from_millis(500));
        if let Some(error) = edge.configuration_error() {
            anyhow::bail!("VPN network configuration failed: {}", error);
        }
        // Reuse the runner instead of adding a netlink thread/dependency.
        // A two-second snapshot naturally coalesces network event bursts.
        if last_network_check.elapsed() >= Duration::from_secs(2) {
            last_network_check = Instant::now();
            match probe_exits(&hosts, &tun) {
                Ok(current) => {
                    let mut previous = physical_exits
                        .lock()
                        .map_err(|_| anyhow::anyhow!("exits lock poisoned"))?;
                    if !network_available || *previous != current {
                        let result = set_server_routes(
                            &current,
                            &mut *route_state
                                .lock()
                                .map_err(|_| anyhow::anyhow!("route state lock poisoned"))?,
                        );
                        match result {
                            Ok(()) => {
                                info!(
                                    "Physical exit restored/changed: {:?} -> {:?}",
                                    *previous, current
                                );
                                *previous = current;
                                network_available = true;
                                edge.reconnect()?;
                            }
                            Err(e) => {
                                if network_available {
                                    warn!("Could not update server route: {e:#}");
                                }
                                network_available = false;
                            }
                        }
                    }
                }
                Err(e) => {
                    if network_available {
                        info!("Waiting for physical network: {e:#}");
                    }
                    network_available = false;
                }
            }
            // DHCP/NetworkManager may publish DNS after the path event or
            // handshake. Keep checking while active so that ordering does
            // not leave the restored tunnel using the physical network DNS.
            if network_available && edge.is_active() {
                match dns.ensure_applied() {
                    Ok(true) => info!("VPN DNS configuration restored after external change"),
                    Ok(false) => {}
                    Err(e) => warn!("Could not restore VPN DNS configuration: {e:#}"),
                }
            }
        }
        if last_stats.elapsed() >= Duration::from_secs(10) {
            let s = edge.traffic_stats();
            info!(
                "Traffic: active={} sent={}B ({}B/s) recv={}B ({}B/s) pkts={}/{}",
                edge.is_active(),
                s.bytes_sent,
                s.send_speed,
                s.bytes_received,
                s.receive_speed,
                s.packets_sent,
                s.packets_received
            );
            last_stats = Instant::now();
        }
    }

    edge.shutdown();
    drop(edge);
    routes.restore()?;
    dns.restore()?;
    Ok(())
}

fn required_command(program: &str, args: &[&str]) -> anyhow::Result<()> {
    let output = Command::new(program).args(args).output()?;
    anyhow::ensure!(
        output.status.success(),
        "{} {} failed ({}): {}",
        program,
        args.join(" "),
        output.status,
        String::from_utf8_lossy(&output.stderr).trim()
    );
    Ok(())
}

/// Probe the physical default route once per address family present in
/// `hosts`; the server IP itself is only used to pick the family. A
/// family without a usable route contributes no exit — its candidates
/// simply lose the core's handshake race. Only when no family at all
/// resolves is the network considered down.
fn probe_exits(hosts: &[SocketAddr], tun: &str) -> anyhow::Result<FamilyExits> {
    let mut exits = FamilyExits::default();
    let mut errors = Vec::new();
    for server in hosts {
        let slot = if server.is_ipv6() {
            &mut exits.v6
        } else {
            &mut exits.v4
        };
        if slot.is_some() {
            continue;
        }
        match interface::get_default_physical_interface(server.ip(), tun) {
            Ok(found) => *slot = Some(found),
            Err(e) => errors.push(format!("{e:#}")),
        }
    }
    anyhow::ensure!(
        exits.v4.is_some() || exits.v6.is_some(),
        "no physical default route: {}",
        errors.join("; ")
    );
    Ok(exits)
}

fn set_server_routes(exits: &FamilyExits, routes: &mut RouteState) -> anyhow::Result<()> {
    routes.set_hosts(
        exits
            .v4
            .as_ref()
            .map(|i| (i.name(), i.gateway_ipv4().map(IpAddr::V4))),
        exits
            .v6
            .as_ref()
            .map(|i| (i.name(), i.gateway_ipv6().map(IpAddr::V6))),
    )
}

fn on_ip_assigned(
    exits: &FamilyExits,
    device: &TunTapDevice,
    ipv4: Option<&Ipv4>,
    ipv6: Option<&Ipv6>,
    routes: &mut RouteState,
) -> anyhow::Result<()> {
    set_server_routes(exits, routes)?;
    info!("TUN device {} opened successfully", device.get_ifname());
    util::run_command("ip", &["route", "flush", "cache"]);

    if ipv4.is_some() {
        let key = format!("net.ipv4.conf.{}.rp_filter=0", device.get_ifname());
        required_command("sysctl", &["-w", &key])?;
    }
    routes.clear_tunnel_defaults()?;
    required_command("ip", &["addr", "flush", "dev", device.get_ifname()])?;
    device.set_ip(ipv4, ipv6)?;
    if let Some(ipv4) = ipv4 {
        routes.set_default(IpAddr::V4(ipv4.ip))?;
    }
    if let Some(ipv6) = ipv6 {
        routes.set_default(IpAddr::V6(ipv6.ip))?;
    }
    Ok(())
}

fn logger_init(verbose: bool, quiet: bool, log_dir: Option<&String>) -> anyhow::Result<()> {
    let targets = DashMap::new();
    init_logger(
        log_dir.map_or("/var/log/vault/", |d| d),
        targets,
        cli_log_levels(verbose, quiet),
    );

    Ok(())
}
