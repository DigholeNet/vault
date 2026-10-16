// SPDX-License-Identifier: MIT
use std::{
    fs::OpenOptions,
    io::Write as _,
    net::{IpAddr, SocketAddr, ToSocketAddrs as _},
    process::Command,
    sync::Arc,
    time::{Duration, Instant},
};

use dashmap::DashMap;
use tracing::{error, info, warn};
use vault_core::{
    PrivDropRequest, SysSignal, app_main,
    device::{Ipv4, Ipv6, TunTapDevice},
    logger::init_logger,
    util,
};

use crate::config::EdgeConfig;
use crate::edge::Edge;
use crate::interface::{self, Interface};

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
    let server_addr = format!("{}:{}", config.get_host(), config.get_port());
    info!("Resolving server address: {}", server_addr);
    let server_addrs: Vec<_> = server_addr.to_socket_addrs()?.collect();
    if server_addrs.is_empty() {
        return Err(anyhow::anyhow!("Could not resolve server address"));
    }
    let super_node = server_addrs[0];
    let routes = get_default_routes();

    // Self-heal first: a previous run killed before rollback (SIGKILL, OOM)
    // leaves its resolv.conf backup behind.
    restore_resolv_conf_backup();

    let resolv_conf = setup_dns(config.get_dns())?;

    let mut edge = Edge::new(
        config,
        interface::get_default_physical_interface()?,
        super_node,
        on_ip_assigned,
        on_rollback,
    )?;

    // TUN device, routes and DNS are set up; drop privileges before entering
    // the wait loop. The exit-time route/DNS rollback below relies on the
    // retained capabilities.
    privdrop.apply()?;

    // Wait for the quit signal; log traffic stats periodically. The
    // session reconnects itself with exponential backoff on failures.
    let mut last_stats = Instant::now();
    while !signal.is_exited() {
        std::thread::sleep(Duration::from_millis(500));
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

    if let Ok((v4, v6)) = routes {
        for s in v4 {
            info!("Adding backup route: {}", s);
            let mut args = vec!["route", "add"];
            args.extend(s.split_whitespace());
            util::run_command("ip", &args);
        }

        for s in v6 {
            info!("Adding backup route: {}", s);
            let mut args = vec!["-6", "route", "add"];
            args.extend(s.split_whitespace());
            util::run_command("ip", &args);
        }
    }

    rollback_dns(&resolv_conf)?;
    Ok(())
}

fn on_ip_assigned(
    interface: &Interface,
    device: &TunTapDevice,
    super_node: &SocketAddr,
    ipv4: Option<&Ipv4>,
    ipv6: Option<&Ipv6>,
) -> anyhow::Result<()> {
    setup_route(super_node, interface);

    info!("TUN device {} opened successfully", device.get_ifname());

    info!("Flushing route cache");
    util::run_command("ip", &["route", "flush", "cache"]);

    // Disable rp_filter on the TUN interface only; other host interfaces
    // keep their source-address validation. No rollback needed: the setting
    // dies with the interface when the TUN fd closes.
    let rp_filter_key = format!("net.ipv4.conf.{}.rp_filter=0", device.get_ifname());
    util::run_command("sysctl", &["-w", &rp_filter_key]);

    // Remove addresses left over from a previous assignment before applying
    // the new one: IPv4 SIOCSIFADDR replaces the primary address, but IPv6
    // *adds* — after a supernode restart assigns a different IPv6, the stale
    // one would linger and the kernel might pick it as the source, which the
    // supernode then drops as spoofed.
    util::run_command("ip", &["addr", "flush", "dev", device.get_ifname()]);

    device.set_ip(ipv4, ipv6)?;
    add_vpn_default_route(device.get_ifname(), ipv4, ipv6)?;

    Ok(())
}

fn add_vpn_default_route(
    interface_name: &str,
    ipv4: Option<&Ipv4>,
    ipv6: Option<&Ipv6>,
) -> anyhow::Result<()> {
    // Idempotent: on_ip_assigned fires on every reconnect.
    if let Some(ipv4) = ipv4 {
        let source = ipv4.ip.to_string();
        info!(
            "Adding VPN ipv4 default route via {} with source {}",
            interface_name, source
        );
        if util::run_command(
            "ip",
            &[
                "route",
                "replace",
                "default",
                "dev",
                interface_name,
                "metric",
                "1",
                "src",
                &source,
            ],
        ) {
            info!("VPN ipv4 default route added successfully with metric 1");
        }
    }
    if let Some(ipv6) = ipv6 {
        let source = ipv6.ip.to_string();
        info!(
            "Adding VPN ipv6 default route via {} with source {}",
            interface_name, source
        );
        if util::run_command(
            "ip",
            &[
                "-6",
                "route",
                "replace",
                "default",
                "dev",
                interface_name,
                "metric",
                "1",
                "src",
                &source,
            ],
        ) {
            info!("VPN ipv6 default route added successfully with metric 1");
        }
    }

    Ok(())
}

fn setup_route(super_node: &SocketAddr, physical_iface: &Interface) {
    match super_node.ip() {
        IpAddr::V4(ipv4) => {
            if let Some(gateway) = physical_iface.gateway_ipv4() {
                let host = format!("{}/32", ipv4);
                let gateway = gateway.to_string();
                util::run_command(
                    "ip",
                    &[
                        "route",
                        "replace",
                        &host,
                        "via",
                        &gateway,
                        "dev",
                        physical_iface.name(),
                    ],
                );
            }
        }
        IpAddr::V6(ipv6) => {
            if let Some(gateway) = physical_iface.gateway_ipv6() {
                let host = format!("{}/128", ipv6);
                let gateway = gateway.to_string();
                util::run_command(
                    "ip",
                    &[
                        "-6",
                        "route",
                        "replace",
                        &host,
                        "via",
                        &gateway,
                        "dev",
                        physical_iface.name(),
                    ],
                );
            }
        }
    }
}

fn get_default_routes() -> anyhow::Result<(Vec<String>, Vec<String>)> {
    let mut ipv4_routes = vec![];
    let mut ipv6_routes = vec![];

    {
        let output = Command::new("ip")
            .arg("route")
            .arg("show")
            .arg("default")
            .output()?;
        if output.status.success() {
            let stdout = String::from_utf8(output.stdout)?;
            for line in stdout.lines() {
                ipv4_routes.push(line.to_string());
            }
        }
    }

    {
        let output = Command::new("ip")
            .arg("-6")
            .arg("route")
            .arg("show")
            .arg("default")
            .output()?;
        if !output.status.success() {
            return Ok((ipv4_routes, ipv6_routes));
        }
        let stdout = String::from_utf8(output.stdout)?;
        for line in stdout.lines() {
            ipv6_routes.push(line.to_string());
        }
    }

    Ok((ipv4_routes, ipv6_routes))
}

fn on_rollback(interface: &Interface, super_node: &SocketAddr) -> anyhow::Result<()> {
    info!("Rollback route");
    match super_node.ip() {
        IpAddr::V4(ipv4) => {
            if let Some(gateway) = interface.gateway_ipv4() {
                let host = format!("{}/32", ipv4);
                let gateway = gateway.to_string();
                util::run_command("ip", &["route", "del", &host, "via", &gateway]);
            }
        }
        IpAddr::V6(ipv6) => {
            if let Some(gateway) = interface.gateway_ipv6() {
                let host = format!("{}/128", ipv6);
                let gateway = gateway.to_string();
                util::run_command("ip", &["-6", "route", "del", &host, "via", &gateway]);
            }
        }
    }

    Ok(())
}

/// Restore /etc/resolv.conf from a leftover backup of a crashed run.
/// Best-effort: a failure is logged, never fatal.
fn restore_resolv_conf_backup() {
    let backup = match std::fs::read_to_string(RESOLV_CONF_BACKUP_PATH) {
        Ok(c) => c,
        Err(_) => return,
    };
    warn!("Found resolv.conf backup from a crashed run, restoring");
    if let Err(e) = std::fs::write(RESOLV_CONF_PATH, backup) {
        error!("Failed to restore {}: {}", RESOLV_CONF_PATH, e);
    }
    let _ = std::fs::remove_file(RESOLV_CONF_BACKUP_PATH);
}

fn setup_dns(dns_servers: &[String]) -> anyhow::Result<String> {
    let resolv_conf = std::fs::read_to_string(RESOLV_CONF_PATH)?;

    if dns_servers.is_empty() {
        return Ok(resolv_conf);
    }

    // Refuse to write system configuration with values that cannot possibly
    // be valid.
    for dns_server in dns_servers {
        dns_server
            .parse::<IpAddr>()
            .map_err(|_| anyhow::anyhow!("invalid DNS server address: {}", dns_server))?;
    }

    // Persist the backup before touching the live file: if the process is
    // killed before rollback, the next start restores from it.
    if let Some(dir) = std::path::Path::new(RESOLV_CONF_BACKUP_PATH).parent() {
        std::fs::create_dir_all(dir)?;
    }
    std::fs::write(RESOLV_CONF_BACKUP_PATH, &resolv_conf)?;

    let mut output = OpenOptions::new()
        .write(true)
        .truncate(true)
        .open(RESOLV_CONF_PATH)?;
    writeln!(&mut output, "search .")?;
    for dns_server in dns_servers {
        writeln!(&mut output, "nameserver {}", dns_server)?;
    }
    Ok(resolv_conf)
}

fn rollback_dns(resolv_conf: &str) -> anyhow::Result<()> {
    info!("Rollback dns");
    let mut output = OpenOptions::new()
        .write(true)
        .truncate(true)
        .open(RESOLV_CONF_PATH)?;
    writeln!(&mut output, "{}", resolv_conf)?;
    // Rollback done; the backup must not trigger a bogus restore on the
    // next start.
    let _ = std::fs::remove_file(RESOLV_CONF_BACKUP_PATH);
    Ok(())
}

fn logger_init(_verbose: bool, _quiet: bool, log_dir: Option<&String>) -> anyhow::Result<()> {
    let targets = DashMap::new();
    init_logger(log_dir.map_or("/var/log/vault/", |d| d), targets, &[]);

    Ok(())
}
