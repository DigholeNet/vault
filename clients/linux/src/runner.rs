// SPDX-License-Identifier: MIT
use std::{
    io,
    net::{IpAddr, SocketAddr, ToSocketAddrs as _},
    os::{
        linux::net::SocketAddrExt,
        unix::net::{SocketAddr as UnixSocketAddr, UnixDatagram},
    },
    process::Command,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use anyhow::Context;
use dashmap::DashMap;
use tracing::{error, info, warn};
use vault_core::{
    SysSignal, app_main,
    device::{self, Ipv4, Ipv6, TunTapDevice},
    logger::rolling::{LoggerGuard, cli_log_levels, init_logger},
    util,
};

use crate::config::EdgeConfig;
use crate::dns::DnsGuard;
use crate::edge::Edge;
use crate::interface::{self, FamilyExits};
use crate::routes::{RouteGuard, RouteState};

/// Hold from before the first network mutation until all route/DNS cleanup ends.
/// The abstract socket name is local to the network namespace and disappears
/// when its last fd closes, including on SIGKILL. No messages are processed.
struct NetworkLock {
    _socket: UnixDatagram,
}

impl NetworkLock {
    fn acquire() -> anyhow::Result<Self> {
        Self::bind(b"vault.edge.routes")
    }

    fn bind(name: &[u8]) -> anyhow::Result<Self> {
        let address =
            UnixSocketAddr::from_abstract_name(name).context("create Edge lock address")?;
        let socket = UnixDatagram::bind_addr(&address).map_err(|error| {
            if error.kind() == io::ErrorKind::AddrInUse {
                anyhow::anyhow!("another process already owns the Edge network namespace lock")
            } else {
                anyhow::Error::new(error).context("bind Edge network namespace lock")
            }
        })?;
        Ok(Self { _socket: socket })
    }
}

pub fn run() -> anyhow::Result<()> {
    app_main::<EdgeConfig, _, _>("edge", logger_init, |signal, config| {
        // Log errors explicitly: in daemon mode stderr is /dev/null, so an
        // error returned from here would otherwise be lost.
        if let Err(e) = run_inner(signal, config) {
            error!("edge exited with error: {:#}", e);
            return Err(e);
        }
        Ok(())
    })
}

fn run_inner(signal: Arc<SysSignal>, config: EdgeConfig) -> anyhow::Result<()> {
    // Keep the netns lease until DNS/routes/TUN have all been cleaned up.
    // Unlike the control-file lock, this also covers private /run mounts.
    let _network_lock = NetworkLock::acquire()?;
    // Resolve name templates before configuring routes or DNS.
    let device = device::setup_device(config.get_iface(), &device::DeviceType::Tun)?;
    let tun = device.get_ifname().to_string();
    let dns = DnsGuard::setup_for_interface(&tun);
    let server_addr = format!("{}:{}", config.get_host(), config.get_port());
    info!("Resolving server address: {}", server_addr);
    let hosts: Vec<_> = server_addr.to_socket_addrs()?.collect();
    if hosts.is_empty() {
        return Err(anyhow::anyhow!("Could not resolve server address"));
    }
    // Probe each address family's physical exit independently: IPv4 and
    // IPv6 default routes may live on different interfaces with different
    // gateways. A family without a default route contributes no exit; its
    // candidates simply lose the core's handshake race.
    let physical_exits = Arc::new(Mutex::new(probe_exits(&hosts, &tun)?));
    // DNS is selected only after the handshake assigns tunnel addresses.
    let dns_v4 = config.dns_for(true, false);
    let dns_v6 = config.dns_for(false, true);
    let dns_dual = config.dns_for(true, true);
    let assigned_dns = Arc::new(Mutex::new(None::<Vec<String>>));
    let assignment_dns = assigned_dns.clone();
    let routes = RouteGuard::new(&tun, hosts.iter().map(|addr| addr.ip()).collect());
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
        device,
        physical_exits.clone(),
        hosts.clone(),
        move |exits, device, _, ipv4, ipv6| {
            // Serialize assignment routes with DNS application. A poll must not
            // apply an old list after a newer assignment changed the routes.
            let mut selected = assignment_dns
                .lock()
                .map_err(|_| anyhow::anyhow!("DNS state lock poisoned"))?;
            let mut routes = assignment_routes
                .lock()
                .map_err(|_| anyhow::anyhow!("route state lock poisoned"))?;
            if let Err(e) = on_ip_assigned(exits, device, ipv4, ipv6, &mut routes) {
                if let Err(rollback) = routes.restore() {
                    return Err(e.context(format!("route rollback also failed: {rollback:#}")));
                }
                return Err(e);
            }
            let servers = match (ipv4.is_some(), ipv6.is_some()) {
                (true, true) => &dns_dual,
                (true, false) => &dns_v4,
                (false, true) => &dns_v6,
                (false, false) => anyhow::bail!("no tunnel address assigned"),
            };
            *selected = Some(servers.clone());
            Ok(())
        },
    )?;

    // Drop DNS before Edge removes the TUN, including on early returns.
    let mut dns = dns;

    // Wait for the quit signal; log traffic stats periodically. The
    // session reconnects itself with exponential backoff on failures.
    let mut last_stats = Instant::now();
    let mut last_network_check = Instant::now();
    let mut network_available = true;
    let mut last_route_error = None;
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
                                last_route_error = None;
                                edge.reconnect()?;
                            }
                            Err(e) => {
                                // A conflict may first appear after an offline
                                // period. Report it even when availability was
                                // already false, without repeating every poll.
                                let message = format!("{e:#}");
                                if last_route_error.as_ref() != Some(&message) {
                                    warn!("Could not update server route: {message}");
                                    last_route_error = Some(message);
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
            // Reapply this link's DNS if resolved loses it during reconnect.
            if network_available && edge.is_active() {
                let servers = assigned_dns
                    .lock()
                    .map_err(|_| anyhow::anyhow!("DNS state lock poisoned"))?;
                match servers
                    .as_ref()
                    .map_or(Ok(false), |servers| update_dns(&mut dns, servers))
                {
                    Ok(true) => info!("VPN interface DNS configuration applied"),
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
    dns.restore()?;
    drop(edge);
    routes.restore()?;
    Ok(())
}

fn update_dns(dns: &mut DnsGuard, servers: &[String]) -> anyhow::Result<bool> {
    dns.set_servers(servers)?;
    dns.ensure_applied()
}

fn required_command(program: &str, args: &[&str]) -> anyhow::Result<()> {
    util::checked_output(Command::new(program).args(args))?;
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
        // Loose validation accommodates asymmetric VPN routing. Linux uses
        // max(all, interface), so 0 would still be strict on hosts with all=1.
        // Change only our exclusively created TUN; slash notation also handles
        // interface names containing dots.
        let key = format!("net/ipv4/conf/{}/rp_filter=2", device.get_ifname());
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

fn logger_init(
    verbose: bool,
    quiet: bool,
    log_dir: Option<&String>,
) -> anyhow::Result<LoggerGuard> {
    let targets = DashMap::new();
    targets.insert("metrics", "metrics");
    Ok(init_logger(
        log_dir.map_or("/var/log/vault/", |d| d),
        targets,
        cli_log_levels(verbose, quiet),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{BufRead, BufReader, Read, Write};
    use std::path::Path;
    use std::process::Stdio;
    use vault_core::device::{DeviceType, setup_device};

    #[test]
    fn lock_busy() {
        // Ordinary unit tests never occupy the production lock name.
        let name = format!("vault.edge.busy.{}", std::process::id());
        let owner = NetworkLock::bind(name.as_bytes()).unwrap();
        let error = NetworkLock::bind(name.as_bytes()).err().unwrap();
        assert!(error.to_string().contains("already owns"));
        drop(owner);
        assert!(NetworkLock::bind(name.as_bytes()).is_ok());
    }

    #[test]
    fn lock_child() {
        let Ok(name) = std::env::var("VAULT_EDGE_LOCK_CHILD") else {
            return;
        };
        let _owner = NetworkLock::bind(name.as_bytes()).unwrap();
        println!("\nREADY");
        std::io::stdout().flush().unwrap();
        // Dropping the parent's stdin also ends the child after a test failure.
        let _ = std::io::stdin().read_exact(&mut [0]);
    }

    #[test]
    fn lock_killed() {
        let name = format!("vault.edge.killed.{}", std::process::id());
        let mut child = Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "runner::tests::lock_child", "--nocapture"])
            .env("VAULT_EDGE_LOCK_CHILD", &name)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .unwrap();
        let mut output = BufReader::new(child.stdout.take().unwrap());
        loop {
            let mut line = String::new();
            assert!(
                output.read_line(&mut line).unwrap() > 0,
                "lock child exited"
            );
            if line.trim() == "READY" {
                break;
            }
        }
        child.stdout = Some(output.into_inner());
        assert!(NetworkLock::bind(name.as_bytes()).is_err());
        child.kill().unwrap();
        use std::os::unix::process::ExitStatusExt;
        // Child::kill sends SIGKILL (9) on Linux.
        assert_eq!(child.wait().unwrap().signal(), Some(9));
        assert!(NetworkLock::bind(name.as_bytes()).is_ok());
    }

    #[test]
    #[ignore = "requires disposable Linux namespaces and CAP_SYS_ADMIN"]
    fn netns_lock() {
        assert_eq!(
            std::env::var("VAULT_EDGE_LOCK_TEST_NAMESPACE").as_deref(),
            Ok("1")
        );
        assert_ne!(
            std::fs::read_link("/proc/self/ns/net").unwrap(),
            std::fs::read_link("/proc/1/ns/net").unwrap()
        );
        match std::env::var("VAULT_EDGE_LOCK_TEST_MODE").as_deref() {
            Ok("busy") => {
                let error = NetworkLock::acquire().err().unwrap();
                assert!(error.to_string().contains("already owns"));
                return;
            }
            Ok("free") => {
                let _owner = NetworkLock::acquire().unwrap();
                return;
            }
            _ => {}
        }

        let _owner = NetworkLock::acquire().unwrap();
        let executable = std::env::current_exe().unwrap();
        let args = ["--exact", "runner::tests::netns_lock", "--ignored"];
        // A separate mount namespace with a fresh /run must not bypass the
        // lock. Make mounts private before mounting so nothing reaches the host.
        let status = Command::new("unshare")
            .args([
                "--mount",
                "--propagation",
                "private",
                "--",
                "sh",
                "-c",
                "mount -t tmpfs tmpfs /run && exec \"$@\"",
                "_",
            ])
            .arg(&executable)
            .args(args)
            .env("VAULT_EDGE_LOCK_TEST_MODE", "busy")
            .status()
            .unwrap();
        assert!(status.success());

        // A genuinely separate network namespace has separate routes and lock.
        let status = Command::new("unshare")
            .args(["--net", "--"])
            .arg(&executable)
            .args(args)
            .env("VAULT_EDGE_LOCK_TEST_MODE", "free")
            .status()
            .unwrap();
        assert!(status.success());
    }

    #[test]
    #[ignore = "requires a fresh Linux network namespace; run scripts/test-network-namespace.sh"]
    fn rpf_policy() {
        assert_eq!(
            std::env::var("VAULT_NETWORK_TEST_NAMESPACE").as_deref(),
            Ok("1")
        );
        assert_ne!(
            std::fs::read_link("/proc/self/ns/net").unwrap(),
            std::fs::read_link("/proc/1/ns/net").unwrap()
        );
        fn rpf(interface: &str) -> String {
            std::fs::read_to_string(format!("/proc/sys/net/ipv4/conf/{interface}/rp_filter"))
                .unwrap()
        }
        required_command("ip", &["link", "set", "lo", "up"]).unwrap();
        required_command("ip", &["link", "add", "vault-exit", "type", "dummy"]).unwrap();
        required_command("ip", &["link", "set", "vault-exit", "up"]).unwrap();
        required_command("ip", &["route", "add", "default", "dev", "vault-exit"]).unwrap();
        required_command(
            "sysctl",
            &[
                "-w",
                "net/ipv4/conf/default/rp_filter=1",
                "net/ipv4/conf/vault-exit/rp_filter=0",
            ],
        )
        .unwrap();
        let host_values = || ["all", "default", "vault-exit"].map(rpf);
        let ipv4 = Ipv4 {
            ip: "10.70.0.2".parse().unwrap(),
            netmask: "255.255.255.0".parse().unwrap(),
        };
        let ipv6 = Ipv6 {
            ip: "fd70::2".parse().unwrap(),
            prefix_len: 64,
        };
        for global in 0..=2 {
            required_command(
                "sysctl",
                &["-w", &format!("net/ipv4/conf/all/rp_filter={global}")],
            )
            .unwrap();
            for v4 in [true, false] {
                let before = host_values();
                // Exercise a dotted template name and inherited strict RPF.
                let device = setup_device("vault.test%d", &DeviceType::Tun).unwrap();
                let tun = device.get_ifname().to_string();
                assert!(!tun.contains('%'));
                assert_eq!(rpf(device.get_ifname()).trim(), "1");
                let routes = RouteGuard::new(device.get_ifname(), vec![]);
                on_ip_assigned(
                    &FamilyExits::default(),
                    &device,
                    v4.then_some(&ipv4),
                    (!v4).then_some(&ipv6),
                    &mut routes.shared().lock().unwrap(),
                )
                .unwrap();
                assert_eq!(rpf(device.get_ifname()).trim(), if v4 { "2" } else { "1" });
                assert_eq!(host_values(), before);
                routes.restore().unwrap();
                drop(routes);
                drop(device);
                // /proc follows this network namespace; an inherited sysfs
                // mount can still show the host namespace's interfaces.
                let local_rpf = format!("/proc/sys/net/ipv4/conf/{tun}/rp_filter");
                let deadline = Instant::now() + Duration::from_secs(2);
                while Path::new(&local_rpf).exists() {
                    assert!(Instant::now() < deadline, "owned TUN survived fd close");
                    std::thread::sleep(Duration::from_millis(20));
                }
                assert_eq!(host_values(), before);
            }
        }
    }
}
