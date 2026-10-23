// SPDX-License-Identifier: MIT
//! Own only routes changed by this connection, including partial setup.

use std::net::IpAddr;
#[cfg(target_os = "linux")]
use std::process::Command;
use std::sync::{Arc, Mutex};

#[cfg(target_os = "linux")]
use anyhow::Context;

trait IpCommand: Send {
    fn run(&mut self, args: &[String]) -> anyhow::Result<String>;
}

#[cfg(target_os = "linux")]
struct SystemIp;
#[cfg(target_os = "linux")]
impl IpCommand for SystemIp {
    fn run(&mut self, args: &[String]) -> anyhow::Result<String> {
        let output = Command::new("ip")
            .args(args)
            .output()
            .context("execute ip")?;
        anyhow::ensure!(
            output.status.success(),
            "ip {} failed ({}): {}",
            args.join(" "),
            output.status,
            String::from_utf8_lossy(&output.stderr).trim()
        );
        Ok(String::from_utf8(output.stdout)?)
    }
}

/// Exact attributes of a route added by this connection. Kernel decorations
/// such as `scope link` and IPv6 `pref medium` are not ownership attributes.
#[derive(Clone, PartialEq, Eq)]
struct OwnedRoute {
    ipv6: bool,
    prefix: String,
    interface: String,
    gateway: Option<IpAddr>,
    source: Option<IpAddr>,
}

impl OwnedRoute {
    fn args(&self, operation: &str) -> Vec<String> {
        let mut args = vec![
            "route".into(),
            operation.into(),
            self.prefix.clone(),
            "dev".into(),
            self.interface.clone(),
        ];
        if let Some(gateway) = self.gateway {
            args.extend(["via".into(), gateway.to_string()]);
        }
        if let Some(source) = self.source {
            args.extend(["src".into(), source.to_string()]);
        }
        args.extend(["metric".into(), "1".into(), "proto".into(), "static".into()]);
        args
    }

    fn matches(&self, line: &str) -> bool {
        let words: Vec<_> = line.split_whitespace().collect();
        let field = |key| {
            words
                .windows(2)
                .find(|pair| pair[0] == key)
                .map(|pair| pair[1])
        };
        let prefix_matches = words.first().is_some_and(|prefix| {
            if self.prefix == "default" {
                return *prefix == "default";
            }
            prefix
                .split('/')
                .next()
                .and_then(|ip| ip.parse::<IpAddr>().ok())
                == self
                    .prefix
                    .split('/')
                    .next()
                    .and_then(|ip| ip.parse::<IpAddr>().ok())
        });
        prefix_matches
            && field("dev") == Some(self.interface.as_str())
            && field("via").and_then(|ip| ip.parse().ok()) == self.gateway
            && field("src").and_then(|ip| ip.parse().ok()) == self.source
            && field("metric") == Some("1")
            && field("proto") == Some("static")
    }
}

pub struct RouteState {
    command: Box<dyn IpCommand>,
    tun: String,
    servers: Vec<IpAddr>,
    installed: Vec<OwnedRoute>,
}

pub struct RouteGuard {
    state: Arc<Mutex<RouteState>>,
}

impl RouteGuard {
    #[cfg(target_os = "linux")]
    pub fn new(tun: &str, servers: Vec<IpAddr>) -> Self {
        Self::with_command(tun, servers, Box::new(SystemIp))
    }

    fn with_command(tun: &str, servers: Vec<IpAddr>, command: Box<dyn IpCommand>) -> Self {
        Self {
            state: Arc::new(Mutex::new(RouteState {
                command,
                tun: tun.into(),
                servers,
                installed: Vec::new(),
            })),
        }
    }

    pub fn shared(&self) -> Arc<Mutex<RouteState>> {
        self.state.clone()
    }

    pub fn restore(&self) -> anyhow::Result<()> {
        self.state
            .lock()
            .map_err(|_| anyhow::anyhow!("route state lock poisoned"))?
            .restore()
    }
}

impl Drop for RouteGuard {
    fn drop(&mut self) {
        if let Err(e) = self.restore() {
            tracing::error!("Route cleanup failed: {e:#}");
        }
    }
}

impl RouteState {
    fn run(&mut self, ipv6: bool, mut args: Vec<String>) -> anyhow::Result<String> {
        if ipv6 {
            args.insert(0, "-6".into());
        }
        self.command.run(&args)
    }

    fn is_present(&mut self, route: &OwnedRoute) -> anyhow::Result<bool> {
        let output = self.run(
            route.ipv6,
            vec![
                "route".into(),
                "show".into(),
                "exact".into(),
                route.prefix.clone(),
            ],
        )?;
        Ok(output.lines().any(|line| route.matches(line)))
    }

    fn remove_owned(&mut self, index: usize) -> anyhow::Result<()> {
        let route = self.installed[index].clone();
        if self.is_present(&route)? {
            self.run(route.ipv6, route.args("del"))?;
        }
        // An externally removed/replaced route is no longer ours to undo.
        self.installed.remove(index);
        Ok(())
    }

    fn install(&mut self, route: OwnedRoute) -> anyhow::Result<()> {
        if let Some(index) = self
            .installed
            .iter()
            .position(|old| old.ipv6 == route.ipv6 && old.prefix == route.prefix)
        {
            if self.installed[index] == route && self.is_present(&route)? {
                return Ok(());
            }
            self.remove_owned(index)?;
        }
        // A previous process may have left the same host route behind. Reuse
        // it without claiming ownership: cleanup must leave borrowed routes.
        if self.is_present(&route)? {
            return Ok(());
        }
        // `add` fails on conflict instead of overwriting another owner's route.
        // Record only successful changes, so partial failures need no snapshots.
        self.run(route.ipv6, route.args("add"))?;
        self.installed.push(route);
        Ok(())
    }

    /// Install one host route per server candidate, choosing the interface
    /// and gateway by address family, so every raced handshake address
    /// bypasses the tunnel. A family whose physical exit is gone (None)
    /// gets its owned host routes removed instead of keeping a stale
    /// gateway.
    pub fn set_hosts(
        &mut self,
        v4: Option<(&str, Option<IpAddr>)>,
        v6: Option<(&str, Option<IpAddr>)>,
    ) -> anyhow::Result<()> {
        for server in self.servers.clone() {
            let ipv6 = server.is_ipv6();
            let prefix = format!("{}/{}", server, if ipv6 { 128 } else { 32 });
            match if ipv6 { v6 } else { v4 } {
                Some((interface, gateway)) => self.install(OwnedRoute {
                    ipv6,
                    prefix,
                    interface: interface.into(),
                    gateway,
                    source: None,
                })?,
                None => {
                    if let Some(index) = self
                        .installed
                        .iter()
                        .position(|route| route.ipv6 == ipv6 && route.prefix == prefix)
                    {
                        self.remove_owned(index)?;
                    }
                }
            }
        }
        Ok(())
    }

    pub fn set_default(&mut self, source: IpAddr) -> anyhow::Result<()> {
        self.install(OwnedRoute {
            ipv6: source.is_ipv6(),
            prefix: "default".into(),
            interface: self.tun.clone(),
            gateway: None,
            source: Some(source),
        })
    }

    /// Remove our defaults before flushing TUN addresses. In particular,
    /// IPv6 address deletion can clear a route's preferred source without
    /// deleting the route, so it would no longer match our ownership record.
    /// Keep the server host route in place for the ongoing handshake.
    pub fn clear_tunnel_defaults(&mut self) -> anyhow::Result<()> {
        for index in (0..self.installed.len()).rev() {
            if self.installed[index].prefix == "default"
                && self.installed[index].interface == self.tun
            {
                self.remove_owned(index)?;
            }
        }
        // A reused/stale default is not in `installed`. The TUN is owned by
        // this edge instance; clear only defaults with edge's exact static
        // metric and no gateway, including those whose src was already lost.
        // Physical defaults and borrowed server host routes remain untouched.
        for ipv6 in [false, true] {
            let output = self.run(
                ipv6,
                vec![
                    "route".into(),
                    "show".into(),
                    "exact".into(),
                    "default".into(),
                ],
            )?;
            for line in output.lines() {
                let words: Vec<_> = line.split_whitespace().collect();
                let source = words
                    .windows(2)
                    .find(|pair| pair[0] == "src")
                    .map(|pair| pair[1].parse::<IpAddr>())
                    .transpose()?;
                let route = OwnedRoute {
                    ipv6,
                    prefix: "default".into(),
                    interface: self.tun.clone(),
                    gateway: None,
                    source,
                };
                if route.matches(line) {
                    self.run(ipv6, route.args("del"))?;
                }
            }
        }
        Ok(())
    }

    pub fn restore(&mut self) -> anyhow::Result<()> {
        let mut errors = Vec::new();
        for index in (0..self.installed.len()).rev() {
            if let Err(e) = self.remove_owned(index) {
                errors.push(format!("{e:#}"));
            }
        }
        anyhow::ensure!(errors.is_empty(), "{}", errors.join("; "));
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Default)]
    struct FakeState {
        routes: Vec<(bool, String)>,
        calls: Vec<String>,
        fail_ipv6: bool,
    }
    struct FakeIp(Arc<Mutex<FakeState>>);
    impl IpCommand for FakeIp {
        fn run(&mut self, args: &[String]) -> anyhow::Result<String> {
            let mut state = self.0.lock().unwrap();
            state.calls.push(args.join(" "));
            let ipv6 = args[0] == "-6";
            let args = if ipv6 { &args[1..] } else { args };
            let prefix = &args[if args[1] == "show" { 3 } else { 2 }];
            let same_prefix = |line: &str| line.split_whitespace().next() == Some(prefix.as_str());
            match args[1].as_str() {
                "show" => Ok(state
                    .routes
                    .iter()
                    .filter(|(v6, line)| *v6 == ipv6 && same_prefix(line))
                    .map(|(_, line)| line.clone())
                    .collect::<Vec<_>>()
                    .join("\n")),
                "add" => {
                    anyhow::ensure!(!(ipv6 && state.fail_ipv6), "injected IPv6 failure");
                    anyhow::ensure!(
                        !state.routes.iter().any(|(v6, line)| *v6 == ipv6
                            && same_prefix(line)
                            && line.contains("metric 1 ")),
                        "route already exists"
                    );
                    state.routes.push((ipv6, args[2..].join(" ")));
                    Ok(String::new())
                }
                "del" => {
                    let index = state
                        .routes
                        .iter()
                        .position(|(v6, line)| *v6 == ipv6 && *line == args[2..].join(" "))
                        .ok_or_else(|| anyhow::anyhow!("route not found"))?;
                    state.routes.remove(index);
                    Ok(String::new())
                }
                other => panic!("unexpected operation {other}"),
            }
        }
    }

    fn fixture() -> (RouteGuard, Arc<Mutex<FakeState>>) {
        let state = Arc::new(Mutex::new(FakeState {
            routes: vec![
                (
                    false,
                    "default via 192.0.2.1 dev eth0 metric 100 proto dhcp".into(),
                ),
                (
                    false,
                    "203.0.113.1/32 via 192.0.2.2 dev eth1 metric 20 proto static".into(),
                ),
            ],
            ..Default::default()
        }));
        (
            RouteGuard::with_command(
                "vpn0",
                vec!["203.0.113.1".parse().unwrap()],
                Box::new(FakeIp(state.clone())),
            ),
            state,
        )
    }

    #[test]
    fn partial_failure_removes_own_routes() {
        let (guard, state) = fixture();
        let original = state.lock().unwrap().routes.clone();
        {
            let shared = guard.shared();
            let mut routes = shared.lock().unwrap();
            routes
                .set_hosts(Some(("eth0", Some("192.0.2.1".parse().unwrap()))), None)
                .unwrap();
            routes.set_default("10.0.0.2".parse().unwrap()).unwrap();
            state.lock().unwrap().fail_ipv6 = true;
            assert!(routes.set_default("fd00::2".parse().unwrap()).is_err());
        }
        guard.restore().unwrap();
        let count = state.lock().unwrap().calls.len();
        guard.restore().unwrap();
        let state = state.lock().unwrap();
        assert_eq!(state.routes, original);
        assert_eq!(state.calls.len(), count);
        assert!(!state.calls.iter().any(|call| call.contains("replace")));
    }

    #[test]
    fn external_changes_survive_cleanup() {
        let (guard, state) = fixture();
        let shared = guard.shared();
        shared
            .lock()
            .unwrap()
            .set_hosts(Some(("eth0", Some("192.0.2.1".parse().unwrap()))), None)
            .unwrap();
        shared
            .lock()
            .unwrap()
            .set_default("10.0.0.2".parse().unwrap())
            .unwrap();
        {
            let mut state = state.lock().unwrap();
            state.routes.retain(|(_, line)| !line.contains("metric 1 "));
            state
                .routes
                .push((false, "default dev eth9 metric 1 proto static".into()));
            state.routes.push((
                false,
                "203.0.113.1/32 via 192.0.2.9 dev eth9 metric 1 proto static".into(),
            ));
            state
                .routes
                .push((false, "default dev eth2 metric 50 proto dhcp".into()));
        }
        let external = state.lock().unwrap().routes.clone();
        drop(guard);
        assert_eq!(state.lock().unwrap().routes, external);
        assert!(
            !state
                .lock()
                .unwrap()
                .calls
                .iter()
                .any(|call| call.contains("route del"))
        );
    }

    #[test]
    fn conflicting_route_changes_nothing() {
        let (guard, state) = fixture();
        state
            .lock()
            .unwrap()
            .routes
            .push((false, "default dev eth9 metric 1 proto static".into()));
        let original = state.lock().unwrap().routes.clone();
        assert!(
            guard
                .shared()
                .lock()
                .unwrap()
                .set_default("10.0.0.2".parse().unwrap())
                .is_err()
        );
        drop(guard);
        assert_eq!(state.lock().unwrap().routes, original);
        assert!(
            !state
                .lock()
                .unwrap()
                .calls
                .iter()
                .any(|call| call.contains("route del"))
        );
    }

    #[test]
    fn leftover_routes_are_borrowed() {
        for (server, gateway, ipv6, prefix) in [
            ("203.0.113.1", "192.0.2.1", false, "203.0.113.1/32"),
            ("2001:db8::1", "2001:db8::2", true, "2001:db8::1/128"),
        ] {
            let state = Arc::new(Mutex::new(FakeState {
                routes: vec![
                    (
                        ipv6,
                        format!("{prefix} dev eth0 via {gateway} metric 1 proto static"),
                    ),
                    (
                        ipv6,
                        format!(
                            "default dev vpn0 src {} metric 1 proto static",
                            if ipv6 { "fd00::2" } else { "10.0.0.2" }
                        ),
                    ),
                ],
                ..Default::default()
            }));
            let original = state.lock().unwrap().routes.clone();
            let guard = RouteGuard::with_command(
                "vpn0",
                vec![server.parse().unwrap()],
                Box::new(FakeIp(state.clone())),
            );
            {
                let shared = guard.shared();
                let mut routes = shared.lock().unwrap();
                for _ in 0..2 {
                    let exit = Some(("eth0", Some(gateway.parse().unwrap())));
                    let (exit_v4, exit_v6) = if ipv6 { (None, exit) } else { (exit, None) };
                    routes.set_hosts(exit_v4, exit_v6).unwrap();
                    routes
                        .set_default(if ipv6 { "fd00::2" } else { "10.0.0.2" }.parse().unwrap())
                        .unwrap();
                }
                assert!(routes.installed.is_empty());
            }
            drop(guard);
            let state = state.lock().unwrap();
            assert_eq!(state.routes, original);
            assert!(
                state
                    .calls
                    .iter()
                    .all(|call| call.contains("route show exact"))
            );
        }
    }

    #[test]
    fn route_switch() {
        let (guard, state) = fixture();
        let original = state.lock().unwrap().routes.clone();
        {
            let shared = guard.shared();
            let mut routes = shared.lock().unwrap();
            routes
                .set_hosts(Some(("eth0", Some("192.0.2.1".parse().unwrap()))), None)
                .unwrap();
            routes.set_default("10.0.0.2".parse().unwrap()).unwrap();
            routes
                .set_hosts(Some(("wlan0", Some("198.51.100.1".parse().unwrap()))), None)
                .unwrap();
            let state = state.lock().unwrap();
            assert!(
                !state
                    .routes
                    .iter()
                    .any(|(_, line)| line.starts_with("203.0.113.1/32 dev eth0"))
            );
            assert!(
                state
                    .routes
                    .iter()
                    .any(|(_, line)| line.starts_with("203.0.113.1/32 dev wlan0"))
            );
            assert!(
                state
                    .routes
                    .iter()
                    .any(|(_, line)| line.contains("dev vpn0"))
            );
        }
        guard.restore().unwrap();
        assert_eq!(state.lock().unwrap().routes, original);
    }

    #[test]
    fn lost_family_exit_removes_host_route() {
        let (guard, state) = fixture();
        {
            let shared = guard.shared();
            let mut routes = shared.lock().unwrap();
            routes
                .set_hosts(Some(("eth0", Some("192.0.2.1".parse().unwrap()))), None)
                .unwrap();
            assert!(
                state
                    .lock()
                    .unwrap()
                    .routes
                    .iter()
                    .any(|(_, line)| line.starts_with("203.0.113.1/32 dev eth0"))
            );
            // The v4 default route disappeared: the owned host route must
            // go with it instead of blackholing via a stale gateway. A
            // foreign route for the same prefix (eth1) stays untouched.
            routes.set_hosts(None, None).unwrap();
            assert!(
                !state
                    .lock()
                    .unwrap()
                    .routes
                    .iter()
                    .any(|(_, line)| line.starts_with("203.0.113.1/32 dev eth0"))
            );
            assert!(routes.installed.is_empty());
        }
        guard.restore().unwrap();
        let original = state.lock().unwrap().routes.clone();
        drop(guard);
        assert_eq!(state.lock().unwrap().routes, original);
    }

    #[test]
    fn reconnect_flush() {
        let (guard, state) = fixture();
        let original = state.lock().unwrap().routes.clone();
        {
            let shared = guard.shared();
            let mut routes = shared.lock().unwrap();
            routes
                .set_hosts(Some(("eth0", Some("192.0.2.1".parse().unwrap()))), None)
                .unwrap();
            for source in ["fd00::2", "fd00::2", "fd00::3"] {
                routes.clear_tunnel_defaults().unwrap();
                // Model IPv6 address deletion: the default survives, but
                // its preferred source is cleared. No owned default should
                // remain by the time the runner flushes the addresses.
                let mut kernel = state.lock().unwrap();
                for (ipv6, line) in &mut kernel.routes {
                    if *ipv6 && line.starts_with("default dev vpn0 src ") {
                        let words: Vec<_> = line.split_whitespace().collect();
                        *line = words[..3]
                            .iter()
                            .chain(words[5..].iter())
                            .copied()
                            .collect::<Vec<_>>()
                            .join(" ");
                    }
                }
                drop(kernel);
                routes.set_default("10.0.0.2".parse().unwrap()).unwrap();
                routes.set_default(source.parse().unwrap()).unwrap();
                assert!(
                    routes
                        .installed
                        .iter()
                        .any(|route| route.prefix != "default")
                );
            }
        }
        guard.restore().unwrap();
        assert_eq!(state.lock().unwrap().routes, original);
    }

    #[test]
    fn clear_keeps_host() {
        let (guard, state) = fixture();
        state.lock().unwrap().routes.push((
            false,
            "203.0.113.1/32 dev eth0 via 192.0.2.1 metric 1 proto static".into(),
        ));
        let original = state.lock().unwrap().routes.clone();
        {
            let shared = guard.shared();
            let mut routes = shared.lock().unwrap();
            routes
                .set_hosts(Some(("eth0", Some("192.0.2.1".parse().unwrap()))), None)
                .unwrap();
            routes.set_default("10.0.0.2".parse().unwrap()).unwrap();
            routes.clear_tunnel_defaults().unwrap();
        }
        guard.restore().unwrap();
        assert_eq!(state.lock().unwrap().routes, original);
    }

    #[test]
    fn clear_keeps_external() {
        let (guard, state) = fixture();
        state.lock().unwrap().routes.extend([
            (true, "default dev eth9 metric 1 proto static".into()),
            (true, "default dev vpn0 metric 100 proto static".into()),
            (true, "default dev vpn0 metric 1 proto dhcp".into()),
        ]);
        let original = state.lock().unwrap().routes.clone();
        guard
            .shared()
            .lock()
            .unwrap()
            .clear_tunnel_defaults()
            .unwrap();
        assert_eq!(state.lock().unwrap().routes, original);
    }

    #[test]
    fn reconnect_borrowed() {
        for source in [" src fd00::2", ""] {
            let (guard, state) = fixture();
            let original = state.lock().unwrap().routes.clone();
            state.lock().unwrap().routes.push((
                true,
                format!("default dev vpn0{source} metric 1 proto static"),
            ));
            {
                let shared = guard.shared();
                let mut routes = shared.lock().unwrap();
                if !source.is_empty() {
                    routes.set_default("fd00::2".parse().unwrap()).unwrap();
                    assert!(routes.installed.is_empty());
                }
                routes.clear_tunnel_defaults().unwrap();
                assert_eq!(state.lock().unwrap().routes, original);
                routes.set_default("fd00::3".parse().unwrap()).unwrap();
            }
            guard.restore().unwrap();
            assert_eq!(state.lock().unwrap().routes, original);
        }
    }

    #[test]
    fn reconnect_reuses_owned_routes() {
        let (guard, state) = fixture();
        let shared = guard.shared();
        let mut routes = shared.lock().unwrap();
        routes.set_default("10.0.0.2".parse().unwrap()).unwrap();
        routes.set_default("10.0.0.2".parse().unwrap()).unwrap();
        assert_eq!(
            state
                .lock()
                .unwrap()
                .calls
                .iter()
                .filter(|call| call.contains("route add"))
                .count(),
            1
        );
        routes.set_default("10.0.0.3".parse().unwrap()).unwrap();
        // Flushing TUN addresses can remove the associated route on reconnect.
        state
            .lock()
            .unwrap()
            .routes
            .retain(|(_, line)| !line.contains("dev vpn0"));
        routes.set_default("10.0.0.3".parse().unwrap()).unwrap();
        drop(routes);
        drop(guard);
        assert!(
            !state
                .lock()
                .unwrap()
                .routes
                .iter()
                .any(|(_, line)| line.contains("dev vpn0"))
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    #[ignore = "run manually in a fresh network namespace, e.g.: unshare -n env VAULT_NETWORK_TEST_NAMESPACE=1 cargo test -p edge linux_namespace_route_rollback"]
    fn linux_namespace_route_rollback() {
        // Refuse accidental execution in the host namespace, even as root.
        assert_eq!(
            std::env::var("VAULT_NETWORK_TEST_NAMESPACE").as_deref(),
            Ok("1")
        );
        assert_ne!(
            std::fs::read_link("/proc/self/ns/net").unwrap(),
            std::fs::read_link("/proc/1/ns/net").unwrap()
        );
        fn ip(args: &[&str]) -> String {
            SystemIp
                .run(&args.iter().map(|arg| arg.to_string()).collect::<Vec<_>>())
                .unwrap()
        }
        ip(&["link", "set", "lo", "up"]);
        ip(&["link", "add", "vault-eth", "type", "dummy"]);
        ip(&["link", "set", "vault-eth", "up"]);
        ip(&["addr", "add", "192.0.2.2/24", "dev", "vault-eth"]);
        ip(&[
            "-6",
            "addr",
            "add",
            "2001:db8::2/64",
            "dev",
            "vault-eth",
            "nodad",
        ]);
        ip(&[
            "route",
            "add",
            "default",
            "via",
            "192.0.2.1",
            "dev",
            "vault-eth",
            "metric",
            "100",
        ]);
        ip(&[
            "-6",
            "route",
            "add",
            "default",
            "via",
            "2001:db8::1",
            "dev",
            "vault-eth",
            "metric",
            "100",
        ]);
        ip(&[
            "route",
            "add",
            "203.0.113.1/32",
            "via",
            "192.0.2.254",
            "dev",
            "vault-eth",
            "metric",
            "20",
        ]);
        let _tun =
            vault_core::device::TunTapDevice::new("vault-tun", vault_core::device::DeviceType::Tun)
                .unwrap();
        ip(&["link", "set", "vault-tun", "up"]);
        ip(&["addr", "add", "10.0.0.2/24", "dev", "vault-tun"]);
        ip(&[
            "-6",
            "addr",
            "add",
            "fd00::2/64",
            "dev",
            "vault-tun",
            "nodad",
        ]);
        // Simulate a host route surviving the previous process's SIGKILL.
        ip(&[
            "route",
            "add",
            "203.0.113.1/32",
            "via",
            "192.0.2.1",
            "dev",
            "vault-eth",
            "metric",
            "1",
            "proto",
            "static",
        ]);
        let original_v4 = ip(&["route", "show", "default"]);
        let original_v6 = ip(&["-6", "route", "show", "default"]);
        let original_host = ip(&["route", "show", "exact", "203.0.113.1/32"]);

        for valid_ipv6 in [false, true] {
            let guard = RouteGuard::new("vault-tun", vec!["203.0.113.1".parse().unwrap()]);
            {
                let shared = guard.shared();
                let mut routes = shared.lock().unwrap();
                routes
                    .set_hosts(
                        Some(("vault-eth", Some("192.0.2.1".parse().unwrap()))),
                        None,
                    )
                    .unwrap();
                routes.set_default("10.0.0.2".parse().unwrap()).unwrap();
                let result = routes.set_default(
                    if valid_ipv6 { "fd00::2" } else { "fd00::99" }
                        .parse()
                        .unwrap(),
                );
                assert_eq!(result.is_ok(), valid_ipv6);
                if valid_ipv6 {
                    for address in ["fd00::2", "fd00::3"] {
                        routes.clear_tunnel_defaults().unwrap();
                        ip(&["addr", "flush", "dev", "vault-tun"]);
                        ip(&["addr", "add", "10.0.0.2/24", "dev", "vault-tun"]);
                        ip(&[
                            "-6",
                            "addr",
                            "add",
                            &format!("{address}/64"),
                            "dev",
                            "vault-tun",
                            "nodad",
                        ]);
                        routes.set_default("10.0.0.2".parse().unwrap()).unwrap();
                        routes.set_default(address.parse().unwrap()).unwrap();
                        assert!(
                            ip(&["-6", "route", "show", "default"])
                                .contains(&format!("src {address}"))
                        );
                    }
                }
            }
            assert!(ip(&["route", "get", "198.51.100.1"]).contains("dev vault-tun"));
            guard.restore().unwrap();
            guard.restore().unwrap();
            assert_eq!(ip(&["route", "show", "default"]), original_v4);
            assert_eq!(ip(&["-6", "route", "show", "default"]), original_v6);
            assert_eq!(
                ip(&["route", "show", "exact", "203.0.113.1/32"]),
                original_host
            );
        }
    }
}
