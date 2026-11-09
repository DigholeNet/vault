// SPDX-License-Identifier: MIT
//! Manage Edge routes across reconnects and process crashes.

use std::collections::HashMap;
use std::net::IpAddr;
#[cfg(target_os = "linux")]
use std::process::Command;
use std::sync::{Arc, Mutex};

// Deployment-local reservation, not a kernel ownership credential. All Edge
// instances in a network namespace must hold NetworkLock before recovery.
const ROUTE_PROTOCOL: &str = "242";

trait IpCommand: Send {
    fn run(&mut self, args: &[String]) -> anyhow::Result<String>;
}

fn tunnel_prefixes(ipv6: bool) -> [&'static str; 2] {
    if ipv6 {
        ["::/1", "8000::/1"]
    } else {
        ["0.0.0.0/1", "128.0.0.0/1"]
    }
}

#[cfg(target_os = "linux")]
struct SystemIp;
#[cfg(target_os = "linux")]
impl IpCommand for SystemIp {
    fn run(&mut self, args: &[String]) -> anyhow::Result<String> {
        // Ignore /etc/iproute2 aliases when matching protocol/table IDs.
        let output = vault_core::util::checked_output(Command::new("ip").arg("-N").args(args))?;
        Ok(String::from_utf8(output.stdout)?)
    }
}

/// Exact attributes of a route added by this connection. Kernel decorations
/// such as `scope link` and IPv6 `pref medium` are not ownership attributes.
#[derive(Clone, Debug, PartialEq, Eq)]
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
        args.extend([
            "metric".into(),
            "1".into(),
            "proto".into(),
            ROUTE_PROTOCOL.into(),
            "table".into(),
            "main".into(),
        ]);
        args
    }

    fn matches(&self, line: &str) -> bool {
        Self::parse(self.ipv6, line, ROUTE_PROTOCOL).as_ref() == Some(self)
    }

    /// Accept only the simple routes Edge creates. Unknown attributes (MTU,
    /// multipath, nexthop IDs, etc.) may belong to an administrator's edit.
    fn parse(ipv6: bool, line: &str, protocol: &str) -> Option<Self> {
        let mut words = line.split_whitespace();
        let prefix = words.next()?;
        let prefix = if prefix == "default" {
            prefix.into()
        } else {
            let (address, length) = prefix
                .split_once('/')
                .unwrap_or((prefix, if ipv6 { "128" } else { "32" }));
            let address: IpAddr = address.parse().ok()?;
            let length: u8 = length.parse().ok()?;
            if address.is_ipv6() != ipv6 || length > if ipv6 { 128 } else { 32 } {
                return None;
            }
            format!("{address}/{length}")
        };
        let mut fields = HashMap::new();
        while let Some(key) = words.next() {
            if key == "linkdown" {
                continue;
            }
            if !matches!(
                key,
                "dev" | "via" | "src" | "proto" | "metric" | "table" | "scope" | "pref"
            ) || fields.insert(key, words.next()?).is_some()
            {
                return None;
            }
        }
        if fields.get("proto") != Some(&protocol)
            || fields.get("metric") != Some(&"1")
            || fields
                .get("table")
                .is_some_and(|table| !matches!(*table, "main" | "254"))
            || fields
                .get("scope")
                .is_some_and(|scope| !matches!(*scope, "global" | "link" | "0" | "253"))
            || fields.get("pref").is_some_and(|pref| *pref != "medium")
        {
            return None;
        }
        let address = |key| -> Option<Option<IpAddr>> {
            match fields.get(key) {
                Some(value) => {
                    let ip: IpAddr = value.parse().ok()?;
                    (ip.is_ipv6() == ipv6).then_some(Some(ip))
                }
                None => Some(None),
            }
        };
        Some(Self {
            ipv6,
            prefix,
            interface: fields.get("dev")?.to_string(),
            gateway: address("via")?,
            source: address("src")?,
        })
    }
}

pub struct RouteState {
    command: Box<dyn IpCommand>,
    tun: String,
    servers: Vec<IpAddr>,
    installed: Vec<OwnedRoute>,
    recovered: bool,
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
                recovered: false,
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

    fn show(&mut self, ipv6: bool, prefix: &str) -> anyhow::Result<String> {
        self.run(
            ipv6,
            vec![
                "route".into(),
                "show".into(),
                "exact".into(),
                prefix.into(),
                "table".into(),
                "main".into(),
            ],
        )
    }

    fn is_present(&mut self, route: &OwnedRoute) -> anyhow::Result<bool> {
        Ok(self
            .show(route.ipv6, &route.prefix)?
            .lines()
            .any(|line| route.matches(line)))
    }

    /// Called once under the namespace lock. The kernel marker survives even
    /// a crash between a successful `add` and recording it in `installed`.
    fn recover_hosts(&mut self) -> anyhow::Result<()> {
        if self.recovered {
            return Ok(());
        }
        let mut recovered = Vec::new();
        for server in self.servers.clone() {
            let ipv6 = server.is_ipv6();
            let prefix = format!("{server}/{}", if ipv6 { 128 } else { 32 });
            // Do not filter by proto: ip suppresses fields used as filters.
            // Limit recovery to current servers rather than sweeping a table.
            let output = self.show(ipv6, &prefix)?;
            for line in output.lines() {
                if let Some(route) = OwnedRoute::parse(ipv6, line, ROUTE_PROTOCOL)
                    && route.prefix == prefix
                    && route.source.is_none()
                    && route.interface != self.tun
                    && !recovered.contains(&route)
                {
                    recovered.push(route);
                }
            }
        }
        self.installed.extend(recovered);
        self.recovered = true;
        Ok(())
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
        let mut present = false;
        for index in (0..self.installed.len()).rev() {
            let old = &self.installed[index];
            if old.ipv6 == route.ipv6 && old.prefix == route.prefix {
                if *old == route && self.is_present(&route)? {
                    present = true;
                } else {
                    self.remove_owned(index)?;
                }
            }
        }
        if present {
            return Ok(());
        }
        // Unmarked legacy/static routes are borrowed only when identical.
        // They cannot safely be attributed to Edge and must never be removed.
        let existing = self.show(route.ipv6, &route.prefix)?;
        if existing.lines().any(|line| {
            route.matches(line)
                || ["4", "static"].iter().any(|protocol| {
                    OwnedRoute::parse(route.ipv6, line, protocol).as_ref() == Some(&route)
                })
        }) {
            return Ok(());
        }
        let context = format!(
            "could not install server/tunnel route {} dev {} via {:?}; existing main-table routes: {}; \
             unowned routes are preserved, confirm their owner before removing a conflicting route",
            route.prefix,
            route.interface,
            route.gateway,
            if existing.trim().is_empty() {
                "(none)"
            } else {
                existing.trim()
            },
        );
        // Report an unowned conflict before attempting any route addition.
        anyhow::ensure!(
            !existing.lines().any(|line| line
                .split_whitespace()
                .collect::<Vec<_>>()
                .windows(2)
                .any(|pair| pair == ["metric", "1"])),
            "{context}"
        );
        // Never replace an unowned route. Record only successful additions.
        self.run(route.ipv6, route.args("add"))
            .map_err(|error| error.context(context))?;
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
        self.recover_hosts()?;
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
                    while let Some(index) = self
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
        // More-specific routes win even when the physical default has metric 0.
        for prefix in tunnel_prefixes(source.is_ipv6()) {
            self.install(OwnedRoute {
                ipv6: source.is_ipv6(),
                prefix: prefix.into(),
                interface: self.tun.clone(),
                gateway: None,
                source: Some(source),
            })?;
        }
        Ok(())
    }

    /// Remove our defaults before flushing TUN addresses. In particular,
    /// IPv6 address deletion can clear a route's preferred source without
    /// deleting the route, so it would no longer match our ownership record.
    /// Keep the server host route in place for the ongoing handshake.
    pub fn clear_tunnel_defaults(&mut self) -> anyhow::Result<()> {
        for index in (0..self.installed.len()).rev() {
            let route = &self.installed[index];
            if route.interface == self.tun
                && (route.prefix == "default"
                    || tunnel_prefixes(route.ipv6).contains(&route.prefix.as_str()))
            {
                // IPv6 address removal can clear only the preferred source.
                // Recover that known kernel transition, not arbitrary edits.
                let mut without_source = route.clone();
                without_source.source = None;
                if route.source.is_some() && self.is_present(&without_source)? {
                    self.installed[index] = without_source;
                }
                self.remove_owned(index)?;
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
            let same_prefix = |line: &str| {
                let actual = line.split_whitespace().next().unwrap();
                actual == prefix || format!("{actual}/{}", if ipv6 { 128 } else { 32 }) == *prefix
            };
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
                            && line
                                .split_whitespace()
                                .collect::<Vec<_>>()
                                .windows(2)
                                .any(|pair| pair == ["metric", "1"])),
                        "route already exists"
                    );
                    state.routes.push((ipv6, args[2..].join(" ")));
                    Ok(String::new())
                }
                "del" => {
                    let index = state
                        .routes
                        .iter()
                        .position(|(v6, line)| {
                            *v6 == ipv6
                                && OwnedRoute::parse(ipv6, line, ROUTE_PROTOCOL).is_some()
                                && OwnedRoute::parse(ipv6, line, ROUTE_PROTOCOL)
                                    == OwnedRoute::parse(ipv6, &args[2..].join(" "), ROUTE_PROTOCOL)
                        })
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
                    "default via 192.0.2.1 dev eth0 metric 0 proto static".into(),
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
    fn rollback() {
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
    fn conflict() {
        for prefix in tunnel_prefixes(false) {
            let (guard, state) = fixture();
            state
                .lock()
                .unwrap()
                .routes
                .push((false, format!("{prefix} dev eth9 metric 1 proto static")));
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
        }
    }

    #[test]
    fn legacy() {
        for ipv6 in [false, true] {
            let (guard, state, gateway) = recovery(ipv6);
            let source = if ipv6 { "fd00::2" } else { "10.0.0.2" };
            {
                let mut kernel = state.lock().unwrap();
                kernel.routes[0].1 = kernel.routes[0]
                    .1
                    .replace(&format!("proto {ROUTE_PROTOCOL}"), "proto 4");
                kernel.routes.extend(tunnel_prefixes(ipv6).map(|prefix| {
                    (
                        ipv6,
                        format!("{prefix} dev vpn0 src {source} metric 1 proto 4"),
                    )
                }));
            }
            let original = state.lock().unwrap().routes.clone();
            {
                let shared = guard.shared();
                let mut routes = shared.lock().unwrap();
                hosts(&mut routes, ipv6, gateway).unwrap();
                routes.set_default(source.parse().unwrap()).unwrap();
                routes.clear_tunnel_defaults().unwrap();
                assert!(routes.installed.is_empty());
                let new = if ipv6 { "fe80::2" } else { "192.0.2.2" }.parse().unwrap();
                let error = hosts(&mut routes, ipv6, new).unwrap_err();
                assert!(error.to_string().contains(&original[0].1));
            }
            drop(guard);
            assert_eq!(state.lock().unwrap().routes, original);
        }
    }

    fn recovery(ipv6: bool) -> (RouteGuard, Arc<Mutex<FakeState>>, IpAddr) {
        let server = if ipv6 { "2001:db8::1" } else { "203.0.113.1" };
        let gateway = if ipv6 { "fe80::1" } else { "192.0.2.1" }.parse().unwrap();
        // Match actual ip -N output: omitted host prefix, reordered fields,
        // link-local IPv6 gateway, and kernel decorations.
        let state = Arc::new(Mutex::new(FakeState {
            routes: vec![(
                ipv6,
                format!(
                    "{server} via {gateway} dev eth0 proto {ROUTE_PROTOCOL} metric 1{}",
                    if ipv6 { " pref medium" } else { "" }
                ),
            )],
            ..Default::default()
        }));
        let guard = RouteGuard::with_command(
            "vpn0",
            vec![server.parse().unwrap()],
            Box::new(FakeIp(state.clone())),
        );
        (guard, state, gateway)
    }

    fn hosts(routes: &mut RouteState, ipv6: bool, gateway: IpAddr) -> anyhow::Result<()> {
        let exit = Some(("eth0", Some(gateway)));
        routes.set_hosts(
            if ipv6 { None } else { exit },
            if ipv6 { exit } else { None },
        )
    }

    #[test]
    fn recover_switch() {
        for ipv6 in [false, true] {
            for first in ["same", "changed", "offline"] {
                let (guard, state, old) = recovery(ipv6);
                let new = if ipv6 { "fe80::2" } else { "192.0.2.2" }.parse().unwrap();
                {
                    let shared = guard.shared();
                    let mut routes = shared.lock().unwrap();
                    match first {
                        "same" => {
                            hosts(&mut routes, ipv6, old).unwrap();
                            assert_eq!(routes.installed.len(), 1);
                            assert!(
                                !state
                                    .lock()
                                    .unwrap()
                                    .calls
                                    .iter()
                                    .any(|c| c.contains("route add"))
                            );
                        }
                        "offline" => {
                            routes.set_hosts(None, None).unwrap();
                            assert!(state.lock().unwrap().routes.is_empty());
                        }
                        _ => {}
                    }
                    hosts(&mut routes, ipv6, new).unwrap();
                    assert_eq!(routes.installed[0].gateway, Some(new));
                    assert_eq!(state.lock().unwrap().routes.len(), 1);
                    routes.set_hosts(None, None).unwrap();
                    assert!(state.lock().unwrap().routes.is_empty());
                    hosts(&mut routes, ipv6, new).unwrap();
                }
                drop(guard);
                assert!(state.lock().unwrap().routes.is_empty());
            }
        }
    }

    #[test]
    fn external_edit() {
        for ipv6 in [false, true] {
            for edit in ["gateway", "metric", "mtu"] {
                let (guard, state, old) = recovery(ipv6);
                let shared = guard.shared();
                let mut routes = shared.lock().unwrap();
                hosts(&mut routes, ipv6, old).unwrap();
                let new: IpAddr = if ipv6 { "fe80::2" } else { "192.0.2.2" }.parse().unwrap();
                let mut kernel = state.lock().unwrap();
                let line = &mut kernel.routes[0].1;
                *line = match edit {
                    "gateway" => line.replace(&old.to_string(), &new.to_string()),
                    "metric" => line.replace("metric 1", "metric 20"),
                    _ => format!("{line} mtu 1400"),
                };
                let external = kernel.routes.clone();
                drop(kernel);
                // A subsequent poll must not recover/adopt the edited route.
                let result = hosts(&mut routes, ipv6, new);
                assert_eq!(result.is_ok(), edit != "mtu");
                routes.restore().unwrap();
                assert_eq!(state.lock().unwrap().routes, external);
            }
        }
    }

    #[test]
    fn recover_scope() {
        let (guard, state, gateway) = recovery(false);
        let original = state.lock().unwrap().routes[0].1.clone();
        state.lock().unwrap().routes.extend([
            (false, original.replace("203.0.113.1", "203.0.113.2")),
            (false, original.replace("metric 1", "metric 20")),
            (false, format!("{original} table 100")),
            (false, format!("{original} src 192.0.2.2")),
            (false, format!("{original} mtu 1400")),
        ]);
        hosts(&mut guard.shared().lock().unwrap(), false, gateway).unwrap();
        let untouched = state.lock().unwrap().routes[1..].to_vec();
        drop(guard);
        assert_eq!(state.lock().unwrap().routes, untouched);
    }

    #[test]
    fn direct_recovery() {
        for ipv6 in [false, true] {
            for offline in [false, true] {
                let (guard, state, gateway) = recovery(ipv6);
                {
                    let mut kernel = state.lock().unwrap();
                    let mut line = kernel.routes[0].1.replace(&format!(" via {gateway}"), "");
                    if !ipv6 {
                        line.push_str(" scope 253 linkdown");
                    }
                    kernel.routes[0].1 = line.clone();
                    // IPv6 may already have several direct routes at one metric.
                    if ipv6 {
                        kernel.routes.push((true, line.replace("eth0", "eth1")));
                    }
                }
                let exit = if offline { None } else { Some(("eth0", None)) };
                guard
                    .shared()
                    .lock()
                    .unwrap()
                    .set_hosts(
                        if ipv6 { None } else { exit },
                        if ipv6 { exit } else { None },
                    )
                    .unwrap();
                let kernel = state.lock().unwrap();
                assert_eq!(kernel.routes.len(), usize::from(!offline));
                assert!(!kernel.routes.iter().any(|(_, line)| line.contains("eth1")));
                drop(kernel);
                drop(guard);
                assert!(state.lock().unwrap().routes.is_empty());
            }
        }
    }

    #[test]
    fn recover_retry() {
        let (guard, state, old) = recovery(true);
        state.lock().unwrap().fail_ipv6 = true;
        let shared = guard.shared();
        let mut routes = shared.lock().unwrap();
        let new = "fe80::2".parse().unwrap();
        assert!(hosts(&mut routes, true, new).is_err());
        assert!(state.lock().unwrap().routes.is_empty());
        state.lock().unwrap().fail_ipv6 = false;
        hosts(&mut routes, true, new).unwrap();
        assert_ne!(routes.installed[0].gateway, Some(old));
        routes.restore().unwrap();
        assert!(state.lock().unwrap().routes.is_empty());
    }

    #[test]
    fn lost_source() {
        for source in ["", " src fd00::9"] {
            let (guard, state) = fixture();
            let original = state.lock().unwrap().routes.clone();
            let shared = guard.shared();
            let mut routes = shared.lock().unwrap();
            hosts(&mut routes, false, "192.0.2.1".parse().unwrap()).unwrap();
            let with_host = state.lock().unwrap().routes.clone();
            routes.set_default("fd00::2".parse().unwrap()).unwrap();
            let mut kernel = state.lock().unwrap();
            for (ipv6, line) in &mut kernel.routes {
                if *ipv6 {
                    *line = line.replace(" src fd00::2", source);
                }
            }
            let edited = kernel.routes.clone();
            drop(kernel);
            routes.clear_tunnel_defaults().unwrap();
            if source.is_empty() {
                assert_eq!(state.lock().unwrap().routes, with_host);
                routes.set_default("fd00::3".parse().unwrap()).unwrap();
                routes.restore().unwrap();
                assert_eq!(state.lock().unwrap().routes, original);
            } else {
                assert_eq!(state.lock().unwrap().routes, edited);
                assert!(routes.set_default("fd00::3".parse().unwrap()).is_err());
            }
        }
    }

    #[test]
    fn reuse() {
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
            2
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

    #[test]
    fn prefix_length() {
        let route = OwnedRoute {
            ipv6: true,
            prefix: "::/1".into(),
            interface: "vpn0".into(),
            gateway: None,
            source: None,
        };
        assert!(route.matches(&format!("::/1 dev vpn0 metric 1 proto {ROUTE_PROTOCOL}")));
        for prefix in ["default", "::/0", "::/128", "::"] {
            assert!(!route.matches(&format!(
                "{prefix} dev vpn0 metric 1 proto {ROUTE_PROTOCOL}"
            )));
        }
        let host = OwnedRoute {
            prefix: "::1/128".into(),
            ..route
        };
        assert!(host.matches(&format!("::1 dev vpn0 metric 1 proto {ROUTE_PROTOCOL}")));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn route_child() {
        use std::io::{Read, Write};
        if std::env::var("VAULT_ROUTE_CHILD").as_deref() != Ok("1") {
            return;
        }
        assert_eq!(
            std::env::var("VAULT_NETWORK_TEST_NAMESPACE").as_deref(),
            Ok("1")
        );
        assert_ne!(
            std::fs::read_link("/proc/self/ns/net").unwrap(),
            std::fs::read_link("/proc/1/ns/net").unwrap()
        );
        // The child owns the routes until SIGKILL; Drop must not run.
        let guard = RouteGuard::new(
            "vault-tun",
            vec![
                "203.0.113.2".parse().unwrap(),
                "2001:db9::1".parse().unwrap(),
            ],
        );
        guard
            .shared()
            .lock()
            .unwrap()
            .set_hosts(
                Some(("vault-eth", Some("192.0.2.1".parse().unwrap()))),
                Some(("vault-eth", Some("2001:db8::1".parse().unwrap()))),
            )
            .unwrap();
        println!("\nREADY");
        std::io::stdout().flush().unwrap();
        let _ = std::io::stdin().read_exact(&mut [0]);
    }

    #[cfg(target_os = "linux")]
    #[test]
    #[ignore = "run manually in a fresh network namespace, e.g.: unshare -n env VAULT_NETWORK_TEST_NAMESPACE=1 cargo test -p edge netns_routes"]
    fn netns_routes() {
        // Refuse accidental execution in the host namespace, even as root.
        assert_eq!(
            std::env::var("VAULT_NETWORK_TEST_NAMESPACE").as_deref(),
            Ok("1")
        );
        assert_ne!(
            std::fs::read_link("/proc/self/ns/net").unwrap(),
            std::fs::read_link("/proc/1/ns/net").unwrap()
        );
        fn ip(args: &str) -> String {
            SystemIp
                .run(
                    &args
                        .split_whitespace()
                        .map(str::to_string)
                        .collect::<Vec<_>>(),
                )
                .unwrap()
        }
        ip("link set lo up");
        ip("link add vault-eth type dummy");
        ip("link set vault-eth up");
        ip("addr add 192.0.2.2/24 dev vault-eth");
        ip("-6 addr add 2001:db8::2/64 dev vault-eth nodad");
        ip("route add default via 192.0.2.1 dev vault-eth metric 0");
        ip("-6 route add default via 2001:db8::1 dev vault-eth metric 100");
        ip("route add 203.0.113.1/32 via 192.0.2.254 dev vault-eth metric 20");
        let _tun =
            vault_core::device::TunTapDevice::new("vault-tun", vault_core::device::DeviceType::Tun)
                .unwrap();
        ip("link set vault-tun up");
        ip("addr add 10.0.0.2/24 dev vault-tun");
        ip("-6 addr add fd00::2/64 dev vault-tun nodad");
        // Simulate a host route surviving the previous process's SIGKILL.
        ip("route add 203.0.113.1/32 via 192.0.2.1 dev vault-eth metric 1 proto static");
        let original_v4 = ip("route show default");
        let original_v6 = ip("-6 route show default");
        let original_host = ip("route show exact 203.0.113.1/32");

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
                        ip("addr flush dev vault-tun");
                        ip("addr add 10.0.0.2/24 dev vault-tun");
                        ip(&format!("-6 addr add {address}/64 dev vault-tun nodad"));
                        routes.set_default("10.0.0.2".parse().unwrap()).unwrap();
                        routes.set_default(address.parse().unwrap()).unwrap();
                        for target in ["2001:db9::1", "9000::1"] {
                            let selected = ip(&format!("-6 route get {target}"));
                            assert!(selected.contains("dev vault-tun"));
                            assert!(selected.contains(&format!("src {address}")));
                        }
                    }
                }
            }
            for target in ["1.1.1.1", "198.51.100.1"] {
                assert!(ip(&format!("route get {target}")).contains("dev vault-tun"));
            }
            assert!(ip("route get 203.0.113.1").contains("dev vault-eth"));
            guard.restore().unwrap();
            guard.restore().unwrap();
            assert_eq!(ip("route show default"), original_v4);
            assert_eq!(ip("-6 route show default"), original_v6);
            for ipv6 in [false, true] {
                for prefix in tunnel_prefixes(ipv6) {
                    assert!(
                        ip(&format!(
                            "{} route show exact {prefix}",
                            if ipv6 { "-6" } else { "-4" }
                        ))
                        .is_empty()
                    );
                }
            }
            assert_eq!(ip("route show exact 203.0.113.1/32"), original_host);
        }

        // Exercise the crash boundary with real kernel routes, both address
        // families, and a gateway change before restart.
        use std::io::{BufRead, BufReader};
        use std::process::Stdio;
        {
            let mut child = Command::new(std::env::current_exe().unwrap())
                .args(["--exact", "routes::tests::route_child", "--nocapture"])
                .env("VAULT_ROUTE_CHILD", "1")
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .spawn()
                .unwrap();
            let mut output = BufReader::new(child.stdout.take().unwrap());
            loop {
                let mut line = String::new();
                assert!(
                    output.read_line(&mut line).unwrap() > 0,
                    "route child exited"
                );
                if line.trim() == "READY" {
                    break;
                }
            }
            child.stdout = Some(output.into_inner());
            child.kill().unwrap();
            use std::os::unix::process::ExitStatusExt;
            assert_eq!(child.wait().unwrap().signal(), Some(9));
            for (family, prefix) in [("-4", "203.0.113.2/32"), ("-6", "2001:db9::1/128")] {
                assert!(
                    ip(&format!("{family} route show exact {prefix}"))
                        .contains(&format!("proto {ROUTE_PROTOCOL}"))
                );
            }
            let guard = RouteGuard::new(
                "vault-tun",
                vec![
                    "203.0.113.2".parse().unwrap(),
                    "2001:db9::1".parse().unwrap(),
                ],
            );
            {
                let shared = guard.shared();
                let mut routes = shared.lock().unwrap();
                routes
                    .set_hosts(
                        Some(("vault-eth", Some("192.0.2.254".parse().unwrap()))),
                        Some(("vault-eth", Some("2001:db8::fe".parse().unwrap()))),
                    )
                    .unwrap();
                assert!(ip("route get 203.0.113.2").contains("via 192.0.2.254"));
                assert!(ip("-6 route get 2001:db9::1").contains("via 2001:db8::fe"));
                routes.set_hosts(None, None).unwrap();
                assert!(routes.installed.is_empty());
                routes
                    .set_hosts(
                        Some(("vault-eth", Some("192.0.2.254".parse().unwrap()))),
                        Some(("vault-eth", Some("2001:db8::fe".parse().unwrap()))),
                    )
                    .unwrap();
            }
            drop(guard);
            for (family, prefix) in [("-4", "203.0.113.2/32"), ("-6", "2001:db9::1/128")] {
                assert!(ip(&format!("{family} route show exact {prefix}")).is_empty());
            }
            assert_eq!(ip("route show exact 203.0.113.1/32"), original_host);
        }
    }
}
