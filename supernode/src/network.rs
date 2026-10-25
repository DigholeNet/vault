// SPDX-License-Identifier: MIT
//! Scoped firewall rules with transactional startup and owned-resource cleanup.
#[cfg(target_os = "linux")]
use anyhow::Context;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Rule {
    program: &'static str,
    table: &'static str,
    args: Vec<String>,
}

impl Rule {
    fn new(program: &'static str, table: &'static str, args: &[&str]) -> Self {
        Self {
            program,
            table,
            args: args.iter().map(|arg| (*arg).into()).collect(),
        }
    }

    #[cfg(any(target_os = "linux", test))]
    fn command(&self, verb: &str) -> Vec<String> {
        let mut args = vec![
            "-w".into(),
            "5".into(),
            "-t".into(),
            self.table.into(),
            verb.into(),
        ];
        args.extend(self.args.clone());
        args
    }
}

/// Read the usable routes exported by Linux. No physical-device
/// heuristic: a virtual interface can be the host's real uplink.
#[cfg(target_os = "linux")]
pub fn route_interfaces(tun: &str, ipv4: bool, ipv6: bool) -> anyhow::Result<Vec<String>> {
    let v4 = if ipv4 {
        std::fs::read_to_string("/proc/net/route").context("read IPv4 routes")?
    } else {
        String::new()
    };
    let v6 = if ipv6 {
        std::fs::read_to_string("/proc/net/ipv6_route").context("read IPv6 routes")?
    } else {
        String::new()
    };
    Ok(parse_routes(&v4, &v6, tun))
}

#[cfg(any(target_os = "linux", test))]
fn parse_routes(ipv4: &str, ipv6: &str, tun: &str) -> Vec<String> {
    let mut exits = Vec::new();
    let mut add = |name: &str| {
        if name != tun && name != "lo" && !exits.iter().any(|exit| exit == name) {
            exits.push(name.to_owned());
        }
    };
    for line in ipv4.lines() {
        let fields: Vec<_> = line.split_whitespace().collect();
        if fields.len() >= 8
            && u32::from_str_radix(fields[3], 16)
                .is_ok_and(|flags| flags & 1 != 0 && flags & 0x200 == 0)
        {
            add(fields[0]);
        }
    }
    for line in ipv6.lines() {
        let fields: Vec<_> = line.split_whitespace().collect();
        if fields.len() == 10
            && !fields[0].starts_with("ff")
            && u32::from_str_radix(fields[8], 16)
                .is_ok_and(|flags| flags & 1 != 0 && flags & (0x200 | 0x80000000) == 0)
        {
            add(fields[9]);
        }
    }
    exits
}

/// All command and sysctl effects are injectable for failure/rollback tests.
pub trait Backend {
    fn has_rule(&mut self, rule: &Rule) -> anyhow::Result<bool>;
    fn change_rule(&mut self, rule: &Rule, verb: &str) -> anyhow::Result<()>;
    fn read_sysctl(&mut self, key: &str) -> anyhow::Result<String>;
    fn write_sysctl(&mut self, key: &str, value: &str) -> anyhow::Result<()>;
}

pub struct NetworkSetup<B: Backend> {
    backend: B,
    owned_rules: Vec<Rule>,
    changed_sysctls: Vec<(String, String, String)>,
}

impl<B: Backend> NetworkSetup<B> {
    pub fn new(backend: B) -> Self {
        Self {
            backend,
            owned_rules: Vec::new(),
            changed_sysctls: Vec::new(),
        }
    }

    pub fn configure(
        &mut self,
        tun: &str,
        ipv4: Option<&str>,
        ipv6: Option<&str>,
        exits: &[String],
    ) -> anyhow::Result<()> {
        anyhow::ensure!(
            !exits.is_empty(),
            "no routed egress interface found for the configured address families (check the routing table)"
        );
        // Forwarding is shared host state. Enable it without registering it
        // for rollback: other services may depend on it after we exit.
        for (cidr, key) in [
            (ipv4, "net.ipv4.ip_forward"),
            (ipv6, "net.ipv6.conf.all.forwarding"),
        ] {
            if cidr.is_some() && self.backend.read_sysctl(key)? != "1" {
                if key == "net.ipv6.conf.all.forwarding" {
                    // Preserve RA reception before switching to router mode.
                    // An administrator's explicit accept_ra=0 stays disabled.
                    for exit in exits {
                        let ra = format!("net/ipv6/conf/{exit}/accept_ra");
                        if self.backend.read_sysctl(&ra)? == "1" {
                            self.backend.write_sysctl(&ra, "2")?;
                        }
                    }
                }
                tracing::info!("Enabling host forwarding: {key}=1");
                self.backend.write_sysctl(key, "1")?;
            }
        }
        if ipv4.is_some() {
            // This is optional host hardening, not a forwarding prerequisite.
            // Never change global settings or reject startup because of it.
            match self.backend.read_sysctl("net.ipv4.conf.all.send_redirects") {
                Ok(value) if value == "0" => {}
                Ok(_) => tracing::warn!(
                    "Global IPv4 send_redirects is enabled; TUN-local setting alone may not disable redirects. Continuing startup without changing host settings"
                ),
                Err(error) => tracing::warn!(
                    "Cannot inspect global IPv4 send_redirects: {error:#}; continuing startup"
                ),
            }
        }
        // Only the newly created TUN's settings are owned by this instance.
        // Slash notation preserves dots in interface names.
        if ipv4.is_some() {
            self.set_sysctl(&format!("net/ipv4/conf/{tun}/send_redirects"), "0")?;
        }
        if ipv6.is_some() {
            self.set_sysctl(&format!("net/ipv6/conf/{tun}/accept_redirects"), "0")?;
        }
        for (program, cidr) in [("iptables", ipv4), ("ip6tables", ipv6)] {
            if let Some(cidr) = cidr {
                for rule in tunnel_rules(program, tun, cidr, exits) {
                    if !self.backend.has_rule(&rule)? {
                        self.backend.change_rule(&rule, "-A")?;
                        self.owned_rules.push(rule);
                    }
                }
            }
        }
        Ok(())
    }

    fn set_sysctl(&mut self, key: &str, value: &str) -> anyhow::Result<()> {
        let original = self.backend.read_sysctl(key)?;
        if original != value {
            // Arm before writing: even a failed command may have applied it.
            self.changed_sysctls
                .push((key.into(), original, value.into()));
            self.backend.write_sysctl(key, value)?;
        }
        Ok(())
    }
}

impl<B: Backend> Drop for NetworkSetup<B> {
    fn drop(&mut self) {
        for rule in self.owned_rules.iter().rev() {
            if let Err(error) = self.backend.change_rule(rule, "-D") {
                tracing::error!("Firewall rollback failed: {error:#}");
            }
        }
        for (key, original, applied) in self.changed_sysctls.iter().rev() {
            // Do not overwrite a later administrator change.
            match self.backend.read_sysctl(key) {
                Ok(current) if current == *applied => {
                    if let Err(error) = self.backend.write_sysctl(key, original) {
                        tracing::error!("Sysctl rollback failed for {key}: {error:#}");
                    }
                }
                Ok(_) => {}
                Err(error) => {
                    tracing::error!("Cannot inspect sysctl {key} for rollback: {error:#}")
                }
            }
        }
    }
}

fn tunnel_rules(program: &'static str, tun: &str, cidr: &str, exits: &[String]) -> Vec<Rule> {
    let mut rules = Vec::new();
    for exit in exits {
        rules.push(Rule::new(
            program,
            "nat",
            &["POSTROUTING", "-s", cidr, "-o", exit, "-j", "MASQUERADE"],
        ));
        rules.push(Rule::new(
            program,
            "filter",
            &["FORWARD", "-i", tun, "-s", cidr, "-o", exit, "-j", "ACCEPT"],
        ));
        rules.push(Rule::new(
            program,
            "filter",
            &[
                "FORWARD",
                "-i",
                exit,
                "-o",
                tun,
                "-d",
                cidr,
                "-m",
                "conntrack",
                "--ctstate",
                "ESTABLISHED,RELATED",
                "-j",
                "ACCEPT",
            ],
        ));
    }
    // Peer-to-peer relay also traverses FORWARD with TUN on both sides.
    rules.push(Rule::new(
        program,
        "filter",
        &[
            "FORWARD", "-i", tun, "-o", tun, "-s", cidr, "-d", cidr, "-j", "ACCEPT",
        ],
    ));
    for direction in [["-i", tun, "-s", cidr], ["-o", tun, "-d", cidr]] {
        let mut args = vec!["FORWARD"];
        args.extend(direction);
        args.extend([
            "-p",
            "tcp",
            "--tcp-flags",
            "SYN,RST",
            "SYN",
            "-j",
            "TCPMSS",
            "--clamp-mss-to-pmtu",
        ]);
        rules.push(Rule::new(program, "mangle", &args));
    }
    rules
}

#[cfg(target_os = "linux")]
pub struct SystemBackend;

#[cfg(target_os = "linux")]
impl SystemBackend {
    fn command(program: &str, args: &[String]) -> anyhow::Result<std::process::Output> {
        std::process::Command::new(program)
            .args(args)
            .output()
            .with_context(|| format!("execute {program} {}", args.join(" ")))
    }
}

#[cfg(target_os = "linux")]
impl Backend for SystemBackend {
    fn has_rule(&mut self, rule: &Rule) -> anyhow::Result<bool> {
        let output = Self::command(rule.program, &rule.command("-C"))?;
        match output.status.code() {
            Some(0) => Ok(true),
            Some(1) => Ok(false),
            _ => anyhow::bail!(
                "{} rule check failed: {}",
                rule.program,
                String::from_utf8_lossy(&output.stderr).trim()
            ),
        }
    }

    fn change_rule(&mut self, rule: &Rule, verb: &str) -> anyhow::Result<()> {
        let args = rule.command(verb);
        let output = Self::command(rule.program, &args)?;
        anyhow::ensure!(
            output.status.success(),
            "{} {} failed: {}",
            rule.program,
            args.join(" "),
            String::from_utf8_lossy(&output.stderr).trim()
        );
        Ok(())
    }

    fn read_sysctl(&mut self, key: &str) -> anyhow::Result<String> {
        let output = Self::command("sysctl", &["-n".into(), key.into()])?;
        anyhow::ensure!(
            output.status.success(),
            "read sysctl {key}: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
        Ok(String::from_utf8(output.stdout)?.trim().into())
    }

    fn write_sysctl(&mut self, key: &str, value: &str) -> anyhow::Result<()> {
        let output = Self::command("sysctl", &["-w".into(), format!("{key}={value}")])?;
        anyhow::ensure!(
            output.status.success(),
            "write sysctl {key}: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{cell::RefCell, collections::HashMap, rc::Rc};

    #[derive(Default)]
    struct State {
        rules: Vec<Rule>,
        sysctls: HashMap<String, String>,
        writes: Vec<(String, String)>,
        calls: usize,
        fail_at: Option<usize>,
    }
    #[derive(Clone, Default)]
    struct Fake(Rc<RefCell<State>>);
    impl Fake {
        fn step(&self) -> anyhow::Result<()> {
            let mut state = self.0.borrow_mut();
            state.calls += 1;
            anyhow::ensure!(Some(state.calls) != state.fail_at, "injected failure");
            Ok(())
        }
    }
    impl Backend for Fake {
        fn has_rule(&mut self, rule: &Rule) -> anyhow::Result<bool> {
            self.step()?;
            Ok(self.0.borrow().rules.contains(rule))
        }
        fn change_rule(&mut self, rule: &Rule, verb: &str) -> anyhow::Result<()> {
            self.step()?;
            let mut state = self.0.borrow_mut();
            if verb == "-A" {
                state.rules.push(rule.clone());
            } else {
                state.rules.retain(|r| r != rule);
            }
            Ok(())
        }
        fn read_sysctl(&mut self, key: &str) -> anyhow::Result<String> {
            self.step()?;
            Ok(self
                .0
                .borrow()
                .sysctls
                .get(key)
                .cloned()
                .unwrap_or_else(|| "0".into()))
        }
        fn write_sysctl(&mut self, key: &str, value: &str) -> anyhow::Result<()> {
            assert!(
                (key.starts_with("net/ipv") && key.contains("/conf/vpn"))
                    || matches!(
                        key,
                        "net.ipv4.ip_forward"
                            | "net.ipv6.conf.all.forwarding"
                            | "net/ipv6/conf/eth0/accept_ra"
                    ),
                "unexpected host mutation: {key}"
            );
            self.step()?;
            let mut state = self.0.borrow_mut();
            state.writes.push((key.into(), value.into()));
            state.sysctls.insert(key.into(), value.into());
            Ok(())
        }
    }
    fn fixture() -> Fake {
        let fake = Fake::default();
        fake.0.borrow_mut().sysctls.extend([
            ("net.ipv4.ip_forward".into(), "1".into()),
            ("net.ipv6.conf.all.forwarding".into(), "1".into()),
            ("net/ipv6/conf/eth0/accept_ra".into(), "2".into()),
            ("net/ipv4/conf/eth0/rp_filter".into(), "2".into()),
        ]);
        fake.0
            .borrow_mut()
            .sysctls
            .insert("net/ipv4/conf/vpn/send_redirects".into(), "1".into());
        fake.0
            .borrow_mut()
            .sysctls
            .insert("net/ipv6/conf/vpn/accept_redirects".into(), "1".into());
        fake
    }

    #[test]
    fn virtual_uplink_routes() {
        let v4 = "Iface Destination Gateway Flags RefCnt Use Metric Mask
eth0 00000000 0100000A 0003 0 0 0 00000000
br0 00000000 00000000 0001 0 0 10 00000000
bond0.100 00000000 00000000 0001 0 0 20 00000000
vpn0 00000000 00000000 0001 0 0 0 00000000
lo 00000000 00000000 0201 0 0 0 00000000
down0 00000000 00000000 0000 0 0 0 00000000
lan0 0000000A 00000000 0001 0 0 0 00FFFFFF
";
        let zero = "00000000000000000000000000000000";
        let v6 = format!(
            "{zero} 00 {zero} 00 {zero} 00000064 00000000 00000000 00000001 eth0\n\
             {zero} 00 {zero} 00 {zero} 00000064 00000000 00000000 00000001 veth0\n\
             {zero} 00 {zero} 00 {zero} ffffffff 00000000 00000000 00200200 lo\n"
        );
        assert_eq!(
            parse_routes(v4, &v6, "vpn0"),
            ["eth0", "br0", "bond0.100", "lan0", "veth0"]
        );
        assert!(parse_routes("garbage", "garbage", "vpn0").is_empty());
    }

    #[test]
    fn routes_without_default() {
        let v4 = "lan0 0001A8C0 00000000 0001 0 0 0 00FFFFFF\n\
                  lan0 000010AC 0101A8C0 0003 0 0 0 0000FFFF\n\
                  vpn0 0000000A 00000000 0001 0 0 0 00FFFFFF\n\
                  reject0 00000000 00000000 0201 0 0 0 00000000\n";
        let zero = "00000000000000000000000000000000";
        let v6 = format!(
            "fd010000000000000000000000000000 40 {zero} 00 {zero} 00000064 0 0 00000001 lan6\n\
             fd020000000000000000000000000000 40 {zero} 00 {zero} 00000064 0 0 00000001 vpn0\n\
             fd030000000000000000000000000001 80 {zero} 00 {zero} 00000000 0 0 80000001 local6\n\
             {zero} 00 {zero} 00 {zero} ffffffff 0 0 00000201 reject6\n"
        );
        assert_eq!(parse_routes(v4, &v6, "vpn0"), ["lan0", "lan6"]);
    }

    #[test]
    fn redirects_are_optional() {
        for unreadable in [false, true] {
            let fake = fixture();
            fake.0
                .borrow_mut()
                .sysctls
                .insert("net.ipv4.conf.all.send_redirects".into(), "1".into());
            // IPv4 forwarding read comes first, optional redirect read second.
            if unreadable {
                fake.0.borrow_mut().fail_at = Some(2);
            }
            let before = fake.0.borrow().sysctls.clone();
            {
                let mut setup = NetworkSetup::new(fake.clone());
                setup
                    .configure("vpn", Some("10.0.0.0/24"), None, &["eth0".into()])
                    .unwrap();
                let state = fake.0.borrow();
                assert_eq!(state.sysctls["net.ipv4.conf.all.send_redirects"], "1");
                assert_eq!(state.sysctls["net/ipv4/conf/vpn/send_redirects"], "0");
                assert_eq!(
                    state.rules,
                    tunnel_rules("iptables", "vpn", "10.0.0.0/24", &["eth0".into()])
                );
            }
            assert_eq!(fake.0.borrow().sysctls, before);
            assert!(fake.0.borrow().rules.is_empty());
        }
    }

    #[test]
    fn startup_failure_rollback() {
        let exits = vec!["eth0".into()];
        let existing = tunnel_rules("iptables", "vpn", "10.0.0.0/24", &exits)[0].clone();
        let probe = fixture();
        probe.0.borrow_mut().rules.push(existing.clone());
        let startup_calls;
        {
            let mut setup = NetworkSetup::new(probe.clone());
            setup
                .configure("vpn", Some("10.0.0.0/24"), Some("fd00::/96"), &exits)
                .unwrap();
            startup_calls = probe.0.borrow().calls;
        }
        // Exercise every read, check and mutation in startup.
        for fail_at in 1..=startup_calls {
            let fake = fixture();
            fake.0.borrow_mut().rules.push(existing.clone());
            let original_sysctls = fake.0.borrow().sysctls.clone();
            fake.0.borrow_mut().fail_at = Some(fail_at);
            {
                let mut setup = NetworkSetup::new(fake.clone());
                let result = setup.configure("vpn", Some("10.0.0.0/24"), Some("fd00::/96"), &exits);
                // The optional global redirect inspection is call 3.
                assert_eq!(result.is_ok(), fail_at == 3, "failure {fail_at}");
            }
            let state = fake.0.borrow();
            assert_eq!(state.rules, vec![existing.clone()], "failure {fail_at}");
            for (key, original) in &original_sysctls {
                assert_eq!(state.sysctls.get(key), Some(original));
            }
            assert_eq!(
                state
                    .sysctls
                    .get("net.ipv4.ip_forward")
                    .map(String::as_str)
                    .unwrap_or("0"),
                "1"
            );
            assert_eq!(
                state
                    .sysctls
                    .get("net.ipv6.conf.all.forwarding")
                    .map(String::as_str)
                    .unwrap_or("0"),
                "1"
            );
        }
    }

    #[test]
    fn dual_stack_rule_scope() {
        let exits = vec!["eth0".into()];
        for (program, cidr) in [("iptables", "10.0.0.0/24"), ("ip6tables", "fd00::/96")] {
            let rules = tunnel_rules(program, "vpn", cidr, &exits);
            assert_eq!(rules.len(), 6);
            assert_eq!(&rules[0].command("-A")[..5], ["-w", "5", "-t", "nat", "-A"]);
            for rule in &rules {
                assert!(rule.args.contains(&cidr.into()));
                if rule.table != "nat" {
                    assert!(rule.args.contains(&"vpn".into()));
                }
            }
            assert!(
                rules
                    .iter()
                    .any(|r| r.table == "filter" && r.args.windows(2).any(|p| p == ["-i", "vpn"]))
            );
            assert!(
                rules
                    .iter()
                    .any(|r| r.args.contains(&"ESTABLISHED,RELATED".into()))
            );
        }
    }

    #[test]
    fn forwarding_survives_cleanup() {
        let fake = fixture();
        for key in ["net.ipv4.ip_forward", "net.ipv6.conf.all.forwarding"] {
            fake.0.borrow_mut().sysctls.insert(key.into(), "0".into());
        }
        fake.0
            .borrow_mut()
            .sysctls
            .insert("net/ipv6/conf/eth0/accept_ra".into(), "1".into());
        {
            let mut setup = NetworkSetup::new(fake.clone());
            setup
                .configure(
                    "vpn",
                    Some("10.0.0.0/24"),
                    Some("fd00::/96"),
                    &["eth0".into()],
                )
                .unwrap();
        }
        let state = fake.0.borrow();
        assert!(state.rules.is_empty());
        assert_eq!(state.sysctls["net.ipv4.ip_forward"], "1");
        assert_eq!(state.sysctls["net.ipv6.conf.all.forwarding"], "1");
        assert_eq!(state.sysctls["net/ipv6/conf/eth0/accept_ra"], "2");
        assert_eq!(
            state.writes[..3],
            [
                ("net.ipv4.ip_forward".into(), "1".into()),
                ("net/ipv6/conf/eth0/accept_ra".into(), "2".into()),
                ("net.ipv6.conf.all.forwarding".into(), "1".into()),
            ]
        );
    }

    #[test]
    fn startup_keeps_forwarding() {
        let fake = fixture();
        fake.0
            .borrow_mut()
            .sysctls
            .insert("net.ipv4.ip_forward".into(), "0".into());
        // Fail the TUN-local write after forwarding was enabled.
        fake.0.borrow_mut().fail_at = Some(5);
        let mut setup = NetworkSetup::new(fake.clone());
        assert!(
            setup
                .configure("vpn", Some("10.0.0.0/24"), None, &["eth0".into()])
                .is_err()
        );
        drop(setup);
        assert_eq!(fake.0.borrow().sysctls["net.ipv4.ip_forward"], "1");
        assert_eq!(
            fake.0.borrow().sysctls["net/ipv4/conf/vpn/send_redirects"],
            "1"
        );
        assert!(fake.0.borrow().rules.is_empty());
    }

    #[test]
    fn forwarding_write_failure() {
        let fake = fixture();
        fake.0
            .borrow_mut()
            .sysctls
            .insert("net.ipv4.ip_forward".into(), "0".into());
        fake.0.borrow_mut().fail_at = Some(2);
        let mut setup = NetworkSetup::new(fake.clone());
        assert!(
            setup
                .configure("vpn", Some("10.0.0.0/24"), None, &["eth0".into()])
                .is_err()
        );
        drop(setup);
        assert!(fake.0.borrow().rules.is_empty());
        assert_eq!(fake.0.borrow().sysctls["net.ipv6.conf.all.forwarding"], "1");
    }

    #[test]
    fn ipv6_only_forwarding() {
        let fake = fixture();
        for key in [
            "net.ipv4.ip_forward",
            "net.ipv6.conf.all.forwarding",
            "net/ipv6/conf/eth0/accept_ra",
        ] {
            fake.0.borrow_mut().sysctls.insert(key.into(), "0".into());
        }
        let mut setup = NetworkSetup::new(fake.clone());
        setup
            .configure("vpn", None, Some("fd00::/96"), &["eth0".into()])
            .unwrap();
        drop(setup);
        let state = fake.0.borrow();
        assert_eq!(state.sysctls["net.ipv4.ip_forward"], "0");
        assert_eq!(state.sysctls["net.ipv6.conf.all.forwarding"], "1");
        assert_eq!(state.sysctls["net/ipv6/conf/eth0/accept_ra"], "0");
    }

    /// Executed by scripts/test-network-namespace.sh in a fresh netns only.
    #[cfg(target_os = "linux")]
    #[test]
    #[ignore = "requires root in an isolated Linux network namespace"]
    fn linux_network_namespace() {
        use std::process::Command;
        assert_eq!(
            std::env::var("VAULT_NETWORK_TEST_ISOLATED").as_deref(),
            Ok("1")
        );
        assert_ne!(
            std::fs::read_link("/proc/self/ns/net").unwrap(),
            std::fs::read_link("/proc/1/ns/net").unwrap()
        );
        for name in ["vpn0", "exit0", "lan0"] {
            let output = Command::new("ip")
                .args(["link", "add", name, "type", "dummy"])
                .output()
                .unwrap();
            assert!(
                output.status.success(),
                "{}",
                String::from_utf8_lossy(&output.stderr)
            );
        }
        for args in [
            vec!["link", "set", "exit0", "up"],
            vec!["route", "add", "default", "dev", "exit0"],
            vec!["link", "set", "lan0", "up"],
            vec!["address", "add", "192.168.50.1/24", "dev", "lan0"],
            vec!["-6", "address", "add", "fd50::1/64", "dev", "lan0"],
        ] {
            let output = Command::new("ip").args(args).output().unwrap();
            assert!(
                output.status.success(),
                "{}",
                String::from_utf8_lossy(&output.stderr)
            );
        }
        let mut detected = route_interfaces("vpn0", true, false).unwrap();
        detected.sort();
        assert_eq!(detected, ["exit0", "lan0"]);
        let mut backend = SystemBackend;
        backend.write_sysctl("net.ipv4.ip_forward", "0").unwrap();
        {
            let mut setup = NetworkSetup::new(SystemBackend);
            assert!(
                setup
                    .configure("vpn0", Some("10.0.0.0/24"), None, &["exit0".into()])
                    .is_ok()
            );
        }
        assert_eq!(backend.read_sysctl("net.ipv4.ip_forward").unwrap(), "1");
        // Apply custom settings after the initial IPv4 router transition.
        backend
            .write_sysctl("net/ipv6/conf/exit0/accept_ra", "2")
            .unwrap();
        backend
            .write_sysctl("net.ipv6.conf.all.forwarding", "1")
            .unwrap();
        backend.write_sysctl("net.ipv4.ip_forward", "1").unwrap();
        backend
            .write_sysctl("net.ipv4.conf.all.send_redirects", "1")
            .unwrap();
        backend
            .write_sysctl("net/ipv4/conf/exit0/rp_filter", "2")
            .unwrap();
        let keys = [
            "net.ipv4.ip_forward",
            "net.ipv4.conf.all.send_redirects",
            "net.ipv6.conf.all.forwarding",
            "net/ipv6/conf/exit0/accept_ra",
            "net/ipv4/conf/exit0/rp_filter",
            "net/ipv4/conf/vpn0/send_redirects",
            "net/ipv6/conf/vpn0/accept_redirects",
        ];
        let before: Vec<_> = keys
            .iter()
            .map(|k| backend.read_sysctl(k).unwrap())
            .collect();
        let exits = route_interfaces("vpn0", true, true).unwrap();
        assert!(exits.contains(&"lan0".to_owned()));
        {
            let mut setup = NetworkSetup::new(SystemBackend);
            setup
                .configure("vpn0", Some("10.0.0.0/24"), Some("fd00::/96"), &exits)
                .unwrap();
            for (program, cidr) in [("iptables", "10.0.0.0/24"), ("ip6tables", "fd00::/96")] {
                for rule in tunnel_rules(program, "vpn0", cidr, &exits) {
                    assert!(backend.has_rule(&rule).unwrap());
                }
            }
            assert_eq!(
                backend
                    .read_sysctl("net/ipv6/conf/exit0/accept_ra")
                    .unwrap(),
                "2"
            );
        }
        let after: Vec<_> = keys
            .iter()
            .map(|k| backend.read_sysctl(k).unwrap())
            .collect();
        assert_eq!(before, after);
        for (program, cidr) in [("iptables", "10.0.0.0/24"), ("ip6tables", "fd00::/96")] {
            for rule in tunnel_rules(program, "vpn0", cidr, &exits) {
                assert!(!backend.has_rule(&rule).unwrap());
            }
        }
        // A LAN-only server needs no default route. Feed actual discovery
        // into setup and verify both forwarding and NAT, not just parsing.
        let output = Command::new("ip")
            .args(["route", "del", "default", "dev", "exit0"])
            .output()
            .unwrap();
        assert!(output.status.success());
        let exits = route_interfaces("vpn0", true, false).unwrap();
        assert_eq!(exits, ["lan0"]);
        {
            let mut setup = NetworkSetup::new(SystemBackend);
            setup
                .configure("vpn0", Some("10.0.0.0/24"), None, &exits)
                .unwrap();
            for rule in tunnel_rules("iptables", "vpn0", "10.0.0.0/24", &exits) {
                assert!(backend.has_rule(&rule).unwrap());
            }
        }
        for rule in tunnel_rules("iptables", "vpn0", "10.0.0.0/24", &exits) {
            assert!(!backend.has_rule(&rule).unwrap());
        }
    }

    #[test]
    fn isolated_instance_cleanup() {
        let fake = fixture();
        let host_before = fake.0.borrow().sysctls.clone();
        let exits = vec!["eth0".into()];
        let mut a = NetworkSetup::new(fake.clone());
        a.configure("vpn.1", Some("10.1.0.0/24"), Some("fd01::/96"), &exits)
            .unwrap();
        let mut b = NetworkSetup::new(fake.clone());
        b.configure("vpn.2", Some("10.2.0.0/24"), Some("fd02::/96"), &exits)
            .unwrap();
        drop(a);
        for (program, cidr) in [("iptables", "10.2.0.0/24"), ("ip6tables", "fd02::/96")] {
            for rule in tunnel_rules(program, "vpn.2", cidr, &exits) {
                assert!(fake.0.borrow().rules.contains(&rule));
            }
        }
        for (key, value) in &host_before {
            assert_eq!(fake.0.borrow().sysctls.get(key), Some(value));
        }
        drop(b);
        assert!(fake.0.borrow().rules.is_empty());
        for (key, value) in &host_before {
            assert_eq!(fake.0.borrow().sysctls.get(key), Some(value));
        }
    }
}
