// SPDX-License-Identifier: MIT
//! DNS is scoped to the VPN link through systemd-resolved; other resolvers are manual.

use std::net::IpAddr;
use std::path::Path;
use std::process::{Command, Output, Stdio};
use std::time::{Duration, Instant};

use anyhow::Context;

fn resolved_file(path: &Path) -> bool {
    std::fs::read_to_string(path).is_ok_and(|text| {
        let mut found = false;
        for line in text.lines() {
            let mut words = line.split_whitespace();
            if words.next() == Some("nameserver") {
                if !matches!(words.next(), Some("127.0.0.53" | "127.0.0.54")) {
                    return false;
                }
                found = true;
            }
        }
        found
    })
}

fn bounded_output(command: &mut Command, timeout: Duration) -> anyhow::Result<Output> {
    let mut child = command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .context("start DNS command")?;
    let started = Instant::now();
    loop {
        match child.try_wait() {
            Ok(Some(_)) => {
                return child
                    .wait_with_output()
                    .context("collect DNS command output");
            }
            Ok(None) if started.elapsed() < timeout => {
                std::thread::sleep(Duration::from_millis(20))
            }
            result => {
                let _ = child.kill();
                let _ = child.wait();
                return match result {
                    Err(error) => Err(error).context("wait for DNS command"),
                    _ => Err(anyhow::anyhow!(
                        "DNS command timed out after {}ms",
                        timeout.as_millis()
                    )),
                };
            }
        }
    }
}

fn resolvectl(args: &[String]) -> anyhow::Result<String> {
    let mut command = Command::new("resolvectl");
    command.arg("--no-pager").args(args).env("LC_ALL", "C");
    let output =
        bounded_output(&mut command, Duration::from_secs(2)).context("execute resolvectl")?;
    let output = vault_core::util::successful_output(&command, output)?;
    Ok(String::from_utf8(output.stdout)?)
}

fn validate_servers(servers: &[String]) -> anyhow::Result<()> {
    for server in servers {
        server
            .parse::<IpAddr>()
            .with_context(|| format!("invalid DNS server address: {server}"))?;
    }
    Ok(())
}

struct ResolvedDns {
    link: String,
    servers: Vec<String>,
    applied: bool,
    flush_pending: bool,
}

impl ResolvedDns {
    fn ensure_with(
        &mut self,
        mut run: impl FnMut(&[String]) -> anyhow::Result<String>,
    ) -> anyhow::Result<bool> {
        let dns = run(&["dns".into(), self.link.clone()])?;
        let domains = run(&["domain".into(), self.link.clone()])?;
        let values = |text: &str| -> Vec<String> {
            text.split_once(':')
                .map_or("", |(_, values)| values)
                .split_whitespace()
                .map(str::to_string)
                .collect()
        };
        let actual: Vec<IpAddr> = values(&dns)
            .iter()
            .filter_map(|ip| ip.parse().ok())
            .collect();
        let expected: Vec<IpAddr> = self.servers.iter().map(|ip| ip.parse().unwrap()).collect();
        let changed = !self.applied || actual != expected || values(&domains) != ["~."];
        if changed {
            // Arm cleanup before the first mutation, including partial failures.
            self.applied = true;
            self.flush_pending = true;
            let mut args = vec!["dns".into(), self.link.clone()];
            args.extend(self.servers.clone());
            run(&args)?;
            run(&["domain".into(), self.link.clone(), "~.".into()])?;
        }
        if self.flush_pending {
            run(&["flush-caches".into()])?;
            self.flush_pending = false;
        }
        Ok(changed)
    }

    fn restore_with(
        &mut self,
        mut run: impl FnMut(&[String]) -> anyhow::Result<String>,
    ) -> anyhow::Result<()> {
        if self.applied {
            run(&["revert".into(), self.link.clone()])?;
            self.applied = false;
        }
        Ok(())
    }
}

pub struct DnsGuard {
    resolved: Option<ResolvedDns>,
}

impl DnsGuard {
    #[cfg(target_os = "linux")]
    pub fn setup_for_interface(link: &str) -> Self {
        Self::setup_with(Path::new("/etc/resolv.conf"), link, resolvectl)
    }

    fn setup_with(
        live: &Path,
        link: &str,
        mut run: impl FnMut(&[String]) -> anyhow::Result<String>,
    ) -> Self {
        if resolved_file(live) {
            // Keep the availability probe independent of interface count.
            match run(&["statistics".into()]) {
                Ok(_) => {
                    tracing::info!("Using systemd-resolved DNS configuration for {link}");
                    return Self {
                        resolved: Some(ResolvedDns {
                            link: link.into(),
                            servers: Vec::new(),
                            applied: false,
                            flush_pending: false,
                        }),
                    };
                }
                Err(error) => {
                    tracing::warn!("Automatic DNS unavailable: {error:#}; configure DNS manually")
                }
            }
        } else {
            tracing::warn!(
                "System resolver does not use the systemd-resolved stub; configure DNS manually"
            );
        }
        Self { resolved: None }
    }

    pub fn set_servers(&mut self, servers: &[String]) -> anyhow::Result<()> {
        anyhow::ensure!(!servers.is_empty(), "no DNS servers selected");
        validate_servers(servers)?;
        if let Some(resolved) = &mut self.resolved {
            resolved.servers = servers.to_vec();
        }
        Ok(())
    }

    pub fn ensure_applied(&mut self) -> anyhow::Result<bool> {
        match &mut self.resolved {
            Some(resolved) if !resolved.servers.is_empty() => resolved.ensure_with(resolvectl),
            _ => Ok(false),
        }
    }

    pub fn restore(&mut self) -> anyhow::Result<()> {
        if let Some(resolved) = &mut self.resolved {
            resolved.restore_with(resolvectl)?;
        }
        self.resolved = None;
        Ok(())
    }
}

impl Drop for DnsGuard {
    fn drop(&mut self) {
        if let Err(e) = self.restore() {
            tracing::error!("Could not clear VPN interface DNS: {e:#}");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicUsize, Ordering};

    struct Fixture {
        dir: PathBuf,
        live: PathBuf,
    }
    impl Fixture {
        fn new() -> Self {
            static NEXT: AtomicUsize = AtomicUsize::new(0);
            let dir = std::env::temp_dir().join(format!(
                "vault-dns-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            std::fs::create_dir(&dir).unwrap();
            let live = dir.join("resolv.conf");
            std::fs::write(&live, "nameserver 192.0.2.1\n").unwrap();
            Self { dir, live }
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.dir);
        }
    }

    #[test]
    fn manual_dns() {
        let fixture = Fixture::new();
        let backup = fixture.dir.join("backup");
        std::fs::write(&backup, "old DNS").unwrap();
        for current in ["nameserver 192.0.2.1\n", "nameserver 198.51.100.53\n"] {
            std::fs::write(&fixture.live, current).unwrap();
            let mut guard = DnsGuard::setup_with(&fixture.live, "vpn", |_| {
                panic!("manual DNS must not call resolvectl")
            });
            guard.set_servers(&["1.1.1.1".into()]).unwrap();
            assert!(!guard.ensure_applied().unwrap());
            guard.set_servers(&["2001:4860:4860::8888".into()]).unwrap();
            assert!(!guard.ensure_applied().unwrap());
            guard.restore().unwrap();
            drop(guard);
            assert_eq!(std::fs::read_to_string(&fixture.live).unwrap(), current);
            assert_eq!(std::fs::read_to_string(&backup).unwrap(), "old DNS");
        }
    }

    #[test]
    fn resolved_setup() {
        let fixture = Fixture::new();
        for (content, expected) in [
            ("nameserver 127.0.0.53\noptions edns0 trust-ad\n", true),
            ("nameserver 127.0.0.54\n", true),
            ("nameserver 127.0.0.53\nnameserver 192.0.2.1\n", false),
            ("nameserver 192.0.2.1\n", false),
            ("# nameserver 127.0.0.53\n", false),
            ("", false),
        ] {
            std::fs::write(&fixture.live, content).unwrap();
            let mut guard = DnsGuard::setup_with(&fixture.live, "vpn", |args| {
                assert!(expected);
                assert_eq!(args, ["statistics"]);
                Ok(String::new())
            });
            assert_eq!(guard.resolved.is_some(), expected);
            assert!(!guard.ensure_applied().unwrap());
            assert!(guard.set_servers(&[]).is_err());
            assert!(guard.set_servers(&["invalid".into()]).is_err());
            drop(guard);
            assert_eq!(std::fs::read_to_string(&fixture.live).unwrap(), content);
        }
        std::fs::write(&fixture.live, "nameserver 127.0.0.53\n").unwrap();
        let mut guard = DnsGuard::setup_with(&fixture.live, "vpn", |_| {
            anyhow::bail!("resolvectl or daemon unavailable")
        });
        assert!(guard.resolved.is_none());
        guard.set_servers(&["1.1.1.1".into()]).unwrap();
        assert!(!guard.ensure_applied().unwrap());
    }

    #[derive(Default)]
    struct FakeResolved {
        servers: String,
        domains: String,
        calls: Vec<String>,
        fail_domain: bool,
    }

    impl FakeResolved {
        fn run(&mut self, args: &[String]) -> anyhow::Result<String> {
            self.calls.push(args.join(" "));
            match args[0].as_str() {
                "dns" if args.len() == 2 => Ok(format!("Link 6 (vpn): {}", self.servers)),
                "domain" if args.len() == 2 => Ok(format!("Link 6 (vpn): {}", self.domains)),
                "dns" => {
                    self.servers = args[2..].join(" ");
                    Ok(String::new())
                }
                "domain" => {
                    anyhow::ensure!(!self.fail_domain, "injected domain failure");
                    self.domains = args[2..].join(" ");
                    Ok(String::new())
                }
                "flush-caches" => Ok(String::new()),
                "revert" => {
                    self.servers.clear();
                    self.domains.clear();
                    Ok(String::new())
                }
                _ => panic!("unexpected resolvectl arguments: {args:?}"),
            }
        }
    }

    fn resolved_fixture() -> ResolvedDns {
        ResolvedDns {
            link: "vpn".into(),
            servers: vec!["1.1.1.1".into()],
            applied: false,
            flush_pending: false,
        }
    }

    #[test]
    fn resolved_switch() {
        let mut dns = resolved_fixture();
        let mut system = FakeResolved::default();
        dns.ensure_with(|args| system.run(args)).unwrap();
        dns.servers = vec!["2001:4860:4860::8888".into()];
        assert!(dns.ensure_with(|args| system.run(args)).unwrap());
        assert_eq!(system.servers, "2001:4860:4860::8888");
        dns.restore_with(|args| system.run(args)).unwrap();
        assert!(system.servers.is_empty());
    }

    #[test]
    fn resolved_reconnect() {
        let mut dns = resolved_fixture();
        let mut system = FakeResolved::default();
        assert!(dns.ensure_with(|args| system.run(args)).unwrap());
        assert_eq!(system.servers, "1.1.1.1");
        assert_eq!(system.domains, "~.");
        let initial_flushes = system
            .calls
            .iter()
            .filter(|call| *call == "flush-caches")
            .count();
        assert!(!dns.ensure_with(|args| system.run(args)).unwrap());
        assert_eq!(
            system
                .calls
                .iter()
                .filter(|call| *call == "flush-caches")
                .count(),
            initial_flushes
        );
        // Simulate loss of link DNS after network reconfiguration.
        system.servers.clear();
        assert!(dns.ensure_with(|args| system.run(args)).unwrap());
        system.domains.clear();
        assert!(dns.ensure_with(|args| system.run(args)).unwrap());
        dns.restore_with(|args| system.run(args)).unwrap();
        dns.restore_with(|args| system.run(args)).unwrap();
        assert_eq!(
            system
                .calls
                .iter()
                .filter(|call| *call == "revert vpn")
                .count(),
            1
        );
        assert!(system.calls.iter().all(|call| !call.contains("wlo1")));
    }

    #[test]
    fn command_timeout() {
        let started = Instant::now();
        let error = bounded_output(
            Command::new("sh").args(["-c", "exec sleep 5"]),
            Duration::from_millis(100),
        )
        .unwrap_err();
        assert!(error.to_string().contains("timed out"));
        assert!(started.elapsed() < Duration::from_secs(2));
        let output = bounded_output(
            Command::new("sh").args(["-c", "printf ready"]),
            Duration::from_secs(2),
        )
        .unwrap();
        assert!(output.status.success());
        assert_eq!(output.stdout, b"ready");
    }

    #[test]
    fn resolved_retry() {
        let mut dns = resolved_fixture();
        let mut system = FakeResolved {
            fail_domain: true,
            ..Default::default()
        };
        assert!(dns.ensure_with(|args| system.run(args)).is_err());
        system.fail_domain = false;
        assert!(dns.ensure_with(|args| system.run(args)).unwrap());
        assert_eq!(system.servers, "1.1.1.1");
        assert_eq!(system.domains, "~.");
        assert!(!dns.ensure_with(|args| system.run(args)).unwrap());
    }

    #[test]
    fn resolved_partial_failure() {
        let mut dns = resolved_fixture();
        let mut system = FakeResolved {
            fail_domain: true,
            ..Default::default()
        };
        assert!(dns.ensure_with(|args| system.run(args)).is_err());
        assert_eq!(system.servers, "1.1.1.1");
        dns.restore_with(|args| system.run(args)).unwrap();
        assert!(system.servers.is_empty());
    }
}
