// SPDX-License-Identifier: MIT
//! DNS changes have one owner and are restored on every return path.

use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::time::{Duration, Instant};

use anyhow::Context;

#[cfg(any(target_os = "linux", test))]
fn resolved_file(path: &Path) -> bool {
    std::fs::canonicalize(path).is_ok_and(|path| path.starts_with("/run/systemd/resolve"))
        || std::fs::read_to_string(path).is_ok_and(|text| {
            text.lines().any(|line| {
                let mut words = line.split_whitespace();
                words.next() == Some("nameserver")
                    && matches!(words.next(), Some("127.0.0.53" | "127.0.0.54"))
            })
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

fn resolv_conf(servers: &[String]) -> String {
    let mut content = String::from("search .\n");
    for server in servers {
        content.push_str(&format!("nameserver {server}\n"));
    }
    content
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

/// Publish only a complete, synced backup. A unique sibling temporary file
/// can be abandoned by SIGKILL without becoming a recovery source. Initial
/// publication refuses to overwrite a backup; refreshes replace it atomically.
fn publish_backup(
    backup: &Path,
    replace: bool,
    write: impl FnOnce(&mut std::fs::File) -> std::io::Result<()>,
) -> anyhow::Result<()> {
    let temporary = backup.with_extension(format!(
        "{}.tmp",
        hex::encode(vault_core::PeerId::default().0)
    ));
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&temporary)
        .context("create temporary DNS backup")?;
    let result = (|| -> anyhow::Result<()> {
        write(&mut file).context("write temporary DNS backup")?;
        file.sync_all().context("sync DNS recovery backup")?;
        if replace {
            std::fs::rename(&temporary, backup).context("replace DNS recovery backup")?;
        } else {
            std::fs::hard_link(&temporary, backup).context("publish DNS recovery backup")?;
        }
        Ok(())
    })();
    drop(file);
    // Once published, the final name refers to the same complete inode.
    // A leftover temporary name is harmless and never used for recovery.
    let _ = std::fs::remove_file(&temporary);
    result
}

pub struct DnsGuard {
    live: PathBuf,
    backup: PathBuf,
    original: Option<String>,
    configured: Option<String>,
    // None while our own write may be incomplete; do not adopt that as system DNS.
    last_applied: Option<String>,
    resolved: Option<ResolvedDns>,
}

impl DnsGuard {
    #[cfg(target_os = "linux")]
    pub fn setup_for_interface(
        live: &Path,
        backup: &Path,
        servers: &[String],
        link: &str,
    ) -> anyhow::Result<Self> {
        if !servers.is_empty() && resolved_file(live) {
            validate_servers(servers)?;
            tracing::info!("Using systemd-resolved DNS configuration for {link}");
            // Leave the resolver-managed stub file and Wi-Fi DNS untouched.
            // The link is created later; apply its DNS after IP assignment.
            return Ok(Self {
                live: live.into(),
                backup: backup.into(),
                original: None,
                configured: None,
                last_applied: None,
                resolved: Some(ResolvedDns {
                    link: link.into(),
                    servers: servers.to_vec(),
                    applied: false,
                    flush_pending: false,
                }),
            });
        }
        Self::setup(live, backup, servers)
    }
    pub fn restore_backup(live: &Path, backup: &Path) -> anyhow::Result<()> {
        let original = match std::fs::read_to_string(backup) {
            Ok(original) => original,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(e) => return Err(e).context("read DNS recovery backup"),
        };
        tracing::warn!("Restoring DNS backup from a previous run");
        // Preserve the only recovery copy if restoring the live file fails.
        std::fs::write(live, original).context("restore DNS recovery backup")?;
        std::fs::remove_file(backup).context("remove restored DNS backup")?;
        Ok(())
    }

    pub fn setup(live: &Path, backup: &Path, servers: &[String]) -> anyhow::Result<Self> {
        Self::setup_with(live, backup, servers, |path, content| {
            std::fs::write(path, content)
        })
    }

    fn setup_with(
        live: &Path,
        backup: &Path,
        servers: &[String],
        write_live: impl FnOnce(&Path, &str) -> std::io::Result<()>,
    ) -> anyhow::Result<Self> {
        let mut guard = Self {
            live: live.into(),
            backup: backup.into(),
            original: None,
            configured: None,
            last_applied: None,
            resolved: None,
        };
        if servers.is_empty() {
            return Ok(guard);
        }
        validate_servers(servers)?;
        let original = std::fs::read_to_string(live).context("read original DNS configuration")?;
        if let Some(parent) = backup.parent() {
            std::fs::create_dir_all(parent)?;
        }
        use std::io::Write;
        publish_backup(backup, false, |file| file.write_all(original.as_bytes()))?;
        // Arm before touching the live file, including partial-write errors.
        guard.original = Some(original);
        let content = resolv_conf(servers);
        guard.configured = Some(content.clone());
        write_live(live, &content).context("apply DNS configuration")?;
        guard.last_applied = Some(content);
        Ok(guard)
    }

    /// Change the active assignment without replacing the saved system DNS.
    pub fn set_servers(&mut self, servers: &[String]) -> anyhow::Result<()> {
        anyhow::ensure!(!servers.is_empty(), "no DNS servers selected");
        validate_servers(servers)?;
        if let Some(resolved) = &mut self.resolved {
            resolved.servers = servers.to_vec();
        } else {
            anyhow::ensure!(self.original.is_some(), "DNS guard is not configured");
            self.configured = Some(resolv_conf(servers));
        }
        Ok(())
    }

    fn remember_external(&mut self, current: &str) -> anyhow::Result<()> {
        if self
            .last_applied
            .as_deref()
            .is_some_and(|last| last != current)
            && self.original.as_deref() != Some(current)
        {
            use std::io::Write;
            publish_backup(&self.backup, true, |file| {
                file.write_all(current.as_bytes())
            })?;
            self.original = Some(current.to_owned());
        }
        Ok(())
    }

    /// Preserve observed network-manager updates before reapplying VPN DNS.
    pub fn ensure_applied(&mut self) -> anyhow::Result<bool> {
        self.ensure_applied_with(|path, content| std::fs::write(path, content))
    }

    fn ensure_applied_with(
        &mut self,
        write_live: impl FnOnce(&Path, &str) -> std::io::Result<()>,
    ) -> anyhow::Result<bool> {
        if let Some(resolved) = &mut self.resolved {
            return resolved.ensure_with(resolvectl);
        }
        let Some(configured) = self.configured.clone() else {
            return Ok(false);
        };
        let current =
            std::fs::read_to_string(&self.live).context("read current DNS configuration")?;
        self.remember_external(&current)?;
        if current == configured {
            self.last_applied = Some(current);
            return Ok(false);
        }
        self.last_applied = None;
        write_live(&self.live, &configured).context("reapply DNS configuration")?;
        self.last_applied = Some(configured);
        Ok(true)
    }

    pub fn restore(&mut self) -> anyhow::Result<()> {
        if let Some(resolved) = &mut self.resolved {
            resolved.restore_with(resolvectl)?;
        }
        self.resolved = None;
        if self.original.is_some() {
            let current = if self.last_applied.is_some() {
                match std::fs::read_to_string(&self.live) {
                    Ok(current) => {
                        self.remember_external(&current)?;
                        Some(current)
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
                    Err(error) => {
                        return Err(error).context("read DNS configuration before restore");
                    }
                }
            } else {
                None
            };
            let original = self.original.as_ref().unwrap();
            if current.as_deref() != Some(original.as_str()) {
                self.last_applied = None;
                std::fs::write(&self.live, original).context("restore system DNS configuration")?;
            }
            // If backup removal fails, a retry must still recognize external updates.
            self.last_applied = Some(original.clone());
            std::fs::remove_file(&self.backup).context("remove DNS recovery backup")?;
            self.original = None;
            self.configured = None;
            self.last_applied = None;
        }
        Ok(())
    }
}

impl Drop for DnsGuard {
    fn drop(&mut self) {
        if let Err(e) = self.restore() {
            tracing::error!("DNS rollback failed; recovery backup retained: {e:#}");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::sync::atomic::{AtomicUsize, Ordering};

    struct Fixture {
        dir: PathBuf,
        live: PathBuf,
        backup: PathBuf,
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
            let backup = dir.join("backup");
            std::fs::write(&live, "nameserver 192.0.2.1\n").unwrap();
            Self { dir, live, backup }
        }
        fn original(&self) {
            assert_eq!(
                std::fs::read_to_string(&self.live).unwrap(),
                "nameserver 192.0.2.1\n"
            );
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.dir);
        }
    }

    #[test]
    fn dns_switch() {
        let fixture = Fixture::new();
        let original = std::fs::read_to_string(&fixture.live).unwrap();
        let mut guard =
            DnsGuard::setup(&fixture.live, &fixture.backup, &["1.1.1.1".into()]).unwrap();
        guard.set_servers(&["2001:4860:4860::8888".into()]).unwrap();
        assert!(guard.ensure_applied().unwrap());
        assert!(
            std::fs::read_to_string(&fixture.live)
                .unwrap()
                .contains("2001:4860:4860::8888")
        );
        assert_eq!(std::fs::read_to_string(&fixture.backup).unwrap(), original);
        guard.restore().unwrap();
        assert_eq!(std::fs::read_to_string(&fixture.live).unwrap(), original);
    }

    #[test]
    fn init_error_restores_dns() {
        let fixture = Fixture::new();
        let result = (|| -> anyhow::Result<()> {
            let _guard = DnsGuard::setup(&fixture.live, &fixture.backup, &["1.1.1.1".into()])?;
            anyhow::bail!("TUN initialization or privilege drop failed");
        })();
        assert!(result.is_err());
        fixture.original();
        assert!(!fixture.backup.exists());
    }

    #[test]
    fn partial_apply_restores_original() {
        let fixture = Fixture::new();
        let result = DnsGuard::setup_with(
            &fixture.live,
            &fixture.backup,
            &["1.1.1.1".into()],
            |path, _| {
                std::fs::write(path, "partial")?;
                Err(std::io::Error::other("injected write failure"))
            },
        );
        assert!(result.is_err());
        fixture.original();
        assert!(!fixture.backup.exists());
    }

    #[test]
    fn incomplete_backup_invisible() {
        let fixture = Fixture::new();
        // A temporary file left by a killed process must not block startup.
        let orphan = fixture.backup.with_extension("previous-process.tmp");
        std::fs::write(&orphan, "partial").unwrap();
        let original = std::fs::read_to_string(&fixture.live).unwrap();
        publish_backup(&fixture.backup, false, |file| {
            file.write_all(&original.as_bytes()[..5])?;
            assert!(!fixture.backup.exists());
            DnsGuard::restore_backup(&fixture.live, &fixture.backup).unwrap();
            fixture.original();
            file.write_all(&original.as_bytes()[5..])
        })
        .unwrap();
        assert_eq!(std::fs::read_to_string(&fixture.backup).unwrap(), original);
        std::fs::write(&fixture.live, "modified\n").unwrap();
        DnsGuard::restore_backup(&fixture.live, &fixture.backup).unwrap();
        fixture.original();
        assert!(orphan.exists());
    }

    #[test]
    fn backup_never_partial_or_overwritten() {
        let fixture = Fixture::new();
        let result = publish_backup(&fixture.backup, false, |file| {
            file.write_all(b"partial")?;
            Err(std::io::Error::other("injected backup write failure"))
        });
        assert!(result.is_err());
        assert!(!fixture.backup.exists());
        fixture.original();
        assert_eq!(std::fs::read_dir(&fixture.dir).unwrap().count(), 1);

        std::fs::write(&fixture.backup, "saved\n").unwrap();
        assert!(
            publish_backup(&fixture.backup, false, |file| file
                .write_all(b"replacement\n"))
            .is_err()
        );
        assert_eq!(std::fs::read_to_string(&fixture.backup).unwrap(), "saved\n");
        fixture.original();
        assert_eq!(std::fs::read_dir(&fixture.dir).unwrap().count(), 2);
    }

    #[test]
    fn backup_refresh() {
        let fixture = Fixture::new();
        std::fs::write(&fixture.backup, "saved\n").unwrap();
        assert!(
            publish_backup(&fixture.backup, true, |file| {
                file.write_all(b"partial")?;
                Err(std::io::Error::other("injected backup write failure"))
            })
            .is_err()
        );
        assert_eq!(std::fs::read_to_string(&fixture.backup).unwrap(), "saved\n");
        publish_backup(&fixture.backup, true, |file| {
            file.write_all(b"new\n")?;
            assert_eq!(std::fs::read_to_string(&fixture.backup).unwrap(), "saved\n");
            Ok(())
        })
        .unwrap();
        assert_eq!(std::fs::read_to_string(&fixture.backup).unwrap(), "new\n");
        assert_eq!(std::fs::read_dir(&fixture.dir).unwrap().count(), 2);
    }

    #[test]
    fn reapply_dns() {
        let fixture = Fixture::new();
        let mut guard =
            DnsGuard::setup(&fixture.live, &fixture.backup, &["1.1.1.1".into()]).unwrap();
        let configured = std::fs::read_to_string(&fixture.live).unwrap();
        assert!(!guard.ensure_applied().unwrap());
        // Repeat to cover both a reconnect and a late DHCP rewrite after
        // the VPN handshake has already completed.
        let networks = [
            "search first.lan\nnameserver 192.168.1.1\noptions timeout:2\n",
            "search second.lan\nnameserver 192.168.2.1\noptions attempts:1\n",
        ];
        for network in networks {
            std::fs::write(&fixture.live, network).unwrap();
            assert!(guard.ensure_applied().unwrap());
            assert_eq!(std::fs::read_to_string(&fixture.live).unwrap(), configured);
            assert_eq!(std::fs::read_to_string(&fixture.backup).unwrap(), network);
            assert!(!guard.ensure_applied().unwrap());
        }
        guard.restore().unwrap();
        assert!(!guard.ensure_applied().unwrap());
        assert_eq!(std::fs::read_to_string(&fixture.live).unwrap(), networks[1]);
    }

    #[test]
    fn late_dns() {
        let fixture = Fixture::new();
        let mut guard =
            DnsGuard::setup(&fixture.live, &fixture.backup, &["1.1.1.1".into()]).unwrap();
        let network = "search new.lan\nnameserver 192.168.2.1\n";
        std::fs::write(&fixture.live, network).unwrap();
        guard.restore().unwrap();
        assert_eq!(std::fs::read_to_string(&fixture.live).unwrap(), network);
        assert!(!fixture.backup.exists());
    }

    #[test]
    fn backup_failure() {
        let fixture = Fixture::new();
        let original = std::fs::read_to_string(&fixture.live).unwrap();
        let mut guard =
            DnsGuard::setup(&fixture.live, &fixture.backup, &["1.1.1.1".into()]).unwrap();
        let network = "nameserver 192.168.2.1\n";
        std::fs::write(&fixture.live, network).unwrap();
        guard.backup = fixture.dir.join("missing/backup");
        assert!(guard.ensure_applied().is_err());
        assert_eq!(std::fs::read_to_string(&fixture.live).unwrap(), network);
        assert_eq!(std::fs::read_to_string(&fixture.backup).unwrap(), original);
        guard.backup = fixture.backup.clone();
        assert!(guard.ensure_applied().unwrap());
        assert_eq!(std::fs::read_to_string(&fixture.backup).unwrap(), network);
        guard.restore().unwrap();
        assert_eq!(std::fs::read_to_string(&fixture.live).unwrap(), network);
    }

    #[test]
    fn write_retry() {
        for (complete, retry) in [(false, false), (false, true), (true, true)] {
            let fixture = Fixture::new();
            let mut guard =
                DnsGuard::setup(&fixture.live, &fixture.backup, &["1.1.1.1".into()]).unwrap();
            let mut network = "nameserver 192.168.2.1\n";
            std::fs::write(&fixture.live, network).unwrap();
            assert!(
                guard
                    .ensure_applied_with(|path, content| {
                        std::fs::write(path, if complete { content } else { "partial" })?;
                        Err(std::io::Error::other("injected DNS write failure"))
                    })
                    .is_err()
            );
            assert_eq!(std::fs::read_to_string(&fixture.backup).unwrap(), network);
            if retry {
                assert_eq!(guard.ensure_applied().unwrap(), !complete);
                network = "nameserver 192.168.3.1\n";
                std::fs::write(&fixture.live, network).unwrap();
                assert!(guard.ensure_applied().unwrap());
                assert_eq!(std::fs::read_to_string(&fixture.backup).unwrap(), network);
            }
            guard.restore().unwrap();
            assert_eq!(std::fs::read_to_string(&fixture.live).unwrap(), network);
            assert!(!fixture.backup.exists());
        }
    }

    #[test]
    fn restore_retry() {
        let fixture = Fixture::new();
        let mut guard =
            DnsGuard::setup(&fixture.live, &fixture.backup, &["1.1.1.1".into()]).unwrap();
        // Fail backup removal after the original DNS has been restored.
        guard.backup = fixture.dir.clone();
        assert!(guard.restore().is_err());
        fixture.original();
        let network = "nameserver 192.168.2.1\n";
        std::fs::write(&fixture.live, network).unwrap();
        guard.backup = fixture.backup.clone();
        guard.restore().unwrap();
        assert_eq!(std::fs::read_to_string(&fixture.live).unwrap(), network);
        assert!(!fixture.backup.exists());
    }

    #[test]
    fn reapply_disabled() {
        let fixture = Fixture::new();
        let mut guard = DnsGuard::setup(&fixture.live, &fixture.backup, &[]).unwrap();
        std::fs::write(&fixture.live, "nameserver 192.168.1.1\n").unwrap();
        assert!(!guard.ensure_applied().unwrap());
        assert_eq!(
            std::fs::read_to_string(&fixture.live).unwrap(),
            "nameserver 192.168.1.1\n"
        );
        assert!(!fixture.backup.exists());
    }

    #[test]
    fn resolved_stub() {
        let fixture = Fixture::new();
        assert!(!resolved_file(&fixture.live));
        std::fs::write(
            &fixture.live,
            "nameserver 127.0.0.53\noptions edns0 trust-ad\n",
        )
        .unwrap();
        assert!(resolved_file(&fixture.live));
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

    #[test]
    fn recovery_failure_keeps_backup() {
        let fixture = Fixture::new();
        std::fs::write(&fixture.backup, "saved\n").unwrap();
        assert!(DnsGuard::restore_backup(&fixture.dir, &fixture.backup).is_err());
        assert_eq!(std::fs::read_to_string(&fixture.backup).unwrap(), "saved\n");
        DnsGuard::restore_backup(&fixture.live, &fixture.backup).unwrap();
        assert_eq!(std::fs::read_to_string(&fixture.live).unwrap(), "saved\n");
        assert!(!fixture.backup.exists());
    }

    #[test]
    fn rollback_failure_keeps_backup() {
        let fixture = Fixture::new();
        let mut guard =
            DnsGuard::setup(&fixture.live, &fixture.backup, &["1.1.1.1".into()]).unwrap();
        std::fs::remove_file(&fixture.live).unwrap();
        std::fs::create_dir(&fixture.live).unwrap();
        assert!(guard.restore().is_err());
        assert_eq!(
            std::fs::read_to_string(&fixture.backup).unwrap(),
            "nameserver 192.0.2.1\n"
        );
        std::fs::remove_dir(&fixture.live).unwrap();
        guard.restore().unwrap();
        fixture.original();
        assert!(!fixture.backup.exists());
    }

    #[test]
    fn idempotent_restore_keeps_changes() {
        let fixture = Fixture::new();
        let mut guard = DnsGuard::setup(&fixture.live, &fixture.backup, &[]).unwrap();
        std::fs::write(&fixture.live, "external\n").unwrap();
        guard.restore().unwrap();
        assert_eq!(
            std::fs::read_to_string(&fixture.live).unwrap(),
            "external\n"
        );
        let mut guard =
            DnsGuard::setup(&fixture.live, &fixture.backup, &["1.1.1.1".into()]).unwrap();
        guard.restore().unwrap();
        std::fs::write(&fixture.live, "new external\n").unwrap();
        guard.restore().unwrap();
        drop(guard);
        assert_eq!(
            std::fs::read_to_string(&fixture.live).unwrap(),
            "new external\n"
        );
    }
}
