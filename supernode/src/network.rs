// SPDX-License-Identifier: MIT
//! Host network setup and Linux socket configuration/sampling.
use std::{
    io,
    net::{SocketAddr, UdpSocket},
    time::{Duration, Instant},
};

#[cfg(target_os = "linux")]
use anyhow::Context;
use vault_core::Buffer;
#[cfg(any(target_os = "linux", test))]
use vault_core::metrics::forwarding::SocketSample;

#[cfg(target_os = "linux")]
const UDP_BUFFER_BYTES: usize = 2 * 1024 * 1024;
const UDP_BATCH_PACKETS: usize = 32;
const UDP_BATCH_TIME: Duration = Duration::from_millis(1);

#[cfg(target_os = "linux")]
pub(crate) fn configure_udp_buffers(socket: &UdpSocket) -> anyhow::Result<()> {
    let socket = socket2::SockRef::from(socket);
    // Leave buffers already at or above the target unchanged. Linux reports
    // twice the requested size; smaller buffers are subject to kernel caps.
    if socket
        .recv_buffer_size()
        .context("read UDP receive buffer")?
        < UDP_BUFFER_BYTES * 2
    {
        socket
            .set_recv_buffer_size(UDP_BUFFER_BYTES)
            .context("set UDP receive buffer")?;
    }
    if socket.send_buffer_size().context("read UDP send buffer")? < UDP_BUFFER_BYTES * 2 {
        socket
            .set_send_buffer_size(UDP_BUFFER_BYTES)
            .context("set UDP send buffer")?;
    }
    let recv_bytes = socket
        .recv_buffer_size()
        .context("read UDP receive buffer")?;
    let send_bytes = socket.send_buffer_size().context("read UDP send buffer")?;
    // Linux doubles the requested size for bookkeeping, after applying the
    // rmem_max/wmem_max caps. Report getsockopt values, as shown by ss -m.
    if recv_bytes < UDP_BUFFER_BYTES * 2 || send_bytes < UDP_BUFFER_BYTES * 2 {
        tracing::warn!(
            requested_bytes = UDP_BUFFER_BYTES,
            recv_bytes,
            send_bytes,
            "UDP socket buffers limited by kernel; check net.core.rmem_max and net.core.wmem_max"
        );
    } else {
        tracing::info!(
            requested_bytes = UDP_BUFFER_BYTES,
            recv_bytes,
            send_bytes,
            "UDP socket buffers configured"
        );
    }
    Ok(())
}

/// Drain a nonblocking socket, yielding to TUN/maintenance after a bounded burst.
/// The callback gets the receive start time for per-packet handling metrics.
pub(crate) fn recv_batch(
    socket: &UdpSocket,
    buffer: &mut Buffer,
    mut handle: impl FnMut(&mut Buffer, SocketAddr, Instant),
) -> io::Result<()> {
    let batch_started = Instant::now();
    for _ in 0..UDP_BATCH_PACKETS {
        let started = Instant::now();
        buffer.clear();
        match socket.recv_from(buffer.buffer()) {
            Ok((size, addr)) => {
                buffer.set_length(size);
                handle(buffer, addr, started);
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => break,
            Err(error) => return Err(error),
        }
        // A packet already in progress (e.g. a handshake) cannot be preempted.
        if batch_started.elapsed() >= UDP_BATCH_TIME {
            break;
        }
    }
    Ok(())
}

// Keep /proc access in the server; shared metrics only consume the sample.
#[cfg(target_os = "linux")]
pub(crate) fn udp_socket_sample(inode: u64) -> Option<SocketSample> {
    for path in ["/proc/net/udp", "/proc/net/udp6"] {
        if let Ok(text) = std::fs::read_to_string(path)
            && let Some(sample) = parse_socket(&text, inode)
        {
            return Some(sample);
        }
    }
    None
}

// Linux udp4_format_sock()/udp6_seq_show(): queues are socket memory accounting,
// not payload bytes or queue peaks; sk_drops includes more than buffer overflow.
#[cfg(any(target_os = "linux", test))]
fn parse_socket(text: &str, inode: u64) -> Option<SocketSample> {
    text.lines().find_map(|line| {
        let mut fields = line.split_whitespace();
        let (tx, rx) = fields.nth(4)?.split_once(':')?;
        if fields.nth(4)?.parse::<u64>().ok()? != inode {
            return None;
        }
        Some(SocketSample {
            drops: fields.nth(2)?.parse().ok()?,
            rx_queue: u64::from_str_radix(rx, 16).ok()?,
            tx_queue: u64::from_str_radix(tx, 16).ok()?,
        })
    })
}

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
            // Apply after enabling forwarding. Linux uses max(all, interface),
            // so an administrator's all=2 keeps loose filtering effective.
            // Never alter all/default or any uplink's reverse-path policy.
            self.set_sysctl(&format!("net/ipv4/conf/{tun}/rp_filter"), "1")?;
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
        vault_core::util::checked_output(std::process::Command::new(rule.program).args(&args))?;
        Ok(())
    }

    fn read_sysctl(&mut self, key: &str) -> anyhow::Result<String> {
        let output = vault_core::util::checked_output(
            std::process::Command::new("sysctl").args(["-n", key]),
        )?;
        Ok(String::from_utf8(output.stdout)?.trim().into())
    }

    fn write_sysctl(&mut self, key: &str, value: &str) -> anyhow::Result<()> {
        vault_core::util::checked_output(
            std::process::Command::new("sysctl").args(["-w", &format!("{key}={value}")]),
        )?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{cell::RefCell, collections::HashMap, rc::Rc};

    const V4: &str = "10.0.0.0/24";
    const V6: &str = "fd00::/96";

    fn wait_for_packet(socket: &UdpSocket) {
        socket.set_nonblocking(false).unwrap();
        socket
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        // A non-empty peek buffer waits for a datagram and leaves it queued,
        // including a zero-length datagram.
        socket
            .peek_from(&mut [0; 1])
            .expect("UDP packet did not arrive");
        socket.set_nonblocking(true).unwrap();
    }

    #[test]
    fn receive_burst() {
        let receiver = UdpSocket::bind("127.0.0.1:0").unwrap();
        receiver.set_nonblocking(true).unwrap();
        let sender = UdpSocket::bind("127.0.0.1:0").unwrap();
        let address = receiver.local_addr().unwrap();
        for value in 0..65_u8 {
            sender.send_to(&[value], address).unwrap();
        }

        let mut buffer = Buffer::new(128);
        let capacity = buffer.buffer().len();
        let mut received = 0_u8;
        while received < 65 {
            wait_for_packet(&receiver);
            let before = received;
            recv_batch(&receiver, &mut buffer, |buffer, source, _| {
                assert_eq!(source, sender.local_addr().unwrap());
                assert_eq!(buffer.buffer().len(), capacity);
                assert_eq!(buffer.as_ref(), &[received]);
                // Packet parsing advances the cursor; the next receive must
                // restore it, including across batch boundaries.
                buffer.take_prefix();
                received += 1;
            })
            .unwrap();
            assert!(received > before);
            assert!(usize::from(received - before) <= UDP_BATCH_PACKETS);
        }
        recv_batch(&receiver, &mut buffer, |_, _, _| {
            panic!("empty socket must not invoke the handler")
        })
        .unwrap();
    }

    #[test]
    fn receive_empty() {
        let receiver = UdpSocket::bind("127.0.0.1:0").unwrap();
        receiver.set_nonblocking(true).unwrap();
        let sender = UdpSocket::bind("127.0.0.1:0").unwrap();
        let packets: [&[u8]; 3] = [&[0xaa; 64], &[], &[0xbb; 128]];
        for packet in packets {
            sender
                .send_to(packet, receiver.local_addr().unwrap())
                .unwrap();
        }
        let mut buffer = Buffer::new(128);
        let mut received = 0;
        while received < packets.len() {
            wait_for_packet(&receiver);
            let before = received;
            recv_batch(&receiver, &mut buffer, |buffer, _, _| {
                assert_eq!(buffer.as_ref(), packets[received]);
                received += 1;
            })
            .unwrap();
            assert!(received > before);
        }
    }

    #[test]
    fn receive_yields() {
        let receiver = UdpSocket::bind("127.0.0.1:0").unwrap();
        receiver.set_nonblocking(true).unwrap();
        let sender = UdpSocket::bind("127.0.0.1:0").unwrap();
        for _ in 0..2 {
            sender
                .send_to(&[1], receiver.local_addr().unwrap())
                .unwrap();
        }
        let mut buffer = Buffer::new(128);
        let mut received = 0;
        wait_for_packet(&receiver);
        recv_batch(&receiver, &mut buffer, |_, _, _| {
            received += 1;
            if received == 1 {
                // Ensure time-budget yielding is tested with another packet ready.
                wait_for_packet(&receiver);
            }
            std::thread::sleep(UDP_BATCH_TIME + Duration::from_millis(1));
        })
        .unwrap();
        assert_eq!(received, 1);
        // Returning at the time limit leaves the next packet queued for a
        // later level-triggered readiness event.
        assert_eq!(receiver.recv_from(buffer.buffer()).unwrap().0, 1);
    }

    #[test]
    fn socket_rows() {
        let rows = "sl local_address rem_address st tx_queue rx_queue tr tm->when retrnsmt uid timeout inode ref pointer drops\n\
                    1: 00000000:4C47 00000000:0000 07 00000010:00000020 00:00000000 00000000 1000 0 123 2 0000000000000000 7\n\
                    2: 00000000000000000000000000000000:4C47 00000000000000000000000000000000:0000 07 00000030:00000040 00:00000000 00000000 1000 0 456 2 0000000000000000 9";
        assert_eq!(
            parse_socket(rows, 123),
            Some(SocketSample {
                drops: 7,
                rx_queue: 32,
                tx_queue: 16
            })
        );
        assert_eq!(
            parse_socket(rows, 456),
            Some(SocketSample {
                drops: 9,
                rx_queue: 64,
                tx_queue: 48
            })
        );
        assert_eq!(parse_socket(rows, 999), None);
        assert_eq!(parse_socket("1: malformed", 123), None);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn socket_probe() {
        use std::os::{fd::AsRawFd, unix::fs::MetadataExt};
        let socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let inode = std::fs::metadata(format!("/proc/self/fd/{}", socket.as_raw_fd()))
            .unwrap()
            .ino();
        let sample = udp_socket_sample(inode).expect("bound UDP socket appears in proc");
        assert_eq!(sample.drops, 0);
        assert_eq!(sample.rx_queue, 0);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn socket_buffers() {
        let socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let sockref = socket2::SockRef::from(&socket);
        sockref.set_recv_buffer_size(4096).unwrap();
        sockref.set_send_buffer_size(4096).unwrap();
        configure_udp_buffers(&socket).unwrap();

        for (actual, limit) in [
            (sockref.recv_buffer_size().unwrap(), "rmem_max"),
            (sockref.send_buffer_size().unwrap(), "wmem_max"),
        ] {
            let maximum: usize = std::fs::read_to_string(format!("/proc/sys/net/core/{limit}"))
                .unwrap()
                .trim()
                .parse()
                .unwrap();
            assert_eq!(actual, UDP_BUFFER_BYTES.min(maximum) * 2);
        }
    }

    #[derive(Default)]
    struct State {
        rules: Vec<Rule>,
        sysctls: HashMap<String, String>,
        reads: Vec<String>,
        writes: Vec<(String, String)>,
        calls: usize,
        fail_at: Option<usize>,
        fail_after_write: Option<String>,
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
            self.0.borrow_mut().reads.push(key.into());
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
            let owned_tun_setting = matches!(
                key.split('/').collect::<Vec<_>>().as_slice(),
                [
                    "net",
                    "ipv4",
                    "conf",
                    "vpn" | "vpn.1" | "vpn.2",
                    "rp_filter" | "send_redirects"
                ] | [
                    "net",
                    "ipv6",
                    "conf",
                    "vpn" | "vpn.1" | "vpn.2",
                    "accept_redirects"
                ]
            );
            assert!(
                owned_tun_setting
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
            if state.fail_after_write.as_deref() == Some(key) {
                state.fail_after_write = None;
                anyhow::bail!("injected failure after applying sysctl");
            }
            Ok(())
        }
    }
    fn fixture() -> Fake {
        let fake = Fake::default();
        fake.0.borrow_mut().sysctls.extend([
            ("net.ipv4.ip_forward".into(), "1".into()),
            ("net.ipv4.conf.all.send_redirects".into(), "1".into()),
            ("net.ipv6.conf.all.forwarding".into(), "1".into()),
            ("net/ipv6/conf/eth0/accept_ra".into(), "2".into()),
            ("net/ipv4/conf/all/rp_filter".into(), "0".into()),
            ("net/ipv4/conf/default/rp_filter".into(), "2".into()),
            ("net/ipv4/conf/eth0/rp_filter".into(), "2".into()),
            ("net/ipv4/conf/vpn/rp_filter".into(), "0".into()),
            ("net/ipv4/conf/vpn/send_redirects".into(), "1".into()),
            ("net/ipv6/conf/vpn/accept_redirects".into(), "1".into()),
        ]);
        fake
    }

    #[test]
    fn routes() {
        let v4 = "Iface Destination Gateway Flags RefCnt Use Metric Mask
eth0 00000000 0100000A 0003 0 0 0 00000000
br0 00000000 00000000 0001 0 0 10 00000000
bond0.100 00000000 00000000 0001 0 0 20 00000000
vpn0 00000000 00000000 0001 0 0 0 00000000
lo 00000000 00000000 0001 0 0 0 00000000
down0 00000000 00000000 0000 0 0 0 00000000
reject0 00000000 00000000 0201 0 0 0 00000000
lan0 0001A8C0 00000000 0001 0 0 0 00FFFFFF
lan0 000010AC 0101A8C0 0003 0 0 0 0000FFFF";
        let zero = "00000000000000000000000000000000";
        let v6 = format!(
            "{zero} 00 {zero} 00 {zero} 64 0 0 00000001 eth0\n\
             {zero} 00 {zero} 00 {zero} 64 0 0 00000001 veth0\n\
             fd010000000000000000000000000000 40 {zero} 00 {zero} 64 0 0 00000001 lan6\n\
             fd020000000000000000000000000000 40 {zero} 00 {zero} 64 0 0 00000001 vpn0\n\
             fd030000000000000000000000000001 80 {zero} 00 {zero} 00 0 0 80000001 local6\n\
             {zero} 00 {zero} 00 {zero} ffffffff 0 0 00000201 reject6\n\
             {zero} 00 {zero} 00 {zero} 00 0 0 00000001 lo"
        );
        assert_eq!(
            parse_routes(v4, &v6, "vpn0"),
            ["eth0", "br0", "bond0.100", "lan0", "veth0", "lan6"]
        );
        assert!(parse_routes("garbage", "garbage", "vpn0").is_empty());
    }

    #[test]
    fn rpf_scope() {
        let key = "net/ipv4/conf/vpn/rp_filter";
        for global in ["0", "1", "2"] {
            for original in ["0", "1", "2"] {
                let fake = fixture();
                fake.0.borrow_mut().sysctls.extend([
                    ("net/ipv4/conf/all/rp_filter".into(), global.into()),
                    (key.into(), original.into()),
                ]);
                let before = fake.0.borrow().sysctls.clone();
                let mut active = before.clone();
                active.insert(key.into(), "1".into());
                active.insert("net/ipv4/conf/vpn/send_redirects".into(), "0".into());
                let mut setup = NetworkSetup::new(fake.clone());
                setup
                    .configure("vpn", Some(V4), None, &["eth0".into()])
                    .unwrap();
                assert_eq!(fake.0.borrow().sysctls, active);
                drop(setup);
                let state = fake.0.borrow();
                assert_eq!(state.sysctls, before);
                assert!(state.rules.is_empty());
                let writes: Vec<_> = state
                    .writes
                    .iter()
                    .filter(|(k, _)| k.ends_with("rp_filter"))
                    .cloned()
                    .collect();
                let expected = if original == "1" {
                    vec![]
                } else {
                    vec![(key.into(), "1".into()), (key.into(), original.into())]
                };
                assert_eq!(writes, expected);
            }
        }
    }

    #[test]
    fn rpf_restore() {
        let key = "net/ipv4/conf/vpn/rp_filter";
        for fail in [false, true] {
            let fake = fixture();
            let mut expected = fake.0.borrow().sysctls.clone();
            if fail {
                fake.0.borrow_mut().fail_after_write = Some(key.into());
            }
            let mut setup = NetworkSetup::new(fake.clone());
            assert_eq!(
                setup
                    .configure("vpn", Some(V4), None, &["eth0".into()])
                    .is_err(),
                fail
            );
            assert_eq!(fake.0.borrow().sysctls[key], "1");
            if !fail {
                // An administrator's later edit must survive cleanup.
                fake.0.borrow_mut().sysctls.insert(key.into(), "2".into());
                expected.insert(key.into(), "2".into());
            }
            drop(setup);
            assert_eq!(fake.0.borrow().sysctls, expected);
            assert!(fake.0.borrow().rules.is_empty());
        }
    }

    #[test]
    fn rollback() {
        let exits = vec!["eth0".into()];
        let existing = tunnel_rules("iptables", "vpn", V4, &exits)[0].clone();
        let probe = fixture();
        probe.0.borrow_mut().rules.push(existing.clone());
        let mut setup = NetworkSetup::new(probe.clone());
        setup.configure("vpn", Some(V4), Some(V6), &exits).unwrap();
        let startup_calls = probe.0.borrow().calls;
        drop(setup);
        // Exercise every read, check and mutation, including the optional read.
        for fail_at in 1..=startup_calls {
            let fake = fixture();
            fake.0.borrow_mut().rules.push(existing.clone());
            let original = fake.0.borrow().sysctls.clone();
            fake.0.borrow_mut().fail_at = Some(fail_at);
            let mut setup = NetworkSetup::new(fake.clone());
            let result = setup.configure("vpn", Some(V4), Some(V6), &exits);
            assert_eq!(result.is_ok(), fail_at == 3, "failure {fail_at}");
            drop(setup);
            let state = fake.0.borrow();
            assert_eq!(state.rules, vec![existing.clone()], "failure {fail_at}");
            assert_eq!(state.sysctls, original, "failure {fail_at}");
        }
    }

    #[test]
    fn rule_scope() {
        let exits = vec!["eth0".into()];
        for (program, cidr) in [("iptables", V4), ("ip6tables", V6)] {
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
    fn forwarding() {
        for ipv4 in [Some(V4), None] {
            let fake = fixture();
            fake.0.borrow_mut().sysctls.extend([
                ("net.ipv4.ip_forward".into(), "0".into()),
                ("net.ipv6.conf.all.forwarding".into(), "0".into()),
                (
                    "net/ipv6/conf/eth0/accept_ra".into(),
                    if ipv4.is_some() { "1" } else { "0" }.into(),
                ),
            ]);
            let mut expected = fake.0.borrow().sysctls.clone();
            expected.insert("net.ipv6.conf.all.forwarding".into(), "1".into());
            if ipv4.is_some() {
                expected.insert("net.ipv4.ip_forward".into(), "1".into());
                expected.insert("net/ipv6/conf/eth0/accept_ra".into(), "2".into());
            }
            let mut setup = NetworkSetup::new(fake.clone());
            setup
                .configure("vpn", ipv4, Some(V6), &["eth0".into()])
                .unwrap();
            drop(setup);
            let state = fake.0.borrow();
            assert!(state.rules.is_empty());
            assert_eq!(state.sysctls, expected);
            if ipv4.is_some() {
                assert_eq!(
                    state.writes[..4],
                    [
                        ("net.ipv4.ip_forward".into(), "1".into()),
                        ("net/ipv6/conf/eth0/accept_ra".into(), "2".into()),
                        ("net.ipv6.conf.all.forwarding".into(), "1".into()),
                        ("net/ipv4/conf/vpn/rp_filter".into(), "1".into()),
                    ]
                );
            } else {
                assert!(state.reads.iter().all(|key| !key.contains("ipv4")));
                assert!(state.writes.iter().all(|(key, _)| !key.contains("ipv4")));
            }
        }
    }

    #[test]
    fn forwarding_failure() {
        // Fail either the forwarding write or the subsequent TUN-local write.
        for fail_at in [2, 5] {
            let fake = fixture();
            fake.0
                .borrow_mut()
                .sysctls
                .insert("net.ipv4.ip_forward".into(), "0".into());
            let mut expected = fake.0.borrow().sysctls.clone();
            if fail_at == 5 {
                expected.insert("net.ipv4.ip_forward".into(), "1".into());
            }
            fake.0.borrow_mut().fail_at = Some(fail_at);
            let mut setup = NetworkSetup::new(fake.clone());
            assert!(
                setup
                    .configure("vpn", Some(V4), None, &["eth0".into()])
                    .is_err()
            );
            drop(setup);
            assert_eq!(fake.0.borrow().sysctls, expected);
            assert!(fake.0.borrow().rules.is_empty());
        }
    }

    /// Executed by scripts/test-network-namespace.sh in a fresh netns only.
    #[cfg(target_os = "linux")]
    #[test]
    #[ignore = "requires root in an isolated Linux network namespace"]
    fn netns_setup() {
        use std::process::Command;
        fn ip(args: &str) {
            vault_core::util::checked_output(Command::new("ip").args(args.split_whitespace()))
                .unwrap();
        }
        assert_eq!(
            std::env::var("VAULT_NETWORK_TEST_ISOLATED").as_deref(),
            Ok("1")
        );
        assert_ne!(
            std::fs::read_link("/proc/self/ns/net").unwrap(),
            std::fs::read_link("/proc/1/ns/net").unwrap()
        );
        for name in ["vpn0", "exit0", "lan0"] {
            ip(&format!("link add {name} type dummy"));
        }
        for args in [
            "link set exit0 up",
            "route add default dev exit0",
            "link set lan0 up",
            "address add 192.168.50.1/24 dev lan0",
            "-6 address add fd50::1/64 dev lan0",
        ] {
            ip(args);
        }
        let mut detected = route_interfaces("vpn0", true, false).unwrap();
        detected.sort();
        assert_eq!(detected, ["exit0", "lan0"]);
        let mut backend = SystemBackend;
        // Set custom reverse-path policy before each host-to-router transition,
        // including all=2 where the kernel's effective TUN mode stays loose.
        let host_rpf = [
            "net/ipv4/conf/all/rp_filter",
            "net/ipv4/conf/default/rp_filter",
            "net/ipv4/conf/exit0/rp_filter",
            "net/ipv4/conf/lan0/rp_filter",
            "net/ipv4/conf/lo/rp_filter",
        ];
        for global in ["0", "1", "2"] {
            backend.write_sysctl("net.ipv4.ip_forward", "0").unwrap();
            let original = [global, "2", "2", "0", "1"];
            for (key, value) in host_rpf.iter().zip(original) {
                backend.write_sysctl(key, value).unwrap();
            }
            backend
                .write_sysctl("net/ipv4/conf/vpn0/rp_filter", "0")
                .unwrap();
            {
                let mut setup = NetworkSetup::new(SystemBackend);
                setup
                    .configure("vpn0", Some(V4), None, &["exit0".into()])
                    .unwrap();
                assert_eq!(backend.read_sysctl("net.ipv4.ip_forward").unwrap(), "1");
                assert_eq!(
                    backend.read_sysctl("net/ipv4/conf/vpn0/rp_filter").unwrap(),
                    "1"
                );
                for (key, value) in host_rpf.iter().zip(original) {
                    assert_eq!(backend.read_sysctl(key).unwrap(), value, "{key}");
                }
            }
            assert_eq!(backend.read_sysctl("net.ipv4.ip_forward").unwrap(), "1");
            assert_eq!(
                backend.read_sysctl("net/ipv4/conf/vpn0/rp_filter").unwrap(),
                "0"
            );
            for (key, value) in host_rpf.iter().zip(original) {
                assert_eq!(backend.read_sysctl(key).unwrap(), value, "{key}");
            }
        }
        // Verify the combined IPv4/IPv6 setup and rollback with forwarding on.
        for (key, value) in [
            ("net/ipv6/conf/exit0/accept_ra", "2"),
            ("net.ipv6.conf.all.forwarding", "1"),
            ("net.ipv4.ip_forward", "1"),
            ("net.ipv4.conf.all.send_redirects", "1"),
            ("net/ipv4/conf/exit0/rp_filter", "2"),
        ] {
            backend.write_sysctl(key, value).unwrap();
        }
        let keys = [
            "net.ipv4.ip_forward",
            "net.ipv4.conf.all.send_redirects",
            "net.ipv6.conf.all.forwarding",
            "net/ipv6/conf/exit0/accept_ra",
            "net/ipv4/conf/all/rp_filter",
            "net/ipv4/conf/default/rp_filter",
            "net/ipv4/conf/exit0/rp_filter",
            "net/ipv4/conf/lan0/rp_filter",
            "net/ipv4/conf/lo/rp_filter",
            "net/ipv4/conf/vpn0/rp_filter",
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
            setup.configure("vpn0", Some(V4), Some(V6), &exits).unwrap();
            for (program, cidr) in [("iptables", V4), ("ip6tables", V6)] {
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
        for (program, cidr) in [("iptables", V4), ("ip6tables", V6)] {
            for rule in tunnel_rules(program, "vpn0", cidr, &exits) {
                assert!(!backend.has_rule(&rule).unwrap());
            }
        }
        // The LAN remains discoverable without a default route; its rules
        // were already installed and rolled back in the dual-stack case.
        ip("route del default dev exit0");
        assert_eq!(route_interfaces("vpn0", true, false).unwrap(), ["lan0"]);
    }

    #[test]
    fn isolated_cleanup() {
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
