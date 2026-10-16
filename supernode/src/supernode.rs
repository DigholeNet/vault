// SPDX-License-Identifier: MIT
use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::{
    net::{IpAddr, Ipv6Addr, SocketAddr, UdpSocket},
    os::fd::AsRawFd,
    sync::Arc,
};
use tracing::{debug, error, info, warn};
use vault_core::device::{Address, DeviceType, Ipv4, Ipv6, parse};
use vault_core::{
    Algorithm, Buffer, CryptoCore, Handshake, PROTOCOL_VERSION, Peer, PeerId, Peers, Role,
    SysSignal, Time, TimeSource, WaitImpl, WaitResult, create_ecdh_keypair,
    device::{self, TunTapDevice},
    pake, protocol, select_algorithm, supported_algorithms,
    util::{self, mapped_addr},
};

use crate::config::SuperNodeConfig;
use crate::ip::{IpManager, Ipv4Cidr, Ipv4Pool, Ipv6Cidr, Ipv6Pool};
use crate::limiter::{InitLimiter, MAX_TRACKED_ENTRIES};

/// Peers idle longer than this are dropped from the routing tables; the IP
/// lease (300s) survives so a reconnecting peer reuses its old address.
const PEER_IDLE_TIMEOUT_SECS: Time = 60;
/// How long a per-client handshake timestamp is remembered for replay
/// suppression. Must exceed the handshake timestamp tolerance by a good
/// margin so old entries never make a fresh legitimate ts look stale.
const HANDSHAKE_TS_RETENTION_SECS: Time = 600;
/// Unconfirmed handshakes older than this are dropped along with their IP
/// lease: the client's first encrypted packet should arrive within seconds.
const PENDING_HANDSHAKE_TIMEOUT_SECS: Time = 15;
/// Max concurrent unconfirmed handshakes. Each holds an IP lease, so the
/// cap bounds how much of the address pool unauthenticated INIT spam can
/// tie up between sweeps.
const MAX_PENDING_HANDSHAKES: usize = 32;
/// Decrypt failures tolerated before a pending handshake is dropped, so a
/// single spoofed or corrupted packet cannot kill a legitimate handshake.
const MAX_PENDING_DECRYPT_FAILURES: u8 = 3;

/// A handshake whose response was sent but whose PAKE key is not yet
/// confirmed by the client: with PAKE, `finish()` succeeds even on a
/// password mismatch (the two sides just derive different keys), so
/// confirmation happens implicitly when the client's first encrypted
/// packet decrypts. Until then the IP lease is held here, not in a peer.
struct PendingHandshake {
    id: PeerId,
    crypto: CryptoCore,
    ipv4: Option<Ipv4Addr>,
    ipv6: Option<Ipv6Addr>,
    created: Time,
    /// Client-reported device name and platform from the handshake request;
    /// empty when the client predates those fields.
    device_name: String,
    platform: String,
    /// Encrypted packets that failed to decrypt against this handshake's
    /// key. A few strikes are tolerated before the entry is dropped.
    failed_decrypts: u8,
}

/// Renders a client-reported string for logs; old clients send an empty
/// string, shown as `-`.
fn or_dash(s: &str) -> &str {
    if s.is_empty() { "-" } else { s }
}

pub struct SuperNode<TS: TimeSource> {
    config: SuperNodeConfig,
    signal: Arc<SysSignal>,
    socket: Arc<UdpSocket>,
    device: Arc<TunTapDevice>,
    ip_manager: IpManager<TS>,
    peers: Peers<TS>,
    /// Handshakes answered but not yet confirmed by an encrypted client
    /// packet, keyed by source address.
    pending: HashMap<SocketAddr, PendingHandshake>,
    /// Per-source-IP INIT rate limiting and failure-based banning.
    init_limiter: InitLimiter<TS>,
    /// Last accepted handshake timestamp per client id; replays of a
    /// captured request carry a stale (non-increasing) timestamp and are
    /// refused.
    handshake_ts: HashMap<PeerId, Time>,
    // Names of the local physical interfaces
    interfaces: Vec<String>,
    next_check_time: Time,
    supported_algorithms: Vec<Algorithm>,
    id: PeerId,
}

fn init_ipv4_pool(ipv4: &Ipv4Cidr) -> anyhow::Result<Ipv4Pool> {
    let pool = Ipv4Pool::new(*ipv4);
    Ok(pool)
}

fn init_ipv6_pool(ipv6: &Ipv6Cidr) -> anyhow::Result<Ipv6Pool> {
    let pool = Ipv6Pool::new(*ipv6);
    Ok(pool)
}

fn is_would_block(err: &anyhow::Error) -> bool {
    err.downcast_ref::<std::io::Error>()
        .is_some_and(|e| e.kind() == std::io::ErrorKind::WouldBlock)
}

/// TCP MSS clamping: the tunnel MTU is smaller than the path MTU, so clamp
/// SYNs to the PMTU instead of letting oversized TCP segments black-hole.
/// Lives in the mangle table (same table name for iptables and ip6tables).
const MSS_CLAMP_TABLE: &str = "mangle";
const MSS_CLAMP_RULE: &[&str] = &[
    "POSTROUTING",
    "-p",
    "tcp",
    "--tcp-flags",
    "SYN,RST",
    "SYN",
    "-j",
    "TCPMSS",
    "--clamp-mss-to-pmtu",
];

/// Build an iptables argv with the table before the command verb, as
/// iptables requires: `iptables -t nat -A POSTROUTING ...`. Placing the
/// verb first makes iptables consume `-t` as the chain name and fail with
/// "Bad argument" (iptables 1.8).
fn netfilter_args<'a>(table: Option<&'a str>, verb: &'a str, rule: &[&'a str]) -> Vec<&'a str> {
    let mut args = Vec::with_capacity(rule.len() + 3);
    if let Some(table) = table {
        args.extend_from_slice(&["-t", table]);
    }
    args.push(verb);
    args.extend_from_slice(rule);
    args
}

/// Append a netfilter rule only when it is not already present. `table` is
/// None for the default filter table; `rule` is the rule spec starting with
/// the chain name, without any verb. The check probe is quiet since "rule
/// absent" is the expected first-run outcome.
fn ensure_netfilter_rule(program: &str, table: Option<&str>, rule: &[&str]) {
    if util::check_command(program, &netfilter_args(table, "-C", rule)) {
        return;
    }
    util::run_command(program, &netfilter_args(table, "-A", rule));
}

/// Delete a netfilter rule; deleting a rule that was never added fails
/// harmlessly.
fn remove_netfilter_rule(program: &str, table: Option<&str>, rule: &[&str]) {
    util::run_command(program, &netfilter_args(table, "-D", rule));
}

impl<TS: TimeSource> SuperNode<TS> {
    pub fn new(config: SuperNodeConfig, signal: Arc<SysSignal>) -> anyhow::Result<Self> {
        let socket = match UdpSocket::bind(SocketAddr::new(
            IpAddr::V6(Ipv6Addr::UNSPECIFIED),
            config.get_port(),
        )) {
            Ok(s) => s,
            Err(e) => {
                warn!("IPv6 bind failed ({}), falling back to IPv4", e);
                UdpSocket::bind(SocketAddr::new(
                    IpAddr::V4(Ipv4Addr::UNSPECIFIED),
                    config.get_port(),
                ))?
            }
        };
        // Non-blocking: a full send buffer must not stall every client.
        socket
            .set_nonblocking(true)
            .map_err(|e| anyhow::anyhow!("Failed to set socket non-blocking: {}", e))?;
        let socket = Arc::new(socket);

        let mut ipv4_pool = config.get_ipv4().as_ref().and_then(|ipv4| {
            let r = init_ipv4_pool(ipv4);
            if let Ok(r) = r {
                info!(
                    "init ipv4 pool: {} network: {} netmask: {} broadcast: {}",
                    r.cidr_string(),
                    r.network(),
                    r.netmask(),
                    r.broadcast()
                );
                Some(r)
            } else {
                error!("init ipv4 range error.");
                None
            }
        });

        let mut ipv6_pool = config.get_ipv6().as_ref().and_then(|ipv6| {
            let r = init_ipv6_pool(ipv6);
            if let Ok(r) = r {
                info!(
                    "init ipv6 pool: {} network: {} last: {}",
                    r.cidr_string(),
                    r.network(),
                    r.last_addr()
                );
                Some(r)
            } else {
                error!("init ipv6 range error.");
                None
            }
        });

        // Reserve local interface addresses that fall inside the pools so they
        // are never assigned to clients (e.g. when the server's real IPv6
        // overlaps with the TUN subnet).
        for i in &pnet::datalink::interfaces() {
            if i.is_loopback() {
                continue;
            }
            for ip_net in &i.ips {
                match ip_net.ip() {
                    IpAddr::V4(ip) => {
                        if let Some(p) = ipv4_pool.as_mut()
                            && p.reserve(ip)
                        {
                            info!("reserve interface ipv4: {} ({})", ip, i.name);
                        }
                    }
                    IpAddr::V6(ip) => {
                        if let Some(p) = ipv6_pool.as_mut()
                            && p.reserve(ip)
                        {
                            info!("reserve interface ipv6: {} ({})", ip, i.name);
                        }
                    }
                }
            }
        }

        let ipv4 = ipv4_pool.as_mut().and_then(|p| {
            p.allocate().ok().map(|ip| Ipv4 {
                ip,
                netmask: p.netmask(),
            })
        });
        let ipv6 = ipv6_pool.as_mut().and_then(|p| {
            p.allocate().ok().map(|ip| Ipv6 {
                ip,
                prefix_len: p.prefix_len(),
            })
        });

        if ipv4.is_none() && ipv6.is_none() {
            return Err(anyhow::anyhow!("Failed to allocate IP for TUN device"));
        }

        let device = device::setup_device(config.get_iface(), &device::DeviceType::Tun)?;
        // Non-blocking: a stalled TUN queue must not stall every client.
        device
            .set_nonblocking()
            .map_err(|e| anyhow::anyhow!("Failed to set device non-blocking: {}", e))?;
        let device = Arc::new(device);
        device
            .set_ip(ipv4.as_ref(), ipv6.as_ref())
            .map_err(|e| anyhow::anyhow!("Failed to set device address: {}", e))?;

        let ip_manager = IpManager::<TS>::new(ipv4_pool, ipv6_pool)?;

        fn is_virtual_device(interface_name: &str) -> bool {
            let virtual_drivers = ["tun", "tap", "veth", "bridge", "dummy"];
            let type_path = format!("/sys/class/net/{}/device/uevent", interface_name);
            if let Ok(type_content) = std::fs::read_to_string(type_path) {
                for line in type_content.lines() {
                    if line.starts_with("DRIVER=") {
                        let driver = line.trim_start_matches("DRIVER=");
                        return virtual_drivers.iter().any(|d| d.eq(&driver));
                    }
                }
            }
            true
        }

        let mut interfaces = vec![];
        for i in &pnet::datalink::interfaces() {
            if !i.is_loopback() && i.is_running() && !is_virtual_device(&i.name) {
                interfaces.push(i.name.clone());
            }
        }

        if config.get_ipv4().is_some() {
            util::run_command("sysctl", &["-w", "net.ipv4.ip_forward=1"]);

            let send_redirects_path = format!(
                "/proc/sys/net/ipv4/conf/{}/send_redirects",
                device.get_ifname()
            );
            if let Err(e) = std::fs::write(&send_redirects_path, "0\n") {
                error!("Failed to write {}: {}", send_redirects_path, e);
            }

            for i in &interfaces {
                ensure_netfilter_rule(
                    "iptables",
                    Some("nat"),
                    &["POSTROUTING", "-o", i, "-j", "MASQUERADE"],
                );
            }
            ensure_netfilter_rule("iptables", Some(MSS_CLAMP_TABLE), MSS_CLAMP_RULE);
        }
        if let Some(ipv6) = config.get_ipv6() {
            util::run_command("sysctl", &["-w", "net.ipv6.conf.all.forwarding=1"]);
            util::run_command("sysctl", &["-w", "net.ipv6.conf.all.accept_redirects=0"]);
            for i in &interfaces {
                ensure_netfilter_rule(
                    "ip6tables",
                    Some("nat"),
                    &["POSTROUTING", "-o", i, "-j", "MASQUERADE"],
                );
            }
            ensure_netfilter_rule(
                "ip6tables",
                None,
                &[
                    "FORWARD",
                    "-m",
                    "state",
                    "--state",
                    "ESTABLISHED,RELATED",
                    "-j",
                    "ACCEPT",
                ],
            );
            let ipv6 = ipv6.to_string();
            ensure_netfilter_rule("ip6tables", None, &["FORWARD", "-s", &ipv6, "-j", "ACCEPT"]);
            ensure_netfilter_rule("ip6tables", Some(MSS_CLAMP_TABLE), MSS_CLAMP_RULE);
        }

        Ok(Self {
            config,
            signal,
            socket,
            device,
            ip_manager,
            peers: Default::default(),
            pending: HashMap::new(),
            init_limiter: InitLimiter::default(),
            handshake_ts: HashMap::new(),
            interfaces,
            next_check_time: TS::now(),
            supported_algorithms: supported_algorithms(),
            id: PeerId::default(),
        })
    }

    pub fn run(mut self) -> anyhow::Result<()> {
        let waiter = WaitImpl::new(self.socket.as_raw_fd(), self.device.as_raw_fd(), 1000)
            .map_err(|e| anyhow::anyhow!("Failed to setup poll: {}", e))?;

        let mut buffer = Buffer::new(128);
        for evt in waiter {
            // HOT PATH
            match evt {
                WaitResult::Error(err) => {
                    debug!("Poll wait failed: {}, retrying...", err);
                }
                WaitResult::Timeout => {}
                WaitResult::Socket => self.handle_net_data(&mut buffer),
                WaitResult::Device => self.handle_device_data(&mut buffer),
            }

            if self.next_check_time < TS::now() {
                if self.signal.is_exited() {
                    break;
                }
                self.next_check_time = TS::now() + 1;
                if let Err(e) = self.ip_manager.clean_expired_items() {
                    error!("{:?}", e)
                }
                // Forget handshake timestamps old enough that they could no
                // longer pass the clock-skew window anyway.
                let cutoff = TS::now() - HANDSHAKE_TS_RETENTION_SECS;
                self.handshake_ts.retain(|_, ts| *ts > cutoff);
                // Expire unconfirmed handshakes and reclaim their leases;
                // a legitimate client confirms within seconds, so anything
                // older is a wrong password or INIT spam.
                let cutoff = TS::now() - PENDING_HANDSHAKE_TIMEOUT_SECS;
                let expired: Vec<SocketAddr> = self
                    .pending
                    .iter()
                    .filter(|(_, p)| p.created < cutoff)
                    .map(|(addr, _)| *addr)
                    .collect();
                for addr in expired {
                    if let Some(p) = self.pending.remove(&addr) {
                        debug!("Pending handshake from {} expired, lease revoked", addr);
                        self.init_limiter.record_init_failure(addr.ip());
                        if let Err(e) = self.ip_manager.revoke(&p.id) {
                            error!("Revoke ip lease error: {:?}", e);
                        }
                    }
                }
                // Drop stale rate-limit/ban entries.
                self.init_limiter.sweep();
                // Peer routing entries expire fast; IP leases last 300s.
                for peer in self.peers.remove_inactive_peers(PEER_IDLE_TIMEOUT_SECS) {
                    info!(
                        target: "client",
                        "{}, {},{}, Peer idle timeout, removed. {:?}/{:?}",
                        hex::encode(peer.id().0),
                        or_dash(peer.platform()),
                        or_dash(peer.device_name()),
                        peer.get_ipv4(),
                        peer.get_ipv6()
                    );
                }
            }
        }
        info!("Shutting down...");
        Ok(())
    }

    fn handle_net_data(&mut self, buffer: &mut Buffer) {
        buffer.clear(); // recv_from writes at the cursor; reset the drift
        match self.socket.recv_from(buffer.buffer()) {
            Ok((size, addr)) => {
                // A zero-length datagram carries no message; without this
                // guard the parser would read stale bytes from the backing
                // array.
                if size == 0 {
                    return;
                }
                buffer.set_length(size);
                let addr = mapped_addr(addr);
                if let Err(e) = self.do_handle_net_data(buffer, addr) {
                    error!("Handle net data error., {} : {}", addr, e);
                }
            }
            Err(e) => {
                let e = anyhow::Error::from(e);
                // Non-blocking socket: a spurious readiness event is not an
                // error.
                if is_would_block(&e) {
                    debug!("Spurious socket readiness, no data available");
                } else {
                    error!("Receive net data error. {}", e);
                }
            }
        }
    }

    fn do_handle_net_data(&mut self, buffer: &mut Buffer, addr: SocketAddr) -> anyhow::Result<()> {
        let r#type = buffer.take_prefix();

        match r#type {
            protocol::INIT => {
                debug!("Receive init request:{}, {:?}", addr, buffer.len());
                // Wide per-IP attempt guard (CPU only). The real
                // anti-guessing mechanism is failure-based banning, so
                // legitimate clients sharing a NAT egress IP are unaffected.
                if !self.init_limiter.check_init_allowed(addr.ip()) {
                    debug!("INIT from {} blocked (banned or over attempt limit)", addr);
                    return Ok(());
                }
                let handshake = protocol::parse_handshake(buffer.as_ref())?;
                match handshake {
                    Handshake::Request(r) => {
                        if r.version != PROTOCOL_VERSION {
                            anyhow::bail!(
                                "Unsupported protocol version {} from {}",
                                r.version,
                                addr
                            );
                        }
                        // Freshness: the timestamp must be near our clock
                        // and strictly newer than any previous handshake
                        // from this client id, so captured requests cannot
                        // be replayed.
                        protocol::check_handshake_ts(r.timestamp, TS::now())?;
                        if let Some(last) = self.handshake_ts.get(&r.id)
                            && r.timestamp <= *last
                        {
                            anyhow::bail!(
                                "Replayed handshake from {} (id {})",
                                addr,
                                hex::encode(r.id.0)
                            );
                        }
                        // Record the timestamp only after the handshake fully
                        // succeeds below; otherwise a failed attempt would
                        // poison the client's next (legitimate) retry as a
                        // "replay".
                        if self.pending.len() >= MAX_PENDING_HANDSHAKES
                            && !self.pending.contains_key(&addr)
                        {
                            warn!("Too many pending handshakes, dropping INIT from {}", addr);
                            return Ok(());
                        }
                        // Complete the PAKE exchange. finish() succeeds even
                        // on a password mismatch (the two sides just derive
                        // different keys); confirmation happens implicitly
                        // when the client's first encrypted packet decrypts.
                        let (pake_state, pake_message) =
                            pake::start_server(self.config.get_password().as_bytes(), &r.id.0);
                        let pake_key = pake_state.finish(&r.pake_message)?;
                        let algorithm =
                            select_algorithm(&self.supported_algorithms, &r.algorithms)?;
                        if let Some(algorithm) = algorithm {
                            let (private_key, ecdh_public_key) = create_ecdh_keypair()?;
                            let crypto = CryptoCore::new(
                                private_key,
                                &algorithm.algorithm_type,
                                &r.public_key_data,
                                Role::Responder,
                                &pake_key,
                            )?;

                            let (ipv4, ipv6) = self.ip_manager.assign(&r.id)?;
                            let response = protocol::build_handshake_response(
                                &self.id,
                                &pake_message,
                                &algorithm,
                                ecdh_public_key.bytes(),
                                ipv4.map_or("".to_string(), |ip| ip.to_string()),
                                self.config
                                    .get_ipv4()
                                    .as_ref()
                                    .map_or("".to_string(), |ip| ip.netmask().to_string()),
                                ipv6.map_or("".to_string(), |ip| ip.to_string()),
                                self.config
                                    .get_ipv6()
                                    .as_ref()
                                    .map_or(0, |ip| ip.prefix_len() as i32),
                                TS::now(),
                                &r.public_key_data,
                                &pake_key,
                            )?;

                            match self.socket.send_to(response.as_ref(), addr) {
                                Ok(_) => {
                                    // A retry from the same address replaces
                                    // its previous pending entry; reclaim the
                                    // old lease when the id differs.
                                    if let Some(old) = self.pending.get(&addr)
                                        && old.id != r.id
                                        && let Err(e) = self.ip_manager.revoke(&old.id)
                                    {
                                        error!("Revoke ip lease error: {:?}", e);
                                    }
                                    self.pending.insert(
                                        addr,
                                        PendingHandshake {
                                            id: r.id,
                                            crypto,
                                            ipv4,
                                            ipv6,
                                            created: TS::now(),
                                            device_name: r.device_name.clone(),
                                            platform: r.platform.clone(),
                                            failed_decrypts: 0,
                                        },
                                    );
                                    // Bounded map: under a spoofed-source
                                    // flood, new ids stop being tracked
                                    // rather than growing memory forever.
                                    if self.handshake_ts.len() < MAX_TRACKED_ENTRIES
                                        || self.handshake_ts.contains_key(&r.id)
                                    {
                                        self.handshake_ts.insert(r.id, r.timestamp);
                                    }
                                    info!(
                                        target: "client",
                                        "{},{},{}, Handshake answered. {:?}/{:?}",
                                        hex::encode(r.id.0),
                                        or_dash(&r.platform),
                                        or_dash(&r.device_name),
                                        ipv4,
                                        ipv6
                                    );
                                    // Connection metadata (ephemeral public
                                    // keys) is only useful when debugging.
                                    debug!(
                                        target: "client",
                                        "{}, Handshake peer public key: {}, local public key: {}",
                                        hex::encode(r.id.0),
                                        hex::encode(&r.public_key_data),
                                        hex::encode(ecdh_public_key.bytes())
                                    );
                                }
                                Err(e) => {
                                    error!("Failed to send handshake response to {}: {}", addr, e);
                                    // Revoke the whole lease, not just the
                                    // pool addresses: leaving the lease row
                                    // behind would let the same IP be
                                    // assigned to another client while this
                                    // id still claims it.
                                    if let Err(e) = self.ip_manager.revoke(&r.id) {
                                        error!("Revoke ip lease error: {:?}", e);
                                    }
                                }
                            }
                        }
                    }
                    Handshake::Response(_) => {
                        error!(
                            "Unexpected handshake response from {} - should not receive response on server",
                            addr
                        );
                    }
                }
            }
            protocol::HEARTBEAT => {
                let known = self.peers.find_peer_by_socket(&addr);
                let (peer, ping) = match known {
                    Some(peer) => {
                        peer.update_active_time();
                        let ping = protocol::parse_ping(buffer, peer.crypto())?;
                        (peer, ping)
                    }
                    // A heartbeat from an unknown address may be the first
                    // encrypted packet of a pending handshake; promotion
                    // decrypts the buffer, so only decode remains.
                    None => match self.promote_pending(&addr, buffer) {
                        Some(peer) => {
                            peer.update_active_time();
                            let ping = protocol::decode_ping(buffer)?;
                            (peer, ping)
                        }
                        None => {
                            protocol::build_rejected(buffer);
                            self.socket.send_to(buffer.as_ref(), addr)?;
                            warn!(
                                target: "client",
                                "Peer not found: {}, must be reinitialized.",
                                addr
                            );
                            return Ok(());
                        }
                    },
                };
                protocol::build_heartbeat_pong(buffer, peer.crypto(), &self.id, TS::now())?;
                self.socket.send_to(buffer.as_ref(), addr)?;
                if let Err(e) = self.ip_manager.update(peer.id()) {
                    error!("Update ip error: {:?}", e)
                }
                info!(
                    target: "client",
                    "{},{},{}, Received ping: {}, timestamp: {}",
                    hex::encode(peer.id().0),
                    or_dash(peer.platform()),
                    or_dash(peer.device_name()),
                    addr,
                    ping.ts
                );
            }
            protocol::DATA_INTERFACE => {
                let peer = match self.peers.find_peer_by_socket(&addr) {
                    Some(peer) => {
                        peer.crypto().decrypt(buffer)?;
                        Some(peer)
                    }
                    // First encrypted packet of a pending handshake;
                    // promotion decrypts the buffer on success.
                    None => self.promote_pending(&addr, buffer),
                };
                if let Some(peer) = peer {
                    peer.update_active_time();

                    let p = parse(&DeviceType::Tun, buffer.as_ref())?;
                    let (src, dst) = p.address;

                    // The tunnel source address must be the assigned one.
                    if let Address::Ip(src_ip) = src {
                        let valid = match src_ip {
                            IpAddr::V4(ip) => peer.get_ipv4().as_ref() == Some(&ip),
                            IpAddr::V6(ip) => peer.get_ipv6().as_ref() == Some(&ip),
                        };
                        if !valid {
                            warn!(
                                target: "client",
                                "{},{},{},{}, Dropping packet with spoofed source {} (assigned {:?}/{:?})",
                                hex::encode(peer.id().0),
                                or_dash(peer.platform()),
                                or_dash(peer.device_name()),
                                addr,
                                src_ip,
                                peer.get_ipv4(),
                                peer.get_ipv6()
                            );
                            return Ok(());
                        }
                    }

                    match self.device.write(buffer) {
                        Ok(_) => {}
                        // TUN queue full: drop rather than stall the loop.
                        Err(e) if is_would_block(&e) => {
                            warn!(
                                target: "client",
                                "{}, TUN write queue full, dropping packet for {}",
                                hex::encode(peer.id().0),
                                addr
                            );
                        }
                        Err(e) => return Err(e),
                    }

                    if let (Address::Ip(src), Address::Ip(dst)) = (src, dst) {
                        debug!(
                            "{}, Writing data to device: src: {}, dst: {} {} bytes",
                            hex::encode(peer.id().0),
                            src,
                            dst,
                            buffer.len()
                        );
                    }
                } else {
                    protocol::build_rejected(buffer);
                    self.socket.send_to(buffer.as_ref(), addr)?;
                    debug!("Peer not found: {}, must be reinitialized.", addr);
                }
            }
            protocol::CLOSE => {
                if let Some(peer) = self.peers.find_peer_by_socket(&addr) {
                    // Only trust CLOSE if it decrypts with the peer's key
                    // and carries its own id.
                    match protocol::parse_close(buffer, peer.crypto()) {
                        Ok(id) if id == *peer.id() => {
                            info!(
                                target: "client",
                                "{},{},{} Received close from {}, peer removed",
                                hex::encode(id.0),
                                or_dash(peer.platform()),
                                or_dash(peer.device_name()),
                                addr
                            );
                            self.peers.remove_peer_by_socket(&addr);
                        }
                        Ok(id) => {
                            warn!(
                                target: "client",
                                "CLOSE id mismatch from {}: {} != {}",
                                addr,
                                hex::encode(id.0),
                                hex::encode(peer.id().0)
                            );
                        }
                        Err(e) => {
                            warn!("Invalid CLOSE from {}: {}", addr, e);
                        }
                    }
                } else {
                    debug!("CLOSE from unknown peer: {}", addr);
                }
            }
            _ => {
                error!("Type {} not supported.", r#type);
            }
        }

        Ok(())
    }

    /// Try to promote a pending (password-unconfirmed) handshake to a full
    /// peer by decrypting its first encrypted packet. On success the buffer
    /// is already decrypted and the new peer is returned. A few decrypt
    /// failures are tolerated so a single spoofed packet cannot kill a
    /// legitimate handshake; beyond that the entry and its IP lease are
    /// dropped and the failure counted against the source IP.
    fn promote_pending(&mut self, addr: &SocketAddr, buffer: &mut Buffer) -> Option<Arc<Peer<TS>>> {
        let pending = self.pending.get_mut(addr)?;
        if pending.crypto.decrypt(buffer).is_err() {
            pending.failed_decrypts += 1;
            if pending.failed_decrypts < MAX_PENDING_DECRYPT_FAILURES {
                debug!(
                    "{}, Pending handshake from {} failed decryption ({}/{})",
                    addr,
                    hex::encode(pending.id.0),
                    pending.failed_decrypts,
                    MAX_PENDING_DECRYPT_FAILURES
                );
                return None;
            }
            let pending = self.pending.remove(addr).expect("presence checked above");
            debug!(
                "{}, Pending handshake from {} failed confirmation, dropped",
                hex::encode(pending.id.0),
                addr
            );
            self.init_limiter.record_init_failure(addr.ip());
            if let Err(e) = self.ip_manager.revoke(&pending.id) {
                error!("Revoke ip lease error: {:?}", e);
            }
            return None;
        }
        let pending = self.pending.remove(addr).expect("presence checked above");
        self.init_limiter.record_init_success(addr.ip());
        info!(
            target: "client",
            "{},{},{} Pending handshake confirmed, peer promoted. {:?}/{:?}",
            hex::encode(pending.id.0),
            or_dash(&pending.platform),
            or_dash(&pending.device_name),
            pending.ipv4,
            pending.ipv6
        );
        self.peers.create_peer(
            pending.id,
            pending.crypto,
            *addr,
            self.socket.clone(),
            pending.ipv4,
            pending.ipv6,
            false,
            pending.device_name,
            pending.platform,
        );
        self.peers.find_peer_by_socket(addr)
    }

    fn handle_device_data(&mut self, buffer: &mut Buffer) {
        match self.device.read(buffer) {
            Ok(_) => {
                if let Err(e) = self.do_handle_device_data(buffer) {
                    error!("Handle device data error. {}", e);
                }
            }
            // Non-blocking fd: a spurious readiness event is not an error.
            Err(e) if is_would_block(&e) => {}
            Err(e) => error!("Receive device data error. {}", e),
        }
    }

    fn do_handle_device_data(&mut self, buffer: &mut Buffer) -> anyhow::Result<()> {
        let p = parse(&DeviceType::Tun, buffer.as_ref())?;
        let (src, dst) = p.address;
        debug!(
            "Received device data, src: {}, dst: {} {} bytes",
            src,
            dst,
            buffer.len()
        );
        if let (Address::Ip(src), Address::Ip(dst)) = (src, dst) {
            if let Some(peer) = self.peers.find_peer_by_ip(&dst) {
                protocol::build_data_interface(buffer, peer.crypto())?;
                match peer.send_to(buffer.as_ref()) {
                    Ok(_) => {}
                    // Send buffer full: drop rather than stall the loop.
                    // debug level: at high pps this would flood the log.
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        debug!("UDP send buffer full, dropping packet for {}", dst);
                    }
                    Err(e) => warn!("Failed to send to {}: {}", peer.get_address(), e),
                }
                debug!(
                    "Writing data to peer: src: {}, dst: {} {} bytes",
                    src,
                    dst,
                    buffer.len()
                );
            } else {
                warn!("Destination {} not found.", dst);
            }
        }

        Ok(())
    }
}

impl<TS: TimeSource> Drop for SuperNode<TS> {
    fn drop(&mut self) {
        for i in &self.interfaces {
            if self.config.get_ipv4().is_some() {
                remove_netfilter_rule(
                    "iptables",
                    Some("nat"),
                    &["POSTROUTING", "-o", i, "-j", "MASQUERADE"],
                );
            }

            if self.config.get_ipv6().is_some() {
                remove_netfilter_rule(
                    "ip6tables",
                    Some("nat"),
                    &["POSTROUTING", "-o", i, "-j", "MASQUERADE"],
                );
            }
        }

        if self.config.get_ipv4().is_some() {
            remove_netfilter_rule("iptables", Some(MSS_CLAMP_TABLE), MSS_CLAMP_RULE);
        }
        if self.config.get_ipv6().is_some() {
            remove_netfilter_rule("ip6tables", Some(MSS_CLAMP_TABLE), MSS_CLAMP_RULE);
        }

        if let Some(ipv6) = self.config.get_ipv6() {
            util::run_command(
                "ip6tables",
                &[
                    "-D",
                    "FORWARD",
                    "-m",
                    "state",
                    "--state",
                    "ESTABLISHED,RELATED",
                    "-j",
                    "ACCEPT",
                ],
            );
            let ipv6 = ipv6.to_string();
            util::run_command("ip6tables", &["-D", "FORWARD", "-s", &ipv6, "-j", "ACCEPT"]);
        }
    }
}
