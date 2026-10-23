// SPDX-License-Identifier: MIT
use std::collections::HashMap;
use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket},
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
    util::mapped_addr,
};

use crate::config::SuperNodeConfig;
use crate::handshake::{
    HandshakeReplay, PendingHandshake, decrypt_preserving_packet, expire_pending,
};
use crate::ip::{IpManager, Ipv4Cidr, Ipv4Pool, Ipv6Cidr, Ipv6Pool};
use crate::limiter::InitLimiter;
use crate::network::{NetworkSetup, SystemBackend};

/// Peers idle longer than this are dropped from the routing tables; the IP
/// lease (300s) survives so a reconnecting peer reuses its old address.
const PEER_IDLE_TIMEOUT_SECS: Time = 60;
/// Unconfirmed handshakes older than this release their own temporary
/// reservations; borrowed established leases are never revoked.
const PENDING_HANDSHAKE_TIMEOUT_SECS: Time = 15;
/// Max concurrent unconfirmed handshakes. Each holds a reservation, so the
/// cap bounds how much of the address pool unauthenticated INIT spam can
/// tie up between sweeps.
const MAX_PENDING_HANDSHAKES: usize = 32;
/// Decrypt failures tolerated before a pending handshake is dropped, so a
/// single spoofed or corrupted packet cannot kill a legitimate handshake.
const MAX_PENDING_DECRYPT_FAILURES: u8 = 3;

/// Renders a client-reported string for logs; old clients send an empty
/// string, shown as `-`.
fn or_dash(s: &str) -> &str {
    if s.is_empty() { "-" } else { s }
}

pub struct SuperNode<TS: TimeSource> {
    config: SuperNodeConfig,
    signal: Arc<SysSignal>,
    socket: Arc<UdpSocket>,
    /// RAII cleanup also rolls back a partially failed startup.
    _network: NetworkSetup<SystemBackend>,
    device: Arc<TunTapDevice>,
    ip_manager: IpManager<TS>,
    peers: Peers<TS>,
    /// Handshakes answered but not yet confirmed by an encrypted client
    /// packet, keyed by source address.
    pending: HashMap<SocketAddr, PendingHandshake>,
    /// Per-source-IP INIT rate limiting and failure-based banning.
    init_limiter: InitLimiter<TS>,
    replay: HandshakeReplay,
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

        // Route ownership, not hardware type, determines a usable exit.
        // This includes container veth, bridges, bonds and VLAN interfaces.
        let interfaces = crate::network::route_interfaces(
            device.get_ifname(),
            config.get_ipv4().is_some(),
            config.get_ipv6().is_some(),
        )?;

        let mut network = NetworkSetup::new(SystemBackend);
        let ipv4_cidr = config.get_ipv4().map(ToString::to_string);
        let ipv6_cidr = config.get_ipv6().map(ToString::to_string);
        network.configure(
            device.get_ifname(),
            ipv4_cidr.as_deref(),
            ipv6_cidr.as_deref(),
            &interfaces,
        )?;

        Ok(Self {
            config,
            signal,
            socket,
            device,
            ip_manager,
            peers: Default::default(),
            pending: HashMap::new(),
            init_limiter: InitLimiter::default(),
            replay: HandshakeReplay::default(),
            _network: network,
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
                self.replay.sweep(TS::now());
                // Unconfirmed attempts may be cancelled Happy-Eyeballs losers
                // or lost responses. Reclaim them without banning the NAT IP.
                expire_pending(
                    &mut self.pending,
                    &mut self.ip_manager,
                    TS::now() - PENDING_HANDSHAKE_TIMEOUT_SECS,
                );
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
                // Wide per-IP attempt guard (CPU only). The counter does
                // not distinguish success from failure, so after a server
                // restart a burst of legitimate clients sharing a NAT egress
                // IP can still exceed it and get dropped. The limiter logs
                // the cause and retry window without flooding per-packet logs.
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
                        let request_key: [u8; 32] = r
                            .public_key_data
                            .as_slice()
                            .try_into()
                            .map_err(|_| anyhow::anyhow!("invalid request public key"))?;
                        self.replay
                            .check(r.id, request_key, r.timestamp, TS::now())?;
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

                            let reservation = self.ip_manager.reserve(&r.id)?;
                            let (ipv4, ipv6) = (reservation.ipv4, reservation.ipv6);
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
                            );
                            let response = match response {
                                Ok(response) => response,
                                Err(e) => {
                                    self.ip_manager.cancel(reservation)?;
                                    return Err(e);
                                }
                            };

                            match self.socket.send_to(response.as_ref(), addr) {
                                Ok(_) => {
                                    if let Some(old) = self.pending.remove(&addr)
                                        && let Err(e) = self.ip_manager.cancel(old.reservation)
                                    {
                                        error!("Cancel IP reservation error: {:?}", e);
                                    }
                                    self.pending.insert(
                                        addr,
                                        PendingHandshake::new(
                                            &r,
                                            request_key,
                                            crypto,
                                            reservation,
                                            TS::now(),
                                        ),
                                    );
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
                                    if let Err(e) = self.ip_manager.cancel(reservation) {
                                        error!("Cancel IP reservation error: {:?}", e);
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
                let Some(peer) = self.receive_authenticated(&addr, buffer, r#type)? else {
                    protocol::build_rejected(buffer);
                    self.socket.send_to(buffer.as_ref(), addr)?;
                    return Ok(());
                };
                let ping = protocol::decode_ping(buffer)?;
                peer.update_active_time();
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
                let peer = self.receive_authenticated(&addr, buffer, r#type)?;
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

    /// Try the established key first; a fresh handshake may reuse the same
    /// public UDP endpoint. Keep the old peer until the pending key confirms.
    fn receive_authenticated(
        &mut self,
        addr: &SocketAddr,
        buffer: &mut Buffer,
        packet_type: u8,
    ) -> anyhow::Result<Option<Arc<Peer<TS>>>> {
        if let Some(peer) = self.peers.find_peer_by_socket(addr) {
            if !self.pending.contains_key(addr) {
                peer.crypto().decrypt(buffer, packet_type)?;
                return Ok(Some(peer));
            }
            match decrypt_preserving_packet(peer.crypto(), buffer, packet_type) {
                Ok(()) => return Ok(Some(peer)),
                Err(error) => {
                    return match self.promote_pending(addr, buffer, packet_type) {
                        Some(promoted) => Ok(Some(promoted)),
                        None => Err(error),
                    };
                }
            }
        }
        Ok(self.promote_pending(addr, buffer, packet_type))
    }

    /// Try to promote a pending (password-unconfirmed) handshake to a full
    /// peer by decrypting its first encrypted packet. On success the buffer
    /// is already decrypted and the new peer is returned. A few decrypt
    /// failures are tolerated so a single spoofed packet cannot kill a
    /// legitimate handshake; beyond that the entry and its owned reservation are
    /// dropped and the failure counted against the source IP.
    fn promote_pending(
        &mut self,
        addr: &SocketAddr,
        buffer: &mut Buffer,
        packet_type: u8,
    ) -> Option<Arc<Peer<TS>>> {
        let pending = self.pending.get_mut(addr)?;
        if pending.authenticate(buffer, packet_type).is_err() {
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
            if let Err(e) = self.ip_manager.cancel(pending.reservation) {
                error!("Cancel IP reservation error: {:?}", e);
            }
            return None;
        }
        let mut pending = self.pending.remove(addr).expect("presence checked above");
        if let Err(e) = pending.commit(&mut self.ip_manager, &mut self.replay, TS::now()) {
            warn!("Pending handshake from {} could not commit: {}", addr, e);
            if let Err(e) = self.ip_manager.cancel(pending.reservation) {
                error!("Cancel IP reservation error: {:?}", e);
            }
            return None;
        }
        self.init_limiter.record_init_success(addr.ip());
        info!(
            target: "client",
            "{},{},{} Pending handshake confirmed, peer promoted. {:?}/{:?}",
            hex::encode(pending.id.0),
            or_dash(&pending.platform),
            or_dash(&pending.device_name),
            pending.reservation.ipv4,
            pending.reservation.ipv6
        );
        self.peers.create_peer(
            pending.id,
            pending.crypto,
            *addr,
            self.socket.clone(),
            pending.reservation.ipv4,
            pending.reservation.ipv6,
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
