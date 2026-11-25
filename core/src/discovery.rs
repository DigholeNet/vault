// SPDX-License-Identifier: MIT
use std::{
    collections::HashMap,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::atomic::Ordering,
    time::{Duration, Instant},
};

use tokio::net::UdpSocket;
use tracing::{debug, info};

use crate::{
    Buffer, PeerId,
    crypto::PeerKeyPair,
    peer_path::{PeerPath, canonical, lease_clock, wire_endpoint},
    protocol::{
        self, FindPeerRequest, FindPeerResponse, PeerInfo, PeerPunch, PeerRegisterResponse,
        find_peer_message::Data, find_peer_request::Target,
        peer_register_message::Data as Register,
    },
    settings::TunnelAssignment,
};

const MAX_PENDING: usize = 8;
const MAX_KNOWN: usize = 64;
const MAX_RETIRED: usize = 64;
const MAX_NEGATIVE: usize = 64;
const RETRIES: [Duration; 3] = [
    Duration::ZERO,
    Duration::from_millis(400),
    Duration::from_secs(1),
];
const QUERY_TIMEOUT: Duration = Duration::from_secs(2);
const NEGATIVE_TTL: Duration = Duration::from_secs(60);
const MAX_LEASE_MS: u32 = 60_000;

#[derive(Clone, Copy)]
pub(crate) struct DirectAuthorization {
    pub peer: PeerId,
    pub pair: [u8; 16],
    pub endpoint: SocketAddr,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum DirectSend {
    Sent,
    Suspend,
    Relay,
    Discard,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Fallback {
    Replay(IpAddr),
    Discard(IpAddr),
}

pub(crate) struct Discovery {
    assignment: TunnelAssignment,
    local_id: PeerId,
    local_epoch: u64,
    key: PeerKeyPair,
    supernode: SocketAddr,
    confirmed: bool,
    accepts_mapping: bool,
    pending: HashMap<IpAddr, Query>,
    known: HashMap<PeerId, Introduction>,
    by_ip: HashMap<IpAddr, PeerId>,
    by_endpoint: HashMap<SocketAddr, PeerId>,
    negative: HashMap<IpAddr, Instant>,
    fallbacks: Vec<Fallback>,
    next_id: u64,
    socket: Option<crate::client::PeerSocket>,
    wire_size: usize,
    enabled: bool,
    clock: fn() -> Option<u64>,
}

struct Query {
    id: u64,
    started: Option<Instant>,
    sent: usize,
    kind: QueryKind,
}

#[derive(Clone, Copy)]
enum QueryKind {
    New,
    Renew([u8; 16]),
    Replace([u8; 16]),
}

struct Introduction {
    info: PeerInfo,
    ips: Vec<IpAddr>,
    expires: u64,
    refresh_at: Instant,
    path: Option<PeerPath>,
    retired: bool,
    retired_at: Option<Instant>,
    last_uplink: Option<Instant>,
    punch_sent: bool,
}

impl Discovery {
    pub fn new(
        assignment: TunnelAssignment,
        local_id: PeerId,
        local_epoch: u64,
        key: PeerKeyPair,
        supernode: SocketAddr,
    ) -> Self {
        Self {
            assignment,
            local_id,
            local_epoch,
            key,
            supernode,
            confirmed: false,
            accepts_mapping: false,
            pending: HashMap::new(),
            known: HashMap::new(),
            by_ip: HashMap::new(),
            by_endpoint: HashMap::new(),
            negative: HashMap::new(),
            fallbacks: Vec::new(),
            next_id: 0,
            socket: None,
            wire_size: 0,
            enabled: true,
            clock: lease_clock,
        }
    }

    pub fn enable_direct(&mut self, socket: crate::client::PeerSocket) {
        self.socket = Some(socket);
        self.update_mtu(Instant::now());
    }

    pub fn disable(&mut self) {
        self.enabled = false;
        self.known.clear();
        self.by_ip.clear();
        self.by_endpoint.clear();
        self.pending.clear();
        self.fallbacks.clear();
    }

    pub fn take_fallbacks(&mut self) -> Vec<Fallback> {
        std::mem::take(&mut self.fallbacks)
    }

    fn update_mtu(&mut self, now: Instant) {
        let Some(socket) = &self.socket else {
            return;
        };
        let size = socket
            .mtu
            .load(Ordering::Acquire)
            .saturating_add(protocol::DATA_OVERHEAD);
        if size != self.wire_size {
            let increased = size > self.wire_size;
            self.wire_size = size;
            for entry in self.known.values_mut() {
                if let Some(path) = &mut entry.path {
                    let selected = path.selected.is_some();
                    path.update_mtu(size, increased, now);
                    if selected && path.selected.is_none() {
                        note_fallback(&mut self.fallbacks, &entry.ips);
                    }
                }
            }
        }
    }

    fn expire(&mut self, now: Instant) -> Option<u64> {
        let clock = (self.clock)();
        for (&id, entry) in &mut self.known {
            if !entry.retired && clock.is_none_or(|clock| clock >= entry.expires) {
                entry.retire(id, &mut self.by_endpoint, &mut self.fallbacks, now);
            }
        }
        self.prune_retired();
        clock
    }

    fn prune_retired(&mut self) {
        let mut retired: Vec<_> = self
            .known
            .iter()
            .filter_map(|(&id, entry)| entry.retired_at.map(|at| (id, at)))
            .collect();
        let excess = retired.len().saturating_sub(MAX_RETIRED);
        if excess == 0 {
            return;
        }
        retired.sort_unstable_by_key(|(_, at)| *at);
        let mut removed = 0;
        for (id, _) in retired {
            if removed == excess {
                break;
            }
            if self
                .known
                .get(&id)
                .is_some_and(|entry| entry.ips.iter().any(|ip| self.pending.contains_key(ip)))
            {
                continue;
            }
            if let Some(entry) = self.known.remove(&id) {
                for ip in entry.ips {
                    if self.by_ip.get(&ip) == Some(&id) {
                        self.by_ip.remove(&ip);
                    }
                }
                removed += 1;
            }
        }
    }

    pub fn confirm(&mut self) {
        self.confirmed = true;
    }

    pub fn mapping_needed(&self, now: Instant) -> bool {
        self.confirmed
            && self.enabled
            && self.known.values().any(|peer| {
                peer.path
                    .as_ref()
                    .is_some_and(|path| path.selected.is_none() && path.uplink_active(now))
            })
    }

    pub fn accepts_mapping(&self) -> bool {
        self.accepts_mapping
    }

    pub fn observe(&mut self, ip: IpAddr, now: Instant) {
        if !self.enabled || !self.pool_contains(ip) {
            return;
        }
        let mut kind = QueryKind::New;
        if let Some(entry) = self.by_ip.get(&ip).and_then(|id| self.known.get_mut(id)) {
            entry.last_uplink = Some(now);
            if let Some(path) = &mut entry.path {
                path.observe(now);
            }
            let id = entry.pair_id();
            if entry.retired {
                kind = QueryKind::Replace(id);
            } else if self.socket.is_some() && now >= entry.refresh_at {
                kind = QueryKind::Renew(id);
            } else {
                return;
            }
        }
        self.queue(ip, kind, now);
    }

    pub fn observe_relayed(&mut self, packet: &[u8], now: Instant) {
        if !self.enabled
            || self.socket.is_none()
            || !destination(packet).is_some_and(|ip| self.is_local(ip))
        {
            return;
        }
        let Some(ip) = source(packet).filter(|&ip| self.pool_contains(ip)) else {
            return;
        };
        let kind = match self.by_ip.get(&ip).and_then(|id| self.known.get(id)) {
            Some(entry) if entry.retired => QueryKind::Replace(entry.pair_id()),
            Some(_) => return,
            None => QueryKind::New,
        };
        self.queue(ip, kind, now);
    }

    fn queue(&mut self, ip: IpAddr, kind: QueryKind, now: Instant) {
        if self.pending.len() >= MAX_PENDING
            || self.pending.contains_key(&ip)
            || self.negative.get(&ip).is_some_and(|expires| now < *expires)
        {
            return;
        }
        let Some(id) = self.next_id.checked_add(1) else {
            return;
        };
        self.next_id = id;
        self.pending.insert(
            ip,
            Query {
                id,
                started: None,
                sent: 0,
                kind,
            },
        );
    }

    fn in_vpn_pool(&self, ip: IpAddr) -> bool {
        match ip {
            IpAddr::V4(ip) => self.assignment.ipv4.as_ref().is_some_and(|a| {
                let mask = u32::from(a.netmask);
                u32::from(ip) & mask == u32::from(a.address) & mask
            }),
            IpAddr::V6(ip) => self.assignment.ipv6.as_ref().is_some_and(|a| {
                let mask = u128::MAX
                    .checked_shl(128 - u32::from(a.prefix_len))
                    .unwrap_or(0);
                u128::from(ip) & mask == u128::from(a.address) & mask
            }),
        }
    }

    fn pool_contains(&self, ip: IpAddr) -> bool {
        match ip {
            IpAddr::V4(ip) if !ip.is_unspecified() && !ip.is_multicast() && !ip.is_loopback() => {
                self.assignment.ipv4.as_ref().is_some_and(|assignment| {
                    let mask = u32::from(assignment.netmask);
                    let network = u32::from(assignment.address) & mask;
                    let address = u32::from(ip);
                    ip != assignment.address
                        && address & mask == network
                        && (assignment.prefix_len >= 31
                            || (address != network && address != (network | !mask)))
                })
            }
            IpAddr::V6(ip) if !ip.is_unspecified() && !ip.is_multicast() && !ip.is_loopback() => {
                self.assignment.ipv6.as_ref().is_some_and(|assignment| {
                    let mask = u128::MAX
                        .checked_shl(128 - u32::from(assignment.prefix_len))
                        .unwrap_or(0);
                    ip != assignment.address
                        && u128::from(ip) & mask == u128::from(assignment.address) & mask
                })
            }
            _ => false,
        }
    }

    pub fn due_queries(&mut self, now: Instant) -> Vec<Data> {
        if !self.confirmed || !self.enabled {
            return Vec::new();
        }
        self.expire(now);
        self.negative.retain(|_, expires| now < *expires);
        let mut due = Vec::new();
        let mut expired = Vec::new();
        for (&ip, query) in &mut self.pending {
            let started = *query.started.get_or_insert(now);
            let elapsed = now - started;
            if elapsed >= QUERY_TIMEOUT {
                expired.push(ip);
            } else if RETRIES
                .get(query.sent)
                .is_some_and(|delay| elapsed >= *delay)
            {
                due.push(Data::Request(FindPeerRequest {
                    request_id: query.id,
                    target: Some(Target::TargetVpnIp(ip.into())),
                    renew_pair_id: match query.kind {
                        QueryKind::Renew(id) => id.to_vec(),
                        _ => Vec::new(),
                    },
                    replace_pair_id: match query.kind {
                        QueryKind::Replace(id) => id.to_vec(),
                        _ => Vec::new(),
                    },
                }));
                query.sent += 1;
            }
        }
        for ip in expired {
            if self
                .pending
                .remove(&ip)
                .is_some_and(|query| !matches!(query.kind, QueryKind::Renew(_)))
            {
                self.deny(ip, now);
            }
        }
        due
    }

    fn deny(&mut self, ip: IpAddr, now: Instant) {
        self.negative.retain(|_, expires| now < *expires);
        if self.negative.len() < MAX_NEGATIVE {
            self.negative.insert(ip, now + NEGATIVE_TTL);
        }
    }

    pub fn receive(&mut self, data: Data, now: Instant) -> anyhow::Result<Option<Data>> {
        if !self.confirmed || !self.enabled {
            return Ok(None);
        }
        match data {
            Data::Request(FindPeerRequest {
                request_id,
                target: Some(Target::Peer(info)),
                renew_pair_id,
                replace_pair_id,
            }) if request_id != 0 && renew_pair_id.is_empty() && replace_pair_id.is_empty() => {
                if self.install(info, None, now)? {
                    return Ok(Some(Data::Response(FindPeerResponse {
                        request_id,
                        peer: None,
                    })));
                }
            }
            Data::Response(FindPeerResponse { request_id, peer }) => {
                let Some((&ip, query)) = self.pending.iter().find(|(_, query)| {
                    query.id == request_id
                        && query
                            .started
                            .is_some_and(|start| now - start < QUERY_TIMEOUT)
                }) else {
                    return Ok(None);
                };
                let kind = query.kind;
                if let Some(info) = peer {
                    if self.install(info, Some(ip), now)? {
                        self.pending.remove(&ip);
                    }
                } else {
                    self.pending.remove(&ip);
                    if let QueryKind::Renew(id) = kind {
                        for (&peer, entry) in self
                            .known
                            .iter_mut()
                            .filter(|(_, entry)| entry.pair_id() == id)
                        {
                            entry.retire(peer, &mut self.by_endpoint, &mut self.fallbacks, now);
                        }
                    } else {
                        self.deny(ip, now);
                    }
                }
            }
            Data::PunchPeer(info) => {
                let peer = PeerId::try_from(info.peer_id.clone())?;
                if self.install(info, None, now)?
                    && let Some(path) = self
                        .known
                        .get_mut(&peer)
                        .and_then(|entry| entry.path.as_mut())
                {
                    debug!(%peer, "Received relayed punch notice");
                    path.on_punch_notice(now);
                }
            }
            _ => {}
        }
        Ok(None)
    }

    fn install(
        &mut self,
        info: PeerInfo,
        target: Option<IpAddr>,
        now: Instant,
    ) -> anyhow::Result<bool> {
        anyhow::ensure!(
            info.pair_id.len() == 16
                && info.revision != 0
                && info.local_session_epoch == self.local_epoch
                && info.peer_session_epoch != 0
                && (1..=MAX_LEASE_MS).contains(&info.valid_for_ms),
            "invalid peer authorization"
        );
        let lease_now = self
            .expire(now)
            .ok_or_else(|| anyhow::anyhow!("peer lease clock unavailable"))?;
        let expires = lease_now
            .checked_add(u64::from(info.valid_for_ms) * 1_000_000)
            .ok_or_else(|| anyhow::anyhow!("peer lease clock unavailable"))?;
        let refresh_at = now + Duration::from_millis(u64::from(info.valid_for_ms / 2));
        let peer_id = PeerId::try_from(info.peer_id.clone())?;
        anyhow::ensure!(peer_id != self.local_id, "self-introduction");
        let observation = info
            .observed_endpoint
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("missing observed endpoint"))?;
        let observed = SocketAddr::try_from(observation)?;
        anyhow::ensure!(
            observed.is_ipv4() == self.supernode.ip().to_canonical().is_ipv4()
                && observed
                    != SocketAddr::new(self.supernode.ip().to_canonical(), self.supernode.port())
                && !observed.ip().is_unspecified()
                && !observed.ip().is_multicast(),
            "invalid observed endpoint"
        );
        if let Some(lan) = &info.lan_endpoint {
            anyhow::ensure!(
                SocketAddr::try_from(lan)?.is_ipv4() == observed.is_ipv4(),
                "invalid LAN address family"
            );
        }
        let mapping = match (info.mapped_port, info.mapped_valid_for_ms) {
            (0, 0) => None,
            (port, ttl)
                if observed.is_ipv4()
                    && port != 0
                    && port <= u16::MAX.into()
                    && (1..=info.valid_for_ms).contains(&ttl) =>
            {
                let endpoint = SocketAddr::new(observed.ip(), port as u16);
                anyhow::ensure!(
                    endpoint != canonical(self.supernode),
                    "invalid mapped endpoint"
                );
                // The mapping lifetime is validated to fit inside the pair lease.
                Some((endpoint, lease_now + u64::from(ttl) * 1_000_000))
            }
            _ => anyhow::bail!("invalid mapped endpoint"),
        };

        let mut ips = Vec::with_capacity(2);
        for ip in &info.peer_vpn_ips {
            let ip = IpAddr::try_from(ip)?;
            anyhow::ensure!(
                self.pool_contains(ip)
                    && !ips
                        .iter()
                        .any(|other: &IpAddr| other.is_ipv4() == ip.is_ipv4()),
                "invalid peer VPN addresses"
            );
            ips.push(ip);
        }
        anyhow::ensure!(
            !ips.is_empty() && target.is_none_or(|target| ips.contains(&target)),
            "introduction does not match target VPN IP"
        );
        if ips.iter().any(|ip| {
            self.by_ip
                .get(ip)
                .filter(|&&owner| owner != peer_id)
                .and_then(|owner| self.known.get(owner))
                .is_some_and(|owner| owner.info.revision >= info.revision)
        }) {
            return Ok(false);
        }

        if self
            .known
            .get(&peer_id)
            .is_none_or(|previous| previous.retired)
            && self.known.values().filter(|entry| !entry.retired).count() >= MAX_KNOWN
        {
            return Ok(false);
        }
        if let Some(previous) = self.known.get_mut(&peer_id) {
            if info.revision < previous.info.revision {
                return Ok(false);
            }
            if info.pair_id == previous.info.pair_id {
                let mut repeated = info.clone();
                repeated.revision = previous.info.revision;
                repeated.valid_for_ms = previous.info.valid_for_ms;
                if info.revision > previous.info.revision {
                    repeated.mapped_port = previous.info.mapped_port;
                }
                repeated.mapped_valid_for_ms = previous.info.mapped_valid_for_ms;
                if repeated != previous.info || previous.retired {
                    return Ok(false);
                }
                self.accepts_mapping |= info.accepts_mapping;
                if info.revision > previous.info.revision {
                    if let Some(path) = &mut previous.path
                        && let Some(removed) = path.set_mapping(mapping, now, lease_now)
                    {
                        remove_endpoint(&mut self.by_endpoint, removed, peer_id);
                    }
                    previous.info = info;
                    previous.expires = expires;
                    previous.refresh_at = refresh_at;
                }
                return Ok(true);
            } else if info.revision == previous.info.revision {
                return Ok(false);
            }
        }

        let key = info.peer_public_key.as_slice().try_into()?;
        let pair = info.pair_id.as_slice().try_into()?;
        let crypto = self.key.derive(
            pair,
            (self.local_id, self.local_epoch),
            (peer_id, info.peer_session_epoch, key),
        )?;
        self.accepts_mapping |= info.accepts_mapping;
        let path = self.socket.as_ref().map(|socket| {
            let lan = info
                .lan_endpoint
                .as_ref()
                .and_then(|endpoint| SocketAddr::try_from(endpoint).ok())
                .filter(|endpoint| {
                    !self.in_vpn_pool(endpoint.ip())
                        && canonical(*endpoint) != canonical(self.supernode)
                        && (socket.allow_lan)(*endpoint)
                });
            let mut path = PeerPath::new(crypto, canonical(observed), lan, now);
            path.set_mapping(mapping, now, lease_now);
            if target.is_some() {
                path.observe(now);
            }
            path
        });
        debug!(%peer_id, revision = info.revision, "Accepted peer introduction");
        if let Some(previous) = self.known.get_mut(&peer_id) {
            previous.retire(peer_id, &mut self.by_endpoint, &mut self.fallbacks, now);
            for ip in &previous.ips {
                if self.by_ip.get(ip) == Some(&peer_id) {
                    self.by_ip.remove(ip);
                }
            }
        }
        for &ip in &ips {
            if let Some(old_id) = self.by_ip.insert(ip, peer_id)
                && let Some(previous) = self.known.get_mut(&old_id)
            {
                previous.discard(old_id, &mut self.by_endpoint, &mut self.fallbacks, now);
            }
        }
        self.known.insert(
            peer_id,
            Introduction {
                info,
                ips,
                expires,
                refresh_at,
                path,
                retired: false,
                retired_at: None,
                last_uplink: target.map(|_| now),
                punch_sent: false,
            },
        );
        Ok(true)
    }

    pub fn poll_paths(
        &mut self,
        socket: &UdpSocket,
        buffer: &mut Buffer,
        now: Instant,
    ) -> Vec<Data> {
        if !self.enabled || self.socket.is_none() {
            return Vec::new();
        }
        let Some(lease_now) = self.expire(now) else {
            return Vec::new();
        };
        self.update_mtu(now);
        let allow_lan = self.socket.as_ref().map(|socket| &socket.allow_lan);
        let mut active = self
            .known
            .values()
            .filter_map(|entry| entry.path.as_ref())
            .filter(|path| path.validating(now))
            .count();
        let mut rediscover = Vec::new();
        let mut punches = Vec::new();
        for (&id, entry) in &mut self.known {
            if let Some(path) = &mut entry.path {
                let was_validating = path.validating(now);
                if let Some(removed) = path.expire_mapping(now, lease_now) {
                    remove_endpoint(&mut self.by_endpoint, removed, id);
                }
                let can_validate = was_validating || active < MAX_PENDING;
                let selected = path.selected.is_some();
                if (selected || can_validate)
                    && path.lan_check_due(now)
                    && allow_lan.is_some_and(|allow| !allow(path.candidates[1].endpoint))
                {
                    let removed = path.candidates[1].endpoint;
                    remove_endpoint(&mut self.by_endpoint, removed, id);
                    path.remove_lan(now, self.wire_size);
                }
                let observed = path.candidates[0].endpoint;
                let mut sent_probe = false;
                let header = protocol::register_header(self.local_id, id);
                let keep = path.poll(
                    now,
                    self.wire_size,
                    can_validate,
                    |crypto, endpoint, data, size| {
                        if self
                            .by_endpoint
                            .get(&endpoint)
                            .is_none_or(|other| *other == id)
                            && protocol::build_peer_register(buffer, crypto, &header, data, size)
                                .is_ok()
                        {
                            let sent = socket
                                .try_send_to(
                                    buffer.as_ref(),
                                    wire_endpoint(endpoint, self.supernode),
                                )
                                .is_ok();
                            sent_probe |=
                                sent && endpoint == observed && size == protocol::REGISTER_MIN;
                        }
                    },
                );
                active = active - usize::from(was_validating)
                    + usize::from(keep && path.validating(now));
                if !keep {
                    entry.retire(id, &mut self.by_endpoint, &mut self.fallbacks, now);
                } else if selected && path.selected.is_none() {
                    note_fallback(&mut self.fallbacks, &entry.ips);
                    info!(peer = %id, "Peer path timed out, relaying");
                }
                if sent_probe
                    && !selected
                    && !entry.punch_sent
                    && entry
                        .last_uplink
                        .is_some_and(|last| now - last < crate::peer_path::UPLINK_ACTIVE)
                {
                    entry.punch_sent = true;
                    punches.push(Data::Punch(PeerPunch {
                        peer_id: id.0.to_vec(),
                        pair_id: entry.info.pair_id.clone(),
                    }));
                }
            }
            if entry.retired
                && entry
                    .last_uplink
                    .is_some_and(|last| now - last < crate::peer_path::UPLINK_ACTIVE)
                && let Some(&ip) = entry.ips.iter().find(|ip| self.by_ip.get(*ip) == Some(&id))
            {
                rediscover.push((ip, entry.pair_id()));
            }
        }
        self.by_endpoint.retain(|endpoint, id| {
            self.known.get(id).is_some_and(|entry| {
                entry.path.as_ref().is_some_and(|path| {
                    path.candidates
                        .iter()
                        .any(|candidate| candidate.registered && candidate.endpoint == *endpoint)
                })
            })
        });
        for (ip, pair) in rediscover {
            self.queue(ip, QueryKind::Replace(pair), now);
        }
        punches
    }

    pub fn send_direct(
        &mut self,
        socket: &UdpSocket,
        buffer: &mut Buffer,
        packet: &[u8],
        ip: IpAddr,
        now: Instant,
    ) -> DirectSend {
        if self.fallbacks.contains(&Fallback::Discard(ip)) {
            return DirectSend::Discard;
        }
        if !self.enabled || self.socket.is_none() {
            return DirectSend::Relay;
        }
        self.update_mtu(now);
        let wire_size = packet.len().saturating_add(protocol::DATA_OVERHEAD);
        if wire_size > self.wire_size
            || self.wire_size > protocol::REGISTER_MAX
            || !source(packet).is_some_and(|ip| self.is_local(ip))
        {
            return DirectSend::Relay;
        }
        let Some(&id) = self.by_ip.get(&ip) else {
            return DirectSend::Relay;
        };
        let Some(entry) = self.known.get_mut(&id) else {
            return DirectSend::Relay;
        };
        if (self.clock)().is_none_or(|time| time >= entry.expires) {
            entry.retire(id, &mut self.by_endpoint, &mut self.fallbacks, now);
            return DirectSend::Relay;
        }
        let Some(path) = &mut entry.path else {
            return DirectSend::Relay;
        };
        let Some(index) = path.selected else {
            return DirectSend::Relay;
        };
        if path.suspending() {
            return DirectSend::Suspend;
        }
        buffer.clear();
        use std::io::Write;
        if buffer.write_all(packet).is_err()
            || protocol::build_data_interface(buffer, &path.crypto).is_err()
        {
            return DirectSend::Relay;
        }
        let endpoint = path.candidates[index].endpoint;
        if (self.clock)()
            .is_none_or(|time| time >= entry.expires || path.mapping_expired(endpoint, time))
        {
            return DirectSend::Relay;
        }
        let endpoint = wire_endpoint(endpoint, self.supernode);
        match socket.try_send_to(buffer.as_ref(), endpoint) {
            Ok(_) => {
                path.on_direct_traffic(now, wire_size);
                DirectSend::Sent
            }
            Err(error) => {
                if error.kind() != std::io::ErrorKind::WouldBlock {
                    let mtu_failure =
                        (error.raw_os_error() == Some(libc::EMSGSIZE)).then_some(self.wire_size);
                    path.fallback(now, mtu_failure);
                    note_fallback(&mut self.fallbacks, &entry.ips);
                    info!(peer = %id, %error, "Peer send failed, relaying");
                }
                DirectSend::Relay
            }
        }
    }

    pub fn admit(&self, source: SocketAddr, packet: &[u8]) -> bool {
        if !self.enabled || self.socket.is_none() {
            return false;
        }
        let source = canonical(source);
        match packet.first() {
            Some(&protocol::PEER_REGISTER)
                if (protocol::REGISTER_MIN..=protocol::REGISTER_MAX).contains(&packet.len())
                    && packet[17..33] == self.local_id.0
                    && source.port() != 0
                    && source != canonical(self.supernode) =>
            {
                let id = PeerId(packet[1..17].try_into().unwrap());
                self.known.get(&id).is_some_and(|e| {
                    e.path.as_ref().is_some_and(|path| {
                        path.candidates
                            .iter()
                            .any(|candidate| candidate.endpoint.ip() == source.ip())
                    })
                })
            }
            Some(&protocol::DATA_INTERFACE)
                if (protocol::DATA_OVERHEAD..=protocol::REGISTER_MAX).contains(&packet.len()) =>
            {
                self.by_endpoint.contains_key(&source)
            }
            _ => false,
        }
    }

    pub fn receive_direct(
        &mut self,
        socket: &UdpSocket,
        buffer: &mut Buffer,
        from: SocketAddr,
        packet: &mut Vec<u8>,
        now: Instant,
    ) -> Option<DirectAuthorization> {
        self.update_mtu(now);
        if !self.admit(from, packet) {
            return None;
        }
        let from = canonical(from);
        if packet[0] == protocol::PEER_REGISTER {
            let id = PeerId(packet[1..17].try_into().unwrap());
            if self
                .by_endpoint
                .get(&from)
                .is_some_and(|other| *other != id)
            {
                return None;
            }
            let entry = self.known.get_mut(&id).unwrap();
            if (self.clock)().is_none_or(|time| time >= entry.expires) {
                entry.retire(id, &mut self.by_endpoint, &mut self.fallbacks, now);
                return None;
            }
            let path = entry.path.as_mut().unwrap();
            let Ok(message) = protocol::parse_peer_register(packet, &path.crypto) else {
                return None;
            };
            let index = match &message {
                Register::Request(_) => path.registration_candidate(from),
                Register::Response(response) => path.ack_candidate(from, response.cookie, now),
            }?;
            if (self.clock)().is_none_or(|time| {
                time >= entry.expires || path.mapping_expired(path.candidates[index].endpoint, time)
            }) {
                return None;
            }
            if path.is_lan(index)
                && self
                    .socket
                    .as_ref()
                    .is_some_and(|socket| !(socket.allow_lan)(from))
            {
                remove_endpoint(&mut self.by_endpoint, path.candidates[index].endpoint, id);
                path.remove_lan(now, self.wire_size);
                return None;
            }
            let start = protocol::REGISTER_HEADER;
            let counter =
                u64::from_le_bytes(packet[start..start + crate::EXTRA_LEN].try_into().unwrap());
            let candidate = &path.candidates[index];
            let rebound = candidate.endpoint != from;
            if rebound {
                if candidate
                    .latest_registration
                    .is_some_and(|seen| counter <= seen)
                {
                    return None;
                }
                let previous = candidate.endpoint;
                remove_endpoint(&mut self.by_endpoint, previous, id);
                note_fallback(&mut self.fallbacks, &entry.ips);
                path.rebind(index, from, now);
                debug!(peer = %id, %previous, endpoint = %from, "Learned peer UDP endpoint");
            }
            let candidate = &mut path.candidates[index];
            candidate.latest_registration = Some(
                candidate
                    .latest_registration
                    .map_or(counter, |seen| seen.max(counter)),
            );
            match message {
                Register::Request(request) => {
                    path.candidates[index].registered = true;
                    self.by_endpoint.insert(from, id);
                    let header = protocol::register_header(self.local_id, id);
                    let reply = Register::Response(PeerRegisterResponse {
                        cookie: request.cookie,
                    });
                    if protocol::build_peer_register(
                        buffer,
                        &path.crypto,
                        &header,
                        reply,
                        protocol::REGISTER_MIN,
                    )
                    .is_ok()
                    {
                        let _ = socket
                            .try_send_to(buffer.as_ref(), wire_endpoint(from, self.supernode));
                    }
                }
                Register::Response(response) => {
                    // An ACK from a changed port can discover that port. A
                    // probe addressed to the new port must validate it.
                    if rebound {
                        return None;
                    }
                    if path.acknowledge(index, response.cookie, self.wire_size, now) {
                        info!(peer = %id, endpoint = %from, "Peer path verified");
                    }
                    if path.candidates[index].registered {
                        self.by_endpoint.insert(from, id);
                    }
                }
            }
            return None;
        }
        let &id = self.by_endpoint.get(&from)?;
        let entry = self.known.get_mut(&id)?;
        let Some(lease_now) = (self.clock)().filter(|&time| time < entry.expires) else {
            entry.retire(id, &mut self.by_endpoint, &mut self.fallbacks, now);
            return None;
        };
        let path = entry.path.as_mut().unwrap();
        if path.mapping_expired(from, lease_now) {
            return None;
        }
        let Ok(plain) = path
            .crypto
            .decrypt_slice(&mut packet[1..], protocol::DATA_INTERFACE)
        else {
            return None;
        };
        if !source(plain).is_some_and(|ip| entry.ips.contains(&ip)) {
            return None;
        }
        let destination = destination(plain);
        let len = plain.len();
        let Some(lease_now) = (self.clock)().filter(|&time| time < entry.expires) else {
            entry.retire(id, &mut self.by_endpoint, &mut self.fallbacks, now);
            return None;
        };
        if path.mapping_expired(from, lease_now) {
            return None;
        }
        path.on_direct_traffic(now, 0);
        let pair = entry.pair_id();
        if !destination.is_some_and(|ip| self.is_local(ip)) {
            return None;
        }
        packet.copy_within(1 + crate::EXTRA_LEN..1 + crate::EXTRA_LEN + len, 0);
        packet.truncate(len);
        Some(DirectAuthorization {
            peer: id,
            pair,
            endpoint: from,
        })
    }

    pub fn authorizes(&self, authorization: DirectAuthorization) -> bool {
        self.enabled
            && self.by_endpoint.get(&authorization.endpoint) == Some(&authorization.peer)
            && self.known.get(&authorization.peer).is_some_and(|entry| {
                entry.pair_id() == authorization.pair
                    && (self.clock)().is_some_and(|now| {
                        now < entry.expires
                            && entry.path.as_ref().is_some_and(|path| {
                                !path.mapping_expired(authorization.endpoint, now)
                            })
                    })
            })
    }

    fn is_local(&self, ip: IpAddr) -> bool {
        match ip {
            IpAddr::V4(ip) => self
                .assignment
                .ipv4
                .as_ref()
                .is_some_and(|a| a.address == ip),
            IpAddr::V6(ip) => self
                .assignment
                .ipv6
                .as_ref()
                .is_some_and(|a| a.address == ip),
        }
    }
}

impl Introduction {
    fn pair_id(&self) -> [u8; 16] {
        self.info.pair_id.as_slice().try_into().unwrap()
    }

    fn retire(
        &mut self,
        id: PeerId,
        endpoints: &mut HashMap<SocketAddr, PeerId>,
        fallbacks: &mut Vec<Fallback>,
        now: Instant,
    ) {
        if self.retired {
            return;
        }
        note_fallback(fallbacks, &self.ips);
        self.retire_inner(id, endpoints, now);
    }

    fn discard(
        &mut self,
        id: PeerId,
        endpoints: &mut HashMap<SocketAddr, PeerId>,
        fallbacks: &mut Vec<Fallback>,
        now: Instant,
    ) {
        for &ip in &self.ips {
            let event = Fallback::Discard(ip);
            if !fallbacks.contains(&event) {
                fallbacks.push(event);
            }
        }
        self.retire_inner(id, endpoints, now);
    }

    fn retire_inner(
        &mut self,
        id: PeerId,
        endpoints: &mut HashMap<SocketAddr, PeerId>,
        now: Instant,
    ) {
        if self.retired {
            return;
        }
        self.retired = true;
        self.retired_at = Some(now);
        if let Some(path) = self.path.take() {
            for candidate in path.candidates {
                remove_endpoint(endpoints, candidate.endpoint, id);
            }
        }
    }
}

fn note_fallback(fallbacks: &mut Vec<Fallback>, ips: &[IpAddr]) {
    for &ip in ips {
        let event = Fallback::Replay(ip);
        if !fallbacks.contains(&event) {
            fallbacks.push(event);
        }
    }
}

fn remove_endpoint(index: &mut HashMap<SocketAddr, PeerId>, endpoint: SocketAddr, id: PeerId) {
    if index.get(&endpoint) == Some(&id) {
        index.remove(&endpoint);
    }
}

fn source(packet: &[u8]) -> Option<IpAddr> {
    address(packet, 12, 8)
}

/// Inspect an outbound TUN packet without allocating or parsing transport headers.
pub(crate) fn destination(packet: &[u8]) -> Option<IpAddr> {
    address(packet, 16, 24)
}

fn address(packet: &[u8], v4: usize, v6: usize) -> Option<IpAddr> {
    match packet.first()? >> 4 {
        4 => {
            let octets: [u8; 4] = packet.get(v4..v4 + 4)?.try_into().ok()?;
            Some(Ipv4Addr::from(octets).into())
        }
        6 => {
            let octets: [u8; 16] = packet.get(v6..v6 + 16)?.try_into().ok()?;
            Some(Ipv6Addr::from(octets).into())
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn test_clock() -> Option<u64> {
        Some(1_000_000_000)
    }

    fn setup() -> (Discovery, PeerInfo) {
        let local = PeerKeyPair::generate().unwrap();
        let remote = PeerKeyPair::generate().unwrap();
        let supernode = "192.0.2.1:9527".parse().unwrap();
        let mut discovery = Discovery::new(
            TunnelAssignment::new("10.0.0.2", "255.255.255.0", "", 0).unwrap(),
            PeerId([1; 16]),
            1,
            local,
            supernode,
        );
        discovery.clock = test_clock;
        let peer = PeerInfo {
            pair_id: vec![5; 16],
            revision: 1,
            local_session_epoch: 1,
            peer_session_epoch: 2,
            peer_id: vec![2; 16],
            peer_public_key: remote.public.to_vec(),
            peer_vpn_ips: vec![IpAddr::V4(Ipv4Addr::new(10, 0, 0, 3)).into()],
            observed_endpoint: Some(SocketAddr::from(([192, 0, 2, 1], 5000)).into()),
            lan_endpoint: None,
            valid_for_ms: 10_000,
            ..Default::default()
        };
        (discovery, peer)
    }

    #[test]
    fn stale_ip_owner() {
        let (mut discovery, mut older) = setup();
        let now = Instant::now();
        let mut current = older.clone();
        current.peer_id = vec![3; 16];
        current.pair_id = vec![6; 16];
        current.revision = 2;
        let ip = IpAddr::try_from(&current.peer_vpn_ips[0]).unwrap();

        assert!(discovery.install(current, Some(ip), now).unwrap());
        assert!(!discovery.install(older.clone(), None, now).unwrap());
        assert_eq!(discovery.by_ip[&ip], PeerId([3; 16]));
        assert!(!discovery.known[&PeerId([3; 16])].retired);

        older.revision = 3;
        assert!(discovery.install(older, Some(ip), now).unwrap());
        assert_eq!(discovery.by_ip[&ip], PeerId([2; 16]));
        assert!(discovery.known[&PeerId([3; 16])].retired);
        assert_eq!(discovery.take_fallbacks(), [Fallback::Discard(ip)]);
    }

    #[tokio::test]
    async fn direct_receive() {
        use crate::client::PeerSocket;
        use std::io::Write;
        use std::sync::{Arc, atomic::AtomicUsize};

        let (mut discovery, mut peer) = setup();
        let remote = PeerKeyPair::generate().unwrap();
        peer.peer_public_key = remote.public.to_vec();
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let remote_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let remote_address = remote_socket.local_addr().unwrap();
        peer.lan_endpoint = Some(remote_address.into());
        let now = Instant::now();
        discovery.enable_direct(PeerSocket {
            mtu: Arc::new(AtomicUsize::new(1280)),
            lan_endpoint: Some(socket.local_addr().unwrap()),
            allow_lan: Arc::new(move |address| address == remote_address),
            gateway: None,
        });
        assert!(discovery.install(peer, None, now).unwrap());
        let sender = PeerId([2; 16]);
        assert!(discovery.known[&sender].path.as_ref().unwrap().is_lan(1));
        let receiver = PeerId([1; 16]);
        let remote_crypto = remote
            .derive([5; 16], (sender, 2), (receiver, 1, discovery.key.public))
            .unwrap();
        let header = protocol::register_header(sender, receiver);
        let mut buffer = Buffer::new(crate::EXTRA_LEN + protocol::REGISTER_HEADER);
        let mut receive = Buffer::new(crate::EXTRA_LEN + protocol::REGISTER_HEADER);
        let request = Register::Request(protocol::PeerRegisterRequest { cookie: 7 });
        protocol::build_peer_register(&mut buffer, &remote_crypto, &header, request, 1452).unwrap();
        let wrong_source = SocketAddr::from(([127, 0, 0, 2], remote_address.port()));
        assert!(
            discovery
                .receive_direct(
                    &socket,
                    &mut receive,
                    wrong_source,
                    &mut buffer.as_ref().to_vec(),
                    now
                )
                .is_none()
        );
        assert!(discovery.by_endpoint.is_empty());

        socket.writable().await.unwrap();
        assert!(
            discovery
                .receive_direct(
                    &socket,
                    &mut receive,
                    remote_address,
                    &mut buffer.as_ref().to_vec(),
                    now
                )
                .is_none()
        );
        assert_eq!(discovery.by_endpoint.get(&remote_address), Some(&sender));
        let mut ack = [0; protocol::REGISTER_MIN];
        let (len, from) =
            tokio::time::timeout(Duration::from_secs(2), remote_socket.recv_from(&mut ack))
                .await
                .unwrap()
                .unwrap();
        assert_eq!(from, socket.local_addr().unwrap());
        assert_eq!(
            protocol::parse_peer_register(&mut ack[..len], &remote_crypto).unwrap(),
            Register::Response(PeerRegisterResponse { cookie: 7 })
        );

        let wire_packet = |buffer: &mut Buffer, source: u8, destination: u8| {
            let mut ip = [0; 1427];
            ip[0] = 0x45;
            let size = ip.len() as u16;
            ip[2..4].copy_from_slice(&size.to_be_bytes());
            ip[12..16].copy_from_slice(&[10, 0, 0, source]);
            ip[16..20].copy_from_slice(&[10, 0, 0, destination]);
            buffer.clear();
            buffer.write_all(&ip).unwrap();
            protocol::build_data_interface(buffer, &remote_crypto).unwrap();
            (buffer.as_ref().to_vec(), ip)
        };
        for (src, dst) in [(8, 2), (3, 4)] {
            let (mut packet, _) = wire_packet(&mut buffer, src, dst);
            assert!(
                discovery
                    .receive_direct(&socket, &mut receive, remote_address, &mut packet, now)
                    .is_none()
            );
        }
        let (mut packet, ip) = wire_packet(&mut buffer, 3, 2);
        let authorization = discovery
            .receive_direct(&socket, &mut receive, remote_address, &mut packet, now)
            .unwrap();
        assert_eq!(packet, ip);
        assert!(discovery.authorizes(authorization));
        discovery.clock = || Some(11_000_000_000);
        assert!(!discovery.authorizes(authorization));
        let (mut packet, _) = wire_packet(&mut buffer, 3, 2);
        assert!(
            discovery
                .receive_direct(&socket, &mut receive, remote_address, &mut packet, now)
                .is_none()
        );
        assert!(discovery.by_endpoint.is_empty());
    }

    #[tokio::test]
    async fn validation_slots() {
        use crate::client::PeerSocket;
        use std::sync::{Arc, atomic::AtomicUsize};

        let (mut discovery, template) = setup();
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        discovery.enable_direct(PeerSocket {
            mtu: Arc::new(AtomicUsize::new(1427)),
            lan_endpoint: None,
            allow_lan: Arc::new(|_| false),
            gateway: None,
        });
        let now = Instant::now();
        for host in 3..=11 {
            let mut peer = template.clone();
            peer.peer_id = vec![host; 16];
            peer.peer_vpn_ips = vec![IpAddr::V4(Ipv4Addr::new(10, 0, 0, host)).into()];
            assert!(discovery.install(peer, None, now).unwrap());
        }
        let mut buffer = Buffer::new(crate::EXTRA_LEN + protocol::REGISTER_HEADER);
        discovery.poll_paths(&socket, &mut buffer, now);
        let (active, waiting): (Vec<_>, Vec<_>) = discovery
            .known
            .iter()
            .partition(|(_, entry)| entry.path.as_ref().unwrap().validating(now));
        assert_eq!(active.len(), MAX_PENDING);
        assert_eq!(waiting.len(), 1);
        let (&id, entry) = waiting[0];
        let later = now + Duration::from_secs(5);
        discovery.observe(entry.ips[0], later);
        discovery.poll_paths(&socket, &mut buffer, later);
        assert!(
            discovery.known[&id]
                .path
                .as_ref()
                .unwrap()
                .validating(later)
        );
    }

    #[tokio::test]
    async fn rebind_peer_port() {
        use crate::client::PeerSocket;
        use std::sync::{Arc, atomic::AtomicUsize};

        let (mut discovery, mut peer) = setup();
        let remote = PeerKeyPair::generate().unwrap();
        peer.peer_public_key = remote.public.to_vec();
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let advertised = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let actual = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let old = advertised.local_addr().unwrap();
        let new = actual.local_addr().unwrap();
        peer.observed_endpoint = Some(old.into());
        let now = Instant::now();
        discovery.enable_direct(PeerSocket {
            mtu: Arc::new(AtomicUsize::new(1427)),
            lan_endpoint: None,
            allow_lan: Arc::new(|_| false),
            gateway: None,
        });
        assert!(discovery.install(peer, None, now).unwrap());
        let id = PeerId([2; 16]);
        let remote_crypto = remote
            .derive(
                [5; 16],
                (id, 2),
                (discovery.local_id, 1, discovery.key.public),
            )
            .unwrap();
        let header = protocol::register_header(id, discovery.local_id);
        let mut outgoing = Buffer::new(crate::EXTRA_LEN + protocol::REGISTER_HEADER);
        let mut incoming = Buffer::new(crate::EXTRA_LEN + protocol::REGISTER_HEADER);
        let mut register = |message| {
            protocol::build_peer_register(
                &mut incoming,
                &remote_crypto,
                &header,
                message,
                protocol::REGISTER_MIN,
            )
            .unwrap();
            incoming.as_ref().to_vec()
        };
        let mut delayed = register(Register::Request(protocol::PeerRegisterRequest {
            cookie: 7,
        }));
        let mut request = register(Register::Request(protocol::PeerRegisterRequest {
            cookie: 8,
        }));
        let last = request.len() - 1;
        request[last] ^= 1;
        assert!(discovery.admit(new, &request));
        discovery.receive_direct(&socket, &mut outgoing, new, &mut request, now);
        assert_eq!(
            discovery.known[&id].path.as_ref().unwrap().candidates[0].endpoint,
            old
        );
        assert!(discovery.by_endpoint.is_empty());

        socket.writable().await.unwrap();
        let mut request = register(Register::Request(protocol::PeerRegisterRequest {
            cookie: 9,
        }));
        discovery.receive_direct(&socket, &mut outgoing, new, &mut request, now);
        assert_eq!(discovery.by_endpoint.get(&new), Some(&id));
        assert!(!discovery.by_endpoint.contains_key(&old));
        let mut wire = [0; protocol::REGISTER_MAX];
        let (len, _) = tokio::time::timeout(Duration::from_secs(2), actual.recv_from(&mut wire))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            protocol::parse_peer_register(&mut wire[..len], &remote_crypto).unwrap(),
            Register::Response(PeerRegisterResponse { cookie: 9 })
        );

        discovery.receive_direct(&socket, &mut outgoing, old, &mut delayed, now);
        assert!(!discovery.by_endpoint.contains_key(&old));

        discovery.observe("10.0.0.3".parse().unwrap(), now);
        for size in [protocol::REGISTER_MIN, 1452] {
            assert_eq!(discovery.known[&id].path.as_ref().unwrap().selected, None);
            let punches = discovery.poll_paths(&socket, &mut outgoing, now);
            if size == protocol::REGISTER_MIN {
                assert_eq!(
                    punches,
                    [Data::Punch(PeerPunch {
                        peer_id: id.0.to_vec(),
                        pair_id: vec![5; 16],
                    })]
                );
            } else {
                assert!(punches.is_empty());
            }
            let (len, _) =
                tokio::time::timeout(Duration::from_secs(2), actual.recv_from(&mut wire))
                    .await
                    .unwrap()
                    .unwrap();
            assert_eq!(len, size);
            let Register::Request(probe) =
                protocol::parse_peer_register(&mut wire[..len], &remote_crypto).unwrap()
            else {
                panic!("expected registration probe");
            };
            let mut ack = register(Register::Response(PeerRegisterResponse {
                cookie: probe.cookie,
            }));
            discovery.receive_direct(&socket, &mut outgoing, new, &mut ack, now);
        }
        let path = discovery.known[&id].path.as_ref().unwrap();
        assert_eq!(path.selected, Some(0));
        assert_eq!(path.candidates[0].endpoint, new);

        let keepalive = now + Duration::from_secs(2);
        discovery.observe("10.0.0.3".parse().unwrap(), keepalive);
        assert!(
            discovery
                .poll_paths(&socket, &mut outgoing, keepalive)
                .is_empty()
        );
        let (len, _) = tokio::time::timeout(Duration::from_secs(2), actual.recv_from(&mut wire))
            .await
            .unwrap()
            .unwrap();
        let Register::Request(probe) =
            protocol::parse_peer_register(&mut wire[..len], &remote_crypto).unwrap()
        else {
            panic!("expected registration probe");
        };
        let wrong_cookie = if probe.cookie == 1 { 2 } else { 1 };
        let mut wrong_ack = register(Register::Response(PeerRegisterResponse {
            cookie: wrong_cookie,
        }));
        discovery.receive_direct(&socket, &mut outgoing, old, &mut wrong_ack, keepalive);
        let path = discovery.known[&id].path.as_ref().unwrap();
        assert_eq!(path.candidates[0].endpoint, new);
        assert_eq!(path.selected, Some(0));

        let mut moved_ack = register(Register::Response(PeerRegisterResponse {
            cookie: probe.cookie,
        }));
        discovery.receive_direct(&socket, &mut outgoing, old, &mut moved_ack, keepalive);
        let path = discovery.known[&id].path.as_ref().unwrap();
        assert_eq!(path.candidates[0].endpoint, old);
        assert_eq!(path.selected, None);
        assert!(discovery.by_endpoint.is_empty());
    }

    #[tokio::test]
    async fn mapping_renewal() {
        use crate::client::PeerSocket;
        use std::io::Write;
        use std::sync::{Arc, atomic::AtomicUsize};

        let (mut discovery, mut peer) = setup();
        let remote = PeerKeyPair::generate().unwrap();
        peer.peer_public_key = remote.public.to_vec();
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let observed = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let mapped = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let rebound = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let rebound_address = rebound.local_addr().unwrap();
        let mapped_address = mapped.local_addr().unwrap();
        let observed_address = observed.local_addr().unwrap();
        peer.observed_endpoint = Some(observed.local_addr().unwrap().into());
        discovery.enable_direct(PeerSocket {
            mtu: Arc::new(AtomicUsize::new(1427)),
            lan_endpoint: None,
            allow_lan: Arc::new(|_| false),
            gateway: None,
        });
        let now = Instant::now();
        let id = PeerId([2; 16]);
        assert!(discovery.install(peer.clone(), None, now).unwrap());
        peer.revision = 2;
        peer.mapped_port = mapped_address.port().into();
        peer.mapped_valid_for_ms = 1_000;
        assert!(discovery.install(peer.clone(), None, now).unwrap());
        socket.writable().await.unwrap();
        let mut buffer = Buffer::new(crate::EXTRA_LEN + protocol::REGISTER_HEADER);
        discovery.poll_paths(&socket, &mut buffer, now);
        let mut packet = [0; protocol::REGISTER_MIN];
        for receiver in [observed, mapped] {
            let len = tokio::time::timeout(Duration::from_secs(1), receiver.recv(&mut packet))
                .await
                .unwrap()
                .unwrap();
            assert_eq!(len, protocol::REGISTER_MIN);
            assert_eq!(packet[0], protocol::PEER_REGISTER);
        }
        let crypto = remote
            .derive(
                [5; 16],
                (id, 2),
                (discovery.local_id, 1, discovery.key.public),
            )
            .unwrap();
        let header = protocol::register_header(id, discovery.local_id);
        for size in [protocol::REGISTER_MIN, protocol::REGISTER_MIN, 1452] {
            discovery.poll_paths(&socket, &mut buffer, now);
            let probe = discovery.known[&id].path.as_ref().unwrap().candidates[1]
                .waiting
                .as_ref()
                .unwrap();
            assert_eq!(probe.size, size);
            let response = Register::Response(PeerRegisterResponse {
                cookie: probe.cookie,
            });
            protocol::build_peer_register(
                &mut buffer,
                &crypto,
                &header,
                response,
                protocol::REGISTER_MIN,
            )
            .unwrap();
            let mut ack = buffer.as_ref().to_vec();
            discovery.receive_direct(&socket, &mut buffer, rebound_address, &mut ack, now);
        }

        discovery.clock = || Some(1_500_000_000);
        peer.revision = 3;
        assert!(discovery.install(peer, None, now).unwrap());
        let path = discovery.known[&id].path.as_ref().unwrap();
        assert_eq!(path.selected, Some(1));
        assert_eq!(path.candidates[0].endpoint, observed_address);
        assert_eq!(path.candidates[1].endpoint, rebound_address);

        let make_packet = |buffer: &mut Buffer| {
            let mut ip = [0; 20];
            ip[..4].copy_from_slice(&[0x45, 0, 0, 20]);
            ip[12..20].copy_from_slice(&[10, 0, 0, 3, 10, 0, 0, 2]);
            buffer.clear();
            buffer.write_all(&ip).unwrap();
            protocol::build_data_interface(buffer, &crypto).unwrap();
            buffer.as_ref().to_vec()
        };
        // The original lease has expired, while the renewed one is still valid.
        discovery.clock = || Some(2_000_000_000);
        let mut packet = make_packet(&mut buffer);
        let authorization = discovery
            .receive_direct(&socket, &mut buffer, rebound_address, &mut packet, now)
            .unwrap();
        assert!(discovery.authorizes(authorization));
        packet[12..20].copy_from_slice(&[10, 0, 0, 2, 10, 0, 0, 3]);
        let destination = "10.0.0.3".parse().unwrap();
        assert_eq!(
            discovery.send_direct(&socket, &mut buffer, &packet, destination, now),
            DirectSend::Sent
        );

        // Advance only the lease clock, as when the device wakes from sleep.
        discovery.clock = || Some(2_500_000_000);
        assert!(!discovery.authorizes(authorization));
        assert_eq!(
            discovery.send_direct(&socket, &mut buffer, &packet, destination, now),
            DirectSend::Relay
        );
        let mut packet = make_packet(&mut buffer);
        assert!(
            discovery
                .receive_direct(&socket, &mut buffer, rebound_address, &mut packet, now)
                .is_none()
        );
        discovery.poll_paths(&socket, &mut buffer, now);
        assert!(!discovery.by_endpoint.contains_key(&rebound_address));
        assert_eq!(
            discovery.known[&id].path.as_ref().unwrap().candidates.len(),
            1
        );

        for from in [mapped_address, rebound_address] {
            protocol::build_peer_register(
                &mut buffer,
                &crypto,
                &header,
                Register::Request(protocol::PeerRegisterRequest { cookie: 7 }),
                protocol::REGISTER_MIN,
            )
            .unwrap();
            let mut late_register = buffer.as_ref().to_vec();
            discovery.receive_direct(&socket, &mut buffer, from, &mut late_register, now);
            assert!(!discovery.by_endpoint.contains_key(&from));
            assert_eq!(
                discovery.known[&id].path.as_ref().unwrap().candidates[0].endpoint,
                observed_address
            );
        }
    }

    #[test]
    fn retired_capacity() {
        let (mut discovery, template) = setup();
        let now = Instant::now();
        let peer = |host: u8| PeerInfo {
            peer_id: vec![host; 16],
            pair_id: vec![host; 16],
            revision: u64::from(host),
            peer_vpn_ips: vec![IpAddr::V4(Ipv4Addr::new(10, 0, 0, host)).into()],
            ..template.clone()
        };
        for host in 3..=66 {
            assert!(discovery.install(peer(host), None, now).unwrap());
        }
        assert!(!discovery.install(peer(100), None, now).unwrap());

        let first = PeerId([3; 16]);
        discovery.known.get_mut(&first).unwrap().expires = 0;
        discovery.expire(now);
        assert!(discovery.install(peer(100), None, now).unwrap());
        let extra = PeerId([100; 16]);
        discovery.known.get_mut(&extra).unwrap().expires = 0;
        discovery.expire(now + Duration::from_millis(1));

        for host in 101..=170 {
            let tick = now + Duration::from_millis(u64::from(host));
            assert!(discovery.install(peer(host), None, tick).unwrap());
            let id = PeerId([host; 16]);
            discovery.known.get_mut(&id).unwrap().expires = 0;
            discovery.expire(tick);
        }
        assert!(discovery.known.len() <= MAX_KNOWN + MAX_RETIRED);
        assert!(
            discovery
                .known
                .values()
                .filter(|entry| entry.retired)
                .count()
                <= MAX_RETIRED
        );
        assert!(!discovery.known.contains_key(&first));
        assert!(!discovery.by_ip.contains_key(&"10.0.0.3".parse().unwrap()));

        let latest = PeerId([170; 16]);
        let latest_ip = "10.0.0.170".parse().unwrap();
        discovery.observe(latest_ip, now);
        assert!(matches!(
            discovery.pending.get(&latest_ip).map(|query| query.kind),
            Some(QueryKind::Replace(pair)) if pair == [170; 16]
        ));
        assert!(discovery.known.contains_key(&latest));
    }

    fn receive_pending(
        discovery: &mut Discovery,
        socket: &UdpSocket,
        buffer: &mut Buffer,
        now: Instant,
        delivered: &mut Vec<Vec<u8>>,
    ) {
        let mut wire = [0; protocol::REGISTER_MAX];
        loop {
            match socket.try_recv_from(&mut wire) {
                Ok((len, from)) => {
                    let mut packet = wire[..len].to_vec();
                    if let Some(authorization) =
                        discovery.receive_direct(socket, buffer, from, &mut packet, now)
                    {
                        assert!(discovery.authorizes(authorization));
                        delivered.push(packet);
                    }
                }
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => break,
                Err(error) => panic!("peer receive failed: {error}"),
            }
        }
    }

    #[tokio::test]
    async fn direct_fallback() {
        use crate::client::PeerSocket;
        use std::sync::{Arc, atomic::AtomicUsize};

        let a_id = PeerId([1; 16]);
        let b_id = PeerId([2; 16]);
        let a_vpn = Ipv4Addr::new(10, 0, 0, 2);
        let b_vpn = Ipv4Addr::new(10, 0, 0, 3);
        let a_key = PeerKeyPair::generate().unwrap();
        let b_key = PeerKeyPair::generate().unwrap();
        let a_public = a_key.public;
        let b_public = b_key.public;
        let supernode = "192.0.2.1:9527".parse().unwrap();
        let mut a = Discovery::new(
            TunnelAssignment::new("10.0.0.2", "255.255.255.0", "", 0).unwrap(),
            a_id,
            1,
            a_key,
            supernode,
        );
        let mut b = Discovery::new(
            TunnelAssignment::new("10.0.0.3", "255.255.255.0", "", 0).unwrap(),
            b_id,
            2,
            b_key,
            supernode,
        );
        a.clock = test_clock;
        b.clock = test_clock;
        let a_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let b_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let a_endpoint = a_socket.local_addr().unwrap();
        let b_endpoint = b_socket.local_addr().unwrap();
        for discovery in [&mut a, &mut b] {
            discovery.enable_direct(PeerSocket {
                mtu: Arc::new(AtomicUsize::new(1427)),
                lan_endpoint: None,
                allow_lan: Arc::new(|_| false),
                gateway: None,
            });
            discovery.confirm();
        }

        fn introduction(
            local_epoch: u64,
            peer_epoch: u64,
            peer: PeerId,
            public: [u8; 32],
            ip: Ipv4Addr,
            endpoint: SocketAddr,
        ) -> PeerInfo {
            PeerInfo {
                pair_id: vec![5; 16],
                revision: 1,
                local_session_epoch: local_epoch,
                peer_session_epoch: peer_epoch,
                peer_id: peer.0.to_vec(),
                peer_public_key: public.to_vec(),
                peer_vpn_ips: vec![IpAddr::V4(ip).into()],
                observed_endpoint: Some(endpoint.into()),
                lan_endpoint: None,
                valid_for_ms: 10_000,
                ..Default::default()
            }
        }
        let now = Instant::now();
        assert!(
            a.install(
                introduction(1, 2, b_id, b_public, b_vpn, b_endpoint),
                Some(IpAddr::V4(b_vpn)),
                now,
            )
            .unwrap()
        );
        assert!(
            b.install(
                introduction(2, 1, a_id, a_public, a_vpn, a_endpoint),
                Some(IpAddr::V4(a_vpn)),
                now,
            )
            .unwrap()
        );

        let mut a_buffer = Buffer::new(crate::EXTRA_LEN + protocol::REGISTER_HEADER);
        let mut b_buffer = Buffer::new(crate::EXTRA_LEN + protocol::REGISTER_HEADER);
        let mut a_packets = Vec::new();
        let mut b_packets = Vec::new();
        tokio::time::timeout(Duration::from_secs(3), async {
            loop {
                let now = Instant::now();
                a.poll_paths(&a_socket, &mut a_buffer, now);
                b.poll_paths(&b_socket, &mut b_buffer, now);
                receive_pending(&mut a, &a_socket, &mut a_buffer, now, &mut a_packets);
                receive_pending(&mut b, &b_socket, &mut b_buffer, now, &mut b_packets);
                if a.known[&b_id].path.as_ref().unwrap().selected.is_some()
                    && b.known[&a_id].path.as_ref().unwrap().selected.is_some()
                {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("peers did not validate full-size direct paths");

        let packet = |source: Ipv4Addr, destination: Ipv4Addr| {
            let mut packet = vec![source.octets()[3]; 1427];
            packet[0] = 0x45;
            let size = packet.len() as u16;
            packet[2..4].copy_from_slice(&size.to_be_bytes());
            packet[12..16].copy_from_slice(&source.octets());
            packet[16..20].copy_from_slice(&destination.octets());
            packet
        };
        let a_to_b = packet(a_vpn, b_vpn);
        assert_eq!(
            a.send_direct(
                &a_socket,
                &mut a_buffer,
                &a_to_b,
                IpAddr::V4(b_vpn),
                Instant::now(),
            ),
            DirectSend::Sent
        );
        tokio::time::timeout(Duration::from_secs(1), async {
            while b_packets.is_empty() {
                receive_pending(
                    &mut b,
                    &b_socket,
                    &mut b_buffer,
                    Instant::now(),
                    &mut b_packets,
                );
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .expect("direct A-to-B packet was not delivered");
        assert_eq!(b_packets, std::slice::from_ref(&a_to_b));

        let b_to_a = packet(b_vpn, a_vpn);
        assert_eq!(
            b.send_direct(
                &b_socket,
                &mut b_buffer,
                &b_to_a,
                IpAddr::V4(a_vpn),
                Instant::now(),
            ),
            DirectSend::Sent
        );
        tokio::time::timeout(Duration::from_secs(1), async {
            while a_packets.is_empty() {
                receive_pending(
                    &mut a,
                    &a_socket,
                    &mut a_buffer,
                    Instant::now(),
                    &mut a_packets,
                );
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .expect("direct B-to-A packet was not delivered");
        assert_eq!(a_packets, [b_to_a]);

        a.fallbacks.push(Fallback::Discard(IpAddr::V4(b_vpn)));
        assert_eq!(
            a.send_direct(
                &a_socket,
                &mut a_buffer,
                &a_to_b,
                IpAddr::V4(b_vpn),
                Instant::now(),
            ),
            DirectSend::Discard
        );
        a.take_fallbacks();

        drop(b_socket);
        let failed_at = Instant::now();
        for step in 1..=4 {
            let tick = failed_at + Duration::from_secs(2 * step);
            a.observe(IpAddr::V4(b_vpn), tick);
            a.poll_paths(&a_socket, &mut a_buffer, tick);
            if step == 2 {
                assert_eq!(
                    a.send_direct(&a_socket, &mut a_buffer, &a_to_b, IpAddr::V4(b_vpn), tick,),
                    DirectSend::Suspend
                );
            }
        }
        assert!(a.known[&b_id].path.as_ref().unwrap().selected.is_none());
        assert_eq!(
            a.send_direct(
                &a_socket,
                &mut a_buffer,
                &a_to_b,
                IpAddr::V4(b_vpn),
                failed_at + Duration::from_secs(8),
            ),
            DirectSend::Relay
        );
        assert!(
            a.take_fallbacks()
                .contains(&Fallback::Replay(IpAddr::V4(b_vpn)))
        );
    }

    #[test]
    fn discover_from_relay() {
        use crate::client::PeerSocket;
        use std::sync::{Arc, atomic::AtomicUsize};

        let (mut discovery, _) = setup();
        discovery.enable_direct(PeerSocket {
            mtu: Arc::new(AtomicUsize::new(1427)),
            lan_endpoint: None,
            allow_lan: Arc::new(|_| false),
            gateway: None,
        });
        let now = Instant::now();
        let mut packet = [0; 20];
        packet[0] = 0x45;
        packet[12..16].copy_from_slice(&[192, 0, 2, 8]);
        packet[16..20].copy_from_slice(&[10, 0, 0, 2]);
        discovery.observe_relayed(&packet, now);
        assert!(discovery.pending.is_empty());

        packet[12..16].copy_from_slice(&[10, 0, 0, 3]);
        discovery.observe_relayed(&packet, now);
        discovery.observe_relayed(&packet, now);
        assert_eq!(discovery.pending.len(), 1);
        assert!(
            discovery
                .pending
                .contains_key(&"10.0.0.3".parse::<IpAddr>().unwrap())
        );
    }

    #[test]
    fn independent_request_ids() {
        let (mut discovery, peer) = setup();
        let now = Instant::now();
        for ip in [
            "10.0.0.0",
            "10.0.0.2",
            "10.0.0.3",
            "10.0.0.255",
            "192.0.2.5",
        ] {
            discovery.observe(ip.parse().unwrap(), now);
        }
        assert_eq!(discovery.pending.len(), 1);
        assert!(discovery.due_queries(now).is_empty());
        discovery.confirm();
        let queries = discovery.due_queries(now);
        let [Data::Request(query)] = queries.as_slice() else {
            panic!("expected one query")
        };
        let intro = Data::Request(FindPeerRequest {
            request_id: query.request_id,
            target: Some(Target::Peer(peer.clone())),
            ..Default::default()
        });
        let ack = Data::Response(FindPeerResponse {
            request_id: query.request_id,
            peer: None,
        });
        assert_eq!(
            discovery.receive(intro.clone(), now).unwrap(),
            Some(ack.clone())
        );
        assert_eq!(
            discovery
                .receive(intro, now + Duration::from_secs(1))
                .unwrap(),
            Some(ack)
        );
        assert_eq!(discovery.pending.len(), 1);
        assert_eq!(discovery.due_queries(now + RETRIES[1]), queries);
        discovery
            .receive(
                Data::Response(FindPeerResponse {
                    request_id: query.request_id,
                    peer: Some(peer),
                }),
                now + RETRIES[1],
            )
            .unwrap();
        assert!(discovery.pending.is_empty());
        let latest = &discovery.known[&PeerId([2; 16])];
        assert_eq!(latest.expires, 11_000_000_000);
    }

    #[test]
    fn reject_expired_pair() {
        let (mut discovery, mut peer) = setup();
        let now = Instant::now();
        assert!(discovery.install(peer.clone(), None, now).unwrap());
        let expired = now + Duration::from_secs(10);
        discovery.clock = || Some(11_000_000_000);
        peer.revision = 2;
        assert!(!discovery.install(peer.clone(), None, expired).unwrap());
        peer.pair_id = vec![6; 16];
        assert!(discovery.install(peer, None, expired).unwrap());
    }
}
