// SPDX-License-Identifier: MIT
use std::{
    collections::{BTreeMap, HashMap},
    net::{IpAddr, SocketAddr},
    time::{Duration, Instant},
};
use vault_core::{
    HandshakeRequest, PeerId,
    protocol::{
        FindPeerRequest, FindPeerResponse, PeerInfo, PeerMapping, PeerPunch,
        find_peer_message::Data, find_peer_request::Target, random_pair_id,
    },
    valid_peer_public_key,
};

const MAX_LEASE: Duration = Duration::from_secs(60);
const RETRY_DELAYS: [Duration; 3] = [
    Duration::ZERO,
    Duration::from_millis(400),
    Duration::from_secs(1),
];
const REQUEST_TIMEOUT: Duration = Duration::from_secs(2);
const REQUEST_WINDOW: u64 = 32;
const QUERIES_PER_SECOND: u8 = 16;
const MAX_PENDING_INTRODUCTIONS: usize = 8;

pub struct Registration {
    pub epoch: u64,
    key: [u8; 32],
    lan: Option<SocketAddr>,
}

struct Session {
    registration: Registration,
    addr: SocketAddr,
    vpn_ips: [Option<IpAddr>; 2],
    query_window: Instant,
    queries: u8,
    highest_request: u64,
    requests: BTreeMap<u64, CachedQuery>,
    next_introduction: u64,
    mapping_revision: u64,
    mapping_updated: Option<Instant>,
    mapping: Option<(u16, Instant)>,
}

struct CachedQuery {
    request: FindPeerRequest,
    result: Option<([PeerId; 2], Pair)>,
    expires: Instant,
}

#[derive(Clone, Copy)]
struct Pair {
    id: [u8; 16],
    revision: u64,
    expires: Instant,
    punches: [bool; 2],
}

struct Introduction {
    request_id: u64,
    pair: Pair,
    started: Instant,
    sent: usize,
}

fn pair_key(a: PeerId, b: PeerId) -> [PeerId; 2] {
    if a.0 < b.0 { [a, b] } else { [b, a] }
}

pub struct Directory {
    sessions: HashMap<PeerId, Session>,
    pairs: HashMap<[PeerId; 2], Pair>,
    introductions: HashMap<([PeerId; 2], PeerId), Introduction>,
    epoch: u64,
    revision: u64,
}

impl Directory {
    pub fn new() -> Self {
        Self {
            sessions: HashMap::new(),
            pairs: HashMap::new(),
            introductions: HashMap::new(),
            epoch: 0,
            revision: 0,
        }
    }

    pub fn registration(
        &mut self,
        request: &HandshakeRequest,
        addr: SocketAddr,
    ) -> Option<Registration> {
        let key = request.peer_public_key.as_slice().try_into().ok()?;
        if key == request.public_key_data.as_slice() || !valid_peer_public_key(key) {
            return None;
        }
        let lan = match &request.peer_lan_endpoint {
            None => None,
            Some(endpoint) => {
                let lan = SocketAddr::try_from(endpoint).ok()?;
                let ip = lan.ip();
                if addr.ip().to_canonical().is_ipv4() != lan.is_ipv4()
                    || ip.is_unspecified()
                    || ip.is_multicast()
                    || ip.is_loopback()
                    || match ip {
                        IpAddr::V4(ip) => ip.is_broadcast() || ip.is_link_local(),
                        IpAddr::V6(ip) => ip.is_unicast_link_local(),
                    }
                {
                    return None;
                }
                Some(lan)
            }
        };
        self.epoch = self.epoch.checked_add(1)?;
        Some(Registration {
            epoch: self.epoch,
            key,
            lan,
        })
    }

    pub fn confirm(
        &mut self,
        id: PeerId,
        addr: SocketAddr,
        vpn_ips: [Option<IpAddr>; 2],
        registration: Option<Registration>,
        now: Instant,
    ) {
        self.remove(id);
        if let Some(registration) = registration {
            self.sessions.insert(
                id,
                Session {
                    registration,
                    addr,
                    vpn_ips,
                    query_window: now,
                    queries: 0,
                    highest_request: 0,
                    requests: BTreeMap::new(),
                    next_introduction: 0,
                    mapping_revision: 0,
                    mapping_updated: None,
                    mapping: None,
                },
            );
        }
    }

    pub fn remove(&mut self, id: PeerId) {
        if self.sessions.remove(&id).is_some() {
            self.pairs.retain(|pair, _| !pair.contains(&id));
            self.introductions
                .retain(|(pair, _), _| !pair.contains(&id));
        }
    }

    pub fn query(
        &mut self,
        source: PeerId,
        request: FindPeerRequest,
        resolve: impl FnOnce(IpAddr) -> Option<(PeerId, Duration)>,
        now: Instant,
    ) -> anyhow::Result<Option<Data>> {
        let Some(Target::TargetVpnIp(ip)) = &request.target else {
            return Ok(None);
        };
        let ip = IpAddr::try_from(ip)?;
        let id = request.request_id;
        let renew = pair_id(&request.renew_pair_id)?;
        let replace = pair_id(&request.replace_pair_id)?;
        if id == 0 || renew.is_some() && replace.is_some() {
            return Ok(None);
        }
        let Some(session) = self.sessions.get_mut(&source) else {
            return Ok(None);
        };
        if now - session.query_window >= Duration::from_secs(1) {
            session.query_window = now;
            session.queries = 0;
        }
        if session.queries >= QUERIES_PER_SECOND {
            return Ok(None);
        }
        session.queries += 1;
        let floor = session.highest_request.saturating_sub(REQUEST_WINDOW - 1);
        if id < floor {
            return Ok(None);
        }
        if let Some(cached) = session.requests.get(&id) {
            if now >= cached.expires || cached.request != request {
                return Ok(None);
            }
            let result = cached.result;
            return Ok(Some(self.response(source, id, result, now)));
        }
        session.highest_request = session.highest_request.max(id);
        let floor = session.highest_request.saturating_sub(REQUEST_WINDOW - 1);
        session.requests.retain(|id, _| *id >= floor);

        let mut result = None;
        if let Some((target, remaining_lease)) = resolve(ip) {
            let key = pair_key(source, target);
            if source != target && self.sessions.contains_key(&target) {
                let source_session = &self.sessions[&source];
                let target_session = &self.sessions[&target];
                if source_session.addr.ip().to_canonical().is_ipv4()
                    == target_session.addr.ip().to_canonical().is_ipv4()
                    && target_session.vpn_ips.contains(&Some(ip))
                {
                    result = self
                        .authorize(key, renew, replace, remaining_lease, now)?
                        .map(|pair| (key, pair));
                    if let Some((key, pair)) = result {
                        self.introduce(key, target, pair, now);
                    }
                }
            }
        }
        if let Some(session) = self.sessions.get_mut(&source) {
            session.requests.insert(
                id,
                CachedQuery {
                    request,
                    result,
                    expires: now + REQUEST_TIMEOUT,
                },
            );
        }
        Ok(Some(self.response(source, id, result, now)))
    }

    fn authorize(
        &mut self,
        key: [PeerId; 2],
        renew: Option<[u8; 16]>,
        replace: Option<[u8; 16]>,
        remaining_lease: Duration,
        now: Instant,
    ) -> anyhow::Result<Option<Pair>> {
        let ttl = remaining_lease.min(MAX_LEASE);
        if ttl.is_zero() {
            return Ok(None);
        }
        let current = self.pairs.get(&key).copied().filter(|p| now < p.expires);
        let id = match (current, renew) {
            (Some(pair), Some(renew)) if pair.id == renew => pair.id,
            (_, Some(_)) => return Ok(None),
            (Some(pair), None) if replace != Some(pair.id) => return Ok(Some(pair)),
            _ => random_pair_id()?,
        };
        self.revision = self
            .revision
            .checked_add(1)
            .ok_or_else(|| anyhow::anyhow!("P2P revisions exhausted"))?;
        let pair = Pair {
            id,
            revision: self.revision,
            expires: now + ttl,
            punches: current
                .filter(|pair| pair.id == id)
                .map_or([false; 2], |pair| pair.punches),
        };
        self.pairs.insert(key, pair);
        Ok(Some(pair))
    }

    pub fn punch(
        &mut self,
        source: PeerId,
        notice: PeerPunch,
        now: Instant,
    ) -> Option<(SocketAddr, Data)> {
        let target = PeerId::try_from(notice.peer_id).ok()?;
        if target == source {
            return None;
        }
        let id: [u8; 16] = notice.pair_id.try_into().ok()?;
        let key = pair_key(source, target);
        let pair = *self.pairs.get(&key)?;
        let direction = usize::from(source == key[1]);
        if id != pair.id || now >= pair.expires || pair.punches[direction] {
            return None;
        }
        let peer = self.info(key, target, pair, now)?;
        let recipient = self.sessions.get(&target)?.addr;
        self.pairs.get_mut(&key)?.punches[direction] = true;
        Some((recipient, Data::PunchPeer(peer)))
    }

    pub fn update_mapping(&mut self, source: PeerId, mapping: PeerMapping, now: Instant) {
        let Some(session) = self.sessions.get_mut(&source) else {
            return;
        };
        let Ok(port) = u16::try_from(mapping.port) else {
            return;
        };
        if !session.addr.ip().to_canonical().is_ipv4()
            || mapping.revision <= session.mapping_revision
            || (port == 0) != (mapping.lifetime_ms == 0)
            || session
                .mapping_updated
                .is_some_and(|prior| now.saturating_duration_since(prior) < Duration::from_secs(1))
        {
            return;
        }
        let previous = session.mapping;
        session.mapping_revision = mapping.revision;
        session.mapping_updated = Some(now);
        session.mapping = (port != 0 && port != session.addr.port()).then(|| {
            (
                port,
                now + Duration::from_millis(u64::from(mapping.lifetime_ms.min(120_000))),
            )
        });
        let current = session.mapping;
        if !mapping_changed(previous, current, now + MAX_LEASE) {
            return;
        }

        let mut changed = Vec::new();
        for (&key, pair) in &mut self.pairs {
            if key.contains(&source)
                && now < pair.expires
                && mapping_changed(previous, current, pair.expires)
                && let Some(revision) = self.revision.checked_add(1)
            {
                self.revision = revision;
                pair.revision = revision;
                let recipient = key[usize::from(key[0] == source)];
                changed.push((key, recipient, *pair));
            }
        }
        for (key, recipient, pair) in changed {
            self.introduce(key, recipient, pair, now);
        }
    }

    fn response(
        &self,
        source: PeerId,
        request_id: u64,
        result: Option<([PeerId; 2], Pair)>,
        now: Instant,
    ) -> Data {
        let peer = result.and_then(|(key, pair)| self.info(key, source, pair, now));
        Data::Response(FindPeerResponse { request_id, peer })
    }

    fn info(
        &self,
        key: [PeerId; 2],
        recipient: PeerId,
        pair: Pair,
        now: Instant,
    ) -> Option<PeerInfo> {
        if self.pairs.get(&key)?.id != pair.id {
            return None;
        }
        let valid_for_ms = pair.expires.checked_duration_since(now)?.as_millis() as u32;
        if valid_for_ms == 0 {
            return None;
        }
        let peer_id = if recipient == key[0] { key[1] } else { key[0] };
        let local = self.sessions.get(&recipient)?;
        let peer = self.sessions.get(&peer_id)?;
        let lan_endpoint = match (
            local.addr.ip().to_canonical(),
            peer.addr.ip().to_canonical(),
            local.registration.lan,
            peer.registration.lan,
        ) {
            (IpAddr::V4(a), IpAddr::V4(b), Some(SocketAddr::V4(x)), Some(SocketAddr::V4(y)))
                if a == b && x.ip().is_private() && y.ip().is_private() && x.ip() != y.ip() =>
            {
                Some(SocketAddr::V4(y).into())
            }
            _ => None,
        };
        let (mapped_port, mapped_valid_for_ms) = peer
            .mapping
            .and_then(|(port, expires)| {
                let remaining = expires.checked_duration_since(now)?.as_millis() as u32;
                (remaining > 0).then_some((u32::from(port), remaining.min(valid_for_ms)))
            })
            .unwrap_or_default();
        Some(PeerInfo {
            pair_id: pair.id.to_vec(),
            revision: pair.revision,
            local_session_epoch: local.registration.epoch,
            peer_session_epoch: peer.registration.epoch,
            peer_id: peer_id.0.to_vec(),
            peer_public_key: peer.registration.key.to_vec(),
            peer_vpn_ips: peer.vpn_ips.into_iter().flatten().map(Into::into).collect(),
            observed_endpoint: Some(peer.addr.into()),
            lan_endpoint,
            valid_for_ms,
            mapped_port,
            mapped_valid_for_ms,
            accepts_mapping: true,
        })
    }

    fn introduce(&mut self, key: [PeerId; 2], target: PeerId, pair: Pair, now: Instant) {
        if let Some(existing) = self.introductions.get(&(key, target)) {
            if existing.pair.revision == pair.revision {
                return;
            }
        } else if self
            .introductions
            .keys()
            .filter(|(_, recipient)| *recipient == target)
            .count()
            >= MAX_PENDING_INTRODUCTIONS
        {
            return;
        }
        let session = self
            .sessions
            .get_mut(&target)
            .expect("online introduction recipient");
        let Some(request_id) = session.next_introduction.checked_add(1) else {
            return;
        };
        session.next_introduction = request_id;
        self.introductions.insert(
            (key, target),
            Introduction {
                request_id,
                pair,
                started: now,
                sent: 0,
            },
        );
    }

    pub fn acknowledge(&mut self, source: PeerId, response: FindPeerResponse) {
        if response.peer.is_none() && response.request_id != 0 {
            self.introductions.retain(|(_, target), intro| {
                *target != source || intro.request_id != response.request_id
            });
        }
    }

    pub fn due_introductions(&mut self, now: Instant) -> Vec<(SocketAddr, Data)> {
        self.pairs.retain(|_, pair| now < pair.expires);
        self.introductions.retain(|(key, _), intro| {
            now - intro.started < REQUEST_TIMEOUT
                && self
                    .pairs
                    .get(key)
                    .is_some_and(|pair| pair.id == intro.pair.id)
        });
        let mut due = Vec::new();
        for (&(key, target), intro) in &mut self.introductions {
            if let Some(delay) = RETRY_DELAYS.get(intro.sent)
                && now - intro.started >= *delay
            {
                intro.sent += 1;
                due.push((key, target, intro.request_id, intro.pair));
            }
        }
        due.into_iter()
            .filter_map(|(key, target, request_id, pair)| {
                let peer = self.info(key, target, pair, now)?;
                let addr = self.sessions.get(&target)?.addr;
                Some((
                    addr,
                    Data::Request(FindPeerRequest {
                        request_id,
                        target: Some(Target::Peer(peer)),
                        renew_pair_id: Vec::new(),
                        replace_pair_id: Vec::new(),
                    }),
                ))
            })
            .collect()
    }
}

fn mapping_changed(
    previous: Option<(u16, Instant)>,
    current: Option<(u16, Instant)>,
    pair_expires: Instant,
) -> bool {
    match (previous, current) {
        (Some((old_port, old_expires)), Some((new_port, new_expires))) if old_port == new_port => {
            // Periodic announcements repeat the remaining lifetime. Ignore
            // network jitter and deadline changes beyond the pair's own lease.
            let old = old_expires.min(pair_expires);
            let new = new_expires.min(pair_expires);
            old.max(new).duration_since(old.min(new)) >= Duration::from_millis(100)
        }
        _ => previous != current,
    }
}

fn pair_id(bytes: &[u8]) -> anyhow::Result<Option<[u8; 16]>> {
    if bytes.is_empty() {
        Ok(None)
    } else {
        Ok(Some(bytes.try_into()?))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const A: PeerId = PeerId([1; 16]);
    const B: PeerId = PeerId([2; 16]);
    const C: PeerId = PeerId([3; 16]);

    fn ip(id: PeerId) -> IpAddr {
        [10, 0, 0, id.0[0] + 1].into()
    }

    fn addr(id: PeerId) -> SocketAddr {
        format!("[::ffff:192.0.2.1]:100{}", id.0[0])
            .parse()
            .unwrap()
    }

    fn register(directory: &mut Directory, id: PeerId) -> Option<Registration> {
        let mut key = vec![0; 32];
        key[0] = 9;
        directory.registration(
            &HandshakeRequest {
                id,
                pake_message: Vec::new(),
                public_key_data: vec![10; 32],
                algorithms: Vec::new(),
                timestamp: 0,
                version: vault_core::PROTOCOL_VERSION,
                device_name: String::new(),
                platform: String::new(),
                peer_public_key: key,
                peer_lan_endpoint: Some(SocketAddr::from(([192, 168, 0, id.0[0]], 9999)).into()),
            },
            addr(id),
        )
    }

    fn confirm(
        directory: &mut Directory,
        id: PeerId,
        registration: Option<Registration>,
        now: Instant,
    ) {
        directory.confirm(id, addr(id), [Some(ip(id)), None], registration, now);
    }

    fn request(id: u64, target: PeerId) -> FindPeerRequest {
        FindPeerRequest {
            request_id: id,
            target: Some(Target::TargetVpnIp(ip(target).into())),
            ..Default::default()
        }
    }

    fn query(
        directory: &mut Directory,
        source: PeerId,
        target: PeerId,
        request: FindPeerRequest,
        now: Instant,
    ) -> Option<PeerInfo> {
        let result = directory
            .query(
                source,
                request,
                |address| {
                    assert_eq!(ip(target), address);
                    Some((target, Duration::from_secs(42)))
                },
                now,
            )
            .unwrap();
        let Some(Data::Response(response)) = result else {
            panic!("expected query response")
        };
        response.peer
    }

    #[test]
    fn mapping_update() {
        let now = Instant::now();
        let mut directory = Directory::new();
        for id in [A, B] {
            let registration = register(&mut directory, id);
            confirm(&mut directory, id, registration, now);
        }
        let before = query(&mut directory, A, B, request(1, B), now).unwrap();
        directory.update_mapping(
            B,
            PeerMapping {
                revision: 1,
                port: 40_000,
                lifetime_ms: 20_000,
            },
            now,
        );
        let updates = directory.due_introductions(now);
        let notice = updates
            .iter()
            .find_map(|(recipient, data)| match data {
                Data::Request(FindPeerRequest {
                    target: Some(Target::Peer(info)),
                    ..
                }) if *recipient == addr(A) => Some(info),
                _ => None,
            })
            .unwrap();
        assert_eq!(notice.pair_id, before.pair_id);
        assert!(notice.revision > before.revision);
        assert_eq!(notice.observed_endpoint, before.observed_endpoint);
        assert_eq!(notice.mapped_port, 40_000);
        assert_eq!(notice.mapped_valid_for_ms, 20_000);

        let later = now + Duration::from_secs(2);
        directory.update_mapping(
            B,
            PeerMapping {
                revision: 2,
                port: 40_000,
                lifetime_ms: 18_000,
            },
            later,
        );
        assert_eq!(directory.pairs[&pair_key(A, B)].revision, notice.revision);

        let renewed = later + Duration::from_secs(8);
        directory.update_mapping(
            B,
            PeerMapping {
                revision: 3,
                port: 40_000,
                lifetime_ms: 20_000,
            },
            renewed,
        );
        assert!(directory.due_introductions(renewed).iter().any(|(recipient, data)| {
            *recipient == addr(A) && matches!(
                data,
                Data::Request(FindPeerRequest { target: Some(Target::Peer(info)), .. })
                    if info.pair_id == notice.pair_id && info.revision > notice.revision
                        && info.mapped_port == 40_000 && info.mapped_valid_for_ms == 20_000
            )
        }));

        let later = renewed + Duration::from_secs(2);
        directory.update_mapping(
            B,
            PeerMapping {
                revision: 4,
                port: 0,
                lifetime_ms: 0,
            },
            later,
        );
        directory.update_mapping(
            B,
            PeerMapping {
                revision: 1,
                port: 40_000,
                lifetime_ms: 120_000,
            },
            later + Duration::from_secs(1),
        );
        let response = query(&mut directory, A, B, request(2, B), later).unwrap();
        assert_eq!(response.pair_id, before.pair_id);
        assert_eq!(response.mapped_port, 0);
    }

    #[test]
    fn punch_relay_once() {
        let now = Instant::now();
        let mut directory = Directory::new();
        for id in [A, B, C] {
            let registration = register(&mut directory, id);
            confirm(&mut directory, id, registration, now);
        }
        let pair = query(&mut directory, A, B, request(1, B), now).unwrap();
        let notice = PeerPunch {
            peer_id: B.0.to_vec(),
            pair_id: pair.pair_id.clone(),
        };
        assert!(directory.punch(C, notice.clone(), now).is_none());

        let (recipient, Data::PunchPeer(peer)) = directory.punch(A, notice.clone(), now).unwrap()
        else {
            panic!("expected a forwarded punch");
        };
        assert_eq!(recipient, addr(B));
        assert_eq!(peer.peer_id, A.0);
        assert_eq!(peer.pair_id, pair.pair_id);
        assert_eq!(
            SocketAddr::try_from(peer.observed_endpoint.as_ref().unwrap()).unwrap(),
            "192.0.2.1:1001".parse::<SocketAddr>().unwrap(),
        );
        assert!(directory.punch(A, notice.clone(), now).is_none());
        let renew = FindPeerRequest {
            renew_pair_id: pair.pair_id.clone(),
            ..request(2, B)
        };
        assert!(query(&mut directory, A, B, renew, now).is_some());
        assert!(directory.punch(A, notice.clone(), now).is_none());

        let reverse = PeerPunch {
            peer_id: A.0.to_vec(),
            pair_id: pair.pair_id,
        };
        assert!(directory.punch(B, reverse, now).is_some());
        directory.remove(B);
        assert!(directory.punch(A, notice, now).is_none());
    }

    #[test]
    fn confirmed_peers_only() {
        let now = Instant::now();
        let mut directory = Directory::new();

        let a = register(&mut directory, A).unwrap();
        let b = register(&mut directory, B).unwrap();
        assert!(a.epoch != 0 && b.epoch > a.epoch);
        let (a_epoch, b_epoch) = (a.epoch, b.epoch);
        confirm(&mut directory, A, Some(a), now);
        assert!(query(&mut directory, A, B, request(1, B), now).is_none());
        assert!(directory.due_introductions(now).is_empty());
        confirm(&mut directory, B, Some(b), now);

        let result = query(&mut directory, A, B, request(2, B), now).unwrap();
        assert_eq!(
            (result.local_session_epoch, result.peer_session_epoch),
            (a_epoch, b_epoch)
        );
        assert_eq!(result.valid_for_ms, 42_000);
        assert_eq!(
            SocketAddr::try_from(result.observed_endpoint.as_ref().unwrap()).unwrap(),
            "192.0.2.1:1002".parse::<SocketAddr>().unwrap()
        );
        assert!(result.lan_endpoint.is_some());

        let mut introductions = directory.due_introductions(now);
        let (recipient, Data::Request(intro)) = introductions.pop().unwrap() else {
            panic!("expected introduction");
        };
        assert_eq!(recipient, addr(B));
        let Some(Target::Peer(info)) = intro.target.as_ref() else {
            panic!("expected peer info")
        };
        assert_eq!(info.pair_id, result.pair_id);
        assert_eq!(info.peer_id, A.0);

        let retry_at = now + RETRY_DELAYS[1];
        let replay = query(&mut directory, A, B, request(2, B), retry_at).unwrap();
        assert_eq!(
            (replay.revision, replay.valid_for_ms),
            (result.revision, 41_600)
        );

        // B can query with the same numeric ID as the outstanding introduction.
        let simultaneous =
            query(&mut directory, B, A, request(intro.request_id, A), retry_at).unwrap();
        assert_eq!(simultaneous.pair_id, result.pair_id);
        let deliveries = directory.due_introductions(retry_at);
        assert!(deliveries.contains(&(
            addr(B),
            Data::Request(FindPeerRequest {
                target: Some(Target::Peer(PeerInfo {
                    valid_for_ms: 41_600,
                    ..info.clone()
                })),
                ..intro.clone()
            })
        )));
        assert!(
            deliveries
                .iter()
                .any(|(recipient, _)| *recipient == addr(A))
        );

        directory.acknowledge(
            B,
            FindPeerResponse {
                request_id: intro.request_id,
                peer: None,
            },
        );
        assert!(
            directory
                .due_introductions(now + RETRY_DELAYS[2])
                .iter()
                .all(|(recipient, _)| *recipient != addr(B))
        );
        assert!(
            directory
                .due_introductions(retry_at + REQUEST_TIMEOUT)
                .is_empty()
        );

        let later = retry_at + REQUEST_TIMEOUT;
        let c = register(&mut directory, C).unwrap();
        directory.confirm(
            C,
            "192.0.2.3:1003".parse().unwrap(),
            [Some(ip(C)), None],
            Some(c),
            later,
        );
        let other_exit = query(&mut directory, C, A, request(1, A), later).unwrap();
        assert!(other_exit.lan_endpoint.is_none());
    }

    #[test]
    fn rediscover_after_reconnect() {
        let now = Instant::now();
        let mut directory = Directory::new();

        let a = register(&mut directory, A).unwrap();
        let b = register(&mut directory, B).unwrap();
        confirm(&mut directory, A, Some(a), now);
        assert!(query(&mut directory, A, A, request(1, A), now).is_none());
        assert!(query(&mut directory, A, B, request(2, B), now).is_none());

        confirm(&mut directory, B, Some(b), now);
        let first = query(&mut directory, A, B, request(3, B), now).unwrap();
        assert_eq!(
            first.lan_endpoint,
            Some(SocketAddr::from(([192, 168, 0, 2], 9999)).into())
        );

        let later = now + RETRY_DELAYS[1];
        let reconnected = register(&mut directory, B).unwrap();
        let new_epoch = reconnected.epoch;
        let new_addr = "192.0.2.2:2002".parse::<SocketAddr>().unwrap();
        directory.confirm(B, new_addr, [Some(ip(B)), None], Some(reconnected), later);
        assert!(directory.due_introductions(later).is_empty());
        assert!(query(&mut directory, A, B, request(3, B), later).is_none());

        let stale_renewal = FindPeerRequest {
            renew_pair_id: first.pair_id.clone(),
            ..request(4, B)
        };
        assert!(query(&mut directory, A, B, stale_renewal, later).is_none());
        let rediscover = FindPeerRequest {
            replace_pair_id: first.pair_id.clone(),
            ..request(5, B)
        };
        let fresh = query(&mut directory, A, B, rediscover, later).unwrap();
        assert_ne!(fresh.pair_id, first.pair_id);
        assert!(fresh.revision > first.revision);
        assert_eq!(fresh.local_session_epoch, first.local_session_epoch);
        assert_eq!(fresh.peer_session_epoch, new_epoch);
        assert!(new_epoch > first.peer_session_epoch);
        assert_eq!(fresh.observed_endpoint, Some(new_addr.into()));
        assert!(fresh.lan_endpoint.is_none());
        let introductions = directory.due_introductions(later);
        assert_eq!(introductions.len(), 1);
        assert_eq!(introductions[0].0, new_addr);
    }

    #[test]
    fn restrict_automatic_lan() {
        let now = Instant::now();
        for lan in [
            None,
            Some(([192, 168, 0, 1], 9998).into()),
            Some(([203, 0, 113, 2], 9999).into()),
        ] {
            let mut directory = Directory::new();
            let a = register(&mut directory, A).unwrap();
            let mut b = register(&mut directory, B).unwrap();
            b.lan = lan;
            confirm(&mut directory, A, Some(a), now);
            confirm(&mut directory, B, Some(b), now);
            for (source, target) in [(A, B), (B, A)] {
                let peer = query(&mut directory, source, target, request(1, target), now).unwrap();
                assert!(peer.lan_endpoint.is_none());
            }
        }
    }

    #[test]
    fn renew_and_replace_pair() {
        let mut directory = Directory::new();
        let now = Instant::now();
        for id in [A, B] {
            let registration = register(&mut directory, id);
            confirm(&mut directory, id, registration, now);
        }
        let first = query(&mut directory, A, B, request(1, B), now).unwrap();
        assert!(first.lan_endpoint.is_some());
        let later = now + Duration::from_secs(1);
        let renewal = FindPeerRequest {
            renew_pair_id: first.pair_id.clone(),
            ..request(2, B)
        };
        let renewed = query(&mut directory, A, B, renewal.clone(), later).unwrap();
        assert_eq!(renewed.pair_id, first.pair_id);
        assert!(renewed.revision > first.revision);
        assert_eq!(
            query(&mut directory, A, B, renewal, later).unwrap(),
            renewed
        );

        let replace = FindPeerRequest {
            replace_pair_id: first.pair_id.clone(),
            ..request(3, B)
        };
        let replacement = query(&mut directory, A, B, replace, later).unwrap();
        assert_ne!(replacement.pair_id, first.pair_id);
        assert!(replacement.revision > renewed.revision);
        let concurrent = query(
            &mut directory,
            B,
            A,
            FindPeerRequest {
                replace_pair_id: first.pair_id.clone(),
                ..request(1, A)
            },
            later,
        )
        .unwrap();
        assert_eq!(concurrent.pair_id, replacement.pair_id);
        assert_eq!(concurrent.revision, replacement.revision);

        assert!(
            query(
                &mut directory,
                A,
                B,
                FindPeerRequest {
                    renew_pair_id: first.pair_id,
                    ..request(4, B)
                },
                later
            )
            .is_none()
        );
        directory.remove(B);
        assert!(query(&mut directory, A, B, request(5, B), later).is_none());
        assert!(directory.due_introductions(later).is_empty());
    }
}
