// SPDX-License-Identifier: MIT
use crate::Time;
use crate::{TimeSource, crypto::CryptoCore};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket};
use std::sync::Arc;
use std::sync::atomic::{AtomicI64, Ordering};
use std::{collections::HashMap, marker::PhantomData};

#[derive(Debug, Hash, PartialEq, Eq, Clone, Copy)]
pub struct PeerId(pub [u8; 16]);

impl Default for PeerId {
    fn default() -> Self {
        PeerId(uuid::Uuid::new_v4().into_bytes())
    }
}

impl TryFrom<Vec<u8>> for PeerId {
    type Error = anyhow::Error;

    fn try_from(value: Vec<u8>) -> Result<Self, Self::Error> {
        let data = value
            .try_into()
            .map_err(|_| anyhow::anyhow!("id format error."))?;
        Ok(PeerId(data))
    }
}

pub struct PendingPeer {
    pub ip: IpAddr,
    pub port: u16,
}

pub struct Peer<TS: TimeSource> {
    id: PeerId,
    crypto: CryptoCore,
    last_active_time: AtomicI64,
    address: SocketAddr,
    socket: Arc<UdpSocket>,
    ipv4: Option<Ipv4Addr>,
    ipv6: Option<Ipv6Addr>,
    super_node: bool,
    device_name: String,
    platform: String,
    _ts: PhantomData<TS>,
}

impl<TS: TimeSource> Peer<TS> {
    #[allow(clippy::too_many_arguments)]
    fn new(
        id: PeerId,
        crypto: CryptoCore,
        address: SocketAddr,
        socket: Arc<UdpSocket>,
        ipv4: Option<Ipv4Addr>,
        ipv6: Option<Ipv6Addr>,
        super_node: bool,
        device_name: String,
        platform: String,
    ) -> Self {
        Self {
            id,
            crypto,
            last_active_time: AtomicI64::new(TS::now()),
            address,
            socket,
            ipv4,
            ipv6,
            super_node,
            device_name,
            platform,
            _ts: PhantomData,
        }
    }

    pub fn id(&self) -> &PeerId {
        &self.id
    }

    pub fn crypto(&self) -> &CryptoCore {
        &self.crypto
    }

    pub fn get_ipv4(&self) -> &Option<Ipv4Addr> {
        &self.ipv4
    }

    pub fn get_ipv6(&self) -> &Option<Ipv6Addr> {
        &self.ipv6
    }

    pub fn get_address(&self) -> &SocketAddr {
        &self.address
    }

    /// Device name reported in the handshake; empty for old clients.
    pub fn device_name(&self) -> &str {
        &self.device_name
    }

    /// Platform reported in the handshake; empty for old clients.
    pub fn platform(&self) -> &str {
        &self.platform
    }

    pub fn get_active_time(&self) -> Time {
        self.last_active_time.load(Ordering::SeqCst)
    }

    pub fn update_active_time(&self) {
        self.last_active_time.swap(TS::now(), Ordering::SeqCst);
    }

    pub fn send_to(&self, buf: &[u8]) -> std::io::Result<usize> {
        self.socket.send_to(buf, self.address)
    }
}

#[derive(Default)]
pub struct Peers<TS: TimeSource> {
    pending_peers: HashMap<IpAddr, PendingPeer>,
    peers: HashMap<IpAddr, Arc<Peer<TS>>>,
    peers_socket: HashMap<SocketAddr, Arc<Peer<TS>>>,
    super_node_ip: Option<IpAddr>,
}

impl<TS: TimeSource> Peers<TS> {
    pub fn update_super_node_ip(&mut self, super_node_ip: Option<IpAddr>) {
        self.super_node_ip = super_node_ip;
    }

    pub fn find_default_peer(&self) -> Option<Arc<Peer<TS>>> {
        self.super_node_ip
            .as_ref()
            .and_then(|k| self.peers.get(k).cloned())
    }

    #[allow(clippy::too_many_arguments)]
    pub fn create_peer(
        &mut self,
        id: PeerId,
        crypto: CryptoCore,
        address: SocketAddr,
        socket: Arc<UdpSocket>,
        ipv4: Option<Ipv4Addr>,
        ipv6: Option<Ipv6Addr>,
        super_node: bool,
        device_name: String,
        platform: String,
    ) {
        // A reconnecting peer (new source address, same id) replaces its old
        // session. Drop the stale entries now: if the old socket entry
        // survived, the idle-timeout sweeper would later remove the NEW
        // peer's IP indexes along with it.
        self.remove_peer_by_id(&id);

        let peer = Arc::new(Peer::<TS>::new(
            id,
            crypto,
            address,
            socket,
            ipv4,
            ipv6,
            super_node,
            device_name,
            platform,
        ));
        if let Some(ipv4) = ipv4 {
            self.peers.insert(IpAddr::V4(ipv4), peer.clone());
        }
        if let Some(ipv6) = ipv6 {
            self.peers.insert(IpAddr::V6(ipv6), peer.clone());
        }
        if super_node {
            self.peers.insert(address.ip(), peer.clone());
        }
        self.peers_socket.insert(address, peer);
    }

    /// Remove the peer with this id from all indexes (any source address).
    pub fn remove_peer_by_id(&mut self, id: &PeerId) {
        let addr = self
            .peers_socket
            .iter()
            .find(|(_, p)| p.id() == id)
            .map(|(addr, _)| *addr);
        if let Some(addr) = addr {
            self.remove_peer_by_socket(&addr);
        }
    }

    pub fn add_pending_peer(&mut self, ip: IpAddr, port: u16) {
        let pending_peer = PendingPeer { ip, port };
        self.pending_peers.insert(ip, pending_peer);
    }

    pub fn get_pending_peers(&self) -> Vec<&PendingPeer> {
        self.pending_peers.values().collect()
    }

    pub fn remove_pending_peer(&mut self, ip: &IpAddr) {
        self.pending_peers.remove(ip);
    }

    pub fn find_peer_by_ip(&self, ip: &IpAddr) -> Option<Arc<Peer<TS>>> {
        self.peers.get(ip).cloned()
    }

    pub fn find_peer_by_socket(&self, addr: &SocketAddr) -> Option<Arc<Peer<TS>>> {
        self.peers_socket.get(addr).cloned()
    }

    pub fn remove_peer(&mut self, ip: &IpAddr) {
        if let Some(peer) = self.find_peer_by_ip(ip) {
            if peer.super_node {
                return;
            }

            if let Some(ipv4) = peer.get_ipv4() {
                let ip = IpAddr::V4(*ipv4);
                self.peers.remove(&ip);
            }
            if let Some(ipv6) = peer.get_ipv6() {
                let ip = IpAddr::V6(*ipv6);
                self.peers.remove(&ip);
            }

            self.peers_socket.remove(&peer.address);
        }
        self.remove_pending_peer(ip);
    }

    /// Remove the peer registered under `addr` from all indexes.
    pub fn remove_peer_by_socket(&mut self, addr: &SocketAddr) -> Option<Arc<Peer<TS>>> {
        let peer = self.peers_socket.remove(addr)?;
        // An IP index may already have been taken over by the peer's newer
        // session (roaming reconnect); only remove entries that still point
        // at the peer being deleted.
        if let Some(ipv4) = peer.get_ipv4() {
            let ip = IpAddr::V4(*ipv4);
            if self.peers.get(&ip).is_some_and(|p| Arc::ptr_eq(p, &peer)) {
                self.peers.remove(&ip);
            }
        }
        if let Some(ipv6) = peer.get_ipv6() {
            let ip = IpAddr::V6(*ipv6);
            if self.peers.get(&ip).is_some_and(|p| Arc::ptr_eq(p, &peer)) {
                self.peers.remove(&ip);
            }
        }
        if peer.super_node {
            let ip = peer.address.ip();
            if self.peers.get(&ip).is_some_and(|p| Arc::ptr_eq(p, &peer)) {
                self.peers.remove(&ip);
            }
        }
        Some(peer)
    }

    /// Remove peers idle for more than `timeout_secs` from all indexes.
    pub fn remove_inactive_peers(&mut self, timeout_secs: Time) -> Vec<Arc<Peer<TS>>> {
        let now = TS::now();
        let inactive: Vec<SocketAddr> = self
            .peers_socket
            .iter()
            .filter(|(_, p)| now - p.get_active_time() > timeout_secs)
            .map(|(addr, _)| *addr)
            .collect();
        inactive
            .iter()
            .filter_map(|addr| self.remove_peer_by_socket(addr))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{AlgorithmType, Role, SystemTimeSource, create_ecdh_keypair};

    fn make_crypto() -> CryptoCore {
        let (privk1, _pubk1) = create_ecdh_keypair().unwrap();
        let (_privk2, pubk2) = create_ecdh_keypair().unwrap();
        CryptoCore::new(
            privk1,
            &AlgorithmType::Aes128Gcm,
            pubk2.bytes(),
            Role::Initiator,
            b"test-pake-key",
        )
        .unwrap()
    }

    fn add_peer(
        peers: &mut Peers<SystemTimeSource>,
        id: PeerId,
        port: u16,
        ipv4: Ipv4Addr,
    ) -> SocketAddr {
        let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").unwrap());
        let addr: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
        peers.create_peer(
            id,
            make_crypto(),
            addr,
            socket,
            Some(ipv4),
            None,
            false,
            String::new(),
            String::new(),
        );
        addr
    }

    #[test]
    fn roaming_reconnect_replaces_old_session_atomically() {
        let mut peers = Peers::<SystemTimeSource>::default();
        let id = PeerId([1u8; 16]);
        let ip = Ipv4Addr::new(10, 0, 0, 2);
        let old_addr = add_peer(&mut peers, id, 5001, ip);

        // Same id reconnects from a new address (NAT mapping changed).
        let new_addr = add_peer(&mut peers, id, 5002, ip);

        assert!(peers.find_peer_by_socket(&old_addr).is_none());
        let peer = peers.find_peer_by_socket(&new_addr).unwrap();
        // The IP index must route to the new session.
        let by_ip = peers.find_peer_by_ip(&IpAddr::V4(ip)).unwrap();
        assert!(Arc::ptr_eq(&peer, &by_ip));

        // Sweeping idle peers afterwards must not disturb the live session.
        drop(peer);
        drop(by_ip);
        let removed = peers.remove_inactive_peers(-1); // everything is "idle"
        assert_eq!(removed.len(), 1);
        assert!(peers.find_peer_by_ip(&IpAddr::V4(ip)).is_none());
        assert!(peers.find_peer_by_socket(&new_addr).is_none());
    }
}
