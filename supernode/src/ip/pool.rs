// SPDX-License-Identifier: MIT
use std::collections::BTreeSet;
use std::fmt::{self, Display};
use std::net::{Ipv4Addr, Ipv6Addr};
use std::str::FromStr;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};

use serde::Serialize;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IpPoolError {
    InvalidCidr,
    InvalidPrefix,
    InvalidIp,
    PoolExhausted,
    IpNotInPool,
    IpIsNetworkAddress,
    IpIsBroadcastAddress,
    IpNotAllocated,
}

impl fmt::Display for IpPoolError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            IpPoolError::InvalidCidr => write!(f, "Invalid CIDR format"),
            IpPoolError::InvalidPrefix => write!(f, "Invalid prefix length"),
            IpPoolError::InvalidIp => write!(f, "Invalid IP address"),
            IpPoolError::PoolExhausted => write!(f, "IP pool exhausted"),
            IpPoolError::IpNotInPool => write!(f, "IP not in pool range"),
            IpPoolError::IpIsNetworkAddress => write!(f, "Cannot allocate network address"),
            IpPoolError::IpIsBroadcastAddress => write!(f, "Cannot allocate broadcast address"),
            IpPoolError::IpNotAllocated => write!(f, "IP not allocated"),
        }
    }
}

impl std::error::Error for IpPoolError {}

fn ipv6_to_u128(addr: Ipv6Addr) -> u128 {
    let segments = addr.segments();
    ((segments[0] as u128) << 112)
        | ((segments[1] as u128) << 96)
        | ((segments[2] as u128) << 80)
        | ((segments[3] as u128) << 64)
        | ((segments[4] as u128) << 48)
        | ((segments[5] as u128) << 32)
        | ((segments[6] as u128) << 16)
        | (segments[7] as u128)
}

fn u128_to_ipv6(val: u128) -> Ipv6Addr {
    Ipv6Addr::new(
        ((val >> 112) & 0xFFFF) as u16,
        ((val >> 96) & 0xFFFF) as u16,
        ((val >> 80) & 0xFFFF) as u16,
        ((val >> 64) & 0xFFFF) as u16,
        ((val >> 48) & 0xFFFF) as u16,
        ((val >> 32) & 0xFFFF) as u16,
        ((val >> 16) & 0xFFFF) as u16,
        (val & 0xFFFF) as u16,
    )
}

// ==================== IPv4 Pool ====================

#[derive(Debug, Clone, Copy, Serialize)]
pub struct Ipv4Cidr {
    network: Ipv4Addr,
    prefix_len: u8,
    netmask: Ipv4Addr,
    first_host: Ipv4Addr,
    last_host: Ipv4Addr,
    broadcast: Ipv4Addr,
}

impl Display for Ipv4Cidr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}/{}",
            self.network.to_string().as_str(),
            self.prefix_len
        )
    }
}

impl Ipv4Cidr {
    pub fn from_str(s: &str) -> Result<Self, IpPoolError> {
        let parts: Vec<&str> = s.split('/').collect();
        if parts.len() != 2 {
            return Err(IpPoolError::InvalidCidr);
        }

        let prefix_len: u8 = parts[1].parse().map_err(|_| IpPoolError::InvalidCidr)?;
        if prefix_len > 32 {
            return Err(IpPoolError::InvalidPrefix);
        }

        let network = Ipv4Addr::from_str(parts[0]).map_err(|_| IpPoolError::InvalidIp)?;
        Self::new(network, prefix_len)
    }

    pub fn new(network: Ipv4Addr, prefix_len: u8) -> Result<Self, IpPoolError> {
        if prefix_len > 32 {
            return Err(IpPoolError::InvalidPrefix);
        }

        let host_bits = 32 - prefix_len;
        let network_u32 = u32::from(network);
        let netmask = if host_bits == 32 {
            0
        } else {
            !0u32 << host_bits
        };
        let network_aligned = network_u32 & netmask;
        let broadcast_u32 = if host_bits == 32 {
            u32::MAX
        } else {
            network_aligned | ((1u32 << host_bits) - 1)
        };

        // RFC 3021: /31 point-to-point link and /32 single host use the
        // full range; otherwise network/broadcast are excluded.
        let (first, last) = if prefix_len == 31 {
            (network_aligned, broadcast_u32)
        } else if prefix_len == 32 {
            (network_aligned, network_aligned)
        } else {
            (network_aligned + 1, broadcast_u32 - 1)
        };

        Ok(Ipv4Cidr {
            network: Ipv4Addr::from(network_aligned),
            prefix_len,
            netmask: Ipv4Addr::from(netmask),
            first_host: Ipv4Addr::from(first),
            last_host: Ipv4Addr::from(last),
            broadcast: Ipv4Addr::from(broadcast_u32),
        })
    }

    pub fn network(&self) -> Ipv4Addr {
        self.network
    }
    pub fn broadcast(&self) -> Ipv4Addr {
        self.broadcast
    }
    pub fn first_host(&self) -> Ipv4Addr {
        self.first_host
    }
    pub fn last_host(&self) -> Ipv4Addr {
        self.last_host
    }
    pub fn prefix_len(&self) -> u8 {
        self.prefix_len
    }
    pub fn netmask(&self) -> Ipv4Addr {
        self.netmask
    }

    pub fn is_host(&self, ip: Ipv4Addr) -> bool {
        let val = u32::from(ip);
        let first = u32::from(self.first_host);
        let last = u32::from(self.last_host);
        val >= first && val <= last
    }
}

struct Ipv4Generator {
    current: AtomicU32,
    last: u32,
    exhausted: AtomicU32,
}

impl Ipv4Generator {
    fn new(first: Ipv4Addr, last: Ipv4Addr) -> Self {
        let first_u32 = u32::from(first);
        let last_u32 = u32::from(last);

        Self {
            current: AtomicU32::new(first_u32),
            last: last_u32,
            exhausted: AtomicU32::new(if first_u32 > last_u32 { 1 } else { 0 }),
        }
    }

    fn next(&self) -> Option<Ipv4Addr> {
        if self.exhausted.load(Ordering::Acquire) != 0 {
            return None;
        }

        let curr = self.current.fetch_add(1, Ordering::Relaxed);

        if curr > self.last {
            self.exhausted.store(1, Ordering::Release);
            self.current.fetch_sub(1, Ordering::Relaxed);
            return None;
        }

        if curr == self.last {
            self.exhausted.store(1, Ordering::Release);
        }

        Some(Ipv4Addr::from(curr))
    }
}

pub struct Ipv4Pool {
    cidr: Ipv4Cidr,
    allocated: BTreeSet<Ipv4Addr>,
    recycled: BTreeSet<Ipv4Addr>,
    generator: Ipv4Generator,
    max_recycled: usize,
}

impl Ipv4Pool {
    pub fn new(cidr: Ipv4Cidr) -> Self {
        let generator = Ipv4Generator::new(cidr.first_host(), cidr.last_host());

        Self {
            cidr,
            allocated: BTreeSet::new(),
            recycled: BTreeSet::new(),
            generator,
            max_recycled: 65536,
        }
    }

    pub fn network(&self) -> Ipv4Addr {
        self.cidr.network()
    }
    pub fn broadcast(&self) -> Ipv4Addr {
        self.cidr.broadcast()
    }
    pub fn netmask(&self) -> Ipv4Addr {
        self.cidr.netmask()
    }
    pub fn prefix_len(&self) -> u8 {
        self.cidr.prefix_len()
    }
    pub fn cidr_string(&self) -> String {
        format!("{}/{}", self.cidr.network(), self.prefix_len())
    }

    pub fn allocate(&mut self) -> Result<Ipv4Addr, IpPoolError> {
        if let Some(ip) = self.recycled.pop_first() {
            if !self.cidr.is_host(ip) {
                return Err(IpPoolError::IpIsNetworkAddress);
            }
            return self.do_allocate(ip);
        }

        // Generate a fresh IP, skipping occupied (including reserved) ones
        loop {
            let ip = self.generator.next().ok_or(IpPoolError::PoolExhausted)?;

            if !self.cidr.is_host(ip) {
                return Err(IpPoolError::PoolExhausted);
            }

            if !self.allocated.contains(&ip) {
                return self.do_allocate(ip);
            }
        }
    }

    /// Reserve an address so it is never allocated (e.g. an address of a
    /// local physical interface). Returns whether it was actually reserved
    /// (only pool host addresses can be reserved).
    pub fn reserve(&mut self, ip: Ipv4Addr) -> bool {
        if self.cidr.is_host(ip) {
            self.allocated.insert(ip)
        } else {
            false
        }
    }

    fn do_allocate(&mut self, ip: Ipv4Addr) -> Result<Ipv4Addr, IpPoolError> {
        self.allocated.insert(ip);
        Ok(ip)
    }

    pub fn release(&mut self, ip: Ipv4Addr) -> Result<(), IpPoolError> {
        if ip == self.cidr.network() {
            return Err(IpPoolError::IpIsNetworkAddress);
        }
        if ip == self.cidr.broadcast() {
            return Err(IpPoolError::IpIsBroadcastAddress);
        }
        if !self.cidr.is_host(ip) {
            return Err(IpPoolError::IpNotInPool);
        }
        if !self.allocated.remove(&ip) {
            return Err(IpPoolError::IpNotAllocated);
        }

        if self.recycled.len() >= self.max_recycled {
            self.recycled.pop_first();
        }
        self.recycled.insert(ip);
        Ok(())
    }
}

// ==================== IPv6 Pool ====================

#[derive(Debug, Clone, Copy, Serialize)]
pub struct Ipv6Cidr {
    network: Ipv6Addr,
    prefix_len: u8,
    first_host: Ipv6Addr,
    last_host: Ipv6Addr,
    last_addr: Ipv6Addr, // IPv6 has no broadcast; this is the last address
}

impl Display for Ipv6Cidr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}/{}",
            self.network.to_string().as_str(),
            self.prefix_len
        )
    }
}

impl Ipv6Cidr {
    pub fn from_str(s: &str) -> Result<Self, IpPoolError> {
        let parts: Vec<&str> = s.split('/').collect();
        if parts.len() != 2 {
            return Err(IpPoolError::InvalidCidr);
        }

        let prefix_len: u8 = parts[1].parse().map_err(|_| IpPoolError::InvalidCidr)?;
        if prefix_len > 128 {
            return Err(IpPoolError::InvalidPrefix);
        }

        let network = Ipv6Addr::from_str(parts[0]).map_err(|_| IpPoolError::InvalidIp)?;
        Self::new(network, prefix_len)
    }

    pub fn new(network: Ipv6Addr, prefix_len: u8) -> Result<Self, IpPoolError> {
        if prefix_len > 128 {
            return Err(IpPoolError::InvalidPrefix);
        }

        let host_bits = 128 - prefix_len;
        let network_u128 = ipv6_to_u128(network);
        let mask = if host_bits == 128 {
            0
        } else {
            !0u128 << host_bits
        };
        let network_aligned = network_u128 & mask;
        let last_u128 = if host_bits == 128 {
            u128::MAX
        } else {
            network_aligned | ((1u128 << host_bits) - 1)
        };

        // /127 is the IPv6 analogue of IPv4 /31; /128 is a single host —
        // both use the full range, otherwise first/last are excluded.
        let (first, last) = if prefix_len == 127 {
            (network_aligned, last_u128)
        } else if prefix_len == 128 {
            (network_aligned, network_aligned)
        } else {
            (network_aligned + 1, last_u128 - 1)
        };

        Ok(Ipv6Cidr {
            network: u128_to_ipv6(network_aligned),
            prefix_len,
            first_host: u128_to_ipv6(first),
            last_host: u128_to_ipv6(last),
            last_addr: u128_to_ipv6(last_u128),
        })
    }

    pub fn network(&self) -> Ipv6Addr {
        self.network
    }
    pub fn last_addr(&self) -> Ipv6Addr {
        self.last_addr
    }

    pub fn first_host(&self) -> Ipv6Addr {
        self.first_host
    }

    pub fn last_host(&self) -> Ipv6Addr {
        self.last_host
    }
    pub fn prefix_len(&self) -> u8 {
        self.prefix_len
    }

    pub fn is_host(&self, ip: Ipv6Addr) -> bool {
        let val = ipv6_to_u128(ip);
        let first = ipv6_to_u128(self.first_host);
        let last = ipv6_to_u128(self.last_host);
        val >= first && val <= last
    }
}

struct Ipv6Generator {
    current: AtomicU64,
    high: u64,
    last: u128,
    exhausted: AtomicU64,
}

impl Ipv6Generator {
    fn new(first: Ipv6Addr, last: Ipv6Addr) -> Self {
        let first_u128 = ipv6_to_u128(first);
        let last_u128 = ipv6_to_u128(last);

        Self {
            current: AtomicU64::new(first_u128 as u64),
            high: (first_u128 >> 64) as u64,
            last: last_u128,
            exhausted: AtomicU64::new(if first_u128 > last_u128 { 1 } else { 0 }),
        }
    }

    fn next(&self) -> Option<Ipv6Addr> {
        if self.exhausted.load(Ordering::Acquire) != 0 {
            return None;
        }

        let low = self.current.fetch_add(1, Ordering::Relaxed);
        let current_u128 = ((self.high as u128) << 64) | (low as u128);

        if current_u128 > self.last {
            self.exhausted.store(1, Ordering::Release);
            self.current.fetch_sub(1, Ordering::Relaxed);
            return None;
        }

        if current_u128 == self.last {
            self.exhausted.store(1, Ordering::Release);
        }

        Some(u128_to_ipv6(current_u128))
    }
}

pub struct Ipv6Pool {
    cidr: Ipv6Cidr,
    allocated: BTreeSet<Ipv6Addr>,
    recycled: BTreeSet<Ipv6Addr>,
    generator: Ipv6Generator,
    max_recycled: usize,
}

impl Ipv6Pool {
    pub fn new(cidr: Ipv6Cidr) -> Self {
        let generator = Ipv6Generator::new(cidr.first_host(), cidr.last_host());

        Self {
            cidr,
            allocated: BTreeSet::new(),
            recycled: BTreeSet::new(),
            generator,
            max_recycled: 65536,
        }
    }

    pub fn network(&self) -> Ipv6Addr {
        self.cidr.network()
    }
    pub fn last_addr(&self) -> Ipv6Addr {
        self.cidr.last_addr()
    }

    pub fn prefix_len(&self) -> u8 {
        self.cidr.prefix_len()
    }

    pub fn cidr_string(&self) -> String {
        format!("{}/{}", self.cidr.network(), self.cidr.prefix_len())
    }

    pub fn allocate(&mut self) -> Result<Ipv6Addr, IpPoolError> {
        if let Some(ip) = self.recycled.pop_first() {
            if !self.cidr.is_host(ip) {
                return Err(IpPoolError::IpIsNetworkAddress);
            }
            return self.do_allocate(ip);
        }

        // Generate a fresh IP, skipping occupied (including reserved) ones
        loop {
            let ip = self.generator.next().ok_or(IpPoolError::PoolExhausted)?;

            if !self.cidr.is_host(ip) {
                return Err(IpPoolError::PoolExhausted);
            }

            if !self.allocated.contains(&ip) {
                return self.do_allocate(ip);
            }
        }
    }

    /// Reserve an address so it is never allocated (e.g. an address of a
    /// local physical interface). Returns whether it was actually reserved
    /// (only pool host addresses can be reserved).
    pub fn reserve(&mut self, ip: Ipv6Addr) -> bool {
        if self.cidr.is_host(ip) {
            self.allocated.insert(ip)
        } else {
            false
        }
    }

    fn do_allocate(&mut self, ip: Ipv6Addr) -> Result<Ipv6Addr, IpPoolError> {
        self.allocated.insert(ip);
        Ok(ip)
    }

    pub fn release(&mut self, ip: Ipv6Addr) -> Result<(), IpPoolError> {
        if ip == self.cidr.network() {
            return Err(IpPoolError::IpIsNetworkAddress);
        }
        // IPv6 has no broadcast address, but the last address is usually reserved
        if ip == self.cidr.last_addr() {
            return Err(IpPoolError::IpIsBroadcastAddress);
        }
        if !self.cidr.is_host(ip) {
            return Err(IpPoolError::IpNotInPool);
        }
        if !self.allocated.remove(&ip) {
            return Err(IpPoolError::IpNotAllocated);
        }

        if self.recycled.len() >= self.max_recycled {
            self.recycled.pop_first();
        }
        self.recycled.insert(ip);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ipv4_basic() {
        let cidr = Ipv4Cidr::from_str("192.168.1.0/24").unwrap();
        let mut pool = Ipv4Pool::new(cidr);

        assert_eq!(pool.network().to_string(), "192.168.1.0");
        assert_eq!(pool.broadcast().to_string(), "192.168.1.255");
        assert_eq!(pool.netmask().to_string(), "255.255.255.0");
        assert_eq!(pool.cidr_string(), "192.168.1.0/24");

        let ip1 = pool.allocate().unwrap();
        assert_eq!(ip1.to_string(), "192.168.1.1");

        let ip2 = pool.allocate().unwrap();
        assert_eq!(ip2.to_string(), "192.168.1.2");

        pool.release(ip1).unwrap();
        let ip3 = pool.allocate().unwrap();
        assert_eq!(ip3, ip1);
    }

    #[test]
    fn test_ipv4_reserve_skips_interface_addr() {
        let cidr = Ipv4Cidr::from_str("192.168.1.0/24").unwrap();
        let mut pool = Ipv4Pool::new(cidr);

        // The server's own address must not be allocated to clients.
        assert!(pool.reserve(Ipv4Addr::from_str("192.168.1.1").unwrap()));
        let ip1 = pool.allocate().unwrap();
        assert_eq!(ip1.to_string(), "192.168.1.2");

        // Reserving an address outside the pool has no effect.
        assert!(!pool.reserve(Ipv4Addr::from_str("192.168.2.1").unwrap()));
    }

    #[test]
    fn test_ipv4_small_subnet() {
        let cidr = Ipv4Cidr::from_str("192.168.1.0/30").unwrap();
        let mut pool = Ipv4Pool::new(cidr);

        let ip1 = pool.allocate().unwrap();
        assert_eq!(ip1.to_string(), "192.168.1.1");

        let ip2 = pool.allocate().unwrap();
        assert_eq!(ip2.to_string(), "192.168.1.2");

        assert!(pool.allocate().is_err());
    }

    #[test]
    fn test_ipv6_basic() {
        let cidr = Ipv6Cidr::from_str("2001:db8::/64").unwrap();
        let mut pool = Ipv6Pool::new(cidr);

        assert_eq!(pool.network().to_string(), "2001:db8::");
        assert_eq!(pool.cidr_string(), "2001:db8::/64");
        assert_eq!(pool.prefix_len(), 64);
        assert_eq!(
            pool.last_addr().to_string(),
            "2001:db8::ffff:ffff:ffff:ffff"
        );

        let ip1 = pool.allocate().unwrap();
        assert!(ip1.to_string().starts_with("2001:db8::"));
    }

    #[test]
    fn test_ipv6_reserve_skips_interface_addr() {
        // Regression scenario: the server's own IPv6 address falls inside the
        // pool and must not be allocated to clients once reserved
        // (addresses use the RFC 3849 documentation prefix 2001:db8::/32)
        let cidr = Ipv6Cidr::from_str("2001:db8::/64").unwrap();
        let mut pool = Ipv6Pool::new(cidr);

        let server_addr = Ipv6Addr::from_str("2001:db8::2").unwrap();
        assert!(pool.reserve(server_addr));

        let ip1 = pool.allocate().unwrap();
        assert_eq!(ip1.to_string(), "2001:db8::1");

        let ip2 = pool.allocate().unwrap();
        assert_eq!(ip2.to_string(), "2001:db8::3");

        // Reserving an address outside the pool has no effect
        let outside = Ipv6Addr::from_str("2001:db8:1::1").unwrap();
        assert!(!pool.reserve(outside));
    }

    #[test]
    fn test_ipv6_small_subnet() {
        let cidr = Ipv6Cidr::from_str("2001:db8::/126").unwrap();
        let mut pool = Ipv6Pool::new(cidr);

        let ip1 = pool.allocate().unwrap();
        println!("IP1: {}", ip1);

        let ip2 = pool.allocate().unwrap();
        println!("IP2: {}", ip2);

        assert!(pool.allocate().is_err());
    }
}
