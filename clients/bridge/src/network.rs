// SPDX-License-Identifier: MIT
//! Platform binding and physical subnet checks for UDP sockets.
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use vault_core::diagnostics::transport::NetworkBinding;

#[derive(Clone)]
pub struct LanAddresses(Arc<[(IpAddr, u8)]>);

impl LanAddresses {
    pub fn new(addresses: &[String]) -> Self {
        Self(
            addresses
                .iter()
                .filter_map(|entry| {
                    let (address, prefix) = entry.split_once('/')?;
                    let address: IpAddr = address.split('%').next()?.parse().ok()?;
                    let prefix: u8 = prefix.parse().ok()?;
                    (usable_lan_ip(address)
                        && (1..=if address.is_ipv4() { 32 } else { 128 }).contains(&prefix))
                    .then_some((address, prefix))
                })
                .collect(),
        )
    }

    pub fn endpoint(
        &self,
        server: SocketAddr,
        port: u16,
        bind: impl FnOnce(i32) -> io::Result<()>,
    ) -> Option<SocketAddr> {
        #[cfg(unix)]
        {
            use std::net::UdpSocket;
            use std::os::fd::AsRawFd;

            let ipv4 = server.ip().to_canonical().is_ipv4();
            if !self.0.iter().any(|(ip, _)| ip.is_ipv4() == ipv4) {
                return None;
            }
            // UDP connect selects the platform's source address without sending a packet.
            // Keep the actual tunnel socket unconnected so it can also receive peer traffic.
            let any = if server.is_ipv4() {
                IpAddr::V4(Ipv4Addr::UNSPECIFIED)
            } else {
                IpAddr::V6(Ipv6Addr::UNSPECIFIED)
            };
            let probe = UdpSocket::bind(SocketAddr::new(any, 0)).ok()?;
            bind(probe.as_raw_fd()).ok()?;
            probe.connect(server).ok()?;
            let source = probe.local_addr().ok()?.ip().to_canonical();
            self.0
                .iter()
                .any(|(ip, _)| *ip == source)
                .then(|| SocketAddr::new(source, port))
        }
        #[cfg(not(unix))]
        {
            let _ = (server, port, bind);
            None
        }
    }

    pub fn allows(&self, local: IpAddr, remote: IpAddr) -> bool {
        usable_lan_ip(remote)
            && !self.0.iter().any(|(own, _)| *own == remote)
            && self.0.iter().any(|&(own, prefix)| {
                if own != local {
                    return false;
                }
                match (own, remote) {
                    (IpAddr::V4(own), IpAddr::V4(remote)) => {
                        let mask = u32::MAX << (32 - prefix);
                        let remote = u32::from(remote);
                        let network = u32::from(own) & mask;
                        remote & mask == network
                            && (prefix >= 31 || (remote != network && remote != (network | !mask)))
                    }
                    (IpAddr::V6(own), IpAddr::V6(remote)) => {
                        let shift = 128 - prefix;
                        u128::from(own) >> shift == u128::from(remote) >> shift
                    }
                    _ => false,
                }
            })
    }
}

fn usable_lan_ip(ip: IpAddr) -> bool {
    !ip.is_unspecified()
        && !ip.is_multicast()
        && !ip.is_loopback()
        && match ip {
            IpAddr::V4(ip) => !ip.is_link_local() && !ip.is_broadcast(),
            IpAddr::V6(ip) => !ip.is_unicast_link_local() && ip.to_ipv4_mapped().is_none(),
        }
}

// Android's NDK equivalent of Network.bindSocket; only tunnel requests use it.
#[cfg(target_os = "android")]
#[link(name = "android")]
unsafe extern "C" {
    fn android_setsocknetwork(network: u64, fd: i32) -> i32;
}

#[cfg(target_os = "android")]
pub struct AndroidNetworkBinding(pub u64);
#[cfg(target_os = "android")]
impl NetworkBinding for AndroidNetworkBinding {
    fn bind(&self, fd: i32, _: bool) -> io::Result<()> {
        // SAFETY: the caller owns the live socket; handle is supplied by Android.
        if unsafe { android_setsocknetwork(self.0, fd) } == 0 {
            Ok(())
        } else {
            Err(io::Error::last_os_error())
        }
    }
}

#[cfg(target_vendor = "apple")]
pub struct AppleInterfaceBinding(pub u32);
#[cfg(target_vendor = "apple")]
impl NetworkBinding for AppleInterfaceBinding {
    fn bind(&self, fd: i32, ipv6: bool) -> io::Result<()> {
        #[cfg(target_vendor = "apple")]
        {
            let (level, option) = if ipv6 {
                (libc::IPPROTO_IPV6, libc::IPV6_BOUND_IF)
            } else {
                (libc::IPPROTO_IP, libc::IP_BOUND_IF)
            };
            // SAFETY: value is a live u32, fd belongs to the caller's socket.
            let rc = unsafe {
                libc::setsockopt(
                    fd,
                    level,
                    option,
                    (&self.0 as *const u32).cast(),
                    size_of::<u32>() as _,
                )
            };
            if rc == 0 {
                Ok(())
            } else {
                Err(io::Error::last_os_error())
            }
        }
        #[cfg(not(target_vendor = "apple"))]
        {
            let _ = (fd, ipv6);
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "platform network binding required",
            ))
        }
    }
}

/// Find the live interface by an assigned IPv4 or IPv6 address. Apple must never silently
/// substitute an unbound socket if a utun interface has disappeared.
#[cfg(target_vendor = "apple")]
pub fn tunnel_interface(address: IpAddr) -> io::Result<u32> {
    let mut list = std::ptr::null_mut();
    // SAFETY: getifaddrs initializes the pointer; every success is freed below.
    if unsafe { libc::getifaddrs(&mut list) } != 0 {
        return Err(io::Error::last_os_error());
    }
    struct Interfaces(*mut libc::ifaddrs);
    impl Drop for Interfaces {
        fn drop(&mut self) {
            unsafe { libc::freeifaddrs(self.0) };
        }
    }
    let _guard = Interfaces(list);
    let mut cursor = list;
    while !cursor.is_null() {
        // SAFETY: cursor and its addresses are owned by the live getifaddrs list.
        let entry = unsafe { &*cursor };
        if !entry.ifa_addr.is_null() {
            let name = unsafe { std::ffi::CStr::from_ptr(entry.ifa_name) };
            let family = unsafe { (*entry.ifa_addr).sa_family as i32 };
            // SAFETY: the family check selects the matching sockaddr layout;
            // the getifaddrs allocation remains live until the guard is dropped.
            let found = match family {
                libc::AF_INET => {
                    let ipv4 = unsafe { &*(entry.ifa_addr.cast::<libc::sockaddr_in>()) };
                    Some(IpAddr::V4(Ipv4Addr::from(
                        ipv4.sin_addr.s_addr.to_ne_bytes(),
                    )))
                }
                libc::AF_INET6 => {
                    let ipv6 = unsafe { &*(entry.ifa_addr.cast::<libc::sockaddr_in6>()) };
                    Some(IpAddr::V6(Ipv6Addr::from(ipv6.sin6_addr.s6_addr)))
                }
                _ => None,
            };
            let matches = found == Some(address);
            let platform_match =
                !cfg!(target_vendor = "apple") || name.to_bytes().starts_with(b"utun");
            if matches && platform_match {
                let index = unsafe { libc::if_nametoindex(entry.ifa_name) };
                if index != 0 {
                    return Ok(index);
                }
            }
        }
        cursor = entry.ifa_next;
    }
    Err(io::Error::new(
        io::ErrorKind::NotFound,
        "current tunnel interface unavailable",
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lan_prefixes() {
        let addresses = LanAddresses::new(
            &[
                "192.168.1.99/25",
                "192.168.1.110/25",
                "fd00:1::99/64",
                "fe80::99%en0/64",
                "10.0.0.1/0",
            ]
            .map(String::from),
        );
        let ipv4 = "192.168.1.99".parse().unwrap();
        assert!(addresses.allows(ipv4, "192.168.1.107".parse().unwrap()));
        for remote in [
            "192.168.1.110",
            "192.168.1.128",
            "192.168.1.0",
            "192.168.1.127",
            "222.210.167.234",
            "224.0.0.1",
            "fd00:1::107",
        ] {
            assert!(!addresses.allows(ipv4, remote.parse().unwrap()), "{remote}");
        }
        let ipv6 = "fd00:1::99".parse().unwrap();
        assert!(addresses.allows(ipv6, "fd00:1::107".parse().unwrap()));
        assert!(!addresses.allows(ipv6, "fd00:2::107".parse().unwrap()));
        assert!(!addresses.allows("fe80::99".parse().unwrap(), "fe80::107".parse().unwrap()));
        assert!(!addresses.allows("10.0.0.1".parse().unwrap(), "10.0.0.2".parse().unwrap()));
    }
}
