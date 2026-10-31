// SPDX-License-Identifier: MIT
//! Platform network binding for the portable diagnostic transport.
use std::io;
#[cfg(target_vendor = "apple")]
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use vault_core::diagnostics::transport::NetworkBinding;

// Android's NDK equivalent of Network.bindSocket; only tunnel requests use it.
#[cfg(target_os = "android")]
#[link(name = "android")]
unsafe extern "C" {
    fn android_setsocknetwork(network: u64, fd: i32) -> i32;
}

#[cfg(target_os = "android")]
pub struct AndroidNetwork(pub u64);
#[cfg(target_os = "android")]
impl NetworkBinding for AndroidNetwork {
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
pub struct InterfaceNetwork(pub u32);
#[cfg(target_vendor = "apple")]
impl NetworkBinding for InterfaceNetwork {
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
