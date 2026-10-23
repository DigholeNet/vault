// SPDX-License-Identifier: MIT
use std::cmp;
use std::ffi::CString;
use std::fmt;
use std::fs;
use std::fs::File;
use std::hash::Hash;
use std::hash::Hasher;
use std::io;
use std::io::Cursor;
use std::io::Read;
use std::io::Write;
use std::net::Ipv6Addr;
use std::net::UdpSocket;
use std::net::{IpAddr, Ipv4Addr};
use std::os::fd::AsRawFd;
use std::os::fd::RawFd;
use std::str::FromStr;

use pnet::packet::Packet;
use pnet::packet::arp::ArpPacket;
use pnet::packet::ethernet::{EtherType, EtherTypes};
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::ipv6::Ipv6Packet;
use pnet::util::MacAddr;
use serde::Deserialize;
use serde::Serialize;
use tracing::{info, warn};

use crate::Buffer;
use crate::util;

pub struct Ipv4 {
    pub ip: Ipv4Addr,
    pub netmask: Ipv4Addr,
}

pub struct Ipv6 {
    pub ip: Ipv6Addr,
    pub prefix_len: u8,
}

#[derive(Copy, Debug, Clone, Eq, PartialEq)]
pub enum Address {
    Mac(MacAddr),
    Ip(IpAddr),
}

#[derive(Debug)]
pub struct DevicePacket {
    pub ether_type: EtherType,
    pub address: (Address, Address),
    pub ip: Option<(IpAddr, IpAddr)>,
}

pub fn parse(r#type: &DeviceType, data: &[u8]) -> anyhow::Result<DevicePacket> {
    match r#type {
        DeviceType::Tun => {
            if let Some((src, dst)) = parse_tun_ip(data) {
                return Ok(DevicePacket {
                    ether_type: {
                        if src.is_ipv4() {
                            EtherTypes::Ipv4
                        } else {
                            EtherTypes::Ipv6
                        }
                    },
                    address: (Address::Ip(src), Address::Ip(dst)),
                    ip: Some((src, dst)),
                });
            }
        }

        DeviceType::Tap => {
            let ethernet_frame = pnet::packet::ethernet::EthernetPacket::new(data);
            if let Some(ethernet_frame) = ethernet_frame {
                match ethernet_frame.get_ethertype() {
                    EtherTypes::Arp => {
                        if let Some(arp) = ArpPacket::new(ethernet_frame.payload()) {
                            return Ok(DevicePacket {
                                ether_type: EtherTypes::Arp,
                                address: (
                                    Address::Mac(arp.get_sender_hw_addr()),
                                    Address::Mac(arp.get_target_hw_addr()),
                                ),
                                ip: Some((
                                    IpAddr::V4(arp.get_sender_proto_addr()),
                                    IpAddr::V4(arp.get_target_proto_addr()),
                                )),
                            });
                        }
                    }
                    EtherTypes::Ipv4 => {
                        if let Some(ip) = Ipv4Packet::new(ethernet_frame.payload()) {
                            return Ok(DevicePacket {
                                ether_type: EtherTypes::Ipv4,
                                address: (
                                    Address::Mac(ethernet_frame.get_source()),
                                    Address::Mac(ethernet_frame.get_destination()),
                                ),
                                ip: Some((
                                    IpAddr::V4(ip.get_source()),
                                    IpAddr::V4(ip.get_destination()),
                                )),
                            });
                        }
                    }
                    EtherTypes::Ipv6 => {
                        if let Some(ip) = Ipv6Packet::new(ethernet_frame.payload()) {
                            return Ok(DevicePacket {
                                ether_type: EtherTypes::Ipv6,
                                address: (
                                    Address::Mac(ethernet_frame.get_source()),
                                    Address::Mac(ethernet_frame.get_destination()),
                                ),
                                ip: Some((
                                    IpAddr::V6(ip.get_source()),
                                    IpAddr::V6(ip.get_destination()),
                                )),
                            });
                        }
                    }
                    _ => {
                        return Ok(DevicePacket {
                            ether_type: ethernet_frame.get_ethertype(),
                            address: (
                                Address::Mac(ethernet_frame.get_source()),
                                Address::Mac(ethernet_frame.get_destination()),
                            ),
                            ip: None,
                        });
                    }
                }
            }
        }
    }

    Err(anyhow::anyhow!("parse packet error."))
}

fn parse_tun_ip(data: &[u8]) -> Option<(IpAddr, IpAddr)> {
    let &first = data.first()?;
    let version = first >> 4;
    match version {
        4 => pnet::packet::ipv4::Ipv4Packet::new(data).map(|ipv4_packet| {
            (
                IpAddr::V4(ipv4_packet.get_source()),
                IpAddr::V4(ipv4_packet.get_destination()),
            )
        }),
        6 => pnet::packet::ipv6::Ipv6Packet::new(data).map(|ipv6_packet| {
            (
                IpAddr::V6(ipv6_packet.get_source()),
                IpAddr::V6(ipv6_packet.get_destination()),
            )
        }),
        _ => None,
    }
}

impl fmt::Display for Address {
    fn fmt(&self, formatter: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        match &self {
            Address::Mac(mac) => {
                write!(
                    formatter,
                    "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                    mac.0, mac.1, mac.2, mac.3, mac.4, mac.5
                )
            }
            Address::Ip(ip) => match ip {
                IpAddr::V4(ip) => {
                    let d = ip.octets();
                    write!(formatter, "{}.{}.{}.{}", d[0], d[1], d[2], d[3])
                }
                IpAddr::V6(ip) => write!(formatter, "{}", Ipv6Addr::from(ip.octets())),
            },
        }
    }
}

impl Hash for Address {
    #[inline]
    fn hash<H: Hasher>(&self, hasher: &mut H) {
        match &self {
            Address::Mac(mac) => {
                let mac = *mac;
                let data: [u8; 6] = mac.into();
                hasher.write(&data)
            }
            Address::Ip(ip) => ip.hash(hasher),
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq)]
pub enum DeviceType {
    /// Tun interface: This interface transports IP packets.
    #[serde(rename = "tun")]
    Tun,
    /// Tap interface: This interface transports Ethernet frames.
    #[serde(rename = "tap")]
    Tap,
}

impl fmt::Display for DeviceType {
    fn fmt(&self, formatter: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        match *self {
            DeviceType::Tun => write!(formatter, "tun"),
            DeviceType::Tap => write!(formatter, "tap"),
        }
    }
}

impl FromStr for DeviceType {
    type Err = &'static str;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        Ok(match &text.to_lowercase() as &str {
            "tun" => Self::Tun,
            "tap" => Self::Tap,
            _ => return Err("Unknown device type"),
        })
    }
}

static TUNSETIFF: libc::c_ulong = 1074025674;

#[repr(C)]
#[derive(Copy, Clone)]
struct IfReqDataAddr {
    af: libc::c_int,
    addr: Ipv4Addr,
}

#[repr(C)]
union IfReqData {
    flags: libc::c_short,
    value: libc::c_int,
    addr: IfReqDataAddr,
    _dummy: [u8; 24],
}

#[repr(C)]
struct IfReq {
    ifr_name: [u8; libc::IF_NAMESIZE],
    data: IfReqData,
}

impl IfReq {
    fn new(name: &str) -> io::Result<Self> {
        if name.len() >= libc::IF_NAMESIZE {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "interface name {} is too long (max {} bytes)",
                    name,
                    libc::IF_NAMESIZE - 1
                ),
            ));
        }
        let mut ifr_name = [0; libc::IF_NAMESIZE];
        ifr_name[..name.len()].clone_from_slice(name.as_bytes());
        Ok(Self {
            ifr_name,
            data: IfReqData { _dummy: [0; 24] },
        })
    }
}

#[repr(C)]
struct In6IfReq {
    addr: libc::in6_addr,
    prefixlen: libc::c_uint,
    ifindex: libc::c_int,
}

pub struct TunTapDevice {
    fd: File,
    ifname: String,
    type_: DeviceType,
}

impl TunTapDevice {
    /// Creates a new tun/tap device
    ///
    /// This method creates a new device of the `type_` kind with the name `ifname`.
    ///
    /// The `ifname` must be an interface name shorter than `IF_NAMESIZE`
    /// (16 bytes, including the NUL terminator). It can contain the string
    /// `%d` which will be replaced with the next free index number that guarantees that the
    /// interface name will be free. In this case, the `ifname()` method can be used to obtain the
    /// final interface name.
    ///
    /// # Errors
    /// This method will return an error when the underlying system call fails. Common cases are:
    /// - The special device file `/dev/net/tun` does not exist or is not accessible by the current user.
    /// - The interface name is too long, invalid, or already in use.
    /// - The current user does not have enough permissions to create tun/tap devices (this requires root permissions).
    #[allow(clippy::useless_conversion)]
    pub fn new(ifname: &str, type_: DeviceType) -> io::Result<Self> {
        let path = Self::default_path(type_);
        let fd = fs::OpenOptions::new().read(true).write(true).open(path)?;

        let flags = match type_ {
            DeviceType::Tun => libc::IFF_TUN | libc::IFF_NO_PI,
            DeviceType::Tap => libc::IFF_TAP | libc::IFF_NO_PI,
        };
        let mut ifreq = IfReq::new(ifname)?;
        ifreq.data.flags = flags as libc::c_short;
        // SAFETY: `fd` is a valid open TUN fd and `ifreq` is a valid,
        // fully initialized stack buffer of the size TUNSETIFF expects.
        let res = unsafe { libc::ioctl(fd.as_raw_fd(), TUNSETIFF.try_into().unwrap(), &mut ifreq) };
        match res {
            0 => {
                let mut ifname = String::with_capacity(32);
                let mut cursor = Cursor::new(ifreq.ifr_name);
                cursor.read_to_string(&mut ifname)?;
                ifname = ifname.trim_end_matches('\0').to_string();
                Ok(Self { fd, ifname, type_ })
            }
            _ => Err(std::io::Error::last_os_error()),
        }
    }

    #[inline]
    fn default_path(type_: DeviceType) -> &'static str {
        match type_ {
            DeviceType::Tun | DeviceType::Tap => "/dev/net/tun",
        }
    }

    #[inline]
    fn correct_data_after_read(&self, _buffer: &mut Buffer) {}

    #[inline]
    fn correct_data_before_write(&self, _buffer: &mut Buffer) {}

    fn get_overhead(&self) -> usize {
        40 /* for outer IPv6 header, can't be sure to only have IPv4 peers */
        + 8 /* for outer UDP header */
        + crate::EXTRA_LEN + crate::TAG_LEN /* crypto overhead */
        + 1 /* message type header */
        + match self.type_ {
            DeviceType::Tap => 14, /* inner ethernet header */
            DeviceType::Tun => 0
        }
    }

    /// Largest MTU that still fits the fixed 65535-byte `Buffer` used on the
    /// receive paths: a full-MTU read is later encrypted in place, which
    /// needs EXTRA_LEN + TAG_LEN of slack plus the headroom the caller
    /// reserves (the supernode uses 128 bytes). A larger TUN MTU would make
    /// encrypt run past the backing buffer and panic.
    const MAX_SAFE_MTU: usize = 65535 - 128 - crate::EXTRA_LEN - crate::TAG_LEN;

    fn set_mtu(&self, value: Option<usize>) -> anyhow::Result<()> {
        let value = match value {
            Some(value) => value,
            None => {
                let derived = get_device_mtu(&util::default_interface()?)? - self.get_overhead();
                if derived > Self::MAX_SAFE_MTU {
                    warn!(
                        "Derived MTU {} exceeds the receive buffer limit, clamping to {}",
                        derived,
                        Self::MAX_SAFE_MTU
                    );
                    Self::MAX_SAFE_MTU
                } else {
                    derived
                }
            }
        };
        info!("Setting MTU {} on device {}", value, self.ifname);
        set_device_mtu(&self.ifname, value)
    }

    pub fn set_ip(&self, ipv4: Option<&Ipv4>, ipv6: Option<&Ipv6>) -> anyhow::Result<()> {
        if ipv4.is_none() && ipv6.is_none() {
            return Err(anyhow::anyhow!("No assigned IP found"));
        }
        if let Some(ipv4) = ipv4 {
            info!(
                "Configuring device with ipv4 {}, netmask {}",
                ipv4.ip, ipv4.netmask
            );
            set_device_addr(&self.ifname, ipv4.ip)?;
            set_device_netmask(&self.ifname, ipv4.netmask)?;
        }
        if let Some(ipv6) = ipv6 {
            info!(
                "Configuring device with ipv6 {}, prefixlen {}",
                ipv6.ip, ipv6.prefix_len
            );
            set_device_addr_v6(&self.ifname, ipv6.ip, ipv6.prefix_len)?;
        }
        Ok(())
    }

    fn get_rp_filter(&self) -> io::Result<u8> {
        Ok(cmp::max(
            get_rp_filter("all")?,
            get_rp_filter(&self.ifname)?,
        ))
    }

    fn fix_rp_filter(&self) -> io::Result<()> {
        if get_rp_filter("all")? > 1 {
            info!("Setting net.ipv4.conf.all.rp_filter=1");
            set_rp_filter("all", 1)?
        }
        if get_rp_filter(&self.ifname)? != 1 {
            info!("Setting net.ipv4.conf.{}.rp_filter=1", self.ifname);
            set_rp_filter(&self.ifname, 1)?
        }
        Ok(())
    }

    pub fn get_ifname(&self) -> &str {
        &self.ifname
    }

    pub fn read(&self, buffer: &mut Buffer) -> anyhow::Result<usize> {
        buffer.clear();
        let r = (&self.fd).read(buffer.buffer())?;
        buffer.set_length(r);
        self.correct_data_after_read(buffer);
        Ok(r)
    }

    pub fn write(&self, buffer: &mut Buffer) -> anyhow::Result<usize> {
        self.correct_data_before_write(buffer);
        let r = (&self.fd).write(buffer.as_ref())?;
        (&self.fd).flush()?;
        Ok(r)
    }

    /// Set O_NONBLOCK so a stalled TUN queue fails with WouldBlock instead
    /// of blocking the caller (supernode event loop).
    pub fn set_nonblocking(&self) -> io::Result<()> {
        // SAFETY: `fd` is a valid open fd; fcntl only flips status flags.
        unsafe {
            let flags = libc::fcntl(self.fd.as_raw_fd(), libc::F_GETFL);
            if flags < 0 {
                return Err(io::Error::last_os_error());
            }
            if libc::fcntl(self.fd.as_raw_fd(), libc::F_SETFL, flags | libc::O_NONBLOCK) < 0 {
                return Err(io::Error::last_os_error());
            }
        }
        Ok(())
    }
}

impl AsRawFd for TunTapDevice {
    #[inline]
    fn as_raw_fd(&self) -> RawFd {
        self.fd.as_raw_fd()
    }
}

#[allow(clippy::useless_conversion)]
fn set_device_mtu(ifname: &str, mtu: usize) -> anyhow::Result<()> {
    let sock = UdpSocket::bind("0.0.0.0:0")?;
    let mut ifreq = IfReq::new(ifname)?;
    ifreq.data.value = mtu as libc::c_int;
    // SAFETY: `sock` is a valid socket fd and `ifreq` points to a valid
    // stack-initialized ifreq; the union field matches SIOCSIFMTU.
    let res = unsafe {
        libc::ioctl(
            sock.as_raw_fd(),
            libc::SIOCSIFMTU.try_into().unwrap(),
            &mut ifreq,
        )
    };
    match res {
        0 => Ok(()),
        _ => Err(anyhow::anyhow!(std::io::Error::last_os_error())),
    }
}

#[allow(clippy::useless_conversion)]
fn get_device_mtu(ifname: &str) -> io::Result<usize> {
    let sock = UdpSocket::bind("0.0.0.0:0")?;
    let mut ifreq = IfReq::new(ifname)?;
    // SAFETY: `sock` is a valid socket fd and `ifreq` is a valid
    // stack-initialized ifreq; the union field matches SIOCGIFMTU.
    let res = unsafe {
        libc::ioctl(
            sock.as_raw_fd(),
            libc::SIOCGIFMTU.try_into().unwrap(),
            &mut ifreq,
        )
    };
    match res {
        // SAFETY: the ioctl succeeded, so the kernel initialized the `value`
        // union member we read here.
        0 => Ok(unsafe { ifreq.data.value as usize }),
        _ => Err(std::io::Error::last_os_error()),
    }
}

#[allow(clippy::useless_conversion)]
fn set_device_addr(ifname: &str, addr: Ipv4Addr) -> io::Result<()> {
    let sock = UdpSocket::bind("0.0.0.0:0")?;
    // SAFETY: `sock` is a valid socket fd; `ifreq` lives on the stack and its
    // `addr` union member is fully initialized for SIOCSIFADDR (AF_INET).
    let res = unsafe {
        let mut ifreq = IfReq::new(ifname)?;
        ifreq.data.addr.af = libc::AF_INET as libc::c_int;
        ifreq.data.addr.addr = addr;

        libc::ioctl(
            sock.as_raw_fd(),
            libc::SIOCSIFADDR.try_into().unwrap(),
            &mut ifreq,
        )
    };
    match res {
        0 => Ok(()),
        _ => Err(std::io::Error::last_os_error()),
    }
}

fn get_ifindex(ifname: &str) -> io::Result<libc::c_int> {
    // SAFETY: plain socket creation with valid constants; the returned fd
    // is checked below and closed before returning.
    let sock = unsafe { libc::socket(libc::AF_INET6, libc::SOCK_DGRAM, 0) };
    if sock < 0 {
        return Err(io::Error::last_os_error());
    }
    let cname = CString::new(ifname).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "interface name contains null byte",
        )
    })?;
    // SAFETY: `cname` is a valid NUL-terminated CString that outlives the call.
    let idx = unsafe { libc::if_nametoindex(cname.as_ptr()) };
    if idx == 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `sock` is a valid fd opened above; closed exactly once.
    unsafe {
        libc::close(sock);
    }
    Ok(idx as libc::c_int)
}

#[allow(clippy::useless_conversion)]
fn set_device_addr_v6(ifname: &str, addr: Ipv6Addr, prefixlen: u8) -> io::Result<()> {
    let ifindex = get_ifindex(ifname)?;
    // SAFETY: plain socket creation with valid constants; the fd is checked
    // below and closed before returning.
    let sock = unsafe { libc::socket(libc::AF_INET6, libc::SOCK_DGRAM, 0) };
    if sock < 0 {
        return Err(io::Error::last_os_error());
    }

    let octets = addr.octets();
    // SAFETY: `in6_addr` is a C struct of 16 bytes; zeroed is a valid
    // representation and the copy writes exactly its 16 bytes.
    let mut in6_addr: libc::in6_addr = unsafe { std::mem::zeroed() };
    unsafe {
        let ptr = &mut in6_addr as *mut _ as *mut u8;
        std::ptr::copy_nonoverlapping(octets.as_ptr(), ptr, 16);
    };
    let mut ifreq6 = In6IfReq {
        addr: in6_addr,
        prefixlen: prefixlen as u32,
        ifindex,
    };

    // SAFETY: `sock` is a valid socket fd and `ifreq6` is a fully
    // initialized stack struct matching SIOCSIFADDR for IPv6.
    let res = unsafe { libc::ioctl(sock, libc::SIOCSIFADDR.try_into().unwrap(), &mut ifreq6) };
    // SAFETY: `sock` is closed exactly once here.
    unsafe {
        libc::close(sock);
    }
    match res {
        0 => Ok(()),
        _ => Err(io::Error::last_os_error()),
    }
}

#[allow(clippy::useless_conversion)]
fn set_device_netmask(ifname: &str, addr: Ipv4Addr) -> anyhow::Result<()> {
    let sock = UdpSocket::bind("0.0.0.0:0")?;

    // SAFETY: `sock` is a valid socket fd; `ifreq` lives on the stack and its
    // `addr` union member is fully initialized for SIOCSIFNETMASK (AF_INET).
    let res = unsafe {
        let mut ifreq = IfReq::new(ifname)?;
        ifreq.data.addr.af = libc::AF_INET as libc::c_int;
        ifreq.data.addr.addr = addr;

        libc::ioctl(
            sock.as_raw_fd(),
            libc::SIOCSIFNETMASK.try_into().unwrap(),
            &mut ifreq,
        )
    };
    match res {
        0 => Ok(()),
        _ => Err(anyhow::anyhow!(std::io::Error::last_os_error())),
    }
}

#[allow(clippy::useless_conversion)]
fn set_device_enabled(ifname: &str, up: bool) -> anyhow::Result<()> {
    let sock = UdpSocket::bind("0.0.0.0:0")?;
    let mut ifreq = IfReq::new(ifname)?;
    // SAFETY: `sock` is a valid socket fd and `ifreq` is a valid
    // stack-initialized ifreq for SIOCGIFFLAGS.
    if unsafe {
        libc::ioctl(
            sock.as_raw_fd(),
            libc::SIOCGIFFLAGS.try_into().unwrap(),
            &mut ifreq,
        )
    } != 0
    {
        return Err(anyhow::anyhow!(std::io::Error::last_os_error()));
    }
    // SAFETY: SIOCGIFFLAGS succeeded above, so the `value` union member is
    // initialized and writable.
    if up {
        unsafe { ifreq.data.value |= libc::IFF_UP | libc::IFF_RUNNING }
    } else {
        unsafe { ifreq.data.value &= !libc::IFF_UP }
    }
    // SAFETY: `sock` is a valid socket fd and `ifreq` is a valid
    // stack-initialized ifreq; the union field matches SIOCSIFFLAGS.
    let res = unsafe {
        libc::ioctl(
            sock.as_raw_fd(),
            libc::SIOCSIFFLAGS.try_into().unwrap(),
            &mut ifreq,
        )
    };
    match res {
        0 => Ok(()),
        _ => Err(anyhow::anyhow!(std::io::Error::last_os_error())),
    }
}

fn get_rp_filter(device: &str) -> io::Result<u8> {
    let mut fd = File::open(format!("/proc/sys/net/ipv4/conf/{}/rp_filter", device))?;
    let mut contents = String::with_capacity(10);
    fd.read_to_string(&mut contents)?;
    u8::from_str(contents.trim())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "Invalid rp_filter value"))
}

fn set_rp_filter(device: &str, val: u8) -> io::Result<()> {
    let mut fd = File::create(format!("/proc/sys/net/ipv4/conf/{}/rp_filter", device))?;
    writeln!(fd, "{}", val)
}

/// `anyhow::Result` instead of exiting: this module also compiles into the
/// Android client, where `process::exit` would silently kill the host app;
/// the caller (a binary entry point) decides how fatal the error is.
pub fn setup_device(iface: &str, device_type: &DeviceType) -> anyhow::Result<TunTapDevice> {
    let device = TunTapDevice::new(iface, *device_type).map_err(|err| {
        anyhow::anyhow!(
            "Failed to open virtual {} interface {}: {}",
            device_type,
            iface,
            err
        )
    })?;
    info!("Opened device {}", device.ifname);
    // A wrong MTU is fatal: reads could overrun the fixed-size buffers used
    // on the encrypt path, so do not continue with a misconfigured device.
    device
        .set_mtu(None)
        .map_err(|err| anyhow::anyhow!("Failed to set MTU on {}: {}", device.ifname, err))?;

    device
        .fix_rp_filter()
        .map_err(|err| anyhow::anyhow!("Failed to change rp_filter settings: {}", err))?;

    if let Ok(val) = device.get_rp_filter()
        && val != 1
    {
        warn!(
            "Your networking configuration might be affected by a vulnerability, please change your rp_filter setting to 1 (currently {}).",
            val
        );
    }

    // Use the kernel-assigned name, not the configured one: a "%d" template
    // resolves to e.g. "vpn0", and SIOCSIFFLAGS on the literal template name
    // always fails.
    set_device_enabled(device.get_ifname(), true).map_err(|err| {
        anyhow::anyhow!("Failed to bring device {} up: {}", device.get_ifname(), err)
    })?;
    info!("set device enable.");
    Ok(device)
}
