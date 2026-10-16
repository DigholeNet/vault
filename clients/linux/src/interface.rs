// SPDX-License-Identifier: MIT
use std::{
    io::{BufRead, BufReader},
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    sync::Arc,
};

use tracing::info;
use vault_core::util;

#[derive(Default, Debug)]
pub struct Interface {
    name: String,
    ipv4: Option<Ipv4Addr>,
    gateway_ipv4: Option<Ipv4Addr>,
    ipv6: Option<Ipv6Addr>,
    gateway_ipv6: Option<Ipv6Addr>,
}

impl Interface {
    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn gateway_ipv4(&self) -> &Option<Ipv4Addr> {
        &self.gateway_ipv4
    }

    pub fn gateway_ipv6(&self) -> &Option<Ipv6Addr> {
        &self.gateway_ipv6
    }
}

/// Snapshot of the default physical interface. Returns an error instead of
/// panicking because hosts without a physical NIC (containers) would
/// otherwise crash at startup.
pub fn get_default_physical_interface() -> anyhow::Result<Arc<Interface>> {
    let name = util::default_interface()?;
    let interface = get_interface(&name).map_err(|e| anyhow::anyhow!("{}", e))?;
    Ok(Arc::new(interface))
}

fn get_interface(ifname: &str) -> Result<Interface, Box<dyn std::error::Error>> {
    let interfaces = pnet::datalink::interfaces();
    let interface = interfaces
        .into_iter()
        .find(|iface| iface.name == ifname)
        .ok_or_else(|| ifname.to_string() + " not found.")?;

    let mut r = Interface {
        name: ifname.to_owned(),
        ..Default::default()
    };

    for ip in &interface.ips {
        match ip.ip() {
            IpAddr::V4(ipv4) => {
                if r.ipv4.is_none() {
                    if let Ok(gateway) = get_v4_gateway(ifname) {
                        r.gateway_ipv4 = Some(gateway);
                    }
                    r.ipv4 = Some(ipv4);
                }
            }
            IpAddr::V6(ipv6) => {
                if r.ipv6.is_none() && is_global(&ipv6) {
                    if let Ok(gateway) = get_v6_gateway(ifname) {
                        r.gateway_ipv6 = Some(gateway);
                    }
                    r.ipv6 = Some(ipv6);
                }
            }
        }
    }
    info!("Read interface info : {}, {:?}", ifname, r);

    Ok(r)
}

fn get_v4_gateway(iface0: &str) -> Result<Ipv4Addr, Box<dyn std::error::Error>> {
    let file = std::fs::File::open("/proc/net/route")?;
    let reader = BufReader::new(file);
    for line in reader.lines().skip(1) {
        let line = line?;

        let fileds: Vec<&str> = line.split_whitespace().collect();

        if fileds.len() >= 8 {
            let iface = fileds[0];
            let destination = u32::from_str_radix(fileds[1], 16)?;
            let gateway = u32::from_str_radix(fileds[2], 16)?;
            let flags = u32::from_str_radix(fileds[3], 16)?;

            if iface.eq(iface0) && destination == 0 && flags & 0x2 > 0 {
                return Ok(Ipv4Addr::from(u32::to_be(gateway)));
            }
        }
    }
    Err("Default gateway not found.".into())
}

fn get_v6_gateway(iface0: &str) -> Result<Ipv6Addr, Box<dyn std::error::Error>> {
    let file = std::fs::File::open("/proc/net/ipv6_route")?;
    let reader = BufReader::new(file);
    for line in reader.lines().skip(1) {
        let line = line?;

        let fileds: Vec<&str> = line.split_whitespace().collect();

        if fileds.len() >= 10 {
            let iface = fileds[9];
            let prefix_len = u16::from_str_radix(fileds[1], 16)?;
            if !iface.eq(iface0) {
                continue;
            }
            if prefix_len == 0 {
                let gateway = fileds[4];
                if gateway.len() == 32 {
                    let segments: Result<Vec<u8>, _> = (0..16)
                        .map(|i| {
                            let segment = &gateway[i * 2..i * 2 + 2];
                            u8::from_str_radix(segment, 16)
                        })
                        .collect();
                    let segments = segments?;
                    let r: Result<[u8; 16], _> = segments.try_into();
                    if let Ok(r) = r {
                        return Ok(Ipv6Addr::from(r));
                    }
                }
            }
        }
    }
    Err("Default gateway not found.".into())
}

const fn is_global(ipv6: &Ipv6Addr) -> bool {
    !(ipv6.is_unspecified()
        || ipv6.is_loopback()
        // IPv4-mapped Address (`::ffff:0:0/96`)
        || matches!(ipv6.segments(), [0, 0, 0, 0, 0, 0xffff, _, _])
        // IPv4-IPv6 Translat. (`64:ff9b:1::/48`)
        || matches!(ipv6.segments(), [0x64, 0xff9b, 1, _, _, _, _, _])
        // Discard-Only Address Block (`100::/64`)
        || matches!(ipv6.segments(), [0x100, 0, 0, 0, _, _, _, _])
        // IETF Protocol Assignments (`2001::/23`)
        || (matches!(ipv6.segments(), [0x2001, b, _, _, _, _, _, _] if b < 0x200)
            && !(
                // Port Control Protocol Anycast (`2001:1::1`)
                u128::from_be_bytes(ipv6.octets()) == 0x2001_0001_0000_0000_0000_0000_0000_0001
                // Traversal Using Relays around NAT Anycast (`2001:1::2`)
                || u128::from_be_bytes(ipv6.octets()) == 0x2001_0001_0000_0000_0000_0000_0000_0002
                // AMT (`2001:3::/32`)
                || matches!(ipv6.segments(), [0x2001, 3, _, _, _, _, _, _])
                // AS112-v6 (`2001:4:112::/48`)
                || matches!(ipv6.segments(), [0x2001, 4, 0x112, _, _, _, _, _])
                // ORCHIDv2 (`2001:20::/28`)
                // Drone Remote ID Protocol Entity Tags (DETs) Prefix (`2001:30::/28`)`
                || matches!(ipv6.segments(), [0x2001, b, _, _, _, _, _, _] if b >= 0x20 && b <= 0x3F)
            ))
        // 6to4 (`2002::/16`) – it's not explicitly documented as globally reachable,
        // IANA says N/A.
        || matches!(ipv6.segments(), [0x2002, _, _, _, _, _, _, _])
        || ((ipv6.segments()[0] == 0x2001) && (ipv6.segments()[1] == 0xdb8))
        || ((ipv6.segments()[0] & 0xfe00) == 0xfc00)
        || ((ipv6.segments()[0] & 0xffc0) == 0xfe80))
}
