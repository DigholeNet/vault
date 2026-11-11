// SPDX-License-Identifier: MIT
//! Portable client settings and tunnel network calculations.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use crate::diagnostics::wire::valid_domain;
use crate::{DEFAULT_DNS_IPV4, DEFAULT_DNS_IPV6, TUNNEL_MTU_MAX, TUNNEL_MTU_MIN, TUNNEL_OVERHEAD};

pub const MAX_DNS_SERVERS: usize = 4;
pub const MAX_PROBE_DOMAINS: usize = 32;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AddressFamily {
    Any,
    Ipv4,
    Ipv6,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SettingsField {
    Host,
    Port,
    Password,
    DnsIpv4,
    DnsIpv6,
    Mtu,
    ProbeDomains,
    PeerId,
}

#[derive(Debug, Clone, Default)]
pub struct EdgeSettings {
    pub host: String,
    pub port: String,
    pub password: String,
    pub dns_ipv4: String,
    pub dns_ipv6: String,
    pub mtu: String,
    pub probe_domains: String,
}

#[derive(Debug, Clone)]
pub struct ValidatedEdgeSettings {
    pub host: String,
    pub port: u16,
    pub password: String,
    pub dns_ipv4: Vec<IpAddr>,
    pub dns_ipv6: Vec<IpAddr>,
    pub mtu_cap: Option<u16>,
    pub probe_domains: Vec<String>,
}

impl EdgeSettings {
    pub fn validate(&self) -> Result<ValidatedEdgeSettings, SettingsField> {
        let host = normalize_host(&self.host);
        if !is_valid_server(&host) {
            return Err(SettingsField::Host);
        }
        let port = self
            .port
            .trim()
            .parse::<u16>()
            .ok()
            .filter(|port| *port > 0)
            .ok_or(SettingsField::Port)?;
        if self.password.is_empty() {
            return Err(SettingsField::Password);
        }
        let dns_ipv4 =
            parse_dns_list(&self.dns_ipv4, AddressFamily::Ipv4).ok_or(SettingsField::DnsIpv4)?;
        let dns_ipv6 =
            parse_dns_list(&self.dns_ipv6, AddressFamily::Ipv6).ok_or(SettingsField::DnsIpv6)?;
        let mtu_cap = parse_mtu(&self.mtu).ok_or(SettingsField::Mtu)?;
        let probe_domains =
            parse_domain_list(&self.probe_domains).ok_or(SettingsField::ProbeDomains)?;
        Ok(ValidatedEdgeSettings {
            host,
            port,
            password: self.password.clone(),
            dns_ipv4,
            dns_ipv6,
            mtu_cap,
            probe_domains,
        })
    }
}

pub fn normalize_host(value: &str) -> String {
    let host = value.trim();
    host.strip_prefix('[')
        .and_then(|host| host.strip_suffix(']'))
        .unwrap_or(host)
        .to_string()
}

pub fn is_valid_address(value: &str) -> bool {
    value.parse::<IpAddr>().is_ok()
}

pub fn is_valid_server(value: &str) -> bool {
    let host = normalize_host(value);
    is_valid_address(&host) || is_valid_domain(&host)
}

pub fn is_valid_domain(value: &str) -> bool {
    let host = value.strip_suffix('.').unwrap_or(value);
    value.len() <= 253 && valid_domain(host)
}

pub fn parse_dns_list(value: &str, family: AddressFamily) -> Option<Vec<IpAddr>> {
    let entries = parse_list(value, MAX_DNS_SERVERS)?;
    entries
        .into_iter()
        .map(|entry| {
            entry.parse::<IpAddr>().ok().filter(|address| {
                matches!(family, AddressFamily::Any)
                    || matches!(
                        (family, address),
                        (AddressFamily::Ipv4, IpAddr::V4(_)) | (AddressFamily::Ipv6, IpAddr::V6(_))
                    )
            })
        })
        .collect()
}

pub fn parse_domain_list(value: &str) -> Option<Vec<String>> {
    parse_list(value, MAX_PROBE_DOMAINS)?
        .into_iter()
        .map(|domain| is_valid_domain(domain).then(|| domain.to_string()))
        .collect()
}

pub fn parse_mtu(value: &str) -> Option<Option<u16>> {
    let value = value.trim();
    if value.is_empty() {
        return Some(None);
    }
    value
        .parse::<u16>()
        .ok()
        .filter(|mtu| (TUNNEL_MTU_MIN..=TUNNEL_MTU_MAX).contains(mtu))
        .map(Some)
}

fn parse_list(value: &str, limit: usize) -> Option<Vec<&str>> {
    if value.trim().is_empty() {
        return Some(vec![]);
    }
    let entries: Vec<_> = value.split(',').map(str::trim).collect();
    (entries.len() <= limit && entries.iter().all(|entry| !entry.is_empty())).then_some(entries)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ipv4Assignment {
    pub address: Ipv4Addr,
    pub netmask: Ipv4Addr,
    pub prefix_len: u8,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ipv6Assignment {
    pub address: Ipv6Addr,
    pub prefix_len: u8,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TunnelAssignment {
    pub ipv4: Option<Ipv4Assignment>,
    pub ipv6: Option<Ipv6Assignment>,
}

impl TunnelAssignment {
    pub fn new(
        ipv4: &str,
        ipv4_mask: &str,
        ipv6: &str,
        ipv6_prefixlen: i32,
    ) -> Result<Self, String> {
        if ipv4.is_empty() != ipv4_mask.is_empty() {
            return Err("incomplete tunnel IPv4 assignment".into());
        }
        let ipv4 = if ipv4.is_empty() {
            None
        } else {
            let address = ipv4
                .parse::<Ipv4Addr>()
                .map_err(|_| "invalid tunnel IPv4 address")?;
            let netmask = ipv4_mask
                .parse::<Ipv4Addr>()
                .map_err(|_| "invalid tunnel IPv4 mask")?;
            let bits = u32::from(netmask);
            let inverse = !bits;
            if inverse & inverse.wrapping_add(1) != 0 {
                return Err("non-contiguous tunnel IPv4 mask".into());
            }
            Some(Ipv4Assignment {
                address,
                netmask,
                prefix_len: bits.count_ones() as u8,
            })
        };
        let ipv6 = if ipv6.is_empty() {
            None
        } else {
            let address = ipv6
                .parse::<Ipv6Addr>()
                .map_err(|_| "invalid tunnel IPv6 address")?;
            let prefix_len = u8::try_from(ipv6_prefixlen)
                .ok()
                .filter(|prefix| *prefix <= 128)
                .ok_or("invalid tunnel IPv6 prefix")?;
            Some(Ipv6Assignment {
                address,
                prefix_len,
            })
        };
        if ipv4.is_none() && ipv6.is_none() {
            return Err("no tunnel address assigned".into());
        }
        Ok(Self { ipv4, ipv6 })
    }

    pub fn mobile_dns(
        &self,
        configured_ipv4: &[IpAddr],
        configured_ipv6: &[IpAddr],
    ) -> Vec<IpAddr> {
        mobile_dns(
            self.ipv4.is_some(),
            self.ipv6.is_some(),
            configured_ipv4,
            configured_ipv6,
        )
    }

    pub fn ipv6_network(&self) -> Option<Ipv6Addr> {
        self.ipv6.as_ref().map(|assignment| {
            let prefix = assignment.prefix_len;
            let address = u128::from(assignment.address);
            let network = if prefix == 0 {
                0
            } else {
                address & (u128::MAX << (128 - prefix))
            };
            Ipv6Addr::from(network)
        })
    }
}

pub fn mobile_dns(
    ipv4: bool,
    ipv6: bool,
    configured_ipv4: &[IpAddr],
    configured_ipv6: &[IpAddr],
) -> Vec<IpAddr> {
    let mut servers = Vec::new();
    if ipv4 {
        servers.extend(default_dns_ipv4(configured_ipv4));
    }
    if ipv6 {
        servers.extend(default_dns_ipv6(configured_ipv6));
    }
    servers
}

pub fn default_dns_ipv4(configured: &[IpAddr]) -> Vec<IpAddr> {
    if configured.is_empty() {
        DEFAULT_DNS_IPV4
            .iter()
            .filter_map(|address| address.parse().ok())
            .collect()
    } else {
        configured.to_vec()
    }
}

pub fn default_dns_ipv6(configured: &[IpAddr]) -> Vec<IpAddr> {
    if configured.is_empty() {
        DEFAULT_DNS_IPV6
            .iter()
            .filter_map(|address| address.parse().ok())
            .collect()
    } else {
        configured.to_vec()
    }
}

pub fn linux_dns(
    ipv4: bool,
    ipv6: bool,
    configured_ipv4: &[IpAddr],
    configured_ipv6: &[IpAddr],
) -> Vec<IpAddr> {
    let v4 = default_dns_ipv4(configured_ipv4);
    let v6 = default_dns_ipv6(configured_ipv6);
    match (ipv4, ipv6) {
        (true, true) => v6
            .into_iter()
            .take(2)
            .chain(v4.into_iter().take(1))
            .collect(),
        (true, false) => v4.into_iter().take(3).collect(),
        (false, true) => v6.into_iter().take(3).collect(),
        (false, false) => vec![],
    }
}

pub fn tunnel_mtu(link_mtu: Option<u32>, cap: Option<u16>) -> u16 {
    let cap = cap
        .unwrap_or(TUNNEL_MTU_MAX)
        .clamp(TUNNEL_MTU_MIN, TUNNEL_MTU_MAX);
    let automatic = link_mtu.map_or(TUNNEL_MTU_MAX, |mtu| {
        mtu.saturating_sub(TUNNEL_OVERHEAD as u32)
            .clamp(TUNNEL_MTU_MIN as u32, TUNNEL_MTU_MAX as u32) as u16
    });
    automatic.min(cap)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn settings() {
        let settings = EdgeSettings {
            host: " vpn.example.com ".into(),
            port: "9527".into(),
            password: " secret ".into(),
            dns_ipv4: " 1.1.1.1, 8.8.8.8 ".into(),
            dns_ipv6: " 2606:4700:4700::1111 ".into(),
            mtu: " 1280 ".into(),
            probe_domains: " example.com, github.com ".into(),
        };
        let validated = settings.validate().unwrap();
        assert_eq!(validated.host, "vpn.example.com");
        assert_eq!(validated.password, " secret ");
        assert_eq!(validated.dns_ipv4.len(), 2);
        assert_eq!(validated.mtu_cap, Some(1280));
        assert_eq!(validated.probe_domains, ["example.com", "github.com"]);
    }

    #[test]
    fn invalid_settings() {
        for host in [
            "",
            "https://example.com",
            "example.com/path",
            "bad host",
            "-bad.example",
        ] {
            assert!(!is_valid_server(host), "{host}");
        }
        for dns in [
            "example.com",
            "1.1.1.1,",
            "999.1.1.1",
            "1.2.3",
            "1.1.1.1,,8.8.8.8",
        ] {
            assert_eq!(parse_dns_list(dns, AddressFamily::Any), None, "{dns}");
        }
        assert_eq!(parse_dns_list("::1", AddressFamily::Ipv4), None);
        assert_eq!(parse_dns_list("1.1.1.1", AddressFamily::Ipv6), None);
        assert_eq!(parse_dns_list("١.٢.٣.٤", AddressFamily::Any), None);
        assert_eq!(
            parse_dns_list(&["1.1.1.1"; 5].join(","), AddressFamily::Ipv4),
            None
        );
        assert_eq!(parse_domain_list(&["d.example"; 33].join(",")), None);
        assert_eq!(parse_domain_list("google.com,"), None);
        assert_eq!(parse_mtu("1279"), None);
        assert_eq!(parse_mtu("1428"), None);
        assert_eq!(parse_mtu(""), Some(None));
    }

    #[test]
    fn assignment() {
        let assignment =
            TunnelAssignment::new("192.168.10.2", "255.255.255.0", "fd00::2", 96).unwrap();
        assert_eq!(assignment.ipv4.as_ref().unwrap().prefix_len, 24);
        assert_eq!(
            assignment.ipv6_network().unwrap(),
            "fd00::".parse::<Ipv6Addr>().unwrap()
        );
        for values in [
            ("", "", "", 0),
            ("192.168.10.2", "", "", 0),
            ("", "255.255.255.0", "fd00::2", 96),
            ("192.168.10.2", "255.0.255.0", "", 0),
            ("fd00::2", "255.255.255.0", "", 0),
            ("", "", "192.168.10.2", 96),
            ("", "", "fd00::2", 129),
        ] {
            assert!(TunnelAssignment::new(values.0, values.1, values.2, values.3).is_err());
        }
    }

    #[test]
    fn dns_policies() {
        let dual = TunnelAssignment::new("192.168.10.2", "255.255.255.0", "fd00::2", 96).unwrap();
        let mobile = dual.mobile_dns(&[], &[]);
        assert_eq!(mobile.len(), 4);
        assert!(mobile[0].is_ipv4());
        let linux = linux_dns(true, true, &[], &[]);
        assert_eq!(linux.len(), 3);
        assert!(linux[0].is_ipv6() && linux[1].is_ipv6() && linux[2].is_ipv4());
    }

    #[test]
    fn mtu_cap() {
        assert_eq!(tunnel_mtu(None, None), TUNNEL_MTU_MAX);
        assert_eq!(tunnel_mtu(Some(1500), None), TUNNEL_MTU_MAX);
        assert_eq!(tunnel_mtu(Some(1400), None), 1327);
        assert_eq!(tunnel_mtu(Some(1400), Some(1300)), 1300);
        assert_eq!(tunnel_mtu(Some(9000), Some(1300)), 1300);
        assert_eq!(tunnel_mtu(Some(1000), None), TUNNEL_MTU_MIN);
        assert_eq!(tunnel_mtu(None, Some(9000)), TUNNEL_MTU_MAX);
    }
}
