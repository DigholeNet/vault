// SPDX-License-Identifier: MIT
//! UniFFI records for vault-core's portable client settings and network plan.

use vault_core::PeerId;
use vault_core::settings::{self, AddressFamily, SettingsField};

#[derive(Debug, thiserror::Error, uniffi::Error)]
#[uniffi(flat_error)]
pub enum SettingsError {
    #[error("invalid host")]
    Host,
    #[error("invalid port")]
    Port,
    #[error("invalid password")]
    Password,
    #[error("invalid IPv4 DNS list")]
    DnsIpv4,
    #[error("invalid IPv6 DNS list")]
    DnsIpv6,
    #[error("invalid MTU")]
    Mtu,
    #[error("invalid probe domain list")]
    ProbeDomains,
    #[error("invalid peer id")]
    PeerId,
    #[error("invalid tunnel assignment: {0}")]
    Assignment(String),
}

impl From<SettingsField> for SettingsError {
    fn from(field: SettingsField) -> Self {
        match field {
            SettingsField::Host => Self::Host,
            SettingsField::Port => Self::Port,
            SettingsField::Password => Self::Password,
            SettingsField::DnsIpv4 => Self::DnsIpv4,
            SettingsField::DnsIpv6 => Self::DnsIpv6,
            SettingsField::Mtu => Self::Mtu,
            SettingsField::ProbeDomains => Self::ProbeDomains,
            SettingsField::PeerId => Self::PeerId,
        }
    }
}

#[derive(uniffi::Record)]
pub struct EdgeSettings {
    pub host: String,
    pub port: String,
    pub password: String,
    pub dns_ipv4: String,
    pub dns_ipv6: String,
    pub mtu: String,
    pub probe_domains: String,
}

#[derive(uniffi::Record)]
pub struct ValidatedEdgeSettings {
    pub host: String,
    pub port: u16,
    pub password: String,
    pub dns_ipv4: Vec<String>,
    pub dns_ipv6: Vec<String>,
    pub mtu_cap: Option<u16>,
    pub probe_domains: Vec<String>,
}

#[uniffi::export]
pub fn validate_edge_settings(
    settings: EdgeSettings,
) -> Result<ValidatedEdgeSettings, SettingsError> {
    let settings = settings::EdgeSettings {
        host: settings.host,
        port: settings.port,
        password: settings.password,
        dns_ipv4: settings.dns_ipv4,
        dns_ipv6: settings.dns_ipv6,
        mtu: settings.mtu,
        probe_domains: settings.probe_domains,
    };
    let validated = settings.validate()?;
    Ok(ValidatedEdgeSettings {
        host: validated.host,
        port: validated.port,
        password: validated.password,
        dns_ipv4: validated.dns_ipv4.iter().map(ToString::to_string).collect(),
        dns_ipv6: validated.dns_ipv6.iter().map(ToString::to_string).collect(),
        mtu_cap: validated.mtu_cap,
        probe_domains: validated.probe_domains,
    })
}

#[uniffi::export]
pub fn is_valid_address(value: String) -> bool {
    settings::is_valid_address(&value)
}

#[uniffi::export]
pub fn is_valid_server(value: String) -> bool {
    settings::is_valid_server(&value)
}

#[uniffi::export]
pub fn is_valid_domain(value: String) -> bool {
    settings::is_valid_domain(&value)
}

#[uniffi::export]
pub fn is_valid_dns_list(value: String, ipv6: Option<bool>) -> bool {
    let family = match ipv6 {
        Some(true) => AddressFamily::Ipv6,
        Some(false) => AddressFamily::Ipv4,
        None => AddressFamily::Any,
    };
    settings::parse_dns_list(&value, family).is_some()
}

#[uniffi::export]
pub fn is_valid_domain_list(value: String) -> bool {
    settings::parse_domain_list(&value).is_some()
}

#[uniffi::export]
pub fn is_valid_mtu(value: String) -> bool {
    settings::parse_mtu(&value).is_some()
}

#[uniffi::export]
pub fn mtu_cap(value: String) -> Option<u16> {
    settings::parse_mtu(&value).flatten()
}

#[uniffi::export]
pub fn calculate_tunnel_mtu(link_mtu: Option<u32>, cap: Option<u16>) -> u16 {
    settings::tunnel_mtu(link_mtu, cap)
}

#[uniffi::export]
pub fn generate_peer_id_hex() -> String {
    PeerId::default().to_string()
}

#[uniffi::export]
pub fn peer_id_from_hex(value: String) -> Result<Vec<u8>, SettingsError> {
    value
        .parse::<PeerId>()
        .map(|id| id.0.to_vec())
        .map_err(|_| SettingsError::PeerId)
}

#[derive(uniffi::Record, Clone, Debug, PartialEq)]
pub struct Ipv4Assignment {
    pub address: String,
    pub netmask: String,
    pub prefix_len: u8,
}

#[derive(uniffi::Record, Clone, Debug, PartialEq)]
pub struct Ipv6Assignment {
    pub address: String,
    pub prefix_len: u8,
}

#[derive(uniffi::Record, Clone, Debug, PartialEq)]
pub struct TunnelAssignment {
    pub ipv4: Option<Ipv4Assignment>,
    pub ipv6: Option<Ipv6Assignment>,
}

impl From<settings::TunnelAssignment> for TunnelAssignment {
    fn from(assignment: settings::TunnelAssignment) -> Self {
        Self {
            ipv4: assignment.ipv4.map(|ipv4| Ipv4Assignment {
                address: ipv4.address.to_string(),
                netmask: ipv4.netmask.to_string(),
                prefix_len: ipv4.prefix_len,
            }),
            ipv6: assignment.ipv6.map(|ipv6| Ipv6Assignment {
                address: ipv6.address.to_string(),
                prefix_len: ipv6.prefix_len,
            }),
        }
    }
}

#[uniffi::export]
pub fn parse_tunnel_assignment(
    ipv4: String,
    ipv4_mask: String,
    ipv6: String,
    ipv6_prefixlen: i32,
) -> Result<TunnelAssignment, SettingsError> {
    settings::TunnelAssignment::new(&ipv4, &ipv4_mask, &ipv6, ipv6_prefixlen)
        .map(Into::into)
        .map_err(SettingsError::Assignment)
}

#[uniffi::export]
pub fn tunnel_dns_servers(
    assignment: TunnelAssignment,
    configured_ipv4: Vec<String>,
    configured_ipv6: Vec<String>,
) -> Result<Vec<String>, SettingsError> {
    let assignment = core_assignment(&assignment)?;
    let configured_ipv4 = parse_addresses(configured_ipv4, AddressFamily::Ipv4)?;
    let configured_ipv6 = parse_addresses(configured_ipv6, AddressFamily::Ipv6)?;
    Ok(assignment
        .mobile_dns(&configured_ipv4, &configured_ipv6)
        .iter()
        .map(ToString::to_string)
        .collect())
}

#[uniffi::export]
pub fn effective_dns_servers(
    ipv4: bool,
    ipv6: bool,
    configured_ipv4: Vec<String>,
    configured_ipv6: Vec<String>,
) -> Result<Vec<String>, SettingsError> {
    let configured_ipv4 = parse_addresses(configured_ipv4, AddressFamily::Ipv4)?;
    let configured_ipv6 = parse_addresses(configured_ipv6, AddressFamily::Ipv6)?;
    Ok(
        settings::mobile_dns(ipv4, ipv6, &configured_ipv4, &configured_ipv6)
            .iter()
            .map(ToString::to_string)
            .collect(),
    )
}

#[uniffi::export]
pub fn tunnel_ipv6_network(assignment: TunnelAssignment) -> Result<Option<String>, SettingsError> {
    Ok(core_assignment(&assignment)?
        .ipv6_network()
        .map(|network| network.to_string()))
}

fn parse_addresses(
    addresses: Vec<String>,
    family: AddressFamily,
) -> Result<Vec<std::net::IpAddr>, SettingsError> {
    let field = match family {
        AddressFamily::Ipv4 => SettingsField::DnsIpv4,
        AddressFamily::Ipv6 => SettingsField::DnsIpv6,
        AddressFamily::Any => unreachable!(),
    };
    addresses
        .iter()
        .map(|value| {
            settings::parse_dns_address(value, family).ok_or_else(|| SettingsError::from(field))
        })
        .collect()
}

fn core_assignment(
    assignment: &TunnelAssignment,
) -> Result<settings::TunnelAssignment, SettingsError> {
    settings::TunnelAssignment::new(
        assignment
            .ipv4
            .as_ref()
            .map_or("", |ipv4| ipv4.address.as_str()),
        assignment
            .ipv4
            .as_ref()
            .map_or("", |ipv4| ipv4.netmask.as_str()),
        assignment
            .ipv6
            .as_ref()
            .map_or("", |ipv6| ipv6.address.as_str()),
        assignment
            .ipv6
            .as_ref()
            .map_or(0, |ipv6| ipv6.prefix_len.into()),
    )
    .map_err(SettingsError::Assignment)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn assignment() {
        let assignment = parse_tunnel_assignment(
            "192.168.10.2".into(),
            "255.255.255.0".into(),
            "fd00::2".into(),
            96,
        )
        .unwrap();
        assert_eq!(assignment.ipv4.as_ref().unwrap().prefix_len, 24);
        assert_eq!(
            tunnel_ipv6_network(assignment.clone()).unwrap().as_deref(),
            Some("fd00::")
        );
        let dns = tunnel_dns_servers(assignment, vec![], vec![]).unwrap();
        assert_eq!(dns.len(), 4);
    }

    #[test]
    fn dns_mapped() {
        let assignment =
            parse_tunnel_assignment("".into(), "".into(), "fd00::2".into(), 96).unwrap();
        for dns in ["::ffff:1.1.1.1", "::ffff:101:101"] {
            assert!(!is_valid_dns_list(dns.into(), Some(true)), "{dns}");
            let settings = EdgeSettings {
                host: "vpn.example.com".into(),
                port: "9527".into(),
                password: "secret".into(),
                dns_ipv4: "".into(),
                dns_ipv6: dns.into(),
                mtu: "".into(),
                probe_domains: "".into(),
            };
            assert!(matches!(
                validate_edge_settings(settings),
                Err(SettingsError::DnsIpv6)
            ));
            assert!(matches!(
                tunnel_dns_servers(assignment.clone(), vec![], vec![dns.into()]),
                Err(SettingsError::DnsIpv6)
            ));
            assert!(matches!(
                effective_dns_servers(false, true, vec![], vec![dns.into()]),
                Err(SettingsError::DnsIpv6)
            ));
        }
    }

    #[test]
    fn peer_id() {
        let id = generate_peer_id_hex();
        assert_eq!(id.len(), 32);
        assert_eq!(peer_id_from_hex(id).unwrap().len(), 16);
        assert!(peer_id_from_hex("invalid".into()).is_err());
    }
}
