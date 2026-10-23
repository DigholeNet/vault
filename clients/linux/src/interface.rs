// SPDX-License-Identifier: MIT
use std::net::IpAddr;
#[cfg(target_os = "linux")]
use std::{
    net::{Ipv4Addr, Ipv6Addr},
    process::Command,
};

use serde::Deserialize;

/// Physical exit snapshot, including addresses so DHCP renewals trigger recovery.
#[cfg(target_os = "linux")]
#[derive(Debug, PartialEq, Eq)]
pub struct Interface {
    name: String,
    addresses: Vec<IpAddr>,
    gateway: Option<IpAddr>,
}
#[cfg(target_os = "linux")]
impl Interface {
    pub fn name(&self) -> &str {
        &self.name
    }
    pub fn gateway_ipv4(&self) -> Option<Ipv4Addr> {
        match self.gateway {
            Some(IpAddr::V4(ip)) => Some(ip),
            _ => None,
        }
    }
    pub fn gateway_ipv6(&self) -> Option<Ipv6Addr> {
        match self.gateway {
            Some(IpAddr::V6(ip)) => Some(ip),
            _ => None,
        }
    }
}

/// Physical exit per address family. IPv4 and IPv6 default routes may live
/// on different interfaces with different gateways, so each family is
/// probed and tracked independently; a family without a default route has
/// no exit (None).
#[cfg(target_os = "linux")]
#[derive(Debug, Default, PartialEq, Eq)]
pub struct FamilyExits {
    pub v4: Option<Interface>,
    pub v6: Option<Interface>,
}

#[derive(Deserialize)]
struct DefaultRoute {
    dev: Option<String>,
    gateway: Option<IpAddr>,
    #[serde(default)]
    metric: u64,
    #[serde(default)]
    flags: Vec<String>,
}

fn select_route<'a>(
    routes: &'a [DefaultRoute],
    tun: &str,
    running: &[String],
) -> Option<&'a DefaultRoute> {
    routes
        .iter()
        .filter(|route| {
            route
                .dev
                .as_ref()
                .is_some_and(|dev| dev != tun && running.contains(dev))
                && !route
                    .flags
                    .iter()
                    .any(|flag| flag == "linkdown" || flag == "dead")
        })
        .min_by_key(|route| route.metric)
}

/// Read physical default routes, ignoring our VPN default route.
/// Polling this snapshot from the existing runner also detects same-type switches.
#[cfg(target_os = "linux")]
pub fn get_default_physical_interface(server: IpAddr, tun: &str) -> anyhow::Result<Interface> {
    let output = Command::new("ip")
        .args([
            "-j",
            if server.is_ipv6() { "-6" } else { "-4" },
            "route",
            "show",
            "default",
        ])
        .output()?;
    anyhow::ensure!(
        output.status.success(),
        "read physical default routes: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let routes: Vec<DefaultRoute> = serde_json::from_slice(&output.stdout)?;
    let interfaces = pnet::datalink::interfaces();
    let running: Vec<_> = interfaces
        .iter()
        .filter(|iface| iface.is_running() && !iface.is_loopback())
        .map(|iface| iface.name.clone())
        .collect();
    let route = select_route(&routes, tun, &running)
        .ok_or_else(|| anyhow::anyhow!("no physical default route for {server}"))?;
    let iface = interfaces
        .iter()
        .find(|iface| Some(&iface.name) == route.dev.as_ref())
        .unwrap();
    let mut addresses: Vec<_> = iface.ips.iter().map(|ip| ip.ip()).collect();
    addresses.sort();
    Ok(Interface {
        name: iface.name.clone(),
        addresses,
        gateway: route.gateway,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn physical_route() {
        let routes: Vec<DefaultRoute> = serde_json::from_str(
            r#"[
            {"dev":"vpn","metric":1},
            {"dev":"wlan0","gateway":"192.0.2.1","metric":100},
            {"dev":"eth0","gateway":"198.51.100.1","metric":10},
            {"dev":"eth1","metric":2,"flags":["linkdown"]},
            {"dev":"removed","metric":0}
        ]"#,
        )
        .unwrap();
        let running = vec!["vpn".into(), "wlan0".into(), "eth0".into(), "eth1".into()];
        assert_eq!(
            select_route(&routes, "vpn", &running)
                .unwrap()
                .dev
                .as_deref(),
            Some("eth0")
        );
        assert!(select_route(&routes, "vpn", &["vpn".into()]).is_none());
    }

    #[test]
    fn ipv6_route() {
        let routes: Vec<DefaultRoute> = serde_json::from_str(
            r#"[
            {"dev":"eth0","gateway":"fe80::1","metric":100},
            {"dev":"wwan0","metric":10}
        ]"#,
        )
        .unwrap();
        let selected = select_route(&routes, "vpn", &["eth0".into(), "wwan0".into()]).unwrap();
        assert_eq!(selected.dev.as_deref(), Some("wwan0"));
        assert_eq!(selected.gateway, None);
    }
}
