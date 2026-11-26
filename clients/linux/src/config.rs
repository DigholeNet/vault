// SPDX-License-Identifier: MIT
use anyhow::Context;
use serde::{Deserialize, Deserializer, de::Error};
use std::{
    collections::{BTreeMap, BTreeSet},
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
};
use vault_core::settings::{AddressFamily, parse_dns_address};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct EdgeFileConfig {
    iface: String,
    storage: String,
    default_profile: Option<String>,
    profiles: BTreeMap<String, EdgeProfile>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct EdgeProfile {
    password: String,
    host: String,
    port: u16,
    #[serde(default)]
    dns_ipv4: Vec<Ipv4Addr>,
    #[serde(default, deserialize_with = "deserialize_dns_ipv6")]
    dns_ipv6: Vec<Ipv6Addr>,
}

#[derive(Debug)]
pub struct SelectedEdgeConfig {
    name: String,
    password: String,
    iface: String,
    host: String,
    port: u16,
    dns_ipv4: Vec<Ipv4Addr>,
    dns_ipv6: Vec<Ipv6Addr>,
    storage: String,
}

fn deserialize_dns_ipv6<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<Vec<Ipv6Addr>, D::Error> {
    Vec::<String>::deserialize(deserializer)?
        .into_iter()
        .map(
            |value| match parse_dns_address(&value, AddressFamily::Ipv6) {
                Some(IpAddr::V6(address)) => Ok(address),
                _ => Err(D::Error::custom(format!(
                    "invalid dns_ipv6 address: {value}"
                ))),
            },
        )
        .collect()
}

impl SelectedEdgeConfig {
    pub fn select(value: toml::Value, requested: Option<&str>) -> anyhow::Result<Self> {
        let file: EdgeFileConfig = value.try_into().context(
            "invalid Edge configuration; legacy single-profile files must be rewritten with [profiles.<name>]",
        )?;
        let mut folded = BTreeSet::new();
        for name in file.profiles.keys() {
            anyhow::ensure!(
                !name.is_empty() && name.trim() == name,
                "profile names must be non-empty and have no surrounding whitespace"
            );
            anyhow::ensure!(
                folded.insert(name.to_lowercase()),
                "profile names must be unique ignoring case: {name}"
            );
        }
        anyhow::ensure!(
            !file.profiles.is_empty(),
            "at least one profile is required"
        );
        let name = match requested.map(str::to_owned).or(file.default_profile) {
            Some(name) => name,
            None if file.profiles.len() == 1 => file.profiles.keys().next().unwrap().clone(),
            None => anyhow::bail!("select a profile with --profile or default_profile"),
        };
        let profile = file
            .profiles
            .get(&name)
            .with_context(|| format!("unknown Edge profile: {name}"))?;
        anyhow::ensure!(
            profile.port > 0,
            "profile {name}: port must be greater than zero"
        );
        Ok(Self {
            name,
            password: profile.password.clone(),
            iface: file.iface,
            host: profile.host.clone(),
            port: profile.port,
            dns_ipv4: profile.dns_ipv4.clone(),
            dns_ipv6: profile.dns_ipv6.clone(),
            storage: file.storage,
        })
    }

    pub fn get_profile(&self) -> &str {
        &self.name
    }

    pub fn get_password(&self) -> &str {
        &self.password
    }

    pub fn get_iface(&self) -> &str {
        &self.iface
    }

    pub fn get_host(&self) -> &str {
        &self.host
    }

    pub fn get_port(&self) -> u16 {
        self.port
    }

    pub fn dns_for(&self, ipv4: bool, ipv6: bool) -> Vec<String> {
        let v4: Vec<_> = self.dns_ipv4.iter().copied().map(IpAddr::V4).collect();
        let v6: Vec<_> = self.dns_ipv6.iter().copied().map(IpAddr::V6).collect();
        vault_core::settings::linux_dns(ipv4, ipv6, &v4, &v6)
            .iter()
            .map(ToString::to_string)
            .collect()
    }

    pub fn get_storage(&self) -> &str {
        &self.storage
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const VALID_TOML: &str = r#"
iface = "vpn"
storage = "./tmp/storage.dat"
default_profile = "home"

[profiles.home]
password = "secret"
host = "vpn.example.com"
port = 9527
dns_ipv4 = ["8.8.8.8", "1.1.1.1"]
dns_ipv6 = ["2001:4860:4860::8888", "2001:4860:4860::8844"]

[profiles.work]
password = "work-secret"
host = "work.example.com"
port = 19527
"#;

    fn select(toml_str: &str, profile: Option<&str>) -> anyhow::Result<SelectedEdgeConfig> {
        SelectedEdgeConfig::select(toml::from_str(toml_str)?, profile)
    }

    #[test]
    fn parse_selected_config() {
        let config = select(VALID_TOML, None).unwrap();
        assert_eq!(config.get_profile(), "home");
        assert_eq!(config.get_password(), "secret");
        assert_eq!(config.get_iface(), "vpn");
        assert_eq!(config.get_host(), "vpn.example.com");
        assert_eq!(config.get_port(), 9527);
        assert_eq!(
            config.dns_for(true, false),
            vec!["8.8.8.8".to_string(), "1.1.1.1".to_string()]
        );
        assert_eq!(config.get_storage(), "./tmp/storage.dat");
        let work = select(VALID_TOML, Some("work")).unwrap();
        assert_eq!(work.get_profile(), "work");
        assert_eq!(work.get_host(), "work.example.com");
        assert_eq!(work.get_port(), 19527);
    }

    #[test]
    fn profile_required() {
        let without_default = VALID_TOML.replace("default_profile = \"home\"\n", "");
        assert!(select(&without_default, None).is_err());
        assert!(select(VALID_TOML, Some("missing")).is_err());
    }

    #[test]
    fn single_profile_default() {
        let single = r#"
iface = "vpn"
storage = "storage.dat"
[profiles.only]
password = "secret"
host = "vpn.example.com"
port = 9527
"#;
        assert_eq!(select(single, None).unwrap().get_profile(), "only");
    }

    #[test]
    fn legacy_config_fails() {
        let legacy = r#"
password = "secret"
iface = "vpn"
host = "vpn.example.com"
port = 9527
storage = "storage.dat"
"#;
        let error = select(legacy, None).unwrap_err().to_string();
        assert!(error.contains("legacy single-profile"), "{error}");
    }

    #[test]
    fn invalid_names() {
        assert!(
            select(
                &VALID_TOML.replace("[profiles.work]", "[profiles.HOME]"),
                None
            )
            .is_err()
        );
        assert!(
            select(
                &VALID_TOML.replace("[profiles.work]", "[profiles.\" work\"]"),
                None
            )
            .is_err()
        );
    }

    #[test]
    fn removed_peer_options() {
        for key in ["peer_discovery", "peer_lan"] {
            let invalid = VALID_TOML.replace("port = 9527", &format!("port = 9527\n{key} = false"));
            assert!(select(&invalid, None).is_err());
        }
    }

    #[test]
    fn zero_port_fails() {
        assert!(select(&VALID_TOML.replace("port = 9527", "port = 0"), None).is_err());
    }
}

#[cfg(test)]
mod dns_tests {
    use super::*;

    fn config(extra: &str) -> anyhow::Result<SelectedEdgeConfig> {
        SelectedEdgeConfig::select(
            toml::from_str(&format!(
                r#"
iface = "vpn"
storage = "storage.dat"
[profiles.default]
password = "secret"
host = "vpn.example.com"
port = 9527
{extra}
"#
            ))?,
            None,
        )
    }

    #[test]
    fn dns_families() {
        let cfg = config("").unwrap();
        assert_eq!(
            config("dns_ipv6 = []").unwrap().dns_for(false, true),
            cfg.dns_for(false, true)
        );
        assert_eq!(cfg.dns_for(true, false), ["1.1.1.1", "8.8.8.8"]);
        assert_eq!(
            cfg.dns_for(false, true),
            ["2001:4860:4860::8888", "2001:4860:4860::8844"]
        );
        assert_eq!(
            cfg.dns_for(true, true),
            ["2001:4860:4860::8888", "2001:4860:4860::8844", "1.1.1.1"]
        );
        assert!(cfg.dns_for(false, false).is_empty());
    }

    #[test]
    fn dns_custom() {
        let cfg = config(
            r#"dns_ipv4 = ["9.9.9.9", "149.112.112.112"]
dns_ipv6 = ["2606:4700:4700::1111", "2606:4700:4700::1001", "2001:4860:4860::8888"]"#,
        )
        .unwrap();
        assert_eq!(
            cfg.dns_for(true, true),
            ["2606:4700:4700::1111", "2606:4700:4700::1001", "9.9.9.9"]
        );
    }

    #[test]
    fn dns_invalid() {
        assert!(config("dns = [\"1.1.1.1\"]").is_err());
        assert!(config("dns_ipv4 = [\"::1\"]").is_err());
        assert!(config("dns_ipv6 = [\"1.1.1.1\"]").is_err());
    }

    #[test]
    fn dns_mapped() {
        for dns in ["::ffff:1.1.1.1", "::ffff:101:101"] {
            for list in [
                format!(r#"dns_ipv6 = ["{dns}"]"#),
                format!(r#"dns_ipv6 = ["2001:4860:4860::8888", "{dns}"]"#),
            ] {
                let error = format!("{:#}", config(&list).unwrap_err());
                assert!(error.contains("dns_ipv6"), "{error}");
            }
        }
    }

    #[test]
    fn dns_ipv6() {
        for dns in ["2001:4860:4860::8888", "::1", "64:ff9b::101:101"] {
            let cfg = config(&format!(r#"dns_ipv6 = ["{dns}"]"#)).unwrap();
            assert_eq!(cfg.dns_for(false, true), [dns]);
        }
    }
}
