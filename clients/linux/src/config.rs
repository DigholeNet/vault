// SPDX-License-Identifier: MIT
use serde::{Deserialize, Serialize};
use std::net::{Ipv4Addr, Ipv6Addr};

#[derive(Serialize, Deserialize, Debug)]
#[serde(deny_unknown_fields)]
pub struct EdgeConfig {
    password: String,
    iface: String,
    host: String,
    port: u16,
    #[serde(default)]
    dns_ipv4: Vec<Ipv4Addr>,
    #[serde(default)]
    dns_ipv6: Vec<Ipv6Addr>,
    storage: String,
}
impl EdgeConfig {
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
        let v4: Vec<String> = if self.dns_ipv4.is_empty() {
            vec!["1.1.1.1".into(), "8.8.8.8".into()]
        } else {
            self.dns_ipv4.iter().map(ToString::to_string).collect()
        };
        let v6: Vec<String> = if self.dns_ipv6.is_empty() {
            vec!["2001:4860:4860::8888".into(), "2001:4860:4860::8844".into()]
        } else {
            self.dns_ipv6.iter().map(ToString::to_string).collect()
        };
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

    pub fn get_storage(&self) -> &str {
        &self.storage
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const VALID_TOML: &str = r#"
password = "secret"
iface = "vpn"
host = "vpn.example.com"
port = 9527
dns_ipv4 = ["8.8.8.8", "1.1.1.1"]
dns_ipv6 = ["2001:4860:4860::8888", "2001:4860:4860::8844"]
storage = "./tmp/storage.dat"
"#;

    #[test]
    fn parse_valid_config() {
        let config: EdgeConfig = toml::from_str(VALID_TOML).unwrap();
        assert_eq!(config.get_password(), "secret");
        assert_eq!(config.get_iface(), "vpn");
        assert_eq!(config.get_host(), "vpn.example.com");
        assert_eq!(config.get_port(), 9527);
        assert_eq!(
            config.dns_for(true, false),
            vec!["8.8.8.8".to_string(), "1.1.1.1".to_string()]
        );
        assert_eq!(config.get_storage(), "./tmp/storage.dat");
    }

    #[test]
    fn missing_field_fails() {
        let toml_str = r#"
password = "secret"
iface = "vpn"
"#;
        assert!(toml::from_str::<EdgeConfig>(toml_str).is_err());
    }
}

#[cfg(test)]
mod dns_tests {
    use super::*;

    fn config(extra: &str) -> anyhow::Result<EdgeConfig> {
        Ok(toml::from_str(&format!(
            r#"
password = "secret"
iface = "vpn"
host = "vpn.example.com"
port = 9527
storage = "storage.dat"
{extra}
"#
        ))?)
    }

    #[test]
    fn dns_families() {
        let cfg = config("").unwrap();
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
        assert!(config(r#"dns = ["1.1.1.1"]"#).is_err());
        assert!(config(r#"dns_ipv4 = ["::1"]"#).is_err());
        assert!(config(r#"dns_ipv6 = ["1.1.1.1"]"#).is_err());
    }
}
