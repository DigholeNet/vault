// SPDX-License-Identifier: MIT
use serde::{Deserialize, Serialize};

use crate::ip::{Ipv4Cidr, Ipv6Cidr, deserialize_ipv4_cidr, deserialize_ipv6_cidr};

#[derive(Serialize, Deserialize, Debug)]
#[serde(deny_unknown_fields)]
pub struct SuperNodeConfig {
    password: String,
    iface: String,
    #[serde(default, deserialize_with = "deserialize_ipv4_cidr")]
    ipv4: Option<Ipv4Cidr>,
    #[serde(default, deserialize_with = "deserialize_ipv6_cidr")]
    ipv6: Option<Ipv6Cidr>,
    port: u16,
}

impl SuperNodeConfig {
    pub fn get_password(&self) -> &str {
        &self.password
    }

    pub fn get_iface(&self) -> &str {
        &self.iface
    }

    pub fn get_ipv4(&self) -> Option<&Ipv4Cidr> {
        self.ipv4.as_ref()
    }

    pub fn get_ipv6(&self) -> Option<&Ipv6Cidr> {
        self.ipv6.as_ref()
    }

    pub fn get_port(&self) -> u16 {
        self.port
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unknown_pool_field_is_rejected() {
        let config = r#"
password = "secret"
iface = "vpn"
port = 9527
ipv4 = "192.168.10.0/24"
ipv_6 = "fd00::/96"
"#;
        let error = toml::from_str::<SuperNodeConfig>(config).unwrap_err();
        assert!(error.to_string().contains("unknown field `ipv_6`"));
        let valid = config.replace("ipv_6", "ipv6");
        let parsed: SuperNodeConfig = toml::from_str(&valid).unwrap();
        assert_eq!(parsed.get_password(), "secret");
        assert_eq!(parsed.get_iface(), "vpn");
        assert_eq!(parsed.get_port(), 9527);
        assert!(parsed.get_ipv4().is_some());
        assert!(parsed.get_ipv6().is_some());
    }
}
