// SPDX-License-Identifier: MIT
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug)]
pub struct EdgeConfig {
    password: String,
    iface: String,
    host: String,
    port: u16,
    dns: Vec<String>,
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

    pub fn get_dns(&self) -> &Vec<String> {
        &self.dns
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
dns = ["8.8.8.8", "1.1.1.1"]
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
            config.get_dns(),
            &vec!["8.8.8.8".to_string(), "1.1.1.1".to_string()]
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
