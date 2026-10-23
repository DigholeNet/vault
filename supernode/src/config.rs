// SPDX-License-Identifier: MIT
use serde::{Deserialize, Serialize};

use crate::ip::{Ipv4Cidr, Ipv6Cidr, deserialize_ipv4_cidr, deserialize_ipv6_cidr};

#[derive(Serialize, Deserialize, Debug)]
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
