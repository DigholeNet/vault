// SPDX-License-Identifier: MIT
mod ip_manager;
mod pool;

pub use ip_manager::IpManager;
pub use ip_manager::IpReservation;
pub use pool::Ipv4Cidr;
pub use pool::Ipv4Pool;
pub use pool::Ipv6Cidr;
pub use pool::Ipv6Pool;
#[cfg(target_os = "linux")]
use serde::Deserialize;
#[cfg(target_os = "linux")]
use serde::Deserializer;

#[cfg(target_os = "linux")]
pub fn deserialize_ipv4_cidr<'de, D>(deserializer: D) -> Result<Option<Ipv4Cidr>, D::Error>
where
    D: Deserializer<'de>,
{
    let opt: Option<String> = Option::deserialize(deserializer)?;

    match opt {
        None => Ok(None),
        Some(s) if s.trim().is_empty() => Ok(None),
        Some(s) => {
            let cidr = Ipv4Cidr::from_str(s.as_str()).map_err(serde::de::Error::custom)?;
            Ok(Some(cidr))
        }
    }
}
#[cfg(target_os = "linux")]
pub fn deserialize_ipv6_cidr<'de, D>(deserializer: D) -> Result<Option<Ipv6Cidr>, D::Error>
where
    D: Deserializer<'de>,
{
    let opt: Option<String> = Option::deserialize(deserializer)?;

    match opt {
        None => Ok(None),
        Some(s) if s.trim().is_empty() => Ok(None),
        Some(s) => {
            let cidr = Ipv6Cidr::from_str(s.as_str()).map_err(serde::de::Error::custom)?;
            Ok(Some(cidr))
        }
    }
}
