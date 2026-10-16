// SPDX-License-Identifier: MIT
// Server CLI entry (daemonize/privdrop); not applicable on iOS clients.
#[cfg(not(target_os = "ios"))]
mod app;
mod buf;
#[cfg(feature = "client")]
pub mod client;
mod crypto;
// TUN device and epoll are server-side (Linux/Android) only.
#[cfg(any(target_os = "linux", target_os = "android"))]
pub mod device;
#[cfg(any(target_os = "linux", target_os = "android"))]
mod epoll;
// Rolling-file tracing logger shared by the server and edge binaries;
// excluded on iOS where only the client feature is used.
#[cfg(not(target_os = "ios"))]
pub mod logger;
pub mod pake;
mod peer;
pub mod protocol;
mod signal;
#[cfg(feature = "test")]
pub mod test_utils;
pub mod util;

#[cfg(not(target_os = "ios"))]
pub use app::PrivDropRequest;
#[cfg(not(target_os = "ios"))]
pub use app::app_main;
pub use buf::Buffer;
pub use crypto::CryptoCore;
pub use crypto::Role;
pub use crypto::create_ecdh_keypair;
pub use crypto::fill_random;
pub use crypto::select_algorithm;
pub use crypto::supported_algorithms;
#[cfg(any(target_os = "linux", target_os = "android"))]
pub use epoll::EpollWait as WaitImpl;
#[cfg(any(target_os = "linux", target_os = "android"))]
pub use epoll::WaitResult;
pub use peer::Peer;
pub use peer::PeerId;
pub use peer::Peers;
pub use peer::PendingPeer;
use ring::aead::AES_128_GCM;
use ring::aead::AES_256_GCM;
use ring::aead::CHACHA20_POLY1305;
pub use signal::SysSignal;

/// Wire protocol version carried in handshake requests; the supernode
/// rejects anything else.
pub const PROTOCOL_VERSION: u32 = 1;

pub const TAG_LEN: usize = 16;
pub const EXTRA_LEN: usize = 8;

mod pb {
    include!(concat!(env!("OUT_DIR"), "/protocol.rs"));
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AlgorithmType {
    Aes128Gcm,
    Aes256Gcm,
    Chacha20Poly1305,
}

impl AlgorithmType {
    pub fn code(&self) -> i32 {
        match self {
            AlgorithmType::Aes128Gcm => 0,
            AlgorithmType::Aes256Gcm => 1,
            AlgorithmType::Chacha20Poly1305 => 2,
        }
    }
}

impl From<&AlgorithmType> for &ring::aead::Algorithm {
    fn from(value: &AlgorithmType) -> Self {
        match value {
            AlgorithmType::Aes128Gcm => &AES_128_GCM,
            AlgorithmType::Aes256Gcm => &AES_256_GCM,
            AlgorithmType::Chacha20Poly1305 => &CHACHA20_POLY1305,
        }
    }
}

impl TryFrom<i32> for AlgorithmType {
    type Error = anyhow::Error;

    fn try_from(value: i32) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(AlgorithmType::Aes128Gcm),
            1 => Ok(AlgorithmType::Aes256Gcm),
            2 => Ok(AlgorithmType::Chacha20Poly1305),
            _ => Err(anyhow::anyhow!("AlgorithmType not {} supported", value)),
        }
    }
}

impl TryFrom<&pb::Algorithm> for Algorithm {
    type Error = anyhow::Error;

    fn try_from(value: &pb::Algorithm) -> Result<Self, Self::Error> {
        Ok(Algorithm {
            algorithm_type: value.algorithm_type.try_into()?,
            speed: value.speed as f64,
        })
    }
}

impl TryFrom<&Algorithm> for pb::Algorithm {
    type Error = anyhow::Error;

    fn try_from(value: &Algorithm) -> Result<Self, Self::Error> {
        Ok(pb::Algorithm {
            algorithm_type: value.algorithm_type.code(),
            speed: value.speed as f32,
        })
    }
}

#[derive(Debug, Clone, Copy)]
pub struct Algorithm {
    pub algorithm_type: AlgorithmType,
    pub speed: f64,
}

pub enum Handshake {
    Request(HandshakeRequest),
    Response(HandshakeResponse),
}

pub struct HandshakeRequest {
    pub id: PeerId,
    pub pake_message: Vec<u8>,
    pub public_key_data: Vec<u8>,
    pub algorithms: Vec<Algorithm>,
    pub timestamp: Time,
    pub version: u32,
    pub device_name: String,
    pub platform: String,
}

pub struct HandshakeResponse {
    pub id: PeerId,
    pub pake_message: Vec<u8>,
    pub public_key_data: Vec<u8>,
    pub algorithm: Algorithm,
    pub ipv4: String,
    pub ipv4_mask: String,
    pub ipv6: String,
    pub ipv6_prefixlen: i32,
    pub timestamp: Time,
    pub request_public_key: Vec<u8>,
    pub confirm_mac: Vec<u8>,
}

pub struct Ping {
    pub ts: i64,
}

pub struct Pong {
    pub ts: i64,
}

impl TryFrom<pb::HandshakeRequest> for HandshakeRequest {
    type Error = anyhow::Error;

    fn try_from(value: pb::HandshakeRequest) -> Result<Self, Self::Error> {
        let mut algos = vec![];
        for a in &value.algorithms {
            algos.push(a.try_into()?);
        }
        // X25519 keys are 32 bytes; a wrong length panics in agree_ephemeral.
        if value.public_key_data.len() != 32 {
            anyhow::bail!("invalid public key length: {}", value.public_key_data.len());
        }

        Ok(HandshakeRequest {
            id: value.id.try_into()?,
            pake_message: value.pake_message,
            public_key_data: value.public_key_data,
            algorithms: algos,
            timestamp: value.timestamp,
            version: value.version,
            device_name: value.device_name,
            platform: value.platform,
        })
    }
}

impl TryFrom<pb::HandshakeResponse> for HandshakeResponse {
    type Error = anyhow::Error;

    fn try_from(value: pb::HandshakeResponse) -> Result<Self, Self::Error> {
        // X25519 keys are 32 bytes; a wrong length panics in agree_ephemeral.
        if value.public_key_data.len() != 32 {
            anyhow::bail!("invalid public key length: {}", value.public_key_data.len());
        }
        Ok(HandshakeResponse {
            id: value.id.try_into()?,
            pake_message: value.pake_message,
            public_key_data: value.public_key_data,
            algorithm: value
                .algorithm
                .as_ref()
                .ok_or(anyhow::anyhow!("algorithm is not exist."))?
                .try_into()?,
            ipv4: value.ipv4,
            ipv4_mask: value.ipv4_mask,
            ipv6: value.ipv6,
            ipv6_prefixlen: value.ipv6_prefixlen,
            timestamp: value.timestamp,
            request_public_key: value.request_public_key,
            confirm_mac: value.confirm_mac,
        })
    }
}

#[macro_export]
macro_rules! fail {
    ($format:expr) => ( {
        use std::process;
        tracing::error!($format);
        process::exit(-1);
    } );
    ($format:expr, $( $arg:expr ),+) => ( {
        use std::process;
        tracing::error!($format, $( $arg ),+ );
        process::exit(-1);
    } );
}

#[macro_export]
macro_rules! try_fail {
    ($val:expr, $format:expr) => ( {
        match $val {
            Ok(val) => val,
            Err(err) => $crate::fail!($format, err)
        }
    } );
    ($val:expr, $format:expr, $( $arg:expr ),+) => ( {
        match $val {
            Ok(val) => val,
            Err(err) => $crate::fail!($format, $( $arg ),+, err)
        }
    } );
}

pub type Time = i64;
pub trait TimeSource: Default + Sync + Copy + Send + 'static {
    fn now() -> Time;
}

#[derive(Default, Clone, Copy)]
pub struct SystemTimeSource;

impl TimeSource for SystemTimeSource {
    fn now() -> Time {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            // A clock set before the epoch yields 0 instead of panicking.
            .map_or(0, |d| d.as_secs() as i64)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn handshake_request(public_key_len: usize) -> pb::HandshakeRequest {
        pb::HandshakeRequest {
            id: vec![1u8; 16],
            pake_message: vec![0u8; 33],
            public_key_data: vec![0u8; public_key_len],
            algorithms: vec![],
            timestamp: 0,
            version: 0,
            device_name: String::new(),
            platform: String::new(),
        }
    }

    #[test]
    fn handshake_request_rejects_bad_public_key_length() {
        assert!(HandshakeRequest::try_from(handshake_request(0)).is_err());
        assert!(HandshakeRequest::try_from(handshake_request(16)).is_err());
        assert!(HandshakeRequest::try_from(handshake_request(32)).is_ok());
    }

    #[test]
    fn handshake_response_rejects_bad_public_key_length() {
        let response = pb::HandshakeResponse {
            id: vec![1u8; 16],
            pake_message: vec![0u8; 33],
            public_key_data: vec![0u8; 16],
            algorithm: Some(pb::Algorithm {
                algorithm_type: 0,
                speed: 1.0,
            }),
            ipv4: String::new(),
            ipv4_mask: String::new(),
            ipv6: String::new(),
            ipv6_prefixlen: 0,
            timestamp: 0,
            request_public_key: vec![],
            confirm_mac: vec![],
        };
        assert!(HandshakeResponse::try_from(response).is_err());
    }
}
