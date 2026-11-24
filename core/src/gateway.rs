// SPDX-License-Identifier: MIT
//! Short IPv4 UDP mappings on the physical gateway. Control traffic uses
//! its own bound socket; the mapping points to the active tunnel socket.
use std::{
    io,
    net::{Ipv4Addr, SocketAddrV4},
    sync::Arc,
    time::Duration,
};

use ring::rand::{SecureRandom, SystemRandom};
use tokio::net::UdpSocket;
use tokio::time::{Instant, timeout};

const LIFETIME: u32 = 120;
const GATEWAY_PORT: u16 = 5351;
const TIMEOUTS: [Duration; 2] = [Duration::from_millis(250), Duration::from_millis(500)];

pub struct Gateway {
    address: SocketAddrV4,
    bind: Arc<dyn Fn(i32) -> io::Result<()> + Send + Sync>,
}

impl Gateway {
    pub fn new(
        address: Ipv4Addr,
        bind: impl Fn(i32) -> io::Result<()> + Send + Sync + 'static,
    ) -> Self {
        Self {
            address: SocketAddrV4::new(address, GATEWAY_PORT),
            bind: Arc::new(bind),
        }
    }

    #[cfg(unix)]
    fn connect(&self) -> io::Result<(UdpSocket, std::net::UdpSocket, Ipv4Addr)> {
        use std::os::fd::AsRawFd;
        let socket = std::net::UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0))?;
        (self.bind)(socket.as_raw_fd())?;
        socket.connect(self.address)?;
        let std::net::IpAddr::V4(source) = socket.local_addr()?.ip() else {
            return Err(io::ErrorKind::InvalidInput.into());
        };
        socket.set_nonblocking(true)?;
        Ok((UdpSocket::from_std(socket.try_clone()?)?, socket, source))
    }

    #[cfg(not(unix))]
    fn connect(&self) -> io::Result<(UdpSocket, std::net::UdpSocket, Ipv4Addr)> {
        Err(io::ErrorKind::Unsupported.into())
    }

    pub(crate) async fn map(&self, port: u16, public_ip: Ipv4Addr) -> io::Result<Lease> {
        let (socket, cleanup, source) = self.connect()?;
        let mut nonce = [0; 12];
        SystemRandom::new()
            .fill(&mut nonce)
            .map_err(|_| io::Error::other("PCP nonce"))?;
        let mut lease = Lease {
            socket,
            cleanup,
            source,
            public_ip,
            port,
            nonce,
            protocol: Protocol::Pcp,
            endpoint: None,
            expires: Instant::now(),
        };
        if lease.renew().await.is_ok() {
            return Ok(lease);
        }
        if lease.endpoint.is_some() {
            // The router answered, but mapped a different WAN address.
            // Let Drop release that PCP mapping before trying anything else.
            return Err(io::Error::other("unusable PCP WAN address"));
        }

        lease.protocol = Protocol::NatPmp;
        lease.renew().await?;
        Ok(lease)
    }
}

#[derive(Clone, Copy)]
enum Protocol {
    Pcp,
    NatPmp,
}

pub(crate) struct Lease {
    socket: UdpSocket,
    cleanup: std::net::UdpSocket,
    source: Ipv4Addr,
    public_ip: Ipv4Addr,
    port: u16,
    nonce: [u8; 12],
    protocol: Protocol,
    endpoint: Option<SocketAddrV4>,
    expires: Instant,
}

impl Lease {
    pub fn renew_after(&self) -> Duration {
        self.expires.saturating_duration_since(Instant::now()) / 2
    }

    pub fn advertised(&self) -> Option<(u16, u32)> {
        let remaining = self
            .expires
            .saturating_duration_since(Instant::now())
            .as_millis();
        (remaining > 0).then_some((
            self.endpoint?.port(),
            remaining.min(u32::MAX as u128) as u32,
        ))
    }

    pub async fn renew(&mut self) -> io::Result<()> {
        let request = self.request(LIFETIME);
        let (endpoint, lifetime) = match self.protocol {
            Protocol::Pcp => {
                let reply = exchange(&self.socket, &request, [2, 129]).await?;
                if reply.len() < 60 || reply[3] != 0 || reply[24..42] != request[24..42] {
                    return Err(io::Error::other("PCP MAP rejected or mismatched"));
                }
                let address =
                    std::net::Ipv6Addr::from(<[u8; 16]>::try_from(&reply[44..60]).unwrap());
                let lifetime = u32::from_be_bytes(reply[4..8].try_into().unwrap());
                let port = u16::from_be_bytes(reply[42..44].try_into().unwrap());
                let ip = address
                    .to_ipv4_mapped()
                    .ok_or_else(|| io::Error::other("PCP did not return IPv4"))?;
                (SocketAddrV4::new(ip, port), lifetime)
            }
            Protocol::NatPmp => {
                // NAT-PMP reports the WAN address independently of the lease.
                let address = exchange(&self.socket, &[0, 0], [0, 128]).await?;
                if address.len() != 12
                    || address[2..4] != [0, 0]
                    || address[8..12] != self.public_ip.octets()
                {
                    return Err(io::Error::other(
                        "NAT-PMP address differs from the Supernode observation",
                    ));
                }
                let reply = exchange(&self.socket, &request, [0, 129]).await?;
                if reply.len() != 16 || reply[2..4] != [0, 0] || reply[8..10] != request[4..6] {
                    return Err(io::Error::other("NAT-PMP mapping rejected or mismatched"));
                }
                let port = u16::from_be_bytes(reply[10..12].try_into().unwrap());
                let lifetime = u32::from_be_bytes(reply[12..16].try_into().unwrap());
                (SocketAddrV4::new(self.public_ip, port), lifetime)
            }
        };
        if endpoint.port() == 0 || lifetime == 0 {
            return Err(io::Error::other("gateway did not grant a UDP lease"));
        }
        self.endpoint = Some(endpoint);
        self.expires = Instant::now() + Duration::from_secs(u64::from(lifetime));
        if *endpoint.ip() != self.public_ip {
            return Err(io::Error::other(
                "PCP address differs from the Supernode observation",
            ));
        }
        Ok(())
    }

    fn request(&self, lifetime: u32) -> Vec<u8> {
        let suggested_port = self.endpoint.map_or(self.port, |addr| addr.port());
        match self.protocol {
            Protocol::Pcp => {
                let mut request = vec![0; 60];
                request[..2].copy_from_slice(&[2, 1]);
                request[4..8].copy_from_slice(&lifetime.to_be_bytes());
                request[8..24].copy_from_slice(&self.source.to_ipv6_mapped().octets());
                request[24..36].copy_from_slice(&self.nonce);
                request[36] = 17; // UDP
                request[40..42].copy_from_slice(&self.port.to_be_bytes());
                request[42..44].copy_from_slice(&suggested_port.to_be_bytes());
                let address = self
                    .endpoint
                    .map_or(Ipv4Addr::UNSPECIFIED, |endpoint| *endpoint.ip());
                request[44..60].copy_from_slice(&address.to_ipv6_mapped().octets());
                request
            }
            Protocol::NatPmp => {
                let mut request = vec![0; 12];
                request[1] = 1; // Map UDP
                request[4..6].copy_from_slice(&self.port.to_be_bytes());
                if lifetime != 0 {
                    request[6..8].copy_from_slice(&suggested_port.to_be_bytes());
                }
                request[8..12].copy_from_slice(&lifetime.to_be_bytes());
                request
            }
        }
    }
}

impl Drop for Lease {
    fn drop(&mut self) {
        if self.endpoint.is_some() {
            // Best effort when a transport is cancelled. The gateway also
            // expires the lease if a departed network cannot be reached.
            let _ = self.cleanup.send(&self.request(0));
        }
    }
}

async fn exchange(socket: &UdpSocket, request: &[u8], prefix: [u8; 2]) -> io::Result<Vec<u8>> {
    let mut reply = [0; 256];
    for wait in TIMEOUTS {
        socket.send(request).await?;
        if let Ok(result) = timeout(wait, async {
            loop {
                let len = socket.recv(&mut reply).await?;
                if reply[..len].starts_with(&prefix) {
                    return Ok(reply[..len].to_vec());
                }
            }
        })
        .await
        {
            return result;
        }
    }
    Err(io::ErrorKind::TimedOut.into())
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;

    #[tokio::test]
    async fn pcp_lease() {
        let server = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let std::net::SocketAddr::V4(address) = server.local_addr().unwrap() else {
            unreachable!()
        };
        let gateway = Gateway {
            address,
            bind: Arc::new(|_| Ok(())),
        };
        let public_ip = Ipv4Addr::new(192, 0, 2, 7);
        let router = tokio::spawn(async move {
            let mut nonce = [0; 12];
            for (lifetime, suggested) in [(LIFETIME, 30000u16), (LIFETIME, 40000), (0, 40000)] {
                let mut request = [0; 60];
                let (size, from) = server.recv_from(&mut request).await.unwrap();
                assert_eq!(size, 60);
                assert_eq!(request[..2], [2, 1]);
                assert_eq!(request[4..8], lifetime.to_be_bytes());
                assert_eq!(request[40..42], 30000u16.to_be_bytes());
                assert_eq!(request[42..44], suggested.to_be_bytes());
                if suggested == 30000 {
                    nonce.copy_from_slice(&request[24..36]);
                    assert_eq!(
                        request[44..60],
                        Ipv4Addr::UNSPECIFIED.to_ipv6_mapped().octets()
                    );
                } else {
                    assert_eq!(request[24..36], nonce);
                }
                if lifetime != 0 {
                    request[1] = 129;
                    request[42..44].copy_from_slice(&40000u16.to_be_bytes());
                    request[44..60].copy_from_slice(&public_ip.to_ipv6_mapped().octets());
                    server.send_to(&request, from).await.unwrap();
                }
            }
        });
        let mut lease = gateway.map(30000, public_ip).await.unwrap();
        assert_eq!(lease.advertised().unwrap().0, 40000);
        lease.renew().await.unwrap();
        drop(lease);
        timeout(Duration::from_secs(2), router)
            .await
            .unwrap()
            .unwrap();
    }

    #[tokio::test]
    async fn nat_pmp_fallback() {
        let server = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let std::net::SocketAddr::V4(address) = server.local_addr().unwrap() else {
            unreachable!()
        };
        let gateway = Gateway {
            address,
            bind: Arc::new(|_| Ok(())),
        };
        let public_ip = Ipv4Addr::new(192, 0, 2, 7);
        let router = tokio::spawn(async move {
            let mut request = [0; 60];
            let (_, from) = server.recv_from(&mut request).await.unwrap();
            assert_eq!(request[..2], [2, 1]);
            let mut unsupported = [0; 24];
            unsupported[..4].copy_from_slice(&[2, 129, 0, 4]);
            server.send_to(&unsupported, from).await.unwrap();
            let (size, from) = server.recv_from(&mut request).await.unwrap();
            assert_eq!(&request[..size], &[0, 0]);
            let mut address = [0; 12];
            address[1] = 128;
            address[8..12].copy_from_slice(&public_ip.octets());
            server.send_to(&address, from).await.unwrap();
            let (size, from) = server.recv_from(&mut request).await.unwrap();
            assert_eq!(size, 12);
            assert_eq!(request[..2], [0, 1]);
            let mut mapped = [0; 16];
            mapped[1] = 129;
            mapped[8..10].copy_from_slice(&request[4..6]);
            mapped[10..12].copy_from_slice(&40000u16.to_be_bytes());
            mapped[12..16].copy_from_slice(&request[8..12]);
            server.send_to(&mapped, from).await.unwrap();
            let (size, _) = server.recv_from(&mut request).await.unwrap();
            assert_eq!(size, 12);
            assert_eq!(request[4..6], 30000u16.to_be_bytes());
            assert_eq!(request[6..12], [0; 6]);
        });
        let lease = gateway.map(30000, public_ip).await.unwrap();
        assert_eq!(lease.advertised().unwrap().0, 40000);
        drop(lease);
        timeout(Duration::from_secs(2), router)
            .await
            .unwrap()
            .unwrap();
    }
}
