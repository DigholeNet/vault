// SPDX-License-Identifier: MIT
//! Synchronous diagnostic networking: standard sockets, rustls and explicit
//! deadlines. No async runtime is needed for a serial diagnostic run.

use super::{ErrorKind, Failure, Observation, Operation, default_routes, wire};
use socket2::{Domain, Protocol, Socket, Type};
use std::io::{self, Read, Write};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpStream, ToSocketAddrs, UdpSocket};
use std::os::fd::AsRawFd;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};

#[derive(Default)]
pub struct Cancellation(AtomicBool);
impl Cancellation {
    pub fn cancel(&self) {
        self.0.store(true, Ordering::Release);
    }
    pub fn is_cancelled(&self) -> bool {
        self.0.load(Ordering::Acquire)
    }
}

struct Context<'a> {
    deadline: Instant,
    cancellation: &'a Cancellation,
}
impl Context<'_> {
    fn remaining(&self) -> io::Result<Duration> {
        if self.cancellation.is_cancelled() {
            return Err(io::Error::new(
                io::ErrorKind::Interrupted,
                "diagnostic cancelled",
            ));
        }
        self.deadline
            .checked_duration_since(Instant::now())
            .filter(|d| !d.is_zero())
            .ok_or_else(|| io::Error::new(io::ErrorKind::TimedOut, "probe deadline exceeded"))
    }
    fn slice(&self) -> io::Result<Duration> {
        Ok(self.remaining()?.min(Duration::from_millis(50)))
    }
}

pub fn execute(
    operation: &Operation,
    domain: &str,
    budget: Duration,
    network: &dyn NetworkBinding,
    cancellation: &Cancellation,
) -> Observation {
    let context = Context {
        deadline: Instant::now() + budget.min(Duration::from_secs(60)),
        cancellation,
    };
    match perform(operation, domain, network, &context) {
        Ok(value) => value,
        Err(failure) => Observation::Failed(failure),
    }
}

fn error(kind: ErrorKind, value: impl std::fmt::Display) -> Failure {
    Failure {
        kind,
        detail: value.to_string(),
    }
}
fn io_error(kind: ErrorKind, value: io::Error) -> Failure {
    let kind = match value.kind() {
        io::ErrorKind::PermissionDenied => ErrorKind::Permission,
        io::ErrorKind::TimedOut => ErrorKind::Timeout,
        io::ErrorKind::Interrupted => ErrorKind::Unavailable,
        _ => kind,
    };
    error(kind, value)
}
fn retry(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
    )
}

/// Platform socket binding supplied by the bridge; core owns the borrowed fd.
pub trait NetworkBinding: Send + Sync {
    fn bind(&self, fd: i32, ipv6: bool) -> io::Result<()>;
}

#[derive(Default)]
pub struct DefaultNetwork;
impl NetworkBinding for DefaultNetwork {
    fn bind(&self, _: i32, _: bool) -> io::Result<()> {
        Ok(())
    }
}

fn perform(
    operation: &Operation,
    domain: &str,
    network: &dyn NetworkBinding,
    context: &Context<'_>,
) -> Result<Observation, Failure> {
    context
        .remaining()
        .map_err(|e| io_error(ErrorKind::Unavailable, e))?;
    match operation {
        Operation::Route => {
            let routes = default_routes();
            Ok(Observation::Route {
                ipv4: routes.ipv4,
                ipv6: routes.ipv6,
            })
        }
        Operation::Dns { server, ipv6 } => dns(
            SocketAddr::new(*server, 53),
            domain,
            *ipv6,
            network,
            context,
        ),
        Operation::Tcp { address, port } => {
            tcp(SocketAddr::new(*address, *port), network, context)?;
            Ok(Observation::Tcp)
        }
        Operation::Https { address, port } => {
            https(domain, *address, *port, network, context, tls_config()?)
        }
        Operation::Ping {
            address,
            sequence,
            packet_size,
        } => ping(*address, *sequence, *packet_size, network, context),
    }
}

fn tcp(
    address: SocketAddr,
    network: &dyn NetworkBinding,
    context: &Context<'_>,
) -> Result<TcpStream, Failure> {
    let connect = || -> io::Result<TcpStream> {
        let socket = Socket::new(
            Domain::for_address(address),
            Type::STREAM,
            Some(Protocol::TCP),
        )?;
        network.bind(socket.as_raw_fd(), address.is_ipv6())?;
        socket.set_nonblocking(true)?;
        if let Err(error) = socket.connect(&address.into()) {
            if error.raw_os_error() != Some(libc::EINPROGRESS)
                && error.kind() != io::ErrorKind::WouldBlock
            {
                return Err(error);
            }
            loop {
                let mut pfd = libc::pollfd {
                    fd: socket.as_raw_fd(),
                    events: libc::POLLOUT,
                    revents: 0,
                };
                let milliseconds = context.slice()?.as_millis().max(1) as i32;
                // SAFETY: pfd is a live pollfd and the socket owns its descriptor.
                let result = unsafe { libc::poll(&mut pfd, 1, milliseconds) };
                if result > 0 {
                    if let Some(error) = socket.take_error()? {
                        return Err(error);
                    }
                    break;
                }
                if result < 0 && io::Error::last_os_error().kind() != io::ErrorKind::Interrupted {
                    return Err(io::Error::last_os_error());
                }
            }
        }
        context.remaining()?;
        socket.set_nonblocking(false)?;
        Ok(socket.into())
    };
    connect().map_err(|e| io_error(ErrorKind::Connect, e))
}

fn datagram(
    address: IpAddr,
    protocol: Protocol,
    network: &dyn NetworkBinding,
) -> Result<UdpSocket, Failure> {
    let create = || -> io::Result<UdpSocket> {
        let socket = Socket::new(
            Domain::for_address(SocketAddr::new(address, 0)),
            Type::DGRAM,
            Some(protocol),
        )?;
        network.bind(socket.as_raw_fd(), address.is_ipv6())?;
        let bind = SocketAddr::new(
            if address.is_ipv4() {
                Ipv4Addr::UNSPECIFIED.into()
            } else {
                std::net::Ipv6Addr::UNSPECIFIED.into()
            },
            0,
        );
        socket.bind(&bind.into())?;
        Ok(socket.into())
    };
    create().map_err(|e| io_error(ErrorKind::Connect, e))
}

fn receive(socket: &UdpSocket, bytes: &mut [u8], context: &Context<'_>) -> io::Result<usize> {
    loop {
        socket.set_read_timeout(Some(context.slice()?))?;
        match socket.recv(bytes) {
            Err(e) if retry(&e) => continue,
            result => return result,
        }
    }
}

fn dns(
    server: SocketAddr,
    domain: &str,
    ipv6: bool,
    network: &dyn NetworkBinding,
    context: &Context<'_>,
) -> Result<Observation, Failure> {
    let mut id = [0; 2];
    ring::rand::SecureRandom::fill(&ring::rand::SystemRandom::new(), &mut id)
        .map_err(|_| error(ErrorKind::Dns, "DNS transaction RNG failed"))?;
    let id = u16::from_ne_bytes(id);
    let query =
        wire::dns_query(domain, id, ipv6).map_err(|e| error(ErrorKind::Dns, format!("{e:?}")))?;
    let socket = datagram(server.ip(), Protocol::UDP, network)?;
    socket
        .connect(server)
        .map_err(|e| io_error(ErrorKind::Dns, e))?;
    socket
        .set_write_timeout(Some(
            context.slice().map_err(|e| io_error(ErrorKind::Dns, e))?,
        ))
        .map_err(|e| io_error(ErrorKind::Dns, e))?;
    socket
        .send(&query)
        .map_err(|e| io_error(ErrorKind::Dns, e))?;
    let mut bytes = vec![0; 65535];
    let count = receive(&socket, &mut bytes, context).map_err(|e| io_error(ErrorKind::Dns, e))?;
    let addresses = wire::dns_answers(&bytes[..count], domain, id, ipv6)
        .map_err(|e| error(ErrorKind::Dns, format!("{e:?}")))?;
    Ok(Observation::Dns { addresses })
}

fn tls_config() -> Result<Arc<rustls::ClientConfig>, Failure> {
    static CONFIG: OnceLock<Arc<rustls::ClientConfig>> = OnceLock::new();
    if let Some(config) = CONFIG.get() {
        return Ok(config.clone());
    }
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut config = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|e| error(ErrorKind::Tls, e))?
        .with_root_certificates(rustls::RootCertStore::from_iter(
            webpki_roots::TLS_SERVER_ROOTS.iter().cloned(),
        ))
        .with_no_client_auth();
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    let config = Arc::new(config);
    Ok(CONFIG.get_or_init(|| config).clone())
}

/// Recompute the deadline for every socket read/write, including rustls I/O.
struct DeadlineTcp<'a, 'b> {
    stream: TcpStream,
    context: &'a Context<'b>,
}
impl Read for DeadlineTcp<'_, '_> {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        loop {
            self.stream.set_read_timeout(Some(self.context.slice()?))?;
            match self.stream.read(bytes) {
                Err(e) if retry(&e) => continue,
                result => return result,
            }
        }
    }
}
impl Write for DeadlineTcp<'_, '_> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        loop {
            self.stream.set_write_timeout(Some(self.context.slice()?))?;
            match self.stream.write(bytes) {
                Err(e) if retry(&e) => continue,
                result => return result,
            }
        }
    }
    fn flush(&mut self) -> io::Result<()> {
        self.context.remaining()?;
        self.stream.flush()
    }
}

fn resolve(domain: &str, port: u16, context: &Context<'_>) -> Result<Vec<SocketAddr>, Failure> {
    // OS resolver calls cannot be interrupted. Keep the caller cancellable and
    // bounded while the OS finishes its lookup on one short-lived thread.
    let (sender, receiver) = std::sync::mpsc::sync_channel(1);
    let domain = domain.to_owned();
    std::thread::spawn(move || {
        let _ = sender.send(
            (domain.as_str(), port)
                .to_socket_addrs()
                .map(|a| a.collect()),
        );
    });
    loop {
        match receiver.recv_timeout(context.slice().map_err(|e| io_error(ErrorKind::Dns, e))?) {
            Ok(result) => return result.map_err(|e| io_error(ErrorKind::Dns, e)),
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => continue,
            Err(_) => return Err(error(ErrorKind::Dns, "system resolver stopped")),
        }
    }
}

fn https(
    domain: &str,
    address: Option<IpAddr>,
    port: u16,
    network: &dyn NetworkBinding,
    context: &Context<'_>,
    config: Arc<rustls::ClientConfig>,
) -> Result<Observation, Failure> {
    let started = Instant::now();
    let request =
        wire::https_request(domain).map_err(|e| error(ErrorKind::Http, format!("{e:?}")))?;
    let addresses = if let Some(address) = address {
        vec![SocketAddr::new(address, port)]
    } else {
        resolve(domain, port, context)?
    };
    let mut last = error(ErrorKind::Connect, "no usable address");
    let mut stream = None;
    for address in addresses {
        match tcp(address, network, context) {
            Ok(connected) => {
                stream = Some(connected);
                break;
            }
            Err(e) => last = e,
        }
    }
    let stream = DeadlineTcp {
        stream: stream.ok_or(last)?,
        context,
    };
    let name = rustls::pki_types::ServerName::try_from(domain.to_owned())
        .map_err(|e| error(ErrorKind::Tls, e))?;
    let connection =
        rustls::ClientConnection::new(config, name).map_err(|e| error(ErrorKind::Tls, e))?;
    let mut tls = rustls::StreamOwned::new(connection, stream);
    while tls.conn.is_handshaking() {
        tls.conn
            .complete_io(&mut tls.sock)
            .map_err(|e| io_error(ErrorKind::Tls, e))?;
    }
    let tls_duration_ms = started.elapsed().as_millis() as u64;
    let certificate = tls
        .conn
        .peer_certificates()
        .and_then(|c| c.first())
        .map(|cert| {
            let digest = ring::digest::digest(&ring::digest::SHA256, cert.as_ref());
            format!(
                "leaf SHA256 {}",
                digest
                    .as_ref()
                    .iter()
                    .map(|b| format!("{b:02x}"))
                    .collect::<String>()
            )
        })
        .unwrap_or_default();
    tls.write_all(&request)
        .map_err(|e| io_error(ErrorKind::Http, e))?;
    tls.flush().map_err(|e| io_error(ErrorKind::Http, e))?;
    let mut bytes = vec![0; 65536];
    let mut count = 0;
    let mut eof = false;
    while count < bytes.len() {
        let n = tls
            .read(&mut bytes[count..])
            .map_err(|e| io_error(ErrorKind::Http, e))?;
        if n == 0 {
            eof = true;
            break;
        }
        count += n;
    }
    let status_line = wire::http_status(&bytes[..count], eof)
        .map_err(|e| error(ErrorKind::Http, format!("{e:?}")))?;
    Ok(Observation::Https {
        status_line,
        received_bytes: count as u32,
        tls_duration_ms,
        certificate,
    })
}

fn ping(
    address: IpAddr,
    sequence: u16,
    packet_size: u16,
    network: &dyn NetworkBinding,
    context: &Context<'_>,
) -> Result<Observation, Failure> {
    let header = if address.is_ipv6() { 40 } else { 20 };
    if packet_size < header + 8 {
        return Err(error(
            ErrorKind::InvalidResponse,
            "ICMP packet size too small",
        ));
    }
    let socket = datagram(
        address,
        if address.is_ipv6() {
            Protocol::ICMPV6
        } else {
            Protocol::ICMPV4
        },
        network,
    )?;
    #[cfg(target_vendor = "apple")]
    if address.is_ipv4() {
        let one: i32 = 1;
        // SAFETY: the option points to a live i32 and the socket owns the fd.
        if unsafe {
            libc::setsockopt(
                socket.as_raw_fd(),
                libc::IPPROTO_IP,
                libc::IP_DONTFRAG,
                (&one as *const i32).cast(),
                size_of::<i32>() as _,
            )
        } != 0
        {
            return Err(io_error(ErrorKind::Connect, io::Error::last_os_error()));
        }
    }
    let mut packet = vec![0; (packet_size - header) as usize];
    packet[0] = if address.is_ipv6() { 128 } else { 8 };
    packet[6..8].copy_from_slice(&sequence.to_be_bytes());
    for (i, byte) in packet[8..].iter_mut().enumerate() {
        *byte = (i % 251) as u8;
    }
    if address.is_ipv4() {
        let checksum = wire::icmp_checksum(&packet);
        packet[2..4].copy_from_slice(&checksum.to_be_bytes());
    }
    socket
        .connect(SocketAddr::new(address, 0))
        .map_err(|e| io_error(ErrorKind::Connect, e))?;
    socket
        .set_write_timeout(Some(
            context
                .slice()
                .map_err(|e| io_error(ErrorKind::Connect, e))?,
        ))
        .map_err(|e| io_error(ErrorKind::Connect, e))?;
    let start = Instant::now();
    socket
        .send(&packet)
        .map_err(|e| io_error(ErrorKind::Connect, e))?;
    let mut bytes = [0; 4096];
    loop {
        let count =
            receive(&socket, &mut bytes, context).map_err(|e| io_error(ErrorKind::Connect, e))?;
        if echo_reply(&bytes[..count], address.is_ipv6(), sequence) {
            return Ok(Observation::Ping {
                rtt_ms: start.elapsed().as_millis() as u64,
            });
        }
    }
}

pub fn echo_reply(bytes: &[u8], ipv6: bool, sequence: u16) -> bool {
    if bytes.len() < 8 {
        return false;
    }
    let offset = if !ipv6 && bytes[0] >> 4 == 4 {
        let offset = (bytes[0] & 15) as usize * 4;
        if offset < 20 {
            return false;
        }
        offset
    } else if ipv6 && bytes[0] >> 4 == 6 {
        40
    } else {
        0
    };
    bytes.get(offset..offset + 8).is_some_and(|header| {
        header[0] == if ipv6 { 129 } else { 0 }
            && header[1] == 0
            && header[6..8] == sequence.to_be_bytes()
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;

    fn context(cancellation: &Cancellation) -> Context<'_> {
        Context {
            deadline: Instant::now() + Duration::from_secs(2),
            cancellation,
        }
    }

    #[test]
    fn dns_udp() {
        let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        let server = socket.local_addr().unwrap();
        let worker = thread::spawn(move || {
            let mut query = [0; 512];
            let (count, peer) = socket.recv_from(&mut query).unwrap();
            let mut response = query[..count].to_vec();
            response[2] = 0x81;
            response[3] = 0x80;
            response[7] = 1;
            response.extend_from_slice(&[0xc0, 12, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 192, 0, 2, 1]);
            socket.send_to(&response, peer).unwrap();
        });
        let cancellation = Cancellation::default();
        let result = dns(
            server,
            "example.com",
            false,
            &DefaultNetwork,
            &context(&cancellation),
        )
        .unwrap();
        assert_eq!(
            result,
            Observation::Dns {
                addresses: vec!["192.0.2.1".parse().unwrap()]
            }
        );
        worker.join().unwrap();
    }

    #[test]
    fn udp_timeout() {
        let server = UdpSocket::bind("127.0.0.1:0").unwrap();
        let cancellation = Cancellation::default();
        let ctx = Context {
            deadline: Instant::now() + Duration::from_millis(100),
            cancellation: &cancellation,
        };
        let started = Instant::now();
        assert_eq!(
            dns(
                server.local_addr().unwrap(),
                "example.com",
                false,
                &DefaultNetwork,
                &ctx
            )
            .unwrap_err()
            .kind,
            ErrorKind::Timeout
        );
        assert!(started.elapsed() < Duration::from_secs(1));
    }

    #[test]
    fn udp_cancel() {
        let server = UdpSocket::bind("127.0.0.1:0").unwrap();
        let address = server.local_addr().unwrap();
        let cancellation = Arc::new(Cancellation::default());
        let cancel = cancellation.clone();
        let worker = thread::spawn(move || {
            let mut bytes = [0; 512];
            server.recv(&mut bytes).unwrap();
            cancel.cancel();
        });
        let start = Instant::now();
        let result = dns(
            address,
            "example.com",
            false,
            &DefaultNetwork,
            &context(&cancellation),
        );
        assert_eq!(result.unwrap_err().kind, ErrorKind::Unavailable);
        assert!(start.elapsed() < Duration::from_secs(1));
        worker.join().unwrap();
    }

    #[test]
    fn ping_loopback() {
        for address in ["127.0.0.1", "::1"] {
            let cancellation = Cancellation::default();
            let result = execute(
                &Operation::Ping {
                    address: address.parse().unwrap(),
                    sequence: 47,
                    packet_size: 64,
                },
                "",
                Duration::from_secs(1),
                &DefaultNetwork,
                &cancellation,
            );
            assert!(
                matches!(result, Observation::Ping { .. }),
                "{address}: {result:?}"
            );
        }
    }

    #[test]
    fn echo_matching() {
        for ipv6 in [false, true] {
            let packet = [if ipv6 { 129 } else { 0 }, 0, 0, 0, 0, 0, 0x12, 0x34];
            assert!(echo_reply(&packet, ipv6, 0x1234));
            assert!(!echo_reply(&packet, ipv6, 0x1235));
            let mut header = vec![0; if ipv6 { 40 } else { 20 }];
            header[0] = if ipv6 { 0x60 } else { 0x45 };
            header.extend_from_slice(&packet);
            assert!(echo_reply(&header, ipv6, 0x1234));
            assert!(!echo_reply(&header[..header.len() - 1], ipv6, 0x1234));
        }
    }
}
