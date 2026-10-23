// SPDX-License-Identifier: MIT
use crate::config::EdgeConfig;
use crate::interface::FamilyExits;
use crate::storage::SimpleFileStorage;
use std::io::Write;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::Duration;
use tracing::{debug, info, warn};
use vault_core::client::{ClientCallbacks, ClientConfig, ClientSession, TrafficStats};
use vault_core::device::{self, Ipv4, Ipv6, TunTapDevice};
use vault_core::{Buffer, PeerId};

/// Thin platform adapter over `vault_core::client::ClientSession`.
///
/// The session owns the UDP socket, handshake, heartbeat, reconnect and
/// traffic statistics; this type only bridges the session to the local TUN
/// device and the platform callbacks (route/DNS setup and rollback).
pub struct Edge {
    session: Arc<ClientSession>,
    configuration_error: Arc<Mutex<Option<String>>>,
    stop: Arc<AtomicBool>,
    reader: Option<JoinHandle<()>>,
}

impl Edge {
    pub fn new<F>(
        config: EdgeConfig,
        exits: Arc<Mutex<FamilyExits>>,
        hosts: Vec<SocketAddr>,
        on_ip_assigned: F,
    ) -> anyhow::Result<Self>
    where
        F: Fn(
                &FamilyExits,
                &TunTapDevice,
                &[SocketAddr],
                Option<&Ipv4>,
                Option<&Ipv6>,
            ) -> anyhow::Result<()>
            + Send
            + Sync
            + 'static,
    {
        // Load or generate the persistent device id. A corrupt storage file
        // is a hard error: silently regenerating the id would lose the IP
        // lease the server assigned to it.
        let storage = SimpleFileStorage::new(config.get_storage())?;
        let mut id_bytes = match storage.get("id")? {
            Some(s) => hex::decode(&s).map_err(|e| {
                anyhow::anyhow!("invalid device id in {}: {}", config.get_storage(), e)
            })?,
            None => vec![],
        };
        if id_bytes.is_empty() {
            id_bytes = PeerId::default().0.to_vec();
            storage.store("id", hex::encode(&id_bytes))?;
        }
        let id = PeerId(
            id_bytes
                .try_into()
                .map_err(|_| anyhow::anyhow!("Invalid id length"))?,
        );

        let device = Arc::new(device::setup_device(
            config.get_iface(),
            &device::DeviceType::Tun,
        )?);

        // The TUN fd stays in blocking mode: the reader thread sleeps in the
        // kernel until a packet arrives instead of polling a non-blocking fd.

        // Pass every resolved server address as an IP literal so the session
        // races them Happy-Eyeballs style and each one matches an installed
        // host route.
        let device_name = std::fs::read_to_string("/proc/sys/kernel/hostname")
            .map(|s| s.trim().to_string())
            .unwrap_or_default();
        let client_config = ClientConfig {
            password: config.get_password().to_string(),
            hosts: hosts.iter().map(|addr| addr.ip().to_string()).collect(),
            port: config.get_port(),
            id,
            device_name,
            platform: "linux".to_string(),
            socket_protect: None,
        };

        let configuration_error = Arc::new(Mutex::new(None));
        let callbacks = Arc::new(EdgeCallbacks {
            configured: AtomicBool::new(false),
            configuration_error: configuration_error.clone(),
            device: device.clone(),
            exits,
            hosts,
            on_ip_assigned,
        });

        let session = Arc::new(ClientSession::start(client_config, callbacks)?);

        // Uplink pump: TUN -> session. The read blocks in the kernel until a
        // packet arrives, so there is no busy loop. Packets read while the
        // session is reconnecting are dropped (UDP semantics).
        let stop = Arc::new(AtomicBool::new(false));
        let reader = {
            let device = device.clone();
            let session = session.clone();
            let stop = stop.clone();
            std::thread::Builder::new()
                .name("tun-reader".to_string())
                .spawn(move || {
                    let mut buffer = Buffer::new(0);
                    while !stop.load(Ordering::Relaxed) {
                        match device.read(&mut buffer) {
                            Ok(len) if len > 0 => {
                                if let Err(e) = session.write_packet(buffer.as_ref().to_vec()) {
                                    debug!("Uplink packet dropped, session not connected: {}", e);
                                }
                            }
                            Ok(_) => {}
                            Err(e) => {
                                debug!("TUN read failed: {}", e);
                                std::thread::sleep(Duration::from_millis(10));
                            }
                        }
                    }
                })?
        };

        Ok(Self {
            session,
            configuration_error,
            stop,
            reader: Some(reader),
        })
    }

    pub fn configuration_error(&self) -> Option<String> {
        self.configuration_error
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }

    pub fn traffic_stats(&self) -> TrafficStats {
        self.session.traffic_stats()
    }

    pub fn is_active(&self) -> bool {
        self.session.is_active()
    }

    pub fn reconnect(&self) -> anyhow::Result<()> {
        self.session.reconnect()?;
        Ok(())
    }

    pub fn shutdown(&mut self) {
        info!("Shutting down session...");
        self.stop.store(true, Ordering::Relaxed);
        // The reader thread may be parked in a blocking read(); detach it —
        // process exit reaps it.
        let _ = self.reader.take();
        if let Err(e) = self.session.shutdown() {
            warn!("Session shutdown failed: {}", e);
        }
    }
}

impl Drop for Edge {
    fn drop(&mut self) {
        self.shutdown();
    }
}

/// Bridges session events to the TUN device and the platform route/DNS setup.
/// Fires on the session's worker threads: must stay cheap and non-blocking.
struct EdgeCallbacks<F> {
    configured: AtomicBool,
    configuration_error: Arc<Mutex<Option<String>>>,
    device: Arc<TunTapDevice>,
    exits: Arc<Mutex<FamilyExits>>,
    hosts: Vec<SocketAddr>,
    on_ip_assigned: F,
}

impl<F> ClientCallbacks for EdgeCallbacks<F>
where
    F: Fn(
            &FamilyExits,
            &TunTapDevice,
            &[SocketAddr],
            Option<&Ipv4>,
            Option<&Ipv6>,
        ) -> anyhow::Result<()>
        + Send
        + Sync,
{
    fn on_packets(&self, packets: Vec<Vec<u8>>) {
        let mut buffer = Buffer::new(0);
        for packet in packets {
            buffer.clear();
            if buffer.write_all(&packet).is_err() {
                continue;
            }
            if let Err(e) = self.device.write(&mut buffer) {
                // The edge TUN fd is blocking, so a full queue blocks here
                // instead of erroring; if write still fails, drop the packet
                // (UDP semantics).
                debug!("Failed to write packet to TUN: {}", e);
            }
        }
    }

    fn on_ip_assigned(
        &self,
        ipv4: String,
        ipv4_mask: String,
        ipv6: String,
        ipv6_prefixlen: i32,
    ) -> Result<(), String> {
        let result = (|| -> anyhow::Result<()> {
            let ipv4 = if ipv4.is_empty() && ipv4_mask.is_empty() {
                None
            } else {
                Some(Ipv4 {
                    ip: ipv4.parse::<Ipv4Addr>()?,
                    netmask: ipv4_mask.parse::<Ipv4Addr>()?,
                })
            };
            let ipv6 = if ipv6.is_empty() {
                None
            } else {
                anyhow::ensure!(
                    (0..=128).contains(&ipv6_prefixlen),
                    "invalid IPv6 prefix: {}",
                    ipv6_prefixlen
                );
                Some(Ipv6 {
                    ip: ipv6.parse::<Ipv6Addr>()?,
                    prefix_len: ipv6_prefixlen as u8,
                })
            };
            anyhow::ensure!(
                ipv4.is_some() || ipv6.is_some(),
                "no valid tunnel address assigned"
            );
            let exits = self
                .exits
                .lock()
                .map_err(|_| anyhow::anyhow!("exits lock poisoned"))?;
            (self.on_ip_assigned)(
                &exits,
                &self.device,
                &self.hosts,
                ipv4.as_ref(),
                ipv6.as_ref(),
            )
        })();
        match result {
            Ok(()) => {
                self.configured.store(true, Ordering::Relaxed);
                Ok(())
            }
            Err(e) => {
                let error = format!("{e:#}");
                // Startup configuration failures remain fatal. Once running,
                // a disappearing interface during a switch is retryable.
                if !self.configured.load(Ordering::Relaxed) {
                    *self
                        .configuration_error
                        .lock()
                        .unwrap_or_else(|e| e.into_inner()) = Some(error.clone());
                }
                Err(error)
            }
        }
    }

    fn on_error(&self, error: String) {
        warn!("Session error: {}", error);
    }
}
