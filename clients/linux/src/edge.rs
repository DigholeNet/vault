// SPDX-License-Identifier: MIT
use crate::config::EdgeConfig;
use crate::storage::SimpleFileStorage;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, mpsc::Sender};
use std::thread::JoinHandle;
use std::time::Duration;
use tracing::{debug, info, warn};
use vault_core::client::{ClientCallbacks, ClientConfig, ClientSession, TrafficStats, TunnelSetup};
use vault_core::device::TunTapDevice;
use vault_core::settings::TunnelAssignment;
use vault_core::{Buffer, PeerId};

pub type Assignment = (TunnelAssignment, Arc<TunnelSetup>);

/// Thin platform adapter over `vault_core::client::ClientSession`.
///
/// The session owns the UDP socket, handshake, heartbeat, reconnect and
/// traffic statistics; this type only bridges the session to the local TUN
/// device and the platform callbacks (route/DNS setup and rollback).
pub struct Edge {
    session: Arc<ClientSession>,
    stop: Arc<AtomicBool>,
    reader: Option<JoinHandle<()>>,
}

impl Edge {
    pub fn new(
        config: &EdgeConfig,
        device: Arc<TunTapDevice>,
        hosts: &[SocketAddr],
        assignments: Sender<Assignment>,
    ) -> anyhow::Result<Self> {
        // Load or generate the persistent device id. A corrupt storage file
        // is a hard error: silently regenerating the id would lose the IP
        // lease the server assigned to it.
        let storage = SimpleFileStorage::new(config.get_storage())?;
        let id = match storage.get("id")? {
            Some(saved) if !saved.is_empty() => saved.parse::<PeerId>().map_err(|error| {
                anyhow::anyhow!("invalid device id in {}: {}", config.get_storage(), error)
            })?,
            _ => {
                let id = PeerId::default();
                storage.store("id", id.to_string())?;
                id
            }
        };

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

        let callbacks = Arc::new(EdgeCallbacks {
            device: device.clone(),
            assignments,
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
            stop,
            reader: Some(reader),
        })
    }

    pub fn traffic_stats(&self) -> TrafficStats {
        self.session.traffic_stats()
    }

    pub fn connection_status(&self) -> vault_core::client::ConnectionStatus {
        self.session.connection_status()
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

/// Bridges session events to the TUN and forwards setup requests to the runner.
struct EdgeCallbacks {
    device: Arc<TunTapDevice>,
    assignments: Sender<Assignment>,
}

impl ClientCallbacks for EdgeCallbacks {
    fn on_packets(&self, packets: Vec<Vec<u8>>) {
        for packet in packets {
            if let Err(e) = self.device.write(&packet) {
                // The edge TUN fd is blocking, so a full queue blocks here
                // instead of erroring; if write still fails, drop the packet
                // (UDP semantics).
                debug!("Failed to write packet to TUN: {}", e);
            }
        }
    }

    fn on_ip_assigned(&self, assignment: TunnelAssignment, setup: Arc<TunnelSetup>) {
        let _ = self.assignments.send((assignment, setup));
    }

    fn on_error(&self, error: String) {
        warn!("Session error: {}", error);
    }
}
