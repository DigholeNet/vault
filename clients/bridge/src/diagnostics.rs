// SPDX-License-Identifier: MIT
//! Typed mobile API. I/O always happens outside the engine mutex. The bridge
//! supplies the monotonic clock so Swift/Kotlin cannot mix uptime/epoch clocks.

use std::sync::{Arc, Mutex};
use std::time::Instant;
use vault_core::diagnostics as core;

macro_rules! shared_enum {
    ($name:ident, $core:ident, $($variant:ident),+ $(,)?) => {
        #[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
        pub enum $name { $($variant),+ }
        impl From<core::$core> for $name {
            fn from(value: core::$core) -> Self { match value { $(core::$core::$variant => Self::$variant),+ } }
        }
        impl From<$name> for core::$core {
            fn from(value: $name) -> Self { match value { $($name::$variant => Self::$variant),+ } }
        }
    }
}
shared_enum!(
    DiagnosticStage,
    Stage,
    Route,
    Dns,
    Tcp,
    Https,
    Dns6,
    Tcp6,
    Https6,
    Gateway,
    Application,
    Ping,
    Ping6
);
shared_enum!(DiagnosticScope, Scope, Tunnel, Application, HostDefault);
shared_enum!(DiagnosticState, State, Passed, Failed, Incomplete);
shared_enum!(
    DiagnosticErrorKind,
    ErrorKind,
    Timeout,
    Dns,
    Connect,
    Tls,
    Http,
    Permission,
    Unavailable,
    InvalidResponse
);

#[derive(Debug, thiserror::Error, uniffi::Error)]
pub enum DiagnosticError {
    #[error("Invalid diagnostic input: {detail}")]
    InvalidInput { detail: String },
    #[error("Invalid diagnostic operation: {detail}")]
    InvalidState { detail: String },
}

fn input(message: impl ToString) -> DiagnosticError {
    DiagnosticError::InvalidInput {
        detail: message.to_string(),
    }
}
impl From<core::EngineError> for DiagnosticError {
    fn from(error: core::EngineError) -> Self {
        DiagnosticError::InvalidState {
            detail: error.to_string(),
        }
    }
}

#[derive(Clone, uniffi::Record)]
pub struct DiagnosticConfig {
    pub session_id: u64,
    pub domains: Vec<String>,
    pub dns_servers: Vec<String>,
    pub tunnel_ipv4: Option<String>,
    pub tunnel_ipv4_prefix: Option<u8>,
    pub tunnel_ipv6: Option<String>,
    pub tunnel_mtu: u16,
}

#[derive(Clone, uniffi::Enum)]
pub enum DiagnosticOperation {
    Route,
    Dns {
        server: String,
        ipv6: bool,
    },
    Tcp {
        address: String,
        port: u16,
    },
    Https {
        address: Option<String>,
        port: u16,
    },
    Ping {
        address: String,
        sequence: u16,
        packet_size: u16,
    },
}

#[derive(Clone, uniffi::Record)]
pub struct DiagnosticRequest {
    pub id: u64,
    pub session_id: u64,
    pub stage: DiagnosticStage,
    pub scope: DiagnosticScope,
    pub domain: String,
    /// Relative to this engine's creation, not wall-clock time.
    pub deadline_ms: u64,
    pub operation: DiagnosticOperation,
}
impl From<core::Request> for DiagnosticRequest {
    fn from(r: core::Request) -> Self {
        let operation = match r.operation {
            core::Operation::Route => DiagnosticOperation::Route,
            core::Operation::Dns { server, ipv6 } => DiagnosticOperation::Dns {
                server: server.to_string(),
                ipv6,
            },
            core::Operation::Tcp { address, port } => DiagnosticOperation::Tcp {
                address: address.to_string(),
                port,
            },
            core::Operation::Https { address, port } => DiagnosticOperation::Https {
                address: address.map(|ip| ip.to_string()),
                port,
            },
            core::Operation::Ping {
                address,
                sequence,
                packet_size,
            } => DiagnosticOperation::Ping {
                address: address.to_string(),
                sequence,
                packet_size,
            },
        };
        Self {
            id: r.id,
            session_id: r.session_id,
            stage: r.stage.into(),
            scope: r.scope.into(),
            domain: r.domain,
            deadline_ms: r.deadline_ms,
            operation,
        }
    }
}

#[derive(Clone, uniffi::Enum)]
pub enum DiagnosticResponse {
    Route {
        ipv4: Option<String>,
        ipv6: Option<String>,
    },
    Dns {
        addresses: Vec<String>,
    },
    Tcp,
    /// Validated by the shared Rust HTTP transport before crossing FFI/IPC.
    Https {
        status_line: String,
        received_bytes: u32,
        tls_duration_ms: u64,
        certificate: String,
    },
    Ping {
        rtt_ms: u64,
    },
    Failed {
        kind: DiagnosticErrorKind,
        detail: String,
    },
}
impl TryFrom<DiagnosticResponse> for core::Observation {
    type Error = DiagnosticError;
    fn try_from(r: DiagnosticResponse) -> Result<Self, Self::Error> {
        Ok(match r {
            DiagnosticResponse::Route { ipv4, ipv6 } => Self::Route {
                ipv4: ipv4.map(|s| s.parse().map_err(input)).transpose()?,
                ipv6: ipv6.map(|s| s.parse().map_err(input)).transpose()?,
            },
            DiagnosticResponse::Dns { addresses } => Self::Dns {
                addresses: addresses
                    .into_iter()
                    .map(|s| s.parse().map_err(input))
                    .collect::<Result<_, _>>()?,
            },
            DiagnosticResponse::Tcp => Self::Tcp,
            DiagnosticResponse::Https {
                status_line,
                received_bytes,
                tls_duration_ms,
                certificate,
            } => Self::Https {
                status_line,
                received_bytes,
                tls_duration_ms,
                certificate,
            },
            DiagnosticResponse::Ping { rtt_ms } => Self::Ping { rtt_ms },
            DiagnosticResponse::Failed { kind, detail } => Self::Failed(core::Failure {
                kind: kind.into(),
                detail,
            }),
        })
    }
}

#[derive(Clone, uniffi::Record)]
pub struct DiagnosticCheck {
    pub stage: DiagnosticStage,
    pub passed: u32,
    pub attempted: u32,
    pub state: DiagnosticState,
    pub duration_ms: u64,
    pub sample_count: u32,
}

#[derive(Clone, uniffi::Record)]
pub struct DiagnosticProbe {
    pub request: DiagnosticRequest,
    pub duration_ms: u64,
    pub succeeded: bool,
    pub error_kind: Option<DiagnosticErrorKind>,
    pub detail: String,
    pub tls_duration_ms: Option<u64>,
}
impl From<core::Probe> for DiagnosticProbe {
    fn from(p: core::Probe) -> Self {
        let (detail, tls_duration_ms, error_kind) = match p.observation {
            core::Observation::Route { ipv4, ipv6 } => {
                (format!("IPv4={ipv4:?}, IPv6={ipv6:?}"), None, None)
            }
            core::Observation::Dns { addresses } => (
                if addresses.is_empty() {
                    "[] (no AAAA records)".into()
                } else {
                    addresses
                        .iter()
                        .map(ToString::to_string)
                        .collect::<Vec<_>>()
                        .join(", ")
                },
                None,
                None,
            ),
            core::Observation::Tcp => ("TCP 443 connected".into(), None, None),
            core::Observation::Https {
                status_line,
                received_bytes,
                tls_duration_ms,
                certificate,
            } => (
                format!("{status_line}, received {received_bytes} bytes · {certificate}"),
                Some(tls_duration_ms),
                None,
            ),
            core::Observation::Ping { rtt_ms } => (format!("reply rtt={rtt_ms}ms"), None, None),
            core::Observation::Failed(f) => (f.detail, None, Some(f.kind.into())),
        };
        Self {
            request: p.request.into(),
            duration_ms: p.duration_ms,
            succeeded: p.succeeded,
            error_kind,
            detail,
            tls_duration_ms,
        }
    }
}

#[derive(Clone, uniffi::Record)]
pub struct DiagnosticDomainState {
    pub domain: String,
    pub state: DiagnosticState,
}

#[derive(Clone, uniffi::Record)]
pub struct DiagnosticSnapshot {
    pub session_id: u64,
    pub domains: Vec<String>,
    pub running: bool,
    pub cancelled: bool,
    pub active_stage: Option<DiagnosticStage>,
    pub state: DiagnosticState,
    pub duration_ms: u64,
    pub checks: Vec<DiagnosticCheck>,
    pub probes: Vec<DiagnosticProbe>,
    pub route_issues: Vec<String>,
    pub route_unavailable: Vec<String>,
    pub domain_states: Vec<DiagnosticDomainState>,
}

#[derive(uniffi::Object)]
pub struct DiagnosticEngine {
    engine: Mutex<core::Engine>,
    clock: Instant,
}

#[uniffi::export]
impl DiagnosticEngine {
    #[uniffi::constructor]
    pub fn new(config: DiagnosticConfig) -> Result<Arc<Self>, DiagnosticError> {
        let config = core::Config {
            session_id: config.session_id,
            domains: config.domains,
            dns_servers: config
                .dns_servers
                .into_iter()
                .map(|s| s.parse().map_err(input))
                .collect::<Result<_, _>>()?,
            tunnel_ipv4: config
                .tunnel_ipv4
                .map(|s| s.parse().map_err(input))
                .transpose()?,
            tunnel_ipv6: config
                .tunnel_ipv6
                .map(|s| s.parse().map_err(input))
                .transpose()?,
            tunnel_ipv4_prefix: config.tunnel_ipv4_prefix,
            tunnel_mtu: config.tunnel_mtu,
        };
        Ok(Arc::new(Self {
            engine: Mutex::new(core::Engine::new(config, 0).map_err(input)?),
            clock: Instant::now(),
        }))
    }

    pub fn elapsed_ms(&self) -> u64 {
        self.clock.elapsed().as_millis().min(u64::MAX as u128) as u64
    }

    pub fn next_request(&self) -> Result<Option<DiagnosticRequest>, DiagnosticError> {
        let mut engine = self.engine.lock().unwrap_or_else(|p| p.into_inner());
        Ok(engine.next_request(self.elapsed_ms())?.map(Into::into))
    }

    pub fn complete(&self, id: u64, response: DiagnosticResponse) -> Result<(), DiagnosticError> {
        let observation = response.try_into()?;
        let mut engine = self.engine.lock().unwrap_or_else(|p| p.into_inner());
        Ok(engine.complete(id, observation, self.elapsed_ms())?)
    }

    pub fn cancel(&self) -> Result<(), DiagnosticError> {
        let mut engine = self.engine.lock().unwrap_or_else(|p| p.into_inner());
        Ok(engine.cancel(self.elapsed_ms())?)
    }

    pub fn snapshot(&self) -> DiagnosticSnapshot {
        let s = self
            .engine
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .snapshot();
        DiagnosticSnapshot {
            session_id: s.session_id,
            domains: s.domains,
            running: s.running,
            cancelled: s.cancelled,
            active_stage: s.active_stage.map(Into::into),
            state: s.state.into(),
            duration_ms: s.duration_ms,
            checks: s
                .checks
                .into_iter()
                .map(|c| DiagnosticCheck {
                    stage: c.stage.into(),
                    passed: c.passed,
                    attempted: c.attempted,
                    state: c.state.into(),
                    duration_ms: c.duration_ms,
                    sample_count: c.sample_count,
                })
                .collect(),
            probes: s.probes.into_iter().map(Into::into).collect(),
            route_issues: s.routes.issues,
            route_unavailable: s.routes.unavailable,
            domain_states: s
                .domain_states
                .into_iter()
                .map(|(domain, state)| DiagnosticDomainState {
                    domain,
                    state: state.into(),
                })
                .collect(),
        }
    }
}

/// Settings validation uses the same domain rules as the network engine.
#[uniffi::export]
pub fn diagnostic_dns_query(
    domain: String,
    id: u16,
    ipv6: bool,
) -> Result<Vec<u8>, DiagnosticError> {
    core::wire::dns_query(&domain, id, ipv6).map_err(|e| input(format!("{e:?}")))
}

impl From<core::Observation> for DiagnosticResponse {
    fn from(observation: core::Observation) -> Self {
        match observation {
            core::Observation::Route { ipv4, ipv6 } => Self::Route {
                ipv4: ipv4.map(|a| a.to_string()),
                ipv6: ipv6.map(|a| a.to_string()),
            },
            core::Observation::Dns { addresses } => Self::Dns {
                addresses: addresses.into_iter().map(|a| a.to_string()).collect(),
            },
            core::Observation::Tcp => Self::Tcp,
            core::Observation::Https {
                status_line,
                received_bytes,
                tls_duration_ms,
                certificate,
            } => Self::Https {
                status_line,
                received_bytes,
                tls_duration_ms,
                certificate,
            },
            core::Observation::Ping { rtt_ms } => Self::Ping { rtt_ms },
            core::Observation::Failed(f) => Self::Failed {
                kind: f.kind.into(),
                detail: f.detail,
            },
        }
    }
}

#[derive(uniffi::Object)]
pub struct DiagnosticTransport {
    network: Box<dyn core::transport::NetworkBinding>,
    cancellation: core::transport::Cancellation,
}

#[uniffi::export]
impl DiagnosticTransport {
    #[uniffi::constructor]
    pub fn new(tunnel_ipv4: Option<String>) -> Result<Arc<Self>, DiagnosticError> {
        let network: Box<dyn core::transport::NetworkBinding> = match tunnel_ipv4 {
            Some(address) => {
                #[cfg(target_vendor = "apple")]
                {
                    let address = address.parse().map_err(input)?;
                    let index = crate::network::tunnel_interface(address).map_err(input)?;
                    Box::new(crate::network::InterfaceNetwork(index))
                }
                #[cfg(not(target_vendor = "apple"))]
                {
                    let _ = address;
                    return Err(input("interface binding is only available on Apple"));
                }
            }
            None => Box::new(core::transport::DefaultNetwork),
        };
        Ok(Arc::new(Self {
            network,
            cancellation: core::transport::Cancellation::default(),
        }))
    }

    #[uniffi::constructor]
    pub fn for_network(network_handle: u64) -> Result<Arc<Self>, DiagnosticError> {
        #[cfg(target_os = "android")]
        {
            if network_handle == 0 {
                return Err(input("VPN network handle must not be zero"));
            }
            Ok(Arc::new(Self {
                network: Box::new(crate::network::AndroidNetwork(network_handle)),
                cancellation: core::transport::Cancellation::default(),
            }))
        }
        #[cfg(not(target_os = "android"))]
        {
            let _ = network_handle;
            Err(input("Android network binding is unavailable"))
        }
    }

    /// Synchronous: call on a worker, cancel from any thread. No runtime/tasks.
    pub fn execute(
        &self,
        operation: DiagnosticOperation,
        domain: String,
        timeout_ms: u64,
    ) -> Result<DiagnosticResponse, DiagnosticError> {
        let operation = match operation {
            DiagnosticOperation::Route => core::Operation::Route,
            DiagnosticOperation::Dns { server, ipv6 } => core::Operation::Dns {
                server: server.parse().map_err(input)?,
                ipv6,
            },
            DiagnosticOperation::Tcp { address, port } => core::Operation::Tcp {
                address: address.parse().map_err(input)?,
                port,
            },
            DiagnosticOperation::Https { address, port } => core::Operation::Https {
                address: address.map(|a| a.parse().map_err(input)).transpose()?,
                port,
            },
            DiagnosticOperation::Ping {
                address,
                sequence,
                packet_size,
            } => core::Operation::Ping {
                address: address.parse().map_err(input)?,
                sequence,
                packet_size,
            },
        };
        Ok(core::transport::execute(
            &operation,
            &domain,
            std::time::Duration::from_millis(timeout_ms),
            self.network.as_ref(),
            &self.cancellation,
        )
        .into())
    }

    pub fn cancel(&self) {
        self.cancellation.cancel();
    }
}
