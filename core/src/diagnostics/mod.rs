// SPDX-License-Identifier: MIT
//! Shared mobile diagnostics engine.
//!
//! The engine owns ordering, retries, deadlines and verdicts. It is a pull-based
//! state machine: a platform host executes one [`Request`] and returns an
//! [`Observation`]. It must not invent its own stages or interpret success.
//! This keeps Android Network binding and Apple NetworkExtension/TLS APIs at
//! the boundary, without invoking foreign code under Rust locks. Apple hosts
//! may dispatch application requests to the app process over IPC.
//!
//! Times are monotonic milliseconds from one clock for the entire run. Hosts
//! MUST enforce `deadline_ms`, cancel outstanding I/O on cancellation/session
//! changes, and use the remaining deadline for *every* blocking operation.
//! The engine rejects stale responses and never accepts a late success.

use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::net::{IpAddr, Ipv4Addr};

pub mod transport;
pub mod wire;

pub const DEFAULT_DOMAINS: [&str; 3] = ["www.google.com", "github.com", "t.co"];
pub const REQUIRED_STAGES: [Stage; 7] = [
    Stage::Dns,
    Stage::Tcp,
    Stage::Https,
    Stage::Dns6,
    Stage::Tcp6,
    Stage::Https6,
    Stage::Application,
];

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Stage {
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
    Ping6,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Scope {
    /// Must bind DNS and sockets to the current VPN network/interface.
    Tunnel,
    /// System resolver/default routing in the user application process.
    Application,
    /// Optional gateway observations from the VPN host, using default routing.
    HostDefault,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum State {
    Passed,
    Failed,
    Incomplete,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorKind {
    Timeout,
    Dns,
    Connect,
    Tls,
    Http,
    Permission,
    Unavailable,
    InvalidResponse,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Failure {
    pub kind: ErrorKind,
    pub detail: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    /// Identifies the live tunnel session, never addresses loaded from cache.
    pub session_id: u64,
    pub domains: Vec<String>,
    pub dns_servers: Vec<IpAddr>,
    pub tunnel_ipv4: Option<Ipv4Addr>,
    pub tunnel_ipv4_prefix: Option<u8>,
    pub tunnel_ipv6: Option<std::net::Ipv6Addr>,
    pub tunnel_mtu: u16,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            session_id: 0,
            domains: vec![],
            dns_servers: vec![],
            tunnel_ipv4: None,
            tunnel_ipv4_prefix: None,
            tunnel_ipv6: None,
            tunnel_mtu: 1427,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Operation {
    Route,
    Dns {
        server: IpAddr,
        ipv6: bool,
    },
    Tcp {
        address: IpAddr,
        port: u16,
    },
    /// GET / with Range: bytes=0-65535, Connection: close; enforce SNI,
    /// hostname validation and platform trust. `None` uses system DNS.
    Https {
        address: Option<IpAddr>,
        port: u16,
    },
    Ping {
        address: IpAddr,
        sequence: u16,
        packet_size: u16,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Request {
    pub id: u64,
    pub session_id: u64,
    pub stage: Stage,
    pub scope: Scope,
    pub domain: String,
    pub deadline_ms: u64,
    pub operation: Operation,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Observation {
    Route {
        ipv4: Option<IpAddr>,
        ipv6: Option<IpAddr>,
    },
    Dns {
        addresses: Vec<IpAddr>,
    },
    Tcp,
    Https {
        status_line: String,
        received_bytes: u32,
        tls_duration_ms: u64,
        certificate: String,
    },
    Ping {
        rtt_ms: u64,
    },
    Failed(Failure),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Probe {
    pub request: Request,
    pub duration_ms: u64,
    pub observation: Observation,
    pub succeeded: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Check {
    pub stage: Stage,
    /// DNS/TCP/HTTPS count domains; Ping counts individual echo requests.
    pub passed: u32,
    pub attempted: u32,
    pub state: State,
    /// Mean of all attempts including failures/retries; Ping uses replies only.
    pub duration_ms: u64,
    pub sample_count: u32,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RouteAssessment {
    pub issues: Vec<String>,
    pub unavailable: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DefaultRoutes {
    pub ipv4: Option<IpAddr>,
    pub ipv6: Option<IpAddr>,
}

/// Observe application default routing without transmitting any packets.
/// Call from the app process: a VPN provider may have different default routes.
pub fn default_routes() -> DefaultRoutes {
    DefaultRoutes {
        ipv4: route_source("1.1.1.1:53".parse().unwrap()),
        ipv6: route_source("[2606:4700:4700::1111]:53".parse().unwrap()),
    }
}

fn route_source(target: std::net::SocketAddr) -> Option<IpAddr> {
    let bind = if target.is_ipv4() {
        "0.0.0.0:0"
    } else {
        "[::]:0"
    };
    let socket = std::net::UdpSocket::bind(bind).ok()?;
    socket.connect(target).ok()?;
    let address = socket.local_addr().ok()?.ip();
    (!address.is_unspecified()).then_some(address)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Snapshot {
    pub session_id: u64,
    pub domains: Vec<String>,
    pub running: bool,
    pub cancelled: bool,
    pub active_stage: Option<Stage>,
    pub state: State,
    pub duration_ms: u64,
    pub planned_checks: Vec<Stage>,
    pub checks: Vec<Check>,
    pub probes: Vec<Probe>,
    pub routes: RouteAssessment,
    pub domain_states: BTreeMap<String, State>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EngineError {
    InvalidConfig,
    ClockWentBackwards,
    ResponsePending,
    StaleResponse,
    WrongObservation,
}

impl std::fmt::Display for EngineError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}
impl std::error::Error for EngineError {}

const PHASES: [Stage; 11] = [
    Stage::Route,
    Stage::Dns,
    Stage::Tcp,
    Stage::Https,
    Stage::Dns6,
    Stage::Tcp6,
    Stage::Https6,
    Stage::Gateway,
    Stage::Application,
    Stage::Ping,
    Stage::Ping6,
];

pub struct Engine {
    config: Config,
    started_ms: u64,
    tunnel_started_ms: u64,
    now_ms: u64,
    finished_ms: Option<u64>,
    application_started_ms: Option<u64>,
    phase: usize,
    initialized: bool,
    queue: VecDeque<(String, Operation)>,
    pending: Option<(Request, u64)>,
    next_id: u64,
    answers: BTreeMap<String, Vec<IpAddr>>,
    selected: BTreeMap<String, IpAddr>,
    expected: usize,
    checks: Vec<Check>,
    probes: Vec<Probe>,
    routes: RouteAssessment,
    cancelled: bool,
}

impl Engine {
    pub fn new(mut config: Config, now_ms: u64) -> Result<Self, EngineError> {
        if !(1280..=1427).contains(&config.tunnel_mtu)
            || config.tunnel_ipv4_prefix.is_some_and(|p| p > 32)
        {
            return Err(EngineError::InvalidConfig);
        }
        if config.domains.is_empty() {
            config.domains = DEFAULT_DOMAINS.map(str::to_owned).to_vec();
        }
        let mut seen = BTreeSet::new();
        config.domains = config
            .domains
            .into_iter()
            .map(|d| {
                d.trim()
                    .strip_suffix('.')
                    .unwrap_or(d.trim())
                    .to_ascii_lowercase()
            })
            .filter(|d| seen.insert(d.clone()))
            .collect();
        if config.domains.len() > 32
            || config.domains.iter().any(|d| !wire::valid_domain(d))
            || config.dns_servers.len() > 8
        {
            return Err(EngineError::InvalidConfig);
        }
        if config.dns_servers.is_empty() {
            let default = if config.tunnel_ipv4.is_none() && config.tunnel_ipv6.is_some() {
                "2001:4860:4860::8888"
            } else {
                "1.1.1.1"
            };
            config.dns_servers.push(default.parse().unwrap());
        }
        Ok(Self {
            config,
            started_ms: now_ms,
            tunnel_started_ms: now_ms,
            now_ms,
            finished_ms: None,
            application_started_ms: None,
            phase: 0,
            initialized: false,
            queue: VecDeque::new(),
            pending: None,
            next_id: 1,
            answers: BTreeMap::new(),
            selected: BTreeMap::new(),
            expected: 0,
            checks: vec![],
            probes: vec![],
            routes: RouteAssessment::default(),
            cancelled: false,
        })
    }

    fn clock(&mut self, now_ms: u64) -> Result<(), EngineError> {
        if now_ms < self.now_ms {
            return Err(EngineError::ClockWentBackwards);
        }
        self.now_ms = now_ms;
        Ok(())
    }

    /// Poll after every completion. `None` means the run is finished.
    pub fn next_request(&mut self, now_ms: u64) -> Result<Option<Request>, EngineError> {
        self.clock(now_ms)?;
        if let Some((request, _)) = &self.pending {
            if now_ms < request.deadline_ms {
                return Err(EngineError::ResponsePending);
            }
            self.complete(
                request.id,
                failure(ErrorKind::Timeout, "probe deadline exceeded"),
                now_ms,
            )?;
        }
        while self.phase < PHASES.len() {
            let stage = PHASES[self.phase];
            if matches!(
                stage,
                Stage::Dns | Stage::Tcp | Stage::Https | Stage::Dns6 | Stage::Tcp6 | Stage::Https6
            ) && !self.required_stage(stage)
            {
                self.phase += 1;
                continue;
            }
            if !self.initialized {
                self.initialize(stage);
            }
            let deadline = self.phase_deadline(stage);
            while let Some((domain, operation)) = self.queue.pop_front() {
                if now_ms >= deadline {
                    self.queue.clear();
                    break;
                }
                if stage == Stage::Gateway
                    && matches!(operation, Operation::Ping { packet_size, .. } if packet_size > 64)
                    && !self
                        .probes
                        .iter()
                        .any(|p| p.request.stage == Stage::Gateway && p.succeeded)
                {
                    self.queue.clear();
                    break;
                }
                if matches!(stage, Stage::Dns | Stage::Dns6) && self.answers.contains_key(&domain)
                    || matches!(stage, Stage::Tcp | Stage::Tcp6)
                        && self.selected.contains_key(&domain)
                {
                    continue;
                }
                let timeout = match stage {
                    Stage::Route | Stage::Dns | Stage::Dns6 => 3000,
                    Stage::Tcp | Stage::Tcp6 => 4000,
                    Stage::Https | Stage::Https6 | Stage::Application => 6000,
                    _ => 2000,
                };
                let scope = match stage {
                    Stage::Route | Stage::Application | Stage::Ping | Stage::Ping6 => {
                        Scope::Application
                    }
                    Stage::Gateway => Scope::HostDefault,
                    _ => Scope::Tunnel,
                };
                let request = Request {
                    id: self.next_id,
                    session_id: self.config.session_id,
                    stage,
                    scope,
                    domain,
                    deadline_ms: deadline.min(now_ms.saturating_add(timeout)),
                    operation,
                };
                self.next_id += 1;
                self.pending = Some((request.clone(), now_ms));
                return Ok(Some(request));
            }
            self.finish_stage(stage);
            self.phase += 1;
            self.initialized = false;
        }
        self.finished_ms.get_or_insert(now_ms);
        Ok(None)
    }

    /// Rejects mismatched response types without consuming the pending request.
    pub fn complete(
        &mut self,
        id: u64,
        mut observation: Observation,
        now_ms: u64,
    ) -> Result<(), EngineError> {
        self.clock(now_ms)?;
        let (request, start) = self.pending.as_ref().ok_or(EngineError::StaleResponse)?;
        if request.id != id {
            return Err(EngineError::StaleResponse);
        }
        let matches = matches!(
            (&request.operation, &observation),
            (_, Observation::Failed(_))
                | (Operation::Route, Observation::Route { .. })
                | (Operation::Dns { .. }, Observation::Dns { .. })
                | (Operation::Tcp { .. }, Observation::Tcp)
                | (Operation::Https { .. }, Observation::Https { .. })
                | (Operation::Ping { .. }, Observation::Ping { .. })
        );
        if !matches {
            return Err(EngineError::WrongObservation);
        }
        if now_ms >= request.deadline_ms {
            observation = failure(ErrorKind::Timeout, "probe deadline exceeded");
        }
        if let Observation::Dns { addresses } = &mut observation {
            let ipv6 = request.stage == Stage::Dns6;
            if addresses.len() > 256 || addresses.iter().any(|ip| ip.is_ipv6() != ipv6) {
                observation = failure(
                    ErrorKind::InvalidResponse,
                    "DNS answer has wrong family or too many addresses",
                );
            } else {
                let mut seen = BTreeSet::new();
                addresses.retain(|ip| seen.insert(*ip));
                if !ipv6 && addresses.is_empty() {
                    observation = failure(ErrorKind::Dns, "No A records");
                }
            }
        }
        if let Observation::Https {
            status_line,
            received_bytes,
            tls_duration_ms,
            ..
        } = &observation
            && (!wire::valid_status_line(status_line)
                || *received_bytes == 0
                || *received_bytes > 65536
                || *tls_duration_ms > now_ms - start)
        {
            observation = failure(
                ErrorKind::InvalidResponse,
                "invalid HTTP response or TLS timing",
            );
        }
        if let Observation::Ping { rtt_ms } = &observation
            && *rtt_ms > now_ms - start
        {
            observation = failure(ErrorKind::InvalidResponse, "invalid Ping RTT");
        }
        let (request, start) = self.pending.take().unwrap();
        let succeeded = !matches!(observation, Observation::Failed(_));
        match &observation {
            Observation::Dns { addresses } => {
                self.answers
                    .insert(request.domain.clone(), addresses.clone());
            }
            Observation::Tcp => {
                if let Operation::Tcp { address, .. } = request.operation {
                    self.selected.insert(request.domain.clone(), address);
                }
            }
            Observation::Route { ipv4, ipv6 } => {
                self.routes = assess_routes(&self.config, *ipv4, *ipv6)
            }
            Observation::Failed(_) if request.stage == Stage::Route => {
                self.routes
                    .unavailable
                    .push("Default route observation unavailable".into());
            }
            _ => {}
        }
        self.probes.push(Probe {
            request,
            duration_ms: now_ms - start,
            observation,
            succeeded,
        });
        Ok(())
    }

    pub fn cancel(&mut self, now_ms: u64) -> Result<(), EngineError> {
        self.clock(now_ms)?;
        if self.phase < PHASES.len() {
            self.cancelled = true;
            self.pending = None;
            self.queue.clear();
            self.phase = PHASES.len();
            self.finished_ms = Some(now_ms);
        }
        Ok(())
    }

    pub fn snapshot(&self) -> Snapshot {
        let running = self.phase < PHASES.len();
        let incomplete = self.cancelled
            || !self.routes.unavailable.is_empty()
            || REQUIRED_STAGES.iter().any(|stage| {
                self.required_stage(*stage)
                    && !self
                        .checks
                        .iter()
                        .any(|c| c.stage == *stage && c.state != State::Incomplete)
            });
        let failed = !self.routes.issues.is_empty()
            || self
                .checks
                .iter()
                .any(|c| self.required_stage(c.stage) && c.state == State::Failed);
        let state = if running || incomplete {
            State::Incomplete
        } else if failed {
            State::Failed
        } else {
            State::Passed
        };
        Snapshot {
            session_id: self.config.session_id,
            domains: self.config.domains.clone(),
            running,
            cancelled: self.cancelled,
            active_stage: PHASES.get(self.phase).copied(),
            state,
            duration_ms: self.finished_ms.unwrap_or(self.now_ms) - self.started_ms,
            planned_checks: PHASES
                .iter()
                .copied()
                .filter(|stage| {
                    self.required_stage(*stage) || matches!(stage, Stage::Ping | Stage::Ping6)
                })
                .collect(),
            checks: self.checks.clone(),
            probes: self.probes.clone(),
            routes: self.routes.clone(),
            domain_states: self
                .config
                .domains
                .iter()
                .map(|d| (d.clone(), self.domain_state(d)))
                .collect(),
        }
    }

    fn required_stage(&self, stage: Stage) -> bool {
        match stage {
            Stage::Dns | Stage::Tcp | Stage::Https => self.config.tunnel_ipv4.is_some(),
            Stage::Dns6 | Stage::Tcp6 | Stage::Https6 => self.config.tunnel_ipv6.is_some(),
            Stage::Application => true,
            _ => false,
        }
    }

    fn domain_state(&self, domain: &str) -> State {
        let probes: Vec<_> = self
            .probes
            .iter()
            .filter(|p| p.request.domain == domain)
            .collect();
        let no_aaaa = probes.iter().any(|p| {
            p.request.stage == Stage::Dns6
                && matches!(&p.observation, Observation::Dns { addresses } if addresses.is_empty())
        });
        let mut missing = false;
        for stage in REQUIRED_STAGES {
            if !self.required_stage(stage) {
                continue;
            }
            if no_aaaa && matches!(stage, Stage::Tcp6 | Stage::Https6) {
                continue;
            }
            let attempts: Vec<_> = probes.iter().filter(|p| p.request.stage == stage).collect();
            if attempts.is_empty() {
                missing = true;
            } else if !attempts.iter().any(|p| p.succeeded) {
                return State::Failed;
            }
        }
        if missing {
            State::Incomplete
        } else {
            State::Passed
        }
    }

    fn phase_deadline(&self, stage: Stage) -> u64 {
        let (base, offset) = match stage {
            Stage::Route => (self.started_ms, 3_000),
            Stage::Dns | Stage::Tcp | Stage::Https => (self.tunnel_started_ms, 25_000),
            Stage::Dns6 | Stage::Tcp6 | Stage::Https6 => (self.tunnel_started_ms, 50_000),
            Stage::Gateway => (self.tunnel_started_ms, 60_000),
            Stage::Application => (self.application_started_ms.unwrap(), 16_000),
            Stage::Ping | Stage::Ping6 => (self.application_started_ms.unwrap(), 24_000),
        };
        base.saturating_add(offset)
    }

    fn initialize(&mut self, stage: Stage) {
        self.initialized = true;
        self.expected = 0;
        match stage {
            Stage::Route => self.queue.push_back((String::new(), Operation::Route)),
            Stage::Dns | Stage::Dns6 => {
                if stage == Stage::Dns || self.config.tunnel_ipv4.is_none() {
                    self.tunnel_started_ms = self.now_ms;
                }
                self.answers.clear();
                self.selected.clear();
                self.expected = self.config.domains.len();
                for domain in &self.config.domains {
                    for server in &self.config.dns_servers {
                        self.queue.push_back((
                            domain.clone(),
                            Operation::Dns {
                                server: *server,
                                ipv6: stage == Stage::Dns6,
                            },
                        ));
                    }
                }
            }
            Stage::Tcp | Stage::Tcp6 => {
                for domain in &self.config.domains {
                    if let Some(ips) = self.answers.get(domain).filter(|ips| !ips.is_empty()) {
                        self.expected += 1;
                        for address in ips.iter().take(2) {
                            self.queue.push_back((
                                domain.clone(),
                                Operation::Tcp {
                                    address: *address,
                                    port: 443,
                                },
                            ));
                        }
                    }
                }
            }
            Stage::Https | Stage::Https6 => {
                self.expected = self.selected.len();
                for domain in &self.config.domains {
                    if let Some(address) = self.selected.get(domain) {
                        self.queue.push_back((
                            domain.clone(),
                            Operation::Https {
                                address: Some(*address),
                                port: 443,
                            },
                        ));
                    }
                }
            }
            Stage::Gateway => {
                if let (Some(ip), Some(prefix)) =
                    (self.config.tunnel_ipv4, self.config.tunnel_ipv4_prefix)
                    && let Some(gateway) = gateway_address(ip, prefix)
                {
                    for packet_size in BTreeSet::from([
                        64,
                        1200.min(self.config.tunnel_mtu),
                        self.config.tunnel_mtu,
                    ]) {
                        for sequence in 0..2 {
                            self.queue.push_back((
                                gateway.to_string(),
                                Operation::Ping {
                                    address: gateway.into(),
                                    sequence,
                                    packet_size,
                                },
                            ));
                        }
                    }
                }
            }
            Stage::Application => {
                self.application_started_ms = Some(self.now_ms);
                self.expected = self.config.domains.len();
                for domain in &self.config.domains {
                    self.queue.push_back((
                        domain.clone(),
                        Operation::Https {
                            address: None,
                            port: 443,
                        },
                    ));
                }
            }
            Stage::Ping | Stage::Ping6 => {
                let address: IpAddr = if stage == Stage::Ping {
                    "1.1.1.1"
                } else {
                    "2606:4700:4700::1111"
                }
                .parse()
                .unwrap();
                self.expected = 2;
                for sequence in 0..2 {
                    self.queue.push_back((
                        address.to_string(),
                        Operation::Ping {
                            address,
                            sequence,
                            packet_size: 64,
                        },
                    ));
                }
            }
        }
    }

    fn finish_stage(&mut self, stage: Stage) {
        if stage == Stage::Route {
            if !self.probes.iter().any(|p| p.request.stage == stage) {
                self.routes
                    .unavailable
                    .push("Route check not completed".into());
            }
            return;
        }
        if stage == Stage::Gateway {
            return;
        }
        let probes: Vec<_> = self
            .probes
            .iter()
            .filter(|p| p.request.stage == stage)
            .collect();
        let ping = matches!(stage, Stage::Ping | Stage::Ping6);
        let attempted = if ping {
            probes.len()
        } else {
            probes
                .iter()
                .map(|p| &p.request.domain)
                .collect::<BTreeSet<_>>()
                .len()
        };
        let passed = if ping {
            probes.iter().filter(|p| p.succeeded).count()
        } else {
            probes
                .iter()
                .filter(|p| p.succeeded)
                .map(|p| &p.request.domain)
                .collect::<BTreeSet<_>>()
                .len()
        };
        let samples: Vec<_> = probes
            .iter()
            .filter(|p| !ping || p.succeeded)
            .map(|p| {
                if let Observation::Ping { rtt_ms } = p.observation {
                    rtt_ms
                } else {
                    p.duration_ms
                }
            })
            .collect();
        let mean = if samples.is_empty() {
            0
        } else {
            ((samples.iter().map(|v| *v as u128).sum::<u128>() + samples.len() as u128 / 2)
                / samples.len() as u128) as u64
        };
        let state = if attempted == 0
            || attempted != self.expected
            || self.now_ms >= self.phase_deadline(stage)
            || ping && passed != 2
        {
            State::Incomplete
        } else if passed != attempted {
            State::Failed
        } else {
            State::Passed
        };
        self.checks.push(Check {
            stage,
            passed: passed as u32,
            attempted: attempted as u32,
            state,
            duration_ms: mean,
            sample_count: samples.len() as u32,
        });
    }
}

fn failure(kind: ErrorKind, detail: &str) -> Observation {
    Observation::Failed(Failure {
        kind,
        detail: detail.into(),
    })
}

pub fn assess_routes(
    config: &Config,
    ipv4: Option<IpAddr>,
    ipv6: Option<IpAddr>,
) -> RouteAssessment {
    let mut result = RouteAssessment::default();
    if config.tunnel_ipv4.is_none() && config.tunnel_ipv6.is_none() {
        result
            .unavailable
            .push("Current tunnel addresses unavailable".into());
        return result;
    }
    match (config.tunnel_ipv4, ipv4) {
        (Some(expected), Some(actual)) if IpAddr::V4(expected) != actual => result
            .issues
            .push(format!("IPv4 route selects {actual}; expected {expected}")),
        (Some(_), None) => result
            .unavailable
            .push("IPv4 default route unavailable".into()),
        (None, Some(actual)) => result.issues.push(format!(
            "IPv4 route selects {actual} without a tunnel IPv4 assignment; possible bypass"
        )),
        _ => {}
    }
    match (config.tunnel_ipv6, ipv6) {
        (Some(expected), Some(actual)) if IpAddr::V6(expected) != actual => result
            .issues
            .push(format!("IPv6 route selects {actual}; expected {expected}")),
        (Some(_), None) => result
            .unavailable
            .push("IPv6 default route unavailable".into()),
        (None, Some(actual)) if config.tunnel_ipv4.is_some() => result.issues.push(format!(
            "IPv6 route selects {actual} without a tunnel IPv6 assignment; possible bypass"
        )),
        _ => {}
    }
    result
}

fn gateway_address(ip: Ipv4Addr, prefix: u8) -> Option<Ipv4Addr> {
    if prefix == 0 || prefix > 32 {
        return None;
    }
    let mask = u32::MAX << (32 - prefix);
    (u32::from(ip) & mask).checked_add(1).map(Ipv4Addr::from)
}

#[cfg(test)]
mod route_tests {
    use super::route_source;

    #[test]
    fn loopback_source() {
        for target in ["127.0.0.1:53", "[::1]:53"] {
            let target = target.parse::<std::net::SocketAddr>().unwrap();
            assert_eq!(route_source(target), Some(target.ip()));
        }
    }
}
