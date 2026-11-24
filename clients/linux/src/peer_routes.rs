// SPDX-License-Identifier: MIT
use std::{
    collections::HashMap,
    io,
    net::{IpAddr, SocketAddr},
    process::Command,
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
};

use anyhow::Context;
use serde_json::Value;
use tracing::warn;
use vault_core::client::{Gateway, PeerSocket, PeerSocketSetup};

use crate::interface::{FamilyExits, Interface};

const TABLE: &str = "24242";
const MARK: u32 = 0x564c5401;
const MARK_TEXT: &str = "0x564c5401";
const PRIORITY: &str = "100";
const REJECT_PRIORITY: &str = "101";
const PROTOCOL: &str = "242";

pub struct PeerRouting {
    state: Arc<Mutex<[Option<Policy>; 2]>>,
    mtu: Arc<AtomicUsize>,
}

impl PeerRouting {
    pub fn new() -> Self {
        Self {
            state: Arc::new(Mutex::new([None, None])),
            mtu: Arc::new(AtomicUsize::new(0)),
        }
    }

    pub fn update(&self, exits: Option<&FamilyExits>, servers: &[SocketAddr]) {
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        *state = [None, None];
        let Some(exits) = exits else {
            return;
        };
        for (slot, iface) in [
            exits.v4.as_ref().filter(|iface| iface.ipv4_direct()),
            exits.v6.as_ref(),
        ]
        .into_iter()
        .enumerate()
        {
            let Some(iface) = iface else {
                continue;
            };
            let ipv6 = slot == 1;
            match Policy::setup(ipv6, iface, servers) {
                Ok(policy) => state[slot] = Some(policy),
                Err(error) => warn!(ipv6, "Peer routing unavailable, using relay: {error:#}"),
            }
        }
    }

    pub fn set_mtu(&self, mtu: usize) {
        self.mtu.store(mtu, Ordering::Release);
    }

    pub fn socket_setup(&self) -> PeerSocketSetup {
        let state = self.state.clone();
        let mtu = self.mtu.clone();
        Arc::new(move |fd, addr, bound| {
            let family = usize::from(addr.ip().to_canonical().is_ipv6());
            let current = state.lock().unwrap_or_else(|e| e.into_inner());
            let policy = current[family].as_ref()?;
            if let Err(error) = mark_socket(fd) {
                warn!(%addr, %error, "Could not mark peer socket, using relay");
                return None;
            }
            let lan_endpoint = policy
                .server_sources
                .get(&addr.ip().to_canonical())
                .copied()
                .map(|address| SocketAddr::new(address, bound.port()));
            let gateway = policy
                .gateway
                .map(|gateway| Gateway::new(gateway, mark_socket));
            // These connected prefixes were installed in the marked table by
            // Policy::setup. The runner invalidates peer paths before replacing
            // the physical snapshot and its routes.
            let mut addresses = policy.addresses.clone();
            addresses.extend(
                pnet::datalink::interfaces()
                    .into_iter()
                    .flat_map(|interface| interface.ips.into_iter().map(|network| network.ip())),
            );
            let prefixes = policy.prefixes.clone();
            Some(PeerSocket {
                mtu: mtu.clone(),
                lan_endpoint,
                allow_lan: Arc::new(move |endpoint| {
                    lan_endpoint.is_some_and(|local| {
                        allow_lan(local.ip(), endpoint.ip(), &addresses, &prefixes)
                    })
                }),
                gateway,
            })
        })
    }
}

impl Drop for PeerRouting {
    fn drop(&mut self) {
        // Socket callbacks can outlive the runner briefly when Tokio shuts
        // down. Remove policies while the runner still owns the netns lock.
        let mut policy = self.state.lock().unwrap_or_else(|e| e.into_inner());
        *policy = [None, None];
    }
}

fn mark_socket(fd: i32) -> io::Result<()> {
    // SAFETY: fd is the caller's UDP socket; MARK is a live u32 optval.
    let result = unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_MARK,
            (&MARK as *const u32).cast(),
            size_of::<u32>() as libc::socklen_t,
        )
    };
    if result == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

struct Policy {
    family: &'static str,
    installed: Vec<Vec<String>>,
    interface: String,
    addresses: Vec<IpAddr>,
    server_sources: HashMap<IpAddr, IpAddr>,
    prefixes: Vec<pnet::ipnetwork::IpNetwork>,
    gateway: Option<std::net::Ipv4Addr>,
}

impl Policy {
    fn setup(ipv6: bool, iface: &Interface, servers: &[SocketAddr]) -> anyhow::Result<Self> {
        let family = if ipv6 { "-6" } else { "-4" };
        let mut policy = Self {
            family,
            installed: Vec::new(),
            interface: iface.name().to_string(),
            addresses: iface.addresses().to_vec(),
            server_sources: HashMap::new(),
            prefixes: iface
                .prefixes()
                .iter()
                .filter_map(|prefix| prefix.parse().ok())
                .collect(),
            gateway: (!ipv6).then(|| iface.gateway_ipv4()).flatten(),
        };
        let rules: Vec<Value> = serde_json::from_str(&policy.run(&["-j", "rule", "show"])?)?;
        anyhow::ensure!(
            !rules.iter().any(|rule| {
                let local = rule["table"].as_u64() == Some(255)
                    || matches!(rule["table"].as_str(), Some("255" | "local"));
                rule["priority"]
                    .as_u64()
                    .is_some_and(|priority| priority <= 101 && !(priority == 0 && local))
                    || rule["fwmark"].as_str() == Some(MARK_TEXT)
            }),
            "an existing rule takes precedence over the peer routing table or uses its socket mark"
        );
        let all = policy.run(&["route", "show", "table", "all"])?;
        anyhow::ensure!(
            !all.lines().any(|line| line
                .split_whitespace()
                .collect::<Vec<_>>()
                .windows(2)
                .any(|fields| fields == ["table", TABLE])),
            "routing table {TABLE} is already in use"
        );

        for prefix in iface.prefixes() {
            policy.add(&[
                "route",
                prefix,
                "dev",
                iface.name(),
                "table",
                TABLE,
                "proto",
                PROTOCOL,
            ])?;
        }
        let gateway = if ipv6 {
            iface.gateway_ipv6().map(|ip| ip.to_string())
        } else {
            iface.gateway_ipv4().map(|ip| ip.to_string())
        };
        let mut route = vec![
            "route",
            "default",
            "dev",
            iface.name(),
            "table",
            TABLE,
            "proto",
            PROTOCOL,
        ];
        if let Some(gateway) = gateway.as_deref() {
            route.extend(["via", gateway, "onlink"]);
        }
        policy.add(&route)?;
        policy.add(&[
            "rule",
            "priority",
            REJECT_PRIORITY,
            "fwmark",
            MARK_TEXT,
            "protocol",
            PROTOCOL,
            "unreachable",
        ])?;
        policy.add(&[
            "rule", "priority", PRIORITY, "fwmark", MARK_TEXT, "protocol", PROTOCOL, "lookup",
            TABLE,
        ])?;

        for server in servers
            .iter()
            .filter(|addr| addr.ip().to_canonical().is_ipv6() == ipv6)
        {
            let address = server.ip().to_canonical();
            let route = policy.route_to(address)?;
            if let Some(source) = route["prefsrc"]
                .as_str()
                .and_then(|source| source.parse::<IpAddr>().ok())
                .filter(|ip| usable_lan(*ip) && policy.addresses.contains(ip))
            {
                policy.server_sources.insert(address, source);
            }
        }
        Ok(policy)
    }

    fn route_to(&self, address: IpAddr) -> anyhow::Result<Value> {
        let address = address.to_string();
        let output: Vec<Value> =
            serde_json::from_str(&self.run(&["-j", "route", "get", &address, "mark", MARK_TEXT])?)?;
        output
            .into_iter()
            .find(|route| {
                route["dev"].as_str() == Some(self.interface.as_str())
                    && (route["table"].as_str() == Some(TABLE)
                        || route["table"].as_u64() == Some(24242))
            })
            .with_context(|| format!("marked route to {address} did not select the physical table"))
    }

    fn run(&self, args: &[&str]) -> anyhow::Result<String> {
        let output = vault_core::util::checked_output(
            Command::new("ip").args(["-N", self.family]).args(args),
        )
        .with_context(|| format!("ip {} {}", self.family, args.join(" ")))?;
        Ok(String::from_utf8(output.stdout)?)
    }

    fn add(&mut self, route: &[&str]) -> anyhow::Result<()> {
        let mut args = vec![route[0], "add"];
        args.extend_from_slice(&route[1..]);
        self.run(&args)?;
        let mut delete = args.into_iter().map(str::to_string).collect::<Vec<_>>();
        delete[1] = "del".into();
        self.installed.push(delete);
        Ok(())
    }
}

impl Drop for Policy {
    fn drop(&mut self) {
        // Remove lookup before its fail-closed rule, and leave the rejection
        // in place until the old marked socket has already been invalidated.
        for delete in std::mem::take(&mut self.installed).into_iter().rev() {
            let args = delete.iter().map(String::as_str).collect::<Vec<_>>();
            if let Err(error) = self.run(&args) {
                warn!("Could not remove Vault peer route: {error:#}");
            }
        }
    }
}

fn usable_lan(ip: IpAddr) -> bool {
    !ip.is_unspecified()
        && !ip.is_multicast()
        && !ip.is_loopback()
        && match ip {
            IpAddr::V4(ip) => !ip.is_link_local() && !ip.is_broadcast(),
            IpAddr::V6(ip) => !ip.is_unicast_link_local(),
        }
}

fn allow_lan(
    local: IpAddr,
    remote: IpAddr,
    addresses: &[IpAddr],
    prefixes: &[pnet::ipnetwork::IpNetwork],
) -> bool {
    usable_lan(remote)
        && !addresses.contains(&remote)
        && prefixes.iter().any(|prefix| {
            prefix.contains(local)
                && prefix.contains(remote)
                && match prefix {
                    pnet::ipnetwork::IpNetwork::V4(prefix) if prefix.prefix() < 31 => {
                        IpAddr::V4(prefix.network()) != remote
                            && IpAddr::V4(prefix.broadcast()) != remote
                    }
                    _ => true,
                }
        })
}
