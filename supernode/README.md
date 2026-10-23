# Vault Supernode

The server of the [Vault VPN](../README.md) system — a Linux-only VPN server
written in Rust. It sits at the center of the star topology: edge clients
connect to it over encrypted UDP tunnels, and it assigns virtual IPs and
relays traffic between them. It reuses `vault-core`'s epoll, TUN, peer
management and protocol implementation, and adds the address pool (CIDR
allocation with leases and recycling), NAT/forwarding setup, and the relay
loop.

System requirements:

- Linux with TUN/TAP support (`/dev/net/tun`)
- `iptables` (including `ip6tables` for IPv6) for NAT/masquerade rules
- `procps` (`sysctl`) for forwarding configuration
- The Debian package installs these runtime command dependencies automatically
- Root privileges (or `CAP_NET_ADMIN`) to create TUN devices and modify iptables

## Project structure

```
supernode/
├── Cargo.toml              # Package manifest with debian metadata
├── build.rs                # Build script for manpage generation
├── supernode.adoc    # Manpage source (AsciiDoc format)
├── src/
│   ├── main.rs             # Application entry point
│   ├── config.rs           # Configuration structure (TOML parsing)
│   ├── error.rs            # Error types
│   ├── supernode.rs        # Main SuperNode logic and event loop
│   ├── handshake.rs        # Pending handshake tracking and replay protection
│   ├── limiter.rs          # INIT rate limiting and source-IP banning
│   ├── mock_time.rs        # Test time source
│   └── ip/
│       ├── mod.rs          # IP module
│       ├── ip_manager.rs   # IP assignment and lease tracking (sqlite, in-memory)
│       └── pool.rs         # IPv4/IPv6 CIDR pools
└── assets/
    ├── supernode.toml.example    # Example configuration file
    ├── supernode.service         # systemd service unit
    ├── supernode.target          # systemd target unit
    └── deb-scripts/
        └── postinst              # Debian post-install script
```

## Architecture

1. **SuperNode** (`src/supernode.rs`)
   - Main server struct that manages the VPN service
   - Event-driven architecture using epoll for I/O multiplexing
   - Handles two main I/O sources:
     - **UDP socket**: communication with edge clients
     - **TUN device**: virtual network interface for VPN traffic

2. **Configuration** (`src/config.rs`)
   - TOML-based configuration (see below)

3. **IP management** (`src/ip/`)
   - `IpManager`: assigns and tracks IP addresses for connected peers,
     automatically cleans up expired leases
   - IP pools (`Ipv4Pool`/`Ipv6Pool`) exclude network/broadcast addresses
     and, at startup, reserve all local physical interface addresses that
     fall inside the pool CIDR, so the server's real (socket) addresses are
     never assigned to clients

Unconfirmed handshakes expire and release their temporary addresses without
penalizing the source IP: packet loss and cancelled connection candidates are
normal behind shared NAT. The per-IP INIT rate limit and bans for repeated invalid
encrypted confirmations remain; blocked requests log the reason and retry window.

The wire protocol (message types, handshake, encryption format) is documented
in [docs/protocol.md](../docs/protocol.md) and implemented in `vault-core`.

### Network configuration

Host-wide forwarding is an administrator-managed prerequisite (below). The
supernode only reads these global switches and never changes or restores them.
On startup it sets redirect switches to zero on its own new TUN interface.
If global IPv4 redirect sending remains enabled, it warns and continues startup. For both IPv4 and IPv6 it installs:

- MASQUERADE rules restricted to the VPN source CIDR and routed exit interface
- FORWARD rules restricted to the TUN interface and VPN CIDR, including outbound
  traffic, established/related return traffic, and client-to-client relay
- TCP MSS clamping restricted to traffic entering or leaving the TUN with VPN
  source/destination addresses

Rules are appended, so earlier administrator DROP rules still take precedence.
The default FORWARD policy can be DROP; the scoped allow rules cover VPN traffic.
Exits are taken from usable routes exposed by Linux for the configured address
families, including default, connected and static routes over physical or virtual
interfaces. Loopback, the server's TUN, rejected routes and IPv6 local/multicast
routes are excluded. LAN-only deployments do not require a default route.
Routes must be present when the server starts; restart after changing exit interfaces. A missing egress interface or a failed sysctl/firewall
command aborts startup.
Partial startup failures and normal shutdown remove only rules added by this
instance and restore its TUN-local tunables if they still have the applied values.
Global forwarding, upstream RA settings, and unrelated host tunables are untouched
on success, failure, and shutdown. After SIGKILL/OOM, inspect firewall rules manually.

### Host forwarding prerequisite

Configure forwarding once as part of provisioning, before starting the service:

```ini
# /etc/sysctl.d/90-vault-forwarding.conf
net.ipv4.ip_forward = 1
# Optional host hardening; not required for startup:
# net.ipv4.conf.all.send_redirects = 0
# Only when an IPv6 pool is configured:
# net.ipv6.conf.eth0.accept_ra = 2
# net.ipv6.conf.all.forwarding = 1
```

For an IPv6 uplink that learns its route through Router Advertisements, replace
`eth0` with the actual uplink name and set `accept_ra = 2` **before** enabling
IPv6 forwarding. Static IPv6 uplinks do not need the RA override. Add the override
for each RA-dependent uplink. Keep these settings in the host network manager if
it owns the interface instead of maintaining conflicting configurations.

IPv4 `send_redirects` is enabled when either the global or interface switch is
on. Administrators may optionally set the global switch to `0` to ensure the
TUN does not send redirects. The daemon only warns if this global switch is on
or cannot be read; it never changes it or blocks startup because of it. Other
interfaces retain their own redirect settings.

Apply the file with `sudo sysctl -p /etc/sysctl.d/90-vault-forwarding.conf`.
Changing IPv4 `ip_forward` resets other IPv4 settings to host/router defaults;
provision it before applying custom IPv4 tunables, or review and reapply those
settings afterward. The daemon deliberately does not automate this host-wide
transition or attempt to reverse it when one VPN process exits.

### Verification

`cargo test -p supernode` covers scoped rules, shared host state, and injected
startup failures. On Linux, `scripts/test-network-namespace.sh` additionally
checks the real sysctl/iptables backend in a disposable network namespace and
is run by Linux CI. It requires sudo, iproute2, iptables, procps and util-linux.
No test in that script changes the host namespace.

The control socket is protected by `/run/supernode.socket.lock` for the process
lifetime, including daemonization. A duplicate start fails without replacing the
active socket. A stale socket from a crashed process is reclaimed after locking;
the lock file itself intentionally remains in place between starts.

## Build

Prerequisites: the stable Rust toolchain (Rust 1.98 or newer) and
optionally `asciidoctor` for manpage generation. The server runs only on
Linux (TUN/TAP); on other platforms the crate still compiles as a stub, so
`cargo check -p supernode` works everywhere.

```bash
# Debug / release build
cargo build
cargo build --release

# Run tests
cargo test -p supernode

# Create Debian package (requires cargo-deb)
cargo deb
```

Build artifacts:

- **Binary**: `target/release/supernode`
- **Manpage**: `target/supernode.1.gz` (generated if asciidoctor is available)

## Configuration

Example (`assets/supernode.toml.example`):

```toml
password = "change-me-to-a-strong-password"
port = 9527
iface = "vpn"
ipv4 = "192.168.10.0/24"
# ipv6 = "fd00::/96"  # optional IPv6 pool
```

Fields:

- `password`: shared secret that edge clients must provide — use a strong,
  unique password (SPAKE2 security depends on its entropy)
- `port`: UDP port for edge client connections
- `iface`: name of the TUN device to create
- `ipv4`: IPv4 pool in CIDR notation (network address, not interface IP); the
  server takes the first pool address for its own TUN device
- `ipv6`: IPv6 pool in CIDR notation (optional)

Command line usage:

```bash
# Run with config file
supernode --config /etc/vault/supernode.toml

# Run with verbose logging
supernode --config /etc/vault/supernode.toml --verbose

# Run as daemon with log file
supernode --config /etc/vault/supernode.toml --daemon --log-dir /var/log/vault
```

## Deployment

### systemd service

The project includes systemd unit files:

- **supernode.service**: main service unit
  - Type: forking; Restart: on-failure (5s delay)
  - Resource limits: 256 tasks, 1024M memory
  - Capabilities: NET_ADMIN, NET_BIND_SERVICE, NET_RAW, etc.
  - Device access: `/dev/net/tun` (read-write)
- **supernode.target**: target unit for grouping

### Debian package installation

```bash
# Install the package
dpkg -i supernode_0.1.0-1_amd64.deb

# Start the service and enable auto-start
systemctl enable --now supernode
```

File locations (Debian):

- Binary: `/usr/bin/supernode`
- Config example: `/etc/vault/supernode.toml.example`
- systemd units: `/lib/systemd/system/`
- Manpage: `/usr/share/man/man1/supernode.1.gz`

## Security considerations

1. **Root privileges required**: the server needs `CAP_NET_ADMIN` to create
   TUN devices and modify iptables rules
2. **Password security**: the shared password is used for authentication;
   use strong, unique passwords
3. **Network exposure**: the UDP port is exposed to the network; open it only
   as needed in your firewall
4. **iptables cleanup**: the Drop implementation attempts to clean up
   iptables rules, but verify after unexpected termination

## Troubleshooting

Common issues:

1. **Permission denied**: ensure running as root or with appropriate capabilities
2. **TUN device error**: check `/dev/net/tun` exists and is accessible
3. **Address already in use**: another process is using the configured UDP port
4. **Manpage build warning**: install `asciidoctor` to generate manpages

Run with `--verbose` to enable debug-level logging for troubleshooting
connection issues.

## License

MIT — see [LICENSE](../LICENSE)
