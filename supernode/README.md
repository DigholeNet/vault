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

The supernode automatically enables host-wide forwarding for each configured
address family when needed (below). It never disables forwarding on shutdown.
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
Enabled forwarding and adjusted upstream RA settings remain in place on
success, failure, and shutdown. After SIGKILL/OOM, inspect firewall rules manually.

### Automatic host forwarding

At startup, the server enables `net.ipv4.ip_forward=1` for an IPv4 pool and
`net.ipv6.conf.all.forwarding=1` for an IPv6 pool if needed. No manual sysctl
configuration is required, including after reboot. Startup fails if a required
sysctl cannot be read or written.

Before enabling IPv6 forwarding, the server changes `accept_ra=1` to
`accept_ra=2` on detected exit interfaces to preserve Router Advertisement
reception in router mode. Explicitly disabled RA (`0`) stays disabled.
Forwarding and uplink RA changes are not rolled back, even if startup later
fails, because other services may depend on them.

Changing IPv4 `ip_forward` resets other IPv4 settings to host/router defaults.
Hosts with custom IPv4 tunables can still provision forwarding before applying
those tunables using `/etc/sysctl.d/90-vault-forwarding.conf`:

```ini
net.ipv4.ip_forward = 1
# For an RA-dependent IPv6 uplink, replace eth0 with the actual interface:
net.ipv6.conf.eth0.accept_ra = 2
net.ipv6.conf.all.forwarding = 1
```

Apply optional persistent configuration with
`sudo sysctl -p /etc/sysctl.d/90-vault-forwarding.conf`.
If a network manager owns these settings, configure it consistently so it does
not disable forwarding while the server is running.

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
`asciidoctor` for Debian packaging (not needed for plain binary builds). The server runs only on
Linux (TUN/TAP); on other platforms the crate still compiles as a stub, so
`cargo check -p supernode` works everywhere.

Run these commands from the repository root:

```bash
# Debug / release build
cargo build -p supernode
cargo build -p supernode --release

# Run tests
cargo test -p supernode

# Create Debian package (requires cargo-deb and asciidoctor)
scripts/package-linux.sh --manpages-only
cargo deb -p supernode
```

Build artifacts:

- **Binary**: `target/release/supernode`
- **Manpage**: `supernode/target/supernode.1.gz` (generated by `scripts/package-linux.sh --manpages-only`)

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
- `ipv4`: optional IPv4 pool in CIDR notation (network address, not interface IP); the
  server takes the first pool address for its own TUN device
- `ipv6`: IPv6 pool in CIDR notation (optional)

Configure at least one of `ipv4` or `ipv6`. For an IPv6-only tunnel, omit
`ipv4`:

```toml
password = "change-me-to-a-strong-password"
port = 9527
iface = "vpn"
ipv6 = "fd00::/96"
```

The server needs working IPv6 egress for clients to reach IPv6 internet targets.

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
# Install a locally built package (adjust the filename to your build)
dpkg -i target/debian/supernode_0.1.0-1_amd64.deb

# Create the configuration on a fresh installation. Set a strong password
# and review the address pools before starting the service.
install -m 600 /etc/vault/supernode.toml.example /etc/vault/supernode.toml
sudoedit /etc/vault/supernode.toml

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
4. **Missing manpage when packaging**: install `asciidoctor` and run
   `scripts/package-linux.sh --manpages-only` before `cargo deb`

Run with `--verbose` to enable debug-level logging for troubleshooting
connection issues.

## License

MIT — see [LICENSE](../LICENSE)
