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
- `iptables` for NAT/masquerade rules
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

The wire protocol (message types, handshake, encryption format) is documented
in [docs/protocol.md](../docs/protocol.md) and implemented in `vault-core`.

### Network configuration

On startup, the supernode automatically configures:

1. IP forwarding (`net.ipv4.ip_forward=1`)
2. Disables send redirects on the TUN interface
3. iptables NAT rules for masquerading VPN traffic to physical interfaces
4. TCP MSS clamping (`TCPMSS --clamp-mss-to-pmtu` in the mangle table) so
   oversized TCP segments cannot black-hole behind the tunnel

On shutdown (Drop impl), NAT and MSS clamp rules are cleaned up. Verify the
cleanup after an unexpected termination.

## Build

Prerequisites: Rust toolchain (stable; edition 2024 requires Rust 1.85+),
Linux (not macOS-compatible due to TUN/TAP dependencies), and optionally
`asciidoctor` for manpage generation.

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
dpkg -i supernode_1.0.0-1_amd64.deb

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
