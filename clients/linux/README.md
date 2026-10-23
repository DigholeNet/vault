# Vault Edge - Linux VPN Client

The Linux client of the [Vault VPN](../../README.md) system.
Built on the platform-independent client session provided by
[`vault-core`](../../core) (`client` feature) — the same session
implementation used by the Vault Android/iOS clients.

## Features

- SPAKE2 password-authenticated handshake, X25519 ECDH key exchange, HKDF-SHA256 session keys
- AES-128-GCM, AES-256-GCM, and ChaCha20-Poly1305 encryption (negotiated by speed)
- Automatic IP assignment from server (IPv4 + IPv6)
- Periodic heartbeat (10s interval, 30s timeout)
- Automatic reconnect with exponential backoff (1s up to 60s)
- Physical exit checks every 2s; route migration and immediate reconnect on changes
- Traffic statistics (bytes/packets and per-second rates, logged every 10s)
- Route and DNS configuration with rollback on exit
- Per-link VPN DNS via `resolvectl` on systemd-resolved systems; repair DNS settings after network changes
- TUN device support

## Runtime dependencies

The Debian package installs `iproute2` (`ip`) and `procps` (`sysctl`).
It recommends `systemd-resolved` for systems where it manages `/etc/resolv.conf`;
`resolvectl` is required in that case. Other systems use the file-based DNS backend.
For source installations, install these tools separately before starting Edge.

## Build

```bash
cargo build --release
```

The binary will be at `target/release/edge`.

## Configuration

Create a configuration file at `/etc/vault/edge.toml`:

```toml
password="your_password"
port=9527
iface="vpn0"
host="your_server_ip"
dns=["8.8.8.8", "1.1.1.1"]
storage="/var/lib/vault/storage.dat"
```

### Configuration Options

- `password`: Server password for authentication
- `port`: Server port
- `iface`: TUN interface name (e.g., "vpn0")
- `host`: VPN server IP address or hostname
- `dns`: List of DNS servers to use
- `storage`: Path to storage file for device ID

When `/etc/resolv.conf` is managed by systemd-resolved, `resolvectl` must be
available. Edge configures DNS and the `~.` routing domain on its own TUN
interface after the tunnel becomes active, flushes stale resolver caches when settings
change, and reverts the link settings on exit. It leaves the managed resolver
file and physical-interface DNS settings intact. Other systems keep the existing
resolv.conf backup/restore behavior. Active DNS settings are checked every 2s so
late DHCP or network-manager updates do not undo recovery.
DNS failures are retried without tearing down the session or rolling back its
routes. Each `resolvectl` command has a 2s timeout.

## Run

### Run directly (requires root):

```bash
sudo ./target/release/edge --config /etc/vault/edge.toml
```

### Run as systemd service:

```bash
sudo cp assets/edge.service /lib/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now edge
```

## Commands

See `edge --help` for the full option list (config file, daemon mode,
pid file, logging, etc.).

Stop a running instance:

```bash
sudo edge -s quit
```

## Architecture

The session layer (handshake, heartbeat, reconnect, crypto, traffic stats)
lives in `vault-core::client`; this crate is a thin Linux platform adapter:

1. **Initialization**:
   - Generates or loads device ID from storage
   - Creates TUN device
   - Resolves the server address (before DNS takeover) and passes it as an IP
     literal to the session
   - Installs the server host route via the physical exit and configures DNS

2. **Connection** (handled by `ClientSession`):
   - Sends X25519 ECDH handshake request to server
   - Receives assigned IP and negotiated encryption algorithm
   - `on_ip_assigned` sets the TUN addresses, installs the VPN default route
     and a host route to the server via the physical interface (idempotent,
     re-applied on every reconnect)

3. **Data Transfer**:
   - A reader thread pumps packets from the TUN device into
     `ClientSession::write_packet` (bounded queue, drops on overflow)
   - The session encrypts/sends and decrypts/receives; decrypted downlink
     batches are written back to the TUN device via `on_packets`
   - The session sends a heartbeat ping every 10s; after 30s without a pong
     it reconnects with exponential backoff

4. **Network changes**:
   - Every 2s, reads physical default routes for the server address family,
     excluding the VPN interface and down links; prefers the lowest metric
   - Interface, address or gateway changes update the server host route before
     requesting a reconnect, without replacing TUN or resetting traffic counters
   - A restored network interrupts retry backoff even when it uses the same exit
   - Configuration failures during recovery are retried; initial setup failures
     still terminate the client
   - The server IP remains the address selected at startup; hostname refresh and
     switching server address families during recovery are follow-up work

5. **Shutdown**:
   - On `SIGTERM` or `-s quit`, the session is shut down, the host route is
     removed, and the original default routes and DNS configuration are
     restored

## License

MIT — see [LICENSE](../../LICENSE)
