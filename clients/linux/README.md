# Vault Edge - Linux VPN Client

The Linux client of the [Vault VPN](../../README.md) system.
Built on the platform-independent client session provided by
[`vault-core`](../../core) — the same session
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

The Debian package installs `iproute2` (`ip`), `procps` (`sysctl`) and
`adduser` (for the dedicated service account). It recommends `systemd-resolved`
and `polkitd` for systems where resolved manages `/etc/resolv.conf`; both
`resolvectl` and Polkit are required by that backend. Other systems use the
file-based DNS backend. For source installations, install these tools separately
before starting Edge.

## Build

Run these commands from the repository root:

```bash
cargo build -p edge --release
```

The binary will be at `target/release/edge`.

## Configuration

Create a configuration file at `/etc/vault/edge.toml`:

```toml
password="your_password"
port=9527
iface="vpn0"
host="your_server_ip"
dns_ipv4=["1.1.1.1", "8.8.8.8"]
dns_ipv6=["2001:4860:4860::8888", "2001:4860:4860::8844"]
storage="/var/lib/vault/storage.dat"
```

### Configuration Options

- `password`: Server password for authentication
- `port`: Server port
- `iface`: TUN interface name (e.g., "vpn0")
- `host`: VPN server IP address or hostname
- `dns_ipv4`: IPv4 DNS server list; omitted or empty uses `1.1.1.1,8.8.8.8`
- `dns_ipv6`: IPv6 DNS server list; omitted or empty uses Google IPv6 DNS
  `2001:4860:4860::8888,2001:4860:4860::8844`
- `storage`: Path to storage file for device ID

The old `dns` field is not supported and causes a configuration error. Each
new field accepts only numeric addresses of its own family. DNS is applied
after the server assigns tunnel addresses and VPN routes are installed:

- IPv4-only: use the IPv4 list, up to three entries.
- IPv6-only: use the IPv6 list, up to three entries.
- Dual stack: use the first two IPv6 entries followed by the first IPv4 entry.
  Shorter custom lists contribute only their available entries.

The same selection is used by the file and systemd-resolved backends. Address
family selection follows the assignment; it does not prove that the server has
working internet egress for that family. Changed assignments recalculate DNS
without replacing the original recovery backup. Assignment route changes and
DNS application are serialized so an old poll cannot overwrite the next
assignment's DNS selection.

When `/etc/resolv.conf` is managed by systemd-resolved, `resolvectl` must be
available. Edge configures DNS and the `~.` routing domain on its own TUN
interface after the tunnel becomes active, flushes stale resolver caches when settings
change, and reverts the link settings on exit. The Debian package grants the
`vault` account only the corresponding Polkit actions; Linux capabilities alone
do not authorize these D-Bus requests. Manual runs with another `--user` need
equivalent Polkit authorization. Edge leaves the managed resolver file and
physical-interface DNS settings intact. Other systems keep the existing
resolv.conf backup/restore behavior. Active DNS settings are checked every 2s so
late DHCP or network-manager updates do not undo recovery.
DNS failures are retried without tearing down the session or rolling back its
routes. Each `resolvectl` command has a 2s timeout.

## Run

### Run directly (requires root):

```bash
sudo install -d -m 700 /etc/vault
# Create /etc/vault/edge.toml as described above, then:
sudo ./target/release/edge --config /etc/vault/edge.toml
```

To change identity, add `--user USER --group GROUP`. This must still start as
root. The switch happens before any logging, Tokio or TUN reader threads start.
The selected log directory and storage parent must support file creation,
append, rename and deletion by the target user. Edge retains `CAP_NET_ADMIN`,
`CAP_NET_RAW` and `CAP_DAC_OVERRIDE` for route/DNS changes and cleanup, so this
is not a complete privilege sandbox.

### Run as systemd service:

Edge and supernode are intended for separate hosts; co-located deployment is
not supported. The Debian package creates a shared `vault` system user/group
and starts the service directly with that identity and the required
capabilities. It also migrates ownership of logs and state created as root by
earlier versions. Upgrades restart only an already-running service; removal
stops and disables it.
For a source build, create the account and install the units from the
repository root before enabling the service:

```bash
sudo addgroup --system vault
sudo adduser --system --ingroup vault --no-create-home --home /var/lib/vault --disabled-login vault
sudo install -m 755 target/release/edge /usr/bin/edge
sudo install -m 644 clients/linux/assets/edge.service /lib/systemd/system/edge.service
sudo install -m 644 clients/linux/assets/edge.target /lib/systemd/system/edge.target
sudo install -m 644 clients/linux/assets/edge-resolved.rules /usr/share/polkit-1/rules.d/50-edge.rules
sudo install -d -m 700 /etc/vault
# Edit /etc/vault/edge.toml with your settings before starting the service.
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
   - Resolves all server address candidates before DNS takeover and passes them
     as IP literals to the shared session for IPv4/IPv6 handshake racing
   - Installs server host routes via the physical exits
   - Applies DNS after address assignment and route configuration succeed

2. **Connection** (handled by `ClientSession`):
   - Sends X25519 ECDH handshake request to server
   - Receives assigned IP and negotiated encryption algorithm
   - `on_ip_assigned` sets the TUN addresses, installs the VPN default route
     and server host routes via the physical interfaces. The callback runs on
     initial assignment and when addresses, mask or prefix change; same-address
     reconnects retain the TUN. The runner separately maintains server routes
     when physical exits change

3. **Data Transfer**:
   - A reader thread pumps packets from the TUN device into
     `ClientSession::write_packet` (bounded queue, drops on overflow)
   - The session encrypts/sends and decrypts/receives; decrypted downlink
     batches are written back to the TUN device via `on_packets`
   - The session sends a heartbeat ping every 10s; after 30s without an authenticated downstream packet (data or pong)
     it reconnects with exponential backoff

4. **Network changes**:
   - Every 2s, reads physical default routes for each server candidate address family,
     excluding the VPN interface and down links; prefers the lowest metric
   - Interface, address or gateway changes update the server host route before
     requesting a reconnect, without replacing TUN or resetting traffic counters
   - A restored network interrupts retry backoff even when it uses the same exit
   - Configuration failures during recovery are retried; initial setup failures
     still terminate the client
   - The candidate set is fixed by startup DNS resolution. Reconnects can race
     those candidates again, including across address families; DNS is not
     refreshed during recovery. Restart Edge to resolve changed server records

5. **Shutdown**:
   - On `SIGINT`, `SIGTERM` or `-s quit`, the session is shut down, the host route is
     removed, and the original default routes and DNS configuration are
     restored

## Logging and configuration errors

Logs are written only to files, including when running in the foreground.
`--log-dir` selects the directory; the default is `/var/log/vault/`.
Current files have fixed names (`default.log`, `error.log`, and
`metrics.log`). On the first write after a UTC date change, the previous file
is archived as `<name>.log.YYYY-MM-DD`, using its last-write date. Same-day
restarts append to the current file. Files from the previous dated naming
scheme are retained; today's dated file is adopted if no current file exists.
Each stream (`default`, `error`, and `metrics` logs)
keeps at most 30 files, including the current file. Older files are removed when
that stream first writes a log or rotates; existing history is cleaned up then too.
This limits file count, not total size or age; a busy day can still produce a large file.
`RUST_LOG` controls filtering unless `--verbose` or `--quiet` overrides it.
Unknown TOML fields are rejected, so configuration typos fail startup.

`VPN uplink metrics` and `VPN downlink metrics` use the `metrics` target and
write to `metrics.log`, including warnings; they are not duplicated in
`default.log` or `error.log`. See [runtime measurements](../../docs/performance.md#runtime-measurements)
for field definitions.


## License

MIT — see [LICENSE](../../LICENSE)
