# Vault Edge - Linux VPN Client

The Linux client of the [Vault VPN](../../README.md) system.
Built on the platform-independent client session provided by
[`vault-core`](../../core) — the same session
implementation used by the Vault Android/iOS clients.

## Runtime dependencies

The Debian package installs `iproute2` (`ip`), `procps` (`sysctl`) and
`adduser` (for the dedicated service account). It recommends `systemd-resolved`
and `polkitd` for systems where resolved manages `/etc/resolv.conf`; both
`resolvectl` and Polkit are required by that backend. Other systems use the
file-based DNS backend. For source installations, install these tools separately
before starting Edge.

## Project structure

```text
clients/linux/
├── Cargo.toml                  # Package and Debian metadata
├── edge.adoc                   # Manpage source
├── src/
│   ├── main.rs                 # Application entry point
│   ├── runner.rs               # Startup, network monitoring and cleanup
│   ├── edge.rs                 # Client session and TUN adapter
│   ├── config.rs               # TOML configuration
│   ├── dns.rs                  # DNS setup, recovery and resolved integration
│   ├── routes.rs               # Route ownership and rollback
│   ├── interface.rs            # Physical-interface discovery
│   └── storage.rs              # Persistent device ID
└── assets/
    ├── edge.toml.example       # Example configuration
    ├── edge.service            # systemd service unit
    ├── edge.target             # systemd target unit
    ├── edge-resolved.rules     # Polkit authorization for resolved
    └── deb-scripts/            # Debian lifecycle scripts
```

## Build and test

Run these commands from the repository root:

```bash
cargo build -p edge --release
cargo test -p edge
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
without replacing the saved system DNS. Assignment route changes and
DNS application are serialized so an old poll cannot overwrite the next
assignment's DNS selection.

When `/etc/resolv.conf` is managed by systemd-resolved, `resolvectl` must be
available. Edge configures DNS and the `~.` routing domain on its own TUN
interface after the tunnel becomes active, flushes stale resolver caches when settings
change, and reverts the link settings on exit. The Debian package grants the
`vault` account only the corresponding Polkit actions; Linux capabilities alone
do not authorize these D-Bus requests. Manual runs with another `--user` need
equivalent Polkit authorization. Edge leaves the managed resolver file and
physical-interface DNS settings intact. In the file backend, observed DHCP or
network-manager updates refresh the recovery backup before VPN DNS is reapplied.
On exit, Edge restores the latest saved system DNS or preserves an external
update already present in the file. Active DNS settings are checked every 2s so
late DHCP or network-manager updates do not undo recovery.
DNS failures are retried without tearing down the session or rolling back its
routes. Each `resolvectl` command has a 2s timeout.

## Usage and deployment

### Run directly (requires root)

```bash
sudo install -d -m 700 /etc/vault
# Create /etc/vault/edge.toml as described above, then:
sudo ./target/release/edge --config /etc/vault/edge.toml
```

To change identity, add `--user USER --group GROUP`; see the security notes
below.

### Run as systemd service

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

See `edge --help` for the full option list (config file, daemon mode,
pid file, logging, etc.). Stop a running instance with:

```bash
sudo edge -s quit
```

## Security considerations

Changing identity with `--user` must still start as root. The switch happens
before any logging, Tokio or TUN reader threads start. The selected log
directory and storage parent must support file creation, append, rename and
deletion by the target user. Edge retains `CAP_NET_ADMIN`, `CAP_NET_RAW` and
`CAP_DAC_OVERRIDE` for route/DNS changes and cleanup, so this is not a complete
privilege sandbox.

## Documentation

- [Protocol](../../docs/protocol.md) — wire format, handshake and encryption
- [Diagnostics](../../docs/diagnostics-engine.md) — shared diagnostic engine
- [Performance](../../docs/performance.md) — runtime measurements
- [Releasing](../../docs/releasing.md) — packaging and signing

## License

MIT — see [LICENSE](../../LICENSE)
