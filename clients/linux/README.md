# Vault Edge - Linux VPN Client

The Linux client of the [Vault VPN](../../README.md) system.
Built on the platform-independent client session provided by
[`vault-core`](../../core) — the same session
implementation used by the Vault Android/iOS clients.

## Runtime dependencies

The Debian package depends on `iproute2` (`ip`), `procps` (`sysctl`) and
`adduser` (for the dedicated service account), and recommends `systemd-resolved`
and `polkitd`. The RPM package depends on `iproute`, `procps-ng` and
`shadow-utils`, with weak dependencies on `polkit` and `systemd-resolved`.
Automatic DNS configuration supports `systemd-resolved`/`resolvectl` and
NetworkManager/`nmcli`, with Polkit authorization. Other resolver setups require
manual DNS configuration. For source installations, install these tools separately.

## Project structure

```text
clients/linux/
├── Cargo.toml                  # Package, Debian and RPM metadata
├── edge.adoc                   # Manpage source
├── src/
│   ├── main.rs                 # Application entry point
│   ├── runner.rs               # Startup, network monitoring and cleanup
│   ├── edge.rs                 # Client session and TUN adapter
│   ├── config.rs               # TOML configuration
│   ├── dns.rs                  # resolved/NetworkManager DNS setup and cleanup
│   ├── routes.rs               # Route ownership and rollback
│   ├── interface.rs            # Physical-interface discovery
│   └── storage.rs              # Persistent device ID
└── assets/
    ├── edge.toml.example       # Example configuration
    ├── edge.service            # systemd service unit
    ├── edge.target             # systemd target unit
    ├── edge-resolved.rules     # Polkit authorization for DNS backends
    ├── deb-scripts/            # Debian lifecycle scripts
    └── rpm-scripts/            # RPM lifecycle scripts
```

## Build and test

Run these commands from the repository root:

```bash
cargo build -p edge --release
cargo test -p edge

# Create Debian and RPM packages (requires cargo-deb,
# cargo-generate-rpm and asciidoctor)
scripts/package-linux.sh --manpages-only
cargo deb -p edge
cargo generate-rpm -p clients/linux
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
- `iface`: Unused TUN interface name (e.g., "vpn0"); Edge creates it.
- `host`: VPN server IP address or hostname
- `dns_ipv4`: IPv4 DNS server list; omitted or empty uses `1.1.1.1,8.8.8.8`
- `dns_ipv6`: IPv6 DNS server list; omitted or empty uses Google IPv6 DNS
  `2001:4860:4860::8888,2001:4860:4860::8844`
- `storage`: Path to storage file for device ID

Only one Edge instance can run per network namespace. See [edge(1)](edge.adoc)
for route recovery and legacy route cleanup.

The old `dns` field is not supported and causes a configuration error. Each
new field accepts only numeric addresses of its own family. DNS is applied after
tunnel addresses are assigned and VPN routes are installed:

- IPv4-only: use the IPv4 list, up to three entries.
- IPv6-only: use the IPv6 list, up to three entries.
- Dual stack: use the first two IPv6 entries followed by the first IPv4 entry.
  Shorter custom lists contribute only their available entries.

Address family selection follows the assignment; it does not prove that the
server has working internet egress for that family. Changed assignments update
the selected DNS servers.

With systemd-resolved's local stub, Edge configures DNS and the `~.` routing
domain on its own TUN, flushes resolver caches and reverts the link on exit.
When NetworkManager generates `/etc/resolv.conf`, Edge replaces its active
nameservers instead. Startup and exit run `nmcli general reload dns-rc`, allowing
NetworkManager to regenerate DNS from its current connections rather than an
Edge-owned historical snapshot. Active settings are checked every 2s and
reapplied after NetworkManager rewrites the file.

The Debian and RPM packages grant the `vault` account the required Polkit
actions; manual runs with another `--user` need equivalent authorization.
Resolver commands have a 2s timeout. Other setups, including
`/run/systemd/resolve/resolv.conf` uplink mode, require manual DNS configuration.
Edge never changes NetworkManager's physical-interface connection settings.

## Usage and deployment

### Run directly (requires root)

Release archives named `edge-v<version>-<arch>.tar.gz` contain only the static
musl executable, LICENSE and NOTICE. They do not install configuration, user
accounts or service units. Install the runtime commands listed above, then
extract the matching archive (amd64 shown here):

```bash
tar -xzf edge-v0.1.1-amd64.tar.gz
./edge-v0.1.1-amd64/edge --help
sudo install -d -m 700 /etc/vault
# Create /etc/vault/edge.toml as described above, then:
sudo ./edge-v0.1.1-amd64/edge --config /etc/vault/edge.toml
```

For a source build, use `./target/release/edge` instead.

To change identity, add `--user USER --group GROUP`; see the security notes
below.

### Run as systemd service

Edge and supernode are intended for separate hosts; co-located deployment is
not supported. Install a locally built system package (amd64 shown; choose
arm64 where appropriate):

```bash
# Debian/Ubuntu
sudo apt install ./dist/edge_0.1.1-1_amd64.deb

# Fedora and other DNF-based distributions
sudo dnf install ./dist/edge-v0.1.1-amd64.rpm
```

The Debian and RPM packages create a shared `vault` system user/group and start
the service directly with that identity and the required capabilities. They
also migrate ownership of logs and state created as root by earlier versions.
Upgrades restart only an already-running service; removal stops and disables
it. Debian packages install systemd units under `/lib/systemd/system`; RPM
packages use `/usr/lib/systemd/system`.

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
`CAP_DAC_OVERRIDE` for network setup and access to configuration and control
files, so this is not a complete privilege sandbox.

## Documentation

- [Protocol](../../docs/protocol.md) — wire format, handshake and encryption
- [Diagnostics](../../docs/diagnostics-engine.md) — shared diagnostic engine
- [Performance](../../docs/performance.md) — runtime measurements
- [Releasing](../../docs/releasing.md) — packaging and signing

## License

MIT — see [LICENSE](../../LICENSE)
