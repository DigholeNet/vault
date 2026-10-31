# Privacy Policy

**Last Updated:** October 31, 2026

## Introduction

Vault is open-source, self-hosted VPN software. This is an important distinction:

- **The software authors** ("we") publish the Vault source code and client applications.
  We operate no VPN servers and receive no data from your use of the software.
- **The server operator** is whoever deploys and runs the `supernode` server you
  connect to. All VPN traffic is relayed through that server by design. If you use a
  server operated by someone else, their logging and retention practices apply to you —
  ask them, not us.

## Software Behavior

### Client applications (iOS / macOS / Android / Linux)

The client applications:

- Store your VPN configuration, DNS preferences, and a randomly generated device ID
  locally on your device
- Send the device ID, device name/model or hostname, platform, and supported cipher
  speeds to your configured server during the handshake. These handshake fields are
  not encrypted and can also be observed on the network. The password itself is
  not sent; it is used in the SPAKE2 exchange
- Transmit nothing to the software authors
- Integrate no third-party analytics, advertising, or tracking services

On Apple platforms the app stores the password in Keychain. Connecting also saves
it in the OS-managed VPN profile (`providerConfiguration`) so the tunnel can restart
on demand, including when the macOS system extension runs outside the user session.
This copy persists after disconnecting; the password is not confined to Keychain or
memory. On Android it is protected by Android Keystore, with a plaintext fallback in
app-private DataStore when encrypted storage fails. Password ciphertext and the
other VPN settings are committed together in DataStore; the encryption key stays
in Keystore. Legacy encrypted SharedPreferences entries are removed after a
successful migration, and plaintext fallback entries are encrypted when Keystore
recovers. Linux configuration files
contain the password in plaintext and should be readable only by the administrator.

### Active diagnostics and settings validation

On Apple and Android, starting diagnostics manually sends DNS, TCP, HTTPS and
ICMP probes. The default diagnostic domains are `www.google.com`, `github.com`
and `t.co`; users can change them in settings. Tunnel DNS uses the configured
resolvers. Apple and Android default to `1.1.1.1,8.8.8.8` for IPv4 DNS and
Google `2001:4860:4860::8888,2001:4860:4860::8844` for IPv6 DNS when each
field is empty. Only assigned families are applied; dual-stack tunnels use
both resolver lists. Linux uses the same per-family defaults; for dual stack
it selects two IPv6 resolvers and one IPv4 resolver. Application Ping targets
`1.1.1.1` and `2606:4700:4700::1111`; optional gateway probes target the VPN
gateway. Domain validation in settings checks syntax without sending DNS
queries; the exported query builder constructs bytes for validation only.

Tunnel probes bind to the live VPN interface/network. Application probes use
the app process's system DNS and default routing, which may select a path
outside the tunnel; optional host-default probes run in the VPN host process.
Resolvers and target operators can observe the queries or connections and
the source IP visible on the selected route. These requests are connectivity
checks, not analytics reports to the software authors. HTTPS response samples
remain in Rust; only validated metadata is returned to the app.
See [shared diagnostics](docs/diagnostics-engine.md) for probe scopes and defaults.

### Server (supernode)

The supernode decrypts tunnel packets and reads their IP headers to route traffic.
It does not log packet bodies, browsing URLs, or DNS query contents. Its runtime logs
include **connection metadata** needed to operate and debug the service:

- Client source IP address and port
- Client device ID, reported device name/model or hostname, and platform
- The tunnel IP address assigned to each client
- Handshake and disconnect events with timestamps

Debug-level packet logs additionally include source/destination IP addresses and
packet sizes. Warning logs can include addresses for rejected or unroutable packets,
even without debug logging. Do not enable verbose logging if recording this metadata
is unsuitable for your deployment; review and redact logs before sharing them.

These logs are written to the server's own log directory (`/var/log/vault/` by
default), are controlled entirely by the server operator, and their verbosity depends
on the configured log level. The software sends none of this anywhere else.

## Network Permissions

The Android app requires the following permissions:

- **INTERNET**: Required to establish VPN connections
- **ACCESS_NETWORK_STATE**: Required to monitor network changes
- **CHANGE_NETWORK_STATE**: Required to reconfigure connectivity when the
  network changes
- **BIND_VPN_SERVICE**: Required to create and manage the VPN tunnel
- **FOREGROUND_SERVICE** / **FOREGROUND_SERVICE_SPECIAL_USE**: Required to
  maintain the VPN connection in the background
- **POST_NOTIFICATIONS**: Required to show VPN status notifications
  (Android 13+)

## Data Security

The protocol implements industry-standard cryptography:

- **Encryption**: All VPN traffic is encrypted using AES-256-GCM, AES-128-GCM, or
  ChaCha20-Poly1305
- **Key Exchange**: X25519 Elliptic Curve Diffie-Hellman for secure key exchange
- **Authentication**: SPAKE2 password-authenticated key exchange (PAKE) for handshake verification
- **Perfect Forward Secrecy**: New keys are generated for each session

See [SECURITY.md](SECURITY.md) for the full security model and known limitations.

## Your Rights

You have the right to:

- Access your locally stored configuration data
- Remove app-local configuration by uninstalling the application. On Apple platforms,
  Keychain entries and OS-managed VPN profiles may remain; remove the VPN profile in
  system settings and remove saved Keychain credentials separately when needed
- Audit exactly what the software does — the complete source code is available in
  this repository

For data held by a server you connect to, contact that server's operator.

## Changes to This Privacy Policy

We may update this Privacy Policy from time to time. Changes are posted in this
repository with an updated "Last Updated" date.

## Contact

If you have any questions about this Privacy Policy, please contact us:

- GitHub Issues: https://github.com/DigholeNet/vault/issues
