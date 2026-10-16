# Privacy Policy

**Last Updated:** October 13, 2026

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

- Store your VPN configuration (host, port, password), DNS preferences, and a randomly
  generated device ID **locally on your device only**
- Transmit nothing to the software authors
- Integrate no third-party analytics, advertising, or tracking services

On Apple platforms the password is stored in the system Keychain; on Android it is
protected by the Android Keystore (with a plaintext fallback only on devices where the
Keystore is unavailable).

### Server (supernode)

The supernode does not inspect, log, or store traffic content, browsing history,
traffic destinations, or DNS queries. Its runtime logs do include **connection
metadata** needed to operate and debug the service:

- Client source IP address and port
- The tunnel IP address assigned to each client
- Handshake and disconnect events with timestamps

These logs are written to the server's own log directory (`/var/log/vault/` by
default), are controlled entirely by the server operator, and their verbosity depends
on the configured log level. The software sends none of this anywhere else.

## Network Permissions

The Android app requires the following permissions:

- **INTERNET**: Required to establish VPN connections
- **ACCESS_NETWORK_STATE**: Required to monitor network changes
- **BIND_VPN_SERVICE**: Required to create and manage the VPN tunnel
- **FOREGROUND_SERVICE**: Required to maintain the VPN connection in the background

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
- Delete all local data by uninstalling the application
- Audit exactly what the software does — the complete source code is available in
  this repository

For data held by a server you connect to, contact that server's operator.

## Changes to This Privacy Policy

We may update this Privacy Policy from time to time. Changes are posted in this
repository with an updated "Last Updated" date.

## Contact

If you have any questions about this Privacy Policy, please contact us:

- GitHub Issues: https://github.com/DigholeNet/vault/issues
