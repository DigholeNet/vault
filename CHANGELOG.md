# Changelog

Notable changes to Vault are recorded here using the
[Keep a Changelog](https://keepachangelog.com/en/1.0.0/) structure.

## [0.1.1] - Unreleased

### Added

- Minimal statically linked musl binary archives for Linux edge and supernode on amd64 and arm64

## [0.1.0] - 2026-11-10

Initial public release.

### Added

- Shared Rust VPN core, Linux supernode, and Linux, Android, iOS and macOS clients
- SPAKE2 password authentication, ephemeral X25519 key exchange and HKDF-SHA256 session keys
- AES-128-GCM, AES-256-GCM and ChaCha20-Poly1305 with automatic cipher selection based on measured speed
- Authenticated packet types, role-separated counter nonces, data replay protection and handshake confirmation
- IPv4/IPv6 address assignment, lease management and traffic relay through the supernode
- Shared client heartbeat, IPv4/IPv6 connection racing, automatic recovery with exponential backoff and traffic statistics
- Linux route cleanup, recovery of Edge-owned routes after crashes and physical-network switching
- Linux automatic DNS through systemd-resolved's local stub; other resolver setups require manual configuration without rewriting `/etc/resolv.conf`
- Exclusive Linux TUN ownership and interface-scoped reverse-path filtering
- Dedicated `vault` accounts for packaged Linux services, privilege changes before background threads start and account-scoped Polkit authorization for systemd-resolved DNS management
- Separate Linux IPv4/IPv6 DNS fields, with two IPv6 resolvers and one IPv4 resolver selected for dual-stack tunnels
- Scoped supernode firewall/NAT rules, automatic host forwarding and IPv6 Router Advertisement preservation
- Android and Apple connection settings, diagnostics and runtime log interfaces
- Separate Apple IPv4/IPv6 DNS fields and IPv6-only diagnostic interface binding
- Android IPv4, IPv6-only and dual-stack tunnel configuration, with separate IPv4/IPv6 DNS settings, per-family defaults and migration of existing DNS settings
- 16 KB page alignment for 64-bit Android native libraries
- Shared mobile DNS, TCP, HTTPS, ICMP and route diagnostics, with Rust-owned TLS verification and platform network binding
- Android Keystore-backed credential encryption with an app-private plaintext fallback; Apple Keychain storage with a password copy in the OS VPN profile
- English and Simplified Chinese mobile interfaces; Traditional Chinese, Japanese and Spanish additionally on Android
- Apple apps for iOS 18.5+ and macOS 15.5+; the shared Swift package supports iOS 18+ and macOS 15+
- Debian amd64/arm64, Android APK and Apple packaging scripts, plus release automation that excludes Ad Hoc iOS IPAs from public artifacts
- Rust, Android and Apple CI checks required before release packaging, parser fuzz targets and isolated Linux network tests
- Single-stack-aware shared diagnostics with bypass detection for either unassigned address family
- Shared Android release-version encoding with ordered alpha, beta, rc and final version codes
- Packaged LICENSE/NOTICE resources
- Explicit manpage generation for Linux packaging, independent of Cargo caches
- Website version, download links and Android QR code synchronized with stable releases
- Contributor, security, privacy, protocol, diagnostics and release documentation

[0.1.1]: https://github.com/DigholeNet/vault/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/DigholeNet/vault/releases/tag/v0.1.0
