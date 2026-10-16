# Changelog

All notable changes to Vault are documented in this file, grouped by platform.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [1.0.0] - 2026-10-16

### Security

- Handshake authentication rebuilt on SPAKE2 (password-authenticated key exchange): no password-derived verifier ever crosses the wire, so captured handshakes do not enable offline dictionary attacks; an active attacker gets exactly one password guess per handshake, and the supernode temporarily bans source IPs after repeated handshake failures
- Session keys are derived with HKDF-SHA256 from the X25519 shared secret (previously truncated and used directly as the AEAD key), salted with the PAKE handshake key and bound to both sides' ephemeral public keys
- Root-privileged system configuration commands (`sysctl`, `iptables`, `ip route`) now run through argv arrays instead of `sh -c` string interpolation, eliminating shell injection risk
- A poisoned mutex no longer cascades into a process-wide panic in the decrypt hot path or client session loops
- AEAD nonces switched from 56-bit random values to role-separated 64-bit counters, eliminating nonce reuse under a session key
- Data channel gains replay protection: counters double as sequence numbers checked against a 2048-bit sliding window on receive
- Handshake messages carry timestamps (±120s acceptance window, strictly increasing per client on the server), and responses echo the request's ephemeral public key and carry a PAKE-keyed confirmation MAC, making captured handshakes unreplayable
- The unauthenticated REJECTED packet no longer tears down a client session on its own; the client probes the server with a ping first and reconnects only if it stays silent
- The daemon control sockets (`/run/supernode.socket`, `/run/edge.socket`) are not world-writable (0o660) and are per-service, so the two daemons no longer share one path

### Features

- VPN Connection: One-tap connect/disconnect to Vault server
- Dual Stack: IPv4 and IPv6 network support
- Auto Reconnect: Automatic recovery on network changes
- X25519 key exchange (perfect forward secrecy)
- AES-128-GCM / AES-256-GCM / ChaCha20-Poly1305 with automatic cipher negotiation
- Traffic Stats: Real-time upload/download speed and data usage
- Server Config: Customizable host, port, password, and DNS
- Multi-language: Simplified Chinese, Traditional Chinese, English, Japanese, Spanish

### Platform Support

- Android
- iOS 18+ and macOS 15+
- Linux

[Unreleased]: https://github.com/DigholeNet/vault/compare/v1.0.0...HEAD
[1.0.0]: https://github.com/DigholeNet/vault/releases/tag/v1.0.0
