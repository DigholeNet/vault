# Security Policy

## Supported Versions

We release security updates for the following versions:

| Version | Supported          |
|---------|--------------------|
| 1.0.x   | :white_check_mark: |
| < 1.0.0 | :x:                |

## Reporting a Vulnerability

We take the security of Vault seriously. If you believe you have found a security
vulnerability, please report it to us responsibly.

**Please DO NOT report security vulnerabilities through public GitHub issues.**

Instead, report via GitHub Private Vulnerability Reporting:

- https://github.com/DigholeNet/vault/security/advisories

### What to Include

When reporting a vulnerability, please include:

1. **Description**: Clear description of the vulnerability
2. **Impact**: What could an attacker achieve by exploiting this?
3. **Steps to Reproduce**: Detailed steps to reproduce the issue
4. **Affected Versions**: Which versions are affected
5. **Mitigation**: Any suggested fixes or mitigations (optional)

### Response Timeline

We aim to respond to security reports within:

- **48 hours**: Initial acknowledgment
- **7 days**: Assessment and prioritization
- **30 days**: Fix implementation and testing
- **90 days**: Public disclosure (with reporter's consent)

## Security Model

Vault is implemented in Rust. All protocol and cryptographic logic lives in the shared
`core/` crate (`vault-core`); clients and the supernode server exchange messages over a
custom UDP-based protocol.

Cryptographic primitives are provided by the [ring](https://github.com/briansmith/ring)
library:

| Component              | Algorithm                            | Purpose                  |
|------------------------|--------------------------------------|--------------------------|
| Key Exchange           | X25519 (Curve25519)                  | ECDH key agreement       |
| Data Encryption        | AES-128-GCM / AES-256-GCM            | Symmetric encryption     |
| Alternative Encryption | ChaCha20-Poly1305                    | Mobile/ARM-optimized     |
| Password Authentication| SPAKE2 (PAKE, Ed25519 group)         | Handshake authentication |
| Key Derivation         | HKDF-SHA256 (over X25519 + PAKE key) | Session keys             |
| Random Generation      | ring `SystemRandom`                  | Key generation           |

Security properties:

- **Perfect Forward Secrecy**: A fresh ephemeral X25519 key pair is generated for every
  handshake, so session keys are not recoverable from long-term secrets.
- **Authenticated Encryption**: Every data packet carries an AEAD tag; tampered
  ciphertext is rejected before parsing.
- **Replay Protection**: AEAD nonces are role-separated 64-bit counters (never reused
  under a session key) that double as sequence numbers, checked against a 2048-bit
  sliding window on receive. Handshake messages carry timestamps accepted
  within a ±120 s window and strictly increasing per client on the server, and
  responses echo the request's ephemeral public key and carry a PAKE-keyed
  confirmation MAC — captured handshake traffic cannot be replayed.
- **Handshake Authentication**: Both sides run SPAKE2, a password-authenticated key
  exchange (PAKE). No password-derived verifier ever crosses the wire, so a passive
  observer cannot verify password guesses offline; an active attacker gets exactly
  one guess per handshake, and the supernode temporarily bans source IPs after
  repeated handshake failures.
  The server proves it holds the password with a confirmation MAC before the client
  sends any traffic, and the PAKE output salts the session-key HKDF, binding the
  encrypted channel to the authenticated exchange.

## Known Limitations

We believe in being upfront about the weak spots of the current protocol. These are
known, accepted limitations of the 1.0.x protocol:

1. **Symmetric, network-level trust model.** Clients and the supernode authenticate to
   each other with the *same* password-derived key. Anyone who holds the password can
   therefore impersonate the server to clients (and vice versa) within that network.
   Treat the password as a network-wide shared secret: do not reuse it across
   deployments, and do not give it to anyone you would not trust to run the network.

2. **Passwords remain guessable online in principle.** PAKE removes the offline
   dictionary attack entirely, but an active attacker can still test one password
   per handshake against the live supernode (source IPs are banned after repeated
   failures). A weak
   human-chosen password can eventually fall to a patient online attack, so use a
   strong, high-entropy password.

3. **Clock-synchronized handshake freshness.** Replay protection for handshakes relies
   on timestamps, so clients and servers need roughly correct clocks
   (±120 s, NTP is sufficient). Within that window, an attacker who races a victim's
   first handshake can briefly blackhole the victim's traffic; the victim's
   reconnect then wins and the attacker's stale timestamps are rejected.

4. **Android credential storage can fall back to plaintext.** The Android client keeps
   server passwords in Android Keystore–backed encrypted storage, but deliberately
   falls back to unencrypted DataStore preferences on devices where the Keystore is
   unavailable, so the app remains usable
   (`clients/android/app/src/main/java/net/dighole/vault/data/VaultConfigPreferences.kt`).
   On such devices, stored passwords are protected only by Android's app sandbox.

5. **The REJECTED packet is unauthenticated.** When the supernode no longer recognizes
   a client address it answers with REJECTED, a single-byte plaintext packet. An
   on-path attacker can therefore forge it to disrupt a session. The client mitigates
   this by not trusting REJECTED on its own: it probes the server with an encrypted
   ping and reconnects only if no authenticated packet arrives within 3 seconds.
   A determined on-path attacker can still force a reconnect by combining forged
   REJECTED packets with packet dropping, but cannot impersonate the server or
   decrypt/inject tunnel traffic this way.

## Security Best Practices for Users

- Use strong, unique passwords for each VPN network you deploy (see limitation 2)
- Keep clients and the supernode updated to receive security patches
- Restrict network access to the supernode's UDP port where possible (firewall rules)
- Only connect to VPN servers operated by parties you trust — all traffic is relayed
  through the supernode by design

## Security Updates

Security updates will be released as:

- **Critical**: Immediate patch release
- **High**: Next scheduled release (within 2 weeks)
- **Medium**: Bundled with next feature release
- **Low**: Addressed in regular development cycle

## Acknowledgments

We thank the security researchers who have responsibly disclosed vulnerabilities in the
past.
