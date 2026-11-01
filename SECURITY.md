# Security Policy

## Supported Versions

There are no formal releases yet. `0.1.0` is the current development version.
Security fixes currently land on `main`; development snapshots have no supported
release series or backport guarantee. A supported-version table will be added
when the first version is released.

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

X25519, AEAD, HKDF, confirmation MACs and their random generation use
[ring](https://github.com/briansmith/ring). SPAKE2 uses the
[spake2](https://github.com/RustCrypto/PAKEs) crate with its Ed25519 group
implementation; it is not implemented by ring:

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
- **Authenticated Encryption**: Every encrypted packet carries an AEAD tag covering
  its ciphertext and the outer packet type (associated data). Changing a heartbeat
  into a CLOSE packet therefore fails authentication before payload parsing.
- **Replay Protection**: AEAD nonces are role-separated 64-bit counters (never reused
  under a session key) that double as sequence numbers, checked against a 2048-bit
  sliding window on receive. Handshake messages carry timestamps accepted
  within a ±120 s window. The server records authenticated client IDs and
  ephemeral public keys for 600 s after confirmation to reject repeats, and
  responses echo the request's ephemeral public key and carry a PAKE-keyed
  confirmation MAC — captured handshake traffic cannot be replayed.
- **Handshake Authentication**: Both sides run SPAKE2, a password-authenticated key
  exchange (PAKE). No password-derived verifier ever crosses the wire, so a passive
  observer cannot verify password guesses offline; an active attacker gets exactly
  one guess per handshake. The supernode rate-limits INIT requests and separately
  bans source IPs after repeated invalid encrypted confirmations.
  The server proves it holds the password with a confirmation MAC before the client
  sends any traffic, and the PAKE output salts the session-key HKDF, binding the
  encrypted channel to the authenticated exchange.

## Known Limitations

We believe in being upfront about the weak spots of the current protocol. These are
known limitations of the current development protocol:

1. **Symmetric, network-level trust model.** Clients and the supernode authenticate to
   each other with the *same* password-derived key. Anyone who holds the password can
   therefore impersonate the server to clients (and vice versa) within that network.
   Treat the password as a network-wide shared secret: do not reuse it across
   deployments, and do not give it to anyone you would not trust to run the network.

2. **Passwords remain guessable online in principle.** PAKE removes the offline
   dictionary attack entirely, but an active attacker can still test one password
   per handshake against the live supernode. The per-IP INIT limit is 60 requests
   per 60 seconds. A guess can be checked against the server confirmation MAC
   without sending an encrypted confirmation; abandoned attempts do not count
   toward authentication-failure bans. Those bans cover repeated invalid
   encrypted confirmations, not every wrong-password guess. A weak human-chosen
   password can eventually fall to an online attack, so use a strong,
   high-entropy password.

3. **Clock-synchronized handshake freshness.** Replay protection for handshakes relies
   on timestamps, so clients and servers need roughly correct clocks
   (±120 s, NTP is sufficient). Unauthenticated requests can consume bounded
   pending slots and temporary address reservations, but cannot commit replay
   records, revoke established leases, or replace established sessions without
   proving possession of the session key.

4. **Android credential storage can fall back to plaintext.** The Android client keeps
   server passwords in Android Keystore–backed encrypted storage, but deliberately
   falls back to unencrypted DataStore preferences when encrypted credential storage
   fails, so the app remains usable
   (`clients/android/app/src/main/java/net/dighole/vault/data/VaultConfigPreferences.kt`).
   Fallback entries are migrated and removed after encrypted storage recovers.
   Until then, stored passwords are protected only by Android's app sandbox.

5. **The REJECTED packet is unauthenticated.** When the supernode no longer recognizes
   a client address it answers with REJECTED, a single-byte plaintext packet. An
   on-path attacker can therefore forge it to disrupt a session. The client mitigates
   this by not trusting REJECTED on its own: it probes the server with an encrypted
   ping and reconnects only if no authenticated packet arrives within 3 seconds.
   A determined on-path attacker can still force a reconnect by combining forged
   REJECTED packets with packet dropping, but cannot impersonate the server or
   decrypt/inject tunnel traffic this way.

6. **Handshake rate limiting and banning can be weaponized with spoofed source IPs.**
   INIT packets are unauthenticated UDP datagrams, and the supernode's rate limiting
   and failure-based banning key on the source IP. An attacker who can spoof source
   addresses can consume a victim IP's INIT rate-limit budget with spoofed requests.
   INIT flooding alone does not count as failed authentication: abandoned and
   expired attempts release their reservations without a failure penalty.
   Failure-based bans require repeated invalid encrypted confirmations against
   pending sessions; a spoofing attacker able to target those sessions can also
   cause failures for the victim IP. Separately, the 32 pending-handshake slots
   can be exhausted with spoofed INITs, denying service to legitimate clients
   until entries expire. These controls are shared by clients behind one NAT.
   Deployments that face untrusted networks should
   mitigate this at the firewall by restricting which source addresses may reach the
   supernode's UDP port.

## Security Best Practices for Users

- Use strong, unique passwords for each VPN network you deploy (see limitation 2)
- Keep clients and the supernode updated to receive security patches
- Restrict network access to the supernode's UDP port where possible (firewall rules)
- Only connect to VPN servers operated by parties you trust — tunnel traffic is
  decrypted and relayed through the supernode by design
- Review [traffic protection scope](README.md#traffic-routing-and-protection-scope):
  server-route exclusions, unassigned address families and OS teardown can leave
  traffic outside the VPN. Vault has no cross-platform persistent kill switch

## Security Updates

Once formal releases begin, the target security-update schedule is:

- **Critical**: Immediate patch release
- **High**: Next scheduled release (within 2 weeks)
- **Medium**: Bundled with next feature release
- **Low**: Addressed in regular development cycle

## Acknowledgments

We thank the security researchers who have responsibly disclosed vulnerabilities in the
past.
