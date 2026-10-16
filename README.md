# Vault

[![Rust checks](https://github.com/DigholeNet/vault/actions/workflows/rust.yml/badge.svg)](https://github.com/DigholeNet/vault/actions/workflows/rust.yml)
[![Release](https://github.com/DigholeNet/vault/actions/workflows/release.yml/badge.svg)](https://github.com/DigholeNet/vault/actions/workflows/release.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

Vault is a cross-platform VPN system: a **single Rust protocol core**, **three client platforms** (Apple / Android / Linux), and a **Linux server** (supernode). Star topology — all traffic is relayed through the server over encrypted tunnels.

## Architecture

```
                        ┌────────────────────────────┐
                        │         supernode          │
                        │        (supernode/)        │
                        │ handshake · IP assignment  │
                        │      · traffic relay       │
                        └─────────────┬──────────────┘
                                      │  encrypted UDP tunnels
            ┌─────────────────────────┼─────────────────────────┐
            │                         │                         │
   ┌────────┴────────┐      ┌────────┴────────┐       ┌────────┴────────┐
   │   iOS / macOS   │      │     Android     │       │      Linux      │
   │ (clients/apple) │      │(clients/android)│       │ (clients/linux) │
   └─────────────────┘      └─────────────────┘       └─────────────────┘
```

### Design principles

**1. One implementation of the protocol and security logic.**
`core/` (vault-core) owns all protocol behavior: packet encoding (protobuf), SPAKE2 password-authenticated key exchange (PAKE — no password-derived verifier crosses the wire, so captured handshakes do not enable offline dictionary attacks), X25519 ECDH key agreement with HKDF-derived session keys bound to the PAKE exchange, AEAD encryption (AES-128/256-GCM, ChaCha20-Poly1305 — negotiated by measured speed) with counter nonces and a sliding replay window, heartbeat keepalive (10s interval / 30s timeout), exponential-backoff reconnect (1s→60s), and traffic statistics. The entire client session state machine lives in `ClientSession`, so all platforms behave identically and protocol evolution happens in exactly one place.

**2. Clients are thin platform adapters.**
Each client only handles: TUN fd I/O, route/DNS configuration, OS VPN API integration, config persistence, and UI. Mobile platforms bridge to the core through UniFFI:

| Client | Bridge | Artifact | Platform work |
|---|---|---|---|
| Apple | `vault-bridge` (staticlib, UniFFI) | XCFramework + Swift bindings | NetworkExtension / PacketTunnelProvider |
| Android | `vault-bridge` (cdylib, UniFFI) | jniLibs + Kotlin bindings | VpnService / network-change listening |
| Linux | none (links core directly) | binary + deb/systemd | TUN / route / DNS setup and rollback |

Both mobile platforms share a single bridge crate (`clients/bridge/`): one UniFFI interface definition generates both the Kotlin and Swift bindings.

**3. The server is Linux-only by design.**
The supernode reuses the core's epoll, TUN, peer management and protocol implementation; it only adds the address pool (CIDR allocation with leases and recycling), NAT/forwarding setup, and the relay loop.

### Module map

| Directory | Package | Role |
|---|---|---|
| `core/` | vault-core | Protocol, crypto, client session, TUN/epoll/peer primitives |
| `supernode/` | supernode | Linux server: handshake handling, IP assignment, traffic relay |
| `clients/apple/` | — | iOS/macOS app (SwiftUI + NetworkExtension) |
| `clients/bridge/` | vault-bridge | Mobile UniFFI bridge (shared by Android + Apple) |
| `clients/android/` | — | Android app (Kotlin + VpnService) |
| `clients/linux/` | edge | Linux client (TUN/route/DNS adapter + systemd) |

## Quick start

### For users — prebuilt artifacts

Tagged releases (`v*`) publish the Linux server/client debs and the signed
Android APK to
[Releases](https://github.com/DigholeNet/vault/releases). (The Apple apps are
not distributed prebuilt yet — build from source, see below.)

Minimal setup: one Linux server as the supernode, one client.

**1. Server (Linux)** — install the supernode deb and write
`/etc/vault/supernode.toml`:

```toml
password = "a-long-random-password"  # SPAKE2 security depends on its entropy
port = 9527
iface = "vpn"
ipv4 = "192.168.10.0/24"
# ipv6 = "fd00::/96"  # optional IPv6 pool
```

```bash
sudo systemctl enable --now supernode
```

Open UDP port 9527 on the firewall. The server takes the first pool address
(`192.168.10.1`) for its own TUN device.

**2. Linux client** — install the edge deb and write `/etc/vault/edge.toml`:

```toml
password = "a-long-random-password"  # must match the server
host = "your.server.ip"
port = 9527
iface = "vpn0"
dns = ["1.1.1.1", "8.8.8.8"]
storage = "/var/lib/vault/storage.dat"
```

```bash
sudo systemctl enable --now edge
```

The client is assigned an address from the pool (e.g. `192.168.10.2`);
`ping 192.168.10.1` verifies the tunnel.

**3. Android** — install the APK, enter the same host, port and password,
and toggle connect.

### For developers — build from source

```bash
git clone https://github.com/DigholeNet/vault.git && cd vault
```

Prerequisites: a Rust toolchain (`rust-toolchain.toml` pins the channel and
targets) and `protoc` (the protobuf build script in `core/`). The repository
root is a Cargo workspace (edition 2024); on macOS the default members are
the portable crates (core + bridge), the Linux-only supernode and Linux
client must be built explicitly.

**Linux server / client:**

```bash
cargo build --workspace                    # Linux: everything (macOS: plain `cargo build`)
cargo test -p vault-core --features test   # protocol integration test (mock server)
cargo deb -p edge                    # Linux: deb package (also: -p supernode)
```

**Android** — needs the Android SDK + NDK and `cargo-ndk`
(see [clients/android/README.md](clients/android/README.md)); then:

```bash
cd clients/android && ./gradlew :app:assembleDebug
```

Gradle locates the SDK via the `ANDROID_HOME` environment variable or
`sdk.dir` in `local.properties` (Android Studio creates that file
automatically on first open; CLI-only setup):

```properties
# clients/android/local.properties — adjust to your SDK location
# (macOS default shown; Linux: ~/Android/Sdk)
sdk.dir=/Users/you/Library/Android/sdk
```

Debug builds need no signing keys and coexist with a released app
(`.debug` applicationId suffix). To publish your own build, change
`applicationId` in `app/build.gradle.kts` and set up signing (see
[docs/releasing.md](docs/releasing.md)).

**Apple (iOS/macOS)** — the XCFramework and Swift bindings are generated
artifacts; build them once after cloning:

```bash
cd clients/apple && VaultCore/Scripts/build-xcframework.sh && open Vault.xcodeproj
```

Simulator builds work without an Apple Developer account. Device and
distribution builds are signed by your own team, and the shipped bundle IDs
and app group are registered under the Dighole team (another account cannot
provision them), so point them at your own identifiers first:

```bash
# clients/apple/Config/Shared.xcconfig
APP_GROUP_ID = group.com.example.vault   # app group registered in your account
APP_BUNDLE_ID_PREFIX = com.example.Vault
```

Then set `DEVELOPMENT_TEAM` in Xcode (or pass `TEAM_ID` to
`scripts/package-apple.sh`). Details:
[Building Your Own Fork](clients/apple/README.md#building-your-own-fork).

## Packaging

One-command local packaging (artifacts land in `dist/`):

```bash
TEAM_ID=ABCDE12345 scripts/package-all.sh     # all platforms
scripts/package-android.sh    # signed Android APK only
scripts/package-linux.sh      # Linux debs only (cross-built via rust-lld on macOS)
TEAM_ID=ABCDE12345 scripts/package-apple.sh   # Apple only (iOS IPA + macOS app)
```

Apple packaging requires an Apple Developer team; tagging `v*` triggers the
release workflow. Release mechanics, signing keys, and provisioning profiles:
[docs/releasing.md](docs/releasing.md).

## Documentation

- Component READMEs: [supernode](supernode/README.md) ·
  [Apple client](clients/apple/README.md) ·
  [Android client](clients/android/README.md) ·
  [Linux client](clients/linux/README.md) ·
  [UniFFI bridge](clients/bridge/README.md)
- [docs/protocol.md](docs/protocol.md) — wire protocol: message types, handshake, encryption format
- [docs/performance.md](docs/performance.md) — indicative performance measurements
- [docs/releasing.md](docs/releasing.md) — release process and signing keys

## License

MIT — see [LICENSE](LICENSE)
