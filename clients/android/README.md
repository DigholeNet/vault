# Vault for Android

The Android client of the [Vault VPN](../../README.md) system — a secure,
high-performance VPN app built with Kotlin and modern Android architecture.
All protocol logic (handshake, heartbeat, reconnect, crypto, data pump)
lives in the shared Rust core ([`vault-core`](../../core/) via
[`vault-bridge`](../bridge/), loaded through UniFFI/JNA); this app is a thin
platform adapter.

Features:

- Encrypted client-to-server tunnels (SPAKE2 PAKE handshake, X25519 key exchange, AEAD ciphers); the supernode decrypts and relays traffic
- Automatic reconnection on network changes
- IPv4 and IPv6 support
- Split tunneling for server traffic

## Network recovery

Once connected, the VPN keeps its TUN interface and native session through long
offline periods. The Rust core retries with exponential backoff; Android no
longer stops recovery after 120 seconds. A debounced network change also wakes
an already recovering session, bypassing the current retry delay. Repeated
watchdog checks remain deduplicated so they do not interrupt handshakes.

The UI stays in the reconnecting state until a fresh handshake configures the
tunnel and TUN I/O is ready. Traffic counters are preserved. User disconnect,
VPN permission revocation, and service destruction still cancel recovery and
close the session. Initial connection failures retain their existing behavior.

## Architecture

```
┌────────────────────────────────────────────┐
│                 Android App                 │
│  MainActivity ─ StatusFragment (status UI)  │
│               ├ ConfigureFragment (config)  │
│               └ AboutFragment               │
│                      │ bind/controls        │
│               VaultVpnService (VpnService)  │
└──────────────────────┼─────────────────────┘
                       ▼
              vaultcore module
              Edge.kt (Kotlin wrapper)
                       │ UniFFI / JNA
                       ▼
        vault-bridge → vault-core (Rust)
        handshake · heartbeat · reconnect
        crypto · data pump
                       │ encrypted UDP
                       ▼
                  supernode (server)
```

Data flow: the app starts `VaultVpnService`, which creates an `Edge` session
over a protected socket; after the handshake completes the service
establishes the VPN interface and pumps packets between the TUN fd and the
Rust session.

## Build

Requirements:

- Android SDK (API 36+) and an NDK. Point Gradle at the SDK via `ANDROID_HOME` or `sdk.dir` in `local.properties` (Android Studio writes it automatically). Set `ANDROID_NDK_HOME` to use a specific NDK; otherwise the build selects the highest installed version from the SDK's `ndk/` directory or legacy `ndk-bundle`. If no NDK is installed, AGP downloads **NDK 27.3.13750724**
- Any JDK 17+ to run Gradle — the compile JDK (24) is auto-provisioned via the foojay resolver
- Rust toolchain + `cargo-ndk` (`cargo install cargo-ndk`) for the shared `vault-core` / `vault-bridge` native library

Gradle (wrapper) and Kotlin are pinned by the project — no manual install needed.

```bash
git clone https://github.com/DigholeNet/vault.git
cd vault/clients/android

# Build debug APK
./gradlew :app:assembleDebug

# Build release APK (needs signing keys — see docs/releasing.md)
./gradlew :app:assembleRelease

# Install to device
adb install app/build/outputs/apk/debug/app-debug.apk
```

Debug builds need no signing keys and install alongside the release app
(`applicationId` gets a `.debug` suffix). To publish your own build, change
`applicationId` in `app/build.gradle.kts` and configure release signing —
see [docs/releasing.md](../../docs/releasing.md).

## Configuration

Server settings in the app:

| Setting | Description | Default |
|---|---|---|
| Host | Vault server hostname or IP | Required |
| Port | Server UDP port | 9527 |
| Password | Authentication password | Required |
| DNS | Comma-separated DNS servers | 1.1.1.1,8.8.8.8 |

The server assigns the client's virtual IP address (IPv4 and/or IPv6) in the
handshake response.

Credentials are encrypted with an Android Keystore key; their ciphertext is
committed in the same DataStore transaction as host, port, and DNS settings.
If encryption fails, that same transaction stores the existing app-private
plaintext fallback. Legacy SharedPreferences credentials are removed only
after the new record commits. Reads, migrations, and writes are serialized by
DataStore; failed or cancelled commits leave the previous configuration intact.

## Troubleshooting

Connection issues:

| Symptom | Possible cause | Solution |
|---|---|---|
| "Handshake failed" | Wrong password | Verify server password |
| "Cannot resolve host" | DNS issue | Try IP address instead of hostname |
| "Apply IP failed" | Server unreachable | Check network and firewall |

Performance issues:

| Symptom | Diagnosis | Solution |
|---|---|---|
| Slow speeds | Wrong algorithm | Enable AES-GCM for hardware acceleration |
| High latency | Distant server | Choose closer server location |
| Battery drain | Frequent reconnection | Check network stability |

## Development

Project structure:

```
clients/android/
├── app/                          # Android application
│   ├── src/main/
│   │   ├── java/net/dighole/vault/
│   │   │   ├── MainActivity.kt    # Main entry point
│   │   │   ├── VaultVpnService.kt # VPN service implementation
│   │   │   ├── StatusFragment.kt  # Connection status UI
│   │   │   └── ConfigureFragment.kt # Settings UI
│   │   └── res/                  # Layouts, drawables, values
│   └── build.gradle.kts
├── vaultcore/                    # Kotlin wrapper over the Rust core (UniFFI)
│   └── src/main/java/net/dighole/vaultcore/
│       ├── Edge.kt               # Main networking component (bridges to vault-core)
│       ├── PeerId.kt             # Peer identifier type
│       └── LogThrottle.kt        # Rate limiter for high-frequency log statements
└── build.gradle.kts
```

Code style: Kotlin coding conventions, 4-space indentation, max line length
120, KDoc for public APIs.

```bash
# Run unit tests
./gradlew test

# Run instrumentation tests
./gradlew connectedAndroidTest
```

## Documentation

- [Protocol specification](../../docs/protocol.md) — wire format, handshake, encryption
- [Performance measurements](../../docs/performance.md) — indicative benchmarks
- [Releasing](../../docs/releasing.md) — release process and signing keys
- [Changelog](../../CHANGELOG.md) — version history and release notes
- [Privacy Policy](../../PRIVACY.md) — how we handle your data
- [Security Policy](../../SECURITY.md) — reporting vulnerabilities
- [Contributing Guide](../../CONTRIBUTING.md) — how to contribute

## License

MIT — see [LICENSE](../../LICENSE)
