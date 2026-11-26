# Vault for Android

The Android client of the [Vault VPN](../../README.md) system — a secure,
high-performance VPN app built with Kotlin and modern Android architecture.
All protocol logic (handshake, peer discovery, path verification, heartbeat,
reconnect, crypto, data pump and diagnostics)
lives in the shared Rust core ([`vault-core`](../../core/) via
[`vault-bridge`](../bridge/), loaded through UniFFI/JNA). Kotlin provides UI,
configuration storage, Android lifecycle and VPN interface/socket callbacks. Diagnostic network binding lives in the Rust bridge.

Runtime requirement: **Android API 36 or newer**, matching the app's `minSdk`.
This is a device installation requirement, separate from the build SDK.

Features:

- Encrypted Supernode sessions with SPAKE2, X25519 and AEAD
- Automatic encrypted UDP direct paths to eligible VPN peers, with Supernode relay during discovery and after direct-path failure
- Automatic reconnection on network changes
- IPv4 and IPv6 support
- Displays tunnel addresses and the server-observed public/egress IP on the status screen
- Excludes server addresses from VPN routing to avoid routing loops

## Project structure

```
clients/android/
├── app/                          # Android application
│   ├── src/main/
│   │   ├── java/net/dighole/vault/
│   │   │   ├── MainActivity.kt    # Main entry point
│   │   │   ├── VaultVpnService.kt # VPN service implementation
│   │   │   ├── StatusFragment.kt  # Connection status UI
│   │   │   ├── ConfigureFragment.kt # Settings UI
│   │   │   ├── DiagnosticsViewModel.kt # Rust diagnostics adapter
│   │   │   └── DiagnosticsFragment.kt # Checks and logs UI
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

## Build and test

Requirements:

- Android SDK (API 36+) and an NDK. Point Gradle at the SDK via `ANDROID_HOME` or `sdk.dir` in `local.properties` (Android Studio writes it automatically). Set `ANDROID_NDK_HOME` to use a specific NDK; otherwise the build selects the highest installed version from the SDK's `ndk/` directory or legacy `ndk-bundle`. If no NDK is installed, AGP downloads **NDK 27.3.13750724**
- Any JDK 17+ to run Gradle — the compile JDK (24) is auto-provisioned via the foojay resolver
- Rust 1.98 or newer and `cargo-ndk` for the shared native library
- `protoc` on PATH (Debian/Ubuntu: `sudo apt-get install protobuf-compiler`;
  macOS: `brew install protobuf`)
- Rust Android targets: `aarch64-linux-android`, `armv7-linux-androideabi`,
  `x86_64-linux-android`

Gradle (wrapper) and Kotlin are pinned by the project — no manual install needed.

The app still requires API 36 or newer, but its Rust native API is selected
from the actual NDK sysroot: the highest API at or below `minSdk` available
for all three ABIs. For example, an NDK with libraries through API 35 uses
`cargo ndk --platform 35` for this API-36 app. This also handles API levels
with no separate native library directory. AGP's NDK version and path are
kept consistent, and AGP and cargo-ndk use the same NDK;
the build logs its path and selected API. Missing startup objects or Android
system libraries fail early with the exact missing path. Lowering the native
API does not lower the APK's installation requirement or disable unresolved-
symbol checks.

Run `./gradlew :vaultcore:testNdkPlatformSelection --no-daemon` to check
selection against older/newer NDK layouts, missing API directories and
incomplete installations. Android CI runs this before app tests and packaging.

```bash
git clone https://github.com/DigholeNet/vault.git
cd vault/clients/android

cargo install cargo-ndk --locked
rustup target add aarch64-linux-android armv7-linux-androideabi x86_64-linux-android

# Build debug APK
./gradlew :app:assembleDebug

# Build release APK (needs signing keys — see docs/releasing.md)
./gradlew :app:assembleRelease

# Install to device
adb install app/build/outputs/apk/debug/app-debug.apk
```

```bash
# Run unit tests
./gradlew test
```

Direct Gradle builds default to version `0.1.1` / code `1`. For versioned
release artifacts, run `scripts/package-android.sh` from the repository root;
it injects the workspace version and derived Android version code.
The script writes `dist/vault-android.apk`, retaining all three supported ABIs
with native debug information stripped. App packaging and Rust compilation
share the same NDK selection so the strip tool is available to both modules.
The original unstripped libraries remain in `vaultcore/src/main/jniLibs/`;
retain those from the matching build if diagnosing a release-native crash.

Debug builds need no signing keys and install alongside a release-build app
(`applicationId` gets a `.debug` suffix). To publish your own build, change
`applicationId` in `app/build.gradle.kts` and configure release signing —
see [docs/releasing.md](../../docs/releasing.md).

The APK includes the project LICENSE and NOTICE files.

Rust builds resolve Cargo from `CARGO` (an explicit executable path), then
`CARGO_HOME/bin`, then `PATH`, falling back to the default rustup location.
For example, set `CARGO=/opt/rust/bin/cargo` for a custom installation.

## Configuration

### Configuration options

- `Profile name`: Unique display name
- `Device ID`: Read-only peer identifier generated on the device
- `Host`: Vault server hostname or IP address; required
- `Port`: Server UDP port; defaults to 9527
- `Password`: Authentication password; required
- `MTU`: 1280–1427; empty uses link-based automatic sizing; a value caps the automatic result
- `IPv4 DNS`: Comma-separated IPv4 resolvers; empty uses `1.1.1.1,8.8.8.8`
- `IPv6 DNS`: Comma-separated IPv6 resolvers; empty uses
  `2001:4860:4860::8888,2001:4860:4860::8844`
- `Probe domains`: App-wide diagnostic setting on the Diagnostics page; comma-separated,
  empty uses `www.google.com,github.com,t.co`
- `Language`: App language; defaults to the system language and applies immediately

The server assigns the client's virtual IP address (IPv4, IPv6-only or dual-stack)
in the handshake response. Each DNS field accepts up to four addresses of its own family; probe domains
are limited to 32 entries.
Empty fields use the defaults above. IPv4-only tunnels apply only IPv4 DNS;
IPv6-only tunnels apply only IPv6 DNS; dual-stack tunnels combine both lists.
The Android resolver chooses which configured server to use; list order does
not guarantee query order. Both IPv4 and IPv6 resolvers can answer A and AAAA
queries. Settings for an unassigned family are retained but not applied.

The Configure page manages named Supernode profiles. Status selects the profile
for the next connection while disconnected. Old single-profile settings and
credentials are not migrated.

Credentials use Android Keystore encryption, with an app-private plaintext
fallback if encryption fails.

## Usage and deployment

The app has Status, Configure, Diagnostics, and About tabs. Connection changes
apply on the next connection.

## Network recovery

The client requires a protocol v2 Supernode. It resolves the configured host
on the selected non-VPN network and protects and binds the UDP socket to that
network. The same socket carries Supernode traffic and direct traffic. The
app can offer LAN candidates on Wi-Fi and Ethernet.

The Rust core keeps retrying with exponential backoff through offline periods.
A debounced network change wakes a recovering session and invalidates its old
direct paths. On reconnect, the app refreshes Supernode route exclusions for
the selected network and replaces the TUN configuration when needed. The
Supernode can relay traffic again after setup succeeds.

The UI stays in the reconnecting state until a fresh handshake configures the
tunnel and TUN I/O is ready. Traffic counters are preserved. User disconnect,
VPN permission revocation, and service destruction still cancel recovery and
close the session. Initial connection failures retain their existing behavior.

## Troubleshooting

Connection issues:

| Symptom | Possible cause | Solution |
|---|---|---|
| "Handshake failed" | Wrong password or protocol mismatch | Verify the password and use a v2 Supernode |
| "Cannot resolve host" | DNS issue | Try IP address instead of hostname |
| "Apply IP failed" | Server unreachable | Check network and firewall |

Latency and repeated reconnection should be investigated with Diagnostics and
Runtime Logs. The app does not expose a cipher-selection setting.

## Documentation

- [Shared diagnostics](../../docs/diagnostics-engine.md) — workflow, transport, trust and verification
- [Protocol specification](../../docs/protocol.md) — wire format, handshake, encryption
- [Performance](../../docs/performance.md) — protocol costs, timers and measurement guidance
- [Releasing](../../docs/releasing.md) — release process and signing keys
- [Changelog](../../CHANGELOG.md) — version history and release notes
- [Privacy Policy](../../PRIVACY.md) — how we handle your data
- [Security Policy](../../SECURITY.md) — reporting vulnerabilities
- [Contributing Guide](../../CONTRIBUTING.md) — how to contribute

## License

MIT — see [LICENSE](../../LICENSE)
