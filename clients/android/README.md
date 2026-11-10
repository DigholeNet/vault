# Vault for Android

The Android client of the [Vault VPN](../../README.md) system — a secure,
high-performance VPN app built with Kotlin and modern Android architecture.
All protocol logic (handshake, heartbeat, reconnect, crypto, data pump, diagnostics)
lives in the shared Rust core ([`vault-core`](../../core/) via
[`vault-bridge`](../bridge/), loaded through UniFFI/JNA). Kotlin provides UI,
configuration storage, Android lifecycle and VPN interface/socket callbacks. Diagnostic network binding lives in the Rust bridge.

Runtime requirement: **Android API 36 or newer**, matching the app's `minSdk`.
This is a device installation requirement, separate from the build SDK.

Features:

- Encrypted client-to-server tunnels (SPAKE2 PAKE handshake, X25519 key exchange, AEAD ciphers); the supernode decrypts and relays traffic
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

# Run instrumentation tests
./gradlew connectedAndroidTest
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

- `Device ID`: Read-only peer identifier generated on the device
- `Host`: Vault server hostname or IP address; required
- `Port`: Server UDP port; defaults to 9527
- `Password`: Authentication password; required
- `MTU`: 1280–1427; empty uses link-based automatic sizing
- `IPv4 DNS`: Comma-separated IPv4 resolvers; empty uses `1.1.1.1,8.8.8.8`
- `IPv6 DNS`: Comma-separated IPv6 resolvers; empty uses
  `2001:4860:4860::8888,2001:4860:4860::8844`
- `Probe domains`: Comma-separated diagnostic domains; empty uses
  `www.google.com,github.com,t.co`
- `Language`: App language; defaults to the system language and applies immediately

The server assigns the client's virtual IP address (IPv4, IPv6-only or dual-stack)
in the handshake response. Each DNS field accepts up to four addresses of its own family; probe domains
are limited to 32 entries.
Empty fields use the defaults above. IPv4-only tunnels apply only IPv4 DNS;
IPv6-only tunnels apply only IPv6 DNS; dual-stack tunnels combine both lists.
The Android resolver chooses which configured server to use; list order does
not guarantee query order. Both IPv4 and IPv6 resolvers can answer A and AAAA
queries. Settings for an unassigned family are retained but not applied.

Existing combined DNS settings migrate into the two fields by address family,
preserving custom values and their order within each family. The migration
commits both fields and removes the old key in one DataStore transaction; a
failed commit keeps the old record intact. Each field can be cleared independently
to restore its defaults. Connection-setting changes apply on the next connection.

Credentials are encrypted with an Android Keystore key; their ciphertext is
committed in the same DataStore transaction as host, port, and DNS settings.
If encryption fails, that same transaction stores the existing app-private
plaintext fallback. Legacy SharedPreferences credentials are removed only
after the new record commits. Reads, migrations, and writes are serialized by
DataStore; failed or cancelled commits leave the previous configuration intact.

## Usage and deployment

The four tabs follow the iOS client: Status, Configure, Diagnostics, and About.
Android uses Material 3 controls and light/dark surfaces. Configuration groups
follow iOS, including separate IPv4 and IPv6 DNS fields; language selection
lives in Configure. Saving keeps the page open, and connection changes apply on the next connection. Drafts
survive tab switches, rotation, and language changes.

## Network recovery

Once connected, the VPN keeps its TUN interface and native session through long
offline periods. The Rust core retries with exponential backoff until recovery
or explicit teardown. A debounced network change also wakes
an already recovering session, bypassing the current retry delay. Repeated
watchdog checks remain deduplicated so they do not interrupt handshakes.

The UI stays in the reconnecting state until a fresh handshake configures the
tunnel and TUN I/O is ready. Traffic counters are preserved. User disconnect,
VPN permission revocation, and service destruction still cancel recovery and
close the session. Initial connection failures retain their existing behavior.

## Troubleshooting

Connection issues:

| Symptom | Possible cause | Solution |
|---|---|---|
| "Handshake failed" | Wrong password | Verify server password |
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
