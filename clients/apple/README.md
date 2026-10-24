# Vault for iOS & macOS

SwiftUI clients using NetworkExtension and the shared [Rust VPN core](../../core/).
The app requires iOS 18.5+ or macOS 15.5+; the Swift package supports iOS 18+
and macOS 15+. Build with full Xcode, a Swift 6 toolchain (Swift 5 language mode),
Rust and `protoc`.

## Usage

- **iOS:** Status shows the connection button, session clock, assigned IPv4/IPv6
  addresses and traffic. Configure edits settings immediately; Diagnostics holds
  connection checks and logs. About shows the app icon and version.
- **macOS:** the menu bar shows connection state. The popover has a connection
  button, session clock, traffic, and Diagnostics / Settings / Quit actions.
  Settings groups General, Connection, Network and Advanced; connection/network/
  advanced edits require Save and apply on the next connection. General changes
  apply immediately. About is at the bottom of the Settings sidebar.
- Closing a macOS window leaves the VPN running; Quit waits for the VPN profile
  cleanup and tunnel shutdown. If cleanup fails, Vault stays open so you can retry.
  Login-item registration may require approval in System Settings.

macOS keyboard shortcuts: `⌘,` Settings, `⌘1`–`⌘4` Settings sections, `⌘S` Save,
`⌘W` Close, `⌘Return` Connect/Disconnect, `⌘⇧D` Diagnostics, `⌘Q` Quit.
Tab / Shift-Tab moves between controls; Space / Return activates an action.

## Connection lifecycle

The app serializes preparation and teardown on the main queue. The four states
are `connecting`, `connected`, `disconnected`, and `disconnecting`. Cancelling a
connection waits for the current activation/profile operation to settle before
cleanup begins. A connect request during teardown records the latest intent and
starts only after the system confirms disconnection; another disconnect clears
that intent. Failed cleanup requires an explicit retry.

The provider startup watchdog covers DNS resolution, handshake, and network
settings. After issuing a stop, the app waits up to 15 seconds for the system to
confirm disconnection, then reports failure and enables retry without claiming
the tunnel is down. Preferences writes always settle before another operation.

## Diagnostics & logs

Connect the VPN, then start diagnostics manually. Both platforms share the
request/progress model and result interpretation:

- Tunnel-bound DNS A/AAAA, TCP and HTTPS checks with separate IPv4/IPv6 results,
  plus app-process HTTPS using the system resolver and default routes. AAAA
  queries use the configured resolver; their DNS transport may be IPv4.
- App-process Ping sends two 64-byte echo requests each to `1.1.1.1` and
  `2606:4700:4700::1111`, with reply counts, per-request details, and average RTT
  over received replies. ICMP is informational and does not change the required
  connectivity verdict. Missing tunnel IPv6 addresses remain unmeasured; domains
  without AAAA records are excluded from IPv6 transport targets. HTTPS reads a bounded sample (64 KiB).
- Per-check times are request averages, including retries and failures; total
  time is wall-clock elapsed time. All times use milliseconds.
- Route checks use current provider addresses, not the persisted display cache.
  Missing evidence or a changed session makes verification incomplete.
- ICMP is informational. Missing replies do not establish packet loss or an MTU
  fault. These checks are not a comprehensive IPv6 or DNS-leak audit.

File records use `[YYYY-MM-DD HH:mm:ss.SSSZ] [LEVEL] [SOURCE] message`:
UTC timestamps, bracketed severity, and `app`, `ne`, or `rust` as the source.
Runtime Logs also normalize older Rust severity fields and repair duplicated
opening timestamp brackets before chronological merging.

The Clear Logs button truncates the current and previous log files, clears the
macOS provider-log cache, and invalidates in-flight UI refreshes. On macOS, an
unavailable root provider is marked for clearing on the next connection; the UI
reports this explicitly and excludes its old cache until clearing is confirmed.
New events can appear after clearing while the VPN remains active.

Connection logs include an app operation ID and provider session ID. Timings in
`durationMs` cover system-extension activation, profile load/save/reload,
`startVPNTunnel`, DNS resolution, Edge initialization, and network settings.
The provider logs its process ID, the system-extension main entry,
`startSystemExtensionMode`, provider instance creation, callback arrival, and the
delay to its main queue. Exit logs identify the process. A quick `exit(0)` followed
by a restart can trigger launchd's respawn throttle; confirm this in launchd's
system log (`service spawn deferred ... due to throttle`) rather than attributing
the entire pre-callback gap to process initialization.

Provider IPC logs include command names, request IDs, app/provider PIDs, real
NEVPNStatus values, preparation/stop/termination flags, reply duration, and a
snapshot of utun names. Quit logs mark the request, cleanup result, timeout, and
final termination. Healthy periodic messages are sampled every 30 seconds;
state changes, inactive-session messages, and messages during quit are traced.
Offline log reads use only local files and the extension cache. No provider
manager is loaded solely for an IPC request. A final send gate blocks messages
to inactive providers and during teardown/quit; the startup acknowledgement used
for safe connection cancellation is the only exception.
Empty legacy status requests retain their original wire format. Message payloads
and log contents are never copied into trace records.

Logs are under Diagnostics → Runtime Logs. iOS follows new entries automatically;
macOS also offers search, source filters, optional auto-scroll and Copy. macOS
fetches the system extension's log over provider messages and caches it for
viewing after disconnecting. Diagnostic time budgets are 60 seconds in the
provider, 24 seconds for app HTTPS and Ping, and 95 seconds overall.

Probe domains are configurable under macOS Settings → Advanced or iOS Configure.
Empty uses `www.google.com, github.com, t.co`.

## Build & test

From `clients/apple`:

```bash
# Generate the Rust XCFramework and UniFFI Swift bindings after cloning or core changes.
VaultCore/Scripts/build-xcframework.sh

# Unsigned builds; choose an installed simulator for UI tests.
xcodebuild -project Vault.xcodeproj -scheme Vault \
  -destination 'generic/platform=iOS Simulator' CODE_SIGNING_ALLOWED=NO build
xcodebuild -project Vault.xcodeproj -scheme Vault \
  -destination 'platform=macOS' CODE_SIGNING_ALLOWED=NO build

swift test --package-path VaultCore
xcodebuild -project Vault.xcodeproj -scheme Vault \
  -destination 'platform=iOS Simulator,name=iPhone 17' test
```

The framework build script lists the required Rust targets. Generated bindings
and `VaultCore/Frameworks/VaultCoreFFI.xcframework` are not committed. Swift Testing
covers core/glue logic; XCTest covers app/UI tests. CI also runs SwiftLint.
Unsigned builds validate compilation; real tunnel tests need signed targets.

## Building Your Own Fork

Set `TEAM_ID` in git-ignored `Config/Local.xcconfig` or pass it when packaging
from the repository root:

```bash
TEAM_ID=ABCDE12345 scripts/package-apple.sh
```

Outputs go to `dist/`. Signing profiles, notarization and CI setup are documented
in [Releasing](../../docs/releasing.md#apple-packaging-and-signing).
For a fork, change `APP_BUNDLE_ID_PREFIX` and `APP_GROUP_ID` in
`Config/Shared.xcconfig` to identifiers registered to your team, and supply your
own provisioning/export profiles. Bundle IDs, entitlements and Mach service names
derive from those values.

The iOS provider is an embedded app extension; macOS uses a system extension.
On macOS, install the signed app in `/Applications` and approve the extension in
System Settings. macOS App Groups are team-prefixed; the system extension runs
outside the user's session, so status/log communication uses provider messages.

## Source layout

| Path | Purpose |
|---|---|
| `Vault/` | Shared app state, configuration, VPN controller and diagnostics model |
| `Vault/UI/iOS/`, `Vault/UI/macOS/` | Platform UI |
| `TunnelProvider/` | Shared packet tunnel provider |
| `VaultCore/` | Rust bindings, Swift glue, diagnostics and unit tests |
| `VaultNetworkExtension/`, `VaultSystemExtension/` | Platform extension targets |
| `VaultTests/`, `VaultUITests/` | App and UI tests |
| `Config/` | Signing and identifier configuration |

Non-secret settings use App Group storage. The password is stored in Keychain
and copied into the OS VPN profile for on-demand restarts; disconnecting does
not delete that profile. Physical-path changes trigger reconnects; the core
retries unreachable servers. IPv6 interfaces use a `/120` compatibility prefix
without changing server allocation. Actual routing must be verified on-device.

See [Protocol](../../docs/protocol.md), [Privacy](../../PRIVACY.md) and
[License](../../LICENSE) for shared project details.
