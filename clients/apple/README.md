# Vault for iOS & macOS

SwiftUI clients using NetworkExtension and the shared [Rust VPN core](../../core/).
The app requires iOS 18.5+ or macOS 15.5+; the Swift package supports iOS 18+
and macOS 15+. Build with full Xcode, a Swift 6 toolchain (Swift 5 language mode),
Rust and `protoc`.

## Usage

- **iOS:** Status shows the connection button, session clock, assigned IPv4/IPv6
  addresses and traffic. Configure validates a draft; Save applies connection settings
  on the next connection. Language changes apply immediately. Diagnostics holds
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

Application bundles include the project LICENSE and NOTICE.

## DNS configuration

Both iOS Configure and macOS Settings → Network have separate IPv4 DNS and
IPv6 DNS fields. Each accepts up to four comma-separated addresses of its own family.
Empty IPv4 DNS uses `1.1.1.1,8.8.8.8`; empty IPv6 DNS uses Google IPv6 DNS
`2001:4860:4860::8888,2001:4860:4860::8844`. IPv4-only tunnels apply the first
group, IPv6-only tunnels the second, and dual-stack tunnels combine both groups.
The effective list is recorded with the successfully applied tunnel settings
and supplied to diagnostics. Changes apply on the next connection.

The new App Group/profile keys are `dnsIpv4` and `dnsIpv6`. Old `dns` settings
are ignored and are not migrated; re-enter custom DNS values and reconnect to
save the new VPN profile. Diagnostic interface binding accepts either a live
IPv4 or IPv6 tunnel address, including IPv6-only assignments.

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

Connect the VPN, then start diagnostics manually. Android, iOS and macOS use
one [Rust diagnostic engine and transport](../../docs/diagnostics-engine.md),
including DNS, TCP, HTTPS, ICMP, route assessment, deadlines and verdicts.
Rustls verifies HTTPS against bundled Mozilla roots; platform trust stores do
not affect diagnostic results.

The Apple app drives the engine on a worker queue. It runs application-route
requests locally and forwards tunnel/host-default requests to the provider as
single-probe IPC messages. The provider supplies live tunnel configuration.
Swift adapts cancellation and IPC; the UI reads the Rust snapshot directly. A changed session
invalidates the run. IPC reply waits allow transport deadlines plus delivery time;
a normal probe timeout remains a probe result rather than cancelling the run.

On iOS, each check expands to show its individual requests; target details also
group results by domain. Ping is informational and uses reply-only average RTT.
All durations are milliseconds. For probe order, budgets and result rules, see
the shared diagnostics document rather than maintaining a separate Apple plan.

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
viewing after disconnecting. Both platforms refresh visible logs every two seconds.

Up to 32 probe domains are configurable under macOS Settings → Advanced or iOS Configure.
Empty uses `www.google.com, github.com, t.co`.

## Build & test

From `clients/apple`, format handwritten Swift with the checked-in `.swiftformat`
configuration. Generated bindings and build outputs are excluded:

```bash
swiftformat . --cache ignore
swiftformat . --lint --cache ignore
```

Build and test:

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
  -destination 'platform=macOS' -only-testing:VaultTests \
  -parallel-testing-enabled NO CODE_SIGNING_ALLOWED=NO test
xcodebuild -project Vault.xcodeproj -scheme Vault \
  -destination 'platform=iOS Simulator,name=iPhone 17' test
```

The framework build script lists the required Rust targets. Generated bindings
and `VaultCore/Frameworks/VaultCoreFFI.xcframework` are not committed. Swift Testing
covers core/glue logic; XCTest covers app/UI tests. CI runs SwiftLint, VaultCore
tests, and unsigned app builds and `VaultTests` on both macOS and iOS Simulator.
The macOS run includes the platform-specific lifecycle, Quit and IPC regressions.
The iOS run also checks Diagnostics / Logs / About navigation without a VPN,
using an available iPhone simulator running iOS 18.5 or later. Tests run serially
within each platform; `.xcresult` bundles are retained as CI artifacts for 7 days.
These checks do not activate a real tunnel; real tunnel tests need signed targets.

## Building Your Own Fork

Set `TEAM_ID` in git-ignored `Config/Local.xcconfig` or pass it when packaging
from the repository root:

```bash
TEAM_ID=ABCDE12345 scripts/package-apple.sh
```

Outputs go to `dist/`. Packaging takes the marketing version from the root
Cargo manifest; direct Xcode builds retain the project development default
`1.0` unless `MARKETING_VERSION` is overridden. Signing profiles, notarization and CI setup are documented
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
| `Vault/AppData.swift` | Main App runtime state, including assigned addresses and traffic |
| `Vault/VaultConfig.swift` | Saved App settings, editable drafts, validation feedback and conversion to the shared profile schema |
| `Vault/KeychainPasswordStore.swift` | Main App credential storage |
| `Vault/AppPresentation.swift` | Status labels, IP/version helpers, diagnostic result models and display formatting |
| Other `Vault/` files | Main App VPN controller, diagnostics ViewModel and platform app integration |
| `Vault/UI/iOS/`, `Vault/UI/macOS/` | Platform UI |
| `TunnelProvider/` | Shared packet tunnel provider |
| `VaultCore/Sources/VaultCore/TunnelModels.swift` | Saved launch configuration, applied tunnel configuration and traffic snapshot values |
| `VaultCore/Sources/VaultCore/ProviderProtocol.swift` | Shared status, command envelopes and diagnostic IPC types |
| `VaultCore/Sources/VaultCore/TunnelState.swift` | Network settings serialization, startup completion ownership and traffic session state |
| `VaultCore/Sources/VaultCore/RustDiagnostics.swift` | Cancellation and Rust transport/engine adapter returning native snapshots and errors |
| Other `VaultCore/` files | Rust bindings, shared profile/status/message types and independent domain logic |
| `VaultNetworkExtension/`, `VaultSystemExtension/` | Platform extension targets |
| `VaultTests/`, `VaultUITests/` | App and UI tests |
| `Config/` | Signing and identifier configuration |

`Vault` and the extension targets depend on the Swift `VaultCore` library, which
adapts the separate Rust VPN core. Core code does not depend on App state,
SwiftUI layouts, form drafts or diagnostic display models. The provider owns
NetworkExtension callbacks and live tunnel resources; the App owns user intent,
profile management and presentation. The library is loaded separately in each
process, so its singletons are not shared memory.

Core tests cover native engine snapshots, protocol compatibility and pure logic.
App tests cover draft validation, display formatting and conversion of engine
errors into UI results.

Both apps poll one provider status IPC endpoint for live addresses and traffic.
The provider keeps counters in memory. Assigned addresses live only in app runtime
state, and legacy persisted addresses are removed when configuration loads. Polls do not overlap, and replies from an ended
session cannot update the UI. Provider session identifiers preserve displayed
traffic totals across extension restarts.

Connection intent and phase belong to `VPNConnectionLifecycle`; `AppData` is its
UI projection. iOS and macOS share `ConnectionDraft` validation, normalization and
save operations, while macOS still saves each settings section independently.

Provider commands use one typed Codable envelope, retaining the legacy empty
status request and the existing probe payload format. Message replies enter the
app asynchronously on the main queue. Profile loading, saving and reloading also
complete on main before the next lifecycle operation proceeds.

A shared `TunnelLaunchConfiguration` converts settings into the OS VPN
profile keys and validates the provider's startup input. The password changes
only through explicit save/load/retry operations; a read retry never writes the
placeholder value back to Keychain.

Non-secret settings use App Group storage. The password is stored in Keychain
and copied into the OS VPN profile for on-demand restarts; disconnecting does
not delete that profile. Physical-path changes trigger reconnects; the core
retries unreachable servers. IPv6 interfaces use a `/120` compatibility prefix
without changing server allocation. Actual routing must be verified on-device.

See [Protocol](../../docs/protocol.md), [Privacy](../../PRIVACY.md) and
[License](../../LICENSE) for shared project details.
