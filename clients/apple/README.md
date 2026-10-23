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
- Closing a macOS window leaves the VPN running; Quit disconnects it. Login-item
  registration may require approval in System Settings.

macOS keyboard shortcuts: `⌘,` Settings, `⌘1`–`⌘4` Settings sections, `⌘S` Save,
`⌘W` Close, `⌘Return` Connect/Disconnect, `⌘⇧D` Diagnostics, `⌘Q` Quit.
Tab / Shift-Tab moves between controls; Space / Return activates an action.

## Diagnostics & logs

Connect the VPN, then start diagnostics manually. Both platforms share the
request/progress model and result interpretation:

- Tunnel-bound IPv4 DNS, TCP and HTTPS checks, plus app-process HTTPS using the
  system resolver and default routes. HTTPS reads a bounded sample (64 KiB).
- Per-check times are request averages, including retries and failures; total
  time is wall-clock elapsed time. All times use milliseconds.
- Route checks use current provider addresses, not the persisted display cache.
  Missing evidence or a changed session makes verification incomplete.
- ICMP is informational. Missing replies do not establish packet loss or an MTU
  fault. These checks are not a comprehensive IPv6 or DNS-leak audit.

Logs are under Diagnostics → Runtime Logs. iOS follows new entries automatically;
macOS also offers search, source filters, optional auto-scroll and Copy. macOS
fetches the system extension's log over provider messages and caches it for
viewing after disconnecting. Diagnostic time budgets are 60 seconds in the
provider, 20 seconds for app HTTPS, and 95 seconds overall.

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
