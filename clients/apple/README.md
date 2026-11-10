# Vault for iOS & macOS

SwiftUI clients using NetworkExtension and the shared [Rust VPN core](../../core/).
The app requires iOS 18.5+ or macOS 15.5+; the Swift package supports iOS 18+
and macOS 15+. Build with full Xcode, a Swift 6 toolchain (Swift 5 language mode),
Rust and `protoc`.

Running the iOS VPN on a physical device requires Apple Developer Program
membership and signing profiles with Network Extension and App Group
entitlements. Unsigned simulator builds are for UI development and tests,
not for establishing an iOS VPN tunnel. See Apple’s
[Network Extension configuration](https://developer.apple.com/documentation/xcode/configuring-network-extensions/)
and [supported iOS capabilities](https://developer.apple.com/help/account/reference/supported-capabilities-ios).

## Project structure

```text
clients/apple/
├── Vault.xcodeproj           # Xcode project
├── Vault/                    # SwiftUI apps, controllers and platform UI
├── TunnelProvider/           # Shared packet tunnel provider
├── VaultNetworkExtension/    # iOS app extension
├── VaultSystemExtension/     # macOS system extension
├── VaultCore/                # Swift package, Rust bindings and XCFramework build script
├── Config/                   # Signing and bundle identifiers
├── VaultTests/               # App tests
└── VaultUITests/             # UI tests
```

## Build and test

From `clients/apple`, format handwritten Swift with the checked-in `.swiftformat`
configuration. Generated bindings and build outputs are excluded:

```bash
swiftformat . --cache ignore
swiftformat . --lint --cache ignore
```

Build and test:

```bash
# Generate the Rust XCFramework and UniFFI Swift bindings after cloning or core changes.
rustup target add aarch64-apple-ios aarch64-apple-ios-sim x86_64-apple-ios \
  aarch64-apple-darwin x86_64-apple-darwin
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

## Configuration

### Configuration options

- `Device ID`: Peer identifier generated on the device
- `Host`: Vault server hostname or IP address; required
- `Port`: Server UDP port; defaults to 9527
- `Password`: Authentication password; required
- `MTU`: 1280–1427; empty uses automatic link-based sizing
- `IPv4 DNS`: Comma-separated IPv4 resolvers; empty uses `1.1.1.1,8.8.8.8`
- `IPv6 DNS`: Comma-separated IPv6 resolvers; empty uses
  `2001:4860:4860::8888,2001:4860:4860::8844`
- `Probe domains`: Comma-separated diagnostic domains; empty uses
  `www.google.com,github.com,t.co`
- `Language`: App language; defaults to the system language and applies immediately
- `Launch at login`: macOS only; registers Vault as a login item
- `Connect when Vault opens`: macOS only; starts the VPN when the app launches
- `Show in Dock`: macOS only; controls the Dock icon

Each DNS field accepts up to four addresses of its own family; probe domains
are limited to 32 entries. IPv4-only tunnels apply only IPv4 DNS, IPv6-only
tunnels apply only IPv6 DNS, and dual-stack tunnels combine both lists.
Connection, network and advanced changes apply on the next connection;
language and macOS general settings apply immediately.

The App Group/profile keys are `dnsIpv4` and `dnsIpv6`. Old `dns` settings
are ignored and are not migrated; re-enter custom DNS values and reconnect to
save the new VPN profile. Diagnostic interface binding accepts either a live
IPv4 or IPv6 tunnel address, including IPv6-only assignments.

## Usage and deployment

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

### Building Your Own Fork

Set `TEAM_ID` in git-ignored `Config/Local.xcconfig` or pass it when packaging
from the repository root:

```bash
TEAM_ID=ABCDE12345 scripts/package-apple.sh
```

Outputs go to `dist/`. Packaging takes the marketing version from the root
Cargo manifest; direct Xcode builds retain the project development default
`0.1.1` unless `MARKETING_VERSION` is overridden. Signing profiles, notarization and CI setup are documented
in [Releasing](../../docs/releasing.md#apple-packaging-and-signing).
For a fork, change `APP_BUNDLE_ID_PREFIX` and `APP_GROUP_ID` in
`Config/Shared.xcconfig` to identifiers registered to your team, and supply your
own provisioning/export profiles. Bundle IDs, entitlements and Mach service names
derive from those values.

For macOS Release packaging, also update both `PROVISIONING_PROFILE_SPECIFIER`
values in `Vault.xcodeproj/project.pbxproj` to your installed Developer ID
profile names (app and system extension). In
`scripts/apple/ExportOptions-developerid.plist`, replace both Bundle ID keys
and profile-name values in `provisioningProfiles` to match. Alternatively,
pass a custom plist through `MACOS_EXPORT_OPTIONS`; the project's profile
names still need to match your installed profiles.

The packaging script uses macOS Release signing and requires Developer ID.
For a development-signed macOS app, use the Xcode Debug configuration.

The iOS provider is an embedded app extension; macOS uses a system extension.
On macOS, install the signed app in `/Applications` and approve the extension in
System Settings. macOS App Groups are team-prefixed; the system extension runs
outside the user's session, so status/log communication uses provider messages.

Rust builds resolve Cargo from `CARGO` (an explicit executable path), then
`CARGO_HOME/bin`, then `PATH`, falling back to the default rustup location.
For example, set `CARGO=/opt/rust/bin/cargo` for a custom installation.

## Documentation

- [Protocol](../../docs/protocol.md) — shared wire protocol
- [Diagnostics](../../docs/diagnostics-engine.md) — shared diagnostic engine
- [Releasing](../../docs/releasing.md) — packaging and signing
- [Privacy](../../PRIVACY.md) — data handling

## License

See the project [License](../../LICENSE).
