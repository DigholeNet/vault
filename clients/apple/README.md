# Vault for iOS & macOS

**Vault** is the Apple client of the [Vault VPN](../../README.md) system,
available on iOS & macOS. It connects to the supernode over an encrypted
tunnel via the NetworkExtension framework.

## Network recovery

The tunnel extension monitors physical network paths and coalesces changes for
750 ms before requesting a reconnect. Wake-up also checks for a stale session.
Recovery keeps the tunnel and traffic counters alive; the core creates a fresh
UDP socket and interrupts any retry backoff. The system reports `reasserting`
until the new handshake and tunnel settings finish. An unreachable server no
longer cancels the tunnel after 15 seconds; the core continues retrying.

Server addresses are resolved once at tunnel startup and handed to the core,
which races all of them Happy-Eyeballs style (IPv6 first, 300 ms stagger) on
every (re)connect — a dead address family costs at most one stagger interval.
Re-resolving the original hostname during a running tunnel is follow-up work.
Paths whose interface/gateway signature does not change fall back to the
core heartbeat timeout.

## Technology Stack

### Core Technologies
- **Language**: Swift 6.0 (with Swift 5 language mode)
- **UI Framework**: SwiftUI
- **Minimum OS Versions**: iOS 18+, macOS 15+
- **Build System**: Xcode + Swift Package Manager

### Key Dependencies
| Package | Version | Purpose |
|---------|---------|---------|
| [vault-core](../../core/) | workspace | Rust VPN core (handshake, heartbeat, reconnect, crypto, data pump) |
| [bridge](../bridge/) | workspace | UniFFI wrapper crate generating the Swift/Kotlin bindings |
| UniFFI | 0.32 | Rust → Swift bindings generator |

The VPN core protocol and cryptography are implemented in Rust
(`vault-core`, client feature). `VaultCore` is only a thin Swift glue
layer over the UniFFI bindings; the Rust code is built into
`VaultCore/Frameworks/VaultCoreFFI.xcframework` (not committed) by
`VaultCore/Scripts/build-xcframework.sh`.

### Cryptography

Implemented in `vault-core` — see [docs/protocol.md](../../docs/protocol.md)
for the handshake (SPAKE2 PAKE + X25519), key derivation (HKDF-SHA256), and
AEAD algorithms (AES-128/256-GCM, ChaCha20-Poly1305).

## Project Structure

```
vault-apple/
├── Config/
│   └── Shared.xcconfig       # App group + bundle ID prefix (forks edit here)
├── Vault/                      # Main iOS/macOS Application
│   ├── VaultApp.swift          # App entry point (@main)
│   ├── VpnManager.swift        # VPN connection manager
│   ├── VaultCommon.swift       # Shared utilities and config
│   ├── Vault.entitlements      # App entitlements
│   └── UI/                     # Platform-specific UI
│       ├── iOS/               # iOS SwiftUI views
│       │   ├── IosMainView.swift
│       │   ├── IosStatusView.swift
│       │   ├── IosConfigureView.swift
│       │   └── IosAboutView.swift
│       └── macOS/             # macOS SwiftUI views
│           ├── MacosMenuView.swift      # Menu bar extra
│           ├── MacosConfigureView.swift
│           ├── MacosAboutView.swift
│           └── WindowManager.swift
│
├── VaultCore/                  # Swift Package - glue layer over the Rust core
│   ├── Package.swift          # SPM manifest (binaryTarget + glue target)
│   ├── Scripts/
│   │   └── build-xcframework.sh   # Builds Rust libs + Swift bindings + XCFramework
│   ├── Frameworks/            # VaultCoreFFI.xcframework (generated, not committed)
│   ├── Sources/VaultCore/     # Glue source code
│   │   ├── Generated/         # UniFFI-generated Swift bindings (not committed)
│   │   ├── Edge.swift         # Edge glue class (delegates to RustEdge)
│   │   ├── EdgeConfig.swift   # Edge configuration
│   │   ├── PacketStats.swift  # Cross-process traffic statistics
│   │   ├── FileLogger.swift   # Shared file logger (App Group container)
│   │   └── Extension.swift    # Logger / hex helpers, app group id
│   └── Tests/VaultCoreTests/  # Glue unit tests (Swift Testing)
│
├── TunnelProvider/             # Shared packet tunnel source (iOS app extension + macOS system extension)
│   └── PacketTunnelProvider.swift   # NEPacketTunnelProvider implementation
│
├── VaultNetworkExtension/      # iOS app extension target
│   ├── Info.plist
│   └── VaultNetworkExtension.entitlements
│
├── VaultSystemExtension/       # macOS system extension target
│   ├── main.swift             # System extension entry point
│   ├── Info.plist
│   ├── InfoPlist.xcstrings
│   └── VaultSystemExtension(-Distribution).entitlements
│
├── VaultTests/                 # App-level tests
│   └── VaultTests.swift
│
├── VaultUITests/              # UI tests
├── Vault.xcodeproj/           # Xcode project
└── ../../PRIVACY.md           # Privacy policy (repository root)
```

## Architecture Overview

### Component Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    Application Layer                         │
│  ┌──────────────────┐      ┌──────────────────┐            │
│  │   iOS App        │      │   macOS App      │            │
│  │  (TabView UI)    │      │ (Menu Bar Extra) │            │
│  └────────┬─────────┘      └────────┬─────────┘            │
│           │                         │                       │
│           └────────────┬────────────┘                       │
│                        ▼                                    │
│              ┌──────────────────┐                          │
│              │   VpnManager     │                          │
│              │  (Connection Mgr)│                          │
│              └────────┬─────────┘                          │
└───────────────────────┼─────────────────────────────────────┘
                        │
┌───────────────────────┼─────────────────────────────────────┐
│           NetworkExtension Framework                         │
│                       ▼                                      │
│              ┌──────────────────┐                          │
│              │PacketTunnelProvider│                          │
│              │  (VPN Extension) │                          │
│              └────────┬─────────┘                          │
└───────────────────────┼─────────────────────────────────────┘
                        │
┌───────────────────────┼─────────────────────────────────────┐
│                 VaultCore (glue layer)                       │
│                       ▼                                      │
│              ┌──────────────────┐                          │
│              │      Edge        │  Swift glue (UniFFI)      │
│              └────────┬─────────┘                          │
│                       ▼                                      │
│              ┌──────────────────┐                          │
│              │  vault-core   │  Rust: handshake, heartbeat│
│              │  (ClientSession) │  reconnect, crypto, pump   │
│              └──────────────────┘                          │
└─────────────────────────────────────────────────────────────┘
```

### Data Flow

1. **User toggles VPN** → VpnManager.connect()/disconnect()
2. **Start tunnel** → PacketTunnelProvider.startTunnel() creates virtual interface
3. **Edge initialization** → vault-core ClientSession starts: DNS, handshake, heartbeat (Rust)
4. **Packet flow**:
   - **Outbound**: System → PacketTunnel → Edge.writeData() → Encrypt → UDP (Rust)
   - **Inbound**: UDP → Decrypt (Rust) → EdgeCallbacks → PacketTunnel → System

## Build and Test Commands

### Building the Rust Core (required after cloning)

The XCFramework and Swift bindings are generated artifacts and not
committed. Build them once after cloning, and again after pulling
vault-core updates:

```bash
# Requires: Rust toolchain (targets: aarch64-apple-ios, aarch64-apple-ios-sim,
# x86_64-apple-ios, aarch64-apple-darwin, x86_64-apple-darwin) and full Xcode.
VaultCore/Scripts/build-xcframework.sh
```

### Building the Project

```bash
# Build VaultCore Swift Package
cd VaultCore && swift build

# Build entire project with Xcode
xcodebuild -project Vault.xcodeproj -scheme Vault -configuration Debug

# Build for iOS Simulator
xcodebuild -project Vault.xcodeproj -scheme Vault -destination 'platform=iOS Simulator,name=iPhone 16'

# Build for macOS
xcodebuild -project Vault.xcodeproj -scheme Vault -destination 'platform=macOS'
```

### Running Tests

```bash
# Run VaultCore glue tests
cd VaultCore && swift test

# Run all tests via Xcode
xcodebuild test -project Vault.xcodeproj -scheme Vault -destination 'platform=iOS Simulator,name=iPhone 16'
```

## Building Your Own Fork

The bundle IDs and the app group shipped in this repo are registered under
the Dighole team and cannot be provisioned by another Apple Developer
account. To build or distribute your own fork:

1. Edit `Config/Shared.xcconfig` — set `APP_BUNDLE_ID_PREFIX` and
   `APP_GROUP_ID` to identifiers registered under your own team (register
   the app group in your Apple Developer account).
2. Set your team ID in `Config/Local.xcconfig` (git-ignored:
   `TEAM_ID = ABCDE12345`), or pass `TEAM_ID` to
   `scripts/package-apple.sh`.
3. For Developer ID distribution, create your own provisioning profiles and
   point `MACOS_EXPORT_OPTIONS` at your own export-options plist (see
   [docs/releasing.md](../../docs/releasing.md)).

Everything else — entitlements, the extensions' Info.plists, the Mach
service name, and the app group resolved at runtime — derives from the
xcconfig values.

## Code Style Guidelines

### Naming Conventions
- **Files**: PascalCase matching the primary type (e.g., `Edge.swift`, `VpnManager.swift`)
- **Classes/Structs**: PascalCase (e.g., `PacketTunnelProvider`, `EdgeConfig`)
- **Methods/Variables**: camelCase (e.g., `writeData`, `vpnStatus`)
- **Private Properties**: Use `fileprivate` or `private` appropriately

### Code Organization
- One class/struct per file, named after the type
- Extensions grouped by functionality in `Extension.swift`
- Platform-specific code guarded with `#if os(iOS)` / `#if os(macOS)`

### Comments
- File headers use `//` style with author and date
- Documentation comments for public APIs using `///`

### Import Style
```swift
import SwiftUI
import NetworkExtension
import VaultCore  // Local package
```

## Key Modules Explained

### Edge.swift
Thin Swift glue over the Rust `RustEdge` (vault-core `ClientSession` via
UniFFI). Keeps the public API used by `PacketTunnelProvider` (`init` with
callbacks, `writeData`, `close`) while the Rust runtime handles:
- UDP socket, DNS resolution and handshake with the supernode
- Heartbeat and exponential-backoff reconnect
- Packet encryption/decryption and the data pump
- Traffic statistics

### PacketTunnelProvider.swift
The NetworkExtension packet tunnel implementation:
- Creates virtual network interface
- Routes IP packets between system and Edge
- Applies network settings (IP, DNS, routes)

### VpnManager.swift
App-side VPN controller:
- NETunnelProviderManager lifecycle
- Configuration persistence
- Status observation and notification

## Configuration

User configuration uses App Group `@AppStorage` for non-secret settings.
The app password is stored in Keychain; connecting also saves a copy in the
OS-managed VPN profile (`providerConfiguration`) for on-demand restarts,
including macOS system-extension launches outside the user session.
Disconnecting does not delete that saved profile or its password.
Keychain failures are shown on the configuration screen with a retry action.
Legacy plaintext credentials are removed only after a successful Keychain save;
a failed read is retried as a read rather than saving an empty placeholder.

| Key | Type | Description |
|-----|------|-------------|
| `id` | String | Device unique identifier (hex UUID) |
| `host` | String | Server hostname or IP |
| `port` | Int | Server port (default: 9527) |
| `password` | String | Connection password (Keychain and OS VPN profile, not `@AppStorage`) |
| `ip` | String | Assigned virtual IP |
| `dns` | String | DNS servers (comma-separated) |

## Security Considerations

### Network Security
- Server IP excluded from VPN routes (prevent routing loops)
- DNS traffic tunneled by default
- MTU probed from the underlying link (link MTU minus tunnel overhead, clamped to 1280...1427)

Cryptographic properties are covered by
[docs/protocol.md](../../docs/protocol.md); the required entitlements are
listed under Deployment Notes → Capabilities.

## Testing Strategy

### Unit Tests (VaultCoreTests)
- `GlueTests.swift`: glue layer tests (hex parsing, config, formatting)
- The core protocol and crypto are tested in vault-core's Rust test suite

### Test Requirements
- Tests use Swift Testing framework (not XCTest)

### UI Tests
- Minimal UI test coverage in `VaultUITests/`
- Relies on manual testing for UI flows

## Deployment Notes

### Platform Packaging of the Tunnel Provider

- **iOS**: the provider ships as an app extension
  (`VaultNetworkExtension.appex`) embedded in `PlugIns/`.
- **macOS**: Developer ID only provisions the *system extension* variant of
  Network Extension entitlements, so the provider ships as a system
  extension (`net.dighole.Vault.VaultSystemExtension.systemextension`)
  embedded in `Library/SystemExtensions/`. Both targets share the same
  source (`TunnelProvider/PacketTunnelProvider.swift`).
  Note: the `.systemextension` bundle file name (minus extension) must equal
  the extension's bundle identifier — `sysextd` rejects the activation with
  a misleading `OSSystemExtensionErrorDomain` code 4 ("Extension not found")
  otherwise. The target achieves this via
  `PRODUCT_NAME = $(PRODUCT_BUNDLE_IDENTIFIER)`; `PRODUCT_MODULE_NAME` stays
  `VaultSystemExtension` so the Swift module name is unchanged.

macOS specifics:

- The app must run from `/Applications` to activate the system extension;
  the first activation requires user approval in System Settings → General →
  Login Items & Extensions. For debugging, copy the built app to
  `/Applications` and launch it there (use "Wait for the executable to be
  launched" in the scheme to attach the debugger).
- Debug and Release builds use different entitlements and signing
  identities (development vs. Developer ID, manual signing with named
  provisioning profiles) — see
  [docs/releasing.md](../../docs/releasing.md#macos-signing-specifics).

### App Group

The unprefixed group ID comes from `APP_GROUP_ID` in
`Config/Shared.xcconfig`; the signing team's prefix is added automatically
(see Building Your Own Fork for using your own team).

- iOS: `group.net.dighole.vault`
- macOS: team-prefixed form `<team-id>.group.net.dighole.vault`
  (`$(TeamIdentifierPrefix)$(APP_GROUP_ID)` in entitlements) — required for
  Developer ID and for the system extension's Mach service.

### Bundle Identifiers

Derived from `APP_BUNDLE_ID_PREFIX` in `Config/Shared.xcconfig`:

- Main App: `net.dighole.Vault`
- iOS app extension: `net.dighole.Vault.VaultNetworkExtension`
- macOS system extension: `net.dighole.Vault.VaultSystemExtension`

### Capabilities
The app requires special entitlements that must be provisioned:
1. Network Extension (Packet Tunnel; `-systemextension` variant on macOS
   Release)
2. VPN API Access
3. App Groups
4. System Extension install (macOS only)

## Development Workflow

1. **Core Changes**: The VPN core lives in `core/` (vault-core, Rust); the UniFFI wrapper in `clients/bridge/` — rebuild with `VaultCore/Scripts/build-xcframework.sh`
2. **UI Changes**: Modify platform-specific files in `Vault/UI/`
3. **Extension Changes**: Modify `TunnelProvider/PacketTunnelProvider.swift` (shared by the iOS app extension and the macOS system extension)

## License

MIT — see [LICENSE](../../LICENSE)