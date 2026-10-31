# Releasing

## Current status and build versions

There are no formal releases yet. `0.1.0` in the workspace manifest is the
current development version; all existing changes are recorded under
`Unreleased` in `CHANGELOG.md`. Do not treat development snapshots as a
supported release series.

The root `Cargo.toml` is the version source for Rust and packaged artifacts.
Android packaging and release CI inject `versionName`/`versionCode`; direct
Gradle builds default to `0.1.0` / `1` unless those properties are supplied.
Direct Xcode builds default to `MARKETING_VERSION=1.0` (the app version) and
`CURRENT_PROJECT_VERSION=1` (the build number), unless overridden. Apple
packaging replaces the app version with the Cargo version and derives the build
number from the Git commit count, appending a timestamp for tracked local
changes. Direct app builds are therefore not substitutes for the versioned
packaging entry points.

`rust-toolchain.toml` selects rolling `stable`, with Rust 1.98 as the declared
minimum. Cargo.lock fixes Rust dependency resolution, not the compiler or all
external tools. Record compiler, SDK, NDK, Xcode and packaging-tool versions
when diagnosing or reproducing a build.

Linux packaging regenerates manpages explicitly before `cargo deb`; it does
not rely on Cargo build-script side effects or cached generated files. For
direct `cargo deb` use, first run `scripts/package-linux.sh --manpages-only`.

Local `scripts/package-linux.sh` cross-builds x86_64 musl binaries with Zig;
the release workflow builds native GNU/Linux binaries on Ubuntu after all
platform checks pass. Both produce
Debian packages, but libc/linking requirements can differ. The current Debian
metadata declares libc6/libgcc dependencies even for local musl packages.
Validate each package on the intended Debian/Ubuntu host; do not assume the
local script reproduces CI binaries byte for byte.

Release CI writes each Debian package into a runner temporary directory outside
the Cargo cache and uploads only that matrix component's package. Cached debs
from previous builds are not collected as release artifacts.

## Android version-code policy

Local packaging and release CI share the encoder in `scripts/package-android.sh`.
Use `scripts/package-android.sh --version-code [VERSION]` to print the code
without building; omitting VERSION reads the workspace manifest.
For Android-only packaging, supported versions are `major.minor.patch`, optionally followed by
`-alpha.N`, `-beta.N` or `-rc.N`. Each numeric release component is 0–99;
`N` is 1–499. Leading zeroes, other suffixes and build metadata are rejected.

The code is `(major*10000 + minor*100 + patch)*2000 + rank`, where alpha uses
`N`, beta `500+N`, rc `1000+N`, and a final release `1999`. Thus alpha, beta,
rc and final versions sort in order, including consecutive prereleases; the
maximum code is 1,999,999,999. `0.1.0` encodes to `201999`, above the previous
development code `100`. Direct Gradle builds still default to code `1` and are
not versioned release artifacts.

Apple packaging and the all-platform release gate accept only numeric
`major.minor.patch` versions. Pre-release suffixes are rejected before packaging;
they are not passed into Apple's marketing-version field.

## Release process

1. Choose the release version in the root `Cargo.toml` (the packaged version source;
   `scripts/package-android.sh` injects it into the Gradle build as
   `-PversionName`/`-PversionCode`).
2. Move completed entries from `Unreleased` into a dated version section in
   `CHANGELOG.md`. For the first release, create the first version section then;
   there is no historical `0.1.0` release to preserve.
3. Commit and push the changes.
4. Review device/network validation for affected paths, then create a tag
   matching the chosen manifest version. Release CI invokes the Rust, Android
   and Apple check workflows on that exact commit, including the Linux network
   namespace check, before any platform packaging job can run. Failed checks
   block packaging and publication. Check workflows also support manual runs
   without PR/push path filters. For an initial
   `0.1.0` release: `git tag -a v0.1.0 -m "Release v0.1.0"`
5. Push the tag (using the same version): `git push origin v0.1.0`
6. Tagging `v*.*.*` triggers `.github/workflows/release.yml`, which publishes
   the Linux client deb, Linux supernode deb, signed Android APK, and
   notarized macOS app zip in one release. The signed iOS IPA is built in the
   same workflow for validation but is not uploaded as an artifact or Release
   asset: its Ad Hoc profile contains the team name and device UDIDs.
   Build locally when you need the IPA — see *Apple signing in CI* below.
   Apple packaging requires the signing secrets described in *Apple signing
   in CI* below; the
   `apple-packages` job fails fast with a list of missing secrets if they
   are not configured. The separate Apple CI (`.github/workflows/apple.yml`)
   performs PR/push checks: SwiftLint, VaultCore unit tests, unsigned macOS
   and iOS Simulator app builds and `VaultTests`, plus an iOS navigation
   smoke test. Test result bundles are uploaded even when tests fail.
   Apple artifacts can also be built locally as
   described below.

## Apple packaging and signing

The release workflow packages Apple artifacts on a macOS runner; the same
packaging can be run locally (no automated TestFlight distribution yet):

```bash
TEAM_ID=ABCDE12345 scripts/package-apple.sh   # iOS IPA + macOS app, into dist/
TEAM_ID=ABCDE12345 scripts/package-all.sh      # all platforms
```

An Apple Developer team is required: pass your team ID via `TEAM_ID` (also
injected into the export options), or set `TEAM_ID` in
`clients/apple/Config/Local.xcconfig` (git-ignored) for local development.
The script fails fast with a clear error when neither is set.

### macOS signing specifics

- Debug builds use development-signed entitlements
  (`Vault-macOS.entitlements`, plain `packet-tunnel-provider` value);
  Release builds sign directly with the Developer ID identity and use the
  `-systemextension` entitlement values
  (`Vault-macOS-Distribution.entitlements`,
  `VaultSystemExtension-Distribution.entitlements`), because development
  and Developer ID provisioning profiles grant different value sets.
- Release macOS targets use manual signing (`CODE_SIGN_STYLE=Manual`,
  identity `Developer ID Application`), so the two Developer ID
  provisioning profiles must exist on the Apple Developer portal and be
  installed under `~/Library/MobileDevice/Provisioning Profiles/` with
  exactly these names:
  - `Vault macOS Developer ID` (App ID `net.dighole.Vault`)
  - `VaultSystemExtension macOS Developer ID` (App ID
    `net.dighole.Vault.VaultSystemExtension`)

  The names are referenced by `PROVISIONING_PROFILE_SPECIFIER` in the
  project and by the `provisioningProfiles` mapping in
  `scripts/apple/ExportOptions-developerid.plist`.

  Forks must update both project profile specifiers and the export plist's
  Bundle ID/profile-name mapping to match their own identifiers and installed
  profiles. A custom export plist can be selected with `MACOS_EXPORT_OPTIONS`.
  Setting that variable to empty only skips export; the archive still uses
  Developer ID signing. Use Xcode's Debug configuration for development signing.

### Apple signing in CI

The `apple-packages` job in `.github/workflows/release.yml` signs and
notarizes on a GitHub-hosted macOS runner. Set up these secrets under
Settings > Secrets and variables > Actions:

| Secret name | Content |
|---|---|
| `APPLE_CERTIFICATE_P12_BASE64` | Base64 of a `.p12` exporting the signing certificates with private keys. Needs *Apple Distribution* (iOS) and *Developer ID Application* (macOS); a single `.p12` may carry both |
| `APPLE_CERTIFICATE_PASSWORD` | Password of the `.p12` |
| `APPLE_TEAM_ID` | 10-character Apple Developer team ID |
| `APP_STORE_CONNECT_KEY_ID` / `APP_STORE_CONNECT_ISSUER_ID` / `APP_STORE_CONNECT_PRIVATE_KEY` | App Store Connect API key. Authenticates xcodebuild's `-allowProvisioningUpdates` (no Xcode account on the runner) and the notarytool credentials |
| `APPLE_PROVISIONING_PROFILE_MACOS_APP_BASE64` / `APPLE_PROVISIONING_PROFILE_MACOS_SYSEX_BASE64` | Base64 of the two macOS Developer ID provisioning profiles named above. Required: Release macOS targets sign manually, so the profiles must be installed on the runner |
| `APPLE_PROVISIONING_PROFILE_IOS_APP_BASE64` / `APPLE_PROVISIONING_PROFILE_IOS_NE_BASE64` | Base64 of the iOS provisioning profiles (App and Network Extension targets; the latter needs the `packet-tunnel-provider` entitlement, which requires a paid developer account). Optional: iOS targets sign automatically and fetch profiles via `-allowProvisioningUpdates` |

**Privacy: the exported iOS IPA embeds its provisioning profile.** Anyone who
gets hold of `Vault-iOS.ipa` can extract `embedded.mobileprovision` and read
the team name (your legal name on a personal developer account) and, because
the export is Ad Hoc (`release-testing`), the UDIDs of every device
registered in the profile; automatic signing generates an "iOS Team Ad Hoc
Provisioning Profile" containing **all** devices registered to the team.
The release workflow therefore uploads only the macOS zip; the IPA remains
on the ephemeral runner and is discarded when the job ends. A GitHub login
is not a privacy boundary: ordinary signed-in users can download artifacts
from public repositories. Delete historical artifacts containing an IPA
before making a repository public (or immediately if it is already public);
this workflow change does not remove previously uploaded files. For local
IPA distribution, further limit exposure by creating
dedicated Ad Hoc profiles for `net.dighole.Vault` and
`net.dighole.Vault.VaultNetworkExtension` containing only a dedicated device
(or the minimum set you need), and supply them via the optional
`APPLE_PROVISIONING_PROFILE_IOS_*` secrets above so automatic signing does
not generate an all-devices profile. The team name itself ships in every
distribution profile and cannot be hidden — use an organization account if
that is a concern. Do not hand an IPA exported this way to anyone you would
not give the device list to.

The job imports the `.p12` into an ephemeral keychain (deleted in a cleanup
step, also on failure), installs the provisioning profiles under their UUID
file names, and registers the App Store Connect key as the `vault-notary`
notarytool keychain profile that `scripts/package-apple.sh` uses.

### Setting up a new packaging machine

The CI signing step is a scripted version of this checklist; on a fresh Mac,
do by hand what the workflow does automatically:

1. **Build environment**: full Xcode (not just the Command Line Tools), the
   Rust Apple targets (`rustup target add
   aarch64-apple-ios aarch64-apple-ios-sim x86_64-apple-ios
   aarch64-apple-darwin x86_64-apple-darwin`), and `brew install protobuf`.
2. **Signing material**: import `vault-dist.p12` (the certificates with
   private keys) into the login keychain — double-click it or use
   `security import` — and install the two macOS Developer ID provisioning
   profiles under `~/Library/MobileDevice/Provisioning Profiles/`. iOS
   profiles are fetched automatically; no manual install needed.
3. **Provisioning authentication** (either one):
   - sign in with the Apple ID under Xcode > Settings > Accounts, or
   - pass the App Store Connect API key when running the script:
     `ASC_KEY_PATH=~/keys/AuthKey_XXXX.p8 ASC_KEY_ID=XXXX ASC_KEY_ISSUER=YYYY`
     (the script forwards them to xcodebuild).
4. **Notarization credentials** (once per machine):
   `xcrun notarytool store-credentials vault-notary --key AuthKey_XXXX.p8
   --key-id <KEY_ID> --issuer <ISSUER_ID>`. Without this profile the script
   fails at the notarization step; set `NOTARY_PROFILE=` (empty) to skip
   notarization for local test builds.
5. **Run**: `TEAM_ID=<team-id> scripts/package-apple.sh`.

## Android signing keys

Generate a keystore (if you don't have one yet):

```bash
keytool -genkey -v -keystore vault-release.keystore -alias vault -keyalg RSA -keysize 2048 -validity 10000
```

When keytool prompts for a key password, press Enter to reuse the store
password — PKCS12 keystores (the default format) do not support a key
password different from the store password, and the Gradle signing config
uses the store password for both.

**Back up the keystore somewhere safe.** Android requires every version of
an app to be signed with the same certificate; if the keystore is lost,
you can no longer publish upgrades — the only way out is a new
`applicationId`, which means existing users cannot update in place.

Convert to Base64:

```bash
# macOS
base64 -i vault-release.keystore | pbcopy

# Linux
base64 -w 0 vault-release.keystore | xclip -selection clipboard
```

Set up secrets in GitHub: go to Settings > Secrets and variables > Actions,
and add:

| Secret name | Content |
|---|---|
| `ANDROID_SIGNING_KEY_STORE_BASE64` | Base64-encoded keystore |
| `ANDROID_SIGNING_KEY_STORE_PASSWORD` | Keystore password (also used as the key password) |
| `ANDROID_SIGNING_KEY_ALIAS` | Key alias (e.g., `vault`) |

Local release config example (the same base64 value as the GitHub secret,
on a single line — `local.properties` is a Java properties file):

```properties
# clients/android/local.properties
sdk.dir=/xxx/xxx/Android/sdk
signing.keyStoreBase64=<single-line base64 of vault-release.keystore>
signing.keyStorePassword=xxx
signing.keyAlias=vault
```
