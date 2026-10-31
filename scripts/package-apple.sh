#!/usr/bin/env bash
#
# Packages the Apple clients: iOS IPA + macOS app (zip).
#
# Prerequisites:
#   - Full Xcode (iOS SDK); if xcode-select points at the Command Line
#     Tools, DEVELOPER_DIR is set automatically
#   - Apple signing identities in the keychain (Apple Development suffices
#     for development-signed artifacts)
#   - Rust Apple targets (see rust-toolchain.toml)
#
# Usage: TEAM_ID=<your-team-id> scripts/package-apple.sh
#
# The committed Config/Shared.xcconfig ships with an empty TEAM_ID, so
# signing needs TEAM_ID passed to this script (overrides everything as an
# xcodebuild argument) or set in Config/Local.xcconfig (git-ignored). The
# script fails fast when neither provides one.
#
# Environment:
#   EXPORT_OPTIONS        path to an exportOptions plist for iOS
#                         (default: ExportOptions-adhoc.plist — real Ad Hoc
#                         distribution signature, registered devices;
#                         use ExportOptions-development.plist for a
#                         development-signed build)
#   MACOS_EXPORT_OPTIONS  path to an exportOptions plist for macOS; the app
#                         is re-signed from the archive with it (default:
#                         ExportOptions-developerid.plist; set to empty for
#                         a development-signed app zipped from the archive)
#   NOTARY_PROFILE        notarytool keychain profile used to notarize and
#                         staple the macOS app (default: vault-notary;
#                         set to empty to skip notarization)
#   TEAM_ID               Apple Developer team ID; overrides the xcconfig
#                         value as an xcodebuild argument and is injected
#                         into the export options. Unset: use TEAM_ID from
#                         Config/Shared.xcconfig + Config/Local.xcconfig;
#                         if neither sets one, the script exits with an
#                         error before building.
#   ASC_KEY_PATH/ASC_KEY_ID/ASC_KEY_ISSUER
#                         App Store Connect API key used to authenticate
#                         xcodebuild's -allowProvisioningUpdates when no
#                         Xcode account is signed in (CI)
#   SKIP_RUST=1           skip rebuilding the XCFramework (reuse existing)

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
APPLE_DIR="$ROOT/clients/apple"
DIST_DIR="$ROOT/dist"
BUILD_DIR="$APPLE_DIR/build"
EXPORT_OPTIONS="${EXPORT_OPTIONS:-$ROOT/scripts/apple/ExportOptions-adhoc.plist}"
MACOS_EXPORT_OPTIONS="${MACOS_EXPORT_OPTIONS-$ROOT/scripts/apple/ExportOptions-developerid.plist}"
NOTARY_PROFILE="${NOTARY_PROFILE-vault-notary}"
TEAM_ID="${TEAM_ID:-}"

VERSION="$(grep -m1 '^version = ' "$ROOT/Cargo.toml" | cut -d'"' -f2)"
if [[ ! "$VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    echo "error: Apple packaging requires a numeric major.minor.patch version; prerelease suffixes are not supported." >&2
    exit 1
fi

# Fail fast with a clear message when no team is available: the committed
# Shared.xcconfig ships with an empty TEAM_ID, so signing needs TEAM_ID
# from the environment or from Config/Local.xcconfig (git-ignored).
if [[ -z "$TEAM_ID" ]] && ! grep -Eq '^[[:blank:]]*TEAM_ID[[:blank:]]*=[[:blank:]]*[A-Z0-9]{10}[[:space:]]*(//.*)?$' \
    "$APPLE_DIR/Config/Shared.xcconfig" "$APPLE_DIR/Config/Local.xcconfig" 2>/dev/null; then
    echo "error: no Apple Developer team configured." >&2
    echo "Pass TEAM_ID (e.g. TEAM_ID=ABCDE12345 $0) or set TEAM_ID in clients/apple/Config/Local.xcconfig." >&2
    exit 1
fi

# Fail fast when the Apple timestamp server is unreachable: Release signing
# uses the hardened runtime, which requires a secure timestamp from
# timestamp.apple.com; otherwise the build only fails at the codesign step
# (a common failure when a VPN/proxy is active while packaging).
if ! curl -sS -o /dev/null --connect-timeout 5 --max-time 10 \
    http://timestamp.apple.com/ts01; then
    echo "error: cannot reach timestamp.apple.com; Release codesign needs it for the secure timestamp." >&2
    echo "Disconnect any VPN/proxy that may block it, then re-run." >&2
    exit 1
fi

# Cargo supplies the marketing version. Git history and tracked local edits
# supply the build identity. Different version identifiers trigger the system
# extension replacement delegate; our delegate requests replacement.
# Dirty builds append a minute timestamp. This is a development build identity,
# not a promise of a globally monotonic counter across branches or machines.
COMMITS="$(git -C "$ROOT" rev-list --count HEAD 2>/dev/null || echo 0)"
if git -C "$ROOT" diff-index --quiet HEAD -- 2>/dev/null; then
    BUILD_NUMBER="$COMMITS"
else
    BUILD_NUMBER="$COMMITS.$(date +%Y%m%d%H%M)"
fi
echo "==> Version: $VERSION ($BUILD_NUMBER)"
XCB_VERSION=("MARKETING_VERSION=$VERSION" "CURRENT_PROJECT_VERSION=$BUILD_NUMBER")

# When TEAM_ID is set, override the project's DEVELOPMENT_TEAM and inject the
# team into the export options (the plists in the repo carry no teamID).
XCB_TEAM=()
if [[ -n "$TEAM_ID" ]]; then
    XCB_TEAM=("DEVELOPMENT_TEAM=$TEAM_ID")
fi

# App Store Connect API key authentication for -allowProvisioningUpdates.
# Required in CI, where no Xcode account is signed in; locally Xcode's
# logged-in account is used instead and these stay empty.
XCB_AUTH=()
if [[ -n "${ASC_KEY_PATH:-}" && -n "${ASC_KEY_ID:-}" && -n "${ASC_KEY_ISSUER:-}" ]]; then
    XCB_AUTH=(-authenticationKeyPath "$ASC_KEY_PATH"
        -authenticationKeyID "$ASC_KEY_ID"
        -authenticationKeyIssuerID "$ASC_KEY_ISSUER")
fi

# Prints the exportOptions plist to use: the source file as-is, or a copy
# under BUILD_DIR with teamID inserted when TEAM_ID is set.
resolve_export_options() {
    local src="$1"
    if [[ -z "$TEAM_ID" ]]; then
        printf '%s\n' "$src"
        return
    fi
    mkdir -p "$BUILD_DIR/export-options"
    local dst="$BUILD_DIR/export-options/$(basename "$src")"
    cp "$src" "$dst"
    plutil -insert teamID -string "$TEAM_ID" "$dst"
    printf '%s\n' "$dst"
}

# Use full Xcode when the Command Line Tools are selected (no iOS SDK there).
if ! xcode-select -p | grep -q "Xcode.app"; then
    export DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer
fi

if [[ "${SKIP_RUST:-0}" != "1" ]]; then
    echo "==> Building Rust XCFramework and Swift bindings"
    "$APPLE_DIR/VaultCore/Scripts/build-xcframework.sh"
fi

echo "==> Archiving iOS (Release)"
xcodebuild -project "$APPLE_DIR/Vault.xcodeproj" \
    -scheme Vault \
    -destination 'generic/platform=iOS' \
    -configuration Release \
    -archivePath "$BUILD_DIR/Vault-iOS.xcarchive" \
    -allowProvisioningUpdates \
    ${XCB_TEAM[@]+"${XCB_TEAM[@]}"} \
    ${XCB_AUTH[@]+"${XCB_AUTH[@]}"} \
    "${XCB_VERSION[@]}" \
    archive

echo "==> Exporting iOS IPA"
xcodebuild -exportArchive \
    -archivePath "$BUILD_DIR/Vault-iOS.xcarchive" \
    -exportPath "$BUILD_DIR/ios-ipa" \
    -exportOptionsPlist "$(resolve_export_options "$EXPORT_OPTIONS")" \
    -allowProvisioningUpdates \
    ${XCB_AUTH[@]+"${XCB_AUTH[@]}"}

echo "==> Archiving macOS (Release)"
xcodebuild -project "$APPLE_DIR/Vault.xcodeproj" \
    -scheme Vault \
    -destination 'platform=macOS' \
    -configuration Release \
    -archivePath "$BUILD_DIR/Vault-macOS.xcarchive" \
    -allowProvisioningUpdates \
    ${XCB_TEAM[@]+"${XCB_TEAM[@]}"} \
    ${XCB_AUTH[@]+"${XCB_AUTH[@]}"} \
    "${XCB_VERSION[@]}" \
    archive

# With MACOS_EXPORT_OPTIONS set (the default), the app is re-signed from the
# archive (Developer ID) as notarization and Gatekeeper require; with it set
# to empty, the development-signed .app is taken straight from the archive.
MACOS_APP="$BUILD_DIR/Vault-macOS.xcarchive/Products/Applications/Vault.app"
if [[ -n "${MACOS_EXPORT_OPTIONS:-}" ]]; then
    echo "==> Exporting macOS app (re-signing)"
    xcodebuild -exportArchive \
        -archivePath "$BUILD_DIR/Vault-macOS.xcarchive" \
        -exportPath "$BUILD_DIR/macos-export" \
        -exportOptionsPlist "$(resolve_export_options "$MACOS_EXPORT_OPTIONS")" \
        -allowProvisioningUpdates \
        ${XCB_AUTH[@]+"${XCB_AUTH[@]}"}
    MACOS_APP="$BUILD_DIR/macos-export/Vault.app"
fi

mkdir -p "$DIST_DIR"
cp "$BUILD_DIR/ios-ipa/Vault.ipa" "$DIST_DIR/Vault-iOS.ipa"
rm -f "$DIST_DIR/Vault-macOS.zip"
ditto -c -k --keepParent "$MACOS_APP" "$DIST_DIR/Vault-macOS.zip"

if [[ -n "${NOTARY_PROFILE:-}" ]]; then
    echo "==> Notarizing macOS app (profile: $NOTARY_PROFILE)"
    xcrun notarytool submit "$DIST_DIR/Vault-macOS.zip" \
        --keychain-profile "$NOTARY_PROFILE" --wait
    echo "==> Stapling notarization ticket"
    xcrun stapler staple "$MACOS_APP"
    # Re-create the zip so it ships the stapled app.
    rm -f "$DIST_DIR/Vault-macOS.zip"
    ditto -c -k --keepParent "$MACOS_APP" "$DIST_DIR/Vault-macOS.zip"
fi

echo ""
echo "Done:"
ls -lh "$DIST_DIR"/Vault-iOS.ipa "$DIST_DIR"/Vault-macOS.zip
