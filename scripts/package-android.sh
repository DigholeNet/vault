#!/usr/bin/env bash
#
# Packages the Android client as a signed release APK.
#
# Prerequisites:
#   - Android SDK + NDK (local.properties: sdk.dir)
#   - Release signing: signing.keyStoreBase64 / signing.keyStorePassword /
#     signing.keyAlias in clients/android/local.properties (gitignored), or
#     the ANDROID_SIGNING_KEY_STORE_* env vars; the base64 keystore is decoded into
#     app/build/ at build time, and no keystore file is tracked in git
#   - Rust Android targets + cargo-ndk and protoc
#
# Usage: scripts/package-android.sh
#        scripts/package-android.sh --version-code [VERSION] (no build)

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ANDROID_DIR="$ROOT/clients/android"
DIST_DIR="$ROOT/dist"

# Keep release CI and local packaging on the same version-code policy.
version_code() {
    local component='(0|[1-9][0-9]?)'
    local pattern="^${component}\.${component}\.${component}(-(alpha|beta|rc)\.([1-9][0-9]{0,2}))?$"
    if [[ ! "$1" =~ $pattern ]]; then
        echo "error: expected major.minor.patch[-alpha.N|-beta.N|-rc.N]; components 0-99, N 1-499" >&2
        return 1
    fi
    local major="${BASH_REMATCH[1]}" minor="${BASH_REMATCH[2]}" patch="${BASH_REMATCH[3]}"
    local stage="${BASH_REMATCH[5]:-}" sequence="${BASH_REMATCH[6]:-0}" rank=1999
    if ((sequence > 499)); then
        echo "error: prerelease sequence must be between 1 and 499" >&2
        return 1
    fi
    case "$stage" in
        alpha) rank=$sequence ;;
        beta) rank=$((500 + sequence)) ;;
        rc) rank=$((1000 + sequence)) ;;
    esac
    echo "$(((major * 10000 + minor * 100 + patch) * 2000 + rank))"
}

VERSION="$(grep -m1 '^version = ' "$ROOT/Cargo.toml" | cut -d'"' -f2)"
if [[ "${1:-}" == --version-code && $# -le 2 ]]; then
    version_code "${2:-$VERSION}"
    exit
elif (($#)); then
    echo "Usage: $0 [--version-code [VERSION]]" >&2
    exit 1
fi
VERSION_CODE="$(version_code "$VERSION")"
cd "$ANDROID_DIR"
echo "==> Version: $VERSION (versionCode $VERSION_CODE)"

echo "==> Building signed release APK"
./gradlew :app:assembleRelease --no-daemon \
    -PversionName="$VERSION" -PversionCode="$VERSION_CODE"

APK="app/build/outputs/apk/release/app-release.apk"
if [[ ! -f "$APK" ]]; then
    echo "error: APK not found at $APK" >&2
    exit 1
fi

mkdir -p "$DIST_DIR"
cp "$APK" "$DIST_DIR/vault-android.apk"

echo ""
echo "Done: $DIST_DIR/vault-android.apk"
