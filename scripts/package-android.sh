#!/usr/bin/env bash
#
# Packages the Android client as a signed release APK.
#
# Prerequisites:
#   - Android SDK + NDK (local.properties: sdk.dir)
#   - Release keystore: clients/android/vault-release.keystore
#     and signing.* entries in clients/android/local.properties
#     (both are gitignored; or use SIGNING_KEY_STORE_* env vars)
#   - Rust Android targets + cargo-ndk
#
# Usage: scripts/package-android.sh

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ANDROID_DIR="$ROOT/clients/android"
DIST_DIR="$ROOT/dist"

cd "$ANDROID_DIR"

# Single version source: the workspace package version in the root
# Cargo.toml. versionCode is derived as major*10000 + minor*100 + patch.
VERSION="$(grep -m1 '^version = ' "$ROOT/Cargo.toml" | cut -d'"' -f2)"
IFS='.' read -r V_MAJOR V_MINOR V_PATCH <<< "$VERSION"
VERSION_CODE=$((V_MAJOR * 10000 + V_MINOR * 100 + V_PATCH))
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
