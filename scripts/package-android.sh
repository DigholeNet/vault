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
# Strip any pre-release suffix (e.g. 1.0.0-rc1 -> V_PATCH=0) so the
# arithmetic never sees a non-numeric component.
V_PATCH="${V_PATCH%%[!0-9]*}"
for part in V_MAJOR V_MINOR V_PATCH; do
    if [[ ! "${!part}" =~ ^[0-9]+$ ]]; then
        echo "error: invalid version component $part='${!part}' in version '$VERSION'" >&2
        exit 1
    fi
done
VERSION_CODE=$((V_MAJOR * 10000 + V_MINOR * 100 + V_PATCH))
# Pre-release versions (1.0.0-rc1) must sort below the final release so an
# installed rc APK can upgrade to it.
if [[ "$VERSION" == *-* && "$VERSION_CODE" -gt 1 ]]; then
    VERSION_CODE=$((VERSION_CODE - 1))
fi
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
