#!/usr/bin/env bash
#
# Builds the vault-bridge Rust library (thin UniFFI wrapper over vault-core)
# for all Apple targets, generates the Swift bindings and packages everything
# as Frameworks/VaultCoreFFI.xcframework consumed by the SwiftPM binaryTarget.
#
# Prerequisites:
#   - Rust toolchain with the targets below (rustup target add ...)
#   - protoc (e.g. brew install protobuf)
#   - Full Xcode (iOS SDK). If xcode-select points at the Command Line Tools,
#     DEVELOPER_DIR is set automatically.
#
# Usage: VaultCore/Scripts/build-xcframework.sh

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PKG_DIR="$(dirname "$SCRIPT_DIR")"
# The shared UniFFI bridge crate lives at <repo>/clients/bridge,
# outside the SwiftPM package.
RUST_DIR="$(dirname "$(dirname "$PKG_DIR")")/bridge"
GEN_DIR="$PKG_DIR/Sources/VaultCore/Generated"
BUILD_DIR="$PKG_DIR/build"
FRAMEWORKS_DIR="$PKG_DIR/Frameworks"
FFI_MODULE="VaultCoreFFI"

CARGO="${CARGO:-$HOME/.cargo/bin/cargo}"
# Pin the crate's target dir next to the crate (it is a workspace member).
export CARGO_TARGET_DIR="$RUST_DIR/target"

# ring's build script needs the Apple SDKs; the Command Line Tools only ship
# the macOS SDK, so fall back to full Xcode when the iOS SDK is missing.
if ! xcrun --show-sdk-path --sdk iphoneos >/dev/null 2>&1; then
    if [ -d /Applications/Xcode.app/Contents/Developer ]; then
        export DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer
    else
        echo "error: iOS SDK not found; install Xcode or run:" >&2
        echo "  sudo xcode-select -s /Applications/Xcode.app/Contents/Developer" >&2
        exit 1
    fi
fi

# Match the deployment targets declared in Package.swift. Without these,
# clang (cc crate: ring, oslog wrapper, ...) and rustc stamp object files
# with the SDK version as their minimum OS, and ld warns:
#   "object file ... was built for newer 'iOS' version (26.2) than being linked (18.5)"
export IPHONEOS_DEPLOYMENT_TARGET=18.0
export MACOSX_DEPLOYMENT_TARGET=15.0

IOS_DEVICE=aarch64-apple-ios
SIM_TARGETS=(aarch64-apple-ios-sim x86_64-apple-ios)
MAC_TARGETS=(aarch64-apple-darwin x86_64-apple-darwin)
ALL_TARGETS=("$IOS_DEVICE" "${SIM_TARGETS[@]}" "${MAC_TARGETS[@]}")

missing=()
installed="$(rustup target list --installed)"
for t in "${ALL_TARGETS[@]}"; do
    grep -qx "$t" <<<"$installed" || missing+=("$t")
done
if ((${#missing[@]})); then
    echo "error: missing Rust targets: ${missing[*]}" >&2
    echo "install with: rustup target add ${missing[*]}" >&2
    exit 1
fi

cd "$RUST_DIR"

echo "==> Building host library for UniFFI bindgen"
"$CARGO" build

echo "==> Generating Swift bindings"
BINDINGS_DIR="$BUILD_DIR/bindings"
rm -rf "$BINDINGS_DIR"
"$CARGO" run --features bindgen --bin uniffi-bindgen -- \
    generate \
    --library target/debug/libvault_bridge.dylib \
    --language swift \
    --out-dir "$BINDINGS_DIR"
mkdir -p "$GEN_DIR"
cp "$BINDINGS_DIR/vault_bridge.swift" "$GEN_DIR/vault_bridge.swift"

echo "==> Building static libraries (${ALL_TARGETS[*]})"
for t in "${ALL_TARGETS[@]}"; do
    "$CARGO" build --release --target "$t"
done

echo "==> Creating universal libraries (lipo)"
mkdir -p "$BUILD_DIR/lipo"
lipo -create \
    target/aarch64-apple-ios-sim/release/libvault_bridge.a \
    target/x86_64-apple-ios/release/libvault_bridge.a \
    -output "$BUILD_DIR/lipo/libvault_bridge_iossim.a"
lipo -create \
    target/aarch64-apple-darwin/release/libvault_bridge.a \
    target/x86_64-apple-darwin/release/libvault_bridge.a \
    -output "$BUILD_DIR/lipo/libvault_bridge_macos.a"

echo "==> Creating XCFramework"
HEADERS_DIR="$BUILD_DIR/headers"
rm -rf "$HEADERS_DIR"
mkdir -p "$HEADERS_DIR"
cp "$BINDINGS_DIR/$FFI_MODULE.h" "$HEADERS_DIR/"
# XCFramework slices expect a conventional module.modulemap.
cp "$BINDINGS_DIR/$FFI_MODULE.modulemap" "$HEADERS_DIR/module.modulemap"

rm -rf "$FRAMEWORKS_DIR/VaultCoreFFI.xcframework"
mkdir -p "$FRAMEWORKS_DIR"
xcodebuild -create-xcframework \
    -library "target/$IOS_DEVICE/release/libvault_bridge.a" -headers "$HEADERS_DIR" \
    -library "$BUILD_DIR/lipo/libvault_bridge_iossim.a" -headers "$HEADERS_DIR" \
    -library "$BUILD_DIR/lipo/libvault_bridge_macos.a" -headers "$HEADERS_DIR" \
    -output "$FRAMEWORKS_DIR/VaultCoreFFI.xcframework"

echo ""
echo "Done."
echo "  XCFramework: $FRAMEWORKS_DIR/VaultCoreFFI.xcframework"
echo "  Bindings:    $GEN_DIR/vault_bridge.swift"
