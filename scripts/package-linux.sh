#!/usr/bin/env bash
#
# Packages the Linux client (edge) and server (supernode) as amd64 and arm64
# .deb/.rpm packages and minimal statically linked binary tarballs.
#
# Cross-building uses Zig for Linux C dependencies (ring and bundled SQLite)
# as well as linking. rust-lld alone cannot compile those dependencies.
#
# Prerequisites:
#   - rustup target add x86_64-unknown-linux-musl aarch64-unknown-linux-musl
#   - cargo install cargo-deb cargo-generate-rpm (except for binary-only builds)
#   - cargo install cargo-zigbuild
#   - zig (on macOS: brew install zig)
#   - asciidoctor (only for system packaging)
#
# Usage: scripts/package-linux.sh
#        scripts/package-linux.sh --binaries-only
#        scripts/package-linux.sh --binary PACKAGE TARGET
#        scripts/package-linux.sh --manpages-only

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DIST_DIR="${DIST_DIR:-$ROOT/dist}"
VERSION="$(grep -m1 '^version = ' "$ROOT/Cargo.toml" | cut -d'"' -f2)"
TARGETS=(x86_64-unknown-linux-musl aarch64-unknown-linux-musl)

arch_for_target() {
    case "$1" in
        x86_64-unknown-linux-musl) echo amd64 ;;
        aarch64-unknown-linux-musl) echo arm64 ;;
        *)
            echo "error: unsupported Linux target: $1" >&2
            return 1
            ;;
    esac
}

package_binary() {
    local pkg="$1" target="$2"
    local arch bundle staging
    arch="$(arch_for_target "$target")"
    bundle="$pkg-v$VERSION-$arch"
    staging="$ROOT/target/binary-packages/$bundle"
    rm -rf "$staging"
    mkdir -p "$staging" "$DIST_DIR"
    install -m 755 "$ROOT/target/$target/release/$pkg" "$staging/$pkg"
    install -m 644 "$ROOT/LICENSE" "$ROOT/NOTICE" "$staging/"
    tar -C "$ROOT/target/binary-packages" -czf "$DIST_DIR/$bundle.tar.gz" "$bundle"
    rm -rf "$staging"
}

build_binary() {
    local pkg="$1" target="$2"
    echo "==> Building static binary: $pkg ($target)"
    cargo zigbuild -p "$pkg" --release --target "$target" --locked
    package_binary "$pkg" "$target"
}

# Packaging owns these files explicitly; Cargo cache hits must not skip them.
generate_manpages() {
    command -v asciidoctor >/dev/null 2>&1 || {
        echo "error: asciidoctor not found; install it before packaging" >&2
        return 1
    }
    for component in clients/linux/edge supernode/supernode; do
        local source="$ROOT/$component.adoc"
        local output="$(dirname "$source")/target/$(basename "$component").1"
        mkdir -p "$(dirname "$output")"
        asciidoctor -b manpage -o "$output" "$source"
        gzip -f "$output"
    done
}

mode=all
if [[ "${1:-}" == --manpages-only && $# == 1 ]]; then
    generate_manpages
    exit
elif [[ "${1:-}" == --binaries-only && $# == 1 ]]; then
    mode=binaries
elif [[ "${1:-}" == --binary && $# == 3 ]]; then
    mode=single
    single_pkg="$2"
    single_target="$3"
    [[ "$single_pkg" == edge || "$single_pkg" == supernode ]] || {
        echo "error: package must be edge or supernode" >&2
        exit 1
    }
    arch_for_target "$single_target" >/dev/null
    TARGETS=("$single_target")
elif (($#)); then
    echo "Usage: $0 [--binaries-only | --binary PACKAGE TARGET | --manpages-only]" >&2
    exit 1
fi

for tool in cargo-zigbuild zig; do
    if ! command -v "$tool" >/dev/null 2>&1; then
        case "$tool" in
            cargo-zigbuild) hint="cargo install cargo-zigbuild" ;;
            zig) hint="brew install zig (macOS), or install Zig from ziglang.org" ;;
        esac
        echo "error: $tool not found; install with: $hint" >&2
        exit 1
    fi
done
for target in "${TARGETS[@]}"; do
    if ! rustup target list --installed | grep -qx "$target"; then
        echo "error: missing Rust target; install with: rustup target add $target" >&2
        exit 1
    fi
done

if [[ "$mode" == all ]]; then
    for tool in cargo-deb cargo-generate-rpm; do
        if ! command -v "$tool" >/dev/null 2>&1; then
            echo "error: $tool not found; install with: cargo install $tool" >&2
            exit 1
        fi
    done
    if ! command -v asciidoctor >/dev/null 2>&1; then
        echo "error: asciidoctor not found; install with: gem install asciidoctor" >&2
        exit 1
    fi
fi

# Let cargo-zigbuild configure both the C compiler and linker. A global
# RUSTFLAGS linker override would bypass Zig's target/sysroot configuration.

cd "$ROOT"
mkdir -p "$DIST_DIR"
if [[ "$mode" == all ]]; then
    generate_manpages
fi
for target in "${TARGETS[@]}"; do
    arch="$(arch_for_target "$target")"
    packages=(edge supernode)
    if [[ "$mode" == single ]]; then
        packages=("$single_pkg")
    fi
    for pkg in "${packages[@]}"; do
        build_binary "$pkg" "$target"
        if [[ "$mode" == all ]]; then
            rpm_dir="$pkg"
            if [[ "$pkg" == edge ]]; then
                rpm_dir=clients/linux
            fi
            cargo deb -p "$pkg" --variant musl --target "$target" --no-build --no-strip --output "$DIST_DIR/"
            cargo generate-rpm -p "$rpm_dir" --variant musl --target "$target" --output "$DIST_DIR/$pkg-v$VERSION-$arch.rpm"
        fi
    done
done

echo ""
echo "Done:"
shopt -s nullglob
artifacts=("$DIST_DIR"/*.deb "$DIST_DIR"/*.rpm "$DIST_DIR"/*.tar.gz)
ls -lh "${artifacts[@]}"
