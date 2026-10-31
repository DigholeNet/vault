#!/usr/bin/env bash
#
# Packages the Linux client (edge) and server (supernode) as
# .deb packages for x86_64.
#
# Cross-building uses Zig for Linux C dependencies (ring and bundled SQLite)
# as well as linking. rust-lld alone cannot compile those dependencies.
#
# Prerequisites:
#   - rustup target add x86_64-unknown-linux-musl
#   - cargo install cargo-deb
#   - cargo install cargo-zigbuild
#   - zig (on macOS: brew install zig)
#   - asciidoctor (on macOS: brew install asciidoctor)
#
# Usage: scripts/package-linux.sh
#        scripts/package-linux.sh --manpages-only

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DIST_DIR="$ROOT/dist"
TARGET="x86_64-unknown-linux-musl"

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

if [[ "${1:-}" == --manpages-only && $# == 1 ]]; then
    generate_manpages
    exit
elif (($#)); then
    echo "Usage: $0 [--manpages-only]" >&2
    exit 1
fi

if ! command -v cargo-deb >/dev/null 2>&1; then
    echo "error: cargo-deb not found; install with: cargo install cargo-deb" >&2
    exit 1
fi
if ! rustup target list --installed | grep -qx "$TARGET"; then
    echo "error: missing Rust target; install with: rustup target add $TARGET" >&2
    exit 1
fi
for tool in cargo-zigbuild zig asciidoctor; do
    if ! command -v "$tool" >/dev/null 2>&1; then
        case "$tool" in
            cargo-zigbuild) hint="cargo install cargo-zigbuild" ;;
            zig) hint="brew install zig (macOS), or install Zig from ziglang.org" ;;
            asciidoctor) hint="gem install asciidoctor" ;;
        esac
        echo "error: $tool not found; install with: $hint" >&2
        exit 1
    fi
done

# Let cargo-zigbuild configure both the C compiler and linker. A global
# RUSTFLAGS linker override would bypass Zig's target/sysroot configuration.

cd "$ROOT"
mkdir -p "$DIST_DIR"
generate_manpages
for pkg in edge supernode; do
    echo "==> Building deb: $pkg ($TARGET)"
    cargo zigbuild -p "$pkg" --release --target "$TARGET" --locked
    cargo deb -p "$pkg" --target "$TARGET" --no-build --no-strip --output "$DIST_DIR/"
done

echo ""
echo "Done:"
ls -lh "$DIST_DIR"/*.deb
