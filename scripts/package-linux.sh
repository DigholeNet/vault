#!/usr/bin/env bash
#
# Packages the Linux client (edge) and server (supernode) as
# .deb packages for x86_64.
#
# Cross-building from macOS works because the musl target links statically
# with rust-lld (no Linux toolchain needed).
#
# Prerequisites:
#   - rustup target add x86_64-unknown-linux-musl
#   - cargo install cargo-deb
#   - asciidoctor (optional, for manpages; builds warn without it)
#
# Usage: scripts/package-linux.sh

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DIST_DIR="$ROOT/dist"
TARGET="x86_64-unknown-linux-musl"

if ! command -v cargo-deb >/dev/null 2>&1; then
    echo "error: cargo-deb not found; install with: cargo install cargo-deb" >&2
    exit 1
fi
if ! rustup target list --installed | grep -qx "$TARGET"; then
    echo "error: missing Rust target; install with: rustup target add $TARGET" >&2
    exit 1
fi
if ! command -v asciidoctor >/dev/null 2>&1; then
    echo "warning: asciidoctor not found; manpages will be skipped" >&2
fi

# rust-lld replaces the host system linker (Apple ld / GNU ld both reject
# each other's flags); musl links statically so the .deb has no libc dep.
export RUSTFLAGS="-C linker=rust-lld"

cd "$ROOT"
for pkg in edge supernode; do
    echo "==> Building deb: $pkg ($TARGET)"
    cargo deb -p "$pkg" --target "$TARGET" --no-strip
done

mkdir -p "$DIST_DIR"
cp target/debian/*.deb "$DIST_DIR/"

echo ""
echo "Done:"
ls -lh "$DIST_DIR"/*.deb
