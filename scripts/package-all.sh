#!/usr/bin/env bash
#
# Packages all platforms into dist/:
#   - Android signed APK
#   - Linux client + server .deb (x86_64)
#   - Apple iOS IPA + macOS app zip
#
# Usage: TEAM_ID=<your-team-id> scripts/package-all.sh
#   SKIP_ANDROID=1 / SKIP_LINUX=1 / SKIP_APPLE=1 to skip a platform.
#   TEAM_ID is required for the Apple step unless TEAM_ID is set in
#   clients/apple/Config/Local.xcconfig (see scripts/package-apple.sh).

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

[[ "${SKIP_ANDROID:-0}" == "1" ]] || "$ROOT/scripts/package-android.sh"
[[ "${SKIP_LINUX:-0}" == "1" ]]   || "$ROOT/scripts/package-linux.sh"
[[ "${SKIP_APPLE:-0}" == "1" ]]   || "$ROOT/scripts/package-apple.sh"

echo ""
echo "==> All artifacts in $ROOT/dist:"
ls -lh "$ROOT/dist"
