#!/usr/bin/env bash
# Build the macOS desktop app signed with the owner's Apple Development identity
# and install it to ~/Desktop. A stable signature keeps macOS privacy grants
# (Accessibility, Documents) valid across rebuilds; ad-hoc builds lose them.
#
#   scripts/build-mac-local.sh            # uses the first "Apple Development" identity
#   APPLE_SIGNING_IDENTITY="..." scripts/build-mac-local.sh
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck disable=SC1091
[ -f "$HOME/.cargo/env" ] && . "$HOME/.cargo/env"
if [ -z "${APPLE_SIGNING_IDENTITY:-}" ]; then
  APPLE_SIGNING_IDENTITY="$(security find-identity -v -p codesigning | sed -n 's/.*"\(Apple Development:[^"]*\)".*/\1/p' | head -1)"
fi
[ -n "$APPLE_SIGNING_IDENTITY" ] || { echo "no Apple Development signing identity found" >&2; exit 1; }
export APPLE_SIGNING_IDENTITY
(cd "$ROOT/desktop/app" && npm ci --silent && cargo tauri build)
pkill -f "Ventriloquist.app/Contents/MacOS" || true
sleep 2
rm -rf "$HOME/Desktop/Ventriloquist.app"
ditto "$ROOT/target/release/bundle/macos/Ventriloquist.app" "$HOME/Desktop/Ventriloquist.app"
codesign -dv "$HOME/Desktop/Ventriloquist.app" 2>&1 | grep -E "Authority=Apple Development|TeamIdentifier"
open "$HOME/Desktop/Ventriloquist.app"
