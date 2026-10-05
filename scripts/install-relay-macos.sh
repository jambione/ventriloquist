#!/usr/bin/env bash
# Install vq-relay on macOS as a launchd user agent (run as the owner, no sudo
# needed except for writing /usr/local/bin).
#
#   scripts/install-relay-macos.sh [--token-file FILE]
#
# Builds the release binary if needed, installs it to /usr/local/bin/vq-relay,
# creates the owner-token file (0600; generated unless one exists or is given),
# installs the launchd plist and loads it with `launchctl bootstrap`.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
LABEL=com.jbrasfield.vq-relay
DATA_DIR="$HOME/Library/Application Support/vq-relay"
TOKEN_FILE="$DATA_DIR/owner-token"
PLIST="$HOME/Library/LaunchAgents/$LABEL.plist"
BIN=/usr/local/bin/vq-relay

if [ "${1:-}" = "--token-file" ]; then SRC_TOKEN="${2:?--token-file needs a path}"; fi

if [ "$(uname)" != "Darwin" ]; then echo "macOS only" >&2; exit 1; fi

# shellcheck disable=SC1091
[ -f "$HOME/.cargo/env" ] && . "$HOME/.cargo/env"
# Always build: after a `git pull` the existing binary may be stale (cargo is a
# no-op when nothing changed).
(cd "$ROOT" && cargo build --release -p vq-relay)

sudo install -m 755 "$ROOT/target/release/vq-relay" "$BIN"

mkdir -p "$DATA_DIR" "$HOME/Library/Logs" "$HOME/Library/LaunchAgents"
chmod 700 "$DATA_DIR"
if [ -n "${SRC_TOKEN:-}" ]; then
  install -m 600 "$SRC_TOKEN" "$TOKEN_FILE"
elif [ ! -f "$TOKEN_FILE" ]; then
  (umask 077 && openssl rand -base64 32 > "$TOKEN_FILE")
  echo "Generated a new owner token in $TOKEN_FILE"
fi
chmod 600 "$TOKEN_FILE"

sed "s|__HOME__|$HOME|g" "$ROOT/relay/deploy/$LABEL.plist" > "$PLIST"
plutil -lint "$PLIST" >/dev/null

DOMAIN="gui/$(id -u)"
launchctl bootout "$DOMAIN/$LABEL" 2>/dev/null || true
launchctl bootstrap "$DOMAIN" "$PLIST"
launchctl kickstart -k "$DOMAIN/$LABEL"

sleep 1
curl -fsS http://127.0.0.1:8787/v1/health && echo
echo "vq-relay is running. Owner token (paste into the desktop app, Settings > Relay):"
cat "$TOKEN_FILE"
