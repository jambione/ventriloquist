#!/usr/bin/env bash
# Ventriloquist verification gates. Each gate is a function; later
# milestones append gates and add them to GATES below.
set -euo pipefail

# shellcheck disable=SC1091
. "$HOME/.cargo/env"

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

step() { printf '\n==> %s\n' "$*"; }

# Gate 1: wire protocol (Rust crate + Swift package agree on the vectors).
gate1_protocol() {
  step "gate 1: cargo test -p vq-protocol"
  cargo test -p vq-protocol
  step "gate 1: cargo clippy -p vq-protocol"
  cargo clippy -p vq-protocol --all-targets -- -D warnings
  step "gate 1: swift test (ios/VQProtocol)"
  (cd ios/VQProtocol && swift test)
}

# Gate 2: desktop core. Tests need the TCP dev transport, which only
# builds in debug (dev-tcp is a compile_error in release).
gate2_desktop_core() {
  step "gate 2: cargo test -p vq-host-core --features dev-tcp"
  cargo test -p vq-host-core --features dev-tcp
  step "gate 2: cargo clippy -p vq-host-core --features dev-tcp"
  cargo clippy -p vq-host-core --all-targets --features dev-tcp -- -D warnings
  step "gate 2: cargo build -p vq-host-core (default features)"
  cargo build -p vq-host-core
  step "gate 2: cargo build -p vq-host-core --no-default-features"
  cargo build -p vq-host-core --no-default-features
  step "gate 2: release build with dev-tcp must be refused"
  if cargo build --release -p vq-host-core --features dev-tcp >/dev/null 2>&1; then
    echo "error: release build with dev-tcp succeeded (compile_error guard missing)" >&2
    return 1
  fi
}

GATES=(gate1_protocol gate2_desktop_core)

# Run all gates, or only those named on the command line.
if [ "$#" -gt 0 ]; then
  GATES=("$@")
fi
for g in "${GATES[@]}"; do
  "$g"
done
printf '\nAll gates passed: %s\n' "${GATES[*]}"
