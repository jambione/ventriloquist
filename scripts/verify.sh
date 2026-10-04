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

# Gate 3: end-to-end over the TCP dev transport: vq-host (debug, dev-tcp)
# against PhoneSim (the real PhoneEngine). run.sh builds both itself.
gate3_e2e() {
  step "gate 3: swift build --product PhoneSim (ios/VQProtocol)"
  (cd ios/VQProtocol && swift build --product PhoneSim)
  step "gate 3: tests/e2e/run.sh"
  tests/e2e/run.sh
}

# Gate 4 (desktop half): the Tauri app. Clippy over the whole workspace
# (default features: the app must never get dev-tcp), then the bundle.
gate4_desktop() {
  step "gate 4: cargo clippy --workspace (default features)"
  cargo clippy --workspace --all-targets -- -D warnings
  step "gate 4: app must not depend on vq-host-core/dev-tcp"
  local tree
  tree="$(cargo tree -p ventriloquist-desktop -e features -i vq-host-core)"
  if grep -q 'dev-tcp' <<<"$tree"; then
    echo "error: the app enables vq-host-core/dev-tcp" >&2
    return 1
  fi
  step "gate 4: frontend dependencies (npm ci)"
  (cd desktop/app && npm ci --no-audit --no-fund)
  if [ "$(uname)" = "Darwin" ]; then
    step "gate 4: cargo tauri build (desktop/app)"
    (cd desktop/app && cargo tauri build)
  else
    echo "skipping cargo tauri build (macOS only for agents; Windows is built by the owner)"
  fi
}

# Gate 5: frontend type check (strict), unit tests and production build.
gate5_frontend() {
  step "gate 5: npm ci (desktop/app)"
  (cd desktop/app && npm ci --no-audit --no-fund)
  step "gate 5: tsc --noEmit (strict)"
  (cd desktop/app && npx tsc --noEmit)
  step "gate 5: npm test (vitest)"
  (cd desktop/app && npm test)
  step "gate 5: npm run build"
  (cd desktop/app && npm run build)
}

GATES=(gate1_protocol gate2_desktop_core gate3_e2e gate4_desktop gate5_frontend)

# Run all gates, or only those named on the command line.
if [ "$#" -gt 0 ]; then
  GATES=("$@")
fi
for g in "${GATES[@]}"; do
  "$g"
done
printf '\nAll gates passed: %s\n' "${GATES[*]}"
