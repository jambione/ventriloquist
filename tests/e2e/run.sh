#!/usr/bin/env bash
# End-to-end test, SPEC §9 / SPEC_V3 §10 gate 3: the real desktop core
# (`vq-host`) against the real phone engine (`PhoneSim`).
#
# Default: through a real local `vq-relay` (random port and owner token, temp
# data dir): vq-host creates its room, the phone pairs from the QR link that
# vq-host emits (start_phone_pairing), and everything runs over the relay's
# WebSocket (scenarios h and i: long-poll only; relay restart).
# `--tcp`: the old TCP dev transport of protocol/README.md §2.1 (scenarios
# a-g only; vq-host is the TCP client, PhoneSim the server).
#
# Scenarios (each prints PASS or FAIL; the first failure stops the run and
# the rest are reported as SKIP):
#   a  pairing with the code from vq-host's pairing_code_shown (relay: from the
#      QR link, no code shown); secure session
#   b  partials stream, then final, then edit; log format; no partials logged;
#      re-send from history makes a new id
#   c  multi-line + unicode text is byte-exact in entry_upserted and rendered
#      inertly in the log
#   d  drop the connection with an unacked final (desktop never saw it; and
#      desktop saw it but the ack was lost) -> reconnect -> re-delivery ->
#      acked once, shown once, logged once. Relay: the desktop process is
#      frozen and killed with a final pending (the TCP-only "ack lost" half
#      is covered by i)
#   e  restart vq-host (same config dir) -> secure again without re-pairing
#   f  restart PhoneSim (same state dir) -> secure again without re-pairing
#   g  a fresh phone with a wrong pairing code -> pairing fails on both
#      sides; nothing it sends is accepted. Relay: a wrong `c`, and a wrong
#      `k` (desktop key pin mismatch) in the QR link
#   h  (relay) a fresh pairing and session with the WebSocket never used
#      (VQ_RELAY_FORCE_LONGPOLL=1 in both clients)
#   i  (relay) vq-relay is killed mid-session (finals pending, one maybe in
#      flight) and restarted -> both reconnect; every final arrives once
#
# Usage: tests/e2e/run.sh [--tcp]    (env: E2E_TIMEOUT=seconds, default 300;
#                                     E2E_KEEP=1 keeps the temp dir)
# Needs: swift, cargo, python3, curl.
set -euo pipefail
set -E

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
MODE=relay
for arg in "$@"; do
  case "$arg" in
    --tcp) MODE=tcp ;;
    *) echo "usage: tests/e2e/run.sh [--tcp]" >&2; exit 2 ;;
  esac
done
HELPER="$ROOT/tests/e2e/e2e.py"
OVERALL_TIMEOUT="${E2E_TIMEOUT:-300}"
WAIT=20 # default seconds for one awaited event

if [ -f "$HOME/.cargo/env" ]; then
  # shellcheck disable=SC1091
  . "$HOME/.cargo/env"
fi

# Keep the original stdout/stderr on fds 4/5: a trap can fire while a
# function's output is redirected (e.g. `phone ... >/dev/null`), and the
# summary must still reach the terminal.
exec 4>&1 5>&2

WORK="$(mktemp -d "${TMPDIR:-/tmp}/vq-e2e.XXXXXX")"
LOG_DIR="$WORK/logs"
HOST_CFG="$WORK/host-config"
PHONE_STATE="$WORK/phone-state"
RELAY_DATA="$WORK/relay-data"
RELAY_PID=""
RELAY_PORT=""
RELAY_N=0
OWNER_TOKEN=""
FORCE_LP="" # VQ_RELAY_FORCE_LONGPOLL for vq-host and PhoneSim (scenario h)

PHONE_PID=""
HOST_PID=""
WATCHDOG_PID=""
PHONE_EV=""
PHONE_N=0
HOST_EV=""
HOST_N=0
HOST_FILES=()
PORT=""

if [ "$MODE" = tcp ]; then SCENARIOS=(a b c d e f g); else SCENARIOS=(a b c d e f g h i); fi
# bash 3.2 (macOS /bin/bash) has no associative arrays.
title() {
  if [ "$MODE" = relay ]; then
    case "$1" in
      a) echo "pairing from the QR link through the relay; secure session" ;;
      d) echo "desktop frozen+killed with a pending final -> reconnect -> re-delivered, acked once, logged once" ;;
      g) echo "wrong code and wrong key pin in the QR link -> pairing fails, nothing accepted" ;;
      h) echo "long-poll only (no WebSocket): pairing and a session" ;;
      i) echo "vq-relay killed and restarted mid-session -> both reconnect, finals arrive once" ;;
    esac
    [ "$1" = a ] || [ "$1" = d ] || [ "$1" = g ] || [ "$1" = h ] || [ "$1" = i ] || title_common "$1"
    return
  fi
  title_common "$1"
}
title_common() {
  case "$1" in
    a) echo "pairing succeeds on both sides; secure session" ;;
    b) echo "partials, final, edit; log format; re-send" ;;
    c) echo "multi-line + unicode text byte-exact; inert log rendering" ;;
    d) echo "drop with unacked final -> reconnect -> re-delivered, acked once, logged once" ;;
    e) echo "restart vq-host -> reconnect without re-pairing" ;;
    f) echo "restart PhoneSim -> reconnect without re-pairing" ;;
    g) echo "wrong pairing code from a fresh phone -> failure surfaced, nothing accepted" ;;
  esac
}
PASSED=" "
FAILED=""
CURRENT=""
START_TIME=$(date +%s)

say() { printf '%s\n' "$*"; }
note() { printf '    %s\n' "$*"; }

# ---------------------------------------------------------------------------
# Process management and cleanup

stop_pid() { # pid: TERM, then KILL after 5 s
  local pid="$1" i
  [ -n "$pid" ] || return 0
  kill -TERM "$pid" 2>/dev/null || return 0
  for i in $(seq 50); do
    kill -0 "$pid" 2>/dev/null || break
    case "$(ps -o stat= -p "$pid" 2>/dev/null)" in Z*) break ;; esac # exited, not reaped
    sleep 0.1
  done
  kill -KILL "$pid" 2>/dev/null || true
  wait "$pid" 2>/dev/null || true
}

summary() {
  local s status=0
  say ""
  say "==> E2E summary ($(($(date +%s) - START_TIME)) s)"
  for s in "${SCENARIOS[@]}"; do
    local r=SKIP
    case "$PASSED" in *" $s "*) r=PASS ;; esac
    [ "$s" = "$FAILED" ] && r=FAIL
    [ "$r" = PASS ] || status=1
    printf '  %-4s %s: %s\n' "$r" "$s" "$(title "$s")"
  done
  return $status
}

cleanup() {
  local code=$?
  trap - EXIT ERR INT TERM
  set +e
  exec 1>&4 2>&5
  { exec 3>&-; } 2>/dev/null || true
  { exec 6>&-; } 2>/dev/null || true
  stop_pid "$PHONE_PID"
  stop_pid "$HOST_PID"
  stop_pid "$RELAY_PID"
  [ -n "$WATCHDOG_PID" ] && kill "$WATCHDOG_PID" 2>/dev/null || true
  if [ -n "$CURRENT" ]; then
    FAILED="$CURRENT"
    code=1
  fi
  if [ "$code" -ne 0 ]; then
    for f in "$WORK"/*.err; do
      [ -s "$f" ] || continue
      say "  --- last lines of $(basename "$f")"
      tail -n 15 "$f" | sed 's/^/    /'
    done
  fi
  summary || code=1
  if [ "$code" -ne 0 ] || [ "${E2E_KEEP:-0}" = 1 ]; then
    say "  artifacts (event logs *.jsonl, stderr *.err, logs/) kept in $WORK"
  else
    rm -rf "$WORK"
  fi
  exit "$code"
}

on_err() {
  say "FAIL [${CURRENT:-setup}] line $1: $2" >&5
  exit 1
}

trap cleanup EXIT
trap 'on_err "$LINENO" "$BASH_COMMAND"' ERR
trap 'say "interrupted (overall timeout ${OVERALL_TIMEOUT}s?)" >&5; exit 124' INT TERM

# Overall timeout: TERM this script, which runs cleanup (every wait below is
# itself bounded, so the trap runs promptly).
(
  trap - ERR
  for _ in $(seq "$OVERALL_TIMEOUT"); do sleep 1; done
  kill -TERM $$ 2>/dev/null || true
) &
WATCHDOG_PID=$!
disown "$WATCHDOG_PID" 2>/dev/null || true

# ---------------------------------------------------------------------------
# Event helpers

ev() { python3 "$HELPER" "$@"; }
lines() { ev lines "$1"; }
host_mark() { lines "$HOST_EV"; }
phone_mark() { lines "$PHONE_EV"; }
# host_wait AFTER EXPR [k=v ...] / phone_wait AFTER EXPR [k=v ...]
host_wait() { ev wait "$HOST_EV" "$1" "$WAIT" "${@:2}"; }
phone_wait() { ev wait "$PHONE_EV" "$1" "$WAIT" "${@:2}"; }
get() { ev get "$1" "$2"; }

expect_eq() { # actual expected message
  if [ "$1" != "$2" ]; then
    say "    expected $3 = $2, got $1" >&5
    return 1
  fi
}

# ---------------------------------------------------------------------------
# PhoneSim: commands go to its stdin through a FIFO on fd 3; every command is
# answered by command_done / command_failed with the same seq.

phone_start() { # name state_dir port
  PHONE_N=$((PHONE_N + 1))
  PHONE_EV="$WORK/phone-$PHONE_N.jsonl"
  echo 0 >"$WORK/phone.seq"
  local fifo="$WORK/phone-$PHONE_N.fifo"
  mkfifo "$fifo"
  "$PHONESIM" --port "$3" --name "$1" --state-dir "$2" <"$fifo" >"$PHONE_EV" 2>"$WORK/phone-$PHONE_N.err" 3>&- 4>&- 5>&- 6>&- &
  PHONE_PID=$!
  exec 3>"$fifo"
  local listening
  listening=$(phone_wait 0 'e["event"]=="listening"')
  PORT=$(get "$listening" port)
}

phone_start_relay() { # name state_dir [pairing-uri]: without a URI, reconnect to the saved desktops
  PHONE_N=$((PHONE_N + 1))
  PHONE_EV="$WORK/phone-$PHONE_N.jsonl"
  echo 0 >"$WORK/phone.seq"
  local fifo="$WORK/phone-$PHONE_N.fifo" args=(--name "$1" --state-dir "$2")
  mkfifo "$fifo"
  if [ -n "${3:-}" ]; then args+=(--relay-pair-uri "$3"); else args+=(--relay); fi
  VQ_RELAY_FORCE_LONGPOLL="$FORCE_LP" "$PHONESIM" "${args[@]}" <"$fifo" >"$PHONE_EV" 2>"$WORK/phone-$PHONE_N.err" 3>&- 4>&- 5>&- 6>&- &
  PHONE_PID=$!
  exec 3>"$fifo"
  phone_wait 0 'e["event"]=="started"' >/dev/null
}

# The seq counter lives in a file: phone is often called inside $(...), a
# subshell whose variable changes would be lost.
phone_send() { # command line (its seq is then in $WORK/phone.seq)
  local n
  n=$(($(cat "$WORK/phone.seq") + 1))
  printf '%s\n' "$n" >"$WORK/phone.seq"
  printf '%s\n' "$1" >&3
}
last_seq() { cat "$WORK/phone.seq"; }

phone_result() { # seq [timeout] -> the command_done line; fails on command_failed
  local line
  line=$(ev wait "$PHONE_EV" 0 "${2:-$WAIT}" 'e["event"] in ("command_done","command_failed") and e["seq"]==int(s)' "s=$1")
  if [ "$(get "$line" event)" != command_done ]; then
    say "    PhoneSim command $1 failed: $line" >&5
    return 1
  fi
  printf '%s\n' "$line"
}

phone() { # command line; prints its command_done line
  phone_send "$1"
  phone_result "$(last_seq)" "${2:-$WAIT}"
}

phone_stop() { # quit and check the exit status
  phone quit >/dev/null
  exec 3>&-
  local status=0
  wait "$PHONE_PID" || status=$?
  PHONE_PID=""
  expect_eq "$status" 0 "PhoneSim exit status"
}

# ---------------------------------------------------------------------------
# vq-host

host_start() {
  HOST_N=$((HOST_N + 1))
  HOST_EV="$WORK/host-$HOST_N.jsonl"
  HOST_FILES+=("$HOST_EV")
  if [ "$MODE" = tcp ]; then
    VQ_LOG=1 "$VQHOST" --connect "127.0.0.1:$PORT" --log-dir "$LOG_DIR" --config-dir "$HOST_CFG" \
      --name "E2E Desk" </dev/null >"$HOST_EV" 2>"$WORK/host-$HOST_N.err" 3>&- 4>&- 5>&- &
    HOST_PID=$!
  else
    # Commands (start_phone_pairing) go to stdin through a FIFO on fd 6.
    local fifo="$WORK/host-$HOST_N.fifo"
    mkfifo "$fifo"
    VQ_LOG=1 VQ_RELAY_FORCE_LONGPOLL="$FORCE_LP" "$VQHOST" --relay "http://127.0.0.1:$RELAY_PORT" \
      --owner-token "$OWNER_TOKEN" --log-dir "$LOG_DIR" --config-dir "$HOST_CFG" \
      --name "E2E Desk" <"$fifo" >"$HOST_EV" 2>"$WORK/host-$HOST_N.err" 3>&- 4>&- 5>&- &
    HOST_PID=$!
    exec 6>"$fifo"
  fi
  host_wait 0 'e["event"]=="started"' >/dev/null
}

host_stop() {
  local status=0
  kill -TERM "$HOST_PID"
  wait "$HOST_PID" || status=$?
  HOST_PID=""
  { exec 6>&-; } 2>/dev/null || true
  expect_eq "$status" 0 "vq-host exit status"
}

host_kill() { # SIGKILL (also works on a stopped process); no exit status check
  kill -KILL "$HOST_PID" 2>/dev/null || true
  wait "$HOST_PID" 2>/dev/null || true
  HOST_PID=""
  { exec 6>&-; } 2>/dev/null || true
}

host_cmd() { printf '%s\n' "$1" >&6; }

# A fresh pairing URI (it carries the room secret: kept in shell variables
# and the event file only; the code in it is the active v1 pairing code).
pairing_uri() {
  local m
  m=$(host_mark)
  host_cmd '{"command":"start_phone_pairing"}'
  get "$(host_wait "$m" 'e["event"]=="phone_pairing_qr"')" uri
}

relay_start() {
  RELAY_N=$((RELAY_N + 1))
  local i attempt
  for attempt in 1 2 3 4 5; do
    VQ_RELAY_OWNER_TOKEN="$OWNER_TOKEN" "$VQRELAY" --listen "127.0.0.1:$RELAY_PORT" --data-dir "$RELAY_DATA" \
      >"$WORK/relay-$RELAY_N.out" 2>"$WORK/relay-$RELAY_N.err" 3>&- 4>&- 5>&- 6>&- &
    RELAY_PID=$!
    for i in $(seq 50); do
      curl -fsS --max-time 2 "http://127.0.0.1:$RELAY_PORT/v1/health" >/dev/null 2>&1 && return 0
      kill -0 "$RELAY_PID" 2>/dev/null || break
      sleep 0.1
    done
    wait "$RELAY_PID" 2>/dev/null || true # the port may still be closing: retry
    sleep 0.5
  done
  RELAY_PID=""
  say "    vq-relay did not start" >&5
  return 1
}

relay_kill() {
  kill -KILL "$RELAY_PID" 2>/dev/null || true
  wait "$RELAY_PID" 2>/dev/null || true
  RELAY_PID=""
}

log_check() { ev log-check "$LOG_DIR" "${HOST_FILES[@]}"; }
log_count() { ev log-count "$LOG_DIR" "$1"; }

begin() {
  CURRENT="$1"
  say ""
  say "==> scenario $1: $(title "$1")"
}
pass() {
  PASSED="$PASSED$CURRENT "
  say "PASS $CURRENT ($(($(date +%s) - START_TIME)) s since start)"
  CURRENT=""
}

# ---------------------------------------------------------------------------
# Build

say "==> build PhoneSim, vq-host$([ "$MODE" = relay ] && echo ", vq-relay") (debug)"
t0=$(date +%s)
(cd "$ROOT/ios/VQProtocol" && swift build --product PhoneSim 2>&1 | tail -n 3)
PHONESIM="$(cd "$ROOT/ios/VQProtocol" && swift build --show-bin-path)/PhoneSim"
(cd "$ROOT" && cargo build -q -p vq-host-core --features dev-tcp --bin vq-host)
VQHOST="$ROOT/target/debug/vq-host"
VQRELAY="$ROOT/target/debug/vq-relay"
if [ "$MODE" = relay ]; then
  (cd "$ROOT" && cargo build -q -p vq-relay --bin vq-relay)
  [ -x "$VQRELAY" ]
fi
[ -x "$PHONESIM" ] && [ -x "$VQHOST" ]
note "built in $(($(date +%s) - t0)) s; work dir $WORK"

# ---------------------------------------------------------------------------
begin a
if [ "$MODE" = relay ]; then
  RELAY_PORT=$(ev free-port)
  OWNER_TOKEN=$(python3 -c 'import secrets; print(secrets.token_urlsafe(24))')
  relay_start
  note "vq-relay on 127.0.0.1:$RELAY_PORT"
  host_start
  HOST_ID=$(get "$(host_wait 0 'e["event"]=="started"')" device_id)
  host_wait 0 'e["event"]=="relay_status" and e["status"]["link"]=="websocket"' >/dev/null
  URI=$(pairing_uri)
  phone_start_relay "E2E Phone" "$PHONE_STATE" "$URI"
  PHONE_ID=$(get "$(phone_wait 0 'e["event"]=="started"')" device_id)
  phone_wait 0 'e["event"]=="relay_pairing"' >/dev/null
  host_wait 0 'e["event"]=="pairing_result" and e["ok"] is True and e["device_id"]==p' "p=$PHONE_ID" >/dev/null
  host_wait 0 'e["event"]=="paired_peers_changed" and any(x["device_id"]==p for x in e["peers"])' "p=$PHONE_ID" >/dev/null
  host_wait 0 'e["event"]=="phone_pairing_ended" and e["reason"]=="paired"' >/dev/null
  host_wait 0 'e["event"]=="connection_status" and e["state"]=="secure" and e["device_id"]==p and e["paired"] is True' "p=$PHONE_ID" >/dev/null
  phone wait-secure >/dev/null
  phone_wait 0 'e["event"]=="paired" and e["host_id"]==h' "h=$HOST_ID" >/dev/null
  # The QR carries the code: nothing to type, no code modal on the desktop.
  ev expect-count "$HOST_EV" 0 0 'e["event"] in ("pairing_code_shown","pairing_code_ended")'
  [ -f "$PHONE_STATE/relay-desktops.json" ]
  pass
else
phone_start "E2E Phone" "$PHONE_STATE" 0
PHONE_ID=$(get "$(phone_wait 0 'e["event"]=="started"')" device_id)
note "PhoneSim listening on 127.0.0.1:$PORT, device $PHONE_ID"
host_start
HOST_ID=$(get "$(host_wait 0 'e["event"]=="started"')" device_id)
phone wait-connected >/dev/null
# The code exists only once the phone has asked for it: pair asynchronously,
# copy the code vq-host shows into the file PhoneSim is waiting for.
phone_send "pair @$WORK/code-a"
pair_seq=$(last_seq)
shown=$(host_wait 0 'e["event"]=="pairing_code_shown" and e["device_id"]==p' "p=$PHONE_ID")
code=$(get "$shown" code)
[[ "$code" =~ ^[0-9]{6}$ ]]
expect_eq "$(get "$shown" phone_name)" "E2E Phone" "pairing_code_shown.phone_name"
printf '%s\n' "$code" >"$WORK/code-a"
res=$(phone_result "$pair_seq")
expect_eq "$(get "$res" ok)" true "PhoneSim pair_result.ok"
expect_eq "$(get "$res" host_id)" "$HOST_ID" "paired host id"
host_wait 0 'e["event"]=="pairing_result" and e["ok"] is True and e["device_id"]==p' "p=$PHONE_ID" >/dev/null
host_wait 0 'e["event"]=="paired_peers_changed" and any(x["device_id"]==p for x in e["peers"])' "p=$PHONE_ID" >/dev/null
host_wait 0 'e["event"]=="connection_status" and e["state"]=="secure" and e["device_id"]==p and e["paired"] is True' "p=$PHONE_ID" >/dev/null
phone wait-secure >/dev/null
phone_wait 0 'e["event"]=="paired" and e["host_id"]==h' "h=$HOST_ID" >/dev/null
[ -f "$PHONE_STATE/paired-hosts.json" ]
pass
fi

# ---------------------------------------------------------------------------
begin b
m=$(host_mark)
U1=$(get "$(phone start)" id)
phone "partial b-partial-one" >/dev/null
host_wait "$m" 'e["event"]=="entry_upserted" and e["entry"]["id"]==u and e["entry"]["state"]=="partial" and e["entry"]["partial"] is True' "u=$U1" >/dev/null
phone "sleep 300" >/dev/null
phone "partial b-partial-one b-partial-two" >/dev/null
host_wait "$m" 'e["event"]=="entry_upserted" and e["entry"]["id"]==u and e["entry"]["text"]=="b-partial-one b-partial-two"' "u=$U1" >/dev/null
phone "sleep 300" >/dev/null
phone "final kubectl get pods" >/dev/null
phone "wait-acked $U1" >/dev/null
final=$(host_wait "$m" 'e["event"]=="entry_upserted" and e["entry"]["id"]==u and e["entry"]["state"]=="final"' "u=$U1")
expect_eq "$(get "$final" entry.text)" "kubectl get pods" "final text"
expect_eq "$(get "$final" entry.partial)" false "final entry.partial"
expect_eq "$(get "$final" entry.device_name)" "E2E Phone" "final entry.device_name"
phone "edit kubectl get pods -A" >/dev/null
phone "wait-acked $U1" >/dev/null
edit=$(host_wait "$m" 'e["event"]=="entry_upserted" and e["entry"]["id"]==u and e["entry"]["state"]=="edit"' "u=$U1")
expect_eq "$(get "$edit" entry.text)" "kubectl get pods -A" "edit text"
expect_eq "$(get "$edit" entry.edited)" true "edit entry.edited"
# Order on the desktop: partial(s) < final < edit, with increasing rev.
ev expect-count "$HOST_EV" "$m" 1 'e["event"]=="entry_upserted" and e["entry"]["id"]==u and e["entry"]["state"]=="final"' "u=$U1"
ev expect-count "$HOST_EV" "$m" 1 'e["event"]=="entry_upserted" and e["entry"]["id"]==u and e["entry"]["state"]=="edit"' "u=$U1"
[ "$(get "$final" entry.rev)" -lt "$(get "$edit" entry.rev)" ]
# Log: exactly the SPEC §6.2 lines for the final and the edit, nothing else.
DAY=$(get "$final" entry.received_at | cut -c1-10)
LOG_FILE="$LOG_DIR/$DAY.md"
expected="# Ventriloquist — $DAY

- **$(get "$final" entry.time)** · E2E Phone · \`id=${U1:0:8}\`
  kubectl get pods
- **$(get "$edit" entry.time)** · E2E Phone · \`id=${U1:0:8}\` · edited
  kubectl get pods -A"
expect_eq "$(cat "$LOG_FILE")" "$expected" "log file $DAY.md"
expect_eq "$(tail -c 1 "$LOG_FILE" | od -An -c | tr -d ' ')" '\n' "log file ends with a newline"
expect_eq "$(log_count b-partial)" 0 "partials in the log"
log_check
# Re-send from history: a new id with a single final carrying the latest text.
m=$(host_mark)
R1=$(get "$(phone "resend 0")" id)
[ "$R1" != "$U1" ]
phone "wait-acked $R1" >/dev/null
rs=$(host_wait "$m" 'e["event"]=="entry_upserted" and e["entry"]["id"]==r' "r=$R1")
expect_eq "$(get "$rs" entry.state)" final "re-send state"
expect_eq "$(get "$rs" entry.text)" "kubectl get pods -A" "re-send text"
ev expect-count "$HOST_EV" "$m" 1 'e["event"]=="entry_upserted" and e["entry"]["id"]==r' "r=$R1"
log_check
pass

# ---------------------------------------------------------------------------
begin c
# ASCII JSON for: CJK, emoji (+ ZWJ sequence), precomposed and combining é,
# RLO/PDF and RLM (bidi), tab, BEL and ESC, CRLF, an empty line, leading spaces.
UNI='"日本語 CJK 🎉 👨‍👩‍👧 café café\nsecond\tline ‮evil‬ ‏ end\u0007\u001b[31m\r\n\n  indented \"quoted\" \\ backslash `tick` **md**"'
m=$(host_mark)
phone start >/dev/null
phone "partial $UNI" >/dev/null
phone "sleep 250" >/dev/null
C1=$(get "$(phone "final $UNI")" id)
phone "wait-acked $C1" >/dev/null
fin=$(host_wait "$m" 'e["event"]=="entry_upserted" and e["entry"]["id"]==u and e["entry"]["state"]=="final"' "u=$C1")
# Byte-exact: the desktop's text equals the phone's, as UTF-8 bytes, unnormalized.
ev expect-count "$HOST_EV" "$m" 1 'e["event"]=="entry_upserted" and e["entry"]["id"]==u and e["entry"]["state"]=="final" and e["entry"]["text"].encode("utf-8")==json.loads(t).encode("utf-8")' "u=$C1" "t=$UNI"
ev expect-count "$HOST_EV" "$m" 1 'e["event"]=="entry_upserted" and e["entry"]["id"]==u and e["entry"]["state"]=="partial" and e["entry"]["text"]==json.loads(t)' "u=$C1" "t=$UNI"
# Log: the core's documented inert rendering (logger.rs): 2-space indent per
# LF-separated line, CR before LF dropped, controls/bidi as \u{..}, TAB kept.
rendered=$(ev render "$UNI")
block="- **$(get "$fin" entry.time)** · E2E Phone · \`id=${C1:0:8}\`
$rendered"
grep -qF -- "  second	line \\u{202e}evil\\u{202c} \\u{200f} end\\u{7}\\u{1b}[31m" "$LOG_FILE"
grep -qF -- "  日本語 CJK 🎉" "$LOG_FILE"
python3 - "$LOG_FILE" "$block" <<'PY'
import sys
log, block = open(sys.argv[1], encoding="utf-8").read(), sys.argv[2]
assert log.count(block + "\n") == 1, "rendered block not found exactly once"
for b in "\x07\x1b‮‬‏\r":
    assert b not in log, f"raw {b!r} in log"
PY
log_check
pass

# ---------------------------------------------------------------------------
begin d
if [ "$MODE" = relay ]; then
# The desktop is frozen (SIGSTOP: it reads and acks nothing), the phone sends
# a final, then the desktop is killed; a restarted desktop (same config) is
# a new peer, so the phone re-hello's and re-delivers the pending final.
D1=$(get "$(phone start)" id)
pm=$(phone_mark)
phone "partial d1-partial" >/dev/null
host_wait 0 'e["event"]=="entry_upserted" and e["entry"]["id"]==u and e["entry"]["state"]=="partial"' "u=$D1" >/dev/null
kill -STOP "$HOST_PID"
phone "final d1 final sent while the desktop is frozen" >/dev/null
phone "sleep 500" >/dev/null
expect_eq "$(get "$(phone "status $D1")" status)" pending "d1 status before the kill"
host_kill
host_start
host_wait 0 'e["event"]=="started" and any(x["device_id"]==p for x in e["paired_peers"])' "p=$PHONE_ID" >/dev/null
phone "wait-secure 30000" 30 >/dev/null
phone "wait-acked $D1 30000" 30 >/dev/null
host_wait 0 'e["event"]=="entry_upserted" and e["entry"]["id"]==u and e["entry"]["state"]=="final"' "u=$D1" >/dev/null
phone "sleep 500" >/dev/null
ev expect-count "$HOST_EV" 0 1 'e["event"]=="entry_upserted" and e["entry"]["id"]==u and e["entry"]["state"]=="final"' "u=$D1"
ev expect-count "$HOST_EV" 0 1 'e["event"]=="final_accepted" and e["entry"]["id"]==u' "u=$D1"
ev expect-count "$PHONE_EV" "$pm" 1 'e["event"]=="delivery" and e["id"]==u and e["status"]=="acked"' "u=$D1"
expect_eq "$(log_count "id=${D1:0:8}")" 1 "log entries for ${D1:0:8}"
expect_eq "$(log_count d1-partial)" 0 "interrupted partial in the log"
log_check
pass
else
# d1: the final never reaches the desktop (TX paused, then the socket closes).
m=$(host_mark)
pm=$(phone_mark)
D1=$(get "$(phone start)" id)
phone "partial d1-partial" >/dev/null
host_wait "$m" 'e["event"]=="entry_upserted" and e["entry"]["id"]==u and e["entry"]["state"]=="partial"' "u=$D1" >/dev/null
phone tx-pause >/dev/null
phone "final d1 final sent while the link drops" >/dev/null
expect_eq "$(get "$(phone "status $D1")" status)" pending "d1 status before drop"
phone drop-connection >/dev/null
host_wait "$m" 'e["event"]=="connection_status" and e["state"]=="closed" and e["device_id"]==p' "p=$PHONE_ID" >/dev/null
host_wait "$m" 'e["event"]=="entry_upserted" and e["entry"]["id"]==u and e["entry"]["state"]=="interrupted"' "u=$D1" >/dev/null
phone "wait-secure 30000" 30 >/dev/null
phone "wait-acked $D1 30000" 30 >/dev/null
host_wait "$m" 'e["event"]=="entry_upserted" and e["entry"]["id"]==u and e["entry"]["state"]=="final"' "u=$D1" >/dev/null
# d2: the desktop gets the final but the ack is lost (RX paused, then drop).
phone rx-pause >/dev/null
D2=$(get "$(phone start)" id)
phone "final d2 final whose ack is lost" >/dev/null
host_wait "$m" 'e["event"]=="entry_upserted" and e["entry"]["id"]==u and e["entry"]["state"]=="final"' "u=$D2" >/dev/null
phone "sleep 300" >/dev/null
expect_eq "$(get "$(phone "status $D2")" status)" pending "d2 status before drop"
phone drop-connection >/dev/null
phone "wait-secure 30000" 30 >/dev/null
phone "wait-acked $D2 30000" 30 >/dev/null
phone "sleep 500" >/dev/null
for id in "$D1" "$D2"; do
  ev expect-count "$HOST_EV" "$m" 1 'e["event"]=="entry_upserted" and e["entry"]["id"]==u and e["entry"]["state"]=="final"' "u=$id"
  ev expect-count "$PHONE_EV" "$pm" 1 'e["event"]=="delivery" and e["id"]==u and e["status"]=="acked"' "u=$id"
  expect_eq "$(log_count "id=${id:0:8}")" 1 "log entries for ${id:0:8}"
done
expect_eq "$(log_count d1-partial)" 0 "interrupted partial in the log"
reconnects=$(ev count "$HOST_EV" "$m" 'e["event"]=="connection_status" and e["state"]=="secure" and e["device_id"]==p' "p=$PHONE_ID")
expect_eq "$reconnects" 2 "secure reconnects"
log_check
pass
fi

# ---------------------------------------------------------------------------
begin e
pm=$(phone_mark)
host_stop
if [ "$MODE" = tcp ]; then
  phone "wait-disconnected" >/dev/null
else
  phone_wait "$pm" 'e["event"]=="hosts_changed" and e["indicator"]!="secure"' >/dev/null
fi
host_start
started=$(host_wait 0 'e["event"]=="started"')
expect_eq "$(get "$started" device_id)" "$HOST_ID" "vq-host device id after restart"
host_wait 0 'e["event"]=="started" and any(x["device_id"]==p for x in e["paired_peers"])' "p=$PHONE_ID" >/dev/null
phone "wait-secure 30000" 30 >/dev/null
host_wait 0 'e["event"]=="connection_status" and e["state"]=="secure" and e["device_id"]==p and e["paired"] is True' "p=$PHONE_ID" >/dev/null
E1=$(get "$(phone start)" id)
phone "final after the desktop restarted" >/dev/null
phone "wait-acked $E1" >/dev/null
host_wait 0 'e["event"]=="entry_upserted" and e["entry"]["id"]==u and e["entry"]["state"]=="final" and e["entry"]["text"]=="after the desktop restarted"' "u=$E1" >/dev/null
ev expect-count "$HOST_EV" 0 0 'e["event"] in ("pairing_code_shown","pairing_result","paired_peers_changed")'
log_check
pass

# ---------------------------------------------------------------------------
begin f
m=$(host_mark)
phone_stop
host_wait "$m" 'e["event"]=="connection_status" and e["state"]=="closed" and e["device_id"]==p' "p=$PHONE_ID" >/dev/null
if [ "$MODE" = tcp ]; then
  phone_start "E2E Phone" "$PHONE_STATE" "$PORT"
else
  phone_start_relay "E2E Phone" "$PHONE_STATE"
fi
st=$(phone_wait 0 'e["event"]=="started"')
expect_eq "$(get "$st" device_id)" "$PHONE_ID" "PhoneSim device id after restart"
expect_eq "$(get "$st" active_host_id)" "$HOST_ID" "remembered active host"
phone_wait 0 'e["event"]=="started" and any(x["device_id"]==h for x in e["paired_hosts"])' "h=$HOST_ID" >/dev/null
phone "wait-secure 30000" 30 >/dev/null
phone "select $HOST_ID" >/dev/null
host_wait "$m" 'e["event"]=="connection_status" and e["state"]=="secure" and e["device_id"]==p and e["paired"] is True' "p=$PHONE_ID" >/dev/null
F1=$(get "$(phone start)" id)
phone "partial after the phone" >/dev/null
phone "sleep 250" >/dev/null
phone "final after the phone restarted" >/dev/null
phone "wait-acked $F1" >/dev/null
host_wait "$m" 'e["event"]=="entry_upserted" and e["entry"]["id"]==u and e["entry"]["state"]=="final" and e["entry"]["text"]=="after the phone restarted"' "u=$F1" >/dev/null
ev expect-count "$HOST_EV" "$m" 0 'e["event"] in ("pairing_code_shown","pairing_result","paired_peers_changed")'
ev expect-count "$PHONE_EV" 0 0 'e["event"]=="pairing" and e["phase"] is not None'
log_check
pass

# ---------------------------------------------------------------------------
begin g
if [ "$MODE" = relay ]; then
m=$(host_mark)
phone_stop
host_wait "$m" 'e["event"]=="connection_status" and e["state"]=="closed" and e["device_id"]==p' "p=$PHONE_ID" >/dev/null
# g1: a wrong code (`c`): the phone's confirmation is refused.
URI=$(pairing_uri)
CODE=$(python3 -c 'import sys,urllib.parse as u; print(u.parse_qs(u.urlparse(sys.argv[1]).query)["c"][0])' "$URI")
BADCODE=$(printf '%06d' $(((10#$CODE + 1) % 1000000)))
m=$(host_mark)
phone_start_relay "Intruder" "$WORK/intruder-state" "$(ev uri-set "$URI" c "$BADCODE")"
INTRUDER=$(get "$(phone_wait 0 'e["event"]=="started"')" device_id)
[ "$INTRUDER" != "$PHONE_ID" ]
host_wait "$m" 'e["event"]=="pairing_result" and e["ok"] is False and e["device_id"]==p' "p=$INTRUDER" >/dev/null
phone_wait 0 'e["event"]=="pairing" and e["phase"]=="enter_code" and e["error"] is not None' >/dev/null
phone start >/dev/null
phone "final g text that must not arrive" >/dev/null
phone "sleep 1000" >/dev/null
expect_eq "$(get "$(phone hosts)" indicator)" none "intruder indicator after a wrong code"
ev expect-count "$HOST_EV" "$m" 0 'e["event"]=="entry_upserted"'
ev expect-count "$HOST_EV" "$m" 0 'e["event"]=="paired_peers_changed"'
ev expect-count "$HOST_EV" "$m" 0 'e["event"]=="connection_status" and e["state"]=="secure"'
phone_stop
# g2: a wrong desktop key pin (`k`) with the right code: the phone refuses the
# desktop's hello and never confirms.
URI=$(pairing_uri)
BADKEY=$(python3 -c 'import base64; print(base64.urlsafe_b64encode(bytes([0x42]) * 32).decode().rstrip("="))')
m=$(host_mark)
phone_start_relay "Intruder" "$WORK/intruder-state-2" "$(ev uri-set "$URI" k "$BADKEY")"
phone_wait 0 'e["event"]=="notice" and e["kind"]=="pairing_code_mismatch"' >/dev/null
phone start >/dev/null
phone "final g2 text that must not arrive" >/dev/null
phone "sleep 1000" >/dev/null
expect_eq "$(get "$(phone hosts)" indicator)" none "intruder indicator after a key mismatch"
ev expect-count "$HOST_EV" "$m" 0 'e["event"]=="entry_upserted"'
ev expect-count "$HOST_EV" "$m" 0 'e["event"]=="paired_peers_changed"'
ev expect-count "$HOST_EV" "$m" 0 'e["event"]=="pairing_result" and e["ok"] is True'
ev expect-count "$HOST_EV" "$m" 0 'e["event"]=="connection_status" and e["state"]=="secure"'
expect_eq "$(log_count "g text")" 0 "intruder text in the log"
expect_eq "$(log_count "g2 text")" 0 "intruder text in the log"
log_check
phone_stop
pass
else
m=$(host_mark)
phone_stop
host_wait "$m" 'e["event"]=="connection_status" and e["state"]=="closed" and e["device_id"]==p' "p=$PHONE_ID" >/dev/null
phone_start "Intruder" "$WORK/intruder-state" "$PORT"
INTRUDER=$(get "$(phone_wait 0 'e["event"]=="started"')" device_id)
[ "$INTRUDER" != "$PHONE_ID" ]
expect_eq "$(get "$(phone "wait-connected 30000" 30)" paired)" false "intruder knows the desktop"
phone_send "pair @$WORK/code-g"
pair_seq=$(last_seq)
shown=$(host_wait "$m" 'e["event"]=="pairing_code_shown" and e["device_id"]==p' "p=$INTRUDER")
code=$(get "$shown" code)
printf '%06d\n' $(((10#$code + 1) % 1000000)) >"$WORK/code-g"
res=$(phone_result "$pair_seq")
expect_eq "$(get "$res" ok)" false "intruder pair_result.ok"
host_wait "$m" 'e["event"]=="pairing_result" and e["ok"] is False and e["device_id"]==p' "p=$INTRUDER" >/dev/null
# Nothing the unpaired phone sends is accepted: the engine has no session to
# send on, and a forged plaintext utt is rejected by the desktop.
phone start >/dev/null
phone "final g text that must not arrive" >/dev/null
phone "inject-plaintext-utt g injected plaintext" >/dev/null
host_wait "$m" 'e["event"]=="message_rejected" and e["code"]=="plaintext_not_allowed"' >/dev/null
phone "sleep 1000" >/dev/null
expect_eq "$(get "$(phone hosts)" indicator)" none "intruder indicator"
ev expect-count "$HOST_EV" "$m" 0 'e["event"]=="entry_upserted"'
ev expect-count "$HOST_EV" "$m" 0 'e["event"]=="paired_peers_changed"'
ev expect-count "$HOST_EV" "$m" 0 'e["event"]=="connection_status" and e["state"]=="secure"'
expect_eq "$(log_count "g text")" 0 "intruder text in the log"
expect_eq "$(log_count "g injected")" 0 "injected text in the log"
log_check
phone_stop
pass
fi

if [ "$MODE" = relay ]; then
# ---------------------------------------------------------------------------
begin i
# The legitimate phone comes back (scenario g left only intruders).
phone_start_relay "E2E Phone" "$PHONE_STATE"
phone "wait-secure 30000" 30 >/dev/null
I0=$(get "$(phone start)" id)
phone "final i before the relay dies" >/dev/null
phone "wait-acked $I0" >/dev/null
hm=$(host_mark)
pm=$(phone_mark)
# I1 is sent and the relay is killed at once: delivered with its ack lost, or
# not delivered at all (a race that either way must end in exactly one entry).
I1=$(get "$(phone start)" id)
phone "final i1 sent as the relay dies" >/dev/null
relay_kill
# I2 is sent while the relay is down.
I2=$(get "$(phone start)" id)
phone "final i2 sent while the relay is down" >/dev/null
phone "sleep 500" >/dev/null
expect_eq "$(get "$(phone "status $I2")" status)" pending "i2 status while the relay is down"
host_wait "$hm" 'e["event"]=="relay_status" and e["status"]["link"] not in ("websocket","fallback")' >/dev/null
relay_start
host_wait "$hm" 'e["event"]=="relay_status" and e["status"]["link"] in ("websocket","fallback")' >/dev/null
host_wait "$hm" 'e["event"]=="connection_status" and e["state"]=="secure" and e["device_id"]==p and e["paired"] is True' "p=$PHONE_ID" >/dev/null
phone "wait-secure 30000" 30 >/dev/null
for id in "$I1" "$I2"; do
  phone "wait-acked $id 30000" 30 >/dev/null
  host_wait "$hm" 'e["event"]=="entry_upserted" and e["entry"]["id"]==u and e["entry"]["state"]=="final"' "u=$id" >/dev/null
done
phone "sleep 500" >/dev/null
for id in "$I1" "$I2"; do
  ev expect-count "$HOST_EV" "$hm" 1 'e["event"]=="entry_upserted" and e["entry"]["id"]==u and e["entry"]["state"]=="final"' "u=$id"
  ev expect-count "$HOST_EV" "$hm" 1 'e["event"]=="final_accepted" and e["entry"]["id"]==u' "u=$id"
  ev expect-count "$PHONE_EV" "$pm" 1 'e["event"]=="delivery" and e["id"]==u and e["status"]=="acked"' "u=$id"
  expect_eq "$(log_count "id=${id:0:8}")" 1 "log entries for ${id:0:8}"
done
ev expect-count "$HOST_EV" "$hm" 0 'e["event"] in ("pairing_code_shown","pairing_result","paired_peers_changed")'
# The session works after the outage, both ways of delivery.
I3=$(get "$(phone start)" id)
phone "final i3 after the relay came back" >/dev/null
phone "wait-acked $I3" >/dev/null
host_wait "$hm" 'e["event"]=="entry_upserted" and e["entry"]["id"]==u and e["entry"]["state"]=="final"' "u=$I3" >/dev/null
log_check
pass

# ---------------------------------------------------------------------------
begin h
# A new desktop identity and a new phone, both with the WebSocket disabled:
# room creation, QR pairing and the session all run over the long-poll.
phone_stop
host_stop
FORCE_LP=1
HOST_CFG="$WORK/host-config-h"
host_start
HOST_ID=$(get "$(host_wait 0 'e["event"]=="started"')" device_id)
# (vq-host reports `fallback` only once the first poll answers, which an
# empty room holds back for up to 25 s: pair first, check the link after.)
URI=$(pairing_uri)
phone_start_relay "E2E Phone H" "$WORK/phone-state-h" "$URI"
PHONE_ID=$(get "$(phone_wait 0 'e["event"]=="started"')" device_id)
host_wait 0 'e["event"]=="pairing_result" and e["ok"] is True and e["device_id"]==p' "p=$PHONE_ID" >/dev/null
host_wait 0 'e["event"]=="connection_status" and e["state"]=="secure" and e["device_id"]==p and e["paired"] is True' "p=$PHONE_ID" >/dev/null
phone "wait-secure 30000" 30 >/dev/null
host_wait 0 'e["event"]=="relay_status" and e["status"]["link"]=="fallback"' >/dev/null
H1=$(get "$(phone start)" id)
phone "partial h-partial" >/dev/null
phone "sleep 300" >/dev/null
phone "final over the long-poll only" >/dev/null
phone "wait-acked $H1 30000" 30 >/dev/null
host_wait 0 'e["event"]=="entry_upserted" and e["entry"]["id"]==u and e["entry"]["state"]=="final" and e["entry"]["text"]=="over the long-poll only"' "u=$H1" >/dev/null
ev expect-count "$HOST_EV" 0 1 'e["event"]=="entry_upserted" and e["entry"]["id"]==u and e["entry"]["state"]=="final"' "u=$H1"
ev expect-count "$HOST_EV" 0 0 'e["event"]=="relay_status" and e["status"]["link"]=="websocket"'
expect_eq "$(log_count "id=${H1:0:8}")" 1 "log entries for ${H1:0:8}"
log_check
phone_stop
pass
fi

host_stop
CURRENT=""
