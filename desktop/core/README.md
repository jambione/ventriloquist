# vq-host-core

The Ventriloquist desktop core (SPEC §7). It has no Tauri dependencies and uses only the production API of `vq-protocol`.

| Module | Role |
|---|---|
| `session` | `SessionManager`: the per-peer state machine `Connected → HelloExchanged → (Pairing →) Secure → Closed` (README §7), plus framing, crypto, acks and keepalive. It does no I/O. |
| `transcript` | `TranscriptStore`: the highest `rev` per `id` wins, capped at 500 entries. |
| `logger` | `Logger`: daily Markdown log (SPEC §6.2) with dedupe by (`id`, `rev`) through `<log_dir>/.vq-index/`. |
| `pairing_store` | `Identity` (`identity.json`, mode 0600) and `PairingStore` (`peers.json`). |
| `config` | `config.json`: log directory (default `~/Documents/Ventriloquist/`) and display name (default: the hostname). |
| `core` | `Core`: the components above combined, with no I/O and an injectable `Clock`. File writes leave it as `IoJob`s. |
| `io_worker` | `IoWorker`: runs `IoJob`s (log, `peers.json`, `config.json`) in order on a dedicated thread; retries failed log entries. |
| `outbox` | `EventOutbox`: coalescing queue between the host loop and a slow UI. |
| `pairing_guard` | Pairing rate limits and global lockout (README §7.3; D10). |
| `host` | `spawn_host`: tokio runtime, with `HostCommand` in and `HostEvent` out over a bounded channel (`spawn_host_with_io` lets tests inject a slow disk). |
| `transport` | The `Transport` trait; `ble::BleCentralTransport` (feature `ble`, on by default); `tcp::TcpTransport` (feature `dev-tcp`, for tests and dev only); `policy` (backoff, MTU, idle drop, BLE slot expiry, scan retry, adapter re-acquire). |

## Commands

```sh
cargo test  -p vq-host-core --features dev-tcp
cargo clippy -p vq-host-core --all-targets --features dev-tcp -- -D warnings   # --all-features also works (debug)
cargo build -p vq-host-core                       # default features (ble)
scripts/verify.sh                                 # all gates
cargo run   -p vq-host-core --features dev-tcp --bin vq-host -- --connect 127.0.0.1:47800 \
            --log-dir /tmp/vq-logs --config-dir /tmp/vq-cfg [--name "My Mac"]
```

`Core::open` takes an exclusive advisory lock on `<config_dir>/.lock` for as long as the core lives; a second host on the same config directory fails to open with `AddrInUse` ("Ventriloquist is already running").

**`dev-tcp` is refused in release builds** (`compile_error!`; D14): run the tests, the E2E harness and `vq-host` in debug builds only, and never enable `dev-tcp` for the app.

`vq-host` is the desktop side of the TCP dev transport, so it is the **client**. Its default config directory is `<OS local config dir>/com.ventriloquist.desktop.dev`, which is separate from the app's. It reconnects with backoff (1, 2, 4, 8, max 15 s) until the phone simulator's server is up. Set `VQ_LOG=1` to get diagnostics on stderr. It stops on SIGINT or SIGTERM.

## `vq-host` stdout format (stable; the M4 E2E test parses it)

Every event is written to stdout as **one JSON object on one line**, flushed after each line. The tag `"event"` names the event type. Fields not listed here may be added later, so parsers should ignore unknown fields and unknown events. UUIDs are lowercase and hyphenated, and peer ids are opaque strings.

The first line is always `started`:

```json
{"event":"started","device_id":"…","name":"My Mac","log_dir":"/tmp/vq-logs","paired_peers":[]}
```

Events:

| `event` | Fields |
|---|---|
| `started` | `device_id`, `name`, `log_dir`, `paired_peers` (array of `{device_id,name,public_key(b64),paired_at_ms}`) |
| `snapshot` | answer to the `snapshot` command: `device_id`, `name`, `log_dir`, `paired_peers`, `adapter_state`, `peers` (array of `{peer, state, device_id, name, paired, pairing: null or {code, phone_name, expires_in_secs}}`), `entries` (array of entries, oldest first), `log_warning` (string while the log folder cannot be written, else null) |
| `connection_status` | `peer`, `state` (`connected`/`hello_exchanged`/`pairing`/`secure`/`closed`), `device_id` (null until the phone's hello), `name` (likewise), `paired` (bool), `reason` (null, or e.g. `unknown_peer`, `keepalive_timeout`, `idle_unpaired`, `rate_limited`, `protocol`, `version`) |
| `pairing_code_shown` | `peer`, `device_id`, `phone_name`, `code` (exactly 6 ASCII digits), `expires_in_secs` (120) |
| `pairing_code_ended` | `peer`, `reason` (`expired`/`too_many_failures`/`cancelled`/`disconnected`) |
| `pairing_result` | `peer`, `device_id`, `phone_name`, `ok`, `attempts_remaining` |
| `paired_peers_changed` | `peers` |
| `entry_upserted` | `entry`: `{id, rev, state ("partial"/"final"/"edit"/"interrupted"), text, ts, device_id, device_name, first_received_at, received_at (RFC 3339 local), time ("HH:MM:SS"), partial (bool), edited (bool)}` |
| `final_accepted` | `entry` (same shape as in `entry_upserted`, `state:"final"`). Emitted **exactly once per utterance id**, when the first `final` for the id is accepted (right after its `entry_upserted`). Never for partials, edits, duplicate or stale revisions, ids evicted from the transcript, or a `final` that the log's dedupe index (arrival day and the day before) already holds, as when the phone re-delivers it after a host restart. It fires when the I/O worker takes the log job, **not** when the write succeeds, so a failing or deferred log write (retry queue) neither delays nor suppresses it, and later retries never repeat it. If the I/O queue overflows, it is still emitted (the index cannot be consulted then). The outbox never coalesces or drops it. It is the only trigger intended for automatic delivery of text. |
| `entry_evicted` | `id` |
| `peer_error` | `peer`, `code`, `message`, `authenticated` |
| `version_mismatch` | `peer`, `device` (the device to update) |
| `message_rejected` | `peer`, `code` (vq-protocol error code, e.g. `plaintext_not_allowed`, `text_too_long`) |
| `log_warning` / `storage_warning` | `message` |
| `log_recovered` | (none): every entry that failed to log has now been written |
| `adapter_state` | `state` (`unknown`/`no_adapter`/`powered_off`/`unauthorized`/`scanning`; TCP reports `scanning`) |
| `devices_seen` | `count`: BLE advertisements seen since the current scan started (diagnostics; at most one event per second, coalesced; `snapshot` carries it as `devices_seen`) |
| `config_changed` | `log_dir`, `name`, `persisted` (bool) |

`entry_upserted` is emitted only when a revision is **accepted**, meaning its `rev` is higher than any seen for that `id` in this run (evicted ids included, D8). Duplicate or older revisions are acked to the phone but produce no event. The one exception: when a connection closes, its live partials are re-emitted once with `state:"interrupted"` and `partial:false`.

The event channel is bounded. While a consumer is slow, queued partial updates of the same entry and repeated `message_rejected` events are coalesced (D11); `final_accepted` is never coalesced or dropped. A UI that reloads should send `snapshot`.

Example:

```json
{"event":"pairing_code_shown","peer":"tcp:127.0.0.1:47800#1","device_id":"0f8fad5b-d9cb-469f-a165-70867728950e","phone_name":"PhoneSim","code":"042917","expires_in_secs":120}
{"event":"entry_upserted","entry":{"id":"3b241101-e2bb-4255-8caf-4136c566a962","rev":2,"state":"final","text":"kubectl get pods","ts":1759500000000,"device_id":"0f8fad5b-…","device_name":"PhoneSim","first_received_at":"2026-10-03T14:03:21+02:00","received_at":"2026-10-03T14:03:22+02:00","time":"14:03:22","partial":false,"edited":false}}
```

### stdin commands (optional)

Commands are optional. Send one JSON object per line on stdin. EOF on stdin does **not** stop the host.

```json
{"command":"cancel_pairing","peer":"tcp:127.0.0.1:47800#1"}
{"command":"forget_peer","device_id":"…"}
{"command":"set_log_dir","path":"/tmp/other"}
{"command":"set_name","name":"Other"}
{"command":"snapshot"}
{"command":"shutdown"}
```

## Log format

The logger writes `<log_dir>/YYYY-MM-DD.md`, using the local date when the revision arrived:

```
# Ventriloquist — 2026-10-03

- **14:03:22** · Jon's iPhone · `id=1a2b3c4d`
  kubectl get pods
- **14:04:10** · Jon's iPhone · `id=1a2b3c4d` · edited
  kubectl get pods -A
```

Rendering rules and the dedupe index are described in `src/logger.rs` and in docs/SPEC_QUESTIONS.md D1–D3.

## Windows

The crate keeps to the portable APIs:
- `btleplug` uses WinRT on Windows.
- The unix permission code is behind `cfg(unix)`.
- Config files live in the per-user, non-roaming `%LOCALAPPDATA%` and rely on its ACL.

No Windows build is run by the agents.

## BLE scanning and diagnostics

- The scan starts with an **empty `ScanFilter`**: nothing is filtered by the OS or by btleplug (some Windows drivers drop filtered advertisements; btleplug's WinRT backend filters in software). `transport::ble` matches every advertisement itself with `policy::is_candidate(services, local_name)`: the advertised services contain the Ventriloquist service UUID **or** the local name is `Ventriloquist` (iOS may put a 128-bit UUID in the scan response or the overflow area).
- A name-only match is verified after connecting (`discover_services`). If the GATT service is missing, the device is dropped and not retried for 5 minutes (`policy::NAME_ONLY_BLOCK`).
- The transport logs at info (the desktop app writes these to its log file): the adapter (and `adapter_info`), scan start/stop/errors, every discovered device once per id per 60 s (id, local name, RSSI, advertised services, matched), every connect attempt, the services and characteristics found, the subscribe result and every error with its Debug text.
- `TransportEvent::DevicesSeen(n)` / `HostEvent::DevicesSeen` carry the advertisement count so the UI can show "Scanning… (N devices seen)".
