# vq-host-core

The Ventriloquist desktop core (SPEC §7). It has no Tauri dependencies and uses only the production API of `vq-protocol`.

| Module | Role |
|---|---|
| `session` | `SessionManager`: the per-peer state machine `Connected → HelloExchanged → (Pairing →) Secure → Closed` (README §7), plus framing, crypto, acks and keepalive. It does no I/O. |
| `transcript` | `TranscriptStore`: the highest `rev` per `id` wins, capped at 500 entries. |
| `logger` | `Logger`: daily Markdown log (SPEC §6.2) with dedupe by (`id`, `rev`) through `<log_dir>/.vq-index/`. |
| `pairing_store` | `Identity` (`identity.json`, mode 0600) and `PairingStore` (`peers.json`). |
| `config` | `config.json`: log directory (default `~/Documents/Ventriloquist/`) and display name (default: the hostname). |
| `core` | `Core`: the components above combined, with no I/O and an injectable `Clock`. |
| `host` | `spawn_host`: tokio runtime, with `HostCommand` in and `HostEvent` out over channels. |
| `transport` | The `Transport` trait; `ble::BleCentralTransport` (feature `ble`, on by default); `tcp::TcpTransport` (feature `dev-tcp`, for tests and dev only); `policy` (backoff, MTU, idle drop). |

## Commands

```sh
cargo test  -p vq-host-core --features dev-tcp
cargo clippy -p vq-host-core --all-targets --all-features -- -D warnings
cargo build -p vq-host-core                       # default features (ble)
cargo run   -p vq-host-core --features dev-tcp --bin vq-host -- --connect 127.0.0.1:47800 \
            --log-dir /tmp/vq-logs --config-dir /tmp/vq-cfg [--name "My Mac"]
```

`vq-host` is the desktop side of the TCP dev transport, so it is the **client**. It reconnects with backoff (1, 2, 4, 8, max 15 s) until the phone simulator's server is up. Set `VQ_LOG=1` to get diagnostics on stderr. It stops on SIGINT or SIGTERM.

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
| `connection_status` | `peer`, `state` (`connected`/`hello_exchanged`/`pairing`/`secure`/`closed`), `device_id` (null until the phone's hello), `name` (likewise), `paired` (bool), `reason` (null, or e.g. `unknown_peer`, `keepalive_timeout`, `idle_unpaired`, `protocol`, `version`) |
| `pairing_code_shown` | `peer`, `device_id`, `phone_name`, `code` (exactly 6 ASCII digits), `expires_in_secs` (120) |
| `pairing_code_ended` | `peer`, `reason` (`expired`/`too_many_failures`/`cancelled`/`disconnected`) |
| `pairing_result` | `peer`, `device_id`, `phone_name`, `ok`, `attempts_remaining` |
| `paired_peers_changed` | `peers` |
| `entry_upserted` | `entry`: `{id, rev, state ("partial"/"final"/"edit"), text, ts, device_id, device_name, first_received_at, received_at (RFC 3339 local), time ("HH:MM:SS"), partial (bool), edited (bool)}` |
| `entry_evicted` | `id` |
| `peer_error` | `peer`, `code`, `message`, `authenticated` |
| `version_mismatch` | `peer`, `device` (the device to update) |
| `message_rejected` | `peer`, `code` (vq-protocol error code, e.g. `plaintext_not_allowed`, `text_too_long`) |
| `log_warning` / `storage_warning` | `message` |
| `adapter_state` | `state` (`unknown`/`no_adapter`/`powered_off`/`unauthorized`/`scanning`; TCP reports `scanning`) |
| `config_changed` | `log_dir`, `name` |

`entry_upserted` is emitted only when a revision is **accepted**, meaning its `rev` is higher than any seen for that `id` in this run. Duplicate or older revisions are acked to the phone but produce no event.

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
- Config files rely on the per-user `%APPDATA%` ACL.

No Windows build is run by the agents.
