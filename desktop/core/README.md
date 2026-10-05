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
| `relay_room` | `RelayRoomStore`: the relay URL, `room_id` and `room_secret` (generated once; `relay.json` + the 0600 file `relay_secret`), shared by the core (QR pairing) and the relay transport. |
| `pairing_uri` | The `vq://pair?…` QR payload (SPEC_V3 §5). |
| `transport` | The `Transport` trait; `relay::RelayTransport` (feature `relay`, on by default) with `proxy` (OS proxy / PAC resolution); `tcp::TcpTransport` (feature `dev-tcp`, for tests and dev only); `policy` (backoff, idle drop). |

## Commands

```sh
cargo test  -p vq-host-core --features dev-tcp
cargo clippy -p vq-host-core --all-targets --features dev-tcp -- -D warnings   # --all-features also works (debug)
cargo build -p vq-host-core                       # default features (relay)
scripts/verify.sh                                 # all gates
cargo run   -p vq-host-core --features dev-tcp --bin vq-host -- --connect 127.0.0.1:47800 \
            --log-dir /tmp/vq-logs --config-dir /tmp/vq-cfg [--name "My Mac"]
```

`Core::open` takes an exclusive advisory lock on `<config_dir>/.lock` for as long as the core lives; a second host on the same config directory fails to open with `AddrInUse` ("Ventriloquist is already running").

**`dev-tcp` is refused in release builds** (`compile_error!`; D14): run the tests, the E2E harness and `vq-host` in debug builds only, and never enable `dev-tcp` for the app.

`vq-host --relay <url> [--owner-token-file <file>]` (or env `VQ_RELAY_OWNER_TOKEN`; `--owner-token <t>` also works but is visible in `ps`) runs the relay transport instead (the room is kept in `--config-dir`; `http://` is accepted only for loopback hosts; `start_phone_pairing` on stdin emits `phone_pairing_qr`). `VQ_RELAY_FORCE_LONGPOLL=1` makes the relay transport skip the WebSocket and use only the long-poll fallback (tests). Without `--relay`, `vq-host` is the desktop side of the TCP dev transport, so it is the **client**. Its default config directory is `<OS local config dir>/com.ventriloquist.desktop.dev`, which is separate from the app's. It reconnects with backoff (1, 2, 4, 8, max 15 s) until the phone simulator's server is up. Set `VQ_LOG=1` to get diagnostics on stderr. It stops on SIGINT or SIGTERM.

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
| `snapshot` | answer to the `snapshot` command: `device_id`, `name`, `log_dir`, `paired_peers`, `relay` (`{link, reason, detail}`), `phone_pairing` (null, or `{uri, expires_in_secs}` while "Add phone" is open), `peers` (array of `{peer, state, device_id, name, paired, pairing: null or {code, phone_name, expires_in_secs}}`), `entries` (array of entries, oldest first), `log_warning` (string while the log folder cannot be written, else null) |
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
| `relay_status` | `status`: `{link, reason, detail}`. `link` is `idle` (no relay: the TCP dev transport), `connecting`, `websocket`, `fallback` (HTTPS long-poll) or `unreachable`; then `reason` is one of `dns`, `proxy_auth_required`, `proxy_auth_unsupported` (the proxy offers only NTLM/Kerberos sign-in), `proxy_blocked`, `tls_untrusted`, `owner_token_rejected`, `room_conflict`, `other`. `detail` is a short technical text without secrets. Emitted on change only. |
| `phone_pairing_qr` | `uri` (the `vq://pair?…` payload, **contains the room secret: render it, never log it**), `expires_in_secs` (120). Emitted for `start_phone_pairing`, then again every 120 s while the dialog is open (and at once if the code was used up by wrong confirmations). The `c` field of the URI is the active v1 pairing code. |
| `phone_pairing_ended` | `reason` (`paired`: a phone paired with the QR's code; `closed`: `stop_phone_pairing`) |
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
{"command":"start_phone_pairing"}
{"command":"stop_phone_pairing"}
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

## Phone pairing by QR (SPEC_V3 §5)

`start_phone_pairing` starts a v1 pairing code (`SessionManager::start_qr_pairing`) and emits `phone_pairing_qr`. While that code is active (120 s), the next `pair_request` **uses it** instead of a fresh code: the phone read it from the QR and confirms with it, so the user types nothing. The rest of the flow (`pair_challenge`, `pair_confirm`, the guard's rate limits and lockout) is unchanged. A QR attempt shows **no code modal** (no `pairing_code_shown`/`_ended`); on success the core emits `pairing_result{ok:true}`, `paired_peers_changed` and `phone_pairing_ended{paired}`. The QR code is single-use: it is dropped after a successful pairing and after 3 wrong confirmations (a new one is generated while the dialog is open). `stop_phone_pairing` ends the flow and cancels attempts in progress.

## Relay transport (SPEC_V3 §4, §6)

`transport::relay::RelayTransport::new(store, RelayOptions) -> (RelayTransport, RelayHandle)`. The handle is the run-time configuration surface (owner token, URL, `reset_room`, `test_connection`).

- **Connection order.** `PUT /v1/rooms/{room}` with the owner token (only when a token is set and the room is not known to exist; 201/200 are success), then the WebSocket (`…/ws?role=desktop`, `Authorization: Bearer <room secret>`). If the WebSocket cannot be established (any failure) or ends twice in a row within 10 s, the transport uses the **long-poll fallback** (`POST …/send`, `GET …/poll`, 25 s hold, cursor acknowledgement) and retries the WebSocket every 5 minutes. Reconnect backoff: 1, 2, 4, 8, then 30 s (`relay::backoff_factor`).
- **TLS** is `native-tls` (Windows schannel, macOS Security.framework), so the **OS certificate store** decides (a TLS-inspecting proxy works once its root is installed in the OS). `reqwest` (long-poll, room creation) uses the same `native-tls`.
- **Proxy** (`transport::proxy`): `HTTPS_PROXY`/`ALL_PROXY` (and `HTTP_PROXY` for `http://` relays), filtered by `NO_PROXY`; else the OS: Windows `WinHttpGetIEProxyConfigForCurrentUser` + `WinHttpGetProxyForUrl` (WPAD and PAC evaluated by WinHTTP), macOS `CFNetworkCopySystemProxySettings` + `CFNetworkCopyProxiesForURL`; a PAC URL is fetched (direct, 5 s, cached 5 min) and evaluated with `CFNetworkCopyProxiesForAutoConfigurationScript`. The WebSocket goes through an HTTP `CONNECT` tunnel; `SOCKS` entries are skipped. Proxy credentials are only supported from the `HTTPS_PROXY` URL (Basic); a 407 is reported as `proxy_auth_required` (NTLM/Kerberos single sign-on is not implemented).
- **Peers.** `peer_joined` is `Connected` (`relay:<conn_id>`, `mtu` 8192); `peer_left` and any link failure are `Disconnected`. The relay cannot drop a phone, so a host `Disconnect` reports the peer gone and ignores its frames until it leaves; `reconnect_after` hold-offs do not apply (a reconnecting phone is a new `conn_id`).
- **Errors** are categorised into `RelayReason` (see `relay_status`): DNS; proxy 407/other refusal; TLS trust (by the TLS error text: schannel `0x800B0109`, Security.framework `-9807…`, OpenSSL wording); relay 401 (owner token on `PUT`) / 409 / room secret rejected (`room_conflict`); a 404 for the room without an owner token is `owner_token_rejected`.
- **Reset relay room** rotates the room id **and** secret (the relay answers 409 for a known id with another secret), reconnects, and deletes the old room on a best-effort basis. Desktop pairing records are not touched by core (the app forgets them).
- `http://` relay URLs are accepted (local development, `wrangler dev`/`vq-relay` on loopback); production uses `https://`.

Unsafe code is denied crate-wide except in `transport::proxy::sys` (the OS bindings).

No Windows build is run by the agents (CI cross-checks with `--target x86_64-pc-windows-msvc`); the Windows proxy code (WinHTTP) is therefore only compile-checked, as is schannel TLS.
