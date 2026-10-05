# PhoneSim

`PhoneSim` is a scripted fake phone for the end-to-end test (SPEC §8, gate 3). It is a macOS command-line executable in this package. It runs the **real** `PhoneEngine` (`VQPhoneCore`) over the TCP dev transport of `protocol/README.md` §2.1: the phone is the TCP **server**, each frame travels as `length (u16 BE) ‖ frame`, and `mtu` is 512. The desktop side is `vq-host` (`desktop/core`, feature `dev-tcp`), which connects as the client.

PhoneSim is for tests and development only. Its `--state-dir` holds the identity's private key in a plain file.

```sh
cd ios/VQProtocol
swift build --product PhoneSim
.build/debug/PhoneSim --port 47800 --name "Sim" --state-dir /tmp/sim-state   # commands on stdin
.build/debug/PhoneSim --port 0 --script my.script                           # port 0 = any free port
```

| Flag | Meaning |
|---|---|
| `--port N` | TCP port (default 47800). `0` picks a free port, reported in the `listening` event. |
| `--bind ADDR` | IPv4 address to listen on (default `127.0.0.1`). |
| `--name NAME` | Name sent in `hello` (default `PhoneSim`). |
| `--state-dir DIR` | Keep the identity (`identity.json`), the paired desktops (`paired-hosts.json`) and the last active desktop (`settings.json`) in `DIR`, all mode 0600. A second run with the same directory reuses the pairing. Without it, everything is in memory. |
| `--script FILE` | Read commands from `FILE` instead of stdin. |
| `--relay-pair-uri URI` | **Relay mode** (SPEC_V3 §5): pair through the relay with this `vq://pair?...` QR link instead of listening on TCP. Uses `RelayPhoneTransport` with `URLSessionRelayNetworking` and calls `PhoneEngine.pair(using:)`, which joins the room and enters the QR code automatically when the desktop's `hello` arrives. Emits `relay_pairing`, then the usual `hosts_changed`/`pairing`/`paired` events; use `wait-secure`. A desktop key that differs from the QR gives `notice` kind `pairing_code_mismatch`. `--state-dir` also keeps `relay-desktops.json` and `relay-secrets.json`, so a later run reconnects without the flag. TCP-only commands (`drop-connection`, `tx-*`, `rx-*`, `inject-plaintext-utt`) fail in this mode. |
| `--verbose` | Engine diagnostics on stderr. |

In relay mode the loop runs on the main thread and drives `RunLoop.main` in 20 ms slices (the transport is main-actor bound), polling stdin without blocking. In TCP mode PhoneSim runs one thread: a `poll(2)` loop over the listening socket, the connections and stdin, which calls `PhoneEngine.tick()` about every 20 ms with the real `SystemClock`. It exits after `quit`, or after the last command once stdin (or the script) ends. The exit status is 1 if any command failed and 0 otherwise.

## Commands

There is one command per line. Empty lines and lines starting with `#` are skipped. Commands run strictly in order. A waiting command blocks the ones after it, but the engine and the sockets keep running. Every command is answered by exactly one event:

```json
{"event":"command_done","seq":3,"cmd":"final","id":"…","index":0,"truncated":false}
{"event":"command_failed","seq":4,"cmd":"wait-secure","reason":"timeout"}
```

`seq` counts commands from 1, skipping blank and comment lines. A driver can write a command and then wait for its `seq`.

**Text arguments.** The rest of the line is the text. If it starts with `"`, it is decoded as a JSON string, so `final "a\tb\nc ‮"` can carry tabs, newlines and any Unicode in an ASCII line. A command can also be a JSON object, for example `{"cmd":"edit","ref":"0","text":"…"}`. Its members are `text`, `ref`, `code`, `target`, `ms` and `timeout_ms`.

**References** (`<ref>`): `last` (the default), a history index (`0`, `1`, … in the order `start`/`resend` created them), or an utterance UUID.

| Command | Effect | `command_done` extras |
|---|---|---|
| `wait-connected [ms]` | Waits until a desktop is connected and has sent `hello`. | `host_id`, `name`, `paired` |
| `wait-secure [ms]` | Waits until the **active** desktop is connected and Secure (the green dot). | `host_id`, `name` |
| `wait-disconnected [ms]` | Waits until no TCP connection is open. | — |
| `select <host-id\|name\|first> [ms]` | Makes a paired desktop active (`PhoneEngine.selectHost`) and waits for it to appear. | `host_id` |
| `pair <code\|@file> [ms]` | Pairs with the first online desktop that is not paired: sends `pair_request`, waits for the challenge, submits the code, and waits for the result. `@file` waits until `file` exists and is not empty, then uses its trimmed content. This lets a test pass the code that `vq-host` shows. It also emits a `pair_result` event. A wrong code is **not** a command failure: it completes with `ok:false`. | `ok`, `host_id`, `message` |
| `start` | Begins an utterance (recording started). | `id`, `index` |
| `partial <text>` | Sends the recognizer's current text (`updatePartial`). The engine throttles partials to 5/s and always sends the latest text, so put `sleep 250` between partials if each one must go out. | `id`, `index` |
| `final <text>` | Stops recording and sends the `final` (`finishUtterance`). | `id`, `index`, `truncated` |
| `edit <text>` | Sends a correction (`edit`, higher `rev`) for the last utterance. The JSON form takes `ref`. | `id`, `index` |
| `resend <ref>` | Re-sends from history: a **new** id with a single `final` carrying that entry's latest text. | `id`, `index`, `of` |
| `wait-acked <ref> [ms]` | Waits until the latest `final`/`edit` of `<ref>` is acked. The engine completes a delivery only on an `ack` with `rev` ≥ its pending `rev`, so there is no separate rev argument. | `id`, `index` |
| `status <ref>` | Reports the delivery status (`pending`/`acked`/`failed`/`null`). | `id`, `index`, `status` |
| `drop-connection` | Closes every TCP connection, as if the link dropped. The engine sees a disconnect and the desktop reconnects with its backoff. It also discards frames held by `tx-pause` and clears both pauses. | `closed` |
| `tx-pause` / `tx-resume` | Holds outgoing frames in memory instead of writing them, or releases them. `tx-pause` + `final` + `drop-connection` makes a final that the desktop never saw. | — |
| `rx-pause` / `rx-resume` | Stops reading from the sockets, so acks are not seen, or starts reading again. `rx-pause` + `final` + `drop-connection` makes a final the desktop logged but whose ack was lost. | — |
| `inject-plaintext-utt <text>` | Adversarial. Writes a plaintext-envelope `utt{final}` to every connection, bypassing the engine. The desktop must reject it (`plaintext_not_allowed`). | `id`, `connections` |
| `hosts` | Reports the host list. | `hosts`, `indicator` |
| `sleep <ms>` | Waits. | — |
| `quit` | Exits after answering. | — |

The default wait timeout is 10,000 ms. A timeout fails the command with `reason:"timeout"`.

## Events (stdout, one JSON object per line)

| `event` | Fields |
|---|---|
| `started` | `device_id`, `name`, `state_dir`, `paired_hosts` (`[{device_id,name}]`), `active_host_id` |
| `listening` | `host`, `port` |
| `tcp_connected` / `tcp_disconnected` | `peer` (connection id, `tcp#N`); `reason` (`eof`, `dropped by script`, `closed by engine`, …) |
| `hosts_changed` | `hosts` (`[{id,name,paired,online,state,active,not_recognized,key_changed}]`; `state` is `offline`/`unpaired`/`pairing`/`secure`), `indicator` (`none`/`connecting`/`secure`) |
| `pairing` | `phase` (`null`, `requesting`, `enter_code`, `verifying`, `succeeded`, `failed`), `host_id`, `host_name`, `error`, `note` |
| `pair_result` | `ok`, `host_id`, `message` (from the `pair` command) |
| `paired` | `host_id`, `name` |
| `delivery` | `id`, `index`, `status` (`pending`/`acked`/`failed`) |
| `notice` | `kind` (`version_mismatch`, `not_recognized`, `peer_error:<code>`, `keepalive_timeout`, `storage_failed`), `text` |
| `utterance_limit` | `id`, `text_bytes` |
| `command_done` / `command_failed` | see above |
| `exited` | `failed_commands` |

Strings are written with UTF-8 left unescaped, and only the escapes JSON requires.

## Example script

```text
wait-connected 30000
pair @/tmp/code 60000
wait-secure
start
partial kubectl
sleep 250
partial kubectl get
final kubectl get pods
wait-acked last
edit kubectl get pods -A
wait-acked last
quit
```

`tests/e2e/run.sh` drives PhoneSim interactively through a FIFO on stdin, against `vq-host`.
