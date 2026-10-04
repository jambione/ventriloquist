# Ventriloquist — Specification v3: Cloud relay transport

Status: **APPROVED by owner 2026-10-04**, from the owner interview. This is a delta on [SPEC.md](SPEC.md) (v1) and [SPEC_V2.md](SPEC_V2.md) (bindings).

**Summary.** Bluetooth is replaced, on every platform, by a small **cloud relay** at `relay.jbrasfield.com`, running as a self-hosted `vq-relay` server on the owner's Mac mini, exposed through a Cloudflare Tunnel.
- The phone and the desktop each make an **outbound HTTPS/WebSocket** connection to the relay, which forwards **end-to-end encrypted** frames between them.
- Pairing is done by **scanning a QR code** shown on the desktop.
- Everything above the transport is unchanged: the vq-protocol envelope, the session, delivery, the desktop UI and bindings.

## 1. Why
- On iOS 26.1+, the iPhone, when acting as a peripheral, refuses GATT data access from non-Apple centrals (v2.2/v2.3 investigation).
- The owner's Windows work PC denies GATT advertising to unpackaged apps (`StartAdvertising: E_ACCESSDENIED`).
- The PC is on a corporate network with a **strict, TLS-inspecting proxy**. Direct Wi-Fi between devices is unlikely to work there, but outbound HTTPS is.

## 2. Owner decisions (v3 interview)

| Topic | Decision |
|---|---|
| Transport | **Cloud relay** for Mac and Windows. **Bluetooth is removed** from both apps (it stays in git history) |
| Offline use | Not required; the phone and PC are online |
| Relay hosting | **Self-hosted on the owner's Mac mini**, as a standalone `vq-relay` server (Rust) exposed at `relay.jbrasfield.com` through a **Cloudflare Tunnel** (`cloudflared`; no port-forwarding; the zone is already on Cloudflare). It runs as a launchd service at boot. Revised 2026-10-04: it was a Cloudflare Worker |
| Corporate proxy | Strict and TLS-inspecting. The desktop must use the **OS proxy settings, including PAC**, and the **OS certificate store**, with an **HTTPS long-poll fallback** when WebSockets are blocked |
| Pairing | **QR code** shown on the desktop and scanned by the iPhone camera |
| Relay access | **Only the owner's devices.** Rooms can only be created with an owner secret; joining needs a per-room secret delivered by QR |
| Desktop offline | **The relay stores nothing.** The phone queues pending dictations and re-sends on reconnect, as in v1 |
| Relay URL | A setting in both apps, defaulting to `https://relay.jbrasfield.com` |

## 3. Architecture

```
iPhone app ──wss/https──► relay.jbrasfield.com (Cloudflare edge) ──Tunnel──► Mac mini: vq-relay (127.0.0.1:8787) ◄── Desktop app (same path)
            (outbound 443)                                                        forwards opaque frames; stores only room auth metadata
```

- **Room.** Each desktop install owns exactly one room:
  - `room_id`: 128 random bits, base64url;
  - `room_secret`: 256 random bits, base64url.

  The desktop keeps both in its config dir; the room secret goes in a 0600 file / the per-user store.
- **Roles in a room.** At most **one desktop** connection; **0..n phone** connections. The relay gives each connection an opaque `conn_id`.
- **Relay data model.** The relay stores only what it needs to authenticate a room: `room_id → { secret_hash: SHA-256(room_secret), created_at }`. It **never stores or logs frame contents**, and logs no payload sizes beyond aggregate counts.
- **Above the relay, nothing changes.** Each phone↔desktop link carries the existing vq-protocol: §4.2 framing, the envelope, hello and session establishment, ChaCha20-Poly1305, `utt`/`ack`, pings. The relay sees only ciphertext plus plaintext hello/pairing messages, and those contain no secrets.
- **MTU.** The framing layer's mtu becomes **8192 bytes** for the relay transport, which keeps long-poll requests small.

## 4. Relay protocol (normative; documented in `relay/README.md` and protocol/README.md §2.4)

### 4.1 Endpoints (all under `https://<relay>/v1`)

| Method & path | Who | Purpose |
|---|---|---|
| `PUT /rooms/{room_id}` | desktop | Create or claim a room. Header `X-VQ-Owner: <owner_token>`. Body `{ "secret_hash": "<b64url sha256(room_secret)>" }`. **201** created; **200** if it already exists with the same hash; **409** if it exists with a different hash; **401** for a bad owner token |
| `GET /rooms/{room_id}/ws?role=desktop\|phone` (WebSocket upgrade) | both | Real-time channel. Auth header `Authorization: Bearer <room_secret>` (or the `vq.auth.<secret>` WebSocket subprotocol, for clients that can't set headers) |
| `POST /rooms/{room_id}/send?role=…&session=…` | both | Long-poll fallback: send one or more frames |
| `GET /rooms/{room_id}/poll?role=…&session=…&cursor=…` | both | Long-poll fallback: wait up to **25 s** for frames and events |
| `DELETE /rooms/{room_id}` | desktop | Delete a room (room secret, plus the owner token) |
| `GET /health` | anyone | `200 ok` |

The owner token is set in the relay's config (owner-token file on the Mac mini), and the owner pastes it once into the desktop app (Settings → Relay). **The phone never sees the owner token.**

### 4.2 Messages on the channel (WebSocket binary/text, or long-poll JSON)
- Client → relay: `{ "type": "frame", "to": "<conn_id>", "data": "<b64>" }`. A desktop must give `to`; a phone's `to` is ignored, because phones always send to the desktop.
- Relay → client: `{ "type": "frame", "from": "<conn_id>", "data": "<b64>" }`.
- Relay → desktop:
  - `{ "type": "peer_joined", "conn_id": "…" }`;
  - `{ "type": "peer_left", "conn_id": "…" }`.
- Relay → phone: `{ "type": "desktop_present", "present": true|false }`.
- Keepalive: WebSocket ping every 20 s; on long-poll the poll itself acts as keepalive. A session idle for more than 60 s is closed.
- Limits:
  - frame ≤ 64 KiB;
  - ≤ 50 frames/s per connection;
  - ≤ 8 phones per room;
  - a second desktop connection replaces the first, which is closed with code 4001 "replaced".

### 4.3 Transport mapping
- **Desktop.** Every `peer_joined` is a transport "peer connected", with peer id `relay:<conn_id>`. The core then sends `hello` exactly as before. `peer_left` and errors are disconnects.
- **Phone.** On connecting (and on `desktop_present: true`) the phone has one peer, the desktop. It waits for the desktop's `hello`, as in v1.

## 5. Pairing by QR
1. The desktop shows a QR code in **Settings → Phones → "Add phone"**, and automatically on first run while no phone is paired. The QR is regenerated every 120 s.
2. The QR encodes `vq://pair?v=3&r=<relay url>&room=<room_id>&s=<room_secret>&d=<desktop device_id>&k=<desktop X25519 pub, b64url>&c=<6-digit code>&n=<desktop name>`. The `c` code is the v1 6-digit pairing code, which the desktop starts at the moment it shows the QR.
3. The phone scans it (AVFoundation camera; `NSCameraUsageDescription`), stores relay/room/secret/desktop pub (the secret in the **Keychain**), connects to the room, and runs the **existing v1 pairing flow**: `pair_request` → `pair_challenge` → `pair_confirm`, using `c` automatically. The user types nothing.
4. **Key pinning.** The phone must check that the desktop `hello.pub` equals `k` from the QR. On a mismatch it aborts with "This QR code doesn't match the desktop".
5. Rate limits and lockout from v2 §7.3 still apply, applied per room.
6. **Forget:**
   - on the phone, it deletes the stored room credentials;
   - on the desktop, it removes the phone's pairing record.
   - **"Reset relay room"** on the desktop rotates `room_secret`, which un-pairs every phone.

## 6. Desktop app
- New `RelayTransport` in vq-host-core, implementing the existing `Transport` trait, with:
  - **WebSocket first** (tokio-tungstenite or similar), with **TLS from the OS certificate store** (Windows schannel / macOS Security framework — e.g. `native-tls`, or `rustls-platform-verifier`);
  - **OS proxy settings**:
    - Windows: WinHTTP/WinINet per-user settings, **including PAC/WPAD** (`WinHttpGetIEProxyConfigForCurrentUser` + `WinHttpGetProxyForUrl`);
    - macOS: `CFNetworkCopySystemProxySettings` / PAC;
    - CONNECT tunnelling for wss.
  - **Long-poll fallback** when the WebSocket can't connect or keeps dropping within 10 s. Retry WebSocket every 5 min.
  - Reconnect with backoff 1, 2, 4, 8, max 30 s.
  - Room creation (`PUT /rooms`) on first start, once an owner token is configured.
- **Settings → Relay:**
  - relay URL;
  - owner token (password field, stored in the per-user secret store);
  - status (connected via WebSocket / long-poll / error with reason, e.g. "proxy blocked", "certificate not trusted", "owner token rejected");
  - "Test connection";
  - "Reset relay room".
- **Settings → Phones:** "Add phone" (the QR, as large as possible, with a countdown) and the paired phones list with Forget.
- **Status bar:**
  - "Connected via relay (WebSocket)" / "Connected via relay (fallback)";
  - "Relay unreachable — <reason>";
  - "Waiting for iPhone".
- **Remove:** the BLE transports (`ble.rs`, `ble_peripheral.rs`, BLE policy code), `third_party/btleplug`, the `[patch]` entry, the Bluetooth Info.plist key, and adapter-state UI.

## 7. iPhone app
- New relay transport: `URLSessionWebSocketTask`, with long-poll fallback over `URLSession`. It respects iOS networking (cellular and Wi-Fi) and runs in the foreground only. On background it closes; on foreground it reconnects.
- The phone connects to **every paired desktop's room** while in the foreground. The host list is the paired desktops: online if `desktop_present`, otherwise offline.
- **QR scanner** in the Host picker: "Add desktop" → camera → parse → pair.
- **Remove:** the CoreBluetooth transports, the Bluetooth permission and usage string, and BLE-only UI (nearby list, radio banners).
- PhoneSim gains a relay client (it replaces TCP for E2E), so `tests/e2e` runs against a local `vq-relay`.

## 8. Relay implementation (`/relay`, revised: self-hosted)
- A Rust binary crate **`vq-relay`** in the workspace (axum + tokio, WebSockets via axum's ws support). It listens on **127.0.0.1:8787** by default; only `cloudflared` reaches it.
- Room auth metadata (`room_id → secret_hash, created_at`) is persisted in a small JSON file, written atomically to the relay's data dir (`~/Library/Application Support/vq-relay/` on macOS, overridable with `--data-dir`). Nothing else is persisted.
- Config:
  - env/flags `VQ_RELAY_OWNER_TOKEN`, or `--owner-token-file` (a 0600 file);
  - `--listen`, `--data-dir`.
- Cloudflare's tunnel sets `CF-Connecting-IP`; use it for per-IP limits when present.
- **Deployment on the Mac mini** (`relay/deploy/`, documented in `relay/README.md`):
  1. `cargo build --release -p vq-relay`; install the binary to `/usr/local/bin/vq-relay`, or use it in place.
  2. A launchd plist `com.jbrasfield.vq-relay.plist` (RunAtLoad, KeepAlive, logs to `~/Library/Logs/vq-relay.log`), with `scripts/install-relay-macos.sh` to install and load it.
  3. Cloudflare Tunnel:
     - `brew install cloudflared`;
     - `cloudflared tunnel login` (the owner);
     - `cloudflared tunnel create ventriloquist`;
     - `cloudflared tunnel route dns ventriloquist relay.jbrasfield.com`;
     - config.yml with ingress `relay.jbrasfield.com → http://127.0.0.1:8787` (WebSockets are supported by default);
     - `sudo cloudflared service install`.
  4. Keep the mini awake: `sudo pmset -a sleep 0 disksleep 0`, or the Energy settings ("Prevent automatic sleeping when the display is off").
  5. Check from anywhere with `curl https://relay.jbrasfield.com/v1/health`.
- Tests: Rust integration tests that start the server on an ephemeral port, covering SPEC_V3 §10 gate 1. `tests/e2e` runs `vq-relay` locally (R4).

## 9. Security
- The room secret authorizes joining. The owner token authorizes creating rooms. **Frames are E2E-encrypted by the existing session keys**, so the relay can't read or forge utterances.
- QR pairing pins the desktop's public key, which removes the v1 accepted MITM risk on the pairing code.
- Relay hardening:
  - constant-time secret checks;
  - per-IP rate limits on room creation and failed auth;
  - size and rate limits per connection;
  - **no CORS needed** (native clients only).
- Anyone who photographs the QR during its 120 s window can pair. The desktop shows "Phone '<name>' paired", and the phone list makes extra phones visible.

## 10. Verification (gates)
1. `cargo test -p vq-relay`: auth (owner token, room secret, hash mismatch), routing (desktop↔phone, `to`), presence events, limits, replacement of the second desktop, long-poll send/poll with cursors and the 25 s hold, WebSocket↔long-poll interop in the same room, idle close.
2. vq-host-core RelayTransport unit tests against a mock relay. Proxy resolution logic is pure and tested (PAC evaluation is delegated to the OS API; just test the decision layer).
3. **E2E:** `tests/e2e/run.sh` starts `vq-relay` (local), the desktop core (`vq-host` with relay transport) and PhoneSim (relay client), and runs all existing scenarios plus QR-style pairing and long-poll-only mode.
4. Existing gates stay green: protocol, inject, frontend, desktop build, iOS tests and build.
5. The manual checklist gets a Relay section:
   - Windows on the corporate network, WebSocket and fallback;
   - Mac;
   - phone on cellular;
   - QR pairing, Forget, Reset room;
   - proxy errors surfaced.

## 11. Milestones (v3)

| # | Milestone | Done when |
|---|---|---|
| R1 | `vq-relay` server + tests + Mac mini deploy (launchd + Cloudflare Tunnel) docs/scripts | gate 1 |
| R2 | Desktop RelayTransport (WS + long-poll, OS proxy/PAC, OS certs), Relay & Phones settings, QR display, BLE removal | gates 2, 4 |
| R3 | iPhone relay transport + QR scanner + BLE removal; PhoneSim relay client | iOS gates |
| R4 | E2E via local relay | gate 3 |
| R5 | Reviewer + adversary (relay auth, pairing/QR, proxy handling), fixer | all gates |
| R6 | Owner sets up the Mac mini (relay service + cloudflared tunnel), installs the apps, runs the checklist | owner |

## 12. Open questions
- None blocking. The owner token is generated with `openssl rand -base64 32`, or by the desktop app ("Generate"), which shows it once to put in the relay's owner-token file.
