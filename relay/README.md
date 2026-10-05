# vq-relay

The Ventriloquist relay: a small Rust server (axum + tokio) that forwards **end-to-end encrypted** frames between a desktop and its phones. It runs on the owner's Mac mini, behind a Cloudflare Tunnel, at `https://relay.jbrasfield.com`. See SPEC_V3.md.

The relay stores only `room_id -> { secret_hash, desktop_secret_hash?, created_at }` (a JSON file, written atomically). It never stores or logs frame contents.

## Protocol (normative)

All paths are under `/v1`. Bodies are JSON. Errors are `{"error": "<code>"}` with the HTTP status below.

### Identities and secrets
- `room_id`: 16 to 64 characters of `[A-Za-z0-9_-]` (the desktop uses 128 random bits, base64url).
- `room_secret`: 256 random bits, base64url. The relay holds only `secret_hash = base64url(SHA-256(room_secret))` (43 characters, unpadded).
- `desktop_secret`: a second 256-bit secret, known only to the desktop and never put in the QR. The relay holds `desktop_secret_hash = base64url(SHA-256(desktop_secret))`. `role=desktop` authenticates with it; `role=phone` authenticates with `room_secret`. A room without `desktop_secret_hash` (created before it existed) refuses `role=desktop` with **401** until the desktop re-PUTs. Forgetting a phone does not revoke its relay access (it keeps `room_secret`); "Reset relay room" rotates both secrets.
- `owner_token`: configured on the relay. It authorizes creating and deleting rooms. Phones never see it.
- Secrets are compared in constant time (SHA-256 digests compared with a constant-time equality).

### Endpoints

| Method and path | Who | Purpose |
|---|---|---|
| `PUT /rooms/{room_id}` | desktop | Create or claim a room. Header `X-VQ-Owner: <owner_token>`. Body `{"secret_hash":"<b64url>","desktop_secret_hash":"<b64url>"}` (`desktop_secret_hash` is optional on the wire, for migration). **201** created, **200** exists with the same hashes, **200** and the desktop hash is added when the room has none and `secret_hash` matches, **409** `secret_hash` differs or a different `desktop_secret_hash` is already set, **401** bad owner token, **400** malformed id or hash, or a hash of the empty string. Body limit 4 KiB; auth is checked before any body is read, and the body must arrive within 10 s (else **408**) |
| `GET /rooms/{room_id}/ws?role=desktop\|phone` | both | WebSocket upgrade (real-time channel) |
| `POST /rooms/{room_id}/send?role=..&session=..` | both | Long-poll fallback: send frames |
| `GET /rooms/{room_id}/poll?role=..&session=..&cursor=..` | both | Long-poll fallback: wait for frames and events |
| `DELETE /rooms/{room_id}` | desktop | Delete the room. Needs the owner token header **and** `Authorization: Bearer <room_secret>`. **204**; every connection is closed with 4003 |
| `GET /health` | anyone | `200 ok` |

### Authentication
- WebSocket, send, poll: `Authorization: Bearer <secret>`, where the secret is the `desktop_secret` for `role=desktop` and the `room_secret` for `role=phone`. For clients that cannot set headers on a WebSocket, offer the subprotocol `vq.auth.<room_secret>` instead; the relay echoes it in `Sec-WebSocket-Protocol`.
- Bad, empty or missing secret: **401**. Unknown room: **404**. Bad `role`: **400**.
- There is no CORS; the clients are native.

### Roles
- One **desktop** per room, up to **8 phones**. A phone beyond the eighth is refused: **429** `room_full` (WebSocket upgrade or `send`/`poll`).
- A second desktop connection **replaces** the first. The first is closed with code **4001** `replaced`. Phones then receive `desktop_present:false` followed by `desktop_present:true`, so they can restart their `hello`.
- Every connection (a WebSocket, or a long-poll session) gets an opaque `conn_id`.

### Messages
Client to relay:
```json
{ "type": "frame", "to": "<conn_id>", "data": "<base64>" }
```
- A desktop MUST give `to`. A phone's `to` is ignored: phones always send to the desktop.
- `data` is standard base64 (padding optional); it decodes to at most **65536 bytes**.
- A frame to an unknown or departed `to`, or from a phone when no desktop is present, is silently dropped.
- Text `ping` on a WebSocket is answered with text `pong` (an application-level keepalive).

Relay to client:
```json
{ "type": "frame", "from": "<conn_id>", "data": "<base64>" }
```
Relay to the desktop:
```json
{ "type": "peer_joined", "conn_id": "..." }
{ "type": "peer_left",   "conn_id": "..." }
```
A desktop that connects is sent `peer_joined` for every phone already present. Relay to a phone:
```json
{ "type": "desktop_present", "present": true }
```
A phone gets the current value right after it connects, and again whenever it changes.

### WebSocket details
- Binary or text messages are accepted, UTF-8 JSON in both cases.
- The relay sends a WebSocket ping every 20 s. A connection that sends nothing (messages, pongs or text `ping`) for **60 s** is closed with 4002 `idle`.

### Limits
- Frame: 64 KiB decoded. A message larger than 96 KiB, or a frame over 64 KiB, closes the WebSocket with 1009 (HTTP: **413**). `/send` bodies are limited to 128 KiB, enforced while streaming; request headers must arrive within 10 s.
- Each WebSocket connection has an outbound queue of 256 messages (pongs included); overflow closes it with 4008.
- 50 frames/s per connection (token bucket, burst 50). Exceeding it closes the WebSocket with 4029 (HTTP: **429**).
- 8 phones per room.
- Per IP: 10 new rooms per minute, and 10 failed authentications (owner token or room secret) per minute. Beyond that: **429** `rate_limited`. The IP is the `CF-Connecting-IP` header only when the TCP peer is loopback (the local `cloudflared`); from any other peer the peer address is used.

### Close codes

| Code | Meaning |
|---|---|
| 4001 | replaced by a newer desktop connection |
| 4002 | idle for 60 s |
| 4003 | room deleted |
| 4008 | queue overflow (long-poll: more than 1000 unacknowledged events; WebSocket: 256 queued messages not being read) |
| 4029 | frame rate limit exceeded |
| 1008 | malformed message (not JSON, not a `frame`, bad base64, desktop frame without `to`) |
| 1009 | frame or message too large |

### Long-poll fallback
A *session* is a connection that uses HTTP instead of a WebSocket. It is created by its first `send` or `poll` and identified by the client-chosen `session` (8 to 64 characters of `[A-Za-z0-9_-]`; use a random value). It joins the room exactly like a WebSocket connection, so WebSocket and long-poll clients interoperate in one room.

**`POST send`**: body is a single frame object, or `{"frames":[{"to":"..","data":".."}, ...]}` (the `type` field is optional inside `frames`). Response `200 {"ok":true,"accepted":n,"conn_id":".."}`. **400** malformed, **413** a frame over 64 KiB, **429** rate limit or room full, **410** the session was closed.

**`GET poll`**: waits up to **25 s** for events and answers
```json
{ "conn_id": "..", "cursor": 7, "events": [ { "type": "frame", ... }, ... ] }
```
- Events are the same objects as on a WebSocket, numbered 1, 2, 3, ... per session.
- `cursor` is the number of the last event returned. The client passes it back as `cursor=`; the relay then drops every event up to it. Events are kept until acknowledged, so a poll whose response was lost can be repeated with the same cursor and returns the same events (at-least-once; deduplicate by cursor).
- A poll with no new events returns after 25 s with `"events": []` and an unchanged cursor. A new poll on the same session supersedes one still held.
- The poll itself is the keepalive. A session with no poll or send for **60 s** is closed (peers see `peer_left` / `desktop_present:false`).
- A poll with `cursor=0` on an unknown session creates it. A poll with `cursor>0` on an unknown session is **410** `session_expired`: the client must start a new session (new `session` id) and reconnect its peer state. A cursor beyond the last event is **400**.
- If the session was ended by the relay (replaced, deleted, overflow), the response carries `"closed": {"code": 4001, "reason": "replaced"}` after the remaining events, and the session is dropped.
- More than 1000 unacknowledged events closes the session with 4008 `overflow`.

## Running

```
cargo build --release -p vq-relay
VQ_RELAY_OWNER_TOKEN=$(openssl rand -base64 32) \
  target/release/vq-relay --listen 127.0.0.1:8787 --data-dir ./relay-data
```

| Option | Default |
|---|---|
| `--listen ADDR` | `127.0.0.1:8787` |
| `--data-dir DIR` | `~/Library/Application Support/vq-relay` (macOS) |
| `--owner-token-file FILE` | a 0600 file; used when `VQ_RELAY_OWNER_TOKEN` is unset |

Tests: `cargo test -p vq-relay` (starts the server on ephemeral ports; one test waits out the real 25 s long-poll hold).

## Deploying on the Mac mini

1. **Build and install the service.**
   ```
   scripts/install-relay-macos.sh
   ```
   This builds the release binary, installs it to `~/.local/bin/vq-relay` (no `sudo`, so updates work over SSH), creates `~/Library/Application Support/vq-relay/owner-token` (mode 0600, generated with `openssl rand -base64 32` unless it exists; `--token-file FILE` uses yours), installs `relay/deploy/com.jbrasfield.vq-relay.plist` into `~/Library/LaunchAgents`, and loads it with `launchctl bootstrap gui/$(id -u)`. The service runs at load, restarts if it exits, and logs to `~/Library/Logs/vq-relay.log`. The script prints the owner token; paste it into the desktop app (Settings > Relay).
   Because it is a user agent, the Mac mini must be logged in (enable automatic login), or convert the plist to a LaunchDaemon.
2. **Cloudflare Tunnel** (no port-forwarding; the zone is already on Cloudflare):
   ```
   brew install cloudflared
   cloudflared tunnel login
   cloudflared tunnel create ventriloquist
   cloudflared tunnel route dns ventriloquist relay.jbrasfield.com
   ```
   Put `relay/deploy/cloudflared-config.yml` (filled in with the tunnel UUID and credentials path) at `~/.cloudflared/config.yml`, then
   ```
   sudo cloudflared service install
   ```
   WebSockets work through the tunnel by default.
3. **Keep the Mac awake:** `sudo pmset -a sleep 0 disksleep 0`, or System Settings > Energy > "Prevent automatic sleeping when the display is off".
4. **Check** from anywhere:
   ```
   curl https://relay.jbrasfield.com/v1/health
   ```
   It prints `ok`. Locally: `curl http://127.0.0.1:8787/v1/health`.

Operate: `launchctl kickstart -k gui/$(id -u)/com.jbrasfield.vq-relay` restarts it; `launchctl bootout gui/$(id -u)/com.jbrasfield.vq-relay` stops it. To rotate the owner token, edit the token file and restart.
