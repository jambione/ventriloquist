# Ventriloquist — Specification v1

Speak into an iPhone; the words appear in a desktop app window, ready to copy and paste into a terminal.

Status: **APPROVED by owner 2026-10-03.**

---

## 1. Goals and non-goals

### Goals
- G1. Dictate on an iPhone. Text appears live in a desktop app over **Bluetooth LE**, with no network required.
- G2. On-device transcription on the iPhone (Apple **SpeechAnalyzer**, iOS 26+). Audio never leaves the phone.
- G3. Desktop app on **macOS and Windows** (Tauri + Rust). It shows transcripts for manual copying and appends them to a daily Markdown log.
- G4. One-time pairing with a 6-digit code, after which all traffic is end-to-end encrypted at the application layer.
- G5. Personal use: everything is built from source. There is no App Store, notarization or installer signing.

### Non-goals (v1)
- No auto-typing or keystroke injection into other apps, and no auto-copy to the clipboard.
- No Linux, Android, cloud relay, Wi-Fi transport, or desktop-side speech recognition.
- No background, lock-screen, Action Button or Shortcuts dictation. Dictation works only while the app is in the foreground.
- English (en-US) only.
- Text is never broadcast to more than one desktop at a time.

---

## 2. Owner decisions (from the requirements interview)

| Topic | Decision |
|---|---|
| Speech-to-text | On iPhone, Apple SpeechAnalyzer (iOS 26 minimum) |
| Transport | Bluetooth LE |
| Desktop app | Cross-platform GUI: Tauri v2 + Rust, BLE through `btleplug` |
| Desktop OSes | macOS and Windows |
| Delivery | Display for manual copy, plus append to a log file |
| Streaming | Live partial results, then a final result |
| Phone trigger | Tap to start, tap to stop |
| Pairing/security | One-time 6-digit code plus app-level encryption; both sides remember each other |
| Multiple desktops | Phone chooses one from a list and remembers the last one |
| Phone UI | Live transcript, edit after stopping (sends a correction), history with re-send |
| Edit vs. live | Stream live; an edit after stopping replaces the desktop entry |
| Desktop UI | Scrolling list (newest at bottom), Copy button per entry, search, clear view |
| Log | Daily Markdown files in a configurable directory |
| Language | en-US plus a user-editable custom vocabulary |
| Background | Foreground only |
| Distribution | Personal use, built from source |
| Verification | Shared protocol with test vectors, mock-transport end-to-end test, clean builds, manual on-device checklist |

---

## 3. Architecture

```
┌──────────────── iPhone (iOS 26, SwiftUI) ───────────────┐        ┌──────────── Desktop (Tauri v2) ──────────────┐
│ DictationEngine (SpeechAnalyzer + AVAudioEngine)        │        │ Web UI (Vite + TypeScript)                   │
│        │ partial/final text                             │        │        ▲ Tauri events / commands             │
│ UtteranceController (ids, revisions, throttling, edit)  │        │ vq-host-core (Rust lib, no Tauri deps)       │
│        │                                                │        │   SessionManager · TranscriptStore · Logger  │
│ VQProtocol (Swift pkg): messages · crypto · framing     │◄──────►│ vq-protocol (Rust crate)                     │
│        │                                                │  BLE   │        │                                     │
│ Transport protocol                                      │  GATT  │ Transport trait                              │
│   ├─ BLEPeripheralTransport (CoreBluetooth peripheral)  │        │   ├─ BleCentralTransport (btleplug)          │
│   └─ TCPTransport (tests/dev only, server)              │        │   └─ TcpTransport (tests/dev only, client)   │
└─────────────────────────────────────────────────────────┘        └──────────────────────────────────────────────┘
```

### 3.1 BLE roles (fixed decision)
- **The iPhone is the GATT peripheral; the desktop is the GATT central.** `btleplug` supports only the central role, and peripheral support on Windows is unreliable.
- The phone advertises the Ventriloquist service UUID while the app is in the foreground.
- Each desktop scans for that service UUID, connects, and subscribes. The phone can therefore have **several desktops connected at once**, and it decides which one is *active*. Utterance data is sent only to the active desktop, through `updateValue(_:for:onSubscribedCentrals:)` targeted at that one central.
- The phone's "host list" is the set of identified, connected centrals (desktops that completed `Hello`), merged with remembered paired hosts that are currently offline.

### 3.2 GATT layout
UUIDs are generated once and recorded in `protocol/README.md` and in both codebases as constants.

| Characteristic | Properties | Direction | Purpose |
|---|---|---|---|
| `RX` | Write (with response) | desktop → phone | Frames from the desktop (hello, pairing, acks) |
| `TX` | Notify | phone → desktop | Frames from the phone (pairing, utterances) |

All application traffic goes through the framing layer (§4.2). The two characteristics are a byte pipe; they carry no other semantics.

### 3.3 Repository layout
```
/SPEC.md
/protocol/                  Rust crate `vq-protocol` + README (wire spec) + vectors/*.json
/desktop/core/              Rust crate `vq-host-core` (session, store, logger, transports); no Tauri deps
/desktop/app/               Tauri v2 app (src-tauri depends on vq-host-core; frontend is Vite + TS)
/ios/VQProtocol/            Swift package mirroring vq-protocol, tested against the same vectors
/ios/PhoneSim/              Swift CLI (same package): fake phone over TCP for the E2E test
/ios/App/                   iOS app; project generated by XcodeGen from project.yml
/tests/e2e/                 E2E script: host-core over TCP <-> PhoneSim
/docs/MANUAL_TEST.md        On-device checklist
/scripts/verify.sh          Runs every automated gate (§9)
```
A Cargo workspace at the repo root contains `protocol`, `desktop/core` and `desktop/app/src-tauri`.

---

## 4. Wire protocol

`protocol/README.md` is the normative document for the wire protocol. This section is its source. Rust and Swift **must** both pass every vector in `protocol/vectors/`.

### 4.1 Message encoding
- Plaintext messages are UTF-8 **JSON** objects with a `"t"` type field. Unknown fields are ignored; unknown `t` values are logged and dropped, never fatal.
- Maximum decoded message size is 64 KiB. Anything larger is rejected.
- Maximum `text` length is 32,000 UTF-8 bytes. The phone enforces this by ending the utterance when it is reached.

### 4.2 Framing (handles BLE MTU)
Each logical message is split into frames that fit the negotiated ATT payload (`maximumUpdateValueLength` on iOS, the MTU on the desktop; assume ≥ 20 bytes):
```
byte 0      : flags  (bit0 = FIRST, bit1 = LAST, bits2-7 reserved = 0)
bytes 1..2  : msg_seq (u16 BE, increments per logical message, per direction, wraps)
bytes 3..   : chunk
```
- The receiver reassembles frames per direction. A FIRST frame resets any partial buffer. A frame whose `msg_seq` does not match the current buffer discards that buffer. Exceeding 64 KiB discards the buffer and logs an error.
- The reassembled bytes form one **envelope** (§4.3).

### 4.3 Envelope
```
byte 0      : kind  (0x00 = plaintext, 0x01 = encrypted)
plaintext   : JSON bytes   — allowed ONLY for: hello, pair_request, pair_challenge, pair_confirm, pair_result, error
encrypted   : counter (u64 BE) ‖ ciphertext‖tag (ChaCha20-Poly1305)
```
- Encryption uses ChaCha20-Poly1305. The 12-byte nonce is `direction_byte (0x01 phone→desktop, 0x02 desktop→phone) ‖ 0x000000 ‖ counter u64 BE`. AAD is the kind byte.
- Each direction has its own counter, which starts at 0 per session and is strictly increasing. The receiver rejects any counter ≤ the last accepted one (replay protection).
- After a session is established, every non-plaintext-allowed message **must** be encrypted. Plaintext utterances are rejected.

### 4.4 Identity and pairing
- Each install generates a long-term **X25519 identity key pair** and a random 128-bit `device_id`. iOS stores the private key in the Keychain (`ThisDeviceOnly`). The desktop stores it in a 0600 file in the app config dir (Windows: per-user AppData, ACL'd to the user).
- Pairing is started from the phone, by tapping an unpaired desktop:
  1. Desktop → phone `hello {device_id, name, pub, paired:bool}` is sent automatically after subscribing. The phone replies with `hello`. If both sides already know each other's `device_id` and `pub`, skip to §4.5.
  2. Phone → desktop `pair_request {nonce_p (32B b64)}`.
  3. The desktop generates a 6-digit code `C` (CSPRNG, uniform over 000000–999999) and shows it in a modal: *"Pairing request from <phone name>. Enter this code on your phone: 123 456"*. It replies `pair_challenge {nonce_d}`. The code expires after **120 s**.
  4. The user enters `C` on the phone. Both sides compute `ss = X25519(own_priv, peer_pub)` and `K_pair = HKDF-SHA256(ikm=ss, salt=nonce_p‖nonce_d, info="vq/pair/v1"‖C)`. The phone sends `pair_confirm {mac = HMAC-SHA256(K_pair, "phone"‖pub_p‖pub_d)}`.
  5. The desktop verifies the MAC. On success it stores the phone (`device_id`, `pub`, name) and replies `pair_result {ok:true, mac = HMAC(K_pair, "desktop"‖pub_d‖pub_p)}`. The phone verifies that MAC and stores the desktop. On failure it replies `pair_result {ok:false}`. **After 3 failures, the code is invalidated** and the user must start pairing again.
- **Threat model (explicit):** this design defends against passive eavesdroppers, unpaired devices sending text, and tampering or replay after pairing. An active man-in-the-middle present *during* the 120-second pairing window could brute-force the code offline from the phone's MAC. The owner accepts that risk for a personal tool. Do not "fix" it by adding complexity without the owner's approval.

### 4.5 Session establishment (on every connection)
- After `hello` is exchanged between paired peers, both sides send fresh `session_nonce` values inside `hello`. The session key is `K_sess = HKDF-SHA256(ikm=ss, salt=nonce_phone‖nonce_desktop, info="vq/session/v1")`, 32 bytes, and counters reset to 0.
- Either side may send `error {code, msg}` (plaintext) and disconnect. Codes include `unknown_peer`, `bad_mac`, `decrypt_failed`, `version`.
- `hello` carries `v: 1`. On a version mismatch, the peer sends `error{code:"version"}`, and both UIs show "Update Ventriloquist on <device>".

### 4.6 Application messages (encrypted)
| `t` | Direction | Fields | Semantics |
|---|---|---|---|
| `utt` | phone → desktop | `id` (UUID), `rev` (u32), `state` (`partial`/`final`/`edit`), `text`, `ts` (ms epoch, start of utterance) | Full current text, not a diff. The desktop keeps the highest `rev` per `id` and ignores lower or equal ones. |
| `ack` | desktop → phone | `id`, `rev` | Sent for `final` and `edit` only. |
| `ping` / `pong` | both | — | Keepalive every 15 s. Missing 3 in a row means the peer is treated as disconnected. |

Rules:
- Partials are throttled to at most **5 per second**, always sending the latest text. The final is sent immediately on stop.
- The phone retries an unacked `final`/`edit` every 2 s, up to 5 times while connected. If the desktop reconnects, pending unacked messages are re-sent. Delivery is at-least-once, and the receiver is idempotent by (`id`, `rev`).
- `edit` replaces the text of an existing entry (same `id`, higher `rev`). If the desktop has never seen that `id`, it creates the entry.
- **Re-send from history** creates a **new** `id` with a single `final`.

---

## 5. iPhone app (SwiftUI, iOS 26)

### 5.1 Screens
**Main (Dictate)**
- **Header:** active desktop name with a status dot (green = connected and secure, amber = connecting or reconnecting, grey = none). Tapping it opens the Host picker.
- **Live transcript area:** volatile (partial) text in secondary color, finalized text in primary color. It auto-scrolls.
- **Large circular record button** at the bottom. Tap to start; it pulses red while recording. Tap again to stop.
- **After stopping:** the transcript becomes an editable `TextEditor`. A **"Send correction"** button is enabled only when the text differs from what was sent. Sending it sends `edit`. Starting a new recording commits the current entry to history.
- **Disabled states:** recording is allowed with no host connected. Text queues and sends when a host becomes active. The header says "Not connected — will send when connected".

**Host picker (sheet)**
- Sections: **Paired** (online or offline badge) and **Nearby, not paired**.
- Tapping a paired online host makes it active and remembers it. Tapping an unpaired host starts pairing and opens the code-entry sheet (6 digits, numeric keypad, auto-submits on the 6th digit, shows a clear error on failure).
- Swipe to **Forget** a paired host.
- On launch, the remembered last host is selected automatically when it connects.

**History**
- A list of past utterances (newest first): text, time, and delivery status (✓ acked, ⏳ pending, ✗ failed).
- Tap to view or copy. A **Re-send** action sends the entry to the active host as a new utterance. Swipe to delete. **Clear all** asks for confirmation.
- History is stored locally with SwiftData, capped at 1,000 entries (oldest pruned first).

**Settings**
- Custom vocabulary: an editable list of terms (e.g. `kubectl`, `PostgreSQL`), passed to SpeechAnalyzer as contextual strings.
- Device name shown to desktops (defaults to the iPhone's name).
- Partial streaming on/off. Off means only `final`/`edit` are sent.

### 5.2 Dictation engine
- Uses `SpeechAnalyzer` with `SpeechTranscriber` (locale en-US, volatile results enabled). On first run, the model is fetched through `AssetInventory` with progress UI.
- Custom vocabulary goes in through `AnalysisContext` contextual strings. The builder must verify the API against the iOS 26 SDK. If contextual strings are unsupported for `SpeechTranscriber`, use `DictationTranscriber` and document the choice.
- Audio comes from `AVAudioEngine` with the `.record` category in `.measurement` mode. Audio is processed in memory only and never written to disk.
- Permissions requested on first use: microphone, speech recognition (if required by the API), and Bluetooth. If a permission is denied, the screen explains why it's needed and gives a "Open Settings" button.
- Interruptions such as a phone call or Siri stop the recording gracefully and send `final`.
- When the app is backgrounded during a recording, the recording stops and sends `final`. Advertising stops in the background, and the BLE state is restored on returning to the foreground.

---

## 6. Desktop app (Tauri v2, macOS + Windows)

### 6.1 Window
- **Toolbar:** connection status (e.g. "● Connected to Jon's iPhone (secure)", "Scanning…", "Bluetooth off"), a search field, a **Clear view** button, and a **Settings** gear.
- **Transcript list:**
  - Chat-like, with the newest entry at the bottom. The list auto-scrolls to the bottom only if the user is already at the bottom.
  - Each entry shows its time (HH:MM:SS), device name, and text in a **monospace** font. Text is selectable.
  - A **Copy** button per entry copies the exact text, with no trailing newline, and shows "Copied ✓" for 1.5 s.
  - A live partial entry is shown dimmed and italic with a "speaking…" indicator. It becomes normal when it turns `final`.
  - An entry replaced by an `edit` shows an "edited" badge.
- **Search:** case-insensitive substring filter over the entries currently in view.
- **Clear view:** empties the on-screen list only. It never touches the log.
- **Pairing modal:** shows the 6-digit code in large type, the requesting phone's name, a countdown, and a Cancel button.
- **Settings:** log directory (folder picker; default `~/Documents/Ventriloquist/`), paired phones with a Forget button, this desktop's display name (default: hostname), and an "Open log folder" button.
- In-memory history keeps the last 500 entries for the current run. Earlier history lives in the log files.

### 6.2 Log file
- Path: `<log_dir>/YYYY-MM-DD.md`, using the local date of the utterance's final arrival. The file is created with a `# Ventriloquist — YYYY-MM-DD` header.
- Appended on `final`:
  ```
  - **14:03:22** · Jon's iPhone · `id=1a2b3c4d`
    <text, each line indented 2 spaces>
  ```
- Appended on `edit`: the same format with `· edited`. The original line is never rewritten, so the log is append-only.
- Partials are never logged. Duplicate (`id`, `rev`) deliveries are never logged twice.
- Writes are append plus flush. If the log can't be written, the UI shows a non-blocking warning banner and transcription keeps working.

### 6.3 BLE central (`BleCentralTransport`)
- Scans for the service UUID, connects to every advertising phone, subscribes to `TX`, and sends `hello`.
- Unpaired phones are kept connected while pairing may happen, and are dropped after 5 minutes of no pairing activity.
- Auto-reconnects with backoff (1, 2, 4, 8, max 15 s) whenever the peripheral disappears.
- macOS: `NSBluetoothAlwaysUsageDescription` goes in Info.plist. Windows: WinRT through btleplug. If Bluetooth is off or unauthorized, the toolbar says so.

---

## 7. Desktop core (`vq-host-core`) responsibilities
- `SessionManager`: per-peer state machine (`Connected → HelloExchanged → (Pairing →) Secure → Closed`), framing, crypto, and ack/ping.
- `TranscriptStore`: entries keyed by `id`, revision handling, and a 500-entry cap. Emits `entry_upserted` events.
- `Logger`: append-only daily Markdown with dedupe by (`id`, `rev`).
- `PairingStore`: persisted peers in JSON in the app config dir.
- `Transport` trait implemented by BLE and TCP. The TCP transport is **behind a `dev-tcp` cargo feature** and must not be enabled in release builds of the app.
- It is fully usable headlessly. A `vq-host` binary (feature `dev-tcp`) runs the core over TCP and prints entries to stdout, for the E2E test.

## 8. iOS internals
- `VQProtocol` (Swift package, CryptoKit only, no third-party deps) contains messages, framing, envelope, pairing and session crypto.
- A `Transport` protocol has `BLEPeripheralTransport` and `TCPTransport` (`#if DEBUG` or a test target only).
- `PhoneSim` (an executable target in the same package) is a scripted fake phone that serves TCP, pairs with a given code, sends partial/final/edit, and verifies acks. It is used by the E2E test.
- The app is generated by **XcodeGen** (`ios/App/project.yml`). The generated `.xcodeproj` is gitignored.

---

## 9. Verification gates (all must pass; `scripts/verify.sh` runs them)
1. **Protocol vectors:** `cargo test -p vq-protocol` and `swift test` in `ios/VQProtocol`. Both consume `protocol/vectors/*.json`, which covers framing split/reassembly, the envelope, HKDF outputs, the pairing MACs, encryption with fixed keys, nonces and counters, and replay rejection.
2. **Core tests:** `cargo test -p vq-host-core`. These cover revision ordering, duplicate and out-of-order delivery, the edit-before-final case, log dedupe and formatting, pairing failure lockout after 3 tries, code expiry, plaintext-utterance rejection, and oversize-message rejection.
3. **E2E (mock transport):** `tests/e2e/run.sh` starts `vq-host` (TCP) and `PhoneSim`, pairs, sends partials, a final and an edit, and then asserts the log file contents and the stdout entries. It also covers reconnect and re-delivery without duplicates.
4. **Clean builds:** `cargo clippy --workspace -- -D warnings`, `cargo tauri build` (on macOS), and `xcodegen && xcodebuild -scheme Ventriloquist -destination 'generic/platform=iOS Simulator' build` with zero errors and zero Swift compiler warnings in project code.
5. **Frontend:** `npm run build` plus `tsc --noEmit` with strict mode.
6. **Manual checklist:** `docs/MANUAL_TEST.md` covers pairing, live streaming, edits, re-sends, two desktops, Bluetooth off and on, walking out of range and back, a 5-minute continuous dictation, and Windows-specific steps. The owner runs this checklist; agents only write it.

### Prerequisites the owner must install
- Rust (rustup, stable) and `cargo install tauri-cli --version ^2`
- `brew install xcodegen`
- Xcode 27 (installed) with the iOS 26+ SDK
- For the Windows build: a Windows machine with the Rust MSVC toolchain and WebView2. Windows builds are verified by the owner, not by the agents.

---

## 10. Build process (agents)

The build runs as milestones. Each milestone goes through a **Builder → Critics ∥ Adversary → Fixer → Gate** loop, for up to 3 rounds. After that, any unresolved findings are escalated to the owner.

| # | Milestone | Done when |
|---|---|---|
| M1 | `vq-protocol` (Rust) + vectors + `protocol/README.md` | Gate 1 (Rust half) |
| M2 | `VQProtocol` (Swift) passes the same vectors | Gate 1 (both halves) |
| M3 | `vq-host-core` + `vq-host` TCP binary | Gate 2 |
| M4 | `PhoneSim` + E2E | Gate 3 |
| M5 | Tauri app (UI + BLE central) | Gates 4 (desktop) and 5 |
| M6 | iOS app (dictation, BLE peripheral, UI) | Gate 4 (iOS) |
| M7 | Manual checklist, top-level README, final full-spec audit | All gates; a final critic pass finds no spec deviations |

Roles:
- **Builder:** implements the milestone strictly from this spec.
- **Spec Critic:** compares the code to this spec section by section and reports every deviation, omission and ambiguity, with file and line references.
- **Quality Critic:** reviews correctness, error handling, concurrency and data races, and code clarity.
- **Adversary:** tries to break the code. It writes failing tests for malformed frames, oversize input, replay, wrong-code brute force, out-of-order revisions, disconnects mid-message, counter wrap, unicode edge cases, and log-path problems. Its findings must be **executable failing tests** where possible.
- **Fixer:** fixes the findings and must not weaken or delete adversary tests. If the spec itself is wrong or ambiguous, it records a proposed change in `docs/SPEC_QUESTIONS.md` instead of silently diverging.
- **Gate:** the orchestrator runs the verification commands. A milestone is done only when the gate is green and no critic finding is open.

---

## 11. Owner-resolved items
- Pairing MITM risk during the 120-second window: **accepted** (§4.4). Do not add SAS.
- Apple Team ID: **`D5K4MV7298`** (automatic signing). iOS bundle id: **`com.ventriloquist.app`**. Desktop Tauri identifier: **`com.ventriloquist.desktop`**.
- Toolchain installed on the build Mac: Rust 1.99 (rustup; run `. "$HOME/.cargo/env"` in a fresh shell), tauri-cli 2.12.1, XcodeGen 2.46, Xcode 27, Node 20.
- Windows is built and verified by the owner. Agents only keep the code Windows-compatible (no macOS-only APIs outside `cfg(target_os)`).
- Still open, to be settled by the M6 builder: the custom vocabulary API details (§5.2). Use the documented fallback if needed.
