# Ventriloquist wire protocol, v1 (normative)

This document is the **normative** specification of the bytes exchanged between the
Ventriloquist iPhone app and the desktop host. It is derived from `SPEC.md` §4 and settles
every detail that section left open. The Rust crate `vq-protocol` (this directory) and the
Swift package `ios/VQProtocol` must both implement exactly this. Both must pass every vector
in [`vectors/`](vectors/). If this document and a vector ever disagree, treat it as a bug and
raise it. Do not quietly pick one.

The key words MUST, MUST NOT, SHOULD and MAY are used as in RFC 2119.

Contents:

1. [Conventions](#1-conventions)
2. [Transport: BLE GATT](#2-transport-ble-gatt)
3. [Framing](#3-framing)
4. [Envelope](#4-envelope)
5. [Messages (JSON)](#5-messages-json)
6. [Identity, pairing and session keys](#6-identity-pairing-and-session-keys)
7. [Connection flow](#7-connection-flow)
8. [Limits and constants](#8-limits-and-constants)
9. [Error codes](#9-error-codes)
10. [Test vectors](#10-test-vectors)

---

## 1. Conventions

- `‖` means byte concatenation.
- All multi-byte integers are **big-endian**.
- String literals such as `"vq/pair/v1"` mean their ASCII bytes, with no terminator and no length prefix.
- **Binary fields in JSON** use RFC 4648 §4 **standard** base64 (alphabet `A–Z a–z 0–9 + /`) **with `=` padding**. Decoders MUST be strict:
  - no whitespace or line breaks;
  - padding is required and must be canonical;
  - the non-zero "trailing bits" form is rejected (for a 32-byte value, the character before `=` must encode 2 zero low bits);
  - the URL-safe alphabet (`-`, `_`) is rejected;
  - the decoded length must equal the field's fixed length, which is 32 bytes for every binary field in v1.

  A 32-byte value is always 44 characters, the last one `=`.
- **UUID fields** (`device_id`, `id`) use the 36-character hyphenated form `xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx`. Senders MUST emit lowercase. Receivers MUST accept either case. Receivers MUST reject every other form: no hyphens, braces, `urn:uuid:`, or the wrong length. The version and variant nibbles are not checked.
- **Integers in JSON** MUST be written as plain decimal integers: no fraction, no exponent, no quotes. A value outside the field's range, negative where unsigned, or fractional makes the message invalid.

## 2. Transport: BLE GATT

The iPhone is the GATT **peripheral**. The desktop is the GATT **central**.

| Item | UUID |
|---|---|
| Service (advertised by the phone) | `77608b26-7b68-49da-bb34-7f05d158e219` |
| `RX` characteristic: Write **with** response, desktop → phone | `18489603-21ac-4cf2-9d31-62bd5d9c1635` |
| `TX` characteristic: Notify, phone → desktop | `b01127eb-8819-42a7-a0e8-bdd6159d4e2a` |

Each GATT write to `RX`, and each notification on `TX`, carries exactly **one frame** (§3). The
characteristics carry no other meaning.

The frame size limit `mtu` is the usable ATT payload size:
- on iOS, `central.maximumUpdateValueLength` for notifications;
- on the desktop, the negotiated ATT MTU minus 3 for writes.

Senders MUST NOT use an `mtu` below 20. The TCP dev transport (tests only) carries the same frames. How it delimits them is defined by `vq-host-core`/PhoneSim and is not part of this document.

## 3. Framing

```
offset  size  field
0       1     flags     bit0 = FIRST (0x01), bit1 = LAST (0x02), bits 2-7 reserved, MUST be 0
1       2     msg_seq   u16 BE
3       n     chunk     0 ≤ n ≤ mtu − 3
```

### 3.1 Sending (splitter)
- Each connection keeps one splitter per direction. Its `msg_seq` starts at **0** when the connection is established. It increases by 1 for each logical message (one envelope) and wraps from `0xFFFF` to `0x0000`.
- The envelope is cut into consecutive chunks of `mtu − 3` bytes. The last chunk may be shorter.
- The first frame has FIRST set and the last frame has LAST set. A single-frame message has `flags = 0x03`. Middle frames have `flags = 0x00`.
- Every frame except the last is exactly `mtu` bytes long.
- An empty message produces exactly one frame, `03 ‖ msg_seq`, with no chunk. A conforming sender never needs this, because envelopes are never empty.
- The splitter MUST refuse:
  - `mtu < 20` (`mtu_too_small`);
  - a message longer than 65,536 bytes (`message_too_large`).

  A refused message does not consume a `msg_seq`.

### 3.2 Receiving (reassembler)
Each connection keeps one reassembler per direction. Its state is either *empty* or *partial* (`seq`, `buffer`). For each incoming frame, apply the first matching rule:

1. If the frame is shorter than 3 bytes, drop it and **discard any partial buffer** (error `frame_too_short`).
2. If any reserved flag bit is set (`flags & 0xFC ≠ 0`), drop it and **discard any partial buffer** (`reserved_flags`).
3. If FIRST is set, silently discard any partial buffer and start a new partial with this frame's `msg_seq` and chunk. FIRST resets the buffer even when the `msg_seq` is the same.
4. If FIRST is clear and the state is empty, drop the frame (`orphan_frame`).
5. If FIRST is clear and `msg_seq` ≠ the partial's `seq`, discard the buffer **and** the frame (`seq_mismatch`).
6. Otherwise, append the chunk.
7. If the buffer now holds more than **65,536** bytes, discard it (`message_too_large`). Exactly 65,536 is allowed.
8. If LAST is set, the buffer is a complete message: hand it to the envelope layer (§4) and set the state to empty.

None of these errors is fatal. The receiver logs them and continues. The receiver does **not** check that `msg_seq` increments between messages, and it accepts frames of any length (it does not enforce `mtu`). When a connection drops, the partial buffer is discarded.

## 4. Envelope

The reassembled bytes form one envelope:

```
plaintext : 0x00 ‖ JSON                                       (1 + len(JSON) bytes)
encrypted : 0x01 ‖ counter (u64 BE, 8) ‖ ciphertext ‖ tag (16) (25 + len(plaintext) bytes)
```

Any other first byte is rejected (`unknown_envelope_kind`). So is an empty envelope (`empty_envelope`), an encrypted envelope shorter than 25 bytes (`envelope_too_short`), and any envelope longer than 65,536 bytes (`message_too_large`).

### 4.1 Encryption
- AEAD: **ChaCha20-Poly1305** (RFC 8439) with a 32-byte key `K_sess` (§6.4) and a 16-byte tag.
- Nonce (12 bytes): `direction ‖ 0x00 0x00 0x00 ‖ counter (u64 BE)`.
  - `direction = 0x01` for phone → desktop.
  - `direction = 0x02` for desktop → phone.

  Example: phone → desktop, counter 1 gives `01 000000 0000000000000001`.
- AAD: the single kind byte `0x01`. The counter is not in the AAD, but it is bound through the nonce.
- `ciphertext ‖ tag` is the standard RFC 8439 output. With CryptoKit, `ChaChaPoly.seal(...).ciphertext ‖ .tag`. The envelope does **not** carry the nonce.
- Plaintext: the UTF-8 JSON message (§5).

### 4.2 Counters and replay protection
- Each direction has its own counter. A sender's counter starts at **0** for each new session (each new `K_sess`) and increases by exactly 1 per encrypted envelope sent. A failed encryption, such as an oversize message, does not consume a counter.
- After a sender has used counter `2^64 − 1`, it MUST NOT send again on that session (`counter_exhausted`). It must reconnect to get a new session.
- The receiver keeps `last` = the highest counter it has **accepted**, which is initially none. It MUST reject a counter ≤ `last` (`replay`) **before** decrypting. Gaps are allowed: the first accepted counter need not be 0.
- `last` is updated **only after** the tag verifies. A forged or tampered envelope (`decrypt_failed`) therefore never moves the window.

### 4.3 Plaintext policy
- A plaintext envelope MAY carry only: `hello`, `pair_request`, `pair_challenge`, `pair_confirm`, `pair_result`, `error`. This holds whether or not a session exists.
- A plaintext envelope carrying any other **known** type (`utt`, `ack`, `ping`, `pong`) MUST be rejected (`plaintext_not_allowed`).
- A plaintext envelope with an **unknown** `t` is treated like any unknown message (§5.1): log it and drop it. Do not treat it as fatal.
- An encrypted envelope may carry any type. An encrypted envelope received when no session key exists is rejected (`no_session`).
- Senders MUST encrypt every message outside the allowed list. Senders SHOULD send the allowed types in plaintext.

## 5. Messages (JSON)

### 5.1 General rules
- A message is a UTF-8 JSON **object** with a string member `"t"`.
- Decoding fails as follows:
  - **`invalid_json`**:
    - the input is not valid UTF-8, or not exactly one JSON value (trailing bytes are not allowed; surrounding JSON whitespace is allowed);
    - the input starts with a UTF-8 BOM.
  - **`invalid_message`**:
    - the value is not an object;
    - `t` is missing or is not a string;
    - a known `t` is missing a required field, or a field has the wrong type, the wrong range or an invalid encoding.
- Unknown members are **ignored**, in every message type.
- An unknown `t` value is matched case-sensitively, so `"PING"` is unknown. The receiver logs it and drops it, never fatally.
- A message larger than **65,536 bytes** is rejected (`message_too_large`). This applies even when its type is unknown.
- `utt.text` larger than **32,000 bytes**, measured in UTF-8 bytes **after** JSON unescaping, is rejected (`text_too_long`). Senders MUST NOT exceed it. The phone ends the utterance when it reaches the limit.
- `null` for a required field is invalid. For the optional `pair_result.mac`, `null` is the same as absent.
- Senders MUST NOT emit duplicate keys. Receiver behaviour on duplicate keys is unspecified.
- Encodings are not canonical. The canonical form the Rust implementation emits is compact JSON with `"t"` first, then the fields in the order listed below, with UTF-8 left unescaped. That form is only informative; implementations need not match it byte-for-byte.

### 5.2 `hello` (plaintext, both directions)

| field | type | notes |
|---|---|---|
| `t` | `"hello"` | |
| `v` | integer | Protocol version, `1`. |
| `device_id` | UUID | Sender's random install id. Generated as a UUID v4 at install time. |
| `name` | string | Sender's display name, any UTF-8. |
| `pub` | base64, 32 bytes | Sender's long-term X25519 public key. |
| `paired` | bool | `true` iff the sender has a stored pairing for the receiver (see §7). |
| `session_nonce` | base64, 32 bytes | Fresh CSPRNG bytes for **this connection** (§6.4). It is always present, even when the peers are unpaired. |

Version handling: the receiver first reads `v`.
- If `v` is missing, or is not a non-negative integer, the message is `invalid_message`.
- If `v` is an integer ≠ 1, the message decodes as **hello-unsupported**. No other field is validated, but `name` is read if it is a string. The receiver replies `error{code:"version"}` and disconnects, and the UI shows "Update Ventriloquist on <name>".
- If `v == 1`, every field above is required.

```json
{"t":"hello","v":1,"device_id":"0f8fad5b-d9cb-469f-a165-70867728950e","name":"Jon's Mac","pub":"3p7bfXt9wbTTW2HC7OQ1Nz+DQ8hbeGdNrfx+FG+IK08=","paired":false,"session_nonce":"YGFiY2RlZmdoaWprbG1ub3BxcnN0dXZ3eHl6e3x9fn8="}
```

### 5.3 `pair_request` (plaintext, phone → desktop)
| field | type |
|---|---|
| `nonce_p` | base64, 32 bytes, fresh CSPRNG |
```json
{"t":"pair_request","nonce_p":"AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8="}
```

### 5.4 `pair_challenge` (plaintext, desktop → phone)
| field | type |
|---|---|
| `nonce_d` | base64, 32 bytes, fresh CSPRNG |
```json
{"t":"pair_challenge","nonce_d":"ICEiIyQlJicoKSorLC0uLzAxMjM0NTY3ODk6Ozw9Pj8="}
```
The 6-digit code is **never** sent over the wire.

### 5.5 `pair_confirm` (plaintext, phone → desktop)
| field | type |
|---|---|
| `mac` | base64, 32 bytes: `mac_p` (§6.3) |
```json
{"t":"pair_confirm","mac":"Phumo1O4q/HvpNg5M/8n0v54ViRwhs4du4Z6VC7AIWE="}
```

### 5.6 `pair_result` (plaintext, desktop → phone)
| field | type | notes |
|---|---|---|
| `ok` | bool | required |
| `mac` | base64, 32 bytes | `mac_d` (§6.3). Required when `ok` is `true`. MUST be omitted when `ok` is `false`; a receiver ignores it if present. |
```json
{"t":"pair_result","ok":true,"mac":"5FMswIQYMNbbKaEmKYn/wQlYV8oO7/6Vv82pPTN5bpg="}
{"t":"pair_result","ok":false}
```
`ok:true` without `mac` is `invalid_message`.

### 5.7 `error` (plaintext, either direction)
| field | type | notes |
|---|---|---|
| `code` | string | required. Open set: `unknown_peer`, `bad_mac`, `decrypt_failed`, `version`, … Receivers MUST accept unknown codes. |
| `msg` | string | human-readable; optional on receive, where it defaults to `""`; always emitted by Rust |
```json
{"t":"error","code":"version","msg":"Update Ventriloquist"}
```
After sending `error`, the sender disconnects.

### 5.8 `utt` (encrypted, phone → desktop)
| field | type | notes |
|---|---|---|
| `id` | UUID | utterance id |
| `rev` | integer, u32 (0 … 4294967295) | Revision. The desktop keeps the highest `rev` per `id`. |
| `state` | `"partial"` \| `"final"` \| `"edit"` | Exact lowercase. Any other value is invalid. |
| `text` | string | The full current text, not a diff. ≤ 32,000 UTF-8 bytes. |
| `ts` | integer, u64 | Start of the utterance, in milliseconds since the Unix epoch. |
```json
{"t":"utt","id":"3b241101-e2bb-4255-8caf-4136c566a962","rev":0,"state":"final","text":"kubectl get pods","ts":1759500000000}
```

### 5.9 `ack` (encrypted, desktop → phone)
| field | type |
|---|---|
| `id` | UUID |
| `rev` | u32 |
```json
{"t":"ack","id":"3b241101-e2bb-4255-8caf-4136c566a962","rev":0}
```

### 5.10 `ping` / `pong` (encrypted, both directions)
These have no fields: `{"t":"ping"}` and `{"t":"pong"}`. A `ping` is answered with a `pong`. Each side sends a `ping` every 15 s. If 3 in a row go unanswered, the peer is treated as disconnected.

## 6. Identity, pairing and session keys

### 6.1 Identity
- Long-term key: an X25519 key pair (RFC 7748).
  - The private key is the raw 32-byte scalar, clamped at use per RFC 7748. CryptoKit's `Curve25519.KeyAgreement.PrivateKey(rawRepresentation:)` accepts the same bytes.
  - The public key is the 32-byte u-coordinate.
- `device_id`: a random UUID v4, generated once per install.
- Shared secret: `ss = X25519(own_priv, peer_pub)`, 32 bytes. If `ss` is all zeros (the peer sent a low-order point), it MUST be rejected (`non_contributory`). Abort the pairing or session.

### 6.2 Pairing code
- `C` is a uniformly random integer in `[0, 999999]` from a CSPRNG. Use unbiased sampling, such as rejection sampling. Never use `random % 1_000_000` on a raw 32-bit value.
- Its wire and KDF form is exactly **6 ASCII digits, zero-padded**. For example, 42 becomes `"000042"`.
- Code entry accepts only the strings `[0-9]{6}`, i.e. ASCII digits only. The UI may display the code as `123 456`, but the space is never part of `C`.
- `C` expires 120 s after it is generated. After **3** failed `pair_confirm` verifications, `C` is invalidated.

### 6.3 Pairing key and MACs
```
salt_pair = nonce_p ‖ nonce_d                                    (64 bytes)
info_pair = "vq/pair/v1" ‖ C                                     (10 + 6 = 16 bytes)
            e.g. C = 123456 → 76712f706169722f7631 313233343536
K_pair    = HKDF-SHA256(IKM = ss, salt = salt_pair, info = info_pair, L = 32)

mac_p = HMAC-SHA256(key = K_pair, msg = "phone"   ‖ pub_p ‖ pub_d)   (5 + 32 + 32 = 69 bytes in)
mac_d = HMAC-SHA256(key = K_pair, msg = "desktop" ‖ pub_d ‖ pub_p)   (7 + 32 + 32 = 71 bytes in)
```
- `pub_p` and `pub_d` are the phone's and desktop's raw 32-byte public keys, as carried in their `hello.pub`.
- `"phone"` is `70686f6e65` and `"desktop"` is `6465736b746f70`.
- HKDF is RFC 5869: Extract with the salt, then Expand with the info to 32 bytes. With CryptoKit, use `HKDF<SHA256>.deriveKey(inputKeyMaterial: ss, salt: salt_pair, info: info_pair, outputByteCount: 32)`.
- MACs MUST be compared in constant time.

### 6.4 Session key
```
salt_sess = session_nonce_phone ‖ session_nonce_desktop          (64 bytes; from the two hellos)
info_sess = "vq/session/v1"                                       (7671 2f73 6573 7369 6f6e 2f76 31, 13 bytes)
K_sess    = HKDF-SHA256(IKM = ss, salt = salt_sess, info = info_sess, L = 32)
```
- The order is always **phone's nonce first**, whichever side sent `hello` first.
- Both counters reset to 0 for each new `K_sess`.
- Each side MUST generate a new `session_nonce` for every connection and MUST NOT reuse one.

## 7. Connection flow

```
desktop                                                    phone
   │ ── subscribe TX ─────────────────────────────────────▶ │
   │ ── hello{v,device_id,name,pub,paired,session_nonce} ─▶ │   (plaintext)
   │ ◀───────────────────────────────────────── hello{...} ─ │   (plaintext reply)
   │
   │  Known peer on both sides (stored device_id AND pub match) → derive K_sess → Secure
   │
   │  Otherwise, when the user taps this desktop on the phone:
   │ ◀────────────────────────────── pair_request{nonce_p} ─ │
   │   generate C, show it; ── pair_challenge{nonce_d} ───▶ │
   │                                              user types C
   │ ◀──────────────────────────────────── pair_confirm{mac_p} ─ │
   │   verify mac_p; on success store phone and
   │   ── pair_result{ok:true, mac:mac_d} ───────────────▶ │   verify mac_d, store desktop
   │   on failure ── pair_result{ok:false} ───────────────▶ │   (3rd failure invalidates C)
   │
   │  After a successful pair_result, both sides derive K_sess from the
   │  session_nonces of the hellos already exchanged on THIS connection → Secure
   │
   │ ◀════════════ encrypted utt / ping ═════════════════ │
   │ ═════════════ encrypted ack / pong ════════════════▶ │
```
Rules:
- **`hello` order.** The desktop sends `hello` immediately after subscribing. The phone replies with its own `hello` once it has received the desktop's. A desktop `hello` MAY be resent by the desktop; the receiver treats the newest one as current. Once a session is established on a connection, a new `hello` SHOULD be treated as a protocol error (send `error`, disconnect).
- **`paired` field.**
  - In the phone's reply, `paired` is authoritative for the phone: `true` iff the phone has the desktop's `device_id` **and** `pub` stored.
  - In the desktop's `hello`, `paired` is the desktop's best knowledge when it sends. It may be `false` because the desktop does not yet know the phone's identity.
  - Each side decides "known peer" from its **own** store (`device_id` and `pub` must both match) after it receives the other's `hello`. It does not rely on the `paired` flag.
- **Session established.** The session is established when each side has (a) both hellos and (b) the peer stored as paired. The side that becomes Secure derives `K_sess` (§6.4) and creates its cipher with counters at 0.
- **Phone says paired, desktop does not know it.** If the phone's `hello` says `paired:true` but the desktop does not know the phone, the desktop sends `error{code:"unknown_peer"}` and disconnects. The phone then shows the desktop as unpaired.
- **Desktop knows the phone, phone does not.** If the desktop knows the phone but the phone's `hello` says `paired:false`, the desktop waits for `pair_request`. A new pairing replaces the stored record.
- **Changed `pub`.** A peer whose `device_id` is known but whose `pub` differs is **not** known. It must re-pair.
- **Pairing outside its flow.** Pairing messages received out of order, or while Secure, are ignored. The application layer may send `error` instead.
- **Bad envelopes.** A `decrypt_failed` envelope MAY be answered with `error{code:"decrypt_failed"}` and a disconnect. A `replay` envelope is silently dropped.

## 8. Limits and constants

| name | value |
|---|---|
| protocol version (`hello.v`) | 1 |
| max reassembled message / envelope / JSON | 65,536 bytes |
| max `utt.text` | 32,000 UTF-8 bytes |
| min `mtu` | 20 |
| frame header | 3 bytes |
| nonce sizes (`nonce_p`, `nonce_d`, `session_nonce`) | 32 bytes |
| X25519 key, K_pair, K_sess, MAC | 32 bytes |
| encrypted envelope overhead | 25 bytes (so the max encrypted JSON is 65,511 bytes) |
| pairing code lifetime | 120 s |
| pairing failures before code invalidation | 3 |
| ping interval / missed pings before disconnect | 15 s / 3 |
| partial `utt` rate | ≤ 5 per second |
| `final`/`edit` retry | every 2 s, up to 5 times while connected |

## 9. Error codes

Implementations map their errors to these stable names. The vectors use them.

| code | layer | meaning |
|---|---|---|
| `mtu_too_small` | framing | splitter `mtu` < 20 |
| `frame_too_short` | framing | frame < 3 bytes |
| `reserved_flags` | framing | flags & 0xFC ≠ 0 |
| `orphan_frame` | framing | continuation frame with no partial buffer |
| `seq_mismatch` | framing | continuation frame `msg_seq` ≠ partial's |
| `message_too_large` | any | > 65,536 bytes (frame buffer, envelope, JSON, or JSON produced by an encoder) |
| `text_too_long` | message | `utt.text` > 32,000 UTF-8 bytes |
| `invalid_json` | message | not UTF-8 / not a single JSON value / BOM |
| `invalid_message` | message | not an object, bad/missing `t`, or bad/missing field of a known type |
| `not_encodable` | message (local) | tried to encode a receive-only variant |
| `empty_envelope` | envelope | 0 bytes |
| `unknown_envelope_kind` | envelope | first byte not 0x00/0x01 (also: plaintext given to a decrypt-only API) |
| `envelope_too_short` | envelope | encrypted envelope < 25 bytes |
| `decrypt_failed` | envelope | AEAD tag check failed |
| `replay` | envelope | counter ≤ last accepted |
| `counter_exhausted` | envelope (send) | counter 2^64−1 already used |
| `plaintext_not_allowed` | envelope | known non-allowed type in a plaintext envelope |
| `no_session` | envelope | encrypted envelope without `K_sess` |
| `non_contributory` | crypto | all-zero X25519 output |
| `invalid_code` | crypto | code is not exactly 6 ASCII digits |
| `bad_mac` | crypto | MAC verification failed |

## 10. Test vectors

The vectors live in `vectors/*.json`. Each file has a `description` and `"vectors_version": 1`. Common conventions:

- **Byte values** are lowercase hex strings. A large value may instead be an object `{"prefix_hex"?: hex, "fill_hex": "<1 byte>", "fill_count": n, "suffix_hex"?: hex}`, meaning prefix, then the fill byte repeated `n` times, then suffix.
- **u64 counters** are **decimal strings**, for example `"18446744073709551615"`. Other integers are JSON numbers.
- **Roles** are written `"phone"` / `"desktop"`. **Directions** are written `"phone_to_desktop"` / `"desktop_to_phone"`.
- **Expected errors** use the codes in §9.

| file | sections |
|---|---|
| `framing.json` | `split` (mtu, start seq, message → exact frames, next_seq), `split_large`, `split_errors`, `reassembly` (step-by-step: `pending` / `message` / `error`) |
| `envelope.json` | `plaintext`, `encrypt` (key, direction, counter, plaintext → nonce, aad, envelope), `open_errors`, `decode` (full plaintext-policy decode, with or without a session), `stack` (JSON → envelope → frames) |
| `replay.json` | `sequences` (ordered opens with the expected `last_accepted_after`), `send_sequences` (including counter exhaustion) |
| `crypto.json` | `x25519` (including RFC 7748 §6.1), `x25519_errors` (low-order points), `pair_key` (salt, info, K_pair), `session_key`, `pair_mac` (exact MAC inputs and outputs), `pair_mac_verify` (wrong code, role confusion, bit flip), `code_format`, `code_parse`, `full_pairing` (complete transcript from keys to the first encrypted utt/ack) |
| `messages.json` | `decode` (input as `json` / `json_hex` / `json_fill` → `message` + canonical `expected` object, `unknown`, `hello_unsupported`, or `error`), `encode` (canonical Rust encodings; informative), `encode_errors` |

In `messages.json`:
- `json_fill` is `{prefix, fill, count, suffix}`, where all four are UTF-8 strings and the input is `prefix + fill × count + suffix`.
- For a `message` result, compare the decoded fields with `expected`, which uses the encodings of this document: lowercase UUIDs, base64, and `mac` absent when `ok` is false.

The vectors are regenerated with `cargo run -p vq-protocol --example gen_vectors`, but the committed files are the authority. `cargo test -p vq-protocol` checks the Rust implementation against every one of them. The HKDF and HMAC vectors were also cross-checked with an independent Python `hashlib`/`hmac` implementation.
