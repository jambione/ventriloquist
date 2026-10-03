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
11. [Using `vq-protocol` (informative)](#11-using-vq-protocol-informative)

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
- **Integers in JSON.** Every integer field in v1 is unsigned (`v`, `rev`, `ts`). Its value MUST be a plain JSON integer literal: one or more ASCII digits, with no sign, no fraction and no exponent (so `-0`, `1.0`, `1e0` and `"1"` are all rejected). Leading zeros are already excluded by the JSON grammar. A literal outside the field's range is rejected too. Any of these makes the message `invalid_message`. A number that is not finite as a double is `invalid_json` instead (§5.1).

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

Senders MUST NOT use an `mtu` below 20. When the desktop cannot learn the negotiated ATT MTU, it MUST use `mtu = 20`.

### 2.1 TCP dev transport

For tests and the phone simulator, the same frames can travel over TCP instead of BLE:
- The **phone** side is the TCP **server**. Its default port is **47800**. The **desktop** side is the client.
- Each frame (§3) is sent as `length (u16 BE) ‖ frame`, where `length` is the frame's size in bytes. There is no other delimiting, padding or handshake.
- `mtu` is fixed at **512** in both directions.
- Everything above framing (envelopes, messages, pairing, sessions) is identical to BLE. Connecting is the equivalent of the desktop subscribing to `TX`, so the desktop sends `hello` as soon as the TCP connection is up. Closing the socket is a disconnect.

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

Any other first byte is rejected (`unknown_envelope_kind`). So is an empty envelope (`empty_envelope`), an encrypted envelope shorter than 25 bytes (`envelope_too_short`), and any envelope longer than 65,536 bytes (`message_too_large`). When several of these apply, §9.1 says which error wins.

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
- `last` is updated **as soon as** the tag verifies, before the JSON inside is decoded. An authentic envelope whose plaintext is then `invalid_json` or `invalid_message` still consumes its counter.

### 4.3 Plaintext policy
- A plaintext envelope MAY carry only: `hello`, `pair_request`, `pair_challenge`, `pair_confirm`, `pair_result`, `error`. This holds whether or not a session exists.
- A plaintext envelope carrying any other **known** type (`utt`, `ack`, `ping`, `pong`) MUST be rejected (`plaintext_not_allowed`). This is decided from `t` alone, after the JSON checks of §5.1 and before any other field is validated. For example, a plaintext `{"t":"utt","rev":-1}` is `plaintext_not_allowed`, not `invalid_message`.
- A plaintext envelope with an **unknown** `t` is treated like any unknown message (§5.1): log it and drop it. Do not treat it as fatal.
- An encrypted envelope may carry any type. An encrypted envelope received when no session key exists is rejected (`no_session`).
- Senders MUST encrypt every message outside the allowed list. Senders SHOULD send the allowed types in plaintext.
- **Provenance.** A message from a plaintext envelope is **unauthenticated**: anyone in radio range could have sent it. A message from an encrypted envelope that verified under `K_sess` is authenticated as coming from the paired peer. Receivers MUST keep track of which is which (the Rust API returns `Inbound::Plaintext` or `Inbound::Encrypted`). In particular, an unauthenticated `error` MUST NOT change stored pairing state (§7.4).

## 5. Messages (JSON)

### 5.1 General rules
- A message is a UTF-8 JSON **object** with a string member `"t"`.
- A message larger than **65,536 bytes** is rejected (`message_too_large`) before anything else is checked. This applies even when its type is unknown.

#### JSON strictness (normative)
A receiver MUST check the **whole document**, including members it will later ignore and the contents of unknown message types, and MUST reject it with **`invalid_json`** if any of the following holds:

1. **Encoding and grammar.** The input is not valid UTF-8 (overlong forms, encoded surrogates and code points above U+10FFFF are invalid), or is not exactly one JSON value as defined by RFC 8259 §2–§7, optionally surrounded by JSON whitespace. JSON whitespace is only space, tab, LF and CR, so a UTF-8 BOM (U+FEFF), NBSP and similar characters are rejected. Trailing bytes after the value are rejected. Inside strings, the characters U+0000–U+001F MUST be escaped, and the only escapes are `\" \\ \/ \b \f \n \r \t \uXXXX` (hex digits in either case).
2. **Depth.** Objects and arrays nest more than **32** levels. The outermost container is depth 1. So `{"t":"ping","x":[[…]]}` is allowed with up to 31 nested arrays inside `x`, and rejected with 32. Scalars do not count.
3. **Finite numbers.** A number token, converted to an IEEE 754 binary64 double with round-to-nearest-even, is infinite. This is the same as the decimal value having magnitude ≥ 2^1024 − 2^970. For example `1e309`, `-1e400` and `1.7976931348623159e308` are rejected, while `1.7976931348623157e308`, `1e-400` (which rounds to 0) and a 39-digit integer are accepted. The rule applies to every number, including integer fields: `"rev":1e400` is `invalid_json`, not `invalid_message`.
4. **Lone surrogates.** A `\u` escape of a high surrogate (`D800`–`DBFF`) is not immediately followed by a `\u` escape of a low surrogate (`DC00`–`DFFF`), or a low-surrogate escape appears without such a high surrogate directly before it. This applies to keys and values. A correctly paired `😀` is fine.
5. **Duplicate keys.** Any object, at any depth, has two members whose keys are equal after unescaping (so `"t"` and `"t"` are duplicates). Keys, and the `t` value, are compared as sequences of Unicode scalar values **without normalization**, so U+212A KELVIN SIGN ≠ `K` and precomposed `é` ≠ `e`+U+0301. Members of different objects may share keys.

These five checks all yield the same code, so their relative order is not observable. They come after the size check and before every message-level check (§9.1).

#### Message-level rules
- After the JSON checks, decoding fails with **`invalid_message`** when:
  - the value is not an object;
  - `t` is missing or is not a string;
  - a known `t` is missing a required field, or a field has the wrong type, the wrong range or an invalid encoding (including the integer rules of §1).
- Unknown members are **ignored**, in every message type (after passing the JSON checks above).
- An unknown `t` value is matched case-sensitively, so `"PING"` is unknown. The receiver logs it and drops it, never fatally.
- `utt.text` larger than **32,000 bytes**, measured in UTF-8 bytes **after** JSON unescaping, is rejected (`text_too_long`). This check comes after every field check (§9.1). Senders MUST NOT exceed it; see §5.8 for the sender's full size rule.
- **`null`.** `null` for a required field is invalid (`invalid_message`). For every optional field (`error.msg`, `pair_result.mac`), `null` is exactly the same as the member being absent.
- Senders MUST NOT emit duplicate keys (receivers reject them, see above).
- Encodings are not canonical. The canonical form the Rust implementation emits is compact JSON with `"t"` first, then the fields in the order listed below, with UTF-8 left unescaped and only the escapes JSON requires (`"`, `\`, and U+0000–U+001F, using the short forms `\b \t \n \f \r` where they exist and `\u00XX` otherwise). That form is only informative; implementations need not match it byte-for-byte, but see §5.8 for the size rule that depends on escaping.

### 5.2 `hello` (plaintext, both directions)

| field | type | notes |
|---|---|---|
| `t` | `"hello"` | |
| `v` | integer, u64 | Protocol version, `1`. |
| `device_id` | UUID | Sender's random install id. Generated as a UUID v4 at install time. |
| `name` | string | Sender's display name, any UTF-8. |
| `pub` | base64, 32 bytes | Sender's long-term X25519 public key. |
| `paired` | bool | `true` iff the sender has a stored pairing for the receiver (see §7). |
| `session_nonce` | base64, 32 bytes | Fresh CSPRNG bytes for **this connection** (§6.4). It is always present, even when the peers are unpaired. |

Version handling: the receiver first reads `v`.
- `v` MUST be a JSON integer literal in `0 … 2^64 − 1` under the rules of §1. If it is missing, `null`, any other type, `-0`, `1.0`, `1e0`, or `18446744073709551616` or larger, the message is `invalid_message`.
- If `v` is an integer ≠ 1, the message decodes as **hello-unsupported**. No other field is validated, but `name` is read if it is a string (otherwise it is treated as absent). The receiver replies `error{code:"version"}` and disconnects, and the UI shows "Update Ventriloquist on <name>".
- If `v == 1`, every field above is required.
- Senders always send `v: 1`. The Rust encoder refuses (`not_encodable`) to encode a `hello` with any other `v`.

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
| `mac` | base64, 32 bytes | `mac_d` (§6.3). Required when `ok` is `true` (`null` counts as absent, so `ok:true, mac:null` is invalid). MUST be omitted when `ok` is `false`. When `ok` is `false` a receiver ignores `mac` entirely: it is not validated, whatever its type or content. |
```json
{"t":"pair_result","ok":true,"mac":"5FMswIQYMNbbKaEmKYn/wQlYV8oO7/6Vv82pPTN5bpg="}
{"t":"pair_result","ok":false}
```
`ok:true` without `mac` is `invalid_message`.

### 5.7 `error` (plaintext, either direction)
| field | type | notes |
|---|---|---|
| `code` | string | required. Open set: `unknown_peer`, `bad_mac`, `decrypt_failed`, `version`, … Receivers MUST accept unknown codes. |
| `msg` | string | human-readable; optional on receive, where absent or `null` means `""`; always emitted by Rust |
```json
{"t":"error","code":"version","msg":"Update Ventriloquist"}
```
- Codes used in v1: `unknown_peer`, `bad_mac`, `decrypt_failed`, `version`, and `protocol` (a protocol violation such as a second `hello`, §7).
- After sending `error`, the sender disconnects.
- `msg` is for humans and MUST NOT be built from a local error's description text (in Rust, an `Error`'s `Display`). Such text is for local logs only. In Rust it never contains more than a 64-character excerpt of peer-supplied data.
- An `error` that arrives in a plaintext envelope is unauthenticated. The receiver may disconnect and show it, but MUST NOT change any stored pairing state because of it (§7.4).

### 5.8 `utt` (encrypted, phone → desktop)
| field | type | notes |
|---|---|---|
| `id` | UUID | utterance id |
| `rev` | integer, u32 (0 … 4294967295) | Revision. The desktop keeps the highest `rev` per `id`. |
| `state` | `"partial"` \| `"final"` \| `"edit"` | Exact lowercase. Any other value is invalid. |
| `text` | string | The full current text, not a diff. ≤ 32,000 UTF-8 bytes, and see the size rule below. |
| `ts` | integer, u64 | Start of the utterance, in milliseconds since the Unix epoch. |
```json
{"t":"utt","id":"3b241101-e2bb-4255-8caf-4136c566a962","rev":0,"state":"final","text":"kubectl get pods","ts":1759500000000}
```
- `text` is arbitrary Unicode and may contain control characters (including U+0000), bidi controls and so on. Receivers MUST render and log it inertly. The desktop never types it into other applications in v1.
- **Size rule (normative, for the sender).** A `utt` is always sent encrypted, so its JSON MUST fit in **65,511** bytes (§8). A text within 32,000 bytes can still escape past that (32,000 × U+0001 escapes to 192,000 bytes). The phone therefore ends the utterance as soon as **either** the text reaches 32,000 UTF-8 bytes **or** the encoded `utt` would exceed the limit. The test is defined independently of the other fields:

  ```
  escaped_len(text) = Σ over Unicode scalar values c of:
                        2  if c is " or \ or U+0008, U+0009, U+000A, U+000C, U+000D
                        6  if c is any other character in U+0000–U+001F
                        len_utf8(c) otherwise
  UTT_MAX_OVERHEAD = 126   (the worst-case utt with empty text: lowercase UUID,
                            rev 4294967295, state "partial", ts 18446744073709551615)
  fits(text)  ⇔  len_utf8(text) ≤ 32,000  and  126 + escaped_len(text) ≤ 65,511
  ```
  When `fits` fails, the phone sends the longest prefix of the text, cut at a Unicode scalar value boundary (not a grapheme boundary), for which `fits` holds, as the utterance's `final`, and ends the utterance. Encoders MUST NOT escape more than `escaped_len` assumes (for example, they MUST NOT escape `/` or non-ASCII characters), so that `fits(text)` guarantees the message can be sent. In Rust: `utt_text_fits(text)` and `max_text_prefix(text)`. The vectors are in `messages.json` → `utt_fits`.

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

### 5.11 Delivery rules (from SPEC §4.6)
These rules govern how the application layer uses `utt` and `ack`. They do not change any bytes, but both implementations MUST follow them.
- **Full text.** Every `utt` carries the full current text of the utterance, never a diff.
- **Highest `rev` wins.** The desktop keeps, per `id`, the entry with the highest `rev` seen so far. A `utt` whose `rev` is lower than or equal to the highest seen for its `id` is ignored (but still acked if it is a `final` or `edit`, see below).
- **Acks.** The desktop sends `ack{id, rev}` for every `final` and `edit` it receives, including duplicates and ignored lower revisions, so the phone can stop retrying. It never acks a `partial`.
- **Throttling.** Partials are sent at most **5 per second**, always carrying the latest text. The `final` is sent immediately when the user stops.
- **Retries.** The phone resends an unacked `final` or `edit` every **2 s**, up to **5** times while connected. When the desktop reconnects, all pending unacked `final`/`edit` messages are resent. Delivery is therefore at-least-once, and the receiver MUST be idempotent by (`id`, `rev`).
- **Edits.** `edit` replaces the text of an existing entry: same `id`, higher `rev`. If the desktop has never seen that `id`, it creates the entry.
- **Re-send from history** creates a **new** `id` with a single `final`.

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
- Each side MUST generate a new `session_nonce` from a CSPRNG for every connection and MUST NOT reuse one. A `K_sess` and its counters belong to exactly one connection: they MUST NOT be stored or reused after a disconnect, even with the same peer. (In Rust, `Hello::new` returns a non-clonable `SessionNonce` that `SessionCipher::establish` consumes, so this is enforced by the types.)

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

### 7.1 `hello`
- The desktop sends `hello` immediately after subscribing. The phone replies with its own `hello` once it has received the desktop's.
- **Exactly one `hello` in each direction per connection.** A second `hello` (plaintext or encrypted, any `v`) is a protocol error: the receiver sends `error{code:"protocol"}` and disconnects. Re-keying happens only by reconnecting.
- **`paired` field.** Each side sets `paired` to `true` iff its own store holds a pairing for the peer. The desktop sends first and does not yet know which phone it is talking to, so in practice the desktop sends `paired:false`; its `paired` is informational and the phone ignores it. The phone's `paired` matters, see §7.2.
- **Known peer.** A side *knows* the peer iff its own store holds a record whose `device_id` **and** `pub` both equal the peer's `hello`. A stored `device_id` with a different `pub` is **not** known: that peer must re-pair.

### 7.2 Deciding Secure or pairing (normative)
After both hellos are exchanged:

| desktop knows phone | phone's `hello.paired` | desktop does | phone does |
|---|---|---|---|
| yes | `true` | **Secure**: derive `K_sess` | **Secure** (it knows the desktop, which is why it sent `true`) |
| yes | `false` | stays in the **pairing** state: waits for `pair_request`. A successful re-pair replaces the stored record. | pairs when the user taps the desktop |
| no | `true` | sends `error{code:"unknown_peer"}` (plaintext), disconnects | was Secure, gets the error and the disconnect. Shows the desktop as "not recognised". It keeps its stored record (§7.4). To pair again the user removes the record ("Forget"), so the next connection sends `paired:false`. |
| no | `false` | **pairing** state: waits for `pair_request` | pairs when the user taps the desktop |

- **Desktop:** Secure **iff** its store knows the phone **and** the phone's `hello` says `paired:true`.
- **Phone:** Secure **iff** its store knows the desktop. The desktop's `paired` is ignored. (The phone sends `paired:true` exactly in this case, so the two sides agree.)
- On becoming Secure, each side derives `K_sess` from the two `session_nonce`s of **this** connection (§6.4) and starts both counters at 0. It never waits for any further message. The first encrypted message may come from either side.

### 7.3 Pairing (normative)
In the pairing state:
- **`pair_request`** (phone → desktop). The desktop generates a new code `C` and a fresh `nonce_d`, shows the code, resets the failure count to 0 and replies `pair_challenge{nonce_d}`. This happens whether or not a code was already active: a new `pair_request` invalidates any previous code.
- **`pair_confirm`** (phone → desktop). The desktop MUST answer **every** `pair_confirm` with a `pair_result`, never with silence:
  - If a code is active (generated less than 120 s ago and not invalidated) and `mac_p` verifies: store the phone (replacing any older record for its `device_id`), reply `pair_result{ok:true, mac:mac_d}`, become Secure.
  - Otherwise reply `pair_result{ok:false}`. This covers a wrong MAC, an expired code, a code invalidated by **3** failures, and a `pair_confirm` with no code ever generated on this connection. A wrong MAC with an active code increments the failure count. The third failure invalidates the code. All later `pair_confirm`s get `ok:false` until a new `pair_request` starts a new code.
- **`pair_result`** (desktop → phone).
  - `ok:true`: the phone verifies `mac_d`. On success it stores the desktop and becomes Secure. **On failure** (wrong `mac_d`) the phone sends `error{code:"bad_mac"}`, disconnects and stores nothing.
  - `ok:false`: the phone tells the user the code was wrong. It may let the user try again (another `pair_confirm` with the same nonces) or restart with a new `pair_request`.
- Pairing messages in the wrong direction (for example a `pair_request` received by the phone) are ignored.
- After a successful pairing on a connection, `K_sess` uses the `session_nonce`s of the hellos already exchanged on **that** connection.

### 7.4 Secure state
- Every message outside the plaintext-allowed list arrives encrypted; plaintext ones are `plaintext_not_allowed` (§4.3).
- **Any `hello` or pairing message** (`pair_request`, `pair_challenge`, `pair_confirm`, `pair_result`), plaintext or encrypted, is rejected with `not_allowed_in_session` (Rust: `check_in_session`). For a `hello` the receiver then sends `error{code:"protocol"}` and disconnects (§7.1). Pairing messages are dropped.
- **Unauthenticated `error`.** A plaintext `error` (whatever its `code`, including `unknown_peer`) MAY end the connection, but MUST NOT delete, replace or otherwise change the stored pairing record. Only a successful new pairing (§7.3) replaces a record, and only the user removes one.
- **Bad envelopes.** A `decrypt_failed` envelope MAY be answered with `error{code:"decrypt_failed"}` and a disconnect. A `replay` envelope is silently dropped.

## 8. Limits and constants

| name | value |
|---|---|
| protocol version (`hello.v`) | 1 |
| max reassembled message / envelope / JSON | 65,536 bytes |
| max `utt.text` | 32,000 UTF-8 bytes |
| min `mtu` (and desktop fallback when the ATT MTU is unknown) | 20 |
| TCP dev transport `mtu` / default port (phone = server) | 512 / 47800 |
| max JSON nesting depth (outermost container = 1) | 32 |
| `UTT_MAX_OVERHEAD` (worst-case `utt` with empty text, §5.8) | 126 bytes |
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
| `invalid_json` | message | any rule of §5.1 "JSON strictness": not UTF-8, not a single JSON value, BOM, depth > 32, non-finite number, lone surrogate, duplicate key |
| `invalid_message` | message | not an object, bad/missing `t`, or bad/missing field of a known type (including the integer rules of §1) |
| `not_encodable` | message (local) | tried to encode a receive-only variant |
| `empty_envelope` | envelope | 0 bytes |
| `unknown_envelope_kind` | envelope | first byte not 0x00/0x01 (also: plaintext given to a decrypt-only API) |
| `envelope_too_short` | envelope | encrypted envelope < 25 bytes |
| `decrypt_failed` | envelope | AEAD tag check failed |
| `replay` | envelope | counter ≤ last accepted |
| `counter_exhausted` | envelope (send) | counter 2^64−1 already used |
| `plaintext_not_allowed` | envelope | known non-allowed type in a plaintext envelope |
| `no_session` | envelope | encrypted envelope without `K_sess` |
| `not_allowed_in_session` | connection | `hello` or pairing message received while Secure (§7.4) |
| `non_contributory` | crypto | all-zero X25519 output |
| `invalid_code` | crypto | code is not exactly 6 ASCII digits |
| `bad_mac` | crypto | MAC verification failed |

### 9.1 Error precedence (normative)
When an input breaks several rules, the receiver reports the **first** matching error in this list. The vectors contain a case for each tie (names starting `tie:`).

Receiving (frames are covered by §3.2; this list starts from a reassembled envelope):
1. `message_too_large`: the envelope is longer than 65,536 bytes (whatever its kind).
2. `empty_envelope`.
3. `unknown_envelope_kind`: the first byte is not `0x00` or `0x01`.
4. `envelope_too_short`: kind `0x01` and fewer than 25 bytes.
5. `no_session`: kind `0x01` and no `K_sess`.
6. `replay`: counter ≤ `last` (checked before decrypting, so garbage ciphertext with an old counter is `replay`).
7. `decrypt_failed`. From here on, for kind `0x01`, `last` has already advanced (§4.2).
8. `message_too_large`: the JSON body is longer than 65,536 bytes. (Unreachable through an envelope; it applies when JSON is decoded directly.)
9. `invalid_json`: any rule of §5.1 "JSON strictness", over the whole document.
10. `invalid_message`: not an object; `t` missing or not a string.
11. `plaintext_not_allowed`: plaintext envelope with a known non-allowed `t`.
12. For `hello`: `invalid_message` if `v` breaks §5.2, else **hello-unsupported** if `v ≠ 1` (no further checks).
13. `invalid_message`: a missing, ill-typed, out-of-range or badly encoded field. All field errors share this code, so their order does not matter.
14. `text_too_long`.
15. Only in the Secure state, on a message that decoded successfully: `not_allowed_in_session`.

Sending (Rust):
- `encode_plaintext`: `plaintext_not_allowed`, then the `to_json` errors, then `message_too_large` for the envelope.
- `to_json`: `not_encodable` (receive-only variant, `hello.v ≠ 1`, `pair_result` with `ok` and `mac` inconsistent), then `text_too_long`, then `message_too_large`.
- `seal_message`: the `to_json` errors, then `counter_exhausted`, then `message_too_large` for the envelope (JSON > 65,511 bytes).

## 10. Test vectors

The vectors live in `vectors/*.json`. Each file is one JSON object with a `description` string, `"vectors_version": 1` and the sections below. An implementation passes when it reproduces every value in every section.

### 10.1 Common conventions
- **Bytes** are lowercase hex strings. A large value may instead be an object `{"prefix_hex"?: hex, "fill_hex": "<1 byte>", "fill_count": n, "suffix_hex"?: hex}`, meaning prefix, then the fill byte repeated `n` times, then suffix. Missing prefix or suffix means empty. Any field documented as "bytes" below may use either form.
- **u64 counters** are **decimal strings**, for example `"18446744073709551615"`, so they survive parsers that read numbers as doubles. Other integers are JSON numbers that fit their documented type exactly.
- **Roles** are `"phone"` / `"desktop"`. **Directions** are `"phone_to_desktop"` / `"desktop_to_phone"`. A receiver of role R decrypts the direction R does *not* send.
- **Errors** use the codes in §9.
- **`name`** is a human-readable label, unique within its section. Names starting `tie:` exercise §9.1.

### 10.2 `framing.json`
| section | fields | check |
|---|---|---|
| `split` | `name`, `mtu`, `seq` (u16, the splitter's next `msg_seq`), `message` (bytes), `frames` (array of bytes), `next_seq` | splitting `message` at `mtu` starting at `seq` gives exactly `frames`; the splitter's next `msg_seq` is then `next_seq`; the frames reassemble to `message` |
| `split_large` | `name`, `mtu`, `seq`, `message` (bytes, fill form), `frame_count`, `first_frame_header` (hex, 3 bytes), `last_frame_header`, `last_frame_len` | as `split`, comparing only the frame count, the first and last headers and the last frame's length |
| `split_errors` | `name`, `mtu`, `message` (bytes), `error` | splitting fails with `error`; a fresh splitter's `msg_seq` stays 0 |
| `reassembly` | `name`, `steps`: array of `{frame` (bytes), `result` (`pending` / `message` / `error`), `message`? (bytes, when `message`), `error`? (when `error`)`}` | feed `steps[].frame` in order to ONE fresh reassembler; each push gives the stated result |

### 10.3 `envelope.json`
| section | fields | check |
|---|---|---|
| `plaintext` | `name`, `json_utf8`, `envelope` | `envelope` = `00 ‖ json_utf8`; decoding it gives the message `json_utf8` decodes to |
| `encrypt` | `name`, `key`, `direction`, `counter` (u64 string), `plaintext` (bytes), `nonce` (12 bytes), `aad` (always `"01"`), `envelope` | the AEAD nonce is `nonce`; sealing gives `envelope`; a fresh receiver opens it back to `plaintext` and its `last` becomes `counter` |
| `open_errors` | `name`, `key`, `receiver_role`, `envelope`, `error` (code or `null`), `plaintext`? (when `error` is `null`) | a FRESH receiver opening `envelope` fails with `error` and keeps `last` = none (or succeeds with `plaintext`) |
| `decode` | `name`, `envelope` (bytes), `session` (`null` = no session, or `{key, role, prior}` where `prior` is an array of envelopes the receiver opens successfully first), `result`, plus per result: `message` → `type`, `authenticated`, `expected`; `unknown` → `type`, `authenticated`; `hello_unsupported` → `type` (`"hello"`), `authenticated`, `v`, `peer_name` (string or `null`); `error` → `error`. When `session` is not null: `last_accepted_after` (u64 string or `null`) | full receive path (§4, §5, §9.1): parse, policy, decrypt, decode. `authenticated` is `true` iff the envelope was encrypted. `expected` is compared as in `messages.json`. `last_accepted_after` is the receiver's `last` after the decode, whatever the result |
| `in_session` | `name`, `envelope`, `session` (as in `decode`), `result` (`ok` / `error`), `type` + `authenticated` (when `ok`), `error` (when `error`) | decode as in `decode`, then apply the Secure-state policy (§7.4); `ok` means both passed |
| `stack` | `name`, `key`, `sender_role`, `counter` (u64 string), `seq`, `mtu`, `plaintext_utf8`, `envelope`, `frames` | a sender at `counter` seals `plaintext_utf8` into `envelope`, which splits (at `seq`, `mtu`) into `frames`; a fresh receiver reassembles, decrypts and decodes it |

### 10.4 `replay.json`
| section | fields | check |
|---|---|---|
| `sequences` | `name`, `key`, `receiver_role`, `steps`: array of `{envelope, result` (`ok` / `error`), `plaintext`? (bytes, when `ok`), `error`?, `last_accepted_after` (u64 string or `null`)`}` | ONE receiver opens the steps in order; each step gives its result and leaves `last` = `last_accepted_after` |
| `send_sequences` | `name`, `key`, `sender_role`, `start_counter` (u64 string), `sends`: array of `{plaintext` (bytes), `result` (`ok` / `error`), `envelope`? (when `ok`), `error`?`}` | ONE sender whose next counter is `start_counter` seals the plaintexts in order |

### 10.5 `crypto.json`
| section | fields | check |
|---|---|---|
| `x25519` | `name`, `priv_a`, `pub_a`, `priv_b`, `pub_b`, `shared` | each public key derives from its private key; X25519 in both directions gives `shared` |
| `x25519_errors` | `name`, `priv`, `peer_pub`, `error` (`non_contributory`) | X25519 with a low-order or equivalent point is rejected, including variants with bit 255 set |
| `x25519_high_bit` | `name`, `priv`, `peer_pub` (bit 255 set), `peer_pub_masked` (bit 255 clear), `shared` | RFC 7748 masks bit 255 of a received u-coordinate: both public keys give `shared` |
| `pair_key` | `name`, `shared`, `nonce_p`, `nonce_d`, `code` (6 digits), `salt` (64 bytes), `info` (16 bytes), `info_ascii`, `length` (32), `k_pair` | `salt` = `nonce_p ‖ nonce_d`; `info` = `"vq/pair/v1" ‖ code`; HKDF gives `k_pair` |
| `session_key` | `name`, `shared`, `nonce_phone`, `nonce_desktop`, `salt`, `info`, `info_ascii`, `length`, `k_sess` | `salt` = `nonce_phone ‖ nonce_desktop`; HKDF with `"vq/session/v1"` gives `k_sess` |
| `pair_mac` | `name`, `k_pair`, `pub_phone`, `pub_desktop`, `phone_mac_input`, `phone_mac`, `desktop_mac_input`, `desktop_mac` | the MAC inputs are exactly `"phone" ‖ pub_phone ‖ pub_desktop` and `"desktop" ‖ pub_desktop ‖ pub_phone`; HMAC gives the MACs |
| `pair_mac_verify` | `name`, `k_pair`, `pub_phone`, `pub_desktop`, `kind` (`phone` = verify as `mac_p`, `desktop` = verify as `mac_d`), `mac`, `valid` | verification succeeds iff `valid`; failures are `bad_mac` |
| `code_format` | `value`, `string` | the code `value` is written as `string` |
| `code_parse` | `input`, `valid`, `value`? (when valid) | parsing `input` gives `value`, or fails with `invalid_code` |
| `full_pairing` | `name`; `phone_priv`, `phone_pub`, `phone_device_id`, `desktop_priv`, `desktop_pub`, `desktop_device_id`; `shared`; `nonce_p`, `nonce_d`, `code`, `k_pair`, `phone_mac`, `desktop_mac`; `session_nonce_phone`, `session_nonce_desktop`, `k_sess`; `transcript`: array of `{from` (role), `json_utf8`, `envelope}` in order (desktop hello, phone hello, pair_request, pair_challenge, pair_confirm, pair_result); `first_utt_plaintext_utf8`, `first_utt_envelope` (phone, counter 0), `first_ack_plaintext_utf8`, `first_ack_envelope` (desktop, counter 0) | every value follows from the private keys, the transcript and the code; both sides' derived pairing key, MACs and session ciphers reproduce the envelopes |

### 10.6 `messages.json`
| section | fields | check |
|---|---|---|
| `decode` | `name`; the input as exactly one of `json` (UTF-8 text), `json_hex` (raw bytes, hex) or `json_fill` (`{prefix, fill, count, suffix}`, all UTF-8 strings: the input is `prefix + fill × count + suffix`); `result`; per result: `message` → `type` plus either `expected` or (`text_bytes` and `expected_without_text`); `unknown` → `type`; `hello_unsupported` → `v`, `peer_name` (string or `null`); `error` → `error` | decode the input (no envelope). For `expected`: re-encode the decoded message and compare it **as a JSON object** with `expected` (lowercase UUIDs, base64, `mac` absent when `ok` is `false`, `msg` present); `expected` must also decode to the same message. For a large `utt`, `text_bytes` is the decoded text's UTF-8 length and `expected_without_text` is `expected` without its `text` member |
| `encode` | `type`, `json`, `object` | informative: the Rust encoder emits exactly `json`. Other implementations only need to emit JSON equal to `object` |
| `encode_errors` | `name`, `message` (the message in wire form, as a JSON object), `text_fill`? (`{fill, count}`: `utt.text` is `fill × count`), `error` | encoding the message fails with `error` (§9.1, sending) |
| `utt_max_overhead_bytes` | number | equals `UTT_MAX_OVERHEAD` (§5.8) |
| `utt_fits` | `name`, `text_fill` (`{fill, count}`), `fits` (bool), `max_prefix_bytes` | for text = `fill × count`: `fits(text)` (§5.8) equals `fits`, and the longest fitting prefix is `max_prefix_bytes` UTF-8 bytes long |

The vectors are regenerated with `cargo run -p vq-protocol --example gen_vectors`. Generation is deterministic, but the committed files are the authority. `cargo test -p vq-protocol` checks the Rust implementation against every one of them. The HKDF and HMAC vectors were also cross-checked with an independent Python `hashlib`/`hmac` implementation.

## 11. Using `vq-protocol` (informative)

This section describes the intended use of the Rust API. The desktop core (M3) uses it as is, and the Swift port (M2) should mirror its shape.

**Per connection:**
1. Create one `FrameSplitter` and one `Reassembler` per direction. Drop them on disconnect.
2. Build our `hello` with `Hello::new(device_id, name, identity.public_bytes(), paired)`. It returns the `Hello` and a `SessionNonce` drawn from the OS CSPRNG. Keep the `SessionNonce` for this connection only. It is neither `Clone` nor `Copy`.
3. Decode every reassembled envelope with `decode_inbound(bytes, session.as_mut())`. It returns `Inbound::Plaintext(msg)` (unauthenticated) or `Inbound::Encrypted(msg)` (authenticated). Never act on a plaintext message as if it were authenticated. In particular, an unauthenticated `error` never changes the pairing store.
4. Pair with `PairKey::derive(&identity, own_role, &peer_pub, &pair_request, &pair_challenge, &code)` on both sides. The phone sends `key.confirm_message()` and checks the reply with `key.verify_desktop_mac(..)`. The desktop checks with `key.verify_phone_mac(..)` and replies with `key.success_message()`. `PairKey` hides `K_pair` and fixes the order of the public keys and nonces from the roles, so they cannot be swapped by mistake.
5. When §7.2 says Secure, call `SessionCipher::establish(&identity, own_role, &peer_pub, own_session_nonce, &peer_hello.session_nonce)`. It consumes the `SessionNonce`, derives `K_sess` internally (it is never exposed) and starts both counters at 0. Send with `seal_message`. Never keep a `SessionCipher` across connections; a new connection needs a new nonce exchange.
6. While Secure, pass every decoded `Inbound` to `check_in_session`. On `not_allowed_in_session` for a `hello`, send `error{code:"protocol"}` and disconnect; for pairing messages, drop them.
7. On the phone, before sending each `utt`, check `utt_text_fits(text)`. When it fails, send `max_text_prefix(text)` as the `final` and end the utterance (§5.8).
8. Log `Error` values locally. Never copy their `Display` text into an outgoing `error.msg`.

**Test hooks.** `SessionCipher::new` (raw key), `SessionCipher::with_send_counter` (which can only move a counter forward), `seal_with`, `open_with`, `nonce`, `decode_envelope` (no provenance), `derive_pair_key`, `derive_session_key`, the raw-key MAC helpers, `SharedSecret::{from_bytes, as_bytes}`, `SessionNonce::from_bytes_for_tests` and `PairKey::key_bytes_for_tests` exist only with the `test-vectors` cargo feature. The crate enables that feature for its own tests and examples through a self dev-dependency. Production code MUST NOT enable it.
