# Spec questions and decisions

This file records the places where `SPEC.md` was ambiguous or silent and a builder had to choose. Each entry is a decision that has already been made and implemented. The owner may overturn any of them, and changing one is a protocol change: update `protocol/README.md`, the vectors, Rust and Swift together.

## M1 — `vq-protocol`

### Q1. Field names and encodings of the hello and pairing messages
SPEC §4.4/§4.5 lists the hello fields loosely (`device_id, name, pub, paired`), plus a `session_nonce` mentioned only in §4.5. It does not name the version field placement or say how any field is encoded.

**Decision.** `hello` is `{t, v, device_id, name, pub, paired, session_nonce}`.
- `session_nonce` is **always** present, including for unpaired peers. The session key after a fresh pairing uses the hellos' nonces from the same connection.
- The pairing messages are `pair_request{nonce_p}`, `pair_challenge{nonce_d}`, `pair_confirm{mac}`, `pair_result{ok, mac?}` and `error{code, msg}`.

### Q2. Binary and UUID encodings
**Decision.**
- Binary fields use standard, padded base64 with strict decoding, and must decode to exactly 32 bytes.
- `device_id` and `utt.id` are hyphenated UUID strings. Senders emit lowercase; receivers accept either case. All other UUID forms are rejected.
- `device_id` is a UUID v4, which has 122 random bits. The spec says "random 128-bit". The v4 form is used because it maps directly onto Swift's `UUID`.

### Q3. `hello.paired` semantics and when a session starts
The desktop sends `hello` first, before it knows which phone it is talking to, so it cannot know `paired` reliably. The first version of this decision also said the desktop "waits for `pair_request`" in a case where the phone considered itself paired, which could deadlock.

**Decision (revised in the M1 fix pass).** Each side decides "known peer" from its own store, and both the `device_id` and the `pub` must match. Then (README §7.2):
- **Desktop is Secure iff** it knows the phone **and** the phone's `hello` says `paired:true`.
- **Phone is Secure iff** it knows the desktop. The desktop's `paired` is ignored. The phone sends `paired:true` exactly when it knows the desktop.
- The phone says `paired:true` but the desktop does not know it: the desktop sends `error{unknown_peer}` and disconnects. Because that `error` is unauthenticated, the phone keeps its stored record; the user removes it ("Forget") to pair again.
- The desktop knows the phone but the phone says `paired:false`: the desktop stays in the pairing state and accepts `pair_request`. A successful re-pair replaces the stored record.

### Q4. Version mismatch decoding
**Decision.** `v` is a JSON integer literal in `0 … 2^64 − 1` (no sign, fraction or exponent, so `-0`, `1.0` and `1e0` are rejected). A `hello` whose `v` is such an integer other than 1 decodes to a distinct `HelloUnsupported{v, name?}` result. It is not rejected as an invalid message. This lets the receiver send `error{code:"version"}` and show "Update Ventriloquist on <name>" even if a future version changes the other hello fields. If `v` is missing, `null`, not an integer, or ≥ 2^64, the hello is `invalid_message`. A non-finite number such as `1e400` is `invalid_json` (Q13). Senders always send `v: 1`; the Rust encoder refuses any other value.

### Q5. Pairing key length and code encoding
**Decision.**
- `K_pair` is 32 bytes. SPEC gives no length for it, only for `K_sess`.
- `C` in the HKDF info is exactly the 6 zero-padded ASCII digits, with no separator.
- The salts are the raw 32-byte nonces, concatenated in the order phone then desktop.

### Q6. All-zero X25519 output
**Decision.** An all-zero shared secret from a low-order peer key is rejected (`non_contributory`). The spec did not mention this case.

### Q7. Framing details beyond §4.2
**Decision.**
- `msg_seq` starts at 0 per direction per connection.
- A frame shorter than 3 bytes, or with any reserved flag bit set, is dropped **and discards the partial buffer**. The spec did not say.
- A continuation frame with no partial buffer is dropped (`orphan_frame`).
- A FIRST frame resets the buffer even when its `msg_seq` is the same.
- The receiver does not check that `msg_seq` increments between messages. It also does not enforce the MTU on received frames.
- "Exceeding 64 KiB" means strictly more than 65,536 bytes.
- An empty message is framed as a single `0x03` frame. This never occurs in practice.

### Q8. Where the 64 KiB limit applies, and how big an utterance may get
**Decision.** The limit of 65,536 bytes applies at three points:
- the reassembly buffer, which equals the envelope;
- envelope parsing;
- JSON decode and encode.

As a result, the largest JSON body that can be sent encrypted is 65,511 bytes. The 32,000-byte `text` limit counts UTF-8 bytes after JSON unescaping. A text within that limit can still escape past 64 KiB (32,000 control characters escape to 192,000 bytes), and then the encoder fails with `message_too_large`.

**Sender rule (ruling R2).** The phone ends the utterance when **either** the text reaches 32,000 bytes **or** the encoded `utt` would exceed the limit. "Would exceed" is defined independently of the other fields: `fits(text) ⇔ len_utf8(text) ≤ 32,000 and 126 + escaped_len(text) ≤ 65,511`, where 126 is the worst-case `utt` with empty text and `escaped_len` counts 2 bytes for `"`, `\` and the five short control escapes, 6 for other U+0000–U+001F, and the UTF-8 length otherwise (README §5.8). When the text stops fitting, the phone sends the longest fitting prefix as the `final`. Encoders must not escape more than that (for example not `/`). Rust exposes `utt_text_fits` and `max_text_prefix`.

### Q9. Plaintext-policy edge cases
**Decision.**
- A plaintext envelope with an **unknown** `t` is passed up as `Unknown` and dropped, consistent with §4.1 ("never fatal"). It is not rejected as `plaintext_not_allowed`.
- Plaintext-allowed types may also be sent encrypted, and decode that way. While Secure, though, any `hello` or pairing message is refused by the Secure-state policy (Q14), whatever its provenance; an encrypted `error` is fine.
- A plaintext `utt`, `ack`, `ping` or `pong` is rejected whether or not a session exists.

### Q10. Replay window details
**Decision.**
- The receiver accepts any counter strictly greater than the last accepted one, so gaps are fine and the first accepted counter need not be 0.
- The window advances only after successful authentication, and it advances as soon as the tag verifies, even if the JSON inside then fails to decode.
- After the sender uses counter 2^64−1, it refuses to send again (`counter_exhausted`). Re-establishing the session is required.

### Q11. `pair_result` with `ok:false`, and pairing failures on the wire
**Decision.**
- When `ok` is false, `mac` is omitted. Receivers ignore `mac` entirely when `ok` is false: it is not validated, whatever its type or content. `null` counts as absent.
- `ok:true` without `mac` (or with `mac:null`) is invalid.
- No "attempts remaining" field was added. The spec does not have one.
- **Every `pair_confirm` gets a `pair_result`, never silence.** If no code is active (expired after 120 s, invalidated after 3 failures, or never generated) or the MAC is wrong, the reply is `pair_result{ok:false}`. After the code is invalidated, all further `pair_confirm`s get `ok:false`.
- **`pair_request` always starts a new code**: new `C`, new `nonce_d`, failure count reset. This includes the case where a code is still active, which is then invalidated. The desktop shows the new code.
- **`mac_d` failure.** If the phone gets `pair_result{ok:true}` whose `mac` does not verify, it sends `error{code:"bad_mac"}`, disconnects and stores nothing.

### Q12. `null` for optional fields; `error.msg`
**Decision.** For every optional field (`error.msg`, `pair_result.mac`), `null` is exactly the same as absent. `msg` therefore defaults to `""` when absent or `null`. It is always emitted. `msg` must never be built from a local error's `Display` text; Rust's error text is for logs and contains at most a 64-character excerpt of peer data.

### Q13. JSON strictness (ruling R1)
SPEC says "UTF-8 JSON" and nothing more. Library parsers differ on depth limits, huge numbers, lone surrogates and duplicate keys, and a duplicate `"t"` could change dispatch.

**Decision.** Implementations use their own strict, bounded reader (Rust: `src/json.rs`), so the boundary is defined by README §5.1 and not by any library. Over the **whole document**, including ignored members and unknown types, each of these is `invalid_json`:
- not valid UTF-8, not exactly one RFC 8259 value with only space/tab/LF/CR around it (a UTF-8 BOM is rejected);
- nesting deeper than **32** (objects and arrays; the outermost container is depth 1);
- a number that is infinite as an IEEE 754 double after round-to-nearest-even (`1e400`, `1e309`), anywhere, including integer fields;
- a lone surrogate `\u` escape in any key or string;
- duplicate keys, compared after unescaping, in any object at any depth.

Then, for integer fields only: a plain integer literal in range (no `-0`, fraction or exponent), otherwise `invalid_message`. Other corner cases:
- `null` for a required field is invalid.
- `ts` is the full u64 range. A vector uses `18446744073709551615`, so Swift must decode `UInt64` exactly and not via `Double`.

### Q14. Exactly one `hello` per connection; behaviour while Secure
**Decision (now normative).** Each side sends exactly one `hello` per connection. A second `hello`, plaintext or encrypted, any `v`, is a protocol error: the receiver sends `error{code:"protocol"}` and disconnects. The earlier allowance for the desktop to resend `hello` was removed. While Secure, any pairing message is dropped. Rust reports both cases from `check_in_session` as `not_allowed_in_session` (a new error code). Session re-keying happens only by reconnecting.

### Q15. GATT UUIDs
**Decision.** These random v4 UUIDs were generated once:

| | UUID |
|---|---|
| Service | `77608b26-7b68-49da-bb34-7f05d158e219` |
| RX | `18489603-21ac-4cf2-9d31-62bd5d9c1635` |
| TX | `b01127eb-8819-42a7-a0e8-bdd6159d4e2a` |

### Q16. Error precedence
SPEC does not say which error wins when an input breaks several rules, but the vectors need a single answer.

**Decision.** README §9.1 fixes the order: envelope size → empty → kind → length → no session → replay → decrypt → JSON size → JSON strictness → object/`t` shape → plaintext policy → `hello.v` → fields → text length → (Secure only) `not_allowed_in_session`. The plaintext policy is decided from `t` before other fields are validated, so a plaintext `{"t":"utt","rev":-1}` is `plaintext_not_allowed`. Each tie has a `tie:` vector.

### Q17. TCP dev transport and the BLE MTU fallback
SPEC mentions a TCP mode for tests but does not define it.

**Decision.** The phone side is the TCP server, default port 47800; the desktop is the client. Each frame is sent as `u16 BE length ‖ frame`, and `mtu` is fixed at 512. On BLE the desktop uses `mtu` = negotiated ATT MTU − 3, or 20 when it cannot learn the MTU.

### Q18. Provenance and unauthenticated `error`
A plaintext `error{unknown_peer}` can be injected by anyone in radio range, even mid-session.

**Decision.** Decoding reports provenance (Rust: `Inbound::Plaintext` / `Inbound::Encrypted` from `decode_inbound`). An unauthenticated `error` may end the connection but never changes stored pairing state. Only a successful pairing replaces a record, and only the user removes one.

### Q19. API hardening (implementation, mirrored in Swift)
**Decision.** The production API never exposes raw keys:
- `Hello::new` draws the `session_nonce` and returns a non-clonable `SessionNonce`.
- `SessionCipher::establish` consumes that nonce, derives `K_sess` internally and orders the nonces by role.
- `PairKey::derive` takes the caller's role and the typed `pair_request`/`pair_challenge`, so public keys and nonces cannot be swapped.

Raw-key helpers (`SessionCipher::new`, `with_send_counter`, `seal_with`, `open_with`, `derive_*`, raw MAC functions, `decode_envelope`) exist only behind the `test-vectors` cargo feature. `with_send_counter` can only move a counter forward. HKDF is computed directly on HMAC so that PRK and OKM live only in zeroizing buffers.

### Q20. Acks for duplicates
SPEC says the desktop acks `final` and `edit`, and the phone retries until acked.

**Decision.** The desktop acks every `final` and `edit` it receives, including duplicates and revisions lower than or equal to the highest it has seen (which it otherwise ignores). Otherwise a lost `ack` would make the phone retry five times for nothing. Partials are never acked.

## M2 (Swift) — `ios/VQProtocol`

### Q21. "Equal" strings are byte-equal, never Unicode-equivalent
README §5.1 says duplicate keys are "equal after unescaping" and §5.1 matches `t` "case-sensitively", but does not say whether equality is by code points or by Unicode canonical equivalence. Swift's `String ==` uses canonical equivalence, so `"K"` (U+212A KELVIN SIGN) equals `"K"`, and precomposed `"é"` equals `"é"`. A Swift port that compared keys or `t` with `String ==` would reject `{"K":1,"K":2}` as a duplicate where Rust accepts it.

**Decision.** Everywhere the wire compares strings (duplicate keys, `t` dispatch, `state`, message equality in tests), the Swift package compares the unescaped **UTF-8 bytes** (equivalently, Unicode scalar sequences), exactly like Rust. No normalization is ever applied. The strict reader stores strings as `[UInt8]`; `Message`'s `Equatable` compares strings byte-wise. Suggested README wording for §5.1: "compared as sequences of Unicode scalar values, without normalization".

### Q22. "Character" in §5.8 means Unicode scalar value
README §5.8 defines `escaped_len` "over characters" and cuts `max_text_prefix` "at a character boundary". In Rust a `char` is a Unicode scalar value; in Swift a `Character` is a grapheme cluster.

**Decision.** Swift's `escapedLength`, `uttTextFits` and `maxTextPrefix` iterate `unicodeScalars` and cut at scalar boundaries, matching Rust. A cut can therefore separate a combining mark or emoji modifier from its base; that is accepted (the result is still valid UTF-8 and always fits). Suggested README wording: "Unicode scalar value" instead of "character".

### Q23. Swift API shape (mirrors README §11)
- **`Hello.new(deviceId:name:publicKey:paired:)`** returns `OwnHello: ~Copyable` holding `hello` and the non-copyable `SessionNonce`. Swift does not allow tuples with non-copyable elements, and a client module cannot partially consume a non-frozen struct, so the nonce is moved out with the consuming `OwnHello.takeNonce()`. `SessionCipher.establish(identity:role:peerPublic:ownNonce:peerNonce:)` takes the nonce `consuming`; reusing a nonce is a compile error (verified: "'n' consumed more than once").
- **`SessionCipher`** is a `final class` (one shared counter state; cannot be copied or rewound). It is deliberately not `Sendable`: confine it to one actor per connection. `K_sess` is a CryptoKit `SymmetricKey` and is never exposed.
- **`PairKey`** hides `K_pair`; argument order is derived from `ownRole` and the typed `PairRequest`/`PairChallenge`, as in Rust.
- **Errors** are `VQError` with `code` equal to the Rust codes (README §9). Its `description` contains at most a 64-scalar excerpt of peer data and must not be used for `error.msg`.
- **Fixed-size binary fields** are `Bytes32` (failable init from exactly 32 bytes). `IdentityKeyPair(secretBytes:)` is failable (`nil` unless 32 bytes) instead of Rust's typed array.
- **Test hooks** (raw-key `SessionCipher(rawKeyForTests:role:)`, `advanceSendCounterForTests(to:)` which can only move forward, `sealForTests`, `nonceForTests`, `decodeEnvelopeForTests`, `derivePairKeyForTests`, `deriveSessionKeyForTests`, the raw MAC helpers, `SharedSecret(bytesForTests:)`, `SessionNonce(bytesForTests:)`, `PairKey.keyBytesForTests`) are `internal` and reachable only through `@testable import`, the Swift equivalent of the Rust `test-vectors` feature. Production clients (the app, `PhoneSim`) cannot call them.
- HKDF uses CryptoKit's `HKDF<SHA256>.deriveKey` (README §6.3); MAC checks use `HMAC<SHA256>.isValidAuthenticationCode` (constant time).

### Q24. CryptoKit vs x25519-dalek on low-order points
CryptoKit's `sharedSecretFromKeyAgreement` **throws** (CoreCrypto error -7) for every low-order or non-canonical-zero peer key in `crypto.json → x25519_errors`, including the variants with bit 255 set, instead of returning an all-zero secret as dalek does. **Decision.** Any throw from key agreement, or an all-zero result, maps to `non_contributory`. Both behaviours give the same vector outcome. Bit 255 of a received u-coordinate is masked by CryptoKit exactly as RFC 7748 requires (`x25519_high_bit` passes).

### Q25. Vector loading in Swift
`messages.json` carries `"v": 18446744073709551615` as a JSON **number** (`hello_unsupported`), which `JSONSerialization` would read through `Double` and corrupt. README §10.1 says u64 *counters* are strings but other integers are numbers "that fit their documented type exactly", so this is consistent with the README, but a loader must read numbers exactly. **Decision.** The Swift tests read the vector files with their own small JSON tree parser that keeps numbers as source text. No change to the vectors is needed.

## M3 (desktop core) — `vq-host-core`

These are numbered D1… so they cannot collide with the M2 entries being written at the same time.

### D1. Log dedupe across restarts: sidecar index
The SPEC §6.2 log line carries only an 8-digit id prefix and no revision, so the Markdown file alone cannot identify (`id`, `rev`). **Decision.** Each day file `YYYY-MM-DD.md` has a sidecar index `<log_dir>/.vq-index/YYYY-MM-DD.idx` with one `<uuid> <rev>` line per logged entry. The index line is appended *after* the Markdown entry has been written and flushed. The index is loaded when the logger first writes to a day (and after a log-dir change). A crash between the two appends can log one entry twice, but never loses one. As the spec says, dedupe is per day file: the same (`id`, `rev`) arriving on a later day is logged in that day's file.

### D2. Which revisions are logged, and with which time
**Decision.**
- Only a `final`/`edit` that the transcript store *accepts* (a higher `rev` than any seen for that `id` in this run) is logged, and then only if (`id`, `rev`) is not already in the day's index. A stale lower-revision `final` that arrives after an `edit` is acked but not logged, so the log never shows an older text after the correction.
- The line's `HH:MM:SS` and the file's date are both the local wall-clock time when that revision **arrived**.
- The header is `# Ventriloquist — YYYY-MM-DD` followed by one blank line. Entries follow with no blank lines between them. If someone has edited the file by hand and it no longer ends in a newline, one is added before the next entry.

### D3. "Rendered inertly" in the log
**Decision.**
- LF splits lines, and a CR directly before an LF is dropped. Every text line, including empty ones, is indented two spaces, so no text line can begin at column 0 and pass for an entry or the header.
- These characters are written as visible `\u{XX}` escapes: control characters other than TAB (C0, DEL, C1, a lone CR, ESC), the bidi controls (U+061C, U+200E/F, U+202A–202E, U+2066–2069) and U+2028/U+2029.
- The device name gets the same escaping, and its LF and TAB are escaped too.
- Markdown syntax is **not** escaped, so the text stays verbatim for copying.

### D4. Unpaired idle drop and the reconnect hold-off
SPEC §6.3 says to drop unpaired phones after 5 minutes without pairing activity, and also to reconnect automatically. Taken together, a dropped phone would be reconnected at once. **Decision.**
- The session layer decides the drop (`policy::idle_drop_due`), because it knows the pairing state. Pairing activity is a connect, a `hello`, a `pair_request` or a `pair_confirm`. The rule applies to every session that is not Secure, including one that never sent `hello`.
- The disconnect carries a reconnect hold-off: **60 s** after an idle drop and **30 s** after `error{unknown_peer}`. Without the hold-off, an unknown phone would loop between connect and `unknown_peer`.
- Otherwise the reconnect backoff is 0 for the first attempt, then 1, 2, 4, 8, and 15 s for every later attempt. It resets after a successful connection; the first retry after a drop waits 1 s.
- The TCP dev transport uses the same schedule.
- The owner may tune these constants in `transport/policy.rs`.

### D5. Keepalive details
**Decision.**
- Once Secure, the desktop sends `ping` every 15 s. Only a `pong` resets the count of unanswered pings.
- When a `ping` is due while 3 are still unanswered, the desktop disconnects, about 60 s after the last `pong`. The close reason is `keepalive_timeout`.
- Each incoming `ping` gets a `pong`.
- Sessions that are not Secure send no keepalive; the idle drop (D4) covers them.

### D6. Desktop reactions not fixed by the README
**Decision.**
- **Pairing that cannot be saved.** If the pairing store cannot be written, the desktop answers `pair_result{ok:false}` and emits a `storage_warning`, and the attempt is not counted as a failure. Answering `ok:true` would make the phone store a pairing that the desktop rejects with `unknown_peer` on the next connection.
- **Low-order public key.** If the phone's `hello.pub` is a low-order key (`non_contributory`), the desktop answers `error{protocol}` and disconnects.
- **Out-of-order pairing messages.** A `pair_request` that arrives before `hello` is dropped. A `pair_confirm` that arrives before `hello` gets `pair_result{ok:false}`.
- **Decryption failures.** `decrypt_failed` while Secure is answered with `error{decrypt_failed}` and a disconnect. A `replay` is dropped with no event.
- **Errors from the phone.** An `error` from the phone, whether plaintext or encrypted, is shown and the desktop disconnects. It never changes the pairing store, whatever its provenance.
- **Version errors.** `error{version}` from the phone means *this desktop* must be updated. A `hello` with an unsupported `v` means the phone must be updated.
- **Display name.** The desktop sends its `hello` with `paired:false` (README §7.1). The phone's name comes from that connection's `hello`. The name stored at pairing time is not updated later.

### D7. Files, identity and config
**Decision.**
- The config directory is `<OS config dir>/com.ventriloquist.desktop`, which is the same as the Tauri identifier.
- `identity.json` holds `{version, device_id, secret_key(b64)}`. It is mode 0600 on unix, the mode is restored on every load, and the directory is created 0700. On Windows no explicit ACL is set; the file relies on the per-user `%APPDATA%` ACL.
- A corrupt identity file is an error and is never regenerated silently, because a new key would break every pairing.
- `peers.json` and `config.json` are written atomically: temp file, fsync, rename.
- `vq-host --log-dir/--name` override the values for that run only and are not persisted. The `set_log_dir` and `set_name` commands persist.
- The display name is trimmed, control characters are removed, and it is capped at 64 characters. An empty name resets to the hostname, without `.local`.

### D8. Transcript entry semantics
**Decision.**
- Entries are keyed by `id` across all phones. The cap evicts in order of first arrival, and `entry_evicted` is emitted.
- The entry reflects the highest accepted revision: `partial` = that revision is a partial; `edited` = that revision is an edit.
- `received_at` and `time` are the local arrival time of that revision; `ts` is the phone's start-of-utterance time.
- "Clear view" belongs to the UI only; the core has no command for it.

### D9. Peer ids
**Decision.** A `PeerId` names one *connection*: `tcp:<addr>#<n>` or `ble:<peripheral id>#<n>`. A reconnect therefore gets a new id, and stale commands for an old connection are ignored.
