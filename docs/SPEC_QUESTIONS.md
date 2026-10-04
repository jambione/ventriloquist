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

### Q26. Finiteness of number tokens of any length
README §5.1 rejects a number only when it is not finite after rounding to binary64; length is not a criterion. Swift's `Double(String)` returns `nil` for any string longer than 16,384 bytes, so a port that parses the raw token rejects long but finite numbers (`1.000…0`, `0.000…1`, exponents with many leading zeros) as `invalid_json`, where Rust's `f64` parser accepts them. It also flips the precedence: `"rev":1.000…0` must be `invalid_message` (finite, but not an integer), not `invalid_json`. **Decision.** Swift decides finiteness from the digits. With the significand written as `0.d1d2… × 10^E` (d1 ≠ 0, exponent read with saturation), E ≤ 308 is finite and E ≥ 310 is infinite. Only E = 309 is near the overflow threshold 2^1024 − 2^970; then a short token is rounded with `Double(String)`: at most 800 significant digits, plus a sticky `1` if any dropped digit was non-zero. This rounds exactly like the full token, because no binary64 rounding boundary near 10^308 needs more than 309 significant digits. `messages.json` now pins this for every implementation (`R1 …` cases with 20,000–30,000-digit tokens, and a `tie:` case for `rev`). No README change is needed.

### Q27. Swift public-API hardening (M2 review)
- **`Base64.decode(_:length:)`** stays public but checks `0 ≤ length ≤ input length` before any arithmetic, so `length` near `Int.max` returns `nil` and cannot trap.
- **`PairingCode.generate(using:)`** is `internal` (test-only, for a seeded generator). Production code gets codes only from `generate()`, which uses the system CSPRNG. The draw is `UInt32.random(in: 0..<1_000_000, using:)`, the standard library's unbiased bounded sampler. The test checks that delegation exactly; it does not claim a statistical proof of uniformity.
- **`IdentityKeyPair`** no longer has a public `secretBytes: Data` getter. Persisting the key uses `withSecretBytes { (UnsafeRawBufferPointer) in … }`, which lends the 32 raw bytes for the duration of a Keychain write (e.g. `kSecClassGenericPassword` / `kSecValueData`). Restoring uses `init(secretBytes:)`, or `init(privateKey:)` with a CryptoKit key. The lent buffer is CryptoKit's `rawRepresentation` and is not wiped by us, because mutating it could write through to the key's own storage.
- **Test comparisons** of strings from vectors use UTF-8 byte equality (`sameBytes`), never `String ==`, per Q21.

## M3 (desktop core) — `vq-host-core`

These are numbered D1… so they cannot collide with the M2 entries being written at the same time.

### D1. Log dedupe across restarts: sidecar index
The SPEC §6.2 log line carries only an 8-digit id prefix and no revision, so the Markdown file alone cannot identify (`id`, `rev`). **Decision.** Each day file `YYYY-MM-DD.md` has a sidecar index `<log_dir>/.vq-index/YYYY-MM-DD.idx` with one `<uuid> <rev>` line per logged entry. The index line is appended *after* the Markdown entry has been written and flushed. The index is loaded when the logger first writes to a day (and after a log-dir change). The Markdown entry is `sync_data`'d before its index line is appended. A crash between the two appends can log one entry twice, but never loses one.
- **Midnight (M3 review A4).** Dedupe consults the index of the arrival day **and of the previous day**, so a `final` re-delivered just after midnight, or after a restart, is not logged a second time. The same (`id`, `rev`) arriving two or more days later is logged again in that day's file.
- **Robust index (A5/K4).** Index lines are parsed byte-wise; non-UTF-8, torn or garbage lines are skipped. Before appending, a torn last line is terminated with a newline. An index that cannot be read (except "not found") gives a `log_warning`, is not cached as empty, and is read again on the next write. If the index cannot be written (e.g. `.vq-index` is a file), a `log_warning` is emitted once; the entry counts as written and dedupe continues in memory for the rest of the run.

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
- The config directory is `<OS local config dir>/com.ventriloquist.desktop` (`dirs::config_local_dir`): macOS `~/Library/Application Support`, Windows `%LOCALAPPDATA%` (the non-roaming profile, so the identity key never roams to other machines), Linux `~/.config`. The name is the same as the Tauri identifier.
- `vq-host` defaults to a **separate** directory `…/com.ventriloquist.desktop.dev`, so dev runs never touch the app's identity and pairings. `--config-dir` overrides it.
- A corrupt or unreadable `config.json` does not block start-up: the defaults apply, a `storage_warning` is emitted after `started`, and the file is left alone until a setting changes. A corrupt `identity.json` or `peers.json` remains a hard error. A relative `log_dir` in the file is ignored (the default is used).
- `identity.json` holds `{version, device_id, secret_key(b64)}`. It is mode 0600 on unix, the mode is restored on every load, and the directory is created 0700. On Windows no explicit ACL is set; the file relies on the per-user `%LOCALAPPDATA%` ACL.
- A corrupt identity file is an error and is never regenerated silently, because a new key would break every pairing.
- `peers.json` and `config.json` are written atomically: temp file, fsync, rename.
- `vq-host --log-dir/--name` override the values for that run only and are not persisted. The `set_log_dir` and `set_name` commands persist. `set_log_dir` requires an absolute path (otherwise it is refused with a `storage_warning` and nothing changes). The log directory is created at start-up and on every change; failure is a `log_warning`. `config_changed` is emitted after the save is attempted and carries `persisted` (false: the change holds for this run only, and a `storage_warning` says why).
- The display name is trimmed, control characters, bidi controls and U+2028/U+2029 are removed, and it is capped at 64 characters. An empty name resets to the hostname, without `.local`.
- **Phone names (K13).** A phone's `hello.name` is normalised the same way on receipt, before it is shown, stored in `peers.json` or logged; an empty result becomes `Unnamed phone`.

### D8. Transcript entry semantics
**Decision.**
- Entries are keyed by `id` across all phones. The cap evicts in order of first arrival, and `entry_evicted` is emitted.
- The entry reflects the highest accepted revision: `partial` = that revision is a partial; `edited` = that revision is an edit.
- `received_at` and `time` are the local arrival time of that revision; `ts` is the phone's start-of-utterance time.
- "Clear view" belongs to the UI only; the core has no command for it.
- **Evicted ids (A3).** An evicted id leaves a tombstone holding its highest revision; the last 10,000 are kept. A revision ≤ the tombstone is acked but neither re-inserted nor re-announced; a higher one creates the entry again.
- **Interrupted partials (K18).** When a connection closes, every entry whose current revision is a partial delivered on that connection is re-emitted as `entry_upserted` with `state:"interrupted"`, `partial:false` (same `rev` and text). A later revision (e.g. the `final` re-sent after reconnecting) replaces it as usual.

### D9. Peer ids
**Decision.** A `PeerId` names one *connection*: `tcp:<addr>#<n>` or `ble:<peripheral id>#<n>`. A reconnect therefore gets a new id, and stale commands for an old connection are ignored.

### D10. Pairing rate limits and lockout (M3 review K1/A6)
Without limits a phone could request a new code as often as it liked (each request reset the failure count) and so brute-force the 10^6 code space online. Each request also counted as activity, so the phone was never idle-dropped, and each replaced the code on screen. **Decision** (normative text in README §7.3, "Pairing rate limits"; pure policy in `pairing_guard.rs`):
- **Per device** (keyed by `hello.device_id`, across connections): at most one *accepted* `pair_request` per 10 s; an earlier one gets plaintext `error{rate_limited}` and the connection stays open. A 6th `pair_request` (accepted or not) within 10 minutes gets `error{rate_limited}` and a disconnect with a 10-minute reconnect hold-off. The device is then refused for 10 minutes: an unpaired `hello` from it gets `error{rate_limited}` and a disconnect (a known phone with `paired:true` still becomes Secure).
- **Global lockout.** Each code invalidated by 3 failures locks pairing for all phones: 30 s, doubling with each further invalidation, at most 1 h. A successful pairing resets the lockout and its escalation. During the lockout, `pair_request` gets `error{rate_limited}`.
- **One modal.** While one connection has an active code, a `pair_request` on another connection gets `error{busy}`; the code on screen is not replaced.
- **Idle drop.** Only the first `pair_request` on a connection counts as pairing activity, and a `pair_confirm` counts only while a code is active.
- Refused requests mint no code and do not touch the active one. `rate_limited` and `busy` are added to README §5.7/§9 and as `ErrorMsg::RATE_LIMITED` / `ErrorMsg::BUSY`. They are the only `error`s after which the desktop keeps the connection open.

### D11. Host runtime: no blocking I/O, bounded events, snapshot (K2/K3/K11/A1)
**Decision.**
- After `Core::open`, the core does no file I/O. It emits `IoJob`s (log append, log-dir switch, `peers.json`, `config.json`) that an `IoExecutor` runs **in order** on a dedicated thread, with a bounded queue (1,024). Results return to the core as messages, so the async loop (acks, pongs, keepalive) is never stalled by a slow disk. If the queue is full, a log entry is dropped with a `log_warning`, and a settings or pairing save fails like a write error.
- **Pairing save.** A verified `pair_confirm` is answered only after `peers.json` is written: `ok:true` on success; on failure `ok:false` and a `storage_warning`, not counted as a failure (D6). A `pair_confirm` that arrives while the save is pending gets `ok:false`, not counted. "Forget" removes the phone from memory at once; a failed save is a `storage_warning`.
- **Log retry.** Entries that fail to log are queued (at most 1,000; the oldest is dropped beyond that) and retried, in order, before each new entry and every second. One `log_warning` is emitted when logging starts failing, and `log_recovered` once the queue is empty again.
- **Events.** The host → UI channel is bounded (256). The loop never waits for the UI; events wait in a coalescing outbox. A newer partial `entry_upserted` of the same id replaces the queued one in place. Repeats of a queued `message_rejected` (same peer and code) are dropped, and the newest `pairing_code_shown` per peer replaces the queued one. Beyond 4,096 queued events, coalescible events are dropped; finals, edits and state events never are.
- **Snapshot.** The `snapshot` command answers with a `snapshot` event: device id, name, log dir, paired peers, last adapter state, live connections (state, phone, `paired`, active pairing code with its remaining seconds) and every transcript entry. A reloaded UI rebuilds itself from it.
- Paths in events are serialized lossily (invalid UTF-8 becomes U+FFFD), so serializing an event never fails.

### D12. Transport write back-pressure (A2/K10)
**Decision.** In both transports a per-connection writer task drains a bounded queue of `Send` batches (64). A full queue disconnects the phone ("send queue full"), as does a write slower than 10 s (one TCP batch, or one BLE write with response). The connection loop never awaits a write, so notifications, `Disconnect`, `Shutdown` and peripheral loss are handled at once. `Disconnect` still sends the frames queued before it (e.g. `error{unknown_peer}`), but waits at most 1 s (TCP) for them.

### D13. BLE adapter and peripheral lifecycle (K6–K9)
**Decision.**
- A peripheral slot that is neither connected nor seen advertising for 3 minutes is forgotten (`policy::ble_slot_expired`). This stops endless retries of stale rotating addresses. The end of a connection counts as "seen".
- A failed `start_scan` is retried every second while the adapter is powered on (`policy::scan_retry_due`).
- While the adapter state stays `unknown` (for example, first-run permission not yet granted), the adapter is re-acquired through a new `Manager` every 5 s (`policy::adapter_reacquire_due`). `PermissionDenied` maps to `unauthorized`. Only changes of adapter state are reported.
- Before the adapter is re-acquired, every connection task is closed and drained (2 s at most), so each reports `Disconnected` and none is orphaned.

### D14. `dev-tcp` never in release builds (K5)
**Decision.** `vq-host-core` has `compile_error!` under `all(feature = "dev-tcp", not(debug_assertions))`. The TCP dev transport is unauthenticated, so it can never be unified into a release build of the app. Tests, the E2E harness and `vq-host` run in debug builds (`cargo test`, `cargo run`). `--all-features` works in debug builds (clippy, tests) and fails in release builds by design.

## M6 (iOS app)

Numbered P1… so they cannot collide with entries written by other milestones at the same time.

### P1. Custom vocabulary API: `DictationTranscriber`, not `SpeechTranscriber` (settles SPEC §5.2 / §11)
Checked against the installed SDK (Xcode 27, `iPhoneOS27.0.sdk`, `Speech.framework/Modules/Speech.swiftmodule/arm64e-apple-ios.swiftinterface` and `.swiftdoc`). `AnalysisContext.contextualStrings: [ContextualStringsTag: [String]]` exists and is set on the analyzer (`SpeechAnalyzer.setContext(_:)`), not on a module, so the type system does not say which module honours it. The SDK's documentation comment on `contextualStrings` does: "With the `DictationTranscriber` module, you can use this property to specify short custom phrases… Limit the total number of phrases across all tags to no more than 100." Nothing equivalent is documented for `SpeechTranscriber`. **Decision.** Per the SPEC fallback, the app uses `DictationTranscriber(locale: en-US, contentHints: [], transcriptionOptions: [.punctuation], reportingOptions: [.volatileResults], attributeOptions: [])` (the `progressiveLongDictation` preset's settings) with the vocabulary in `contextualStrings[.general]`, capped at 100 terms in Settings. `SpeechAnalyzer`, `AssetInventory` (status, `reserve`, `assetInstallationRequest` + `downloadAndInstall` with `progress`) and `bestAvailableAudioFormat` are used as specified. `AnalyzerInputConverter` is iOS 27 only, so audio is converted with `AVAudioConverter` (deployment target 26.0).

### P2. Speech-recognition permission
The SDK documentation for `SpeechAnalyzer`/`DictationTranscriber` does not say whether `SFSpeechRecognizer` authorization is required. `DictationTranscriber` is the dictation engine historically gated by that authorization, so the app requests it (with `NSSpeechRecognitionUsageDescription`) together with the microphone on the first recording, and shows the Open Settings screen if either is denied. If on-device testing shows it is unnecessary, the request can be removed.

### P3. Phone-side pairing behaviour not fixed by the README
- **Wrong code** (`pair_result{ok:false}`): the sheet says "Wrong code" and lets the user retry with the same nonces. After the 3rd `ok:false` the desktop has invalidated the code and started its global lockout (30 s, doubling, max 1 h). The phone does **not** send a new `pair_request` by itself: the sheet shows "wait, then try again" with a countdown (`PairingStatus.retryIn`, at least the 30 s lockout for the first invalidation, doubling for each further one since the last success, tracked per desktop). "Get a new code" sends a request only within the limits below.
- **Client-side pairing limits** (mirror of `desktop/core/src/pairing_guard.rs`, README §7.3): per desktop, at least 10 s between `pair_request`s and at most 5 per 10 minutes (refused ones count). When a request would break a limit, nothing is sent and the sheet shows the wait with a disabled, counting-down Try again button. A `rate_limited` that arrives outside a pairing exchange (a refused `hello`) blocks pairing to that desktop for 10 minutes. Beyond the 10 s spacing there is no extra backoff after `rate_limited`/`busy` (the retry is the user's tap).
- **Expired code**: if the user submits 120 s or more after the `pair_challenge` arrived, the phone sends a new `pair_request` (if within the limits) instead of a `pair_confirm` that would certainly fail.
- **`rate_limited` / `busy`** (README §7.3): non-fatal. The pairing sheet shows "…Try again later" with a Try again button, the connection is kept and goes back to the unpaired state. If the desktop does close the link, the transport reports it as usual.
- **Same `device_id` on several connections** (V1): an unauthenticated `hello` never closes an existing connection. A new Secure connection of a desktop we already have is pinged at once; only when a message from it decrypts does it replace the older ones. Until then the older/authenticated one carries utterances and defines the host row.
- **Silent connections** (M20): no `hello` within 30 s closes the connection; at most 8 unproven connections are kept (oldest silent first).
- **Closes tell the desktop** (M8): engine-initiated closes (replaced, forgotten, protocol errors, cap) send plaintext `error{protocol}` first and the transport closes gracefully (queued frames are delivered). Not sent for keepalive timeout (dead link), `disconnectAll` (backgrounding; the vanishing GATT service is the signal) or when an `error` was just sent.
- **Names** (M14, M15): desktop names and our own name are cleaned like the desktop's K13 (control and bidi characters removed, trimmed, at most 64 scalars; empty becomes "Unnamed desktop" / "iPhone"). First run asks for a device name, prefilled with `UIDevice.name` (which is only "iPhone" without a special entitlement).
- **Unreadable host file** (M10): `PhoneEngine.pairedHostsUnreadable` is set, the app shows a banner, and the file is renamed `paired-hosts.unreadable-<time>.json` before the first save; if that fails the pairing is not saved. With a temporary identity (Keychain read failure, M9) the app uses in-memory host and settings stores.
- **Other `error`s** (any provenance): shown, and the phone closes the connection. None of them changes the paired-host store; `unknown_peer` only marks the host "not recognised" in memory.
- A desktop `hello` with `v ≠ 1` shows "Update Ventriloquist on <desktop name>" (README §5.2 wording); a received `error{version}` shows "Update Ventriloquist on this iPhone" (mirrors D6).
- A second connection from the same `device_id` (after `hello`) replaces the older one.
- If the paired-host store cannot be written after a successful pairing, the session is used and a notice says the pairing will not be kept.

### P4. Utterance pipeline details
- `rev` counts every revision actually sent for an `id`, starting at 0 (partials, then the final, then each edit). Retries resend the same `rev`.
- Partials are sent at most every 200 ms (latest text wins; an identical text is not resent). Partials that could not be sent because no host was Secure are not queued, except that the latest one goes out once the host is Secure and the utterance is still open.
- Only the newest `final`/`edit` per `id` is kept for delivery; an `ack` completes it only when its `rev` equals the pending `rev` (lower is stale, higher was never sent, V2).
- Partials are limited to 5/s across the connection, also between back-to-back utterances (V3).
- Memory bounds (V4–V6): at most 1,000 deliveries wait for an ack or a host; on overflow the oldest becomes `failed` and leaves the queue (Re-send from history). Per-id state of acked or dropped ids is kept for the last 1,000 only; `forgetDelivery` releases everything (a later `sendEdit` for it returns `nil`); the app calls it for every history entry pruned or deleted.
- On stop, the app waits up to about 1.5 s in total for the analyzer to finalize (M22).
- Retries: every 2 s, up to 5 per connection; then the status is **failed**. A failed or pending delivery is sent again, with a fresh retry budget, whenever the active host (re)becomes Secure or a different paired host is made active. Pending deliveries follow the active host.
- Pending deliveries are kept in memory only. History entries still "pending" at the next launch are shown as failed so the user can Re-send them.
- An utterance that stops with empty text and never sent a partial is dropped. Deleting a history entry stops its retries.
- `ts` of an `edit` is the original utterance's `ts`. Re-send uses the current time.

### P5. Background and BLE peripheral lifecycle
A peripheral cannot disconnect a central. "Disconnect" on the phone marks the link closed: its queued frames are discarded and its writes ignored until it subscribes again. On backgrounding, the app stops the recording (the `final` is queued), waits up to 5 s (inside a background task) until the final is acked and the BLE queue is empty, then drops every engine connection, stops advertising and removes the GATT service so desktops see the service disappear. A return to the foreground within that wait cancels the teardown. "Disconnect" is graceful: frames already queued (such as an `error`) are still sent (`FrameSendQueue`). On returning to the foreground it re-adds the service and advertises again. A write from a central that has not subscribed yet is treated as its connect. Each link queues at most 12,000 frames for `peripheralManagerIsReady`; beyond that the link is closed.

### P6. Persistence
- Identity: one Keychain generic-password item (`kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly`, not synchronizable); `kSecValueData` is the 32-byte private key written through `IdentityKeyPair.withSecretBytes`; `kSecAttrGeneric` is the 16-byte `device_id`. If the item exists but cannot be read, the app runs with a temporary identity and shows a warning. It never overwrites the stored item.
- Paired hosts: `Application Support/paired-hosts.json` (atomic, protected until first unlock). Settings and the last host: `UserDefaults`. History: SwiftData, 1,000 entries, oldest pruned first.

### P7. VQPhoneCore, PhoneTransport and where the phone-side TCP lives (SPEC §3, §8)
**Decision.** SPEC §3/§8 put a `Transport` protocol with `BLEPeripheralTransport` and `TCPTransport` in the iOS app. The code is stricter. The protocol is `PhoneTransport` (`ios/VQProtocol/Sources/VQPhoneCore/Transport.swift`), in a third SwiftPM target, `VQPhoneCore`, which also holds `PhoneEngine` (utterances, pairing, sessions, keepalive). The app conforms `BLEPeripheralTransport` to `PhoneTransport`. The TCP side is `TCPServer` in the `PhoneSim` executable (`Sources/PhoneSim/TCPServer.swift`), so the app contains no TCP code at all and nothing needs an `#if DEBUG` guard. E1/E2 cover only PhoneSim's location and threading. SPEC §3, §3.3 and §8 were updated to match.

## M5 (desktop app)

Numbered W1… so they cannot collide with entries written by other milestones at the same time.

### W1. One event channel, snapshot reply as an event
All `HostEvent`s go to the main window as one Tauri event, `host-event`, whose payload is the event's JSON exactly as `vq-host` prints it (tagged by `"event"`). The `snapshot` command only queues `HostCommand::Snapshot`; the reply arrives on the same channel as a `snapshot` event, so it is ordered with every other event. It fails (and the UI shows a fatal banner) only when the host could not start, for example because `identity.json` is corrupt; the window still opens.

### W2. Loading and reloading the page
The page subscribes first and then asks for a snapshot, retrying every 3 s until one arrives. Events received before the snapshot are buffered. The snapshot replaces all state, then the buffer is merged: entry upserts and evictions are replayed under the highest-`rev` rule, warnings and notices are replayed, and other state events are dropped because the snapshot supersedes them. Two cases need the merge because the host's outbox coalesces in place (D11), so a newer event can be delivered ahead of an older snapshot:
- A newer partial is kept because of its higher `rev`.
- If a `pairing_code_shown` for the peer that still has a code in the snapshot was delivered before the snapshot, and no `pairing_code_ended` came after it, its code wins.

The UI accepts an entry revision when its `rev` is higher, or when the `rev` is equal and a `partial` becomes `interrupted` (D8).

### W3. Clear view
Clear view records each visible entry's id and current `rev`. An entry stays hidden until a higher revision arrives, which shows it again. That covers an edit to a cleared entry and a partial that was still live when the view was cleared. New ids always show. The record lives only in memory, so a page reload brings everything back from the snapshot. The log and the core are never touched. Search is a case- and accent-insensitive substring match (W11) on the entry text only, not the device name, and it applies to the entries that Clear view has not hidden.

### W4. Pairing modal
The modal opens on `pairing_code_shown`. Only one modal shows at a time (the newest code; W11 for several connections). The countdown runs from the local (monotonic) receipt time plus `expires_in_secs`, or the snapshot's remaining seconds. The modal closes on `pairing_code_ended`, on `pairing_result{ok:true}`, on `pairing_result{ok:false, attempts_remaining:0}`, when its connection closes, at local expiry, and on Cancel or Esc. Cancel closes the modal immediately and sends `cancel_pairing`. A wrong code (`ok:false` with attempts left) keeps the modal open, because the code is still valid, and shows "Wrong code entered on the phone — N attempts left". This reading of "closes on result" is the only one that lets the user retry.

### W5. Toolbar status text
The status line is chosen in this priority order:
1. Adapter problem: "Bluetooth off", "Bluetooth not authorized — enable in System Settings" (Windows: "…enable it in Settings › Privacy & security"), or "No Bluetooth adapter".
2. "Connected to <names> (secure)".
3. "Pairing with <name>…".
4. "Connecting to <name>…", for a peer that is connecting, or one that is paired and has exchanged hellos.
5. "<name> found — pair from the phone", for an unpaired phone that has exchanged hellos.
6. "Scanning…".
7. "Starting Bluetooth…", while the adapter state is `unknown`.

### W6. Warnings and notices
- **Log warning.** `log_warning` sets a persistent, non-blocking banner with the latest message, and `log_recovered` clears it.
- **Dismissible notices.** `storage_warning`, `peer_error` and `version_mismatch` ("Update Ventriloquist on <device>") become dismissible notices. At most 5 are kept, and peer messages are truncated to 200 characters.
- **Persisted flag.** `config_changed{persisted:false}` shows a "could not be saved" line under the log folder in Settings.
- **Ignored.** `message_rejected` is not shown.

### W7. Commands and permissions
- **App commands.** The app's commands are declared in an app manifest (`build.rs`), so each one needs an explicit `allow-<command>` permission.
- **Webview capability.** The only capability, `main`, grants exactly those 8 commands (`snapshot`, `ack_events`, `forget_peer`, `set_name`, `cancel_pairing`, `open_log_folder`, `pick_log_dir`, `copy_text`) plus `core:event:allow-listen` and `core:event:allow-unlisten`.
- **Plugins.** The clipboard, dialog and opener plugins are called from Rust, so the webview gets none of their permissions:
  - `copy_text` writes the given string unchanged, capped at 65,536 bytes (utterances can be 32,000 bytes; R3).
  - `pick_log_dir` shows the picker in Rust and sends `SetLogDir` itself. The web view supplies no path and there is no `set_log_dir` command. A package (`.app`, `.bundle`, …) is refused, and so is a UNC path on Windows (it would send NTLM credentials to the server).
  - `open_log_folder` opens the host's current log directory, which Rust tracks from `started`, `snapshot` and `config_changed`. It takes no path argument, refuses packages and (Windows) UNC paths, checks that the directory exists off the main thread, and names the file manager explicitly (`Finder`, `explorer`), so the OS never launches a bundle.
- **Argument limits.** Other string arguments (name, peer id) are capped at 4 KiB, and `forget_peer` checks that the device id is a UUID.
- **CSP.** The CSP allows only `'self'` and the IPC origins.

### W9. Single instance (R1)
Two layers: `tauri-plugin-single-instance` (registered first; a second launch exits and shows, unminimizes and focuses the main window) and an exclusive advisory lock on `<config dir>/.lock` taken by `Core::open` (also protects `vq-host`). If the lock is held, `Core::open` fails with `AddrInUse` ("Ventriloquist is already running…"), which the window shows as the fatal banner. The lock is released when the `Core` drops, so a restart in the same process works.

### W10. Snapshot carries the log warning (R2)
`snapshot` has `log_warning` (the latest message while the log is failing, else null). `Core` tracks it from the I/O results (`log_warning` sets it, `log_recovered` clears it). The UI applies it when the snapshot starts the page. A snapshot that arrives after the page is ready is merged for entries only (below), so it cannot resurrect a recovered warning. This keeps the banner across page reloads, including the automatic reload after a WebContent crash.

### W11. Hostile and out-of-order input in the UI (adversary U1–U18)
- **Bidi.** Every peer-provided string put into a sentence (names in the status line and notices, error messages, device names) has U+202A–202E, U+2066–2069, U+200E/F and U+061C removed and is wrapped in FSI…PDI (U+2068…U+2069). Status names are clipped to 32 characters, at most 2 are listed, then "and N more".
- **Late snapshots.** A snapshot after the page is ready only merges entries under the highest-`rev` rule; it never regresses or drops an entry, and it does not touch peers, adapter or pairing. A duplicated id inside a snapshot keeps the highest `rev`.
- **Tombstones.** The UI remembers evicted ids with their highest `rev` (at most 10,000, oldest dropped; mirrors the core's A3) and ignores upserts at or below it, so an evicted entry is not resurrected by a re-emitted `interrupted` or a stale revision. Clear view needs no extra record: the tombstone blocks the same revision.
- **Pairing codes.** The UI keeps one code per connection (at most 8) and shows the newest; when it ends, another still-valid code is shown. `attempts_remaining <= 0` closes a code. `expires_in_secs` that is NaN, infinite or negative means already expired (no modal); more than 3600 means 120 s.
- **Clocks.** Pairing deadlines and ticks use `performance.now()` (monotonic), so a wall-clock jump cannot extend a code. `formatCountdown` clamps to 0:00…60:00. `formatDate` returns "" outside the years 1900–9999 or for non-finite input (the adversary test requires 1969/1970 to format, so the lower bound is 1900, not 2000).
- **Search.** Both sides are folded with NFKD, combining marks removed, then `toLowerCase()` (locale-independent), so "İSTANBUL" matches "istanbul". The folded text is cached per entry.

### W12. Event flow control (R6)
The forwarder emits at most 256 unacknowledged events to the page. The page acknowledges with `ack_events(n)` (every 16 events or after 100 ms, from a timer, not from rendering). With a full window the forwarder stops draining the host's bounded, coalescing channel, so a stalled page pushes back on the core. The window is reset when the page asks for a snapshot (a reload loses its acknowledgements) and after 5 s without any acknowledgement. A failed emit is logged and not counted; the page asks for a snapshot every 3 s while loading and shows a notice after 10 unanswered tries. Paths that are not valid Unicode are serialized lossily by the core, so events always serialize.

### W13. Pairing code while the window is hidden
On `pairing_code_shown`, Rust unminimizes and shows the window and requests user attention (informational; focus is not taken).

### W8. Shutdown and BLE permission on macOS
- **Shutdown.** On `RunEvent::Exit`, after the last window closes or on Quit, the app sends `Shutdown` and waits up to 8 s for the host task. The host itself waits at most 3 + 2 + 1 s. A SIGTERM or SIGKILL skips this.
- **Info.plist.** `NSBluetoothAlwaysUsageDescription` comes from `src-tauri/Info.plist`, which the bundler merges into the app's plist.
- **Launching the binary.** macOS kills a process that uses Bluetooth when the *responsible* process has no usage description. Running `Contents/MacOS/Ventriloquist` directly from a terminal therefore crashes with a TCC violation, because the terminal is the responsible process. Launch the bundle with `open Ventriloquist.app`, or from Finder.

## M4 (E2E)

Numbered E1… so they cannot collide with entries written by other milestones at the same time.

### E1. Where PhoneSim lives
SPEC §3.3 lists `/ios/PhoneSim/`. SwiftPM does not allow a target path outside the package root, so the target is `ios/VQProtocol/Sources/PhoneSim` (an `executableTarget` plus an `executable` product in `ios/VQProtocol/Package.swift`), with its docs in `ios/VQProtocol/PhoneSim-README.md`. **Proposed SPEC change:** §3.3 should read `/ios/VQProtocol/Sources/PhoneSim/`.

### E2. PhoneSim design
- **Threading.** One thread with non-blocking POSIX sockets and a `poll(2)` loop. `PhoneEngine` is not `Sendable`, so nothing crosses threads. The loop runs `tick()` about every 20 ms on the real `SystemClock`.
- **State.** `--state-dir` stores the identity (with the private key in a plain 0600 file), the paired hosts and the last host. This is for tests only.
- **`wait-acked`.** It takes no rev argument. The engine marks a delivery acked only for an `ack` with `rev` ≥ the pending `rev`, so "acked" always means the latest `final`/`edit` of that utterance was acked.
- **Test controls.** `tx-pause`, `rx-pause`, `drop-connection` and `inject-plaintext-utt` exist only in PhoneSim, so the e2e test can create unacked finals and send a forged message deterministically.

### E3. E2E harness decisions
- **Driving PhoneSim.** `tests/e2e/run.sh` drives PhoneSim through a FIFO on stdin. Each command is answered by `command_done`/`command_failed` with its `seq`. The pairing code reaches PhoneSim as a file (`pair @file`): the script copies it from vq-host's `pairing_code_shown`.
- **Log assertions.**
  - In scenario b, the log file is compared literally.
  - After every scenario, every log file must equal the header plus the SPEC §6.2 rendering of every accepted `final`/`edit` `entry_upserted`, in order. `tests/e2e/e2e.py` re-implements the `inert()` rules of `desktop/core/src/logger.rs` for this. If those rules change, `e2e.py` must change with them.
  - A run that crosses local midnight can split entries across two day files. The helper groups entries by `received_at` date, so this is handled.
- **Scenario d** is split into two cases:
  - d1: the desktop never received the final. The final goes out under a TX pause and the link is dropped. On reconnect it is re-delivered and logged once.
  - d2: the desktop logged the final but the ack was lost. RX is paused and the link is dropped. On reconnect the re-delivery is deduplicated: there is no second event or log line, and the phone records one ack.
- **Scenario g** uses a fresh phone and the code shown + 1 (mod 10⁶), so there is only one failure and no global lockout. It also injects a plaintext `utt`. The test asserts `message_rejected{plaintext_not_allowed}`, and that the phone produced no entry, no `paired_peers_changed` and no secure session.
- Reconnects rely on vq-host's TCP backoff, which is 1 s after a dropped connection. A full run takes about 12–16 s, with a 300 s overall watchdog (`E2E_TIMEOUT`).
- `run.sh` is compatible with bash 3.2 (macOS `/bin/bash`): it uses no associative arrays.

### E4. Interop findings
None. PhoneSim (the real `PhoneEngine`) and `vq-host` agreed on every scenario on the first attempt. `pairing_result.attempts_remaining` is `0` on success. That is harmless but slightly odd. It is informational and was not changed.

## v2 N1 (vq-inject)

- **`app_id` instead of `bundle_id`** (owner scope change: Windows is primary). `BindingTarget.app_id` and `WindowInfo.app_id` hold the bundle id on macOS and the executable name on Windows. `bindings.json` still reads the old `bundle_id` key (serde alias). App ids compare case-insensitively (planner list and re-match).
- **Windows executables** are in the keystroke-preferred list. **`TargetCaps.elevated`** gives `Blocked("target is elevated")` (UIPI) through `secure_refusal`. The `Injector` trait exposes no macOS types.
- **Planner decisions.**
  - 200 counts Unicode scalar values of the sanitised text, with line breaks counting as 1.
  - Empty text after sanitising gives a no-op plan, even with auto-submit.
  - A blocked caps gives an empty plan with `blocked` set.
  - A lone `\r` is a control character and is dropped. CRLF is one break.
- **Step order.** Keystroke path is Activate, WaitFrontmost, FocusElement (spec lists focus before wait). Focusing an element of a frontmost app is more reliable.
- **AX path + auto-submit.** A Return keystroke needs the target focused, so the AX plan then also runs Activate, WaitFrontmost, FocusElement, Return, ReactivatePrevious after the insertion.
- **AX fallback.** `Plan.fallback` carries the keystroke plan. Read-back confirms only if `AXValue` was readable before and after and changed. An unreadable value counts as unconfirmed, as the spec says, which could in theory double-insert if the app inserted but hides `AXValue`.
- **Rebinding** resets auto-submit to off. An ambiguous exact-title match (two windows with the same title) is unbound, never a guess. A corrupt `bindings.json` is moved to `bindings.json.corrupt`.
- **Injector trait** additions beyond the brief: `assign`, `assign_saved` and `release` (live refs per slot, restore after restart). `capture_focused` returns `CapturedBinding` with an opaque live handle.
- **MacInjector.**
  - Frontmost app is read via AX `AXFocusedApplication` (NSWorkspace as fallback).
  - Activation uses `activateWithOptions` plus `AXFrontmost`, because macOS 14 limits cross-app activation.
  - Key events use a Private CGEventSource with explicit flags, so held hotkey modifiers don't leak in.
  - Pasteboard text is marked `org.nspasteboard.TransientType`.
  - Crates: core-foundation 0.10, core-graphics 0.25, objc2 0.6, objc2-app-kit/foundation 0.3. AX and `IsSecureEventInputEnabled` are hand-written FFI.
- **Gaps and risks.**
  - MacInjector is compile-checked only; nothing was run against real apps. The TextEdit test is `mac-it` and `#[ignore]`.
  - Terminal.app "Secure Keyboard Entry" makes `IsSecureEventInputEnabled` true, so deliveries to Terminal are `blocked` whenever it is on. CGEvent typing would still work, but the spec says to refuse.
  - Rematched slots have no element until delivery, so the AX path is used only if the window's focused element matches the saved role.

## v2 N1w (Windows injector)

- **Crate:** `windows` 0.62 (already in the lockfile via Tauri), features limited to what `desktop/inject` uses. All `unsafe` is in `windows/sys.rs`; `windows/mod.rs` is safe logic plus pure helpers with unit tests (they run on the Windows CI job; this Mac can only cross-check).
- **Planner changes.**
  - `TargetCaps.clipboard_restorable` (macOS always true). When false, text over 200 chars is typed, including in the AX fallback plan. Unit-tested.
  - `SlotSettings.newline_mode` (`ShiftEnter | Spaces`, serde snake_case, default `ShiftEnter`). `BindingsStore::bind` sets it from the app category (`SlotSettings::for_app`: Terminal gives `Spaces`). `set_newline_mode` added. Settings survive re-match and save/load; a file without the key reads as `ShiftEnter`.
  - `Spaces` replaces each (normalised) line break with one space before planning, so the 200-char count uses the flattened text.
  - `Action::CmdV` is kept as the action name and means Ctrl+V on Windows.
- **Clipboard restorability** is decided from the format list: GDI-handle formats (metafiles, owner-display, `CF_GDIOBJ*`, and `CF_BITMAP`/`CF_PALETTE` without a DIB) are not restorable. Windows synthesises `CF_BITMAP` from a DIB, so a plain image copy stays restorable. Snapshots over 64 MB, or a format whose HGLOBAL can't be read, also count as not restorable. Delayed-rendered formats are rendered by `GetClipboardData` and copied. If the snapshot fails at execution (clipboard changed since `caps`), the delivery fails instead of overwriting.
- **Clipboard writes** use a hidden message-only window as owner (`SetClipboardData` fails after `EmptyClipboard` with a NULL owner) and add `ExcludeClipboardContentFromMonitorProcessing`, `CanIncludeInClipboardHistory=0`, `CanUploadToCloudClipboard=0` so history and cloud sync skip our text.
- **UIA re-focus** keeps the captured `IUIAutomationElement` plus its RuntimeId. `FocusElement` calls `SetFocus` only if `GetRuntimeId` still equals the saved one. Restored (`assign_saved`) and re-matched slots have no element and type into whatever the window focuses. No `FindFirst`-by-RuntimeId search (needs a SAFEARRAY VARIANT).
- **Password check** happens at capture, in `caps` (saved element) and again after `FocusElement` (the element that actually has focus, when it belongs to the target pid, gives `Blocked("secure text field")`).
- **Elevation** is checked at capture (refused with `Platform("target is elevated")`, since the trait has no Blocked error), in `caps`, and again at the start of `execute`, before activation. Own pid gives `Blocked`/`SelfFrontmost`.
- **Window list** (`running_windows`/re-match): visible, titled, uncloaked (DWM) top-level windows. `standard` means no owner and not `WS_EX_TOOLWINDOW`. `WindowInfo.id` is the HWND.
- **Notes and risks.**
  - Held modifier keys are not released before `SendInput`.
  - The foreground check is exact HWND equality, as the spec says; a popup stealing focus aborts with "focus changed".
  - Nothing here has run on Windows. The `win-it` Notepad test (launches a unique temp file so it works with classic and Windows 11 Notepad, force-kills by pid) is CI-only and non-blocking; the Win11 Notepad edit control is a RichEdit that should expose TextPattern.
  - Pre-existing and unrelated: `cargo clippy --workspace` currently fails in `desktop/app/src-tauri/src/delivery.rs:690` (identical `if` blocks, `get().is_none()`), which another agent is editing.

## v2 N2 (desktop bindings)

- **One FIFO queue for everything.** Finals, "Send to active slot", bind, select, unbind and settings changes all go through the delivery thread's queue. A hotkey pressed during a delivery therefore runs after it (and after deliveries queued earlier), and affects the next delivery that starts. Hotkey sounds can lag a long paste by its duration.
- **Entry texts live in Rust.** `send_to_active(entry_id)` reads the entry's text when the delivery *starts* (so a correction made while it waits is sent). The forwarder feeds `entry_upserted`, `snapshot`, `entry_evicted` and `final_accepted` into the manager (bounded to 600 ids). Partial and interrupted entries are refused.
- **Events.** Tauri events `delivery` (per entry state: sending, sent, off, missing, blocked, failed), `slots` (slot bar, no deliveries) and `binding-notice`. They bypass the host-event ack window. `slots_snapshot` also returns the last 500 delivery results for page reloads. "sending…" is emitted only when the active slot is not Off.
- **Slot status.** `live` (bound this session or delivered to), `unverified` ("?": re-matched, no success yet), `unbound` (not found; dimmed, "rebind"). A delivery that resolves to `Missing` marks the slot unbound. An active slot that does not re-match at start becomes Off (§4.2). `accessibility_status` re-runs the re-match for unbound slots when permission is seen granted.
- **Hotkeys.** Registered in Rust only (`on_shortcut` per digit); the web view's capability has no global-shortcut permission, and the plugin needs none for Rust use. Modifier sets are validated in Rust (need Ctrl, Alt/Option or Cmd/Win; select and bind must differ), stored in `<config dir>/hotkeys.json`, and a failed registration is reported per digit as "taken by another app". Defaults are the same set on both OSes (Ctrl+Shift select; Ctrl+Alt/Option+Shift bind).
- **Newline mode** is wired to `SlotSettings.newline_mode` (`shift_enter`/`spaces`): shown in each chip's ⋯ menu and set through `set_slot_settings`.
- **Accessibility UI** is shown only when the backend reports `supported` (macOS); `open_accessibility_settings` returns an error elsewhere. Windows shows no permission UI.
- **Exit panic fix.** `tokio::time::timeout` was built outside the runtime inside `block_on`, which panicked in the OS terminate callback and aborted the app. `wait_for_task` now builds it inside the future, `stop_host` is wrapped in `catch_unwind`, and the delivery thread is stopped with a bounded wait (2 s). A unit test calls it from a plain thread.
- **Windows cross-check of the Tauri crate** needs `llvm-rc` (tauri-winres) which is not installed on this Mac; `cargo check -p ventriloquist-desktop --target x86_64-pc-windows-msvc` fails in the build script with `NotAttempted("llvm-rc")`. With a stub `llvm-rc` on PATH (check does not link resources) it passes, so the Rust code compiles for Windows.
- **verify.sh** gains `gate6_inject` (tests, clippy, Windows cross-check when the target is installed); it is not in the default requested gates here.

## v2 N3 (review fixes)

- **R5 (SPEC change): `follow_title_changes`.** Each slot has a boolean, default **true for the Terminal category, false otherwise** (a missing key in an older file gets that default). When false, delivery requires the live window title to equal the bound title exactly, else `Blocked("window changed: was '<old>', now '<new>'")` and no keystrokes; the startup re-match does not adopt a new title either. Rebinding updates the title. UI: the ⋯ menu toggle "Follow window when its title changes". Rationale: the reviewer's Teams scenario (same window, same compose box, another conversation) cannot be told apart by HWND, pid or element RuntimeId, so the title is the only available signal. §4.3, §4.5, §4.6 updated. The flag lives on the slot record (not in `SlotSettings`) so existing `SlotSettings` literals keep compiling.
- **Window identity for the fallback (R7).** Slots also persist the window class and AppUserModelID (`identity`, empty on macOS and in old files, which then do not constrain). The single-window fallback needs equal class/AUMID when both sides are known, is never used for browsers/`ApplicationFrameHost.exe`/generic runtimes (exact title only), and never picks a window on another virtual desktop (R6; those windows still count for ambiguity). AUMID is read per process (`GetApplicationUserModelId`), so unpackaged apps and apps behind `ApplicationFrameHost` have none.
- **Windows password check fails closed (R1), macOS does not (R14).** Windows refuses unless UIA proves the focused element is not a password. macOS refuses a secure text field or secure event input; an element that cannot be inspected is allowed while secure input is off, because Electron/Chromium password fields cannot be detected through AX anyway and macOS secure input is the system's own signal for a focused password field. This is the R14 amendment of R9.
- **R14 (macOS, Claude desktop / Electron).** Electron and Chromium do not expose their AX tree until an assistive client sets `AXManualAccessibility` on the app element. Capture (and the window re-match, and focus re-check) now set it for keystroke-preferred apps and retry for up to ~500 ms. If no focused element can be read but the window is known (`AXFocusedWindow`, or the window server's list through `CGWindowListCopyWindowInfo`, whose names need Screen Recording permission), the slot binds at **window level** (empty element role, `ax_insertable=false`, keystroke path). Windows does the same when UIA reports no focused element; there the fail-closed check at delivery time still decides. DEVICE-CHECK on a real Claude desktop app.
- **R15: refusals are never silent.** Every bind refusal and every blocked/failed/missing delivery is logged at warn level (`VQ_LOG`) with its reason, and the UI raises a notice with the reason (blocked/failed deliveries previously only changed the entry badge).
- **R10 deviations.** "Prefer typing" for multi-line text applies on both platforms up to 1,000 characters (single-line stays 200). Pasted lines wait 150 ms and verify the clipboard sequence; the restore waits until 400 ms after the last paste key (was 250 ms).
- **R3/R4.** The settle (150 ms) before auto-submit Return and before re-activating the previous app, the idle wait (300 ms, max 3 s) and the physical-input stop live in one shared interpreter (`vq_inject::exec`) used by both platforms and tested with a fake OS. macOS samples `CGEventSourceSecondsSinceLastEventType` between chunks and compares it with the time since our own last post, so it works whether or not our synthetic events count in the hardware state. Mouse movement alone does not interrupt (only clicks and wheel), key releases do not either.
- **Not changed / device-only.** #29 (refuse before activating for re-matched slots) stays as is: no element is known, the check after activation is authoritative. Delayed-rendering detection (#24) is the owner-based deny-list plus the private-format rule, not a render probe. The macOS hotkey modifiers released by the user are not waited for. All Windows/macOS executor changes are DEVICE-CHECK items; the ordering logic is covered by unit tests with a fake OS.
- **BLE re-acquire (R16).** See the entry below.
- **R16: BLE adapter replaced under live connections (investigated, ours).** btleplug's macOS `Manager::adapters()` creates a brand-new CoreBluetooth central on every call (`Manager::new()` itself is empty). The K7 re-acquire built a new `Manager` and adapter every 5 s while the state was unknown and not scanning, without looking at connection tasks, and the restart drain gave up after 2 s leaving still-running tasks holding the old adapter (`central.clone()`); dropping/duplicating centrals under a live peripheral gives exactly the owner's log (`Shouldn't get anything but Ok!` from `disconnect`, `Event receiver died`, then `Device not found` for that peripheral id). Fix: one `Manager` for the whole run; `adapter_reacquire_due` additionally requires no live connection (policy test); the restart drain aborts leftover tasks and waits for them once more before a new adapter is used. Not reproducible without hardware: DEVICE-CHECK by toggling Bluetooth while a phone is connected.

## v2.1 (owner changes)

### O1. iPhone History removed (owner, 2026-10-04)
"iPhone app: I don't need a history." Removed the History tab/view, the SwiftData `HistoryEntry`/`HistoryStore` and `ModelContainer`, Re-send, swipe-delete/Clear all and the 1,000 cap. Supersedes the M6 History items (SPEC §5.1). Engine state stays bounded without it: `PhoneEngine` already caps settled per-id state (`maxSettledTracked`), and the app additionally calls `engine.forgetDelivery` for the previous utterance when a new recording starts, if it is acked or failed (a pending one keeps retrying). `VQPhoneCore`'s public API is unchanged (`resend`, `forgetDelivery` stay for PhoneSim and tests). Stale pending-to-failed marking on launch is gone with the store (engine state is in memory only).

### O2. Desktop: search removed, clear bindings, always-on log, BLE discovery (owner, 2026-10-04)
- **Search removed.** The desktop app has no search field (SPEC §6.1); its reducer, state and tests are gone. Clear view stays.
- **Clear one / all bindings.** A bound chip's ⋯ menu has "✕ Clear" and Settings → Bindings has "Clear binding" per slot (both are the old Unbind). Settings → Bindings also has "Clear all bindings" with a two-click confirm (the Forget pattern): it clears every slot, releases the platform references, and sets the active slot to Off (command `clear_all_slots`).
- **Windows stuck on "Scanning…" (v0.2.0).** No console and no logs made it undiagnosable. The desktop app now always writes `<config dir>/logs/ventriloquist.log` (2 MB x 3 files, info; debug with `VQ_LOG=1`; version, OS and adapter at start-up). Settings → Diagnostics shows the path and opens the file or folder. The status shows "Scanning… (N devices seen)".
- **Discovery.** The scan uses an empty `ScanFilter` and the core matches itself: service UUID **or** local name `Ventriloquist` (`policy::is_candidate`). A name-only match whose GATT service is missing after connecting is dropped and not retried for 5 minutes. Every discovered device is logged once per id per 60 s.
- Decisions: the count is "advertisements seen" (DeviceDiscovered/Updated/ServicesAdvertisement events) since the scan started, reported at most once per second as `devices_seen` (coalesced in the outbox). "Open log file" opens the file in TextEdit (macOS) / Notepad (Windows) by name, like the file manager for folders. The log writer is a small in-app rotating file (no new logging dependency).

### O3. BLE polling mode (owner, 2026-10-04)
Windows connects and discovers RX/TX but the TX CCCD write fails (0x80650003); macOS subscribes fine. Matches an iOS 26.1+ regression (Apple forums 812318). Added polling mode, protocol/README.md §2.2 and SPEC_V2.md "v2.2 BLE polling mode": TX is Notify+Read; desktop falls back to polling on any subscribe failure (or `VQ_BLE_FORCE_POLL=1`); the phone creates a poll peer on the first RX write from an unsubscribed central, serves one frame per TX read (empty if none, `invalidOffset` for offset != 0), and drops it after 60 s idle. The phone's queue is the pure `PollQueue` in VQPhoneCore. Poll-loop pacing is `policy::poll_wait`. Decisions: a poll read has a 10 s timeout (error = disconnect); a poll peer closed by the engine stays until its queued frames are read and the 60 s idle rule removes it. The "devices seen" count (supersedes the O2 decision) is now **unique** peripheral ids since the scan started (`policy::note_seen`).

### O4. Current-dictation view, History toggle, phone-app hint (owner, 2026-10-04)
- **Current-dictation view** is the default: one entry, the newest id by first-seen order, large monospace, live partials. The toolbar **History** toggle (localStorage `vq.historyView`) shows the existing list. Clear view works on both views and uses the existing id and revision rule, so it can never hide a newer utterance (tests in state.test.ts). Clear view with nothing but older entries leaves the empty state; older entries are not promoted into the single view.
- **Root cause of "new dictations stop appearing":** the core emits `final_accepted` (after the first `entry_upserted` of an id), but the frontend reducer had no case for it, so `applyEvent` returned `undefined`. The state became undefined, the render threw, and every later event failed. A phone would show the first final and then nothing. The reducer now handles `final_accepted` (upserts the entry; it is idempotent) and ignores unknown events; `onHostEvent` always acknowledges. The Rust forwarder (`Flow`, `notify_one` plus a 5 s timeout) has no lost wakeup (`notify_one` stores a permit); a page that stopped acknowledging only stalled it in 5 s steps, so no Rust change.
- **`phone_app_not_open`:** new additive `HostEvent` (`{active}`) and snapshot field. The BLE transport sends `TransportEvent::PhoneAppNotOpen` when a name-only match has no service; the core emits it on change and clears it on the next `Connected` of any phone. The toolbar shows "iPhone found — open Ventriloquist on it" (after secure, pairing and connecting states, before "Scanning…").
