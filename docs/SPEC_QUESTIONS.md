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
