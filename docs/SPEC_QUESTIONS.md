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

### Q3. `hello.paired` semantics
The desktop sends `hello` first, before it knows which phone it is talking to, so it cannot know `paired` reliably.

**Decision.** `paired` is the sender's best knowledge and is informational. Each side decides "known peer" from its own store, and both the `device_id` and the `pub` must match.

The flow is in README §7:
- The phone says `paired:true` but the desktop does not know it: the desktop sends `error{unknown_peer}` and disconnects.
- The phone says `paired:false` but the desktop knows it: the desktop waits for `pair_request`.

### Q4. Version mismatch decoding
**Decision.** A `hello` whose `v` is an integer other than 1 decodes to a distinct `HelloUnsupported{v, name?}` result. It is not rejected as an invalid message. This lets the receiver send `error{code:"version"}` and show "Update Ventriloquist on <name>" even if a future version changes the other hello fields. If `v` is missing or is not an integer, the hello is `invalid_message`.

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

### Q8. Where the 64 KiB limit applies
**Decision.** The limit of 65,536 bytes applies at three points:
- the reassembly buffer, which equals the envelope;
- envelope parsing;
- JSON decode and encode.

As a result, the largest JSON body that can be sent encrypted is 65,511 bytes. The 32,000-byte `text` limit counts UTF-8 bytes after JSON unescaping. A text that is within that limit but escapes past 64 KiB (for example, 32,000 control characters) cannot be encoded, and the encoder fails with `message_too_large`. The phone's utterance-length logic should therefore also check the encoded size.

### Q9. Plaintext-policy edge cases
**Decision.**
- A plaintext envelope with an **unknown** `t` is passed up as `Unknown` and dropped, consistent with §4.1 ("never fatal"). It is not rejected as `plaintext_not_allowed`.
- Plaintext-allowed types may also be sent encrypted, and are accepted that way.
- A plaintext `utt`, `ack`, `ping` or `pong` is rejected whether or not a session exists.

### Q10. Replay window details
**Decision.**
- The receiver accepts any counter strictly greater than the last accepted one, so gaps are fine and the first accepted counter need not be 0.
- The window advances only after successful authentication.
- After the sender uses counter 2^64−1, it refuses to send again (`counter_exhausted`). Re-establishing the session is required.

### Q11. `pair_result` with `ok:false`
**Decision.**
- When `ok` is false, `mac` is omitted. Receivers ignore a `mac` if one is present and treat `null` as absent.
- `ok:true` without `mac` is invalid.
- No "attempts remaining" field was added. The spec does not have one, and the phone learns of the lockout because further attempts keep failing.

### Q12. `error.msg` optional on receive
**Decision.** `msg` defaults to `""` when absent. It is always emitted.

### Q13. Unspecified JSON corner cases
**Decision.**
- A UTF-8 BOM is rejected.
- Integers must be plain JSON integers. A fractional `rev` such as `7.5` is invalid.
- `null` for a required field is invalid.
- Duplicate keys are unspecified, so senders must not emit them. No vector covers them.
- `ts` is the full u64 range. A vector uses `18446744073709551615`, so Swift must decode `UInt64` exactly and not via `Double`.

### Q14. Re-hello after Secure
**Decision (advisory, for M3).** A `hello` received on a connection that is already Secure SHOULD be treated as a protocol error. Session re-keying happens only by reconnecting.

### Q15. GATT UUIDs
**Decision.** These random v4 UUIDs were generated once:

| | UUID |
|---|---|
| Service | `77608b26-7b68-49da-bb34-7f05d158e219` |
| RX | `18489603-21ac-4cf2-9d31-62bd5d9c1635` |
| TX | `b01127eb-8819-42a7-a0e8-bdd6159d4e2a` |
