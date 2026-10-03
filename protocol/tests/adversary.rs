//! Adversarial tests for `vq-protocol` (M1 adversary pass).
//!
//! Every assertion encodes behaviour REQUIRED by SPEC.md §4 / protocol/README.md,
//! not merely what the implementation currently does. Failing tests are findings.

#![allow(clippy::single_match, clippy::type_complexity, clippy::useless_vec)]

use std::fmt::Debug;

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use vq_protocol::b64::{decode_fixed, encode, format_uuid, parse_uuid};
use vq_protocol::crypto::{
    derive_pair_key, derive_session_key, desktop_result_mac, phone_confirm_mac,
    verify_desktop_result_mac, verify_phone_confirm_mac, IdentityKeyPair, PairingCode,
    SharedSecret,
};
use vq_protocol::envelope::{
    decode_envelope, encode_plaintext, nonce, open_with, seal_with, Direction, Envelope,
    KIND_ENCRYPTED,
};
use vq_protocol::message::{Ack, ErrorMsg, Hello, Message, PairResult, Utt, UttState};
use vq_protocol::{FrameSplitter, Reassembler, Role, SessionCipher, MAX_MESSAGE_BYTES};

// ---------------------------------------------------------------- helpers

const KEY: [u8; 32] = [0x42; 32];
const UID: &str = "0f8fad5b-d9cb-469f-a165-70867728950e";
const B64_32: &str = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=";

#[track_caller]
fn code<T: Debug>(r: vq_protocol::Result<T>) -> &'static str {
    match r {
        Ok(v) => panic!("expected an error, got Ok({v:?})"),
        Err(e) => e.code(),
    }
}

fn dec(s: &str) -> vq_protocol::Result<Message> {
    Message::from_json(s.as_bytes())
}

fn utt_json(text_json: &str) -> String {
    format!(r#"{{"t":"utt","id":"{UID}","rev":1,"state":"final","text":"{text_json}","ts":0}}"#)
}

fn utt_with(field: &str, value: &str) -> String {
    let mut fields = vec![
        ("id", format!("\"{UID}\"")),
        ("rev", "1".to_string()),
        ("state", "\"final\"".to_string()),
        ("text", "\"x\"".to_string()),
        ("ts", "0".to_string()),
    ];
    for f in fields.iter_mut() {
        if f.0 == field {
            f.1 = value.to_string();
        }
    }
    let body: Vec<String> = fields.iter().map(|(k, v)| format!("\"{k}\":{v}")).collect();
    format!("{{\"t\":\"utt\",{}}}", body.join(","))
}

fn hello_json(pub_b64: &str, dev: &str, v: &str) -> String {
    format!(
        r#"{{"t":"hello","v":{v},"device_id":"{dev}","name":"n","pub":"{pub_b64}","paired":false,"session_nonce":"{B64_32}"}}"#
    )
}

fn plain_env(json: &str) -> Vec<u8> {
    let mut v = vec![0u8];
    v.extend_from_slice(json.as_bytes());
    v
}

fn pair() -> (SessionCipher, SessionCipher) {
    (
        SessionCipher::new(&KEY, Role::Phone),
        SessionCipher::new(&KEY, Role::Desktop),
    )
}

fn sample_utt(text: &str) -> Message {
    Message::Utt(Utt {
        id: parse_uuid(UID).unwrap(),
        rev: 1,
        state: UttState::Final,
        text: text.into(),
        ts: 1,
    })
}

/// Deterministic SplitMix64.
struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E3779B97F4A7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58476D1CE4E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D049BB133111EB);
        z ^ (z >> 31)
    }
    fn below(&mut self, n: usize) -> usize {
        (self.next() % n as u64) as usize
    }
    fn byte(&mut self) -> u8 {
        self.next() as u8
    }
    fn bytes(&mut self, n: usize) -> Vec<u8> {
        (0..n).map(|_| self.byte()).collect()
    }
}

// ================================================================ FRAMING

#[test]
fn fr_every_reserved_bit_rejected_and_discards_partial() {
    for bit in 2..8 {
        for base in [0x00u8, 0x01, 0x02, 0x03] {
            let mut r = Reassembler::new();
            r.push(&[0x01, 0, 5, b'a']).unwrap();
            let flags = base | (1 << bit);
            assert_eq!(code(r.push(&[flags, 0, 5, b'b'])), "reserved_flags");
            assert!(!r.has_partial(), "flags {flags:#x} must discard partial");
            // the tail of the old message is now an orphan
            assert_eq!(code(r.push(&[0x02, 0, 5, b'c'])), "orphan_frame");
        }
    }
}

#[test]
fn fr_truncated_frames_discard_partial() {
    for len in 0..3 {
        let mut r = Reassembler::new();
        r.push(&[0x01, 0, 1, b'x']).unwrap();
        assert_eq!(code(r.push(&[0x02, 0, 1][..len])), "frame_too_short");
        assert!(!r.has_partial());
    }
    // header-only FIRST|LAST is a valid (empty) message
    assert_eq!(Reassembler::new().push(&[0x03, 0xFF, 0xFF]).unwrap(), Some(vec![]));
}

#[test]
fn fr_first_reset_mid_message_never_mixes_bytes() {
    let mut r = Reassembler::new();
    r.push(&[0x01, 0, 9, b'A', b'A']).unwrap();
    r.push(&[0x00, 0, 9, b'B', b'B']).unwrap();
    // attacker injects FIRST with same seq mid-stream
    r.push(&[0x01, 0, 9, b'E']).unwrap();
    let out = r.push(&[0x02, 0, 9, b'Z']).unwrap().unwrap();
    assert_eq!(out, b"EZ");
}

#[test]
fn fr_interleaved_messages_are_discarded_not_spliced() {
    let mut s = FrameSplitter::new();
    let a = s.split(&[b'a'; 50], 20).unwrap();
    let b = s.split(&[b'b'; 50], 20).unwrap();
    let mut r = Reassembler::new();
    let mut delivered = vec![];
    let mut errs = vec![];
    for i in 0..a.len().max(b.len()) {
        for f in [a.get(i), b.get(i)].into_iter().flatten() {
            match r.push(f) {
                Ok(Some(m)) => delivered.push(m),
                Ok(None) => {}
                Err(e) => errs.push(e.code()),
            }
        }
    }
    // b's FIRST resets a; then a's 2nd frame mismatches b → both discarded.
    for m in &delivered {
        assert!(
            m.iter().all(|&c| c == m[0]),
            "spliced message delivered: {:?}",
            String::from_utf8_lossy(m)
        );
    }
    assert!(errs.contains(&"seq_mismatch"));
}

#[test]
fn fr_orphans_after_completion_and_reset() {
    let mut r = Reassembler::new();
    assert_eq!(r.push(&[0x03, 0, 1, b'x']).unwrap(), Some(b"x".to_vec()));
    assert_eq!(code(r.push(&[0x00, 0, 1, b'y'])), "orphan_frame");
    assert_eq!(code(r.push(&[0x02, 0, 1, b'y'])), "orphan_frame");
    r.push(&[0x01, 0, 2, b'x']).unwrap();
    r.reset();
    assert_eq!(code(r.push(&[0x02, 0, 2, b'y'])), "orphan_frame");
}

#[test]
fn fr_msg_seq_wrap_and_no_monotonic_check() {
    let mut s = FrameSplitter::with_seq(0xFFFE);
    let mut r = Reassembler::new();
    for expect in [0xFFFEu16, 0xFFFF, 0x0000, 0x0001] {
        let fr = s.split(&[7u8; 40], 20).unwrap();
        for f in &fr {
            assert_eq!(u16::from_be_bytes([f[1], f[2]]), expect);
        }
        let mut out = None;
        for f in &fr {
            out = r.push(f).unwrap();
        }
        assert_eq!(out.unwrap(), vec![7u8; 40]);
    }
    // receiver must not check increments: going backwards is fine
    assert_eq!(r.push(&[0x03, 0x12, 0x34, 1]).unwrap(), Some(vec![1]));
    assert_eq!(r.push(&[0x03, 0x00, 0x00, 2]).unwrap(), Some(vec![2]));
}

#[test]
fn fr_oversize_single_and_byte_by_byte() {
    // exactly 65,536 in one frame: allowed; one more: rejected
    let mut f = vec![0x03, 0, 0];
    f.extend(std::iter::repeat_n(0u8, MAX_MESSAGE_BYTES));
    assert_eq!(Reassembler::new().push(&f).unwrap().unwrap().len(), MAX_MESSAGE_BYTES);
    f.push(0);
    let mut r = Reassembler::new();
    assert_eq!(code(r.push(&f)), "message_too_large");
    assert!(!r.has_partial());

    // 1-byte chunks: 65,536 ok, 65,537th rejected and buffer discarded
    let mut r = Reassembler::new();
    r.push(&[0x01, 0, 3, 0]).unwrap();
    for _ in 1..MAX_MESSAGE_BYTES {
        assert_eq!(r.push(&[0x00, 0, 3, 0]).unwrap(), None);
    }
    assert_eq!(code(r.push(&[0x00, 0, 3, 0])), "message_too_large");
    assert!(!r.has_partial());
    assert_eq!(code(r.push(&[0x02, 0, 3, 0])), "orphan_frame");
    // still usable
    assert_eq!(r.push(&[0x03, 0, 4, 9]).unwrap(), Some(vec![9]));
}

#[test]
fn fr_empty_continuations_do_not_grow_or_fail() {
    let mut r = Reassembler::new();
    r.push(&[0x01, 0, 0, 1, 2, 3]).unwrap();
    for _ in 0..200_000 {
        assert_eq!(r.push(&[0x00, 0, 0]).unwrap(), None);
    }
    assert_eq!(r.push(&[0x02, 0, 0]).unwrap(), Some(vec![1, 2, 3]));
}

#[test]
fn fr_splitter_limits() {
    let mut s = FrameSplitter::with_seq(10);
    for mtu in [0usize, 1, 3, 19] {
        assert_eq!(code(s.split(b"x", mtu)), "mtu_too_small");
    }
    assert_eq!(code(s.split(&vec![0; MAX_MESSAGE_BYTES + 1], 20)), "message_too_large");
    assert_eq!(s.next_seq(), 10);
    // absurd mtu must not panic/overflow
    let fr = s.split(&[1u8; 100], usize::MAX).unwrap();
    assert_eq!(fr.len(), 1);
    assert_eq!(fr[0][0], 0x03);
}

// ================================================================ ENVELOPE

#[test]
fn env_every_unknown_kind_rejected() {
    for k in 0x02..=0xFFu8 {
        let mut d = SessionCipher::new(&KEY, Role::Desktop);
        let env = [vec![k], vec![0u8; 40]].concat();
        assert_eq!(code(Envelope::parse(&env)), "unknown_envelope_kind");
        assert_eq!(code(decode_envelope(&env, Some(&mut d))), "unknown_envelope_kind");
        assert_eq!(code(decode_envelope(&env, None)), "unknown_envelope_kind");
    }
    assert_eq!(code(decode_envelope(&[], None)), "empty_envelope");
}

#[test]
fn env_truncated_counter_and_tag() {
    let (mut p, _) = pair();
    let env = p.seal(b"").unwrap();
    assert_eq!(env.len(), 25);
    for len in 1..25 {
        let mut d = SessionCipher::new(&KEY, Role::Desktop);
        assert_eq!(code(decode_envelope(&env[..len], Some(&mut d))), "envelope_too_short");
        assert_eq!(d.last_received_counter(), None);
    }
    // 25 bytes: decrypts to empty body → invalid_json, not a panic
    let mut d = SessionCipher::new(&KEY, Role::Desktop);
    assert_eq!(code(decode_envelope(&env, Some(&mut d))), "invalid_json");
}

#[test]
fn env_oversize_rejected_both_kinds() {
    for k in [0x00u8, 0x01] {
        let mut env = vec![k];
        env.resize(MAX_MESSAGE_BYTES + 1, b' ');
        let mut d = SessionCipher::new(&KEY, Role::Desktop);
        assert_eq!(code(decode_envelope(&env, Some(&mut d))), "message_too_large");
    }
}

#[test]
fn env_every_bitflip_rejected_and_window_unmoved() {
    let mut p = SessionCipher::new(&KEY, Role::Phone).with_send_counter(5);
    let env = p.seal_message(&sample_utt("secret")).unwrap();
    for i in 1..env.len() {
        for bit in 0..8 {
            let mut t = env.clone();
            t[i] ^= 1 << bit;
            let mut d = SessionCipher::new(&KEY, Role::Desktop);
            let r = decode_envelope(&t, Some(&mut d));
            assert_eq!(code(r), "decrypt_failed", "byte {i} bit {bit}");
            assert_eq!(d.last_received_counter(), None);
        }
    }
}

#[test]
fn env_kind_byte_flip_never_yields_message() {
    let (mut p, mut d) = pair();
    let env = p.seal_message(&Message::Ping).unwrap();
    for k in [0x00u8, 0x02, 0x81, 0xFF] {
        let mut t = env.clone();
        t[0] = k;
        assert!(decode_envelope(&t, Some(&mut d)).is_err(), "kind {k:#x}");
    }
    assert_eq!(d.last_received_counter(), None);
}

#[test]
fn env_wrong_aad_rejected() {
    let cipher = ChaCha20Poly1305::new(Key::from_slice(&KEY));
    let n = nonce(Direction::PhoneToDesktop, 3);
    for aad in [&[][..], &[0x00][..], &[0x01, 0x01][..], &[0x02][..]] {
        let ct = cipher
            .encrypt(Nonce::from_slice(&n), Payload { msg: br#"{"t":"ping"}"#, aad })
            .unwrap();
        let env = [vec![KIND_ENCRYPTED], 3u64.to_be_bytes().to_vec(), ct].concat();
        let mut d = SessionCipher::new(&KEY, Role::Desktop);
        assert_eq!(code(d.open(&env)), "decrypt_failed", "aad {aad:?}");
    }
    // correct AAD = [0x01] works (positive control, independent construction)
    let ct = cipher
        .encrypt(Nonce::from_slice(&n), Payload { msg: br#"{"t":"ping"}"#, aad: &[1] })
        .unwrap();
    let env = [vec![KIND_ENCRYPTED], 3u64.to_be_bytes().to_vec(), ct].concat();
    let mut d = SessionCipher::new(&KEY, Role::Desktop);
    assert_eq!(decode_envelope(&env, Some(&mut d)).unwrap(), Message::Ping);
}

#[test]
fn env_nonce_layout_independent() {
    // nonce = dir ‖ 000000 ‖ ctr; any other padding must fail
    let cipher = ChaCha20Poly1305::new(Key::from_slice(&KEY));
    let ctr = 0x0102_0304_0506_0708u64;
    let mut bad = nonce(Direction::PhoneToDesktop, ctr);
    assert_eq!(bad, [1, 0, 0, 0, 1, 2, 3, 4, 5, 6, 7, 8]);
    bad[3] = 1;
    let ct = cipher
        .encrypt(Nonce::from_slice(&bad), Payload { msg: b"{}", aad: &[1] })
        .unwrap();
    let env = [vec![1], ctr.to_be_bytes().to_vec(), ct].concat();
    assert_eq!(code(open_with(&KEY, Direction::PhoneToDesktop, &env)), "decrypt_failed");
}

#[test]
fn env_replay_and_reordering() {
    let (mut p, mut d) = pair();
    let e: Vec<_> = (0..5).map(|_| p.seal_message(&Message::Ping).unwrap()).collect();
    assert_eq!(decode_envelope(&e[0], Some(&mut d)).unwrap(), Message::Ping);
    assert_eq!(code(decode_envelope(&e[0], Some(&mut d))), "replay");
    assert_eq!(decode_envelope(&e[3], Some(&mut d)).unwrap(), Message::Ping); // gap ok
    assert_eq!(code(decode_envelope(&e[1], Some(&mut d))), "replay"); // reorder
    assert_eq!(code(decode_envelope(&e[2], Some(&mut d))), "replay");
    assert_eq!(code(decode_envelope(&e[3], Some(&mut d))), "replay");
    assert_eq!(decode_envelope(&e[4], Some(&mut d)).unwrap(), Message::Ping);
    assert_eq!(d.last_received_counter(), Some(4));
}

#[test]
fn env_replay_check_happens_before_decrypt() {
    let (p, mut d) = pair();
    let e0 = p.with_send_counter(10).seal(b"{}");
    let e0 = e0.unwrap();
    d.open(&e0).unwrap();
    // garbage ciphertext with counter <= last must be `replay`, not `decrypt_failed`
    for c in [0u64, 9, 10] {
        let env = [vec![1], c.to_be_bytes().to_vec(), vec![0xEE; 30]].concat();
        assert_eq!(code(d.open(&env)), "replay", "counter {c}");
    }
}

#[test]
fn env_forged_max_counter_cannot_burn_window() {
    let (mut p, mut d) = pair();
    let e0 = p.seal(b"{}").unwrap();
    let mut forged = e0.clone();
    forged[1..9].copy_from_slice(&u64::MAX.to_be_bytes());
    assert_eq!(code(d.open(&forged)), "decrypt_failed");
    assert_eq!(d.last_received_counter(), None);
    assert!(d.open(&e0).is_ok());
}

#[test]
fn env_counter_near_max() {
    let mut p = SessionCipher::new(&KEY, Role::Phone).with_send_counter(u64::MAX);
    let mut d = SessionCipher::new(&KEY, Role::Desktop);
    // failed (oversize) seal at MAX does not burn it
    assert_eq!(code(p.seal(&vec![0; MAX_MESSAGE_BYTES])), "message_too_large");
    assert_eq!(p.next_send_counter(), Some(u64::MAX));
    let last = p.seal(b"{}").unwrap();
    assert_eq!(code(p.seal(b"{}")), "counter_exhausted");
    assert_eq!(code(p.seal_message(&Message::Ping)), "counter_exhausted");
    d.open(&last).unwrap();
    assert_eq!(d.last_received_counter(), Some(u64::MAX));
    assert_eq!(code(d.open(&last)), "replay");
    // every subsequent counter is a replay
    let mut p2 = SessionCipher::new(&KEY, Role::Phone).with_send_counter(u64::MAX - 1);
    assert_eq!(code(d.open(&p2.seal(b"{}").unwrap())), "replay");
}

#[test]
fn env_cross_direction_and_reflection() {
    let (mut p, mut d) = pair();
    let from_phone = p.seal(b"{\"t\":\"ping\"}").unwrap();
    let from_desk = d.seal(b"{\"t\":\"ping\"}").unwrap();
    // same key, same counter, same plaintext → different ciphertext (direction in nonce)
    assert_eq!(&from_phone[1..9], &from_desk[1..9]);
    assert_ne!(&from_phone[9..], &from_desk[9..]);
    // phone key/role decrypting desktop→phone works; but reflection fails
    let mut p_rx = SessionCipher::new(&KEY, Role::Phone);
    assert_eq!(code(p_rx.open(&from_phone)), "decrypt_failed"); // own msg reflected
    let mut d_rx = SessionCipher::new(&KEY, Role::Desktop);
    assert_eq!(code(d_rx.open(&from_desk)), "decrypt_failed");
    assert_eq!(code(open_with(&KEY, Direction::DesktopToPhone, &from_phone)), "decrypt_failed");
    assert_eq!(code(open_with(&KEY, Direction::PhoneToDesktop, &from_desk)), "decrypt_failed");
    // XOR of keystreams must not be equal (would indicate nonce reuse)
    let a = seal_with(&KEY, Direction::PhoneToDesktop, 7, &[0u8; 64]).unwrap();
    let b = seal_with(&KEY, Direction::DesktopToPhone, 7, &[0u8; 64]).unwrap();
    assert_ne!(&a[9..73], &b[9..73]);
}

#[test]
fn env_wrong_key_rejected() {
    let (mut p, _) = pair();
    let env = p.seal(b"{}").unwrap();
    let mut d = SessionCipher::new(&[0x43; 32], Role::Desktop);
    assert_eq!(code(d.open(&env)), "decrypt_failed");
}

#[test]
fn env_plaintext_smuggling_rejected() {
    let (_, mut d) = pair();
    let cases = [
        utt_json("hi"),
        format!(r#"{{"t":"ack","id":"{UID}","rev":1}}"#),
        r#"{"t":"ping"}"#.into(),
        r#"{"t":"pong"}"#.into(),
        "  \n{\"t\":\"ping\"}\t ".into(),
        "{\"\x5Cu0074\":\"\x5Cu0070ing\"}".into(), // escaped key + value == ping
        r#"{"t":"ping","extra":{"t":"hello"}}"#.into(),
        r#"{"x":1,"t":"pong"}"#.into(),
    ];
    for c in &cases {
        let env = plain_env(c);
        assert_eq!(code(decode_envelope(&env, None)), "plaintext_not_allowed", "{c}");
        assert_eq!(code(decode_envelope(&env, Some(&mut d))), "plaintext_not_allowed", "{c}");
    }
    // duplicate `t`: behaviour unspecified, but must never yield an encrypted-only type
    for c in [
        format!(r#"{{"t":"error","code":"x","t":"utt","id":"{UID}","rev":1,"state":"final","text":"x","ts":0}}"#),
        format!(r#"{{"t":"utt","id":"{UID}","rev":1,"state":"final","text":"x","ts":0,"t":"error","code":"x"}}"#),
        r#"{"t":"hello","t":"ping"}"#.into(),
        r#"{"t":"ping","t":"error","code":"x"}"#.into(),
    ] {
        match decode_envelope(&plain_env(&c), None) {
            Ok(Message::Utt(_) | Message::Ack(_) | Message::Ping | Message::Pong) => {
                panic!("smuggled encrypted-only type via duplicate key: {c}")
            }
            _ => {}
        }
    }
    // malformed utt in plaintext: must be rejected (any code)
    assert!(decode_envelope(&plain_env(r#"{"t":"utt"}"#), None).is_err());
    // sender side refuses too
    for m in [sample_utt("x"), Message::Ping, Message::Pong,
              Message::Ack(Ack { id: parse_uuid(UID).unwrap(), rev: 0 })] {
        assert_eq!(code(encode_plaintext(&m)), "plaintext_not_allowed");
    }
}

#[test]
fn env_encrypted_without_session_and_plaintext_to_open() {
    let (mut p, mut d) = pair();
    let env = p.seal_message(&Message::Ping).unwrap();
    assert_eq!(code(decode_envelope(&env, None)), "no_session");
    let pt = encode_plaintext(&Message::Error(ErrorMsg::new("x", ""))).unwrap();
    assert_eq!(code(d.open(&pt)), "unknown_envelope_kind");
    assert_eq!(code(open_with(&KEY, Direction::PhoneToDesktop, &pt)), "unknown_envelope_kind");
    // encrypted unknown/hello allowed
    let h = Message::Hello(Hello {
        v: 1,
        device_id: parse_uuid(UID).unwrap(),
        name: "x".into(),
        public_key: [1; 32],
        paired: true,
        session_nonce: [2; 32],
    });
    let env = p.seal_message(&h).unwrap();
    assert_eq!(decode_envelope(&env, Some(&mut d)).unwrap(), h);
}

#[test]
fn env_full_stack_max_utt() {
    // 32,000 bytes of `"` escape to 64,000 JSON bytes — still fits 65,511.
    let (mut p, mut d) = pair();
    let m = sample_utt(&"\"".repeat(32_000));
    let env = p.seal_message(&m).unwrap();
    let frames = FrameSplitter::new().split(&env, 20).unwrap();
    let mut r = Reassembler::new();
    let mut out = None;
    for f in &frames {
        out = r.push(f).unwrap();
    }
    assert_eq!(decode_envelope(&out.unwrap(), Some(&mut d)).unwrap(), m);
}

// ================================================================ MESSAGES

#[test]
fn msg_pair_result_false_ignores_bad_mac() {
    // README §5.6: mac MUST be omitted when ok is false; "a receiver ignores it if present".
    for mac in [
        "\"garbage\"",
        "123",
        "\"AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHg==\"", // 31 bytes
        "{}",
        "null",
        &format!("\"{B64_32}\""),
    ] {
        let j = format!(r#"{{"t":"pair_result","ok":false,"mac":{mac}}}"#);
        assert_eq!(
            dec(&j).unwrap_or_else(|e| panic!("{j}: {e:?}")),
            Message::PairResult(PairResult::failure()),
            "{j}"
        );
    }
}

#[test]
fn msg_pair_result_true_mac_rules() {
    assert_eq!(code(dec(r#"{"t":"pair_result","ok":true,"mac":null}"#)), "invalid_message");
    assert_eq!(code(dec(r#"{"t":"pair_result","ok":true}"#)), "invalid_message");
    assert_eq!(code(dec(r#"{"t":"pair_result","ok":"true","mac":"x"}"#)), "invalid_message");
    assert_eq!(code(dec(r#"{"t":"pair_result","ok":1}"#)), "invalid_message");
}

#[test]
fn msg_huge_number_in_ignored_member() {
    // Ruling R1: every number anywhere in the document (ignored members
    // included) must be finite as an IEEE 754 double, otherwise invalid_json.
    for n in ["1e400", "-1e400", "1E+999999"] {
        let j = format!(r#"{{"t":"ping","pad":{n}}}"#);
        assert_eq!(code(dec(&j)), "invalid_json", "{j}");
        let j = format!(r#"{{"t":"future","pad":{n}}}"#);
        assert_eq!(code(dec(&j)), "invalid_json", "{j}");
        let j = format!(r#"{{"t":"ping","pad":[{{"x":{n}}}]}}"#);
        assert_eq!(code(dec(&j)), "invalid_json", "{j}");
    }
    // finite (even if not exactly representable) numbers in ignored members are fine
    for n in ["123456789012345678901234567890123456789", "1e308", "-1e-400", "-0"] {
        let j = format!(r#"{{"t":"ping","pad":{n}}}"#);
        assert_eq!(dec(&j).unwrap_or_else(|e| panic!("{j}: {e:?}")), Message::Ping);
        let j = format!(r#"{{"t":"future","pad":{n}}}"#);
        assert_eq!(
            dec(&j).unwrap_or_else(|e| panic!("{j}: {e:?}")),
            Message::Unknown { t: "future".into() }
        );
    }
}

#[test]
fn msg_huge_number_in_field_is_invalid_message() {
    // Ruling R1: a non-finite number is invalid_json even in a known field
    // (the JSON check covers the whole document before any field is read).
    for n in ["1e400", "-1e400"] {
        assert_eq!(code(dec(&utt_with("rev", n))), "invalid_json", "rev {n}");
        assert_eq!(code(dec(&utt_with("ts", n))), "invalid_json", "ts {n}");
        assert_eq!(code(dec(&hello_json(B64_32, UID, n))), "invalid_json", "hello.v {n}");
    }
    // finite but out of the field's range → invalid_message
    for n in ["18446744073709551616", "99999999999999999999999999"] {
        assert_eq!(code(dec(&utt_with("rev", n))), "invalid_message", "rev {n}");
        assert_eq!(code(dec(&utt_with("ts", n))), "invalid_message", "ts {n}");
        assert_eq!(
            code(dec(&hello_json(B64_32, UID, n))),
            "invalid_message",
            "hello.v {n}"
        );
    }
}

#[test]
fn msg_integer_forms() {
    for bad in ["1.0", "1e0", "1E2", "\"1\"", "true", "null", "-1", "4294967296", "[1]", "0.5"] {
        assert_eq!(code(dec(&utt_with("rev", bad))), "invalid_message", "rev {bad}");
        let j = format!(r#"{{"t":"ack","id":"{UID}","rev":{bad}}}"#);
        assert_eq!(code(dec(&j)), "invalid_message", "ack.rev {bad}");
    }
    for bad in ["1.0", "1e3", "-1", "\"0\"", "18446744073709551616"] {
        assert_eq!(code(dec(&utt_with("ts", bad))), "invalid_message", "ts {bad}");
    }
    // boundaries accepted
    assert!(matches!(dec(&utt_with("rev", "4294967295")).unwrap(), Message::Utt(u) if u.rev == u32::MAX));
    assert!(matches!(dec(&utt_with("rev", "0")).unwrap(), Message::Utt(u) if u.rev == 0));
    assert!(matches!(dec(&utt_with("ts", "18446744073709551615")).unwrap(), Message::Utt(u) if u.ts == u64::MAX));
    // invalid JSON grammar for numbers
    for bad in ["01", "+1", ".5", "0x10", "NaN", "Infinity"] {
        assert_eq!(code(dec(&utt_with("rev", bad))), "invalid_json", "rev {bad}");
    }
}

#[test]
fn msg_hello_version_handling() {
    for v in ["0", "2", "4294967296", "18446744073709551615"] {
        assert!(
            matches!(dec(&hello_json("garbage", "garbage", v)).unwrap(), Message::HelloUnsupported(_)),
            "v {v}"
        );
    }
    for v in ["1.0", "1e0", "-1", "true", "null", "\"1\"", "-0.0"] {
        assert_eq!(code(dec(&hello_json(B64_32, UID, v))), "invalid_message", "v {v}");
    }
    // v==1 → every field validated
    assert_eq!(code(dec(&hello_json("garbage", UID, "1"))), "invalid_message");
    assert!(matches!(dec(&hello_json(B64_32, UID, "1")).unwrap(), Message::Hello(_)));
}

#[test]
fn msg_deep_nesting_in_ignored_member() {
    // Ruling R1: nesting depth (objects + arrays, outermost object = 1) above 32
    // is invalid_json, even inside an ignored member.
    // `{"t":"ping","x":` + k containers + `}`: total depth = 1 + k.
    let arrays = |k: usize| format!(r#"{{"t":"ping","x":{}{}}}"#, "[".repeat(k), "]".repeat(k));
    // k objects: k-1 levels of {"a": ...} around an empty {}.
    let objects = |k: usize| {
        format!(r#"{{"t":"ping","x":{}{{}}{}}}"#, "{\"a\":".repeat(k - 1), "}".repeat(k - 1))
    };
    for (name, make) in [("arrays", &arrays as &dyn Fn(usize) -> String), ("objects", &objects)] {
        assert_eq!(
            dec(&make(31)).unwrap_or_else(|e| panic!("{name} depth 32: {e:?}")),
            Message::Ping
        );
        assert_eq!(code(dec(&make(32))), "invalid_json", "{name} depth 33");
    }
    // 200 levels: invalid_json
    let depth = 200;
    let j = format!(r#"{{"t":"ping","x":{}{}}}"#, "[".repeat(depth), "]".repeat(depth));
    assert_eq!(code(dec(&j)), "invalid_json");
    let j = format!(r#"{{"t":"future","x":{}{}}}"#, "[".repeat(depth), "]".repeat(depth));
    assert_eq!(code(dec(&j)), "invalid_json");
}

#[test]
fn msg_extreme_nesting_no_panic() {
    // must not stack-overflow, whatever the result
    for open in ["[", "{\"a\":"] {
        let n = 30_000;
        let s = format!(r#"{{"t":"ping","x":{}"#, open.repeat(n));
        let s = &s[..s.len().min(MAX_MESSAGE_BYTES)];
        let _ = Message::from_json(s.as_bytes());
    }
    let s = "[".repeat(MAX_MESSAGE_BYTES);
    let _ = Message::from_json(s.as_bytes());
}

#[test]
fn msg_lone_surrogate_in_ignored_member() {
    // Ruling R1: a lone surrogate escape anywhere in the document (ignored
    // members and keys included) is invalid_json.
    for s in [r"\ud800", r"\udfff", r"\ud800A", r"\udc00\ud800", r"\ud800A", r"\ud800\ud800"] {
        let j = format!(r#"{{"t":"ping","x":"{s}"}}"#);
        assert_eq!(code(dec(&j)), "invalid_json", "{s}");
        let j = format!(r#"{{"t":"ping","x":["{s}"]}}"#);
        assert_eq!(code(dec(&j)), "invalid_json", "{s}");
        let j = format!(r#"{{"t":"ping","{s}":1}}"#);
        assert_eq!(code(dec(&j)), "invalid_json", "{s}");
    }
    // a valid pair in an ignored member is fine
    assert_eq!(dec(r#"{"t":"ping","x":"😀"}"#).unwrap(), Message::Ping);
}

#[test]
fn msg_surrogates_in_text() {
    // valid pair decodes
    match dec(&utt_json("\x5Cud83d\x5Cude00")).unwrap() {
        Message::Utt(u) => assert_eq!(u.text, "\u{1F600}"),
        m => panic!("{m:?}"),
    }
    // lone surrogates cannot be a UTF-8 string: must be rejected, never panic
    for s in [r"\ud800", r"\ude00", r"\ud83dA", r"\ude00\ud83d"] {
        assert!(dec(&utt_json(s)).is_err(), "{s}");
    }
}

#[test]
fn msg_nul_and_control_chars() {
    match dec(&utt_json(r"a\u0000b")).unwrap() {
        Message::Utt(u) => assert_eq!(u.text.as_bytes(), b"a\0b"),
        m => panic!("{m:?}"),
    }
    // raw (unescaped) control chars inside a string are invalid JSON
    for c in ['\0', '\u{1}', '\n', '\u{1f}'] {
        assert_eq!(code(dec(&utt_json(&c.to_string()))), "invalid_json", "{c:?}");
    }
    // raw NUL after the value is trailing garbage
    assert_eq!(code(Message::from_json(b"{\"t\":\"ping\"}\0")), "invalid_json");
    // non-JSON whitespace
    for ws in ["\u{a0}", "\u{c}", "\u{feff}", "\u{2028}"] {
        assert_eq!(code(dec(&format!("{ws}{{\"t\":\"ping\"}}"))), "invalid_json", "{ws:?}");
    }
    assert_eq!(dec(" \t\r\n{\"t\":\"ping\"} \t\r\n").unwrap(), Message::Ping);
}

#[test]
fn msg_text_limits_after_unescape() {
    let ok = |t: &str| match dec(&utt_json(t)).unwrap_or_else(|e| panic!("{e:?}")) {
        Message::Utt(u) => u.text.len(),
        m => panic!("{m:?}"),
    };
    assert_eq!(ok(&"a".repeat(32_000)), 32_000);
    assert_eq!(code(dec(&utt_json(&"a".repeat(32_001)))), "text_too_long");
    // 4-byte chars at the boundary
    assert_eq!(ok(&"\u{1F600}".repeat(8_000)), 32_000);
    assert_eq!(code(dec(&utt_json(&format!("{}a", "\u{1F600}".repeat(8_000))))), "text_too_long");
    assert_eq!(code(dec(&utt_json(&format!("{}\u{1F600}", "a".repeat(31_997))))), "text_too_long");
    assert_eq!(ok(&format!("{}\u{1F600}", "a".repeat(31_996))), 32_000);
    // 3-byte chars
    assert_eq!(ok(&format!("{}ab", "\u{65e5}".repeat(10_666))), 32_000);
    assert_eq!(code(dec(&utt_json(&"\u{65e5}".repeat(10_667)))), "text_too_long");
    // escaped: raw JSON is ~64 KB but unescaped text is exactly 32,000 bytes → allowed
    let esc = format!("{}ab", "\x5Cu65e5".repeat(10_666));
    assert!(esc.len() + 100 < MAX_MESSAGE_BYTES);
    assert_eq!(ok(&esc), 32_000);
    let esc = "\x5Cu65e5".repeat(10_667);
    assert_eq!(code(dec(&utt_json(&esc))), "text_too_long");
    // short raw JSON whose text is just over the limit after unescape
    let esc = format!("{}{}", "a".repeat(31_999), "\x5Cu00e9");
    assert_eq!(code(dec(&utt_json(&esc))), "text_too_long");
    // escaped surrogate pairs: 12 raw bytes each → raw size > 64 KiB
    let esc = "\x5Cud83d\x5Cude00".repeat(8_000);
    assert_eq!(code(dec(&utt_json(&esc))), "message_too_large");
}

#[test]
fn msg_encode_expansion_past_64k() {
    // 32,000 control chars are a legal text but escape to 6 bytes each.
    let m = sample_utt(&"\u{1}".repeat(32_000));
    assert_eq!(code(m.to_json()), "message_too_large");
    let (mut p, _) = pair();
    assert_eq!(code(p.seal_message(&m)), "message_too_large");
    assert_eq!(p.next_send_counter(), Some(0));
    // text over the limit refused by encoder
    assert_eq!(code(sample_utt(&"a".repeat(32_001)).to_json()), "text_too_long");
}

#[test]
fn msg_size_boundary() {
    let prefix = r#"{"t":"ping","pad":""#;
    let suffix = r#""}"#;
    let fill = MAX_MESSAGE_BYTES - prefix.len() - suffix.len();
    let j = format!("{prefix}{}{suffix}", "a".repeat(fill));
    assert_eq!(j.len(), MAX_MESSAGE_BYTES);
    assert_eq!(dec(&j).unwrap(), Message::Ping);
    let j = format!("{prefix}{}{suffix}", "a".repeat(fill + 1));
    assert_eq!(code(dec(&j)), "message_too_large");
}

#[test]
fn msg_invalid_utf8_variants() {
    let base = br#"{"t":"ping","x":"#.to_vec();
    for bad in [
        &b"\xC0\xAF"[..],         // overlong '/'
        &b"\xE0\x80\xAF"[..],     // overlong 3-byte
        &b"\xED\xA0\x80"[..],     // UTF-8-encoded surrogate
        &b"\xF4\x90\x80\x80"[..], // > U+10FFFF
        &b"\xF8\x88\x80\x80\x80"[..],
        &b"\xE6\x97"[..], // truncated
        &b"\x80"[..],
        &b"\xFF"[..],
    ] {
        let mut j = base.clone();
        j.push(b'"');
        j.extend_from_slice(bad);
        j.extend_from_slice(b"\"}");
        assert_eq!(code(Message::from_json(&j)), "invalid_json", "{bad:x?}");
    }
    // BOM, also after whitespace
    assert_eq!(code(Message::from_json(b"\xEF\xBB\xBF{\"t\":\"ping\"}")), "invalid_json");
    assert_eq!(code(Message::from_json(b" \xEF\xBB\xBF{\"t\":\"ping\"}")), "invalid_json");
}

#[test]
fn msg_t_matching() {
    for t in ["PING", "Ping", "ping ", " ping", "ping\u{0}", "p\u{130}ng", "utt\u{200b}"] {
        let j = serde_json::json!({ "t": t }).to_string();
        assert_eq!(dec(&j).unwrap(), Message::Unknown { t: t.into() }, "{t:?}");
    }
    for t in ["1", "null", "[]", "{}", "true"] {
        assert_eq!(code(dec(&format!(r#"{{"t":{t}}}"#))), "invalid_message");
    }
}

#[test]
fn msg_duplicate_keys_no_panic() {
    for j in [
        r#"{"t":"ping","t":"pong"}"#.to_string(),
        utt_with("rev", "1,\"rev\":4294967296"),
        utt_with("text", "\"a\",\"text\":\"b\""),
        format!(r#"{{"t":"pair_result","ok":true,"ok":false,"mac":"{B64_32}"}}"#),
    ] {
        let _ = dec(&j);
    }
}

#[test]
fn msg_uuid_forms() {
    let up = UID.to_uppercase();
    match dec(&format!(r#"{{"t":"ack","id":"{up}","rev":1}}"#)).unwrap() {
        Message::Ack(a) => assert_eq!(format_uuid(&a.id), UID),
        m => panic!("{m:?}"),
    }
    let mixed = "0F8fAd5B-d9cb-469F-a165-70867728950E";
    assert!(parse_uuid(mixed).is_ok());
    for bad in [
        format!("{{{UID}}}"),
        format!("urn:uuid:{UID}"),
        UID.replace('-', ""),
        format!("{UID} "),
        format!(" {UID}"),
        format!("{UID}\n"),
        UID[..35].to_string(),
        format!("{UID}0"),
        "0f8fad5bd-9cb-469f-a165-70867728950e".into(), // hyphen shifted
        "0f8fad5b-d9cb-469f-a16570867728950e-".into(),
        "0f8fad5b-d9cb-469f-a165-70867728950g".into(),
        "0f8fad5b-d9cb-469f-a165-7086772895\u{ff10}".into(), // fullwidth digit
        "0f8fad5b_d9cb_469f_a165_70867728950e".into(),
        "+f8fad5b-d9cb-469f-a165-70867728950e".into(),
        "".into(),
    ] {
        assert!(parse_uuid(&bad).is_err(), "{bad:?}");
        let j = serde_json::json!({"t":"ack","id":bad,"rev":1}).to_string();
        assert_eq!(code(dec(&j)), "invalid_message", "{bad:?}");
    }
}

#[test]
fn msg_base64_strictness() {
    let good = encode(&[0xAB; 32]);
    assert_eq!(decode_fixed::<32>(&good).unwrap(), [0xAB; 32]);
    let zeros = encode(&[0u8; 32]); // "AAAA...AAA="
    let mut bad: Vec<String> = vec![
        zeros.trim_end_matches('=').into(),     // unpadded
        format!("{zeros}="),                     // extra pad
        format!("{}==", &zeros[..42]),           // wrong pad count, same length
        format!("{}A", &zeros[..43]),            // pad replaced
        format!("={}", &zeros[..43]),            // pad at start
        format!("{}={}", &zeros[..20], &zeros[21..]), // pad in middle
        format!("{zeros}\n"),
        format!("{}\r\n{}", &zeros[..22], &zeros[22..]),
        format!("{} {}", &zeros[..22], &zeros[23..]),
        encode(&[0xFB; 32]).replace('+', "-").replace('/', "_"),
        encode(&[0u8; 31]),
        encode(&[0u8; 33]),
        encode(&[0u8; 30]),
        encode(&[0u8; 0]),
        encode(&[0u8; 64]),
        "====".into(),
        "".into(),
        format!("{}\u{c0}=", &zeros[..42]),
        format!("{}A=\u{0}", &zeros[..42]),
    ];
    // every non-zero trailing-bit variant
    for c in "BCDEFGHIJKLMNOPQRSTUVWXYZ".chars().filter(|c| (*c as u8 - b'A') & 3 != 0) {
        bad.push(format!("{}{c}=", &zeros[..42]));
    }
    for b in &bad {
        assert!(decode_fixed::<32>(b).is_err(), "{b:?}");
        let j = serde_json::json!({"t":"pair_request","nonce_p":b}).to_string();
        assert_eq!(code(dec(&j)), "invalid_message", "{b:?}");
    }
}

#[test]
fn msg_wrong_length_macs_rejected() {
    for n in [0usize, 1, 16, 31, 33, 48, 64] {
        let j = format!(r#"{{"t":"pair_confirm","mac":"{}"}}"#, encode(&vec![7u8; n]));
        assert_eq!(code(dec(&j)), "invalid_message", "len {n}");
        let j = format!(r#"{{"t":"pair_result","ok":true,"mac":"{}"}}"#, encode(&vec![7u8; n]));
        assert_eq!(code(dec(&j)), "invalid_message", "len {n}");
    }
}

#[test]
fn msg_null_required_fields() {
    for f in ["id", "rev", "state", "text", "ts"] {
        assert_eq!(code(dec(&utt_with(f, "null"))), "invalid_message", "{f}");
    }
    assert_eq!(code(dec(r#"{"t":"pair_request","nonce_p":null}"#)), "invalid_message");
    assert_eq!(code(dec(r#"{"t":"error","code":null}"#)), "invalid_message");
    assert_eq!(dec(r#"{"t":"error","code":"zzz_new"}"#).unwrap(),
        Message::Error(ErrorMsg::new("zzz_new", "")));
}

#[test]
fn msg_encodable_roundtrip_with_hostile_strings() {
    for s in ["\u{0}", "\"\\/\u{1f}", "\u{2028}\u{2029}", "\u{FEFF}x", "\u{10FFFF}"] {
        let m = sample_utt(s);
        assert_eq!(Message::from_json(&m.to_json().unwrap()).unwrap(), m);
        let e = Message::Error(ErrorMsg::new(s, s));
        assert_eq!(Message::from_json(&e.to_json().unwrap()).unwrap(), e);
    }
    assert_eq!(code(Message::Unknown { t: "x".into() }.to_json()), "not_encodable");
    assert_eq!(code(Message::PairResult(PairResult { ok: false, mac: Some([0; 32]) }).to_json()), "not_encodable");
    assert_eq!(code(Message::PairResult(PairResult { ok: true, mac: None }).to_json()), "not_encodable");
}

// ================================================================ CRYPTO

#[test]
fn cr_pairing_code_parse() {
    for (s, v) in [("000000", 0), ("000042", 42), ("012345", 12_345), ("999999", 999_999)] {
        let c: PairingCode = s.parse().unwrap();
        assert_eq!(c.value(), v);
        assert_eq!(c.to_string(), s);
        assert_eq!(&c.ascii(), s.as_bytes());
    }
    for s in [
        "", "12345", "1234567", "42", "0", " 123456", "123456 ", "123 456", "123456\n",
        "\t123456", "+12345", "-12345", "12345a", "0x1234", "12345\u{0}", "1e5000",
        "١٢٣٤٥٦",       // Arabic-Indic
        "١٢٣",          // 3 Arabic-Indic digits = 6 bytes
        "۱۲۳۴۵۶",       // Extended Arabic-Indic
        "１２３４５６", // fullwidth
        "१२३४५६",       // Devanagari
        "12345\u{663}",
        "１２３",       // fullwidth, 9 bytes
        "\u{0}\u{0}\u{0}\u{0}\u{0}\u{0}",
        "12³456",       // superscript 3
    ] {
        assert_eq!(code(s.parse::<PairingCode>()), "invalid_code", "{s:?}");
    }
    assert!(PairingCode::from_u32(1_000_000).is_none());
    assert!(PairingCode::from_u32(u32::MAX).is_none());
    assert_eq!(PairingCode::from_u32(7).unwrap().to_string(), "000007");
    // Debug must not leak the code
    assert!(!format!("{:?}", PairingCode::from_u32(123_456).unwrap()).contains("123456"));
}

#[test]
fn cr_pairing_code_distribution() {
    let mut buckets = [0u32; 10];
    let n = 200_000;
    for _ in 0..n {
        let c = PairingCode::generate();
        assert!(c.value() < 1_000_000);
        buckets[(c.value() / 100_000) as usize] += 1;
    }
    for b in buckets {
        let frac = b as f64 / n as f64;
        assert!((0.09..0.11).contains(&frac), "{buckets:?}");
    }
}

#[test]
fn cr_low_order_points_rejected() {
    // RFC 7748 / Bernstein list of low-order u-coordinates, plus non-canonical (≥ p) and high-bit variants.
    let hex_pts = [
        "0000000000000000000000000000000000000000000000000000000000000000",
        "0100000000000000000000000000000000000000000000000000000000000000",
        "e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800",
        "5f9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f1157",
        "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f", // p-1
        "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f", // p
        "eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f", // p+1
        "0000000000000000000000000000000000000000000000000000000000000080",
        "0100000000000000000000000000000000000000000000000000000000000080",
        "e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b880", // order-8 point, bit 255 set (masked per RFC 7748)
        "5f9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f11d7",
        "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", // p-1 with bit 255 set
        "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", // p with bit 255 set
    ];
    for _ in 0..4 {
        let me = IdentityKeyPair::generate();
        for h in hex_pts {
            let p: [u8; 32] = hex::decode(h).unwrap().try_into().unwrap();
            assert_eq!(code(me.shared_secret(&p)), "non_contributory", "{h}");
        }
    }
}

fn pairing_fixture() -> ([u8; 32], [u8; 32], [u8; 32], [u8; 32], [u8; 32]) {
    let p = IdentityKeyPair::from_secret_bytes([1; 32]);
    let d = IdentityKeyPair::from_secret_bytes([2; 32]);
    let ss_p = p.shared_secret(&d.public_bytes()).unwrap();
    let ss_d = d.shared_secret(&p.public_bytes()).unwrap();
    assert_eq!(ss_p.as_bytes(), ss_d.as_bytes());
    let code: PairingCode = "004217".parse().unwrap();
    let k = derive_pair_key(&ss_p, &[3; 32], &[4; 32], &code);
    (k, p.public_bytes(), d.public_bytes(), *ss_p.as_bytes(), [0; 32])
}

#[test]
fn cr_mac_verification_attacks() {
    let (k, pp, pd, ss, _) = pairing_fixture();
    let mac_p = phone_confirm_mac(&k, &pp, &pd);
    let mac_d = desktop_result_mac(&k, &pp, &pd);
    verify_phone_confirm_mac(&k, &pp, &pd, &mac_p).unwrap();
    verify_desktop_result_mac(&k, &pp, &pd, &mac_d).unwrap();
    // role confusion / reflection
    assert_eq!(code(verify_desktop_result_mac(&k, &pp, &pd, &mac_p)), "bad_mac");
    assert_eq!(code(verify_phone_confirm_mac(&k, &pp, &pd, &mac_d)), "bad_mac");
    // swapped pubkeys
    assert_eq!(code(verify_phone_confirm_mac(&k, &pd, &pp, &mac_p)), "bad_mac");
    // all-zero / all-FF
    assert_eq!(code(verify_phone_confirm_mac(&k, &pp, &pd, &[0; 32])), "bad_mac");
    assert_eq!(code(verify_phone_confirm_mac(&k, &pp, &pd, &[0xFF; 32])), "bad_mac");
    // every single-bit flip
    for i in 0..256 {
        let mut m = mac_p;
        m[i / 8] ^= 1 << (i % 8);
        assert_eq!(code(verify_phone_confirm_mac(&k, &pp, &pd, &m)), "bad_mac");
    }
    // wrong code (incl. leading-zero confusion 004217 vs 421700 vs 42170)
    let ssx = SharedSecret::from_bytes(ss);
    for c in ["421700", "004218", "000000", "042170"] {
        let k2 = derive_pair_key(&ssx, &[3; 32], &[4; 32], &c.parse().unwrap());
        assert_ne!(k2, k, "{c}");
        assert_eq!(code(verify_phone_confirm_mac(&k2, &pp, &pd, &mac_p)), "bad_mac");
    }
    // swapped nonces → different key
    let k3 = derive_pair_key(&ssx, &[4; 32], &[3; 32], &"004217".parse().unwrap());
    assert_ne!(k3, k);
}

#[test]
fn cr_session_key_order_and_separation() {
    let ss = SharedSecret::from_bytes([9; 32]);
    let a = derive_session_key(&ss, &[1; 32], &[2; 32]);
    let b = derive_session_key(&ss, &[2; 32], &[1; 32]);
    assert_ne!(a, b);
    // session key and pair key domain-separated even with identical salts
    let k = derive_pair_key(&ss, &[1; 32], &[2; 32], &PairingCode::from_u32(0).unwrap());
    assert_ne!(a, k);
}

// ================================================================ FUZZ

#[test]
fn fuzz_reassembler_no_panic() {
    let mut rng = Rng(0xADBE_EF00_1234_5678);
    let mut r = Reassembler::new();
    for i in 0..300_000 {
        let len = match rng.below(10) {
            0 => rng.below(3),
            1 => rng.below(70_000),
            _ => rng.below(300),
        };
        let mut f = rng.bytes(len.min(if i % 1000 == 0 { 70_000 } else { 600 }));
        if !f.is_empty() && rng.below(4) != 0 {
            f[0] &= 0x03;
        }
        if f.len() >= 3 && rng.below(2) == 0 {
            f[1] = 0;
            f[2] = (rng.below(3)) as u8;
        }
        if let Ok(Some(m)) = r.push(&f) {
            assert!(m.len() <= MAX_MESSAGE_BYTES);
            assert!(!r.has_partial());
        }
    }
}

#[test]
fn fuzz_split_reassemble_roundtrip() {
    let mut rng = Rng(42);
    for _ in 0..500 {
        let len = rng.below(5_000);
        let msg = rng.bytes(len);
        let mtu = 20 + rng.below(600);
        let mut s = FrameSplitter::with_seq(rng.next() as u16);
        let fr = s.split(&msg, mtu).unwrap();
        assert!(fr.iter().all(|f| f.len() <= mtu));
        assert!(fr[..fr.len() - 1].iter().all(|f| f.len() == mtu));
        let mut r = Reassembler::new();
        let mut out = None;
        for f in &fr {
            out = r.push(f).unwrap();
        }
        assert_eq!(out.unwrap(), msg);
    }
}

#[test]
fn fuzz_envelope_no_panic_and_window_integrity() {
    let mut rng = Rng(7);
    let (mut p, _) = pair();
    let valid: Vec<Vec<u8>> = (0..16)
        .map(|i| p.seal_message(&sample_utt(&"x".repeat(i * 10))).unwrap())
        .collect();
    let mut d = SessionCipher::new(&KEY, Role::Desktop);
    for _ in 0..100_000 {
        let mut e = match rng.below(3) {
            0 => {
                let n = rng.below(200);
                rng.bytes(n)
            }
            _ => valid[rng.below(valid.len())].clone(),
        };
        // mutate
        for _ in 0..rng.below(4) {
            if e.is_empty() {
                break;
            }
            match rng.below(3) {
                0 => {
                    let i = rng.below(e.len());
                    e[i] ^= 1 << rng.below(8);
                }
                1 => {
                    let n = rng.below(e.len() + 1);
                    e.truncate(n)
                }
                _ => {
                    let b = rng.byte();
                    e.push(b)
                }
            }
        }
        let before = d.last_received_counter();
        let is_valid = valid.contains(&e);
        let r1 = decode_envelope(&e, Some(&mut d));
        if !is_valid {
            // forged envelopes must never be accepted as encrypted, nor move the window
            assert_eq!(d.last_received_counter(), before, "window moved by a forged envelope");
            if e.first() == Some(&1) {
                assert!(r1.is_err(), "forged encrypted envelope accepted");
            }
        } else if r1.is_err() {
            assert_eq!(d.last_received_counter(), before);
        }
        let _ = decode_envelope(&e, None);
        let _ = Envelope::parse(&e);
    }
}

fn rand_json(rng: &mut Rng, depth: usize) -> String {
    let pick = if depth > 6 { rng.below(6) } else { rng.below(9) };
    match pick {
        0 => "null".into(),
        1 => ["true", "false"][rng.below(2)].into(),
        2 => ["0", "-0", "1", "-1", "4294967295", "4294967296", "1.5", "1e400", "-1e-400",
              "18446744073709551615", "18446744073709551616", "1E2", "0.0"][rng.below(13)].into(),
        3 | 4 => {
            let pool = ["ping", "utt", "hello", "pair_result", "", "\\ud800", "\\u0000",
                        "\\ud83d\\ude00", UID, B64_32, "final", "partial", "edit", "é"];
            format!("\"{}\"", pool[rng.below(pool.len())])
        }
        5 => {
            let n = rng.below(40);
            let s: String = (0..n).map(|_| (b' ' + rng.below(94) as u8) as char)
                .filter(|c| *c != '"' && *c != '\\').collect();
            format!("\"{s}\"")
        }
        6 => {
            let n = rng.below(4);
            let items: Vec<String> = (0..n).map(|_| rand_json(rng, depth + 1)).collect();
            format!("[{}]", items.join(","))
        }
        _ => {
            let keys = ["t", "v", "id", "rev", "state", "text", "ts", "ok", "mac", "code",
                        "msg", "device_id", "name", "pub", "paired", "session_nonce",
                        "nonce_p", "nonce_d", "x"];
            let n = rng.below(8);
            let mut items: Vec<String> = (0..n)
                .map(|_| format!("\"{}\":{}", keys[rng.below(keys.len())], rand_json(rng, depth + 1)))
                .collect();
            if depth == 0 {
                let ts = ["ping", "pong", "utt", "ack", "hello", "pair_request", "pair_challenge",
                          "pair_confirm", "pair_result", "error", "zzz"];
                items.insert(0, format!("\"t\":\"{}\"", ts[rng.below(ts.len())]));
            }
            format!("{{{}}}", items.join(","))
        }
    }
}

#[test]
fn fuzz_message_decode_invariants() {
    let mut rng = Rng(0x5EED);
    for i in 0..200_000 {
        let input: Vec<u8> = if i % 3 == 0 {
            let n = rng.below(120);
            rng.bytes(n)
        } else {
            let mut s = rand_json(&mut rng, 0).into_bytes();
            if i % 7 == 0 && !s.is_empty() {
                let j = rng.below(s.len());
                s[j] = rng.byte();
            }
            s
        };
        match Message::from_json(&input) {
            Ok(m) => {
                if let Message::Utt(u) = &m {
                    assert!(u.text.len() <= 32_000);
                }
                if let Message::PairResult(r) = &m {
                    assert_eq!(r.ok, r.mac.is_some(), "pair_result invariant");
                }
                if let Ok(j) = m.to_json() {
                    assert_eq!(Message::from_json(&j).unwrap(), m, "roundtrip");
                }
                // plaintext policy consistency
                if let Ok(env) = encode_plaintext(&m) {
                    assert_eq!(decode_envelope(&env, None).unwrap(), m);
                }
            }
            Err(e) => {
                let _ = e.code();
            }
        }
    }
}

#[test]
fn fuzz_field_parsers_canonical() {
    let mut rng = Rng(99);
    let alpha = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=-_ \n";
    let hexa = b"0123456789abcdefABCDEF-{}gx ";
    let digits = b"0123456789 -+a";
    for _ in 0..200_000 {
        // base64: if accepted, re-encoding must reproduce the input exactly (canonical)
        let n = 40 + rng.below(8);
        let s: String = (0..n).map(|_| alpha[rng.below(alpha.len())] as char).collect();
        if let Ok(b) = decode_fixed::<32>(&s) {
            assert_eq!(encode(&b), s, "non-canonical base64 accepted");
        }
        // mutate a canonical value
        let mut c = encode(&rng.bytes(32)).into_bytes();
        let i = rng.below(c.len());
        c[i] = alpha[rng.below(alpha.len())];
        let c = String::from_utf8(c).unwrap();
        if let Ok(b) = decode_fixed::<32>(&c) {
            assert_eq!(encode(&b), c, "non-canonical base64 accepted");
        }
        // uuid
        let n = 34 + rng.below(4);
        let s: String = (0..n).map(|_| hexa[rng.below(hexa.len())] as char).collect();
        if let Ok(u) = parse_uuid(&s) {
            assert_eq!(format_uuid(&u), s.to_ascii_lowercase());
        }
        // pairing code
        let n = 4 + rng.below(4);
        let s: String = (0..n).map(|_| digits[rng.below(digits.len())] as char).collect();
        if let Ok(pc) = s.parse::<PairingCode>() {
            assert_eq!(pc.to_string(), s);
        }
    }
}

// ================================================================ FIXER ADDITIONS

#[test]
fn msg_duplicate_keys_rejected() {
    // Ruling R1: duplicate keys at any level are invalid_json (so a duplicate
    // `t` can never change dispatch).
    for j in [
        r#"{"t":"ping","t":"pong"}"#.to_string(),
        r#"{"t":"ping","t":"pong"}"#.to_string(),
        utt_with("rev", "1,\"rev\":4294967296"),
        utt_with("text", "\"a\",\"text\":\"b\""),
        format!(r#"{{"t":"pair_result","ok":true,"ok":false,"mac":"{B64_32}"}}"#),
        r#"{"t":"ping","x":{"a":1,"a":1}}"#.to_string(),
        r#"{"t":"zzz","x":[[{"b":[],"b":[]}]]}"#.to_string(),
    ] {
        assert_eq!(code(dec(&j)), "invalid_json", "{j}");
        assert_eq!(code(decode_envelope(&plain_env(&j), None)), "invalid_json", "{j}");
    }
}

#[test]
fn msg_utt_sizing_helper_is_safe() {
    // Ruling R2: if utt_text_fits(text), the utt always encodes and seals,
    // whatever its other fields; max_text_prefix is a char-boundary prefix that fits.
    let mut rng = Rng(0xF17);
    let pool = ["a", "\"", "\\", "\u{1}", "\n", "\u{7f}", "é", "日", "\u{1F600}", "\u{2028}"];
    for _ in 0..300 {
        let n = rng.below(40_000);
        let f = pool[rng.below(pool.len())];
        let g = pool[rng.below(pool.len())];
        let text: String = (0..n / 4).map(|i| if i % 3 == 0 { g } else { f }).collect();
        let prefix = vq_protocol::max_text_prefix(&text);
        assert!(text.starts_with(prefix));
        assert!(vq_protocol::utt_text_fits(prefix));
        assert_eq!(vq_protocol::utt_text_fits(&text), prefix.len() == text.len());
        let m = Message::Utt(Utt {
            id: parse_uuid(UID).unwrap(),
            rev: u32::MAX,
            state: UttState::Partial,
            text: prefix.to_owned(),
            ts: u64::MAX,
        });
        let (mut p, mut d) = pair();
        let env = p.seal_message(&m).unwrap();
        assert_eq!(decode_envelope(&env, Some(&mut d)).unwrap(), m);
        // one more character would not fit (unless the whole text already did)
        if prefix.len() < text.len() {
            let next = text[prefix.len()..].chars().next().unwrap();
            assert!(!vq_protocol::utt_text_fits(&format!("{prefix}{next}")));
        }
    }
}

#[test]
fn env_provenance_and_in_session_policy() {
    use vq_protocol::{check_in_session, decode_inbound, Inbound};
    let (mut p, mut d) = pair();
    // a plaintext `error{unknown_peer}` injected mid-session is visibly unauthenticated
    let inj = plain_env(r#"{"t":"error","code":"unknown_peer"}"#);
    let got = decode_inbound(&inj, Some(&mut d)).unwrap();
    assert!(matches!(got, Inbound::Plaintext(Message::Error(_))));
    assert!(!got.is_authenticated());
    // plaintext hello / pairing messages are refused once Secure
    for j in [
        hello_json(B64_32, UID, "1"),
        hello_json(B64_32, UID, "7"),
        format!(r#"{{"t":"pair_request","nonce_p":"{B64_32}"}}"#),
        format!(r#"{{"t":"pair_confirm","mac":"{B64_32}"}}"#),
        r#"{"t":"pair_result","ok":false}"#.to_string(),
    ] {
        let got = decode_inbound(&plain_env(&j), Some(&mut d)).unwrap();
        assert_eq!(code(check_in_session(&got)), "not_allowed_in_session", "{j}");
    }
    // and encrypted ones too (exactly one hello per connection)
    let env = p.seal(hello_json(B64_32, UID, "1").as_bytes()).unwrap();
    let got = decode_inbound(&env, Some(&mut d)).unwrap();
    assert!(got.is_authenticated());
    assert_eq!(code(check_in_session(&got)), "not_allowed_in_session");
    let env = p.seal_message(&sample_utt("x")).unwrap();
    assert!(check_in_session(&decode_inbound(&env, Some(&mut d)).unwrap()).is_ok());
}
