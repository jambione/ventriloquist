//! Regenerates `protocol/vectors/*.json`.
//!
//!     cargo run -p vq-protocol --example gen_vectors
//!
//! All inputs are fixed, so output is deterministic. The committed JSON files
//! are the authority: `tests/vectors.rs` checks the library against them, and
//! this generator only exists to (re)create them after an intentional change.

#![allow(clippy::type_complexity)]

use std::fs;
use std::path::PathBuf;

use serde_json::{json, Value};
use vq_protocol::crypto::{self, pair_info, PairingCode, SESSION_INFO};
use vq_protocol::envelope::{nonce, seal_with, Direction};
use vq_protocol::{
    b64, encode_plaintext, Error, FrameSplitter, IdentityKeyPair, Message, Reassembler,
    SessionCipher,
};

fn hx(b: &[u8]) -> String {
    hex::encode(b)
}

fn pattern(start: u8) -> [u8; 32] {
    let mut a = [0u8; 32];
    for (i, b) in a.iter_mut().enumerate() {
        *b = start.wrapping_add(i as u8);
    }
    a
}

fn h32(s: &str) -> [u8; 32] {
    hex::decode(s).unwrap().try_into().unwrap()
}

fn fill(prefix: &[u8], byte: u8, count: usize, suffix: &[u8]) -> (Value, Vec<u8>) {
    let mut v = prefix.to_vec();
    v.extend(std::iter::repeat_n(byte, count));
    v.extend_from_slice(suffix);
    let mut o = serde_json::Map::new();
    if !prefix.is_empty() {
        o.insert("prefix_hex".into(), json!(hx(prefix)));
    }
    o.insert("fill_hex".into(), json!(hx(&[byte])));
    o.insert("fill_count".into(), json!(count));
    if !suffix.is_empty() {
        o.insert("suffix_hex".into(), json!(hx(suffix)));
    }
    (Value::Object(o), v)
}

/// Hex, or for large inputs dominated by one repeated byte, the
/// `{prefix_hex, fill_hex, fill_count, suffix_hex}` form.
fn bytes_value(b: &[u8]) -> Value {
    if b.len() <= 4096 {
        return json!(hx(b));
    }
    // longest run of one byte value
    let (mut best_start, mut best_len, mut i) = (0, 0, 0);
    while i < b.len() {
        let mut j = i;
        while j < b.len() && b[j] == b[i] {
            j += 1;
        }
        if j - i > best_len {
            best_start = i;
            best_len = j - i;
        }
        i = j;
    }
    if best_len < 1024 {
        return json!(hx(b));
    }
    let (v, rebuilt) = fill(
        &b[..best_start],
        b[best_start],
        best_len,
        &b[best_start + best_len..],
    );
    assert_eq!(rebuilt, b);
    v
}

fn dir_name(d: Direction) -> &'static str {
    match d {
        Direction::PhoneToDesktop => "phone_to_desktop",
        Direction::DesktopToPhone => "desktop_to_phone",
    }
}

// ---------------------------------------------------------------- framing

fn framing() -> Value {
    let mut split = vec![];
    let msg_100: Vec<u8> = (0..100u8).collect();
    let msg_1000: Vec<u8> = (0..1000u32).map(|i| (i * 7 % 256) as u8).collect();
    let cases: Vec<(&str, usize, u16, Vec<u8>)> = vec![
        ("empty message, mtu 20", 20, 0, vec![]),
        ("1 byte, mtu 20", 20, 0, vec![0xAB]),
        (
            "exactly one chunk (17 bytes), mtu 20",
            20,
            1,
            (1..=17).collect(),
        ),
        (
            "one byte over one chunk (18 bytes), mtu 20",
            20,
            2,
            (1..=18).collect(),
        ),
        (
            "two full chunks (34 bytes), mtu 20",
            20,
            3,
            (1..=34).collect(),
        ),
        ("100 bytes, mtu 20", 20, 0x0102, msg_100.clone()),
        ("100 bytes, mtu 23", 23, 0x7FFF, msg_100.clone()),
        (
            "100 bytes, mtu 185 (single frame)",
            185,
            0x8000,
            msg_100.clone(),
        ),
        ("1000 bytes, mtu 185", 185, 42, msg_1000.clone()),
        ("1000 bytes, mtu 244", 244, 0xFFFE, msg_1000.clone()),
        ("1000 bytes, mtu 512", 512, 0xFFFF, msg_1000.clone()),
        (
            "ASCII JSON, mtu 20, seq wraps after this",
            20,
            0xFFFF,
            br#"{"t":"ping"}"#.to_vec(),
        ),
    ];
    for (name, mtu, seq, msg) in cases {
        let mut s = FrameSplitter::with_seq(seq);
        let frames = s.split(&msg, mtu).unwrap();
        split.push(json!({
            "name": name, "mtu": mtu, "seq": seq, "message": hx(&msg),
            "frames": frames.iter().map(|f| hx(f)).collect::<Vec<_>>(),
            "next_seq": s.next_seq(),
        }));
    }

    let (big_v, big) = fill(&[], 0x41, 65_537, &[]);
    let (max_v, max) = fill(&[], 0x41, 65_536, &[]);
    let mut s = FrameSplitter::new();
    assert_eq!(
        s.split(&big, 20).unwrap_err(),
        Error::MessageTooLarge(65_537)
    );
    let max_frames = s.split(&max, 512).unwrap();
    let split_errors = json!([
        {"name": "mtu 19 is below the minimum", "mtu": 19, "message": "00", "error": "mtu_too_small"},
        {"name": "mtu 3", "mtu": 3, "message": "00", "error": "mtu_too_small"},
        {"name": "mtu 0", "mtu": 0, "message": "", "error": "mtu_too_small"},
        {"name": "65537-byte message", "mtu": 512, "message": big_v, "error": "message_too_large"},
    ]);
    let split_ok_large = json!({
        "name": "65536-byte message at mtu 512 is allowed",
        "mtu": 512, "seq": 0, "message": max_v,
        "frame_count": max_frames.len(),
        "first_frame_header": hx(&max_frames[0][..3]),
        "last_frame_header": hx(&max_frames.last().unwrap()[..3]),
        "last_frame_len": max_frames.last().unwrap().len(),
    });

    // Reassembly scenarios. Each step's expectation is computed by the library
    // and then asserted against what we intend, so the generator itself is checked.
    struct Step {
        frame: (Value, Vec<u8>),
        expect: Result<Option<Vec<u8>>, &'static str>,
    }
    fn hexf(h: &str) -> (Value, Vec<u8>) {
        let b = hex::decode(h).unwrap();
        (json!(h), b)
    }
    let pending: Result<Option<Vec<u8>>, &'static str> = Ok(None);
    let msg =
        |h: &str| -> Result<Option<Vec<u8>>, &'static str> { Ok(Some(hex::decode(h).unwrap())) };
    let scenarios: Vec<(&str, Vec<Step>)> = vec![
        (
            "single FIRST|LAST frame",
            vec![Step {
                frame: hexf("03000568656c6c6f"),
                expect: msg("68656c6c6f"),
            }],
        ),
        (
            "empty FIRST|LAST frame yields an empty message",
            vec![Step {
                frame: hexf("030000"),
                expect: msg(""),
            }],
        ),
        (
            "three frames",
            vec![
                Step {
                    frame: hexf("010001aabb"),
                    expect: pending.clone(),
                },
                Step {
                    frame: hexf("000001ccdd"),
                    expect: pending.clone(),
                },
                Step {
                    frame: hexf("020001ee"),
                    expect: msg("aabbccddee"),
                },
            ],
        ),
        (
            "empty middle and last chunks are fine",
            vec![
                Step {
                    frame: hexf("010009aa"),
                    expect: pending.clone(),
                },
                Step {
                    frame: hexf("000009"),
                    expect: pending.clone(),
                },
                Step {
                    frame: hexf("020009"),
                    expect: msg("aa"),
                },
            ],
        ),
        (
            "FIRST resets a partial buffer (different seq)",
            vec![
                Step {
                    frame: hexf("01000111"),
                    expect: pending.clone(),
                },
                Step {
                    frame: hexf("01000222"),
                    expect: pending.clone(),
                },
                Step {
                    frame: hexf("02000233"),
                    expect: msg("2233"),
                },
            ],
        ),
        (
            "FIRST resets a partial buffer (same seq)",
            vec![
                Step {
                    frame: hexf("01000711"),
                    expect: pending.clone(),
                },
                Step {
                    frame: hexf("03000722"),
                    expect: msg("22"),
                },
            ],
        ),
        (
            "seq mismatch discards the buffer; remaining frames are orphans",
            vec![
                Step {
                    frame: hexf("01000111"),
                    expect: pending.clone(),
                },
                Step {
                    frame: hexf("00000222"),
                    expect: Err("seq_mismatch"),
                },
                Step {
                    frame: hexf("02000133"),
                    expect: Err("orphan_frame"),
                },
                Step {
                    frame: hexf("03000344"),
                    expect: msg("44"),
                },
            ],
        ),
        (
            "continuation without FIRST is an orphan",
            vec![
                Step {
                    frame: hexf("00000011"),
                    expect: Err("orphan_frame"),
                },
                Step {
                    frame: hexf("02000011"),
                    expect: Err("orphan_frame"),
                },
            ],
        ),
        (
            "frame shorter than header discards the buffer",
            vec![
                Step {
                    frame: hexf("01000111"),
                    expect: pending.clone(),
                },
                Step {
                    frame: hexf("0200"),
                    expect: Err("frame_too_short"),
                },
                Step {
                    frame: hexf("02000122"),
                    expect: Err("orphan_frame"),
                },
                Step {
                    frame: hexf(""),
                    expect: Err("frame_too_short"),
                },
            ],
        ),
        (
            "reserved flag bits set discards the buffer",
            vec![
                Step {
                    frame: hexf("01000111"),
                    expect: pending.clone(),
                },
                Step {
                    frame: hexf("06000122"),
                    expect: Err("reserved_flags"),
                },
                Step {
                    frame: hexf("02000133"),
                    expect: Err("orphan_frame"),
                },
                Step {
                    frame: hexf("83000144"),
                    expect: Err("reserved_flags"),
                },
                Step {
                    frame: hexf("fc000144"),
                    expect: Err("reserved_flags"),
                },
            ],
        ),
        (
            "seq 0xffff then wrap to 0x0000",
            vec![
                Step {
                    frame: hexf("01ffff01"),
                    expect: pending.clone(),
                },
                Step {
                    frame: hexf("02ffff02"),
                    expect: msg("0102"),
                },
                Step {
                    frame: hexf("03000003"),
                    expect: msg("03"),
                },
            ],
        ),
        (
            "buffer of exactly 65536 bytes is accepted",
            vec![
                Step {
                    frame: fill(&[0x01, 0x00, 0x05], 0x5A, 65_535, &[]),
                    expect: pending.clone(),
                },
                Step {
                    frame: hexf("0200055a"),
                    expect: Ok(Some(vec![0x5A; 65_536])),
                },
            ],
        ),
        (
            "buffer exceeding 65536 bytes is discarded",
            vec![
                Step {
                    frame: fill(&[0x01, 0x00, 0x05], 0x5A, 65_536, &[]),
                    expect: pending.clone(),
                },
                Step {
                    frame: hexf("0000055a"),
                    expect: Err("message_too_large"),
                },
                Step {
                    frame: hexf("0200055a"),
                    expect: Err("orphan_frame"),
                },
                Step {
                    frame: hexf("030006"),
                    expect: msg(""),
                },
            ],
        ),
        (
            "single FIRST frame over the limit",
            vec![Step {
                frame: fill(&[0x03, 0x00, 0x05], 0x5A, 65_537, &[]),
                expect: Err("message_too_large"),
            }],
        ),
    ];
    let mut reassembly = vec![];
    for (name, steps) in scenarios {
        let mut r = Reassembler::new();
        let mut jsteps = vec![];
        for st in steps {
            let got = r.push(&st.frame.1).map_err(|e| e.code());
            assert_eq!(got, st.expect, "{name}");
            let mut o = json!({ "frame": st.frame.0 });
            match got {
                Ok(None) => o["result"] = json!("pending"),
                Ok(Some(m)) => {
                    o["result"] = json!("message");
                    o["message"] = if m.len() > 64 && m.iter().all(|b| *b == m[0]) {
                        fill(&[], m[0], m.len(), &[]).0
                    } else {
                        json!(hx(&m))
                    };
                }
                Err(e) => {
                    o["result"] = json!("error");
                    o["error"] = json!(e);
                }
            }
            jsteps.push(o);
        }
        reassembly.push(json!({ "name": name, "steps": jsteps }));
    }

    json!({
        "description": "Framing (SPEC §4.2). Frame = flags(1) ‖ msg_seq(u16 BE) ‖ chunk. `split`: FrameSplitter starting at `seq`, splitting `message` for payload size `mtu`, must produce exactly `frames`, and the next message uses `next_seq`. `reassembly`: feed `steps[].frame` in order to ONE fresh reassembler; each step yields `pending`, a complete `message`, or an `error` code (the frame was dropped; the reassembler stays usable).",
        "split": split,
        "split_large": [split_ok_large],
        "split_errors": split_errors,
        "reassembly": reassembly,
    })
}

// ---------------------------------------------------------------- envelope

const ENV_KEY: [u8; 32] = [
    0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f,
    0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98, 0x99, 0x9a, 0x9b, 0x9c, 0x9d, 0x9e, 0x9f,
];

fn envelope_vectors() -> Value {
    let mut plaintext = vec![];
    for j in [
        r#"{"t":"pair_request","nonce_p":"AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8="}"#,
        r#"{"t":"error","code":"version","msg":"Update Ventriloquist"}"#,
    ] {
        let msg = Message::from_json(j.as_bytes()).unwrap();
        let env = encode_plaintext(&msg).unwrap();
        assert_eq!(&env[1..], j.as_bytes());
        plaintext.push(json!({ "name": msg.type_name(), "json_utf8": j, "envelope": hx(&env) }));
    }

    let mut encrypt = vec![];
    let utt = br#"{"t":"utt","id":"0f8fad5b-d9cb-469f-a165-70867728950e","rev":1,"state":"partial","text":"hello world","ts":1759500000000}"#;
    let cases: Vec<(&str, [u8; 32], Direction, u64, Vec<u8>)> = vec![
        ("utt, phone→desktop, counter 0", ENV_KEY, Direction::PhoneToDesktop, 0, utt.to_vec()),
        ("utt, phone→desktop, counter 1", ENV_KEY, Direction::PhoneToDesktop, 1, utt.to_vec()),
        ("same plaintext+counter, desktop→phone (different nonce)", ENV_KEY, Direction::DesktopToPhone, 1, utt.to_vec()),
        ("ack, desktop→phone, counter 0x0102030405060708", ENV_KEY, Direction::DesktopToPhone, 0x0102030405060708,
            br#"{"t":"ack","id":"0f8fad5b-d9cb-469f-a165-70867728950e","rev":1}"#.to_vec()),
        ("ping, counter u64::MAX", pattern(0x00), Direction::PhoneToDesktop, u64::MAX, br#"{"t":"ping"}"#.to_vec()),
        ("empty plaintext", pattern(0x00), Direction::DesktopToPhone, 7, vec![]),
        ("multibyte UTF-8 text", pattern(0x40), Direction::PhoneToDesktop, 2,
            r#"{"t":"utt","id":"0f8fad5b-d9cb-469f-a165-70867728950e","rev":2,"state":"final","text":"naïve café 😀\nline2","ts":1759500000000}"#.as_bytes().to_vec()),
    ];
    for (name, key, dir, counter, pt) in cases {
        let env = seal_with(&key, dir, counter, &pt).unwrap();
        encrypt.push(json!({
            "name": name, "key": hx(&key), "direction": dir_name(dir), "counter": counter.to_string(),
            "plaintext": hx(&pt), "nonce": hx(&nonce(dir, counter)), "aad": "01", "envelope": hx(&env),
        }));
    }

    // open errors (stateless; fresh receiver)
    let good = seal_with(&ENV_KEY, Direction::PhoneToDesktop, 3, br#"{"t":"pong"}"#).unwrap();
    let mut flip_tag = good.clone();
    *flip_tag.last_mut().unwrap() ^= 0x80;
    let mut flip_ct = good.clone();
    flip_ct[9] ^= 0x01;
    let mut flip_ctr = good.clone();
    flip_ctr[8] ^= 0x01;
    let mut wrong_key = ENV_KEY;
    wrong_key[0] ^= 0xFF;
    let open_cases: Vec<(&str, [u8; 32], &str, Vec<u8>, &str)> = vec![
        (
            "valid envelope opened by the wrong role (direction mismatch)",
            ENV_KEY,
            "phone",
            good.clone(),
            "decrypt_failed",
        ),
        (
            "wrong key",
            wrong_key,
            "desktop",
            good.clone(),
            "decrypt_failed",
        ),
        (
            "tag bit flipped",
            ENV_KEY,
            "desktop",
            flip_tag,
            "decrypt_failed",
        ),
        (
            "ciphertext bit flipped",
            ENV_KEY,
            "desktop",
            flip_ct,
            "decrypt_failed",
        ),
        (
            "counter bit flipped",
            ENV_KEY,
            "desktop",
            flip_ctr,
            "decrypt_failed",
        ),
        (
            "truncated by one byte",
            ENV_KEY,
            "desktop",
            good[..good.len() - 1].to_vec(),
            "decrypt_failed",
        ),
        (
            "24 bytes: shorter than kind+counter+tag",
            ENV_KEY,
            "desktop",
            good[..24].to_vec(),
            "envelope_too_short",
        ),
        (
            "kind byte only",
            ENV_KEY,
            "desktop",
            vec![0x01],
            "envelope_too_short",
        ),
        (
            "empty envelope",
            ENV_KEY,
            "desktop",
            vec![],
            "empty_envelope",
        ),
        (
            "unknown kind 0x02",
            ENV_KEY,
            "desktop",
            [&[0x02u8][..], &good[1..]].concat(),
            "unknown_envelope_kind",
        ),
        (
            "unknown kind 0xff",
            ENV_KEY,
            "desktop",
            vec![0xFF],
            "unknown_envelope_kind",
        ),
    ];
    let mut open_errors = vec![];
    for (name, key, role, env, err) in open_cases {
        let role_v = if role == "phone" {
            vq_protocol::Role::Phone
        } else {
            vq_protocol::Role::Desktop
        };
        let mut c = SessionCipher::new(&key, role_v);
        assert_eq!(c.open(&env).unwrap_err().code(), err, "{name}");
        open_errors.push(json!({ "name": name, "key": hx(&key), "receiver_role": role, "envelope": hx(&env), "error": err }));
    }
    open_errors.push(json!({
        "name": "valid envelope (sanity: no error)", "key": hx(&ENV_KEY), "receiver_role": "desktop",
        "envelope": hx(&good), "error": null, "plaintext": hx(br#"{"t":"pong"}"#)
    }));

    // decode policy (decode_envelope)
    let enc_utt = seal_with(&ENV_KEY, Direction::PhoneToDesktop, 0, utt).unwrap();
    let enc_hello_err = seal_with(
        &ENV_KEY,
        Direction::PhoneToDesktop,
        0,
        br#"{"t":"error","code":"bad_mac"}"#,
    )
    .unwrap();
    let enc_unknown = seal_with(
        &ENV_KEY,
        Direction::PhoneToDesktop,
        0,
        br#"{"t":"future_thing","x":1}"#,
    )
    .unwrap();
    let enc_badjson = seal_with(&ENV_KEY, Direction::PhoneToDesktop, 0, b"not json").unwrap();
    let p = |j: &str| [&[0u8][..], j.as_bytes()].concat();
    let hello_json = format!(
        r#"{{"t":"hello","v":1,"device_id":"6f1c9a0e-1d2b-4c3d-8e4f-5a6b7c8d9e0f","name":"Desk","pub":"{}","paired":false,"session_nonce":"{}"}}"#,
        b64::encode(&pattern(0x10)),
        b64::encode(&pattern(0x30))
    );
    let decode_cases: Vec<(&str, Vec<u8>, bool, &str, &str)> = vec![
        // (name, envelope, with desktop session, result, type-or-error)
        (
            "plaintext hello allowed",
            p(&hello_json),
            false,
            "message",
            "hello",
        ),
        (
            "plaintext pair_request allowed",
            p(r#"{"t":"pair_request","nonce_p":"AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8="}"#),
            false,
            "message",
            "pair_request",
        ),
        (
            "plaintext pair_challenge allowed",
            p(r#"{"t":"pair_challenge","nonce_d":"ICEiIyQlJicoKSorLC0uLzAxMjM0NTY3ODk6Ozw9Pj8="}"#),
            false,
            "message",
            "pair_challenge",
        ),
        (
            "plaintext pair_confirm allowed",
            p(r#"{"t":"pair_confirm","mac":"AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8="}"#),
            false,
            "message",
            "pair_confirm",
        ),
        (
            "plaintext pair_result allowed",
            p(r#"{"t":"pair_result","ok":false}"#),
            false,
            "message",
            "pair_result",
        ),
        (
            "plaintext error allowed (with session too)",
            p(r#"{"t":"error","code":"unknown_peer","msg":""}"#),
            true,
            "message",
            "error",
        ),
        (
            "plaintext utt rejected (no session)",
            p(std::str::from_utf8(utt).unwrap()),
            false,
            "error",
            "plaintext_not_allowed",
        ),
        (
            "plaintext utt rejected (session established)",
            p(std::str::from_utf8(utt).unwrap()),
            true,
            "error",
            "plaintext_not_allowed",
        ),
        (
            "plaintext ack rejected",
            p(r#"{"t":"ack","id":"0f8fad5b-d9cb-469f-a165-70867728950e","rev":1}"#),
            true,
            "error",
            "plaintext_not_allowed",
        ),
        (
            "plaintext ping rejected",
            p(r#"{"t":"ping"}"#),
            true,
            "error",
            "plaintext_not_allowed",
        ),
        (
            "plaintext pong rejected",
            p(r#"{"t":"pong"}"#),
            false,
            "error",
            "plaintext_not_allowed",
        ),
        (
            "plaintext unknown type is passed up as unknown (dropped, not fatal)",
            p(r#"{"t":"future_thing"}"#),
            false,
            "unknown",
            "future_thing",
        ),
        (
            "plaintext invalid JSON",
            p("{"),
            false,
            "error",
            "invalid_json",
        ),
        (
            "plaintext empty body",
            vec![0x00],
            false,
            "error",
            "invalid_json",
        ),
        (
            "encrypted utt with session",
            enc_utt.clone(),
            true,
            "message",
            "utt",
        ),
        (
            "encrypted utt without session",
            enc_utt,
            false,
            "error",
            "no_session",
        ),
        (
            "encrypted error is also fine",
            enc_hello_err,
            true,
            "message",
            "error",
        ),
        (
            "encrypted unknown type",
            enc_unknown,
            true,
            "unknown",
            "future_thing",
        ),
        (
            "encrypted non-JSON",
            enc_badjson,
            true,
            "error",
            "invalid_json",
        ),
    ];
    // More decode cases: size/limits, provenance, and error-precedence ties.
    let d_seal = |c: u64, pt: &[u8]| seal_with(&ENV_KEY, Direction::PhoneToDesktop, c, pt).unwrap();
    let max_ping = {
        let prefix = br#"{"t":"ping","pad":""#;
        let mut j = prefix.to_vec();
        j.resize(vq_protocol::MAX_ENCRYPTED_JSON_BYTES - 2, b'a');
        j.extend_from_slice(br#""}"#);
        j
    };
    let max_enc = d_seal(0, &max_ping);
    assert_eq!(max_enc.len(), vq_protocol::MAX_MESSAGE_BYTES);
    let mut too_big_pt = vec![0u8];
    too_big_pt.extend_from_slice(br#"{"t":"pair_result","ok":false,"pad":""#);
    too_big_pt.resize(vq_protocol::MAX_MESSAGE_BYTES - 1, b'a');
    too_big_pt.extend_from_slice(br#""}"#);
    assert_eq!(too_big_pt.len(), vq_protocol::MAX_MESSAGE_BYTES + 1);
    let mut max_pt = too_big_pt.clone();
    max_pt.remove(40);
    let mut too_big_enc = vec![0x01u8];
    too_big_enc.resize(vq_protocol::MAX_MESSAGE_BYTES + 1, 0);
    let mut too_big_kind2 = vec![0x02u8];
    too_big_kind2.resize(vq_protocol::MAX_MESSAGE_BYTES + 1, 0);
    let garbage_ct = |c: u64| [vec![0x01], c.to_be_bytes().to_vec(), vec![0xEE; 30]].concat();
    let prior5 = vec![d_seal(5, br#"{"t":"ping"}"#)];
    #[allow(clippy::type_complexity)]
    let more: Vec<(&str, Vec<u8>, Option<Vec<Vec<u8>>>, &str, &str)> = vec![
        (
            "plaintext envelope of exactly 65536 bytes",
            max_pt,
            None,
            "message",
            "pair_result",
        ),
        (
            "plaintext envelope of 65537 bytes",
            too_big_pt,
            None,
            "error",
            "message_too_large",
        ),
        (
            "encrypted envelope of exactly 65536 bytes (65511-byte JSON)",
            max_enc,
            Some(vec![]),
            "message",
            "ping",
        ),
        (
            "encrypted envelope of 65537 bytes",
            too_big_enc,
            Some(vec![]),
            "error",
            "message_too_large",
        ),
        (
            "plaintext hello with v 2 → hello_unsupported",
            p(r#"{"t":"hello","v":2,"name":"Future Mac"}"#),
            None,
            "hello_unsupported",
            "hello",
        ),
        (
            "encrypted: good tag, invalid JSON still advances the window",
            d_seal(4, b"{\"t\":"),
            Some(vec![]),
            "error",
            "invalid_json",
        ),
        (
            "encrypted: good tag, invalid message still advances the window",
            d_seal(4, br#"{"t":"ack"}"#),
            Some(vec![]),
            "error",
            "invalid_message",
        ),
        (
            "tie: >65536 bytes AND unknown kind → message_too_large",
            too_big_kind2,
            None,
            "error",
            "message_too_large",
        ),
        (
            "tie: unknown kind AND short → unknown_envelope_kind",
            vec![0x02, 0x00],
            Some(vec![]),
            "error",
            "unknown_envelope_kind",
        ),
        (
            "tie: encrypted too short AND no session → envelope_too_short",
            vec![0x01; 10],
            None,
            "error",
            "envelope_too_short",
        ),
        (
            "tie: no session AND garbage ciphertext → no_session",
            garbage_ct(0),
            None,
            "error",
            "no_session",
        ),
        (
            "tie: older counter AND garbage ciphertext → replay",
            garbage_ct(3),
            Some(prior5.clone()),
            "error",
            "replay",
        ),
        (
            "tie: equal counter AND garbage ciphertext → replay",
            garbage_ct(5),
            Some(prior5.clone()),
            "error",
            "replay",
        ),
        (
            "tie: fresh counter AND garbage ciphertext → decrypt_failed",
            garbage_ct(6),
            Some(prior5.clone()),
            "error",
            "decrypt_failed",
        ),
        (
            "tie: plaintext utt with 1e400 → invalid_json before plaintext_not_allowed",
            p(r#"{"t":"utt","x":1e400}"#),
            None,
            "error",
            "invalid_json",
        ),
        (
            "tie: plaintext utt with a duplicate key → invalid_json",
            p(r#"{"t":"utt","t":"utt"}"#),
            None,
            "error",
            "invalid_json",
        ),
        (
            "tie: plaintext utt with bad fields → plaintext_not_allowed before invalid_message",
            p(r#"{"t":"utt","rev":-1}"#),
            None,
            "error",
            "plaintext_not_allowed",
        ),
        (
            "tie: plaintext non-object → invalid_message",
            p("[]"),
            None,
            "error",
            "invalid_message",
        ),
        (
            "tie: plaintext ping with t not a string → invalid_message",
            p(r#"{"t":["ping"]}"#),
            None,
            "error",
            "invalid_message",
        ),
    ];
    let mut all: Vec<(&str, Vec<u8>, Option<Vec<Vec<u8>>>, &str, &str)> = decode_cases
        .into_iter()
        .map(|(n, e, ws, r, w)| (n, e, ws.then(Vec::new), r, w))
        .collect();
    all.extend(more);
    let mut decode = vec![];
    for (name, env, session, result, what) in all {
        let mut sess = SessionCipher::new(&ENV_KEY, vq_protocol::Role::Desktop);
        if let Some(prior) = &session {
            for e in prior {
                sess.open(e).unwrap();
            }
        }
        let got = vq_protocol::decode_inbound(
            &env,
            if session.is_some() {
                Some(&mut sess)
            } else {
                None
            },
        );
        let mut o = json!({
            "name": name, "envelope": bytes_value(&env),
            "session": match &session {
                Some(prior) => json!({
                    "key": hx(&ENV_KEY), "role": "desktop",
                    "prior": prior.iter().map(|e| hx(e)).collect::<Vec<_>>(),
                }),
                None => Value::Null,
            },
            "result": result,
        });
        match (result, got) {
            ("message", Ok(inb)) => {
                o["authenticated"] = json!(inb.is_authenticated());
                let m = inb.into_message();
                assert!(!matches!(
                    m,
                    Message::Unknown { .. } | Message::HelloUnsupported(_)
                ));
                assert_eq!(m.type_name(), what, "{name}");
                o["type"] = json!(what);
                o["expected"] = serde_json::from_slice(&m.to_json().unwrap()).unwrap();
            }
            ("unknown", Ok(inb)) => {
                o["authenticated"] = json!(inb.is_authenticated());
                let Message::Unknown { t } = inb.into_message() else {
                    panic!("{name}")
                };
                assert_eq!(t, what);
                o["type"] = json!(what);
            }
            ("hello_unsupported", Ok(inb)) => {
                o["authenticated"] = json!(inb.is_authenticated());
                let Message::HelloUnsupported(h) = inb.into_message() else {
                    panic!("{name}")
                };
                o["type"] = json!(what);
                o["v"] = json!(h.v);
                o["peer_name"] = json!(h.name);
            }
            ("error", Err(e)) => {
                assert_eq!(e.code(), what, "{name}");
                o["error"] = json!(what);
            }
            (r, g) => panic!("{name}: expected {r}, got {g:?}"),
        }
        if session.is_some() {
            o["last_accepted_after"] = sess
                .last_received_counter()
                .map(|n| json!(n.to_string()))
                .unwrap_or(Value::Null);
        }
        decode.push(o);
    }

    // Secure-state policy (check_in_session) on a desktop receiver.
    let mut in_session = vec![];
    let hello_v1 = p(&hello_json);
    let enc_pr = d_seal(
        0,
        br#"{"t":"pair_request","nonce_p":"AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8="}"#,
    );
    let enc_hello = d_seal(0, hello_json.as_bytes());
    for (name, env, result, what) in [
        (
            "plaintext error passes (unauthenticated)",
            p(r#"{"t":"error","code":"unknown_peer"}"#),
            "ok",
            "error",
        ),
        (
            "plaintext unknown type passes (dropped by caller)",
            p(r#"{"t":"future_thing"}"#),
            "ok",
            "future_thing",
        ),
        ("encrypted utt passes", d_seal(0, utt), "ok", "utt"),
        (
            "encrypted ping passes",
            d_seal(0, br#"{"t":"ping"}"#),
            "ok",
            "ping",
        ),
        (
            "plaintext hello (second hello) is rejected",
            hello_v1,
            "error",
            "not_allowed_in_session",
        ),
        (
            "plaintext hello with another version is rejected",
            p(r#"{"t":"hello","v":2}"#),
            "error",
            "not_allowed_in_session",
        ),
        (
            "encrypted hello is rejected",
            enc_hello,
            "error",
            "not_allowed_in_session",
        ),
        (
            "plaintext pair_result is rejected",
            p(r#"{"t":"pair_result","ok":false}"#),
            "error",
            "not_allowed_in_session",
        ),
        (
            "encrypted pair_request is rejected",
            enc_pr,
            "error",
            "not_allowed_in_session",
        ),
        (
            "plaintext utt is still plaintext_not_allowed (decode fails first)",
            p(std::str::from_utf8(utt).unwrap()),
            "error",
            "plaintext_not_allowed",
        ),
    ] {
        let mut sess = SessionCipher::new(&ENV_KEY, vq_protocol::Role::Desktop);
        let got = vq_protocol::decode_inbound(&env, Some(&mut sess))
            .and_then(|i| vq_protocol::check_in_session(&i).map(|()| i));
        let mut o = json!({ "name": name, "envelope": hx(&env),
            "session": {"key": hx(&ENV_KEY), "role": "desktop", "prior": []}, "result": result });
        match (result, got) {
            ("ok", Ok(i)) => {
                assert_eq!(i.message().type_name(), what, "{name}");
                o["type"] = json!(what);
                o["authenticated"] = json!(i.is_authenticated());
            }
            ("error", Err(e)) => {
                assert_eq!(e.code(), what, "{name}");
                o["error"] = json!(what);
            }
            (r, g) => panic!("{name}: expected {r}, got {g:?}"),
        }
        in_session.push(o);
    }

    // full stack: JSON → encrypted envelope → frames
    let mut stack = vec![];
    for (name, role, counter, seq, mtu) in [
        (
            "utt phone→desktop, mtu 20",
            vq_protocol::Role::Phone,
            0u64,
            0u16,
            20usize,
        ),
        (
            "utt phone→desktop, mtu 185",
            vq_protocol::Role::Phone,
            5,
            9,
            185,
        ),
        (
            "ack desktop→phone, mtu 20",
            vq_protocol::Role::Desktop,
            0,
            0xFFFF,
            20,
        ),
    ] {
        let pt: &[u8] = if role == vq_protocol::Role::Phone {
            utt
        } else {
            br#"{"t":"ack","id":"0f8fad5b-d9cb-469f-a165-70867728950e","rev":1}"#
        };
        let mut c = SessionCipher::new(&ENV_KEY, role).with_send_counter(counter);
        let env = c.seal(pt).unwrap();
        let frames = FrameSplitter::with_seq(seq).split(&env, mtu).unwrap();
        stack.push(json!({
            "name": name, "key": hx(&ENV_KEY), "sender_role": if role == vq_protocol::Role::Phone { "phone" } else { "desktop" },
            "counter": counter.to_string(), "seq": seq, "mtu": mtu,
            "plaintext_utf8": std::str::from_utf8(pt).unwrap(),
            "envelope": hx(&env), "frames": frames.iter().map(|f| hx(f)).collect::<Vec<_>>(),
        }));
    }

    json!({
        "description": "Envelopes (SPEC §4.3; schema in README §10.3). Plaintext = 00 ‖ JSON. Encrypted = 01 ‖ counter(u64 BE) ‖ ChaCha20-Poly1305(key, nonce, plaintext, aad=01) where nonce = direction byte ‖ 000000 ‖ counter(u64 BE); direction phone_to_desktop=01, desktop_to_phone=02. Counters are decimal strings. `open_errors`: open `envelope` with a FRESH receiver of `receiver_role`. `decode`: full receive path; `session` null = no session key, else {key, role, prior} where the receiver first opens every `prior` envelope; `authenticated` = arrived encrypted; `expected` compared as a JSON object with the re-encoded message; `last_accepted_after` (only with a session) is the receiver's last accepted counter afterwards. Names starting `tie:` exercise the error precedence of README §9.1. `in_session`: decode, then apply the Secure-state policy (README §7.4). `stack`: plaintext → envelope (sender's counter) → frames (splitter at `seq`, `mtu`).",
        "plaintext": plaintext,
        "encrypt": encrypt,
        "open_errors": open_errors,
        "decode": decode,
        "in_session": in_session,
        "stack": stack,
    })
}

// ---------------------------------------------------------------- replay

fn replay() -> Value {
    let key = ENV_KEY;
    let seal = |d: Direction, c: u64, pt: &[u8]| seal_with(&key, d, c, pt).unwrap();
    let p2d = Direction::PhoneToDesktop;
    let d2p = Direction::DesktopToPhone;
    let e = |c: u64| seal(p2d, c, format!(r#"{{"t":"ping","n":{c}}}"#).as_bytes());
    let mut forged = e(3);
    forged[1..9].copy_from_slice(&u64::MAX.to_be_bytes());
    let mut tampered4 = e(4);
    *tampered4.last_mut().unwrap() ^= 1;
    let seqs: Vec<(&str, &str, Vec<Vec<u8>>)> = vec![
        (
            "in order, duplicate, gap, old, forged high counter",
            "desktop",
            vec![e(0), e(1), e(1), e(0), e(3), e(2), forged, e(4), e(4)],
        ),
        (
            "first accepted counter need not be 0; then 0 is a replay",
            "desktop",
            vec![e(5), e(0), e(5), e(6)],
        ),
        (
            "tampered envelope does not advance the window",
            "desktop",
            vec![tampered4, e(4), e(4)],
        ),
        (
            "desktop→phone direction, counter u64::MAX is accepted once",
            "phone",
            vec![
                seal(d2p, 0, b"{}"),
                seal(d2p, u64::MAX, b"{}"),
                seal(d2p, u64::MAX, b"{}"),
                seal(d2p, 1, b"{}"),
            ],
        ),
        (
            "wrong-direction envelope fails and does not advance",
            "phone",
            vec![e(9), seal(d2p, 0, b"{}")],
        ),
    ];
    let mut out = vec![];
    for (name, role, envs) in seqs {
        let r = if role == "phone" {
            vq_protocol::Role::Phone
        } else {
            vq_protocol::Role::Desktop
        };
        let mut c = SessionCipher::new(&key, r);
        let mut steps = vec![];
        for env in envs {
            let mut o = json!({ "envelope": hx(&env) });
            match c.open(&env) {
                Ok(pt) => {
                    o["result"] = json!("ok");
                    o["plaintext"] = json!(hx(&pt));
                }
                Err(err) => {
                    o["result"] = json!("error");
                    o["error"] = json!(err.code());
                }
            }
            o["last_accepted_after"] = c
                .last_received_counter()
                .map(|n| json!(n.to_string()))
                .unwrap_or(Value::Null);
            steps.push(o);
        }
        out.push(json!({ "name": name, "key": hx(&key), "receiver_role": role, "steps": steps }));
    }

    // sender side: counter exhaustion
    let mut c = SessionCipher::new(&key, vq_protocol::Role::Phone).with_send_counter(u64::MAX - 1);
    let mut sends = vec![];
    for pt in [
        &b"{\"t\":\"ping\"}"[..],
        b"{\"t\":\"pong\"}",
        b"{\"t\":\"ping\"}",
    ] {
        match c.seal(pt) {
            Ok(env) => {
                sends.push(json!({ "plaintext": hx(pt), "result": "ok", "envelope": hx(&env) }))
            }
            Err(e) => {
                sends.push(json!({ "plaintext": hx(pt), "result": "error", "error": e.code() }))
            }
        }
    }
    let mut c0 = SessionCipher::new(&key, vq_protocol::Role::Desktop);
    let mut sends0 = vec![];
    for pt in [
        &b"{\"t\":\"ping\"}"[..],
        b"{\"t\":\"ping\"}",
        b"{\"t\":\"ping\"}",
    ] {
        sends0.push(
            json!({ "plaintext": hx(pt), "result": "ok", "envelope": hx(&c0.seal(pt).unwrap()) }),
        );
    }

    json!({
        "description": "Replay protection (SPEC §4.3). For each sequence, create ONE receiver for `receiver_role` with `key` and open `steps[].envelope` in order. A step is accepted iff its counter is strictly greater than the last ACCEPTED counter (none initially) AND the tag verifies; failed steps never change state. `last_accepted_after` is the last accepted counter after the step (decimal string, null = none). `send_sequences`: a sender starting at `start_counter` seals `sends[].plaintext` in order; after using counter u64::MAX the sender must refuse with counter_exhausted.",
        "sequences": out,
        "send_sequences": [
            { "name": "fresh session starts at 0 and increments", "key": hx(&key), "sender_role": "desktop", "start_counter": "0", "sends": sends0 },
            { "name": "counter exhaustion", "key": hx(&key), "sender_role": "phone", "start_counter": (u64::MAX - 1).to_string(), "sends": sends },
        ],
    })
}

// ---------------------------------------------------------------- crypto

fn crypto_vectors() -> Value {
    // RFC 7748 §6.1 keys: Alice plays the phone, Bob plays the desktop.
    let phone = IdentityKeyPair::from_secret_bytes(h32(
        "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a",
    ));
    let desk = IdentityKeyPair::from_secret_bytes(h32(
        "5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb",
    ));
    let k3 = IdentityKeyPair::from_secret_bytes(pattern(0xA0));
    let k4 = IdentityKeyPair::from_secret_bytes([0xFF; 32]);

    let mut x25519 = vec![];
    for (name, a, b) in [
        ("RFC 7748 §6.1", &phone, &desk),
        (
            "patterned keys (a0..bf and ff..ff; clamping applies)",
            &k3,
            &k4,
        ),
        ("RFC 7748 Alice with patterned key", &phone, &k3),
    ] {
        let ss = a.shared_secret(&b.public_bytes()).unwrap();
        assert_eq!(
            ss.as_bytes(),
            b.shared_secret(&a.public_bytes()).unwrap().as_bytes()
        );
        x25519.push(json!({
            "name": name,
            "priv_a": hx(&*a.secret_bytes()), "pub_a": hx(&a.public_bytes()),
            "priv_b": hx(&*b.secret_bytes()), "pub_b": hx(&b.public_bytes()),
            "shared": hx(ss.as_bytes()),
        }));
    }
    let mut x25519_errors = vec![];
    let mut one = [0u8; 32];
    one[0] = 1;
    for (name, peer) in [
        ("all-zero public key", [0u8; 32]),
        ("u = 1 (low order)", one),
        (
            "order-8 point",
            h32("e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800"),
        ),
        (
            "order-8 point (2)",
            h32("5f9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f1157"),
        ),
        (
            "p-1",
            h32("ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"),
        ),
        (
            "p (non-canonical 0)",
            h32("edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"),
        ),
        (
            "all-zero with bit 255 set (bit 255 is masked)",
            h32("0000000000000000000000000000000000000000000000000000000000000080"),
        ),
        (
            "u = 1 with bit 255 set",
            h32("0100000000000000000000000000000000000000000000000000000000000080"),
        ),
        (
            "order-8 point with bit 255 set",
            h32("e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b880"),
        ),
        (
            "p with bit 255 set",
            h32("edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"),
        ),
    ] {
        assert_eq!(
            phone.shared_secret(&peer).unwrap_err(),
            Error::NonContributory,
            "{name}"
        );
        x25519_errors.push(json!({ "name": name, "priv": hx(&*phone.secret_bytes()), "peer_pub": hx(&peer), "error": "non_contributory" }));
    }

    // RFC 7748 §5: the receiver masks bit 255 of a peer's u-coordinate.
    let mut x25519_high_bit = vec![];
    for (name, me, peer) in [
        (
            "RFC 7748 desktop public key with bit 255 set",
            &phone,
            &desk,
        ),
        ("patterned public key with bit 255 set", &phone, &k4),
    ] {
        let masked = peer.public_bytes();
        assert_eq!(masked[31] & 0x80, 0);
        let mut high = masked;
        high[31] |= 0x80;
        let ss_hi = me.shared_secret(&high).unwrap();
        assert_eq!(
            ss_hi.as_bytes(),
            me.shared_secret(&masked).unwrap().as_bytes()
        );
        x25519_high_bit.push(json!({
            "name": name, "priv": hx(&*me.secret_bytes()), "peer_pub": hx(&high),
            "peer_pub_masked": hx(&masked), "shared": hx(ss_hi.as_bytes()),
        }));
    }

    let ss = phone.shared_secret(&desk.public_bytes()).unwrap();
    let ss2 = k3.shared_secret(&k4.public_bytes()).unwrap();

    let mut pair_key = vec![];
    for (name, s, np, nd, code) in [
        (
            "RFC 7748 shared secret, code 123456",
            &ss,
            pattern(0x00),
            pattern(0x20),
            123_456u32,
        ),
        ("code 000000", &ss, pattern(0x00), pattern(0x20), 0),
        (
            "code 000042 (zero padding)",
            &ss,
            pattern(0x00),
            pattern(0x20),
            42,
        ),
        ("code 999999", &ss, pattern(0x00), pattern(0x20), 999_999),
        (
            "nonces swapped vs. first case",
            &ss,
            pattern(0x20),
            pattern(0x00),
            123_456,
        ),
        ("other shared secret", &ss2, [0xEE; 32], [0x11; 32], 314_159),
    ] {
        let c = PairingCode::from_u32(code).unwrap();
        let k = crypto::derive_pair_key(s, &np, &nd, &c);
        pair_key.push(json!({
            "name": name, "shared": hx(s.as_bytes()), "nonce_p": hx(&np), "nonce_d": hx(&nd),
            "code": c.to_string(), "salt": hx(&[np, nd].concat()), "info": hx(&pair_info(&c)),
            "info_ascii": String::from_utf8(pair_info(&c)).unwrap(), "length": 32, "k_pair": hx(&k),
        }));
    }

    let mut session_key = vec![];
    for (name, s, a, b) in [
        ("RFC 7748 shared secret", &ss, pattern(0x40), pattern(0x60)),
        ("nonces swapped", &ss, pattern(0x60), pattern(0x40)),
        ("other shared secret", &ss2, [0x00; 32], [0xFF; 32]),
    ] {
        let k = crypto::derive_session_key(s, &a, &b);
        session_key.push(json!({
            "name": name, "shared": hx(s.as_bytes()), "nonce_phone": hx(&a), "nonce_desktop": hx(&b),
            "salt": hx(&[a, b].concat()), "info": hx(SESSION_INFO), "info_ascii": "vq/session/v1", "length": 32, "k_sess": hx(&k),
        }));
    }

    let (pp, pd) = (phone.public_bytes(), desk.public_bytes());
    let k_pair = crypto::derive_pair_key(
        &ss,
        &pattern(0x00),
        &pattern(0x20),
        &PairingCode::from_u32(123_456).unwrap(),
    );
    let mut pair_mac = vec![];
    for (name, k, a, b) in [
        (
            "RFC 7748 keys, K_pair from first pair_key case",
            k_pair,
            pp,
            pd,
        ),
        (
            "patterned keys and K_pair",
            pattern(0x55),
            k3.public_bytes(),
            k4.public_bytes(),
        ),
    ] {
        pair_mac.push(json!({
            "name": name, "k_pair": hx(&k), "pub_phone": hx(&a), "pub_desktop": hx(&b),
            "phone_mac_input": hx(&[&b"phone"[..], &a, &b].concat()),
            "phone_mac": hx(&crypto::phone_confirm_mac(&k, &a, &b)),
            "desktop_mac_input": hx(&[&b"desktop"[..], &b, &a].concat()),
            "desktop_mac": hx(&crypto::desktop_result_mac(&k, &a, &b)),
        }));
    }
    let good_p = crypto::phone_confirm_mac(&k_pair, &pp, &pd);
    let good_d = crypto::desktop_result_mac(&k_pair, &pp, &pd);
    let wrong_k = crypto::derive_pair_key(
        &ss,
        &pattern(0x00),
        &pattern(0x20),
        &PairingCode::from_u32(123_457).unwrap(),
    );
    let mut bit = good_p;
    bit[31] ^= 1;
    let mut verify = vec![];
    for (name, k, kind, mac, valid) in [
        ("phone MAC verifies", k_pair, "phone", good_p, true),
        ("desktop MAC verifies", k_pair, "desktop", good_d, true),
        (
            "phone MAC made with code 123456, verified with K_pair for 123457",
            wrong_k,
            "phone",
            good_p,
            false,
        ),
        (
            "phone MAC presented as desktop MAC (role confusion)",
            k_pair,
            "desktop",
            good_p,
            false,
        ),
        (
            "desktop MAC presented as phone MAC",
            k_pair,
            "phone",
            good_d,
            false,
        ),
        (
            "phone MAC with one bit flipped",
            k_pair,
            "phone",
            bit,
            false,
        ),
    ] {
        let r = if kind == "phone" {
            crypto::verify_phone_confirm_mac(&k, &pp, &pd, &mac)
        } else {
            crypto::verify_desktop_result_mac(&k, &pp, &pd, &mac)
        };
        assert_eq!(r.is_ok(), valid, "{name}");
        verify.push(json!({ "name": name, "k_pair": hx(&k), "pub_phone": hx(&pp), "pub_desktop": hx(&pd), "kind": kind, "mac": hx(&mac), "valid": valid }));
    }

    let codes = json!([
        {"value": 0, "string": "000000"}, {"value": 7, "string": "000007"}, {"value": 42, "string": "000042"},
        {"value": 123456, "string": "123456"}, {"value": 999999, "string": "999999"}, {"value": 100000, "string": "100000"},
    ]);
    let code_parse = json!([
        {"input": "123456", "valid": true, "value": 123456},
        {"input": "000000", "valid": true, "value": 0},
        {"input": "000042", "valid": true, "value": 42},
        {"input": "12345", "valid": false}, {"input": "1234567", "valid": false},
        {"input": "12a456", "valid": false}, {"input": "123 456", "valid": false},
        {"input": " 12345", "valid": false}, {"input": "+12345", "valid": false},
        {"input": "-12345", "valid": false}, {"input": "", "valid": false},
        {"input": "١٢٣٤٥٦", "valid": false}, {"input": "１２３４５６", "valid": false},
    ]);
    for c in code_parse.as_array().unwrap() {
        let r = c["input"].as_str().unwrap().parse::<PairingCode>();
        assert_eq!(r.is_ok(), c["valid"].as_bool().unwrap());
    }

    // End-to-end pairing + session transcript
    let np = pattern(0x00);
    let nd = pattern(0x20);
    let code = PairingCode::from_u32(123_456).unwrap();
    let snp = pattern(0x40);
    let snd = pattern(0x60);
    let k_sess = crypto::derive_session_key(&ss, &snp, &snd);
    let phone_id = "a1b2c3d4-e5f6-4789-8abc-def012345678";
    let desk_id = "0f8fad5b-d9cb-469f-a165-70867728950e";
    let msgs = [
        Message::Hello(vq_protocol::Hello {
            v: 1,
            device_id: b64::parse_uuid(desk_id).unwrap(),
            name: "Jon's Mac".into(),
            public_key: pd,
            paired: false,
            session_nonce: snd,
        }),
        Message::Hello(vq_protocol::Hello {
            v: 1,
            device_id: b64::parse_uuid(phone_id).unwrap(),
            name: "Jon's iPhone".into(),
            public_key: pp,
            paired: false,
            session_nonce: snp,
        }),
        Message::PairRequest(vq_protocol::PairRequest { nonce_p: np }),
        Message::PairChallenge(vq_protocol::PairChallenge { nonce_d: nd }),
        Message::PairConfirm(vq_protocol::PairConfirm { mac: good_p }),
        Message::PairResult(vq_protocol::PairResult::success(good_d)),
    ];
    let transcript: Vec<Value> = msgs
        .iter()
        .zip(["desktop", "phone", "phone", "desktop", "phone", "desktop"])
        .map(|(m, from)| {
            let env = encode_plaintext(m).unwrap();
            json!({ "from": from, "json_utf8": std::str::from_utf8(&env[1..]).unwrap(), "envelope": hx(&env) })
        })
        .collect();
    let mut phone_c = SessionCipher::new(&k_sess, vq_protocol::Role::Phone);
    let first_utt = phone_c.seal(br#"{"t":"utt","id":"3b241101-e2bb-4255-8caf-4136c566a962","rev":0,"state":"final","text":"kubectl get pods","ts":1759500000000}"#).unwrap();
    let mut desk_c = SessionCipher::new(&k_sess, vq_protocol::Role::Desktop);
    let first_ack = desk_c
        .seal(br#"{"t":"ack","id":"3b241101-e2bb-4255-8caf-4136c566a962","rev":0}"#)
        .unwrap();
    let full = json!({
        "name": "fresh pairing then first encrypted exchange (RFC 7748 keys)",
        "phone_priv": hx(&*phone.secret_bytes()), "phone_pub": hx(&pp), "phone_device_id": phone_id,
        "desktop_priv": hx(&*desk.secret_bytes()), "desktop_pub": hx(&pd), "desktop_device_id": desk_id,
        "shared": hx(ss.as_bytes()),
        "nonce_p": hx(&np), "nonce_d": hx(&nd), "code": code.to_string(),
        "k_pair": hx(&k_pair), "phone_mac": hx(&good_p), "desktop_mac": hx(&good_d),
        "session_nonce_phone": hx(&snp), "session_nonce_desktop": hx(&snd), "k_sess": hx(&k_sess),
        "transcript": transcript,
        "first_utt_plaintext_utf8": r#"{"t":"utt","id":"3b241101-e2bb-4255-8caf-4136c566a962","rev":0,"state":"final","text":"kubectl get pods","ts":1759500000000}"#,
        "first_utt_envelope": hx(&first_utt),
        "first_ack_plaintext_utf8": r#"{"t":"ack","id":"3b241101-e2bb-4255-8caf-4136c566a962","rev":0}"#,
        "first_ack_envelope": hx(&first_ack),
    });

    json!({
        "description": "Identity, pairing and session crypto (SPEC §4.4, §4.5). All binary values are lowercase hex. X25519 per RFC 7748 (private keys are raw 32-byte scalars, clamped on use; an all-zero shared secret MUST be rejected). HKDF-SHA256 per RFC 5869 with the given salt/info, output length 32. MACs are HMAC-SHA256 with K_pair as key over the given *_mac_input bytes.",
        "x25519": x25519,
        "x25519_errors": x25519_errors,
        "x25519_high_bit": x25519_high_bit,
        "pair_key": pair_key,
        "session_key": session_key,
        "pair_mac": pair_mac,
        "pair_mac_verify": verify,
        "code_format": codes,
        "code_parse": code_parse,
        "full_pairing": [full],
    })
}

// ---------------------------------------------------------------- messages

fn messages() -> Value {
    let id = "0f8fad5b-d9cb-469f-a165-70867728950e";
    let k = b64::encode(&pattern(0x00));
    let n = b64::encode(&pattern(0x20));
    let hello = format!(
        r#"{{"t":"hello","v":1,"device_id":"{id}","name":"Jon's iPhone","pub":"{k}","paired":true,"session_nonce":"{n}"}}"#
    );
    let utt = |text: &str| {
        format!(
            r#"{{"t":"utt","id":"{id}","rev":7,"state":"partial","text":{},"ts":1759500000000}}"#,
            serde_json::to_string(text).unwrap()
        )
    };

    enum In {
        Text(String),
        Fill {
            prefix: String,
            fill: String,
            count: usize,
            suffix: String,
        },
        Hex(Vec<u8>),
    }
    let t = |s: &str| In::Text(s.to_owned());
    let sized = |prefix: &str, total: usize| In::Fill {
        prefix: prefix.to_owned(),
        fill: "a".into(),
        count: total - prefix.len() - 2,
        suffix: r#""}"#.into(),
    };
    let text_prefix = format!(r#"{{"t":"utt","id":"{id}","rev":1,"state":"final","text":""#);
    let text_suffix = r#"","ts":0}"#.to_owned();
    let cases: Vec<(&str, In)> = vec![
        ("hello", In::Text(hello.clone())),
        (
            "hello with uppercase device_id and extra fields",
            In::Text(
                hello
                    .replace(id, &id.to_uppercase())
                    .replace(r#""t":"hello","#, r#""t":"hello","caps":["x"],"#),
            ),
        ),
        (
            "hello with other version → hello_unsupported",
            t(r#"{"t":"hello","v":2,"name":"Jon's Mac","future":{"a":1}}"#),
        ),
        ("hello v 0 → hello_unsupported", t(r#"{"t":"hello","v":0}"#)),
        ("hello missing v", t(&hello.replace(r#""v":1,"#, ""))),
        (
            "hello v as string",
            t(&hello.replace(r#""v":1"#, r#""v":"1""#)),
        ),
        (
            "hello v negative",
            t(&hello.replace(r#""v":1"#, r#""v":-1"#)),
        ),
        (
            "hello missing session_nonce",
            t(&hello.replace(&format!(r#","session_nonce":"{n}""#), "")),
        ),
        (
            "hello missing paired",
            t(&hello.replace(r#""paired":true,"#, "")),
        ),
        (
            "hello pub unpadded base64",
            t(&hello.replace(&k, k.trim_end_matches('='))),
        ),
        (
            "hello pub url-safe alphabet",
            t(&hello.replace(
                &k,
                &b64::encode(&[0xFB; 32]).replace('+', "-").replace('/', "_"),
            )),
        ),
        (
            "hello pub 31 bytes",
            t(&hello.replace(&k, &b64::encode(&[1; 31]))),
        ),
        (
            "hello pub 33 bytes",
            t(&hello.replace(&k, &b64::encode(&[1; 33]))),
        ),
        (
            "hello device_id without hyphens",
            t(&hello.replace(id, &id.replace('-', ""))),
        ),
        (
            "hello device_id in braces",
            t(&hello.replace(id, &format!("{{{id}}}"))),
        ),
        (
            "pair_request",
            t(&format!(r#"{{"t":"pair_request","nonce_p":"{k}"}}"#)),
        ),
        (
            "pair_challenge",
            t(&format!(r#"{{"t":"pair_challenge","nonce_d":"{n}"}}"#)),
        ),
        (
            "pair_confirm",
            t(&format!(r#"{{"t":"pair_confirm","mac":"{k}"}}"#)),
        ),
        (
            "pair_result ok",
            t(&format!(r#"{{"t":"pair_result","ok":true,"mac":"{k}"}}"#)),
        ),
        ("pair_result fail", t(r#"{"t":"pair_result","ok":false}"#)),
        (
            "pair_result fail with mac: mac is ignored",
            t(&format!(r#"{{"t":"pair_result","ok":false,"mac":"{k}"}}"#)),
        ),
        (
            "pair_result fail with null mac",
            t(r#"{"t":"pair_result","ok":false,"mac":null}"#),
        ),
        (
            "pair_result ok without mac",
            t(r#"{"t":"pair_result","ok":true}"#),
        ),
        (
            "pair_result missing ok",
            t(&format!(r#"{{"t":"pair_result","mac":"{k}"}}"#)),
        ),
        (
            "error",
            t(r#"{"t":"error","code":"bad_mac","msg":"MAC mismatch"}"#),
        ),
        (
            "error without msg (defaults to empty)",
            t(r#"{"t":"error","code":"unknown_peer"}"#),
        ),
        (
            "error with unknown code is fine",
            t(r#"{"t":"error","code":"something_new","msg":"x"}"#),
        ),
        ("error missing code", t(r#"{"t":"error","msg":"x"}"#)),
        ("utt partial", t(&utt("hello world"))),
        ("utt final", t(&utt("x").replace("partial", "final"))),
        ("utt edit", t(&utt("x").replace("partial", "edit"))),
        ("utt empty text", t(&utt(""))),
        (
            "utt escapes and unicode",
            t(&format!(
                r#"{{"t":"utt","id":"{id}","rev":7,"state":"final","text":"café 😀 \"q\" \\ \/ \n\t","ts":1}}"#
            )),
        ),
        ("utt raw multibyte UTF-8", t(&utt("naïve café 😀 日本語"))),
        (
            "utt rev u32 max",
            t(&utt("x").replace(r#""rev":7"#, r#""rev":4294967295"#)),
        ),
        (
            "utt rev u32 max + 1",
            t(&utt("x").replace(r#""rev":7"#, r#""rev":4294967296"#)),
        ),
        (
            "utt rev negative",
            t(&utt("x").replace(r#""rev":7"#, r#""rev":-1"#)),
        ),
        (
            "utt rev fractional",
            t(&utt("x").replace(r#""rev":7"#, r#""rev":7.5"#)),
        ),
        (
            "utt rev as string",
            t(&utt("x").replace(r#""rev":7"#, r#""rev":"7""#)),
        ),
        (
            "utt ts u64 max",
            t(&utt("x").replace("1759500000000", "18446744073709551615")),
        ),
        (
            "utt ts negative",
            t(&utt("x").replace("1759500000000", "-1")),
        ),
        (
            "utt unknown state",
            t(&utt("x").replace("partial", "volatile")),
        ),
        (
            "utt state wrong case",
            t(&utt("x").replace("partial", "Partial")),
        ),
        (
            "utt missing id",
            t(&utt("x").replace(&format!(r#""id":"{id}","#), "")),
        ),
        ("utt bad id", t(&utt("x").replace(id, "not-a-uuid"))),
        (
            "utt text null",
            t(&utt("x").replace(r#""text":"x""#, r#""text":null"#)),
        ),
        (
            "utt text exactly 32000 bytes",
            In::Fill {
                prefix: text_prefix.clone(),
                fill: "a".into(),
                count: 32_000,
                suffix: text_suffix.clone(),
            },
        ),
        (
            "utt text 32001 bytes",
            In::Fill {
                prefix: text_prefix.clone(),
                fill: "a".into(),
                count: 32_001,
                suffix: text_suffix.clone(),
            },
        ),
        (
            "utt text 8000 four-byte emoji = 32000 bytes",
            In::Fill {
                prefix: text_prefix.clone(),
                fill: "😀".into(),
                count: 8000,
                suffix: text_suffix.clone(),
            },
        ),
        (
            "utt text 10667 three-byte chars = 32001 bytes",
            In::Fill {
                prefix: text_prefix.clone(),
                fill: "日".into(),
                count: 10_667,
                suffix: text_suffix.clone(),
            },
        ),
        (
            "utt text 32000 escaped newlines (length counts decoded bytes)",
            In::Fill {
                prefix: text_prefix.clone(),
                fill: "\\n".into(),
                count: 32_000,
                suffix: text_suffix.clone(),
            },
        ),
        ("ack", t(&format!(r#"{{"t":"ack","id":"{id}","rev":3}}"#))),
        (
            "ack missing rev",
            t(&format!(r#"{{"t":"ack","id":"{id}"}}"#)),
        ),
        ("ping", t(r#"{"t":"ping"}"#)),
        (
            "pong with extra fields",
            t(r#"{"t":"pong","seq":1,"x":null}"#),
        ),
        (
            "whitespace around and inside",
            t(" \n{ \"t\" : \"ping\" }\r\n "),
        ),
        ("unknown type", t(r#"{"t":"typing","id":"x"}"#)),
        ("unknown type empty string", t(r#"{"t":""}"#)),
        ("type is case sensitive", t(r#"{"t":"PING"}"#)),
        ("missing t", t(r#"{"id":"x"}"#)),
        ("t is a number", t(r#"{"t":1}"#)),
        ("t is null", t(r#"{"t":null}"#)),
        ("JSON array", t(r#"[{"t":"ping"}]"#)),
        ("JSON string", t(r#""ping""#)),
        ("JSON null", t("null")),
        ("empty input", t("")),
        ("truncated JSON", t(r#"{"t":"ping""#)),
        ("trailing garbage", t(r#"{"t":"ping"}x"#)),
        ("two objects", t(r#"{"t":"ping"}{"t":"pong"}"#)),
        (
            "invalid UTF-8",
            In::Hex(b"{\"t\":\"utt\",\"text\":\"\xff\"}".to_vec()),
        ),
        (
            "UTF-8 BOM prefix",
            In::Hex([&[0xEF, 0xBB, 0xBF][..], br#"{"t":"ping"}"#].concat()),
        ),
        (
            "message of exactly 65536 bytes",
            sized(r#"{"t":"ping","pad":""#, 65_536),
        ),
        (
            "message of 65537 bytes",
            sized(r#"{"t":"ping","pad":""#, 65_537),
        ),
        (
            "unknown type of 65537 bytes is still too large",
            sized(r#"{"t":"zzz","pad":""#, 65_537),
        ),
    ];
    let mut cases = cases;
    let ack = |rev: &str| t(&format!(r#"{{"t":"ack","id":"{id}","rev":{rev}}}"#));
    let ping_with = |member: &str| t(&format!(r#"{{"t":"ping","x":{member}}}"#));
    let arrays = |k: usize| format!("{}{}", "[".repeat(k), "]".repeat(k));
    let objects = |k: usize| format!("{}{{}}{}", "{\"a\":".repeat(k - 1), "}".repeat(k - 1));
    let zeros = b64::encode(&[0u8; 32]);
    let pr =
        |nonce: &str| t(&serde_json::json!({"t": "pair_request", "nonce_p": nonce}).to_string());
    let utt_rev_text = |rev: &str, n: usize| In::Fill {
        prefix: format!(r#"{{"t":"utt","id":"{id}","rev":{rev},"state":"final","text":""#),
        fill: "a".into(),
        count: n,
        suffix: r#"","ts":0}"#.into(),
    };
    cases.extend([
        // ---- R1: depth (outermost object = depth 1)
        (
            "R1 depth 32 (31 nested arrays in an ignored member) is allowed",
            ping_with(&arrays(31)),
        ),
        (
            "R1 depth 33 (32 nested arrays in an ignored member) is invalid_json",
            ping_with(&arrays(32)),
        ),
        (
            "R1 depth 32 with nested objects is allowed",
            ping_with(&objects(31)),
        ),
        (
            "R1 depth 33 with nested objects is invalid_json",
            ping_with(&objects(32)),
        ),
        (
            "R1 depth 200 in an unknown type is invalid_json",
            t(&format!(r#"{{"t":"future","x":{}}}"#, arrays(200))),
        ),
        (
            "R1 top-level array of depth 33 is invalid_json (not invalid_message)",
            t(&arrays(33)),
        ),
        (
            "R1 top-level array of depth 32 is invalid_message (valid JSON, not an object)",
            t(&arrays(32)),
        ),
        // ---- R1: finite numbers
        ("R1 1e400 in an ignored member", ping_with("1e400")),
        (
            "R1 -1e400 nested in an ignored member",
            ping_with(r#"[{"y":-1e400}]"#),
        ),
        ("R1 1e309 overflows binary64", ping_with("1e309")),
        (
            "R1 1.7976931348623157e308 (max double) is finite",
            ping_with("1.7976931348623157e308"),
        ),
        (
            "R1 1.7976931348623159e308 rounds to infinity",
            ping_with("1.7976931348623159e308"),
        ),
        (
            "R1 1e-400 underflows to 0 and is finite",
            ping_with("1e-400"),
        ),
        (
            "R1 39-digit integer in an ignored member is finite",
            ping_with("123456789012345678901234567890123456789"),
        ),
        ("R1 1e400 in unknown type", t(r#"{"t":"future","x":1e400}"#)),
        (
            "R1 1e400 in utt.rev is invalid_json, not invalid_message",
            t(&utt("x").replace(r#""rev":7"#, r#""rev":1e400"#)),
        ),
        (
            "R1 1e400 in hello.v is invalid_json",
            t(r#"{"t":"hello","v":1e400}"#),
        ),
        // ---- R1: lone surrogates
        (
            "R1 lone high surrogate in an ignored member",
            ping_with(r#""\ud800""#),
        ),
        (
            "R1 lone low surrogate in an ignored member",
            ping_with(r#""\udfff""#),
        ),
        (
            "R1 high surrogate followed by a non-escape",
            ping_with(r#""\ud800A""#),
        ),
        (
            "R1 high surrogate followed by a non-low escape",
            ping_with(r#""\ud800A""#),
        ),
        ("R1 reversed surrogate pair", ping_with(r#""\udc00\ud800""#)),
        (
            "R1 lone surrogate in a key",
            t(r#"{"t":"ping","\ud800":1}"#),
        ),
        (
            "R1 lone surrogate in utt.text",
            t(&utt("x").replace(r#""text":"x""#, r#""text":"a\ud83d""#)),
        ),
        (
            "R1 valid surrogate pair in an ignored member",
            ping_with(r#""😀""#),
        ),
        // ---- R1: duplicate keys
        ("R1 duplicate t", t(r#"{"t":"ping","t":"pong"}"#)),
        (
            "R1 duplicate t, second spelled with an escape",
            t(r#"{"t":"ping","t":"utt"}"#),
        ),
        (
            "R1 duplicate field in a known type",
            t(&format!(r#"{{"t":"ack","id":"{id}","rev":1,"rev":2}}"#)),
        ),
        (
            "R1 duplicate key nested in an ignored member",
            ping_with(r#"[{"k":1,"k":1}]"#),
        ),
        (
            "R1 duplicate key in an unknown type",
            t(r#"{"t":"future","a":1,"a":1}"#),
        ),
        (
            "R1 same key in sibling objects is fine",
            ping_with(r#"{"a":{"k":1},"b":{"k":1}}"#),
        ),
        // ---- R1: integer fields
        ("integer field -0 is invalid_message", ack("-0")),
        ("integer field 1.0 is invalid_message", ack("1.0")),
        ("integer field 1e0 is invalid_message", ack("1e0")),
        ("integer field 0.0 is invalid_message", ack("0.0")),
        (
            "integer field 4294967296 (u32 max + 1) is invalid_message",
            ack("4294967296"),
        ),
        ("integer field 0 is fine", ack("0")),
        (
            "hello v -0 is invalid_message",
            t(r#"{"t":"hello","v":-0}"#),
        ),
        (
            "hello v 1.0 is invalid_message",
            t(&hello.replace(r#""v":1"#, r#""v":1.0"#)),
        ),
        (
            "hello v 1e0 is invalid_message",
            t(&hello.replace(r#""v":1"#, r#""v":1e0"#)),
        ),
        (
            "hello v 2^64 is invalid_message",
            t(r#"{"t":"hello","v":18446744073709551616}"#),
        ),
        (
            "hello v 2^64-1 is hello_unsupported",
            t(r#"{"t":"hello","v":18446744073709551615,"name":5}"#),
        ),
        (
            "utt ts 2^64 is invalid_message",
            t(&utt("x").replace("1759500000000", "18446744073709551616")),
        ),
        (
            "utt ts -0 is invalid_message",
            t(&utt("x").replace("1759500000000", "-0")),
        ),
        // ---- null for optional fields
        (
            "error msg null is the same as absent",
            t(r#"{"t":"error","code":"bad_mac","msg":null}"#),
        ),
        (
            "error msg of the wrong type",
            t(r#"{"t":"error","code":"bad_mac","msg":5}"#),
        ),
        (
            "error code null is invalid",
            t(r#"{"t":"error","code":null}"#),
        ),
        (
            "pair_result ok:true with null mac",
            t(r#"{"t":"pair_result","ok":true,"mac":null}"#),
        ),
        // ---- pair_result ok:false ignores mac entirely
        (
            "pair_result fail with non-base64 mac is ignored",
            t(r#"{"t":"pair_result","ok":false,"mac":"garbage"}"#),
        ),
        (
            "pair_result fail with numeric mac is ignored",
            t(r#"{"t":"pair_result","ok":false,"mac":123}"#),
        ),
        (
            "pair_result fail with object mac is ignored",
            t(r#"{"t":"pair_result","ok":false,"mac":{}}"#),
        ),
        (
            "pair_result fail with 31-byte mac is ignored",
            t(&format!(
                r#"{{"t":"pair_result","ok":false,"mac":"{}"}}"#,
                b64::encode(&[7; 31])
            )),
        ),
        (
            "pair_result ok:true with 31-byte mac",
            t(&format!(
                r#"{{"t":"pair_result","ok":true,"mac":"{}"}}"#,
                b64::encode(&[7; 31])
            )),
        ),
        (
            "pair_result ok as string",
            t(r#"{"t":"pair_result","ok":"false"}"#),
        ),
        // ---- strict base64
        ("base64 canonical all-zero value", pr(&zeros)),
        (
            "base64 non-zero trailing bits (B=)",
            pr(&format!("{}B=", &zeros[..42])),
        ),
        (
            "base64 non-zero trailing bits (D=)",
            pr(&format!("{}D=", &zeros[..42])),
        ),
        ("base64 extra '='", pr(&format!("{zeros}="))),
        (
            "base64 '==' padding at the 32-byte length",
            pr(&format!("{}==", &zeros[..42])),
        ),
        ("base64 missing padding", pr(zeros.trim_end_matches('='))),
        ("base64 trailing newline", pr(&format!("{zeros}\n"))),
        (
            "base64 embedded space",
            pr(&format!("{} {}", &zeros[..22], &zeros[22..])),
        ),
        (
            "base64 embedded CRLF",
            pr(&format!("{}\r\n{}", &zeros[..22], &zeros[22..])),
        ),
        ("base64 empty string", pr("")),
        // ---- error precedence ties (README §9.1)
        (
            "tie: >65536 bytes AND invalid JSON → message_too_large",
            In::Fill {
                prefix: r#"{"t":"ping","pad":""#.into(),
                fill: "a".into(),
                count: 65_536,
                suffix: String::new(),
            },
        ),
        (
            "tie: invalid JSON (1e400) AND bad field → invalid_json",
            t(&utt("x").replace(r#""rev":7"#, r#""rev":-1,"x":1e400"#)),
        ),
        (
            "tie: duplicate key AND t not a string → invalid_json",
            t(r#"{"t":5,"t":5}"#),
        ),
        (
            "tie: t not a string AND bad fields → invalid_message",
            t(r#"{"t":1,"rev":-1}"#),
        ),
        (
            "tie: bad field AND text over 32000 bytes → invalid_message",
            utt_rev_text("-1", 32_001),
        ),
        (
            "tie: text over 32000 bytes AND every field valid → text_too_long",
            utt_rev_text("1", 32_001),
        ),
        (
            "tie: hello v != 1 AND every other field invalid → hello_unsupported",
            t(r#"{"t":"hello","v":3,"device_id":7,"pub":"x","paired":"no"}"#),
        ),
    ]);

    let mut decode = vec![];
    for (name, input) in cases {
        let (input_v, bytes) = match &input {
            In::Text(s) => (json!({ "json": s }), s.as_bytes().to_vec()),
            In::Fill {
                prefix,
                fill,
                count,
                suffix,
            } => (
                json!({ "json_fill": { "prefix": prefix, "fill": fill, "count": count, "suffix": suffix } }),
                format!("{prefix}{}{suffix}", fill.repeat(*count)).into_bytes(),
            ),
            In::Hex(b) => (json!({ "json_hex": hx(b) }), b.clone()),
        };
        let mut o = json!({ "name": name });
        for (k, v) in input_v.as_object().unwrap() {
            o[k] = v.clone();
        }
        match Message::from_json(&bytes) {
            Ok(Message::Unknown { t }) => {
                o["result"] = json!("unknown");
                o["type"] = json!(t);
            }
            Ok(Message::HelloUnsupported(h)) => {
                o["result"] = json!("hello_unsupported");
                o["v"] = json!(h.v);
                o["peer_name"] = json!(h.name);
            }
            Ok(m) => {
                o["result"] = json!("message");
                o["type"] = json!(m.type_name());
                let mut canon: Value = serde_json::from_slice(&m.to_json().unwrap()).unwrap();
                // keep huge canonical texts out of the file; the fill already describes them
                match &m {
                    Message::Utt(u) if u.text.len() > 1024 => {
                        o["text_bytes"] = json!(u.text.len());
                        canon.as_object_mut().unwrap().remove("text");
                        o["expected_without_text"] = canon;
                    }
                    _ => o["expected"] = canon,
                }
            }
            Err(e) => {
                o["result"] = json!("error");
                o["error"] = json!(e.code());
            }
        }
        decode.push(o);
    }

    // encode: canonical compact JSON the Rust implementation emits
    let mut encode = vec![];
    for j in [
        hello.as_str(),
        &format!(r#"{{"t":"pair_request","nonce_p":"{k}"}}"#),
        &format!(r#"{{"t":"pair_challenge","nonce_d":"{n}"}}"#),
        &format!(r#"{{"t":"pair_confirm","mac":"{k}"}}"#),
        &format!(r#"{{"t":"pair_result","ok":true,"mac":"{k}"}}"#),
        r#"{"t":"pair_result","ok":false}"#,
        r#"{"t":"error","code":"version","msg":"Update Ventriloquist on Jon's Mac"}"#,
        &utt("line1\nline2 \"quoted\" café"),
        &format!(r#"{{"t":"ack","id":"{id}","rev":3}}"#),
        r#"{"t":"ping"}"#,
        r#"{"t":"pong"}"#,
    ] {
        let m = Message::from_json(j.as_bytes()).unwrap();
        let out = m.to_json().unwrap();
        assert_eq!(out, j.as_bytes(), "canonical form drifted for {j}");
        encode.push(json!({ "type": m.type_name(), "json": j, "object": serde_json::from_str::<Value>(j).unwrap() }));
    }
    let mut encode_errors = vec![];
    let uid = b64::parse_uuid(id).unwrap();
    let utt_msg = |text: String| {
        Message::Utt(vq_protocol::Utt {
            id: uid,
            rev: 0,
            state: vq_protocol::UttState::Final,
            text,
            ts: 0,
        })
    };
    let utt_obj = json!({"t": "utt", "id": id, "rev": 0, "state": "final", "ts": 0});
    let mut hello_v2 = vq_protocol::Hello {
        v: 1,
        device_id: uid,
        name: "Jon's iPhone".into(),
        public_key: pattern(0x00),
        paired: true,
        session_nonce: pattern(0x20),
    };
    hello_v2.v = 2;
    let cases: Vec<(&str, Message, Value, Option<(&str, usize)>, &str)> = vec![
        (
            "utt text 32001 bytes",
            utt_msg("a".repeat(32_001)),
            utt_obj.clone(),
            Some(("a", 32_001)),
            "text_too_long",
        ),
        (
            "utt of 32000 U+0001 chars escapes past 64 KiB",
            utt_msg("\u{1}".repeat(32_000)),
            utt_obj.clone(),
            Some(("\u{1}", 32_000)),
            "message_too_large",
        ),
        (
            "tie: text over the limit AND escapes past 64 KiB → text_too_long",
            utt_msg("\u{1}".repeat(32_001)),
            utt_obj.clone(),
            Some(("\u{1}", 32_001)),
            "text_too_long",
        ),
        (
            "hello with v 2 cannot be encoded",
            Message::Hello(hello_v2),
            json!({"t": "hello", "v": 2, "device_id": id, "name": "Jon's iPhone", "pub": k, "paired": true, "session_nonce": n}),
            None,
            "not_encodable",
        ),
        (
            "pair_result ok:false with a mac",
            Message::PairResult(vq_protocol::PairResult {
                ok: false,
                mac: Some(pattern(0x00)),
            }),
            json!({"t": "pair_result", "ok": false, "mac": k}),
            None,
            "not_encodable",
        ),
        (
            "pair_result ok:true without a mac",
            Message::PairResult(vq_protocol::PairResult {
                ok: true,
                mac: None,
            }),
            json!({"t": "pair_result", "ok": true}),
            None,
            "not_encodable",
        ),
    ];
    for (name, m, obj, fill, err) in cases {
        assert_eq!(m.to_json().unwrap_err().code(), err, "{name}");
        let mut o = json!({ "name": name, "message": obj, "error": err });
        if let Some((f, count)) = fill {
            o["text_fill"] = json!({ "fill": f, "count": count });
        }
        encode_errors.push(o);
    }

    // utt sizing helper (README §5.8): fits / max_prefix_bytes
    let mut utt_fits = vec![];
    for (name, f, count) in [
        ("empty text", "a", 0usize),
        ("32000 ASCII bytes", "a", 32_000),
        ("32001 ASCII bytes", "a", 32_001),
        (
            "32000 quotes escape to 64000 bytes and still fit",
            "\"",
            32_000,
        ),
        (
            "10897 U+0001 chars (6 bytes each) fit exactly",
            "\u{1}",
            10_897,
        ),
        ("10898 U+0001 chars do not fit", "\u{1}", 10_898),
        ("32000 U+0001 chars do not fit", "\u{1}", 32_000),
        ("8000 four-byte emoji", "\u{1F600}", 8_000),
        ("8001 four-byte emoji", "\u{1F600}", 8_001),
        ("10667 three-byte chars (32001 bytes)", "日", 10_667),
        ("newlines escape to 2 bytes", "\n", 32_000),
    ] {
        let text = f.repeat(count);
        utt_fits.push(json!({
            "name": name,
            "text_fill": { "fill": f, "count": count },
            "fits": vq_protocol::utt_text_fits(&text),
            "max_prefix_bytes": vq_protocol::max_text_prefix(&text).len(),
        }));
    }

    json!({
        "description": "JSON messages (SPEC §4.1, §4.4–4.6; schema in README §10.6). `decode`: the input is `json` (UTF-8 text), `json_hex` (raw bytes) or `json_fill` (prefix + fill repeated count times + suffix, as UTF-8). `result` is `message` (compare the re-encoded message as a JSON object with `expected`, or for large utts with `expected_without_text` plus `text_bytes`), `unknown` (unknown `t`; log and drop), `hello_unsupported` (`hello` with integer v != 1; `peer_name` is the `name` if it was a string), or `error` with an error code. Names starting `R1` exercise the JSON strictness rules of README §5.1; names starting `tie:` the error precedence of README §9.1. `encode`: the canonical compact encoding the Rust implementation emits (informative). `encode_errors`: encoding `message` (wire-form object; `text_fill` gives utt.text) must fail with `error`. `utt_fits`: the sender size rule of README §5.8.",
        "decode": decode,
        "encode": encode,
        "encode_errors": encode_errors,
        "utt_max_overhead_bytes": vq_protocol::message::UTT_MAX_OVERHEAD_BYTES,
        "utt_fits": utt_fits,
    })
}

fn main() {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("vectors");
    fs::create_dir_all(&dir).unwrap();
    for (name, v) in [
        ("framing", framing()),
        ("envelope", envelope_vectors()),
        ("replay", replay()),
        ("crypto", crypto_vectors()),
        ("messages", messages()),
    ] {
        let mut v = v;
        v.as_object_mut()
            .unwrap()
            .insert("vectors_version".into(), json!(1));
        let mut s = serde_json::to_string_pretty(&v).unwrap();
        s.push('\n');
        let path = dir.join(format!("{name}.json"));
        fs::write(&path, s).unwrap();
        println!("wrote {}", path.display());
    }
}
