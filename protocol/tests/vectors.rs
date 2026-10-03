//! Checks the library against every committed vector in `protocol/vectors/`.
//! The JSON files are the authority; this file never regenerates them.

use std::path::PathBuf;

use serde_json::Value;
use vq_protocol::crypto::{self, pair_info, PairingCode, SharedSecret, SESSION_INFO};
use vq_protocol::envelope::{decode_envelope, encode_plaintext, nonce, seal_with, Direction};
use vq_protocol::{
    check_in_session, decode_inbound, FrameSplitter, IdentityKeyPair, Inbound, Message, PairKey,
    Reassembler, Role, SessionCipher, SessionNonce,
};

fn load(name: &str) -> Value {
    let p = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("vectors")
        .join(format!("{name}.json"));
    let v: Value = serde_json::from_str(&std::fs::read_to_string(&p).unwrap()).unwrap();
    assert_eq!(v["vectors_version"], 1, "{name}");
    v
}

fn arr<'a>(v: &'a Value, k: &str) -> &'a Vec<Value> {
    let a = v[k]
        .as_array()
        .unwrap_or_else(|| panic!("missing array {k}"));
    assert!(!a.is_empty(), "empty array {k}");
    a
}

/// A byte value: a hex string or `{prefix_hex?, fill_hex, fill_count, suffix_hex?}`.
fn bytes(v: &Value) -> Vec<u8> {
    match v {
        Value::String(s) => hex::decode(s).unwrap(),
        Value::Object(o) => {
            let h = |k: &str| {
                o.get(k)
                    .map(|x| hex::decode(x.as_str().unwrap()).unwrap())
                    .unwrap_or_default()
            };
            let fill = h("fill_hex");
            assert_eq!(fill.len(), 1);
            let mut out = h("prefix_hex");
            out.extend(std::iter::repeat_n(fill[0], usz(&o["fill_count"])));
            out.extend(h("suffix_hex"));
            out
        }
        _ => panic!("bad bytes value {v}"),
    }
}

fn b32(v: &Value) -> [u8; 32] {
    bytes(v).try_into().unwrap()
}

fn s(v: &Value) -> &str {
    v.as_str().unwrap()
}

fn u64s(v: &Value) -> u64 {
    s(v).parse().unwrap()
}

/// A JSON number that must fit `usize` exactly (no truncating casts).
fn usz(v: &Value) -> usize {
    usize::try_from(v.as_u64().unwrap()).unwrap()
}

/// A JSON number that must fit `u16` exactly.
fn u16n(v: &Value) -> u16 {
    u16::try_from(v.as_u64().unwrap()).unwrap()
}

fn role(v: &Value) -> Role {
    match s(v) {
        "phone" => Role::Phone,
        "desktop" => Role::Desktop,
        r => panic!("role {r}"),
    }
}

fn direction(v: &Value) -> Direction {
    match s(v) {
        "phone_to_desktop" => Direction::PhoneToDesktop,
        "desktop_to_phone" => Direction::DesktopToPhone,
        d => panic!("direction {d}"),
    }
}

#[test]
fn framing_vectors() {
    let v = load("framing");
    for c in arr(&v, "split") {
        let name = s(&c["name"]);
        let mut sp = FrameSplitter::with_seq(u16n(&c["seq"]));
        let frames = sp.split(&bytes(&c["message"]), usz(&c["mtu"])).unwrap();
        let want: Vec<Vec<u8>> = c["frames"].as_array().unwrap().iter().map(bytes).collect();
        assert_eq!(frames, want, "{name}");
        assert_eq!(
            u64::from(sp.next_seq()),
            c["next_seq"].as_u64().unwrap(),
            "{name}"
        );
        // and they reassemble
        let mut r = Reassembler::new();
        let mut out = None;
        for f in &frames {
            out = r.push(f).unwrap();
        }
        assert_eq!(out.unwrap(), bytes(&c["message"]), "{name}");
    }
    for c in arr(&v, "split_large") {
        let msg = bytes(&c["message"]);
        let frames = FrameSplitter::with_seq(u16n(&c["seq"]))
            .split(&msg, usz(&c["mtu"]))
            .unwrap();
        assert_eq!(frames.len(), usz(&c["frame_count"]));
        assert_eq!(hex::encode(&frames[0][..3]), s(&c["first_frame_header"]));
        let last = frames.last().unwrap();
        assert_eq!(hex::encode(&last[..3]), s(&c["last_frame_header"]));
        assert_eq!(last.len(), usz(&c["last_frame_len"]));
    }
    for c in arr(&v, "split_errors") {
        let mut sp = FrameSplitter::new();
        let e = sp.split(&bytes(&c["message"]), usz(&c["mtu"])).unwrap_err();
        assert_eq!(e.code(), s(&c["error"]), "{}", s(&c["name"]));
        assert_eq!(sp.next_seq(), 0);
    }
    for c in arr(&v, "reassembly") {
        let name = s(&c["name"]);
        let mut r = Reassembler::new();
        for (i, st) in c["steps"].as_array().unwrap().iter().enumerate() {
            let got = r.push(&bytes(&st["frame"]));
            match (s(&st["result"]), got) {
                ("pending", Ok(None)) => {}
                ("message", Ok(Some(m))) => assert_eq!(m, bytes(&st["message"]), "{name} step {i}"),
                ("error", Err(e)) => assert_eq!(e.code(), s(&st["error"]), "{name} step {i}"),
                (want, got) => panic!("{name} step {i}: want {want}, got {got:?}"),
            }
        }
    }
}

#[test]
fn envelope_vectors() {
    let v = load("envelope");
    for c in arr(&v, "plaintext") {
        let json = s(&c["json_utf8"]);
        let env = bytes(&c["envelope"]);
        assert_eq!(env[0], 0x00);
        assert_eq!(&env[1..], json.as_bytes());
        let m = Message::from_json(json.as_bytes()).unwrap();
        assert_eq!(encode_plaintext(&m).unwrap(), env);
        assert_eq!(decode_envelope(&env, None).unwrap(), m);
    }
    for c in arr(&v, "encrypt") {
        let name = s(&c["name"]);
        let key = b32(&c["key"]);
        let dir = direction(&c["direction"]);
        let counter = u64s(&c["counter"]);
        let pt = bytes(&c["plaintext"]);
        let env = bytes(&c["envelope"]);
        assert_eq!(hex::encode(nonce(dir, counter)), s(&c["nonce"]), "{name}");
        assert_eq!(s(&c["aad"]), "01");
        assert_eq!(seal_with(&key, dir, counter, &pt).unwrap(), env, "{name}");
        // stateful sender produces the same bytes
        let sender = if dir == Direction::PhoneToDesktop {
            Role::Phone
        } else {
            Role::Desktop
        };
        let mut tx = SessionCipher::new(&key, sender).with_send_counter(counter);
        assert_eq!(tx.seal(&pt).unwrap(), env, "{name}");
        let receiver = if sender == Role::Phone {
            Role::Desktop
        } else {
            Role::Phone
        };
        let mut rx = SessionCipher::new(&key, receiver);
        assert_eq!(rx.open(&env).unwrap(), pt, "{name}");
        assert_eq!(rx.last_received_counter(), Some(counter));
    }
    for c in arr(&v, "open_errors") {
        let name = s(&c["name"]);
        let mut rx = SessionCipher::new(&b32(&c["key"]), role(&c["receiver_role"]));
        let got = rx.open(&bytes(&c["envelope"]));
        match &c["error"] {
            Value::Null => assert_eq!(got.unwrap(), bytes(&c["plaintext"]), "{name}"),
            e => {
                assert_eq!(got.unwrap_err().code(), s(e), "{name}");
                assert_eq!(rx.last_received_counter(), None, "{name}");
            }
        }
    }
    for c in arr(&v, "decode") {
        let name = s(&c["name"]);
        let mut sess = session_from(&c["session"]);
        let got = decode_inbound(&bytes(&c["envelope"]), sess.as_mut());
        check_inbound(name, c, got);
        if let Some(rx) = &sess {
            let want = match &c["last_accepted_after"] {
                Value::Null => None,
                x => Some(u64s(x)),
            };
            assert_eq!(rx.last_received_counter(), want, "{name}");
        } else {
            assert!(c.get("last_accepted_after").is_none(), "{name}");
        }
        // the provenance-free test helper agrees
        let mut sess2 = session_from(&c["session"]);
        let r2 = decode_envelope(&bytes(&c["envelope"]), sess2.as_mut());
        assert_eq!(r2.is_ok(), s(&c["result"]) != "error", "{name}");
    }
    for c in arr(&v, "in_session") {
        let name = s(&c["name"]);
        let mut sess = session_from(&c["session"]);
        assert!(sess.is_some(), "{name}");
        let got = decode_inbound(&bytes(&c["envelope"]), sess.as_mut())
            .and_then(|i| check_in_session(&i).map(|()| i));
        match (s(&c["result"]), got) {
            ("ok", Ok(i)) => {
                assert_eq!(i.message().type_name(), s(&c["type"]), "{name}");
                assert_eq!(
                    i.is_authenticated(),
                    c["authenticated"].as_bool().unwrap(),
                    "{name}"
                );
            }
            ("error", Err(e)) => assert_eq!(e.code(), s(&c["error"]), "{name}"),
            (want, got) => panic!("{name}: want {want}, got {got:?}"),
        }
    }
    for c in arr(&v, "stack") {
        let name = s(&c["name"]);
        let key = b32(&c["key"]);
        let sender = role(&c["sender_role"]);
        let pt = s(&c["plaintext_utf8"]).as_bytes();
        let mut tx = SessionCipher::new(&key, sender).with_send_counter(u64s(&c["counter"]));
        let env = tx.seal(pt).unwrap();
        assert_eq!(env, bytes(&c["envelope"]), "{name}");
        let frames = FrameSplitter::with_seq(u16n(&c["seq"]))
            .split(&env, usz(&c["mtu"]))
            .unwrap();
        let want: Vec<Vec<u8>> = c["frames"].as_array().unwrap().iter().map(bytes).collect();
        assert_eq!(frames, want, "{name}");
        // receive path: frames → envelope → message
        let mut r = Reassembler::new();
        let mut out = None;
        for f in &want {
            out = r.push(f).unwrap();
        }
        let receiver = if sender == Role::Phone {
            Role::Desktop
        } else {
            Role::Phone
        };
        let mut rx = SessionCipher::new(&key, receiver);
        let m = decode_envelope(&out.unwrap(), Some(&mut rx)).unwrap();
        assert_eq!(m, Message::from_json(pt).unwrap(), "{name}");
    }
}

/// A desktop/phone receiver for `session` (null = no session), after opening
/// every envelope in `session.prior`.
fn session_from(v: &Value) -> Option<SessionCipher> {
    match v {
        Value::Null => None,
        o => {
            let mut c = SessionCipher::new(&b32(&o["key"]), role(&o["role"]));
            for e in o["prior"].as_array().unwrap() {
                c.open(&bytes(e)).unwrap();
            }
            Some(c)
        }
    }
}

/// Compare a decoded message with a vector's canonical `expected` object
/// (and, for large utts, `expected_without_text` + `text_bytes`).
fn check_expected(name: &str, c: &Value, m: &Message) {
    let mut canon: Value = serde_json::from_slice(&m.to_json().unwrap()).unwrap();
    if let Some(exp) = c.get("expected") {
        assert_eq!(&canon, exp, "{name}");
        // the canonical form decodes to the same message
        assert_eq!(
            &Message::from_json(&serde_json::to_vec(exp).unwrap()).unwrap(),
            m,
            "{name}"
        );
    } else {
        let Message::Utt(u) = m else {
            panic!("{name}: no `expected` on a non-utt")
        };
        assert_eq!(u.text.len(), usz(&c["text_bytes"]), "{name}");
        canon.as_object_mut().unwrap().remove("text");
        assert_eq!(&canon, &c["expected_without_text"], "{name}");
    }
}

fn check_inbound(name: &str, c: &Value, got: vq_protocol::Result<Inbound>) {
    let auth = |i: &Inbound| {
        assert_eq!(
            i.is_authenticated(),
            c["authenticated"].as_bool().unwrap(),
            "{name}"
        );
        assert_eq!(
            matches!(i, Inbound::Encrypted(_)),
            bytes(&c["envelope"])[0] == 0x01,
            "{name}"
        );
    };
    match (s(&c["result"]), got) {
        ("message", Ok(i)) => {
            auth(&i);
            let m = i.into_message();
            assert!(
                !matches!(m, Message::Unknown { .. } | Message::HelloUnsupported(_)),
                "{name}"
            );
            assert_eq!(m.type_name(), s(&c["type"]), "{name}");
            check_expected(name, c, &m);
        }
        ("unknown", Ok(i)) => {
            auth(&i);
            let Message::Unknown { t } = i.into_message() else {
                panic!("{name}: want unknown")
            };
            assert_eq!(t, s(&c["type"]), "{name}");
        }
        ("hello_unsupported", Ok(i)) => {
            auth(&i);
            let Message::HelloUnsupported(h) = i.into_message() else {
                panic!("{name}: want hello_unsupported")
            };
            assert_eq!(h.v, c["v"].as_u64().unwrap(), "{name}");
            assert_eq!(h.name.as_deref(), c["peer_name"].as_str(), "{name}");
        }
        ("error", Err(e)) => assert_eq!(e.code(), s(&c["error"]), "{name}"),
        (want, got) => panic!("{name}: want {want}, got {got:?}"),
    }
}

#[test]
fn replay_vectors() {
    let v = load("replay");
    for c in arr(&v, "sequences") {
        let name = s(&c["name"]);
        let mut rx = SessionCipher::new(&b32(&c["key"]), role(&c["receiver_role"]));
        for (i, st) in c["steps"].as_array().unwrap().iter().enumerate() {
            let got = rx.open(&bytes(&st["envelope"]));
            match (s(&st["result"]), got) {
                ("ok", Ok(pt)) => assert_eq!(pt, bytes(&st["plaintext"]), "{name} step {i}"),
                ("error", Err(e)) => assert_eq!(e.code(), s(&st["error"]), "{name} step {i}"),
                (want, got) => panic!("{name} step {i}: want {want}, got {got:?}"),
            }
            let last = match &st["last_accepted_after"] {
                Value::Null => None,
                x => Some(u64s(x)),
            };
            assert_eq!(rx.last_received_counter(), last, "{name} step {i}");
        }
    }
    for c in arr(&v, "send_sequences") {
        let name = s(&c["name"]);
        let mut tx = SessionCipher::new(&b32(&c["key"]), role(&c["sender_role"]))
            .with_send_counter(u64s(&c["start_counter"]));
        for (i, st) in c["sends"].as_array().unwrap().iter().enumerate() {
            let got = tx.seal(&bytes(&st["plaintext"]));
            match (s(&st["result"]), got) {
                ("ok", Ok(env)) => assert_eq!(env, bytes(&st["envelope"]), "{name} step {i}"),
                ("error", Err(e)) => assert_eq!(e.code(), s(&st["error"]), "{name} step {i}"),
                (want, got) => panic!("{name} step {i}: want {want}, got {got:?}"),
            }
        }
    }
}

#[test]
fn crypto_vectors() {
    let v = load("crypto");
    for c in arr(&v, "x25519") {
        let a = IdentityKeyPair::from_secret_bytes(b32(&c["priv_a"]));
        let b = IdentityKeyPair::from_secret_bytes(b32(&c["priv_b"]));
        assert_eq!(a.public_bytes(), b32(&c["pub_a"]));
        assert_eq!(b.public_bytes(), b32(&c["pub_b"]));
        assert_eq!(
            a.shared_secret(&b.public_bytes()).unwrap().as_bytes(),
            &b32(&c["shared"])
        );
        assert_eq!(
            b.shared_secret(&a.public_bytes()).unwrap().as_bytes(),
            &b32(&c["shared"])
        );
    }
    for c in arr(&v, "x25519_errors") {
        let a = IdentityKeyPair::from_secret_bytes(b32(&c["priv"]));
        assert_eq!(
            a.shared_secret(&b32(&c["peer_pub"])).unwrap_err().code(),
            s(&c["error"]),
            "{}",
            s(&c["name"])
        );
    }
    for c in arr(&v, "x25519_high_bit") {
        let a = IdentityKeyPair::from_secret_bytes(b32(&c["priv"]));
        let hi = b32(&c["peer_pub"]);
        let lo = b32(&c["peer_pub_masked"]);
        assert_eq!(hi[31] & 0x80, 0x80);
        assert_eq!(lo, {
            let mut m = hi;
            m[31] &= 0x7F;
            m
        });
        for p in [hi, lo] {
            assert_eq!(
                a.shared_secret(&p).unwrap().as_bytes(),
                &b32(&c["shared"]),
                "{}",
                s(&c["name"])
            );
        }
    }
    for c in arr(&v, "pair_key") {
        let code: PairingCode = s(&c["code"]).parse().unwrap();
        let (np, nd) = (b32(&c["nonce_p"]), b32(&c["nonce_d"]));
        assert_eq!(bytes(&c["salt"]), [np, nd].concat());
        assert_eq!(bytes(&c["info"]), pair_info(&code));
        assert_eq!(bytes(&c["info"]), s(&c["info_ascii"]).as_bytes());
        let ss = SharedSecret::from_bytes(b32(&c["shared"]));
        assert_eq!(
            crypto::derive_pair_key(&ss, &np, &nd, &code),
            b32(&c["k_pair"]),
            "{}",
            s(&c["name"])
        );
    }
    for c in arr(&v, "session_key") {
        let (a, b) = (b32(&c["nonce_phone"]), b32(&c["nonce_desktop"]));
        assert_eq!(bytes(&c["salt"]), [a, b].concat());
        assert_eq!(bytes(&c["info"]), SESSION_INFO);
        let ss = SharedSecret::from_bytes(b32(&c["shared"]));
        assert_eq!(
            crypto::derive_session_key(&ss, &a, &b),
            b32(&c["k_sess"]),
            "{}",
            s(&c["name"])
        );
    }
    for c in arr(&v, "pair_mac") {
        let (k, pp, pd) = (
            b32(&c["k_pair"]),
            b32(&c["pub_phone"]),
            b32(&c["pub_desktop"]),
        );
        assert_eq!(
            bytes(&c["phone_mac_input"]),
            [&b"phone"[..], &pp, &pd].concat()
        );
        assert_eq!(
            bytes(&c["desktop_mac_input"]),
            [&b"desktop"[..], &pd, &pp].concat()
        );
        assert_eq!(
            crypto::phone_confirm_mac(&k, &pp, &pd),
            b32(&c["phone_mac"])
        );
        assert_eq!(
            crypto::desktop_result_mac(&k, &pp, &pd),
            b32(&c["desktop_mac"])
        );
    }
    for c in arr(&v, "pair_mac_verify") {
        let (k, pp, pd, mac) = (
            b32(&c["k_pair"]),
            b32(&c["pub_phone"]),
            b32(&c["pub_desktop"]),
            b32(&c["mac"]),
        );
        let r = match s(&c["kind"]) {
            "phone" => crypto::verify_phone_confirm_mac(&k, &pp, &pd, &mac),
            "desktop" => crypto::verify_desktop_result_mac(&k, &pp, &pd, &mac),
            other => panic!("{other}"),
        };
        assert_eq!(
            r.is_ok(),
            c["valid"].as_bool().unwrap(),
            "{}",
            s(&c["name"])
        );
        if let Err(e) = r {
            assert_eq!(e.code(), "bad_mac");
        }
    }
    for c in arr(&v, "code_format") {
        let code =
            PairingCode::from_u32(u32::try_from(c["value"].as_u64().unwrap()).unwrap()).unwrap();
        assert_eq!(code.to_string(), s(&c["string"]));
        assert_eq!(&code.ascii(), s(&c["string"]).as_bytes());
    }
    for c in arr(&v, "code_parse") {
        let r = s(&c["input"]).parse::<PairingCode>();
        if c["valid"].as_bool().unwrap() {
            assert_eq!(u64::from(r.unwrap().value()), c["value"].as_u64().unwrap());
        } else {
            assert_eq!(r.unwrap_err().code(), "invalid_code", "{:?}", c["input"]);
        }
    }
    for c in arr(&v, "full_pairing") {
        let phone = IdentityKeyPair::from_secret_bytes(b32(&c["phone_priv"]));
        let desk = IdentityKeyPair::from_secret_bytes(b32(&c["desktop_priv"]));
        let (pp, pd) = (phone.public_bytes(), desk.public_bytes());
        assert_eq!(pp, b32(&c["phone_pub"]));
        assert_eq!(pd, b32(&c["desktop_pub"]));
        let ss = phone.shared_secret(&pd).unwrap();
        assert_eq!(ss.as_bytes(), &b32(&c["shared"]));

        // walk the plaintext transcript and check every field against the scalars
        let t = c["transcript"].as_array().unwrap();
        let msgs: Vec<Message> = t
            .iter()
            .map(|e| {
                let env = bytes(&e["envelope"]);
                assert_eq!(&env[1..], s(&e["json_utf8"]).as_bytes());
                decode_envelope(&env, None).unwrap()
            })
            .collect();
        let [Message::Hello(hd), Message::Hello(hp), Message::PairRequest(req), Message::PairChallenge(ch), Message::PairConfirm(conf), Message::PairResult(res)] =
            msgs.as_slice()
        else {
            panic!("unexpected transcript shape: {msgs:?}");
        };
        assert_eq!(hd.public_key, pd);
        assert_eq!(hp.public_key, pp);
        assert_eq!(hd.device_id.to_string(), s(&c["desktop_device_id"]));
        assert_eq!(hp.device_id.to_string(), s(&c["phone_device_id"]));
        assert_eq!(req.nonce_p, b32(&c["nonce_p"]));
        assert_eq!(ch.nonce_d, b32(&c["nonce_d"]));
        let code: PairingCode = s(&c["code"]).parse().unwrap();
        let k_pair = crypto::derive_pair_key(&ss, &req.nonce_p, &ch.nonce_d, &code);
        assert_eq!(k_pair, b32(&c["k_pair"]));
        crypto::verify_phone_confirm_mac(&k_pair, &pp, &pd, &conf.mac).unwrap();
        assert_eq!(conf.mac, b32(&c["phone_mac"]));
        assert!(res.ok);
        crypto::verify_desktop_result_mac(&k_pair, &pp, &pd, &res.mac.unwrap()).unwrap();
        assert_eq!(res.mac.unwrap(), b32(&c["desktop_mac"]));

        assert_eq!(hp.session_nonce, b32(&c["session_nonce_phone"]));
        assert_eq!(hd.session_nonce, b32(&c["session_nonce_desktop"]));
        let ss_d = desk.shared_secret(&pp).unwrap();
        let k_sess = crypto::derive_session_key(&ss_d, &hp.session_nonce, &hd.session_nonce);
        assert_eq!(k_sess, b32(&c["k_sess"]));

        // The production API reproduces the same keys and MACs.
        let pk_phone = PairKey::derive(&phone, Role::Phone, &pd, req, ch, &code).unwrap();
        let pk_desk = PairKey::derive(&desk, Role::Desktop, &pp, req, ch, &code).unwrap();
        assert_eq!(pk_phone.key_bytes_for_tests(), b32(&c["k_pair"]));
        assert_eq!(pk_desk.key_bytes_for_tests(), b32(&c["k_pair"]));
        assert_eq!(&pk_phone.confirm_message(), conf);
        assert_eq!(&pk_desk.success_message(), res);
        pk_desk.verify_phone_mac(&conf.mac).unwrap();
        pk_phone.verify_desktop_mac(&res.mac.unwrap()).unwrap();

        let mut phone_c = SessionCipher::establish(
            &phone,
            Role::Phone,
            &hd.public_key,
            SessionNonce::from_bytes_for_tests(hp.session_nonce),
            &hd.session_nonce,
        )
        .unwrap();
        let mut desk_c = SessionCipher::establish(
            &desk,
            Role::Desktop,
            &hp.public_key,
            SessionNonce::from_bytes_for_tests(hd.session_nonce),
            &hp.session_nonce,
        )
        .unwrap();
        // ...and agrees with the raw key from the vector
        let mut raw_rx = SessionCipher::new(&k_sess, Role::Desktop);
        let utt_env = phone_c
            .seal(s(&c["first_utt_plaintext_utf8"]).as_bytes())
            .unwrap();
        assert_eq!(utt_env, bytes(&c["first_utt_envelope"]));
        assert_eq!(
            raw_rx.open(&utt_env).unwrap(),
            s(&c["first_utt_plaintext_utf8"]).as_bytes()
        );
        assert!(matches!(
            decode_envelope(&utt_env, Some(&mut desk_c)).unwrap(),
            Message::Utt(_)
        ));
        let ack_env = desk_c
            .seal(s(&c["first_ack_plaintext_utf8"]).as_bytes())
            .unwrap();
        assert_eq!(ack_env, bytes(&c["first_ack_envelope"]));
        assert!(matches!(
            decode_envelope(&ack_env, Some(&mut phone_c)).unwrap(),
            Message::Ack(_)
        ));
    }
}

fn message_input(c: &Value) -> Vec<u8> {
    if let Some(j) = c.get("json") {
        s(j).as_bytes().to_vec()
    } else if let Some(h) = c.get("json_hex") {
        bytes(h)
    } else {
        let f = &c["json_fill"];
        format!(
            "{}{}{}",
            s(&f["prefix"]),
            s(&f["fill"]).repeat(usz(&f["count"])),
            s(&f["suffix"])
        )
        .into_bytes()
    }
}

#[test]
fn message_vectors() {
    let v = load("messages");
    for c in arr(&v, "decode") {
        let name = s(&c["name"]);
        let got = Message::from_json(&message_input(c));
        match (s(&c["result"]), got) {
            ("message", Ok(m)) => {
                assert!(
                    !matches!(m, Message::Unknown { .. } | Message::HelloUnsupported(_)),
                    "{name}"
                );
                assert_eq!(m.type_name(), s(&c["type"]), "{name}");
                check_expected(name, c, &m);
            }
            ("unknown", Ok(Message::Unknown { t })) => assert_eq!(t, s(&c["type"]), "{name}"),
            ("hello_unsupported", Ok(Message::HelloUnsupported(h))) => {
                assert_eq!(h.v, c["v"].as_u64().unwrap(), "{name}");
                assert_eq!(h.name.as_deref(), c["peer_name"].as_str(), "{name}");
            }
            ("error", Err(e)) => assert_eq!(e.code(), s(&c["error"]), "{name}: {e}"),
            (want, got) => panic!("{name}: want {want}, got {got:?}"),
        }
    }
    for c in arr(&v, "encode") {
        let j = s(&c["json"]);
        let m = Message::from_json(j.as_bytes()).unwrap();
        assert_eq!(m.type_name(), s(&c["type"]));
        assert_eq!(m.to_json().unwrap(), j.as_bytes());
        assert_eq!(&serde_json::from_str::<Value>(j).unwrap(), &c["object"]);
    }
    for c in arr(&v, "encode_errors") {
        let m = message_from_object(&c["message"], c.get("text_fill"));
        assert_eq!(
            m.to_json().unwrap_err().code(),
            s(&c["error"]),
            "{}",
            s(&c["name"])
        );
    }
    let overhead = usz(&v["utt_max_overhead_bytes"]);
    assert_eq!(overhead, vq_protocol::message::UTT_MAX_OVERHEAD_BYTES);
    for c in arr(&v, "utt_fits") {
        let name = s(&c["name"]);
        let f = &c["text_fill"];
        let text = s(&f["fill"]).repeat(usz(&f["count"]));
        assert_eq!(
            vq_protocol::utt_text_fits(&text),
            c["fits"].as_bool().unwrap(),
            "{name}"
        );
        let prefix = vq_protocol::max_text_prefix(&text);
        assert_eq!(prefix.len(), usz(&c["max_prefix_bytes"]), "{name}");
        // the prefix always encodes and seals with worst-case other fields
        let m = Message::Utt(vq_protocol::Utt {
            id: uuid::Uuid::nil(),
            rev: u32::MAX,
            state: vq_protocol::UttState::Partial,
            text: prefix.to_owned(),
            ts: u64::MAX,
        });
        assert!(
            m.to_json().unwrap().len() <= vq_protocol::MAX_ENCRYPTED_JSON_BYTES,
            "{name}"
        );
    }
}

/// Build a message (possibly one that cannot be encoded) from a vector's
/// wire-form object; `text_fill` supplies `utt.text`.
fn message_from_object(o: &Value, text_fill: Option<&Value>) -> Message {
    let uuid = |k: &str| vq_protocol::b64::parse_uuid(s(&o[k])).unwrap();
    let b = |k: &str| vq_protocol::b64::decode_fixed::<32>(s(&o[k])).unwrap();
    match s(&o["t"]) {
        "utt" => {
            let text = match text_fill {
                Some(f) => s(&f["fill"]).repeat(usz(&f["count"])),
                None => s(&o["text"]).to_owned(),
            };
            Message::Utt(vq_protocol::Utt {
                id: uuid("id"),
                rev: u32::try_from(o["rev"].as_u64().unwrap()).unwrap(),
                state: match s(&o["state"]) {
                    "partial" => vq_protocol::UttState::Partial,
                    "final" => vq_protocol::UttState::Final,
                    "edit" => vq_protocol::UttState::Edit,
                    x => panic!("state {x}"),
                },
                text,
                ts: o["ts"].as_u64().unwrap(),
            })
        }
        "hello" => Message::Hello(vq_protocol::Hello {
            v: u32::try_from(o["v"].as_u64().unwrap()).unwrap(),
            device_id: uuid("device_id"),
            name: s(&o["name"]).to_owned(),
            public_key: b("pub"),
            paired: o["paired"].as_bool().unwrap(),
            session_nonce: b("session_nonce"),
        }),
        "pair_result" => Message::PairResult(vq_protocol::PairResult {
            ok: o["ok"].as_bool().unwrap(),
            mac: o.get("mac").map(|_| b("mac")),
        }),
        t => panic!("encode_errors: unsupported type {t}"),
    }
}

/// Every vector file in the directory is covered by a test above.
#[test]
fn all_vector_files_are_checked() {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("vectors");
    let mut names: Vec<String> = std::fs::read_dir(dir)
        .unwrap()
        .map(|e| e.unwrap().file_name().into_string().unwrap())
        .filter(|n| n.ends_with(".json"))
        .collect();
    names.sort();
    assert_eq!(
        names,
        [
            "crypto.json",
            "envelope.json",
            "framing.json",
            "messages.json",
            "replay.json"
        ]
    );
}
