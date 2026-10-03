//! Checks the library against every committed vector in `protocol/vectors/`.
//! The JSON files are the authority; this file never regenerates them.

use std::path::PathBuf;

use serde_json::Value;
use vq_protocol::crypto::{self, pair_info, PairingCode, SharedSecret, SESSION_INFO};
use vq_protocol::envelope::{decode_envelope, encode_plaintext, nonce, seal_with, Direction};
use vq_protocol::{FrameSplitter, IdentityKeyPair, Message, Reassembler, Role, SessionCipher};

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
            out.extend(std::iter::repeat_n(
                fill[0],
                o["fill_count"].as_u64().unwrap() as usize,
            ));
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
        let mut sp = FrameSplitter::with_seq(c["seq"].as_u64().unwrap() as u16);
        let frames = sp
            .split(&bytes(&c["message"]), c["mtu"].as_u64().unwrap() as usize)
            .unwrap();
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
        let frames = FrameSplitter::with_seq(c["seq"].as_u64().unwrap() as u16)
            .split(&msg, c["mtu"].as_u64().unwrap() as usize)
            .unwrap();
        assert_eq!(frames.len() as u64, c["frame_count"].as_u64().unwrap());
        assert_eq!(hex::encode(&frames[0][..3]), s(&c["first_frame_header"]));
        let last = frames.last().unwrap();
        assert_eq!(hex::encode(&last[..3]), s(&c["last_frame_header"]));
        assert_eq!(last.len() as u64, c["last_frame_len"].as_u64().unwrap());
    }
    for c in arr(&v, "split_errors") {
        let mut sp = FrameSplitter::new();
        let e = sp
            .split(&bytes(&c["message"]), c["mtu"].as_u64().unwrap() as usize)
            .unwrap_err();
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
        let mut sess = match &c["session"] {
            Value::Null => None,
            o => Some(SessionCipher::new(&b32(&o["key"]), role(&o["role"]))),
        };
        let got = decode_envelope(&bytes(&c["envelope"]), sess.as_mut());
        match (s(&c["result"]), got) {
            ("message", Ok(m)) => {
                assert!(!matches!(m, Message::Unknown { .. }), "{name}");
                assert_eq!(m.type_name(), s(&c["type"]), "{name}");
            }
            ("unknown", Ok(Message::Unknown { t })) => assert_eq!(t, s(&c["type"]), "{name}"),
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
        let frames = FrameSplitter::with_seq(c["seq"].as_u64().unwrap() as u16)
            .split(&env, c["mtu"].as_u64().unwrap() as usize)
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
        let code = PairingCode::from_u32(c["value"].as_u64().unwrap() as u32).unwrap();
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

        let mut phone_c = SessionCipher::new(&k_sess, Role::Phone);
        let mut desk_c = SessionCipher::new(&k_sess, Role::Desktop);
        let utt_env = phone_c
            .seal(s(&c["first_utt_plaintext_utf8"]).as_bytes())
            .unwrap();
        assert_eq!(utt_env, bytes(&c["first_utt_envelope"]));
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
            s(&f["fill"]).repeat(f["count"].as_u64().unwrap() as usize),
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
                if let Some(exp) = c.get("expected") {
                    let canon: Value = serde_json::from_slice(&m.to_json().unwrap()).unwrap();
                    assert_eq!(&canon, exp, "{name}");
                    // the canonical form decodes to the same message
                    assert_eq!(
                        Message::from_json(&serde_json::to_vec(exp).unwrap()).unwrap(),
                        m,
                        "{name}"
                    );
                } else if let Some(n) = c.get("text_bytes") {
                    let Message::Utt(u) = &m else {
                        panic!("{name}: text_bytes on non-utt")
                    };
                    assert_eq!(u.text.len() as u64, n.as_u64().unwrap(), "{name}");
                }
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
        let f = &c["text_fill"];
        let text = s(&f["fill"]).repeat(f["count"].as_u64().unwrap() as usize);
        assert_eq!(s(&c["type"]), "utt");
        let m = Message::Utt(vq_protocol::Utt {
            id: uuid_nil(),
            rev: 0,
            state: vq_protocol::UttState::Final,
            text,
            ts: 0,
        });
        assert_eq!(
            m.to_json().unwrap_err().code(),
            s(&c["error"]),
            "{}",
            s(&c["name"])
        );
    }
}

fn uuid_nil() -> uuid::Uuid {
    uuid::Uuid::nil()
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
