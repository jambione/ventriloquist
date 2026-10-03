//! JSON application messages (SPEC §4.1, §4.4–§4.6).
//!
//! Every message is a UTF-8 JSON object with a string `"t"` type field.
//! Unknown fields are ignored. An unknown `t` decodes to [`Message::Unknown`]
//! (the caller logs and drops it; it is never fatal). A `hello` whose `v` is
//! an integer other than [`crate::PROTOCOL_VERSION`] decodes to
//! [`Message::HelloUnsupported`] so the receiver can answer with
//! `error{code:"version"}`.

use serde::{Deserialize, Serialize};
use serde_json::Value;
use uuid::Uuid;

use crate::b64;
use crate::error::{Error, Result};
use crate::{MAX_MESSAGE_BYTES, MAX_TEXT_BYTES, PROTOCOL_VERSION};

/// `hello` (both directions, plaintext). §4.4 step 1 and §4.5.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Hello {
    /// Protocol version; always 1 for a decoded [`Message::Hello`].
    pub v: u32,
    /// Sender's random 128-bit install identifier.
    #[serde(with = "b64::uuid_str")]
    pub device_id: Uuid,
    /// Sender's human-readable device name.
    pub name: String,
    /// Sender's long-term X25519 public key (wire field `pub`).
    #[serde(rename = "pub", with = "b64::bytes32")]
    pub public_key: [u8; 32],
    /// Whether the sender has a stored pairing for the receiver (see README).
    pub paired: bool,
    /// Fresh 32-byte random nonce for this connection (§4.5).
    #[serde(with = "b64::bytes32")]
    pub session_nonce: [u8; 32],
}

/// A `hello` carrying a `v` this implementation does not speak.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HelloUnsupported {
    /// The peer's protocol version.
    pub v: u64,
    /// The peer's name, if it was present and a string.
    pub name: Option<String>,
}

/// `pair_request` (phone → desktop, plaintext). §4.4 step 2.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PairRequest {
    /// 32 random bytes chosen by the phone.
    #[serde(with = "b64::bytes32")]
    pub nonce_p: [u8; 32],
}

/// `pair_challenge` (desktop → phone, plaintext). §4.4 step 3.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PairChallenge {
    /// 32 random bytes chosen by the desktop.
    #[serde(with = "b64::bytes32")]
    pub nonce_d: [u8; 32],
}

/// `pair_confirm` (phone → desktop, plaintext). §4.4 step 4.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PairConfirm {
    /// `HMAC-SHA256(K_pair, "phone" ‖ pub_p ‖ pub_d)`.
    #[serde(with = "b64::bytes32")]
    pub mac: [u8; 32],
}

/// `pair_result` (desktop → phone, plaintext). §4.4 step 5.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PairResult {
    /// Whether the phone's MAC verified.
    pub ok: bool,
    /// `HMAC-SHA256(K_pair, "desktop" ‖ pub_d ‖ pub_p)`; present iff `ok`.
    #[serde(
        default,
        with = "b64::opt_bytes32",
        skip_serializing_if = "Option::is_none"
    )]
    pub mac: Option<[u8; 32]>,
}

impl PairResult {
    /// Successful result carrying the desktop MAC.
    pub fn success(mac: [u8; 32]) -> Self {
        Self {
            ok: true,
            mac: Some(mac),
        }
    }
    /// Failed result (no MAC).
    pub fn failure() -> Self {
        Self {
            ok: false,
            mac: None,
        }
    }
}

/// `error` (either direction, plaintext). §4.5.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ErrorMsg {
    /// Machine-readable code; see [`ErrorMsg::UNKNOWN_PEER`] etc. Open set.
    pub code: String,
    /// Human-readable detail. Defaults to `""` when absent.
    #[serde(default)]
    pub msg: String,
}

impl ErrorMsg {
    /// Peer is not paired / not recognised.
    pub const UNKNOWN_PEER: &'static str = "unknown_peer";
    /// Pairing MAC did not verify.
    pub const BAD_MAC: &'static str = "bad_mac";
    /// An encrypted envelope failed to decrypt.
    pub const DECRYPT_FAILED: &'static str = "decrypt_failed";
    /// Protocol version mismatch.
    pub const VERSION: &'static str = "version";

    /// Convenience constructor.
    pub fn new(code: impl Into<String>, msg: impl Into<String>) -> Self {
        Self {
            code: code.into(),
            msg: msg.into(),
        }
    }
}

/// `utt.state`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum UttState {
    /// Live, volatile text.
    Partial,
    /// Final text at stop.
    Final,
    /// User correction after stop.
    Edit,
}

/// `utt` (phone → desktop, encrypted). §4.6.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Utt {
    /// Utterance id.
    #[serde(with = "b64::uuid_str")]
    pub id: Uuid,
    /// Revision; the desktop keeps the highest per `id`.
    pub rev: u32,
    /// partial / final / edit.
    pub state: UttState,
    /// Full current text (not a diff), at most 32,000 UTF-8 bytes.
    pub text: String,
    /// Start of utterance, milliseconds since the Unix epoch.
    pub ts: u64,
}

/// `ack` (desktop → phone, encrypted). §4.6.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Ack {
    /// Acknowledged utterance id.
    #[serde(with = "b64::uuid_str")]
    pub id: Uuid,
    /// Acknowledged revision.
    pub rev: u32,
}

/// A decoded protocol message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Message {
    /// `hello` with `v == 1`.
    Hello(Hello),
    /// `hello` with an integer `v != 1` (receive-only).
    HelloUnsupported(HelloUnsupported),
    /// `pair_request`.
    PairRequest(PairRequest),
    /// `pair_challenge`.
    PairChallenge(PairChallenge),
    /// `pair_confirm`.
    PairConfirm(PairConfirm),
    /// `pair_result`.
    PairResult(PairResult),
    /// `error`.
    Error(ErrorMsg),
    /// `utt`.
    Utt(Utt),
    /// `ack`.
    Ack(Ack),
    /// `ping`.
    Ping,
    /// `pong`.
    Pong,
    /// Any other `t` (receive-only). Log and drop.
    Unknown {
        /// The unrecognised `t` value.
        t: String,
    },
}

/// Serialize-only view used for encoding, so `"t"` is emitted first.
#[derive(Serialize)]
#[serde(tag = "t", rename_all = "snake_case")]
enum WireRef<'a> {
    Hello(&'a Hello),
    PairRequest(&'a PairRequest),
    PairChallenge(&'a PairChallenge),
    PairConfirm(&'a PairConfirm),
    PairResult(&'a PairResult),
    Error(&'a ErrorMsg),
    Utt(&'a Utt),
    Ack(&'a Ack),
    Ping,
    Pong,
}

/// Types allowed inside a plaintext envelope (§4.3).
pub const PLAINTEXT_ALLOWED: [&str; 6] = [
    "hello",
    "pair_request",
    "pair_challenge",
    "pair_confirm",
    "pair_result",
    "error",
];

impl Message {
    /// The wire `t` value of this message.
    pub fn type_name(&self) -> &str {
        match self {
            Message::Hello(_) | Message::HelloUnsupported(_) => "hello",
            Message::PairRequest(_) => "pair_request",
            Message::PairChallenge(_) => "pair_challenge",
            Message::PairConfirm(_) => "pair_confirm",
            Message::PairResult(_) => "pair_result",
            Message::Error(_) => "error",
            Message::Utt(_) => "utt",
            Message::Ack(_) => "ack",
            Message::Ping => "ping",
            Message::Pong => "pong",
            Message::Unknown { t } => t,
        }
    }

    /// Whether this message type may travel in a plaintext envelope.
    ///
    /// [`Message::Unknown`] returns `false`; [`crate::decode_envelope`] passes
    /// unknown types through (for the caller to drop) rather than rejecting them.
    pub fn is_plaintext_allowed(&self) -> bool {
        !matches!(self, Message::Unknown { .. }) && PLAINTEXT_ALLOWED.contains(&self.type_name())
    }

    /// Encode as compact UTF-8 JSON with `"t"` first.
    ///
    /// Fails for receive-only variants, for `utt.text` over 32,000 bytes, for
    /// an inconsistent `pair_result`, and when the output exceeds 64 KiB.
    pub fn to_json(&self) -> Result<Vec<u8>> {
        let wire = match self {
            Message::Hello(m) => WireRef::Hello(m),
            Message::PairRequest(m) => WireRef::PairRequest(m),
            Message::PairChallenge(m) => WireRef::PairChallenge(m),
            Message::PairConfirm(m) => WireRef::PairConfirm(m),
            Message::PairResult(m) => {
                if m.ok != m.mac.is_some() {
                    return Err(Error::NotEncodable(
                        "pair_result must carry a mac iff ok is true",
                    ));
                }
                WireRef::PairResult(m)
            }
            Message::Error(m) => WireRef::Error(m),
            Message::Utt(m) => {
                check_text(&m.text)?;
                WireRef::Utt(m)
            }
            Message::Ack(m) => WireRef::Ack(m),
            Message::Ping => WireRef::Ping,
            Message::Pong => WireRef::Pong,
            Message::HelloUnsupported(_) => {
                return Err(Error::NotEncodable("HelloUnsupported is receive-only"))
            }
            Message::Unknown { .. } => return Err(Error::NotEncodable("Unknown is receive-only")),
        };
        // Serializing these plain structs into a Vec cannot fail in practice.
        let bytes = serde_json::to_vec(&wire)
            .map_err(|_| Error::NotEncodable("JSON serialization failed"))?;
        if bytes.len() > MAX_MESSAGE_BYTES {
            return Err(Error::MessageTooLarge(bytes.len()));
        }
        Ok(bytes)
    }

    /// Decode a JSON message body.
    pub fn from_json(bytes: &[u8]) -> Result<Message> {
        if bytes.len() > MAX_MESSAGE_BYTES {
            return Err(Error::MessageTooLarge(bytes.len()));
        }
        let value: Value =
            serde_json::from_slice(bytes).map_err(|e| Error::InvalidJson(e.to_string()))?;
        let Value::Object(map) = &value else {
            return Err(Error::InvalidMessage("message is not a JSON object".into()));
        };
        let t = match map.get("t") {
            Some(Value::String(t)) => t.clone(),
            Some(_) => return Err(Error::InvalidMessage("`t` is not a string".into())),
            None => return Err(Error::InvalidMessage("missing `t`".into())),
        };
        let msg = match t.as_str() {
            "hello" => {
                let v = match map.get("v") {
                    Some(v) => v.as_u64().ok_or_else(|| {
                        Error::InvalidMessage("hello.v is not a non-negative integer".into())
                    })?,
                    None => return Err(Error::InvalidMessage("hello: missing field `v`".into())),
                };
                if v != u64::from(PROTOCOL_VERSION) {
                    Message::HelloUnsupported(HelloUnsupported {
                        v,
                        name: map.get("name").and_then(Value::as_str).map(str::to_owned),
                    })
                } else {
                    Message::Hello(field_parse(&t, value)?)
                }
            }
            "pair_request" => Message::PairRequest(field_parse(&t, value)?),
            "pair_challenge" => Message::PairChallenge(field_parse(&t, value)?),
            "pair_confirm" => Message::PairConfirm(field_parse(&t, value)?),
            "pair_result" => {
                let mut r: PairResult = field_parse(&t, value)?;
                if r.ok && r.mac.is_none() {
                    return Err(Error::InvalidMessage(
                        "pair_result: ok is true but mac is missing".into(),
                    ));
                }
                if !r.ok {
                    r.mac = None;
                }
                Message::PairResult(r)
            }
            "error" => Message::Error(field_parse(&t, value)?),
            "utt" => {
                let u: Utt = field_parse(&t, value)?;
                check_text(&u.text)?;
                Message::Utt(u)
            }
            "ack" => Message::Ack(field_parse(&t, value)?),
            "ping" => Message::Ping,
            "pong" => Message::Pong,
            _ => Message::Unknown { t },
        };
        Ok(msg)
    }
}

fn field_parse<T: serde::de::DeserializeOwned>(t: &str, value: Value) -> Result<T> {
    serde_json::from_value(value).map_err(|e| Error::InvalidMessage(format!("{t}: {e}")))
}

fn check_text(text: &str) -> Result<()> {
    if text.len() > MAX_TEXT_BYTES {
        Err(Error::TextTooLong(text.len()))
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn uid() -> Uuid {
        Uuid::parse_str("0f8fad5b-d9cb-469f-a165-70867728950e").unwrap()
    }

    fn utt(text: &str) -> Message {
        Message::Utt(Utt {
            id: uid(),
            rev: 3,
            state: UttState::Final,
            text: text.into(),
            ts: 1_700_000_000_000,
        })
    }

    fn all_encodable() -> Vec<Message> {
        vec![
            Message::Hello(Hello {
                v: 1,
                device_id: uid(),
                name: "Jon's iPhone".into(),
                public_key: [7; 32],
                paired: true,
                session_nonce: [9; 32],
            }),
            Message::PairRequest(PairRequest { nonce_p: [1; 32] }),
            Message::PairChallenge(PairChallenge { nonce_d: [2; 32] }),
            Message::PairConfirm(PairConfirm { mac: [3; 32] }),
            Message::PairResult(PairResult::success([4; 32])),
            Message::PairResult(PairResult::failure()),
            Message::Error(ErrorMsg::new("version", "upgrade")),
            utt("hello \"world\"\n\u{1F600}"),
            Message::Ack(Ack {
                id: uid(),
                rev: u32::MAX,
            }),
            Message::Ping,
            Message::Pong,
        ]
    }

    #[test]
    fn roundtrip_all() {
        for m in all_encodable() {
            let j = m.to_json().unwrap();
            assert!(
                j.starts_with(br#"{"t":""#),
                "{}",
                String::from_utf8_lossy(&j)
            );
            assert_eq!(Message::from_json(&j).unwrap(), m);
        }
    }

    #[test]
    fn exact_encodings() {
        assert_eq!(Message::Ping.to_json().unwrap(), br#"{"t":"ping"}"#);
        assert_eq!(
            Message::PairResult(PairResult::failure())
                .to_json()
                .unwrap(),
            br#"{"t":"pair_result","ok":false}"#
        );
        let j = String::from_utf8(utt("x").to_json().unwrap()).unwrap();
        assert_eq!(
            j,
            r#"{"t":"utt","id":"0f8fad5b-d9cb-469f-a165-70867728950e","rev":3,"state":"final","text":"x","ts":1700000000000}"#
        );
    }

    #[test]
    fn unknown_type_and_fields() {
        assert_eq!(
            Message::from_json(br#"{"t":"future","x":1}"#).unwrap(),
            Message::Unknown { t: "future".into() }
        );
        assert_eq!(
            Message::from_json(br#"{"t":"ping","extra":[1,2,{}]}"#).unwrap(),
            Message::Ping
        );
        assert!(!Message::Unknown { t: "hello".into() }.is_plaintext_allowed());
        assert_eq!(
            Message::Unknown { t: "x".into() }
                .to_json()
                .unwrap_err()
                .code(),
            "not_encodable"
        );
    }

    #[test]
    fn invalid_shapes() {
        for (j, code) in [
            (&b"not json"[..], "invalid_json"),
            (b"", "invalid_json"),
            (b"\xff\xfe", "invalid_json"),
            (b"[]", "invalid_message"),
            (b"\"ping\"", "invalid_message"),
            (b"{}", "invalid_message"),
            (br#"{"t":5}"#, "invalid_message"),
            (br#"{"t":null}"#, "invalid_message"),
            (br#"{"t":"ack","rev":1}"#, "invalid_message"),
            (
                br#"{"t":"ack","id":"0f8fad5b-d9cb-469f-a165-70867728950e","rev":-1}"#,
                "invalid_message",
            ),
            (
                br#"{"t":"ack","id":"0f8fad5b-d9cb-469f-a165-70867728950e","rev":4294967296}"#,
                "invalid_message",
            ),
            (
                br#"{"t":"ack","id":"0f8fad5b-d9cb-469f-a165-70867728950e","rev":1.5}"#,
                "invalid_message",
            ),
            (br#"{"t":"pair_result","ok":true}"#, "invalid_message"),
            (
                br#"{"t":"pair_request","nonce_p":"AAAA"}"#,
                "invalid_message",
            ),
            (br#"{"t":"hello","v":"1"}"#, "invalid_message"),
            (br#"{"t":"hello"}"#, "invalid_message"),
            (br#"{"t":"hello","v":1}"#, "invalid_message"),
            (br#"{"t":"ping"} x"#, "invalid_json"),
        ] {
            let e = Message::from_json(j).unwrap_err();
            assert_eq!(
                e.code(),
                code,
                "input {:?}: {e}",
                String::from_utf8_lossy(j)
            );
        }
    }

    #[test]
    fn hello_version_mismatch() {
        let m = Message::from_json(br#"{"t":"hello","v":2,"name":"Mac"}"#).unwrap();
        assert_eq!(
            m,
            Message::HelloUnsupported(HelloUnsupported {
                v: 2,
                name: Some("Mac".into())
            })
        );
        assert!(m.is_plaintext_allowed());
        assert!(m.to_json().is_err());
    }

    #[test]
    fn pair_result_normalization() {
        let m = Message::from_json(
            br#"{"t":"pair_result","ok":false,"mac":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="}"#,
        )
        .unwrap();
        assert_eq!(m, Message::PairResult(PairResult::failure()));
        let bad = Message::PairResult(PairResult {
            ok: false,
            mac: Some([0; 32]),
        });
        assert!(bad.to_json().is_err());
        let bad = Message::PairResult(PairResult {
            ok: true,
            mac: None,
        });
        assert!(bad.to_json().is_err());
        assert_eq!(
            Message::from_json(br#"{"t":"pair_result","ok":false,"mac":null}"#).unwrap(),
            Message::PairResult(PairResult::failure())
        );
    }

    #[test]
    fn text_limits() {
        let ok = "a".repeat(MAX_TEXT_BYTES);
        assert!(utt(&ok).to_json().is_ok());
        let too_long = "a".repeat(MAX_TEXT_BYTES + 1);
        assert_eq!(
            utt(&too_long).to_json().unwrap_err(),
            Error::TextTooLong(32_001)
        );
        // multibyte: 8000 x 4-byte emoji = exactly 32000 bytes
        let emoji = "\u{1F600}".repeat(8000);
        assert!(utt(&emoji).to_json().is_ok());
        let emoji_over = format!("{emoji}a");
        assert_eq!(
            utt(&emoji_over).to_json().unwrap_err().code(),
            "text_too_long"
        );
        // decoding enforces it too
        let j = format!(
            r#"{{"t":"utt","id":"0f8fad5b-d9cb-469f-a165-70867728950e","rev":0,"state":"partial","text":"{too_long}","ts":0}}"#
        );
        assert_eq!(
            Message::from_json(j.as_bytes()).unwrap_err().code(),
            "text_too_long"
        );
        // escapes count after decoding: 32000 escaped newlines are 32000 bytes of text
        let j = format!(
            r#"{{"t":"utt","id":"0f8fad5b-d9cb-469f-a165-70867728950e","rev":0,"state":"partial","text":"{}","ts":0}}"#,
            "\\n".repeat(MAX_TEXT_BYTES)
        );
        assert!(Message::from_json(j.as_bytes()).is_ok());
    }

    #[test]
    fn message_size_limit() {
        // within text limit but JSON-escaped beyond 64 KiB: 32000 control chars -> \u0001 x 6
        let ctl = "\u{1}".repeat(MAX_TEXT_BYTES);
        assert_eq!(utt(&ctl).to_json().unwrap_err().code(), "message_too_large");
        let mut big = br#"{"t":"ping","pad":""#.to_vec();
        big.resize(MAX_MESSAGE_BYTES - 2, b'a');
        big.extend_from_slice(b"\"}");
        assert_eq!(big.len(), MAX_MESSAGE_BYTES);
        assert_eq!(Message::from_json(&big).unwrap(), Message::Ping);
        big.insert(big.len() - 2, b'a');
        assert_eq!(
            Message::from_json(&big).unwrap_err().code(),
            "message_too_large"
        );
    }

    #[test]
    fn plaintext_allowed_set() {
        let allowed: Vec<bool> = all_encodable()
            .iter()
            .map(Message::is_plaintext_allowed)
            .collect();
        assert_eq!(
            allowed,
            vec![true, true, true, true, true, true, true, false, false, false, false]
        );
    }

    #[test]
    fn uuid_case_insensitive_and_lowercase_emit() {
        let m = Message::from_json(
            br#"{"t":"ack","id":"0F8FAD5B-D9CB-469F-A165-70867728950E","rev":1}"#,
        )
        .unwrap();
        let j = m.to_json().unwrap();
        assert!(String::from_utf8(j)
            .unwrap()
            .contains("0f8fad5b-d9cb-469f-a165-70867728950e"));
    }
}
