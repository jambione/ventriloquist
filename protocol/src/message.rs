//! JSON application messages (SPEC §4.1, §4.4–§4.6).
//!
//! Every message is a UTF-8 JSON object with a string `"t"` type field.
//! Decoding first validates the whole document with the crate's own strict
//! JSON reader (README §5.1: depth, finite numbers, no lone surrogates, no
//! duplicate keys), then reads the fields of the known types by hand.
//! Unknown fields are ignored. An unknown `t` decodes to [`Message::Unknown`]
//! (the caller logs and drops it; it is never fatal). A `hello` whose `v` is
//! an integer other than [`crate::PROTOCOL_VERSION`] decodes to
//! [`Message::HelloUnsupported`] so the receiver can answer with
//! `error{code:"version"}`.
//!
//! [`Message::from_json`] says nothing about where the bytes came from. On a
//! live connection use [`crate::decode_inbound`], which reports whether the
//! message was authenticated.

use serde::Serialize;
use uuid::Uuid;

use crate::b64;
use crate::crypto::{random_nonce, SessionNonce};
use crate::error::{Error, Result};
use crate::json::{self, Document, Scalar};
use crate::{MAX_ENCRYPTED_JSON_BYTES, MAX_MESSAGE_BYTES, MAX_TEXT_BYTES, PROTOCOL_VERSION};

/// `hello` (both directions, plaintext). §4.4 step 1 and §4.5.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Hello {
    /// Protocol version; always 1 for a decoded [`Message::Hello`]. Encoding
    /// any other value fails with `not_encodable`.
    pub v: u32,
    /// Sender's random 128-bit install identifier.
    #[serde(serialize_with = "b64::uuid_str")]
    pub device_id: Uuid,
    /// Sender's human-readable device name.
    pub name: String,
    /// Sender's long-term X25519 public key (wire field `pub`).
    #[serde(rename = "pub", serialize_with = "b64::bytes32")]
    pub public_key: [u8; 32],
    /// Whether the sender has a stored pairing for the receiver (see README §7).
    pub paired: bool,
    /// Fresh 32-byte random nonce for this connection (§4.5).
    #[serde(serialize_with = "b64::bytes32")]
    pub session_nonce: [u8; 32],
}

impl Hello {
    /// Our `hello` for a new connection, with a fresh CSPRNG
    /// `session_nonce`. Keep the returned [`SessionNonce`] and pass it to
    /// [`crate::SessionCipher::establish`] for this connection only.
    pub fn new(
        device_id: Uuid,
        name: impl Into<String>,
        public_key: [u8; 32],
        paired: bool,
    ) -> (Hello, SessionNonce) {
        let nonce = SessionNonce::generate();
        let hello = Hello {
            v: PROTOCOL_VERSION,
            device_id,
            name: name.into(),
            public_key,
            paired,
            session_nonce: nonce.bytes(),
        };
        (hello, nonce)
    }
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
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PairRequest {
    /// 32 random bytes chosen by the phone.
    #[serde(serialize_with = "b64::bytes32")]
    pub nonce_p: [u8; 32],
}

impl PairRequest {
    /// A request with a fresh CSPRNG `nonce_p`.
    pub fn generate() -> Self {
        Self {
            nonce_p: random_nonce(),
        }
    }
}

/// `pair_challenge` (desktop → phone, plaintext). §4.4 step 3.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PairChallenge {
    /// 32 random bytes chosen by the desktop.
    #[serde(serialize_with = "b64::bytes32")]
    pub nonce_d: [u8; 32],
}

impl PairChallenge {
    /// A challenge with a fresh CSPRNG `nonce_d`.
    pub fn generate() -> Self {
        Self {
            nonce_d: random_nonce(),
        }
    }
}

/// `pair_confirm` (phone → desktop, plaintext). §4.4 step 4.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PairConfirm {
    /// `HMAC-SHA256(K_pair, "phone" ‖ pub_p ‖ pub_d)`.
    #[serde(serialize_with = "b64::bytes32")]
    pub mac: [u8; 32],
}

/// `pair_result` (desktop → phone, plaintext). §4.4 step 5.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PairResult {
    /// Whether the phone's MAC verified.
    pub ok: bool,
    /// `HMAC-SHA256(K_pair, "desktop" ‖ pub_d ‖ pub_p)`; present iff `ok`.
    #[serde(
        serialize_with = "b64::opt_bytes32",
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
///
/// When received in a plaintext envelope it is unauthenticated: it may end
/// the connection but MUST NOT change stored pairing state (README §7).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ErrorMsg {
    /// Machine-readable code; see [`ErrorMsg::UNKNOWN_PEER`] etc. Open set.
    pub code: String,
    /// Human-readable detail. Defaults to `""` when absent or `null`.
    /// Never build it from a local [`crate::Error`]'s `Display` text.
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
    /// Protocol violation, e.g. a second `hello` on one connection.
    pub const PROTOCOL: &'static str = "protocol";

    /// Convenience constructor.
    pub fn new(code: impl Into<String>, msg: impl Into<String>) -> Self {
        Self {
            code: code.into(),
            msg: msg.into(),
        }
    }
}

/// `utt.state`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
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
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Utt {
    /// Utterance id.
    #[serde(serialize_with = "b64::uuid_str")]
    pub id: Uuid,
    /// Revision; the desktop keeps the highest per `id`.
    pub rev: u32,
    /// partial / final / edit.
    pub state: UttState,
    /// Full current text (not a diff), at most 32,000 UTF-8 bytes. Arbitrary
    /// Unicode, including control characters: render it inertly.
    pub text: String,
    /// Start of utterance, milliseconds since the Unix epoch.
    pub ts: u64,
}

/// `ack` (desktop → phone, encrypted). §4.6.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Ack {
    /// Acknowledged utterance id.
    #[serde(serialize_with = "b64::uuid_str")]
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

/// Every `t` value v1 defines.
pub const KNOWN_TYPES: [&str; 10] = [
    "hello",
    "pair_request",
    "pair_challenge",
    "pair_confirm",
    "pair_result",
    "error",
    "utt",
    "ack",
    "ping",
    "pong",
];

/// Whether `t` is one of the v1 message types (case-sensitive).
pub fn is_known_type(t: &str) -> bool {
    KNOWN_TYPES.contains(&t)
}

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
    /// [`Message::Unknown`] returns `false`; [`crate::decode_inbound`] passes
    /// unknown types through (for the caller to drop) rather than rejecting them.
    pub fn is_plaintext_allowed(&self) -> bool {
        !matches!(self, Message::Unknown { .. }) && PLAINTEXT_ALLOWED.contains(&self.type_name())
    }

    /// Encode as compact UTF-8 JSON with `"t"` first.
    ///
    /// Fails, in this order, with `not_encodable` for receive-only variants,
    /// a `hello` whose `v` is not [`PROTOCOL_VERSION`] and an inconsistent
    /// `pair_result`; with `text_too_long` for `utt.text` over 32,000 bytes;
    /// and with `message_too_large` when the output exceeds 64 KiB.
    pub fn to_json(&self) -> Result<Vec<u8>> {
        let wire = match self {
            Message::Hello(m) => {
                if m.v != PROTOCOL_VERSION {
                    return Err(Error::NotEncodable("hello.v must be PROTOCOL_VERSION"));
                }
                WireRef::Hello(m)
            }
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

    /// Decode a JSON message body (no provenance; see [`crate::decode_inbound`]).
    ///
    /// Error precedence: `message_too_large`, then `invalid_json` (whole
    /// document, README §5.1), then `invalid_message` for the shape and `t`,
    /// then field errors (`invalid_message`), then `text_too_long`.
    pub fn from_json(bytes: &[u8]) -> Result<Message> {
        Self::decode_with_policy(bytes, |_| Ok(()))
    }

    /// [`Message::from_json`] with a `t` policy check that runs after `t` is
    /// read and before any other field is validated.
    pub(crate) fn decode_with_policy(
        bytes: &[u8],
        policy: impl FnOnce(&str) -> Result<()>,
    ) -> Result<Message> {
        if bytes.len() > MAX_MESSAGE_BYTES {
            return Err(Error::MessageTooLarge(bytes.len()));
        }
        let members = match json::parse(bytes)? {
            Document::Object(m) => m,
            Document::NotObject => {
                return Err(Error::InvalidMessage("message is not a JSON object".into()))
            }
        };
        let f = Fields(members);
        let t = match f.get("t") {
            Some(Scalar::Str(t)) => t.clone(),
            Some(_) => return Err(Error::InvalidMessage("`t` is not a string".into())),
            None => return Err(Error::InvalidMessage("missing `t`".into())),
        };
        policy(&t)?;
        let msg = match t.as_str() {
            "hello" => decode_hello(&f)?,
            "pair_request" => Message::PairRequest(PairRequest {
                nonce_p: f.b64_32("nonce_p")?,
            }),
            "pair_challenge" => Message::PairChallenge(PairChallenge {
                nonce_d: f.b64_32("nonce_d")?,
            }),
            "pair_confirm" => Message::PairConfirm(PairConfirm {
                mac: f.b64_32("mac")?,
            }),
            "pair_result" => {
                // `mac` is read only when ok is true; with ok false it is
                // ignored entirely, whatever its type or content.
                if f.bool("ok")? {
                    let mac = f.opt_b64_32("mac")?.ok_or_else(|| {
                        Error::InvalidMessage("pair_result: ok is true but mac is missing".into())
                    })?;
                    Message::PairResult(PairResult::success(mac))
                } else {
                    Message::PairResult(PairResult::failure())
                }
            }
            "error" => Message::Error(ErrorMsg {
                code: f.string("code")?,
                msg: f.opt_string("msg")?.unwrap_or_default(),
            }),
            "utt" => {
                let u = Utt {
                    id: f.uuid("id")?,
                    rev: u32::try_from(f.uint("rev", u64::from(u32::MAX))?)
                        .expect("bounded by u32::MAX"),
                    state: f.state("state")?,
                    text: f.string("text")?,
                    ts: f.uint("ts", u64::MAX)?,
                };
                check_text(&u.text)?;
                Message::Utt(u)
            }
            "ack" => Message::Ack(Ack {
                id: f.uuid("id")?,
                rev: u32::try_from(f.uint("rev", u64::from(u32::MAX))?)
                    .expect("bounded by u32::MAX"),
            }),
            "ping" => Message::Ping,
            "pong" => Message::Pong,
            _ => Message::Unknown { t },
        };
        Ok(msg)
    }
}

fn decode_hello(f: &Fields<'_>) -> Result<Message> {
    let v = f.uint("v", u64::MAX)?;
    if v != u64::from(PROTOCOL_VERSION) {
        let name = match f.get("name") {
            Some(Scalar::Str(s)) => Some(s.clone()),
            _ => None,
        };
        return Ok(Message::HelloUnsupported(HelloUnsupported { v, name }));
    }
    Ok(Message::Hello(Hello {
        v: PROTOCOL_VERSION,
        device_id: f.uuid("device_id")?,
        name: f.string("name")?,
        public_key: f.b64_32("pub")?,
        paired: f.bool("paired")?,
        session_nonce: f.b64_32("session_nonce")?,
    }))
}

/// Top-level members of a validated object (keys are unique).
struct Fields<'a>(Vec<(String, Scalar<'a>)>);

fn invalid(field: &str, what: &str) -> Error {
    Error::InvalidMessage(format!("`{field}` {what}"))
}

impl<'a> Fields<'a> {
    fn get(&self, k: &str) -> Option<&Scalar<'a>> {
        self.0.iter().find(|(key, _)| key == k).map(|(_, v)| v)
    }

    /// A required field (`null` counts as present-but-wrong-type).
    fn req(&self, k: &str) -> Result<&Scalar<'a>> {
        self.get(k).ok_or_else(|| invalid(k, "is missing"))
    }

    /// An optional field: absent and `null` are both `None`.
    fn opt(&self, k: &str) -> Option<&Scalar<'a>> {
        match self.get(k) {
            None | Some(Scalar::Null) => None,
            v => v,
        }
    }

    fn string(&self, k: &str) -> Result<String> {
        match self.req(k)? {
            Scalar::Str(s) => Ok(s.clone()),
            _ => Err(invalid(k, "must be a string")),
        }
    }

    fn opt_string(&self, k: &str) -> Result<Option<String>> {
        match self.opt(k) {
            None => Ok(None),
            Some(Scalar::Str(s)) => Ok(Some(s.clone())),
            Some(_) => Err(invalid(k, "must be a string")),
        }
    }

    fn bool(&self, k: &str) -> Result<bool> {
        match self.req(k)? {
            Scalar::Bool(b) => Ok(*b),
            _ => Err(invalid(k, "must be a boolean")),
        }
    }

    /// An unsigned integer field: a plain JSON integer literal (no sign, no
    /// fraction, no exponent; so `-0`, `1.0`, `1e0` are rejected) ≤ `max`.
    fn uint(&self, k: &str, max: u64) -> Result<u64> {
        let Scalar::Num(raw) = self.req(k)? else {
            return Err(invalid(k, "must be an integer"));
        };
        parse_uint(raw, max).ok_or_else(|| invalid(k, "must be a non-negative integer in range"))
    }

    fn b64_32(&self, k: &str) -> Result<[u8; 32]> {
        match self.req(k)? {
            Scalar::Str(s) => b64::decode_fixed::<32>(s).map_err(|e| invalid(k, &e)),
            _ => Err(invalid(k, "must be a base64 string")),
        }
    }

    fn opt_b64_32(&self, k: &str) -> Result<Option<[u8; 32]>> {
        match self.opt(k) {
            None => Ok(None),
            Some(Scalar::Str(s)) => b64::decode_fixed::<32>(s)
                .map(Some)
                .map_err(|e| invalid(k, &e)),
            Some(_) => Err(invalid(k, "must be a base64 string")),
        }
    }

    fn uuid(&self, k: &str) -> Result<Uuid> {
        match self.req(k)? {
            Scalar::Str(s) => b64::parse_uuid(s).map_err(|e| invalid(k, &e)),
            _ => Err(invalid(k, "must be a UUID string")),
        }
    }

    fn state(&self, k: &str) -> Result<UttState> {
        match self.req(k)? {
            Scalar::Str(s) => match s.as_str() {
                "partial" => Ok(UttState::Partial),
                "final" => Ok(UttState::Final),
                "edit" => Ok(UttState::Edit),
                _ => Err(invalid(k, "must be \"partial\", \"final\" or \"edit\"")),
            },
            _ => Err(invalid(k, "must be a string")),
        }
    }
}

/// `raw` is a grammar-checked JSON number token.
fn parse_uint(raw: &str, max: u64) -> Option<u64> {
    if raw.is_empty() || !raw.bytes().all(|c| c.is_ascii_digit()) {
        return None;
    }
    raw.bytes()
        .try_fold(0u64, |acc, d| {
            acc.checked_mul(10)?.checked_add(u64::from(d - b'0'))
        })
        .filter(|v| *v <= max)
}

fn check_text(text: &str) -> Result<()> {
    if text.len() > MAX_TEXT_BYTES {
        Err(Error::TextTooLong(text.len()))
    } else {
        Ok(())
    }
}

// ---- utterance sizing (README §5.8) ----------------------------------------

/// Bytes that `text` occupies inside a JSON string with minimal escaping
/// (the escaping every conforming encoder MUST NOT exceed): `"` and `\` → 2;
/// U+0008, U+0009, U+000A, U+000C, U+000D → 2; other U+0000–U+001F → 6; any
/// other character → its UTF-8 length.
pub fn escaped_len(text: &str) -> usize {
    text.chars().map(escaped_char_len).sum()
}

fn escaped_char_len(c: char) -> usize {
    match c {
        '"' | '\\' | '\u{8}' | '\t' | '\n' | '\u{c}' | '\r' => 2,
        '\u{0}'..='\u{1f}' => 6,
        c => c.len_utf8(),
    }
}

/// Length of the largest possible encoded `utt` with empty text: lowercase
/// UUID, `rev` = 4294967295, `state` = `"partial"`, `ts` = 18446744073709551615.
pub const UTT_MAX_OVERHEAD_BYTES: usize = 126;

/// Whether an utterance with this `text` can always be sent: the text is at
/// most 32,000 UTF-8 bytes **and** the encoded `utt`, whatever its other
/// fields, fits an encrypted envelope (≤ 65,511 JSON bytes).
pub fn utt_text_fits(text: &str) -> bool {
    text.len() <= MAX_TEXT_BYTES
        && UTT_MAX_OVERHEAD_BYTES + escaped_len(text) <= MAX_ENCRYPTED_JSON_BYTES
}

/// The longest prefix of `text`, cut at a character boundary, for which
/// [`utt_text_fits`] holds. The phone ends the utterance with this text when
/// the recognized text grows past it.
pub fn max_text_prefix(text: &str) -> &str {
    let budget = MAX_ENCRYPTED_JSON_BYTES - UTT_MAX_OVERHEAD_BYTES;
    let mut esc = 0;
    for (i, c) in text.char_indices() {
        let next_raw = i + c.len_utf8();
        esc += escaped_char_len(c);
        if next_raw > MAX_TEXT_BYTES || esc > budget {
            return &text[..i];
        }
    }
    text
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
        for mac in [r#""garbage""#, "123", "{}", "[]", "true", r#""AAAA""#] {
            let j = format!(r#"{{"t":"pair_result","ok":false,"mac":{mac}}}"#);
            assert_eq!(
                Message::from_json(j.as_bytes()).unwrap(),
                Message::PairResult(PairResult::failure()),
                "{j}"
            );
        }
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

    #[test]
    fn hello_new_draws_fresh_nonce_and_encode_rejects_other_versions() {
        let (h1, n1) = Hello::new(uid(), "a", [1; 32], false);
        let (h2, n2) = Hello::new(uid(), "a", [1; 32], false);
        assert_eq!(h1.v, PROTOCOL_VERSION);
        assert_eq!(h1.session_nonce, n1.bytes());
        assert_ne!(n1.bytes(), n2.bytes());
        assert_ne!(h1.session_nonce, h2.session_nonce);
        let mut bad = h1.clone();
        bad.v = 2;
        assert_eq!(
            Message::Hello(bad).to_json().unwrap_err().code(),
            "not_encodable"
        );
        assert!(Message::Hello(h1).to_json().is_ok());
    }

    #[test]
    fn r1_and_integer_rules() {
        let u = |rev: &str| {
            format!(r#"{{"t":"ack","id":"0f8fad5b-d9cb-469f-a165-70867728950e","rev":{rev}}}"#)
        };
        for bad in ["-0", "1.0", "1e0", "0e0", "-0.0", "4294967296"] {
            assert_eq!(
                Message::from_json(u(bad).as_bytes()).unwrap_err().code(),
                "invalid_message",
                "{bad}"
            );
        }
        for bad in ["1e400", "-1e400"] {
            assert_eq!(
                Message::from_json(u(bad).as_bytes()).unwrap_err().code(),
                "invalid_json",
                "{bad}"
            );
        }
        for (j, code) in [
            (r#"{"t":"hello","v":-0}"#, "invalid_message"),
            (r#"{"t":"hello","v":1.0}"#, "invalid_message"),
            (
                r#"{"t":"hello","v":18446744073709551616}"#,
                "invalid_message",
            ),
            (r#"{"t":"ping","t":"ping"}"#, "invalid_json"),
            (r#"{"t":"ping","x":"\udc00"}"#, "invalid_json"),
        ] {
            assert_eq!(
                Message::from_json(j.as_bytes()).unwrap_err().code(),
                code,
                "{j}"
            );
        }
        assert!(matches!(
            Message::from_json(br#"{"t":"hello","v":18446744073709551615}"#).unwrap(),
            Message::HelloUnsupported(HelloUnsupported {
                v: u64::MAX,
                name: None
            })
        ));
        assert_eq!(
            Message::from_json(br#"{"t":"error","code":"x","msg":null}"#).unwrap(),
            Message::Error(ErrorMsg::new("x", ""))
        );
        assert_eq!(
            Message::from_json(br#"{"t":"error","code":"x","msg":5}"#)
                .unwrap_err()
                .code(),
            "invalid_message"
        );
    }

    #[test]
    fn error_display_is_bounded() {
        let long = "z".repeat(50_000);
        for j in [
            format!(r#"{{"t":"ack","id":"{long}","rev":1}}"#),
            format!(r#"{{"t":"pair_request","nonce_p":"{long}"}}"#),
            format!(
                r#"{{"t":"utt","id":"0f8fad5b-d9cb-469f-a165-70867728950e","rev":1,"state":"{long}","text":"","ts":0}}"#
            ),
        ] {
            let e = Message::from_json(j.as_bytes()).unwrap_err();
            assert!(e.to_string().len() < 300, "{}", e.to_string().len());
        }
    }

    #[test]
    fn escaped_len_matches_encoder() {
        let base = Message::Utt(Utt {
            id: uid(),
            rev: 0,
            state: UttState::Edit,
            text: String::new(),
            ts: 0,
        })
        .to_json()
        .unwrap()
        .len();
        let mut samples: Vec<String> = (0u32..0x80)
            .filter_map(char::from_u32)
            .map(String::from)
            .collect();
        samples.extend(
            [
                "\u{7f}",
                "\u{2028}",
                "é",
                "日",
                "\u{1F600}",
                "/",
                "a\"b\\c\u{1}\n",
            ]
            .map(String::from),
        );
        for t in samples {
            let m = Message::Utt(Utt {
                id: uid(),
                rev: 0,
                state: UttState::Edit,
                text: t.clone(),
                ts: 0,
            });
            assert_eq!(m.to_json().unwrap().len() - base, escaped_len(&t), "{t:?}");
        }
    }

    #[test]
    fn utt_sizing_helpers() {
        let worst = Message::Utt(Utt {
            id: uid(),
            rev: u32::MAX,
            state: UttState::Partial,
            text: String::new(),
            ts: u64::MAX,
        });
        assert_eq!(worst.to_json().unwrap().len(), UTT_MAX_OVERHEAD_BYTES);
        assert!(utt_text_fits(""));
        assert!(utt_text_fits(&"a".repeat(MAX_TEXT_BYTES)));
        assert!(!utt_text_fits(&"a".repeat(MAX_TEXT_BYTES + 1)));
        // 32,000 quotes: 64,000 escaped + 126 ≤ 65,511
        assert!(utt_text_fits(&"\"".repeat(MAX_TEXT_BYTES)));
        // control chars: budget is (65,511 − 126) / 6 = 10,897 chars
        let ctl = "\u{1}".repeat(MAX_TEXT_BYTES);
        assert!(!utt_text_fits(&ctl));
        let p = max_text_prefix(&ctl);
        assert_eq!(p.len(), 10_897);
        assert!(utt_text_fits(p));
        assert!(!utt_text_fits(&ctl[..p.len() + 1]));
        // the worst-case utt with that prefix really fits an encrypted envelope
        let Message::Utt(mut u) = worst else {
            unreachable!()
        };
        u.text = p.to_owned();
        let mut c = crate::SessionCipher::new(&[0; 32], crate::Role::Phone);
        assert!(c.seal_message(&Message::Utt(u)).is_ok());
        // char boundaries respected: 4-byte chars
        let emoji = "\u{1F600}".repeat(8_001);
        assert_eq!(max_text_prefix(&emoji).len(), MAX_TEXT_BYTES);
        assert_eq!(max_text_prefix("abc"), "abc");
        let mixed = format!("{}\u{1F600}", "a".repeat(MAX_TEXT_BYTES - 2));
        assert_eq!(max_text_prefix(&mixed).len(), MAX_TEXT_BYTES - 2);
    }
}
