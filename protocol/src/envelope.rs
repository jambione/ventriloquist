//! Envelopes (SPEC §4.3).
//!
//! ```text
//! plaintext : 0x00 ‖ JSON
//! encrypted : 0x01 ‖ counter (u64 BE) ‖ ChaCha20-Poly1305 ciphertext ‖ tag (16)
//! nonce (12): direction (0x01 phone→desktop, 0x02 desktop→phone) ‖ 00 00 00 ‖ counter (u64 BE)
//! AAD       : the kind byte (0x01)
//! ```

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};

use crate::error::{Error, Result};
use crate::message::Message;
use crate::MAX_MESSAGE_BYTES;

/// Envelope kind byte: plaintext JSON.
pub const KIND_PLAINTEXT: u8 = 0x00;
/// Envelope kind byte: encrypted.
pub const KIND_ENCRYPTED: u8 = 0x01;
/// Poly1305 tag length.
pub const TAG_BYTES: usize = 16;
/// Smallest valid encrypted envelope: kind + counter + tag.
pub const MIN_ENCRYPTED_BYTES: usize = 1 + 8 + TAG_BYTES;

/// Direction of travel; its byte value is the first nonce byte.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum Direction {
    /// phone → desktop (0x01).
    PhoneToDesktop = 0x01,
    /// desktop → phone (0x02).
    DesktopToPhone = 0x02,
}

impl Direction {
    /// The nonce direction byte.
    pub fn byte(self) -> u8 {
        self as u8
    }
}

/// Which end of the link we are.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Role {
    /// The iPhone (GATT peripheral).
    Phone,
    /// The desktop (GATT central).
    Desktop,
}

impl Role {
    /// Direction of messages this role sends.
    pub fn send_direction(self) -> Direction {
        match self {
            Role::Phone => Direction::PhoneToDesktop,
            Role::Desktop => Direction::DesktopToPhone,
        }
    }
    /// Direction of messages this role receives.
    pub fn recv_direction(self) -> Direction {
        match self {
            Role::Phone => Direction::DesktopToPhone,
            Role::Desktop => Direction::PhoneToDesktop,
        }
    }
}

/// The 12-byte AEAD nonce for `direction` and `counter`.
pub fn nonce(direction: Direction, counter: u64) -> [u8; 12] {
    let mut n = [0u8; 12];
    n[0] = direction.byte();
    n[4..].copy_from_slice(&counter.to_be_bytes());
    n
}

/// A parsed (not yet decrypted) envelope.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Envelope<'a> {
    /// Kind 0x00: JSON bytes.
    Plaintext(&'a [u8]),
    /// Kind 0x01.
    Encrypted {
        /// Sender's counter.
        counter: u64,
        /// Ciphertext followed by the 16-byte tag.
        ciphertext_and_tag: &'a [u8],
    },
}

impl<'a> Envelope<'a> {
    /// Parse the envelope header. Does not decrypt or parse JSON.
    pub fn parse(bytes: &'a [u8]) -> Result<Self> {
        if bytes.len() > MAX_MESSAGE_BYTES {
            return Err(Error::MessageTooLarge(bytes.len()));
        }
        match bytes.first() {
            None => Err(Error::EmptyEnvelope),
            Some(&KIND_PLAINTEXT) => Ok(Envelope::Plaintext(&bytes[1..])),
            Some(&KIND_ENCRYPTED) => {
                if bytes.len() < MIN_ENCRYPTED_BYTES {
                    return Err(Error::EnvelopeTooShort(bytes.len()));
                }
                let counter = u64::from_be_bytes(bytes[1..9].try_into().expect("8 bytes"));
                Ok(Envelope::Encrypted {
                    counter,
                    ciphertext_and_tag: &bytes[9..],
                })
            }
            Some(&k) => Err(Error::UnknownEnvelopeKind(k)),
        }
    }
}

/// Encode a plaintext envelope. Only plaintext-allowed types are accepted.
pub fn encode_plaintext(msg: &Message) -> Result<Vec<u8>> {
    if !msg.is_plaintext_allowed() {
        return Err(Error::PlaintextNotAllowed(msg.type_name().to_owned()));
    }
    let json = msg.to_json()?;
    let mut out = Vec::with_capacity(1 + json.len());
    out.push(KIND_PLAINTEXT);
    out.extend_from_slice(&json);
    if out.len() > MAX_MESSAGE_BYTES {
        return Err(Error::MessageTooLarge(out.len()));
    }
    Ok(out)
}

/// Stateless encryption of one envelope (no counter bookkeeping).
pub fn seal_with(
    key: &[u8; 32],
    direction: Direction,
    counter: u64,
    plaintext: &[u8],
) -> Result<Vec<u8>> {
    let cipher = ChaCha20Poly1305::new(Key::from_slice(key));
    seal_inner(&cipher, direction, counter, plaintext)
}

/// Stateless decryption of one envelope (no replay check). Returns `(counter, plaintext)`.
/// Plaintext envelopes are rejected with [`Error::UnknownEnvelopeKind`]`(0x00)`.
pub fn open_with(key: &[u8; 32], direction: Direction, envelope: &[u8]) -> Result<(u64, Vec<u8>)> {
    let cipher = ChaCha20Poly1305::new(Key::from_slice(key));
    match Envelope::parse(envelope)? {
        Envelope::Encrypted {
            counter,
            ciphertext_and_tag,
        } => Ok((
            counter,
            open_inner(&cipher, direction, counter, ciphertext_and_tag)?,
        )),
        Envelope::Plaintext(_) => Err(Error::UnknownEnvelopeKind(KIND_PLAINTEXT)),
    }
}

fn seal_inner(
    cipher: &ChaCha20Poly1305,
    direction: Direction,
    counter: u64,
    plaintext: &[u8],
) -> Result<Vec<u8>> {
    let total = MIN_ENCRYPTED_BYTES + plaintext.len();
    if total > MAX_MESSAGE_BYTES {
        return Err(Error::MessageTooLarge(total));
    }
    let n = nonce(direction, counter);
    let ct = cipher
        .encrypt(
            Nonce::from_slice(&n),
            Payload {
                msg: plaintext,
                aad: &[KIND_ENCRYPTED],
            },
        )
        .map_err(|_| Error::MessageTooLarge(total))?;
    let mut out = Vec::with_capacity(total);
    out.push(KIND_ENCRYPTED);
    out.extend_from_slice(&counter.to_be_bytes());
    out.extend_from_slice(&ct);
    Ok(out)
}

fn open_inner(
    cipher: &ChaCha20Poly1305,
    direction: Direction,
    counter: u64,
    ct: &[u8],
) -> Result<Vec<u8>> {
    let n = nonce(direction, counter);
    cipher
        .decrypt(
            Nonce::from_slice(&n),
            Payload {
                msg: ct,
                aad: &[KIND_ENCRYPTED],
            },
        )
        .map_err(|_| Error::DecryptFailed)
}

/// Per-session AEAD state: one send counter and one replay window per direction.
pub struct SessionCipher {
    cipher: ChaCha20Poly1305,
    role: Role,
    /// Next counter to send; `None` once `u64::MAX` has been used.
    next_send: Option<u64>,
    /// Highest counter accepted so far.
    last_recv: Option<u64>,
}

impl std::fmt::Debug for SessionCipher {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SessionCipher")
            .field("role", &self.role)
            .field("next_send", &self.next_send)
            .field("last_recv", &self.last_recv)
            .finish_non_exhaustive()
    }
}

impl SessionCipher {
    /// New session with both counters at their initial state (send from 0).
    pub fn new(key: &[u8; 32], role: Role) -> Self {
        Self {
            cipher: ChaCha20Poly1305::new(Key::from_slice(key)),
            role,
            next_send: Some(0),
            last_recv: None,
        }
    }

    /// Start the send counter at `counter` instead of 0 (tests / vectors only).
    pub fn with_send_counter(mut self, counter: u64) -> Self {
        self.next_send = Some(counter);
        self
    }

    /// Our role.
    pub fn role(&self) -> Role {
        self.role
    }

    /// Counter the next [`seal`](Self::seal) will use, or `None` if exhausted.
    pub fn next_send_counter(&self) -> Option<u64> {
        self.next_send
    }

    /// Highest counter accepted from the peer so far.
    pub fn last_received_counter(&self) -> Option<u64> {
        self.last_recv
    }

    /// Encrypt `plaintext` into an envelope and advance the send counter.
    pub fn seal(&mut self, plaintext: &[u8]) -> Result<Vec<u8>> {
        let counter = self.next_send.ok_or(Error::CounterExhausted)?;
        let env = seal_inner(&self.cipher, self.role.send_direction(), counter, plaintext)?;
        self.next_send = counter.checked_add(1);
        Ok(env)
    }

    /// Encode and encrypt a message (any encodable type).
    pub fn seal_message(&mut self, msg: &Message) -> Result<Vec<u8>> {
        let json = msg.to_json()?;
        self.seal(&json)
    }

    /// Decrypt an encrypted envelope from the peer, enforcing strictly
    /// increasing counters. The replay window only advances after the tag
    /// verifies, so forged envelopes cannot burn counters.
    pub fn open(&mut self, envelope: &[u8]) -> Result<Vec<u8>> {
        match Envelope::parse(envelope)? {
            Envelope::Encrypted {
                counter,
                ciphertext_and_tag,
            } => self.open_parts(counter, ciphertext_and_tag),
            Envelope::Plaintext(_) => Err(Error::UnknownEnvelopeKind(KIND_PLAINTEXT)),
        }
    }

    fn open_parts(&mut self, counter: u64, ct: &[u8]) -> Result<Vec<u8>> {
        if let Some(last) = self.last_recv {
            if counter <= last {
                return Err(Error::Replay { counter, last });
            }
        }
        let pt = open_inner(&self.cipher, self.role.recv_direction(), counter, ct)?;
        self.last_recv = Some(counter);
        Ok(pt)
    }
}

/// Decode a reassembled envelope into a message, enforcing §4.3 policy.
///
/// * Plaintext envelope: the JSON must be a plaintext-allowed type
///   (`hello`, `pair_request`, `pair_challenge`, `pair_confirm`, `pair_result`,
///   `error`), otherwise [`Error::PlaintextNotAllowed`]. Unknown types are
///   returned as [`Message::Unknown`] for the caller to drop. This holds
///   whether or not a session exists, so a plaintext `utt` is always rejected.
/// * Encrypted envelope: requires `session` ([`Error::NoSession`] otherwise);
///   decrypts with replay protection, then parses any message type.
pub fn decode_envelope(bytes: &[u8], session: Option<&mut SessionCipher>) -> Result<Message> {
    match Envelope::parse(bytes)? {
        Envelope::Plaintext(json) => {
            let msg = Message::from_json(json)?;
            match msg {
                Message::Unknown { .. } => Ok(msg),
                _ if msg.is_plaintext_allowed() => Ok(msg),
                _ => Err(Error::PlaintextNotAllowed(msg.type_name().to_owned())),
            }
        }
        Envelope::Encrypted {
            counter,
            ciphertext_and_tag,
        } => {
            let session = session.ok_or(Error::NoSession)?;
            let pt = session.open_parts(counter, ciphertext_and_tag)?;
            Message::from_json(&pt)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::message::{ErrorMsg, Utt, UttState};

    const KEY: [u8; 32] = [0x42; 32];

    fn pair() -> (SessionCipher, SessionCipher) {
        (
            SessionCipher::new(&KEY, Role::Phone),
            SessionCipher::new(&KEY, Role::Desktop),
        )
    }

    fn utt() -> Message {
        Message::Utt(Utt {
            id: uuid::Uuid::nil(),
            rev: 1,
            state: UttState::Partial,
            text: "hi".into(),
            ts: 0,
        })
    }

    /// RFC 8439 §2.8.2 AEAD vector, to pin the AEAD construction we rely on.
    #[test]
    fn rfc8439_aead() {
        let key: [u8; 32] =
            hex::decode("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f")
                .unwrap()
                .try_into()
                .unwrap();
        let nonce = hex::decode("070000004041424344454647").unwrap();
        let aad = hex::decode("50515253c0c1c2c3c4c5c6c7").unwrap();
        let pt = b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";
        let c = ChaCha20Poly1305::new(Key::from_slice(&key));
        let ct = c
            .encrypt(Nonce::from_slice(&nonce), Payload { msg: pt, aad: &aad })
            .unwrap();
        assert_eq!(
            hex::encode(&ct[ct.len() - 16..]),
            "1ae10b594f09e26a7e902ecbd0600691"
        );
    }

    #[test]
    fn nonce_layout() {
        assert_eq!(
            nonce(Direction::PhoneToDesktop, 0x0102030405060708),
            [1, 0, 0, 0, 1, 2, 3, 4, 5, 6, 7, 8]
        );
        assert_eq!(nonce(Direction::DesktopToPhone, 0)[0], 2);
    }

    #[test]
    fn roundtrip_both_directions() {
        let (mut p, mut d) = pair();
        for i in 0..5u64 {
            let env = p.seal_message(&utt()).unwrap();
            assert_eq!(env[0], KIND_ENCRYPTED);
            assert_eq!(&env[1..9], &i.to_be_bytes());
            assert_eq!(decode_envelope(&env, Some(&mut d)).unwrap(), utt());
            let back = d.seal_message(&Message::Pong).unwrap();
            assert_eq!(decode_envelope(&back, Some(&mut p)).unwrap(), Message::Pong);
        }
        assert_eq!(p.next_send_counter(), Some(5));
        assert_eq!(d.last_received_counter(), Some(4));
    }

    #[test]
    fn direction_is_bound() {
        let (mut p, _) = pair();
        let env = p.seal(b"{}").unwrap();
        // a phone cannot accept its own (reflected) message
        let mut p2 = SessionCipher::new(&KEY, Role::Phone);
        assert_eq!(p2.open(&env).unwrap_err(), Error::DecryptFailed);
    }

    #[test]
    fn replay_and_gaps() {
        let mut p = SessionCipher::new(&KEY, Role::Phone);
        let mut d = SessionCipher::new(&KEY, Role::Desktop);
        let e0 = p.seal(b"a").unwrap();
        let e1 = p.seal(b"b").unwrap();
        let e2 = p.seal(b"c").unwrap();
        let e3 = p.seal(b"d").unwrap();
        assert_eq!(d.open(&e0).unwrap(), b"a");
        assert_eq!(
            d.open(&e0).unwrap_err(),
            Error::Replay {
                counter: 0,
                last: 0
            }
        );
        assert_eq!(d.open(&e2).unwrap(), b"c"); // gap ok
        assert_eq!(d.open(&e1).unwrap_err().code(), "replay"); // older rejected
                                                               // forged high counter does not advance the window
        let mut forged = e3.clone();
        forged[1..9].copy_from_slice(&u64::MAX.to_be_bytes());
        assert_eq!(d.open(&forged).unwrap_err(), Error::DecryptFailed);
        assert_eq!(d.last_received_counter(), Some(2));
        assert_eq!(d.open(&e3).unwrap(), b"d");
    }

    #[test]
    fn tamper_detection() {
        let mut p = SessionCipher::new(&KEY, Role::Phone);
        let env = p.seal(b"hello").unwrap();
        for i in 0..env.len() {
            let mut t = env.clone();
            t[i] ^= 0x01;
            let mut d = SessionCipher::new(&KEY, Role::Desktop);
            let e = d.open(&t).unwrap_err();
            assert!(
                matches!(e, Error::DecryptFailed | Error::UnknownEnvelopeKind(_)),
                "byte {i}: {e:?}"
            );
            assert_eq!(d.last_received_counter(), None);
        }
        let mut d = SessionCipher::new(&[0x43; 32], Role::Desktop);
        assert_eq!(d.open(&env).unwrap_err(), Error::DecryptFailed);
    }

    #[test]
    fn counter_exhaustion() {
        let mut p = SessionCipher::new(&KEY, Role::Phone).with_send_counter(u64::MAX - 1);
        let mut d = SessionCipher::new(&KEY, Role::Desktop);
        let a = p.seal(b"x").unwrap();
        let b = p.seal(b"y").unwrap();
        assert_eq!(p.seal(b"z").unwrap_err(), Error::CounterExhausted);
        assert_eq!(p.next_send_counter(), None);
        assert_eq!(d.open(&a).unwrap(), b"x");
        assert_eq!(d.open(&b).unwrap(), b"y");
        assert_eq!(d.last_received_counter(), Some(u64::MAX));
        assert_eq!(d.open(&b).unwrap_err().code(), "replay");
    }

    #[test]
    fn envelope_parse_errors() {
        assert_eq!(Envelope::parse(&[]).unwrap_err(), Error::EmptyEnvelope);
        assert_eq!(
            Envelope::parse(&[0x02, 1]).unwrap_err(),
            Error::UnknownEnvelopeKind(2)
        );
        assert_eq!(
            Envelope::parse(&[0x01; 24]).unwrap_err(),
            Error::EnvelopeTooShort(24)
        );
        assert!(matches!(
            Envelope::parse(&[0x01; 25]).unwrap(),
            Envelope::Encrypted { .. }
        ));
        assert_eq!(Envelope::parse(&[0x00]).unwrap(), Envelope::Plaintext(&[]));
        let big = vec![0u8; MAX_MESSAGE_BYTES + 1];
        assert_eq!(
            Envelope::parse(&big).unwrap_err().code(),
            "message_too_large"
        );
    }

    #[test]
    fn plaintext_policy() {
        let env = encode_plaintext(&Message::Error(ErrorMsg::new("bad_mac", ""))).unwrap();
        assert_eq!(env[0], 0);
        assert!(matches!(
            decode_envelope(&env, None).unwrap(),
            Message::Error(_)
        ));
        assert_eq!(
            encode_plaintext(&utt()).unwrap_err().code(),
            "plaintext_not_allowed"
        );
        assert_eq!(
            encode_plaintext(&Message::Ping).unwrap_err().code(),
            "plaintext_not_allowed"
        );

        let mut raw = vec![0u8];
        raw.extend_from_slice(&utt().to_json().unwrap());
        assert_eq!(
            decode_envelope(&raw, None).unwrap_err(),
            Error::PlaintextNotAllowed("utt".into())
        );
        let (_, mut d) = pair();
        assert_eq!(
            decode_envelope(&raw, Some(&mut d)).unwrap_err().code(),
            "plaintext_not_allowed"
        );
        for t in ["ack", "ping", "pong"] {
            let raw = format!(
                "\x00{{\"t\":\"{t}\",\"id\":\"00000000-0000-0000-0000-000000000000\",\"rev\":1}}"
            );
            assert_eq!(
                decode_envelope(raw.as_bytes(), None).unwrap_err().code(),
                "plaintext_not_allowed"
            );
        }
        assert_eq!(
            decode_envelope(b"\x00{\"t\":\"zzz\"}", None).unwrap(),
            Message::Unknown { t: "zzz".into() }
        );
        // encrypted without session
        let (mut p, _) = pair();
        let env = p.seal_message(&utt()).unwrap();
        assert_eq!(decode_envelope(&env, None).unwrap_err(), Error::NoSession);
    }

    #[test]
    fn size_limits() {
        let mut p = SessionCipher::new(&KEY, Role::Phone);
        let max_pt = MAX_MESSAGE_BYTES - MIN_ENCRYPTED_BYTES;
        let env = p.seal(&vec![b' '; max_pt]).unwrap();
        assert_eq!(env.len(), MAX_MESSAGE_BYTES);
        assert_eq!(
            p.seal(&vec![b' '; max_pt + 1]).unwrap_err().code(),
            "message_too_large"
        );
        assert_eq!(p.next_send_counter(), Some(1)); // failed seal doesn't burn a counter
        let mut d = SessionCipher::new(&KEY, Role::Desktop);
        assert_eq!(d.open(&env).unwrap().len(), max_pt);
    }

    #[test]
    fn stateless_helpers_match() {
        let mut p = SessionCipher::new(&KEY, Role::Phone).with_send_counter(9);
        let env = p.seal(b"abc").unwrap();
        assert_eq!(
            seal_with(&KEY, Direction::PhoneToDesktop, 9, b"abc").unwrap(),
            env
        );
        assert_eq!(
            open_with(&KEY, Direction::PhoneToDesktop, &env).unwrap(),
            (9, b"abc".to_vec())
        );
        assert_eq!(
            open_with(&KEY, Direction::DesktopToPhone, &env).unwrap_err(),
            Error::DecryptFailed
        );
    }
}
