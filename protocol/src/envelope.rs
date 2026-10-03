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

use crate::crypto::{self, IdentityKeyPair, SessionNonce};
use crate::error::{Error, Result};
use crate::message::{self, Message, PLAINTEXT_ALLOWED};
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

fn nonce_bytes(direction: Direction, counter: u64) -> [u8; 12] {
    let mut n = [0u8; 12];
    n[0] = direction.byte();
    n[4..].copy_from_slice(&counter.to_be_bytes());
    n
}

/// The 12-byte AEAD nonce for `direction` and `counter` (test vectors only).
#[cfg(any(test, feature = "test-vectors"))]
#[doc(hidden)]
pub fn nonce(direction: Direction, counter: u64) -> [u8; 12] {
    nonce_bytes(direction, counter)
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
    ///
    /// Checks, in order: size (`message_too_large`), emptiness
    /// (`empty_envelope`), kind (`unknown_envelope_kind`) and, for kind 0x01,
    /// length (`envelope_too_short`).
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

/// Stateless encryption of one envelope (test vectors only: no counter
/// bookkeeping, so it can reuse nonces).
#[cfg(any(test, feature = "test-vectors"))]
#[doc(hidden)]
pub fn seal_with(
    key: &[u8; 32],
    direction: Direction,
    counter: u64,
    plaintext: &[u8],
) -> Result<Vec<u8>> {
    let cipher = ChaCha20Poly1305::new(Key::from_slice(key));
    seal_inner(&cipher, direction, counter, plaintext)
}

/// Stateless decryption of one envelope (test vectors only: no replay
/// check). Returns `(counter, plaintext)`. Plaintext envelopes are rejected
/// with [`Error::UnknownEnvelopeKind`]`(0x00)`.
#[cfg(any(test, feature = "test-vectors"))]
#[doc(hidden)]
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
    let n = nonce_bytes(direction, counter);
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
    let n = nonce_bytes(direction, counter);
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
///
/// Create it with [`SessionCipher::establish`], once per connection, from
/// a fresh [`SessionNonce`] exchange. `K_sess` is derived inside and never
/// exposed, and a `SessionCipher` is not `Clone`, so counters cannot be
/// rewound or shared.
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
    /// Establish the session for one connection (README §6.4).
    ///
    /// * `identity`: our long-term key pair; `role`: our role.
    /// * `peer_public`: the peer's `hello.pub` (already checked against our
    ///   pairing store by the caller).
    /// * `own_nonce`: the [`SessionNonce`] whose bytes we sent in our
    ///   `hello` on **this** connection. It is consumed.
    /// * `peer_nonce`: `session_nonce` from the peer's `hello` on this connection.
    ///
    /// Derives `K_sess = HKDF-SHA256(ss, nonce_phone ‖ nonce_desktop,
    /// "vq/session/v1")` with the phone's nonce first, and starts both
    /// counters fresh. Fails with `non_contributory` for a low-order peer key.
    pub fn establish(
        identity: &IdentityKeyPair,
        role: Role,
        peer_public: &[u8; 32],
        own_nonce: SessionNonce,
        peer_nonce: &[u8; 32],
    ) -> Result<Self> {
        let ss = identity.shared_secret(peer_public)?;
        let own = own_nonce.bytes();
        let key = match role {
            Role::Phone => crypto::session_key(&ss, &own, peer_nonce),
            Role::Desktop => crypto::session_key(&ss, peer_nonce, &own),
        };
        Ok(Self::from_key(&key, role))
    }

    fn from_key(key: &[u8; 32], role: Role) -> Self {
        Self {
            cipher: ChaCha20Poly1305::new(Key::from_slice(key)),
            role,
            next_send: Some(0),
            last_recv: None,
        }
    }

    /// New session from a raw key (test vectors only).
    #[cfg(any(test, feature = "test-vectors"))]
    #[doc(hidden)]
    pub fn new(key: &[u8; 32], role: Role) -> Self {
        Self::from_key(key, role)
    }

    /// Move the send counter forward to `counter` (test vectors only).
    ///
    /// # Panics
    /// If that would lower the counter, or the counter is exhausted: a
    /// counter is never reused.
    #[cfg(any(test, feature = "test-vectors"))]
    #[doc(hidden)]
    pub fn with_send_counter(mut self, counter: u64) -> Self {
        let current = self
            .next_send
            .expect("with_send_counter: send counter is exhausted");
        assert!(
            counter >= current,
            "with_send_counter must never lower the counter ({counter} < {current})"
        );
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

/// A decoded inbound message together with its provenance.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Inbound {
    /// Arrived in a plaintext envelope: **unauthenticated**. Anyone in radio
    /// range could have sent it.
    Plaintext(Message),
    /// Arrived in an encrypted envelope that verified under `K_sess`:
    /// authenticated as coming from the paired peer.
    Encrypted(Message),
}

impl Inbound {
    /// The message, whatever its provenance.
    pub fn message(&self) -> &Message {
        match self {
            Inbound::Plaintext(m) | Inbound::Encrypted(m) => m,
        }
    }

    /// Consume into the message.
    pub fn into_message(self) -> Message {
        match self {
            Inbound::Plaintext(m) | Inbound::Encrypted(m) => m,
        }
    }

    /// Whether the message was authenticated (arrived encrypted).
    pub fn is_authenticated(&self) -> bool {
        matches!(self, Inbound::Encrypted(_))
    }
}

/// Decode a reassembled envelope into a message with its provenance,
/// enforcing the §4.3 plaintext policy. Error precedence is README §9.1.
///
/// * Plaintext envelope: a known type outside the plaintext-allowed set
///   (`utt`, `ack`, `ping`, `pong`) is [`Error::PlaintextNotAllowed`],
///   decided from `t` before any other field is checked. Unknown types are
///   returned as [`Message::Unknown`] for the caller to drop. This holds
///   whether or not a session exists.
/// * Encrypted envelope: requires `session` ([`Error::NoSession`]);
///   decrypts with replay protection (the window advances as soon as the tag
///   verifies, even if the JSON inside is then invalid), then parses any
///   message type.
///
/// Once the connection is Secure, pass every result through
/// [`check_in_session`] as well.
pub fn decode_inbound(bytes: &[u8], session: Option<&mut SessionCipher>) -> Result<Inbound> {
    match Envelope::parse(bytes)? {
        Envelope::Plaintext(json) => {
            let msg = Message::decode_with_policy(json, |t| {
                if message::is_known_type(t) && !PLAINTEXT_ALLOWED.contains(&t) {
                    Err(Error::PlaintextNotAllowed(t.to_owned()))
                } else {
                    Ok(())
                }
            })?;
            Ok(Inbound::Plaintext(msg))
        }
        Envelope::Encrypted {
            counter,
            ciphertext_and_tag,
        } => {
            let session = session.ok_or(Error::NoSession)?;
            let pt = session.open_parts(counter, ciphertext_and_tag)?;
            Ok(Inbound::Encrypted(Message::from_json(&pt)?))
        }
    }
}

/// [`decode_inbound`] without provenance (test vectors only).
#[cfg(any(test, feature = "test-vectors"))]
#[doc(hidden)]
pub fn decode_envelope(bytes: &[u8], session: Option<&mut SessionCipher>) -> Result<Message> {
    decode_inbound(bytes, session).map(Inbound::into_message)
}

/// Policy for a connection that is already Secure (README §7.3).
///
/// Rejects with [`Error::NotAllowedInSession`] any `hello` (including an
/// unsupported-version one) and any `pair_request`, `pair_challenge`,
/// `pair_confirm` or `pair_result`, whether it arrived plaintext or
/// encrypted. Everything else passes, including a plaintext `error`: the
/// caller may disconnect on it but MUST NOT change any stored pairing state,
/// because it is unauthenticated ([`Inbound::is_authenticated`]).
pub fn check_in_session(inbound: &Inbound) -> Result<()> {
    match inbound.message() {
        m @ (Message::Hello(_)
        | Message::HelloUnsupported(_)
        | Message::PairRequest(_)
        | Message::PairChallenge(_)
        | Message::PairConfirm(_)
        | Message::PairResult(_)) => Err(Error::NotAllowedInSession(m.type_name().to_owned())),
        _ => Ok(()),
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

    #[test]
    fn establish_derives_matching_ciphers() {
        use crate::crypto::{derive_session_key, IdentityKeyPair, SessionNonce};
        let phone = IdentityKeyPair::generate();
        let desk = IdentityKeyPair::generate();
        let (np, nd) = (SessionNonce::generate(), SessionNonce::generate());
        let (np_b, nd_b) = (np.bytes(), nd.bytes());
        let mut p =
            SessionCipher::establish(&phone, Role::Phone, &desk.public_bytes(), np, &nd_b).unwrap();
        let mut d =
            SessionCipher::establish(&desk, Role::Desktop, &phone.public_bytes(), nd, &np_b)
                .unwrap();
        let env = p.seal_message(&Message::Ping).unwrap();
        assert_eq!(
            decode_inbound(&env, Some(&mut d)).unwrap(),
            Inbound::Encrypted(Message::Ping)
        );
        let back = d.seal_message(&Message::Pong).unwrap();
        assert_eq!(
            decode_inbound(&back, Some(&mut p)).unwrap().into_message(),
            Message::Pong
        );
        // same bytes as the raw derivation, phone nonce first
        let ss = phone.shared_secret(&desk.public_bytes()).unwrap();
        let mut raw = SessionCipher::new(&derive_session_key(&ss, &np_b, &nd_b), Role::Desktop);
        let env = SessionCipher::establish(
            &phone,
            Role::Phone,
            &desk.public_bytes(),
            SessionNonce::from_bytes_for_tests(np_b),
            &nd_b,
        )
        .unwrap()
        .seal(b"{}")
        .unwrap();
        assert_eq!(raw.open(&env).unwrap(), b"{}");
        // low-order peer key
        assert_eq!(
            SessionCipher::establish(
                &phone,
                Role::Phone,
                &[0; 32],
                SessionNonce::generate(),
                &nd_b
            )
            .unwrap_err(),
            Error::NonContributory
        );
    }

    #[test]
    fn provenance_and_in_session_policy() {
        let (mut p, mut d) = pair();
        let pt_err = encode_plaintext(&Message::Error(ErrorMsg::new("unknown_peer", ""))).unwrap();
        let got = decode_inbound(&pt_err, Some(&mut d)).unwrap();
        assert!(!got.is_authenticated());
        assert!(matches!(got, Inbound::Plaintext(Message::Error(_))));
        assert_eq!(check_in_session(&got), Ok(()));
        let enc = p.seal_message(&utt()).unwrap();
        let got = decode_inbound(&enc, Some(&mut d)).unwrap();
        assert!(got.is_authenticated());
        assert_eq!(check_in_session(&got), Ok(()));
        let pr = Message::PairRequest(crate::message::PairRequest { nonce_p: [0; 32] });
        let got = decode_inbound(&encode_plaintext(&pr).unwrap(), Some(&mut d)).unwrap();
        assert_eq!(
            check_in_session(&got).unwrap_err().code(),
            "not_allowed_in_session"
        );
        let got = decode_inbound(&p.seal_message(&pr).unwrap(), Some(&mut d)).unwrap();
        assert!(got.is_authenticated());
        assert_eq!(
            check_in_session(&got).unwrap_err().code(),
            "not_allowed_in_session"
        );
        let got = decode_inbound(b"\x00{\"t\":\"hello\",\"v\":9}", Some(&mut d)).unwrap();
        assert_eq!(
            check_in_session(&got).unwrap_err().code(),
            "not_allowed_in_session"
        );
        let got = decode_inbound(b"\x00{\"t\":\"zzz\"}", Some(&mut d)).unwrap();
        assert_eq!(check_in_session(&got), Ok(()));
    }

    #[test]
    fn policy_precedes_field_validation() {
        // plaintext utt with broken fields: plaintext_not_allowed, not invalid_message
        assert_eq!(
            decode_inbound(b"\x00{\"t\":\"utt\",\"rev\":-1}", None)
                .unwrap_err()
                .code(),
            "plaintext_not_allowed"
        );
        // but JSON-level problems come first
        assert_eq!(
            decode_inbound(b"\x00{\"t\":\"utt\",\"x\":1e400}", None)
                .unwrap_err()
                .code(),
            "invalid_json"
        );
    }

    #[test]
    #[should_panic(expected = "never lower")]
    fn with_send_counter_never_lowers() {
        let (mut p, _) = pair();
        p.seal(b"x").unwrap();
        let _ = p.with_send_counter(0);
    }
}
