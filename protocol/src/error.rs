//! Error type shared by every layer of the protocol.
//!
//! Every variant has a stable, implementation-independent string code
//! ([`Error::code`]). Those codes are what `protocol/vectors/*.json` uses to
//! describe expected failures, so the Swift implementation can map its own
//! errors onto the same names.
//!
//! The `Display` text of an error is for local logs only. It never contains
//! more than a short, bounded excerpt of peer-supplied data, and it MUST NOT
//! be copied into the `msg` of an outgoing `error` message (README §5.7).

use thiserror::Error;

/// All errors produced by `vq-protocol`.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum Error {
    // ---- framing (split) ----
    /// The MTU payload size given to the splitter is below [`crate::MIN_MTU`].
    #[error("MTU payload size {0} is below the minimum of 20 bytes")]
    MtuTooSmall(usize),

    // ---- framing (reassembly) ----
    /// A frame shorter than the 3-byte header.
    #[error("frame is shorter than the 3-byte header")]
    FrameTooShort,
    /// A frame with any of the reserved flag bits (bits 2-7) set.
    #[error("frame has reserved flag bits set (flags = {0:#04x})")]
    ReservedFlags(u8),
    /// A non-FIRST frame arrived while no message was being reassembled.
    #[error("continuation frame without a preceding FIRST frame")]
    OrphanFrame,
    /// A non-FIRST frame whose `msg_seq` differs from the buffer being reassembled.
    #[error("frame msg_seq {got} does not match the message being reassembled ({expected})")]
    SeqMismatch {
        /// `msg_seq` of the partial buffer.
        expected: u16,
        /// `msg_seq` of the offending frame.
        got: u16,
    },

    // ---- size limits (any layer) ----
    /// A message, envelope or reassembly buffer exceeded 64 KiB.
    #[error("message exceeds the 65536-byte limit ({0} bytes)")]
    MessageTooLarge(usize),
    /// An `utt.text` exceeded 32,000 UTF-8 bytes.
    #[error("text exceeds the 32000-byte limit ({0} bytes)")]
    TextTooLong(usize),

    // ---- messages ----
    /// The bytes are not valid UTF-8 JSON.
    #[error("invalid JSON: {0}")]
    InvalidJson(String),
    /// Valid JSON, but not a valid message (not an object, no string `t`,
    /// or a known `t` with missing / ill-typed fields).
    #[error("invalid message: {0}")]
    InvalidMessage(String),
    /// Attempted to encode a message that cannot be put on the wire
    /// (e.g. [`crate::Message::Unknown`]).
    #[error("message cannot be encoded: {0}")]
    NotEncodable(&'static str),

    // ---- envelope ----
    /// Zero-length envelope.
    #[error("empty envelope")]
    EmptyEnvelope,
    /// First envelope byte is neither 0x00 nor 0x01.
    #[error("unknown envelope kind {0:#04x}")]
    UnknownEnvelopeKind(u8),
    /// Encrypted envelope shorter than kind + counter + tag (25 bytes).
    #[error("encrypted envelope too short ({0} bytes, minimum 25)")]
    EnvelopeTooShort(usize),
    /// AEAD authentication failed.
    #[error("decryption failed")]
    DecryptFailed,
    /// Counter is less than or equal to the last accepted counter.
    #[error("replayed or out-of-order counter {counter} (last accepted {last})")]
    Replay {
        /// Counter carried by the rejected envelope.
        counter: u64,
        /// Last accepted counter.
        last: u64,
    },
    /// The sending counter has reached `u64::MAX`; the session must be re-established.
    #[error("send counter exhausted")]
    CounterExhausted,
    /// A message type that must be encrypted arrived (or was about to be sent) in plaintext.
    #[error("message type `{0}` is not allowed in a plaintext envelope")]
    PlaintextNotAllowed(String),
    /// An encrypted envelope arrived but no session key is established.
    #[error("encrypted envelope received without an established session")]
    NoSession,
    /// A `hello` or pairing message arrived on a connection that is already
    /// Secure (see [`crate::check_in_session`]).
    #[error("message type `{0}` is not allowed once a session is established")]
    NotAllowedInSession(String),

    // ---- crypto / pairing ----
    /// X25519 produced the all-zero shared secret (peer sent a low-order point).
    #[error("X25519 shared secret is all zeros (non-contributory peer key)")]
    NonContributory,
    /// A pairing code string that is not exactly 6 ASCII digits.
    #[error("invalid pairing code: must be exactly 6 ASCII digits")]
    InvalidCode,
    /// MAC verification failed.
    #[error("MAC verification failed")]
    BadMac,
}

impl Error {
    /// Stable string code for this error (used in test vectors).
    pub fn code(&self) -> &'static str {
        match self {
            Error::MtuTooSmall(_) => "mtu_too_small",
            Error::FrameTooShort => "frame_too_short",
            Error::ReservedFlags(_) => "reserved_flags",
            Error::OrphanFrame => "orphan_frame",
            Error::SeqMismatch { .. } => "seq_mismatch",
            Error::MessageTooLarge(_) => "message_too_large",
            Error::TextTooLong(_) => "text_too_long",
            Error::InvalidJson(_) => "invalid_json",
            Error::InvalidMessage(_) => "invalid_message",
            Error::NotEncodable(_) => "not_encodable",
            Error::EmptyEnvelope => "empty_envelope",
            Error::UnknownEnvelopeKind(_) => "unknown_envelope_kind",
            Error::EnvelopeTooShort(_) => "envelope_too_short",
            Error::DecryptFailed => "decrypt_failed",
            Error::Replay { .. } => "replay",
            Error::CounterExhausted => "counter_exhausted",
            Error::PlaintextNotAllowed(_) => "plaintext_not_allowed",
            Error::NoSession => "no_session",
            Error::NotAllowedInSession(_) => "not_allowed_in_session",
            Error::NonContributory => "non_contributory",
            Error::InvalidCode => "invalid_code",
            Error::BadMac => "bad_mac",
        }
    }
}

/// At most this many characters of peer-controlled text are ever placed in
/// an error's `Display` output.
pub(crate) const EXCERPT_CHARS: usize = 64;

/// Bounded, quoted excerpt of untrusted input for error messages.
pub(crate) fn excerpt(s: &str) -> String {
    let mut it = s.chars();
    let head: String = it.by_ref().take(EXCERPT_CHARS).collect();
    if it.next().is_some() {
        format!("{head:?}…")
    } else {
        format!("{head:?}")
    }
}

/// Convenience alias.
pub type Result<T> = std::result::Result<T, Error>;
