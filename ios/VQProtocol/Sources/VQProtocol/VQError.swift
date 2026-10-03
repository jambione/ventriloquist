/// All errors produced by VQProtocol.
///
/// Every case has a stable string ``code`` identical to the Rust crate's
/// (README §9). The vectors use these codes.
///
/// The ``description`` is for local logs only. It contains at most a short,
/// bounded excerpt of peer-supplied data and MUST NOT be copied into the
/// `msg` of an outgoing `error` message (README §5.7).
public enum VQError: Error, Equatable, Sendable, CustomStringConvertible {
    // framing (split)
    /// The splitter `mtu` is below 20.
    case mtuTooSmall(Int)
    // framing (reassembly)
    /// A frame shorter than the 3-byte header.
    case frameTooShort
    /// A frame with reserved flag bits set.
    case reservedFlags(UInt8)
    /// A continuation frame with no partial buffer.
    case orphanFrame
    /// A continuation frame whose `msg_seq` differs from the partial buffer's.
    case seqMismatch(expected: UInt16, got: UInt16)
    // size limits
    /// A message, envelope or buffer above 65,536 bytes.
    case messageTooLarge(Int)
    /// `utt.text` above 32,000 UTF-8 bytes.
    case textTooLong(Int)
    // messages
    /// Any rule of README §5.1 "JSON strictness".
    case invalidJSON(String)
    /// Not an object, bad or missing `t`, or a bad field of a known type.
    case invalidMessage(String)
    /// Tried to encode a receive-only or inconsistent message.
    case notEncodable(String)
    // envelope
    /// Zero-length envelope.
    case emptyEnvelope
    /// First envelope byte is neither 0x00 nor 0x01.
    case unknownEnvelopeKind(UInt8)
    /// Encrypted envelope shorter than 25 bytes.
    case envelopeTooShort(Int)
    /// AEAD tag check failed.
    case decryptFailed
    /// Counter ≤ the last accepted counter.
    case replay(counter: UInt64, last: UInt64)
    /// The send counter 2^64−1 has already been used.
    case counterExhausted
    /// A known non-allowed type in a plaintext envelope (or about to be sent so).
    case plaintextNotAllowed(String)
    /// Encrypted envelope without an established session.
    case noSession
    /// `hello` or a pairing message received while Secure.
    case notAllowedInSession(String)
    // crypto / pairing
    /// All-zero X25519 output (low-order peer key).
    case nonContributory
    /// Pairing code is not exactly 6 ASCII digits.
    case invalidCode
    /// MAC verification failed.
    case badMac

    /// The stable, implementation-independent code (README §9).
    public var code: String {
        switch self {
        case .mtuTooSmall: "mtu_too_small"
        case .frameTooShort: "frame_too_short"
        case .reservedFlags: "reserved_flags"
        case .orphanFrame: "orphan_frame"
        case .seqMismatch: "seq_mismatch"
        case .messageTooLarge: "message_too_large"
        case .textTooLong: "text_too_long"
        case .invalidJSON: "invalid_json"
        case .invalidMessage: "invalid_message"
        case .notEncodable: "not_encodable"
        case .emptyEnvelope: "empty_envelope"
        case .unknownEnvelopeKind: "unknown_envelope_kind"
        case .envelopeTooShort: "envelope_too_short"
        case .decryptFailed: "decrypt_failed"
        case .replay: "replay"
        case .counterExhausted: "counter_exhausted"
        case .plaintextNotAllowed: "plaintext_not_allowed"
        case .noSession: "no_session"
        case .notAllowedInSession: "not_allowed_in_session"
        case .nonContributory: "non_contributory"
        case .invalidCode: "invalid_code"
        case .badMac: "bad_mac"
        }
    }

    public var description: String {
        switch self {
        case .mtuTooSmall(let m): "MTU payload size \(m) is below the minimum of 20 bytes"
        case .frameTooShort: "frame is shorter than the 3-byte header"
        case .reservedFlags(let f): "frame has reserved flag bits set (flags = \(hexByte(f)))"
        case .orphanFrame: "continuation frame without a preceding FIRST frame"
        case .seqMismatch(let e, let g):
            "frame msg_seq \(g) does not match the message being reassembled (\(e))"
        case .messageTooLarge(let n): "message exceeds the 65536-byte limit (\(n) bytes)"
        case .textTooLong(let n): "text exceeds the 32000-byte limit (\(n) bytes)"
        case .invalidJSON(let why): "invalid JSON: \(why)"
        case .invalidMessage(let why): "invalid message: \(why)"
        case .notEncodable(let why): "message cannot be encoded: \(why)"
        case .emptyEnvelope: "empty envelope"
        case .unknownEnvelopeKind(let k): "unknown envelope kind \(hexByte(k))"
        case .envelopeTooShort(let n): "encrypted envelope too short (\(n) bytes, minimum 25)"
        case .decryptFailed: "decryption failed"
        case .replay(let c, let l): "replayed or out-of-order counter \(c) (last accepted \(l))"
        case .counterExhausted: "send counter exhausted"
        case .plaintextNotAllowed(let t):
            "message type \(excerpt(t)) is not allowed in a plaintext envelope"
        case .noSession: "encrypted envelope received without an established session"
        case .notAllowedInSession(let t):
            "message type \(excerpt(t)) is not allowed once a session is established"
        case .nonContributory: "X25519 shared secret is all zeros (non-contributory peer key)"
        case .invalidCode: "invalid pairing code: must be exactly 6 ASCII digits"
        case .badMac: "MAC verification failed"
        }
    }
}

/// At most this many characters of peer-controlled text go into an error description.
let excerptChars = 64

/// Bounded, quoted excerpt of untrusted input for error descriptions.
func excerpt(_ s: String) -> String {
    let scalars = s.unicodeScalars
    let head = String(String.UnicodeScalarView(scalars.prefix(excerptChars)))
    let quoted = head.debugDescription
    return scalars.dropFirst(excerptChars).isEmpty ? quoted : quoted + "…"
}

private func hexByte(_ b: UInt8) -> String {
    let digits = Array("0123456789abcdef")
    return "0x" + String(digits[Int(b >> 4)]) + String(digits[Int(b & 0x0F)])
}
