import CryptoKit
import Foundation

/// Envelopes (README §4).
///
///     plaintext : 0x00 ‖ JSON
///     encrypted : 0x01 ‖ counter (u64 BE) ‖ ChaCha20-Poly1305 ciphertext ‖ tag (16)
///     nonce (12): direction ‖ 00 00 00 ‖ counter (u64 BE)
///     AAD       : the kind byte (0x01)
public enum Envelope: Equatable, Sendable {
    /// Kind 0x00: JSON bytes.
    case plaintext([UInt8])
    /// Kind 0x01.
    case encrypted(counter: UInt64, ciphertextAndTag: [UInt8])

    public static let kindPlaintext: UInt8 = 0x00
    public static let kindEncrypted: UInt8 = 0x01
    public static let tagBytes = 16
    /// Smallest valid encrypted envelope: kind + counter + tag.
    public static let minEncryptedBytes = 1 + 8 + tagBytes

    /// Parse the envelope header (no decryption, no JSON).
    ///
    /// Checks, in order: size (`message_too_large`), emptiness
    /// (`empty_envelope`), kind (`unknown_envelope_kind`) and, for kind 0x01,
    /// length (`envelope_too_short`).
    public static func parse(_ bytes: [UInt8]) throws(VQError) -> Envelope {
        guard bytes.count <= VQ.maxMessageBytes else { throw .messageTooLarge(bytes.count) }
        guard let kind = bytes.first else { throw .emptyEnvelope }
        switch kind {
        case kindPlaintext:
            return .plaintext(Array(bytes[1...]))
        case kindEncrypted:
            guard bytes.count >= minEncryptedBytes else { throw .envelopeTooShort(bytes.count) }
            var counter: UInt64 = 0
            for b in bytes[1..<9] { counter = counter << 8 | UInt64(b) }
            return .encrypted(counter: counter, ciphertextAndTag: Array(bytes[9...]))
        default:
            throw .unknownEnvelopeKind(kind)
        }
    }
}

func nonceBytes(_ direction: Direction, _ counter: UInt64) -> [UInt8] {
    var n = [UInt8](repeating: 0, count: 12)
    n[0] = direction.rawValue
    for i in 0..<8 { n[4 + i] = UInt8(truncatingIfNeeded: counter >> UInt64(56 - 8 * i)) }
    return n
}

/// The 12-byte AEAD nonce (test vectors only).
func nonceForTests(_ direction: Direction, _ counter: UInt64) -> [UInt8] { nonceBytes(direction, counter) }

/// Encode a plaintext envelope. Only plaintext-allowed types are accepted.
///
/// Errors: `plaintext_not_allowed`, then the ``Message/toJSON()`` errors,
/// then `message_too_large` for the envelope.
public func encodePlaintext(_ message: Message) throws(VQError) -> [UInt8] {
    guard message.isPlaintextAllowed else { throw .plaintextNotAllowed(message.typeName) }
    let json = try message.toJSON()
    let out = [Envelope.kindPlaintext] + json
    guard out.count <= VQ.maxMessageBytes else { throw .messageTooLarge(out.count) }
    return out
}

private func sealInner(_ key: SymmetricKey, _ direction: Direction, _ counter: UInt64,
                       _ plaintext: [UInt8]) throws(VQError) -> [UInt8] {
    let total = Envelope.minEncryptedBytes + plaintext.count
    guard total <= VQ.maxMessageBytes else { throw .messageTooLarge(total) }
    let box: ChaChaPoly.SealedBox
    do {
        let nonce = try ChaChaPoly.Nonce(data: nonceBytes(direction, counter))
        box = try ChaChaPoly.seal(plaintext, using: key, nonce: nonce, authenticating: [Envelope.kindEncrypted])
    } catch {
        // Unreachable with a 12-byte nonce and a 32-byte key.
        throw .messageTooLarge(total)
    }
    var out: [UInt8] = []
    out.reserveCapacity(total)
    out.append(Envelope.kindEncrypted)
    for i in 0..<8 { out.append(UInt8(truncatingIfNeeded: counter >> UInt64(56 - 8 * i))) }
    out.append(contentsOf: box.ciphertext)
    out.append(contentsOf: box.tag)
    return out
}

private func openInner(_ key: SymmetricKey, _ direction: Direction, _ counter: UInt64,
                       _ ct: [UInt8]) throws(VQError) -> [UInt8] {
    let tagStart = ct.count - Envelope.tagBytes
    do {
        let box = try ChaChaPoly.SealedBox(
            nonce: ChaChaPoly.Nonce(data: nonceBytes(direction, counter)),
            ciphertext: ct[..<tagStart],
            tag: ct[tagStart...])
        return Array(try ChaChaPoly.open(box, using: key, authenticating: [Envelope.kindEncrypted]))
    } catch {
        throw .decryptFailed
    }
}

/// Stateless encryption (test vectors only: no counter bookkeeping).
func sealForTests(key: [UInt8], direction: Direction, counter: UInt64, plaintext: [UInt8]) throws(VQError) -> [UInt8] {
    try sealInner(SymmetricKey(data: key), direction, counter, plaintext)
}

/// Per-session AEAD state: one send counter and one replay window.
///
/// Create it with ``establish(identity:role:peerPublic:ownNonce:peerNonce:)``,
/// once per connection, from a fresh ``SessionNonce`` exchange. `K_sess` is
/// derived inside and never exposed. The counters live in this one object, so
/// they can be neither rewound nor duplicated. Never keep a `SessionCipher`
/// across connections.
public final class SessionCipher: CustomStringConvertible {
    private let key: SymmetricKey
    /// Our role.
    public let role: Role
    /// Counter the next ``seal(_:)`` will use, or `nil` once 2^64−1 has been used.
    public private(set) var nextSendCounter: UInt64?
    /// Highest counter accepted from the peer so far.
    public private(set) var lastReceivedCounter: UInt64?

    private init(key: SymmetricKey, role: Role) {
        self.key = key
        self.role = role
        nextSendCounter = 0
        lastReceivedCounter = nil
    }

    /// Establish the session for one connection (README §6.4).
    ///
    /// - Parameters:
    ///   - identity: our long-term key pair.
    ///   - role: our role.
    ///   - peerPublic: the peer's `hello.pub` (already checked against our store).
    ///   - ownNonce: the nonce we sent in our `hello` on **this** connection. Consumed.
    ///   - peerNonce: `session_nonce` from the peer's `hello` on this connection.
    ///
    /// Derives `K_sess` with the phone's nonce first and starts both counters
    /// fresh. Fails with `non_contributory` for a low-order peer key.
    public static func establish(identity: IdentityKeyPair, role: Role, peerPublic: Bytes32,
                                 ownNonce: consuming SessionNonce,
                                 peerNonce: Bytes32) throws(VQError) -> SessionCipher {
        let ss = try identity.sharedSecret(peerPublic: peerPublic)
        let own = ownNonce.bytes
        let key = role == .phone
            ? sessionKey(ss, noncePhone: own, nonceDesktop: peerNonce)
            : sessionKey(ss, noncePhone: peerNonce, nonceDesktop: own)
        return SessionCipher(key: key, role: role)
    }

    /// New session from a raw key (test vectors only).
    convenience init(rawKeyForTests key: [UInt8], role: Role) {
        self.init(key: SymmetricKey(data: key), role: role)
    }

    /// Move the send counter forward (test vectors only). Never lowers it.
    func advanceSendCounterForTests(to counter: UInt64) {
        guard let current = nextSendCounter else { preconditionFailure("send counter is exhausted") }
        precondition(counter >= current, "the send counter must never be lowered")
        nextSendCounter = counter
    }

    /// Encrypt `plaintext` into an envelope and advance the send counter.
    /// A failed seal (e.g. `message_too_large`) does not consume a counter.
    public func seal(_ plaintext: [UInt8]) throws(VQError) -> [UInt8] {
        guard let counter = nextSendCounter else { throw .counterExhausted }
        let env = try sealInner(key, role.sendDirection, counter, plaintext)
        nextSendCounter = counter == .max ? nil : counter + 1
        return env
    }

    /// Encode and encrypt a message. Errors: the ``Message/toJSON()``
    /// errors, then `counter_exhausted`, then `message_too_large`.
    public func sealMessage(_ message: Message) throws(VQError) -> [UInt8] {
        try seal(try message.toJSON())
    }

    /// Decrypt an encrypted envelope from the peer, rejecting any counter ≤ the
    /// last accepted one before decrypting. The window advances only after the
    /// tag verifies. A plaintext envelope is `unknown_envelope_kind`.
    public func open(_ envelope: [UInt8]) throws(VQError) -> [UInt8] {
        switch try Envelope.parse(envelope) {
        case .encrypted(let counter, let ct): return try openParts(counter, ct)
        case .plaintext: throw .unknownEnvelopeKind(Envelope.kindPlaintext)
        }
    }

    fileprivate func openParts(_ counter: UInt64, _ ct: [UInt8]) throws(VQError) -> [UInt8] {
        if let last = lastReceivedCounter, counter <= last {
            throw .replay(counter: counter, last: last)
        }
        let pt = try openInner(key, role.recvDirection, counter, ct)
        lastReceivedCounter = counter
        return pt
    }

    public var description: String {
        "SessionCipher(role: \(role), nextSend: \(String(describing: nextSendCounter)), lastRecv: \(String(describing: lastReceivedCounter)))"
    }
}

/// A decoded inbound message with its provenance (README §4.3).
public enum Inbound: Equatable, Sendable {
    /// From a plaintext envelope: **unauthenticated**; anyone in radio range
    /// could have sent it. An unauthenticated `error` MUST NOT change stored
    /// pairing state.
    case plaintext(Message)
    /// From an encrypted envelope that verified under `K_sess`: authenticated.
    case encrypted(Message)

    /// The message, whatever its provenance.
    public var message: Message {
        switch self {
        case .plaintext(let m), .encrypted(let m): m
        }
    }

    /// Whether the message was authenticated (arrived encrypted).
    public var isAuthenticated: Bool {
        if case .encrypted = self { return true }
        return false
    }
}

/// Decode a reassembled envelope into a message with its provenance,
/// enforcing the plaintext policy. Error precedence is README §9.1.
///
/// * Plaintext: a known type outside the allowed set is `plaintext_not_allowed`,
///   decided from `t` before other fields. Unknown types come back as
///   ``Message/unknown(t:)`` for the caller to drop.
/// * Encrypted: requires `session` (`no_session`); replay check, decrypt
///   (the window advances as soon as the tag verifies), then any type.
///
/// Once Secure, also pass every result through ``checkInSession(_:)``.
public func decodeInbound(_ bytes: [UInt8], session: SessionCipher?) throws(VQError) -> Inbound {
    switch try Envelope.parse(bytes) {
    case .plaintext(let json):
        let msg = try Message.decode(json, policy: { t throws(VQError) in
            let s = String(decoding: t, as: UTF8.self)
            if isKnownType(s), !plaintextAllowedTypes.contains(where: { Array($0.utf8) == t }) {
                throw .plaintextNotAllowed(s)
            }
        })
        return .plaintext(msg)
    case .encrypted(let counter, let ct):
        guard let session else { throw .noSession }
        let pt = try session.openParts(counter, ct)
        return .encrypted(try Message.fromJSON(pt))
    }
}

/// ``decodeInbound(_:session:)`` without provenance (test vectors only).
func decodeEnvelopeForTests(_ bytes: [UInt8], session: SessionCipher?) throws(VQError) -> Message {
    try decodeInbound(bytes, session: session).message
}

/// Policy for a connection that is already Secure (README §7.4).
///
/// Rejects with `not_allowed_in_session` any `hello` (including an
/// unsupported-version one) and any pairing message, plaintext or encrypted.
/// For a `hello`, send `error{code:"protocol"}` and disconnect; drop pairing
/// messages. Everything else passes, including a plaintext `error`, which may
/// end the connection but MUST NOT change stored pairing state.
public func checkInSession(_ inbound: Inbound) throws(VQError) {
    switch inbound.message {
    case .hello, .helloUnsupported, .pairRequest, .pairChallenge, .pairConfirm, .pairResult:
        throw .notAllowedInSession(inbound.message.typeName)
    default:
        return
    }
}
