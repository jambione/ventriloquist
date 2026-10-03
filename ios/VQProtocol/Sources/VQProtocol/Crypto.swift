import CryptoKit
import Foundation

// Identity keys, pairing and session key derivation (README §6).
//
//   ss     = X25519(own_priv, peer_pub)                       (all-zero rejected)
//   K_pair = HKDF-SHA256(ss, salt = nonce_p ‖ nonce_d, info = "vq/pair/v1" ‖ C)
//   mac_p  = HMAC-SHA256(K_pair, "phone"   ‖ pub_p ‖ pub_d)
//   mac_d  = HMAC-SHA256(K_pair, "desktop" ‖ pub_d ‖ pub_p)
//   K_sess = HKDF-SHA256(ss, salt = nonce_phone ‖ nonce_desktop, info = "vq/session/v1")

let pairInfoPrefix = Array("vq/pair/v1".utf8)
let sessionInfo = Array("vq/session/v1".utf8)
let phoneMacLabel = Array("phone".utf8)
let desktopMacLabel = Array("desktop".utf8)

/// Which end of the link we are.
public enum Role: Sendable, Hashable {
    /// The iPhone (GATT peripheral).
    case phone
    /// The desktop (GATT central).
    case desktop

    /// Direction of messages this role sends.
    public var sendDirection: Direction { self == .phone ? .phoneToDesktop : .desktopToPhone }
    /// Direction of messages this role receives.
    public var recvDirection: Direction { self == .phone ? .desktopToPhone : .phoneToDesktop }
}

/// Direction of travel; its raw value is the first AEAD nonce byte.
public enum Direction: UInt8, Sendable, Hashable {
    case phoneToDesktop = 0x01
    case desktopToPhone = 0x02
}

/// A long-term X25519 identity key pair.
public struct IdentityKeyPair: Sendable, CustomStringConvertible {
    let privateKey: Curve25519.KeyAgreement.PrivateKey

    /// Generate a new key pair from the system CSPRNG.
    public static func generate() -> IdentityKeyPair {
        IdentityKeyPair(privateKey: Curve25519.KeyAgreement.PrivateKey())
    }

    /// Wrap an existing CryptoKit private key (e.g. loaded from the Keychain).
    public init(privateKey: Curve25519.KeyAgreement.PrivateKey) {
        self.privateKey = privateKey
    }

    /// Restore from the raw 32-byte private key (RFC 7748 scalar, clamped on
    /// use). `nil` unless exactly 32 bytes.
    public init?(secretBytes: some ContiguousBytes) {
        let count = secretBytes.withUnsafeBytes { $0.count }
        guard count == 32,
              let k = try? Curve25519.KeyAgreement.PrivateKey(rawRepresentation: secretBytes)
        else { return nil }
        privateKey = k
    }

    /// The raw 32-byte private key, for persistent (Keychain) storage.
    public var secretBytes: Data { privateKey.rawRepresentation }

    /// The 32-byte public key (`hello.pub`).
    public var publicBytes: Bytes32 { Bytes32(privateKey.publicKey.rawRepresentation)! }

    /// `ss = X25519(own_priv, peer_pub)`. Fails with `non_contributory` when the
    /// result is all zeros (low-order peer key).
    ///
    /// CryptoKit itself throws for such points (CoreCrypto error -7) instead of
    /// returning zeros; both outcomes map to `non_contributory`.
    public func sharedSecret(peerPublic: Bytes32) throws(VQError) -> SharedSecret {
        guard let pub = try? Curve25519.KeyAgreement.PublicKey(rawRepresentation: peerPublic.bytes),
              let ss = try? privateKey.sharedSecretFromKeyAgreement(with: pub)
        else { throw .nonContributory }
        let key = ss.withUnsafeBytes { raw -> SymmetricKey? in
            raw.allSatisfy { $0 == 0 } ? nil : SymmetricKey(data: raw)
        }
        guard let key else { throw .nonContributory }
        return SharedSecret(key: key)
    }

    public var description: String { "IdentityKeyPair(public: \(publicBytes.base64))" }
}

/// The X25519 shared secret between two identities. Opaque.
public struct SharedSecret: Sendable, CustomStringConvertible {
    let key: SymmetricKey

    init(key: SymmetricKey) { self.key = key }

    /// Raw bytes in (test vectors only).
    init(bytesForTests bytes: [UInt8]) { key = SymmetricKey(data: bytes) }

    /// Raw bytes out (test vectors only).
    var bytesForTests: [UInt8] { key.withUnsafeBytes { Array($0) } }

    public var description: String { "SharedSecret(..)" }
}

/// New random install identifier (UUID v4).
public func newDeviceId() -> UUID { UUID() }

/// This side's `hello.session_nonce` for one connection.
///
/// It can only be created from the system CSPRNG (``generate()``, usually via
/// ``Hello/new(deviceId:name:publicKey:paired:)``). It is non-copyable and
/// ``SessionCipher/establish(identity:role:peerPublic:ownNonce:peerNonce:)``
/// consumes it, so one nonce keys at most one session.
public struct SessionNonce: ~Copyable, Sendable {
    /// The public nonce bytes (what goes into `hello.session_nonce`).
    public let bytes: Bytes32

    /// A fresh nonce from the system CSPRNG.
    public static func generate() -> SessionNonce { SessionNonce(bytes: .random()) }

    private init(bytes: Bytes32) { self.bytes = bytes }

    /// Fixed nonce (test vectors only).
    init(bytesForTests bytes: Bytes32) { self.bytes = bytes }
}

/// A 6-digit pairing code, 000000–999999 (README §6.2).
public struct PairingCode: Hashable, Sendable, CustomStringConvertible {
    /// Numeric value, 0…999,999.
    public let value: UInt32

    /// Uniformly random code from the system CSPRNG.
    public static func generate() -> PairingCode {
        var rng = SystemRandomNumberGenerator()
        return generate(using: &rng)
    }

    /// Uniformly random code; `random(in:)` samples without modulo bias.
    public static func generate(using rng: inout some RandomNumberGenerator) -> PairingCode {
        PairingCode(unchecked: UInt32.random(in: 0..<1_000_000, using: &rng))
    }

    /// From a number; `nil` if ≥ 1,000,000.
    public init?(value: UInt32) {
        guard value < 1_000_000 else { return nil }
        self.value = value
    }

    private init(unchecked value: UInt32) { self.value = value }

    /// Parse exactly 6 ASCII digits (no spaces, signs or non-ASCII digits).
    public init(parsing s: String) throws(VQError) {
        let b = Array(s.utf8)
        guard b.count == 6, b.allSatisfy({ $0 >= 0x30 && $0 <= 0x39 }) else { throw .invalidCode }
        value = b.reduce(0) { $0 * 10 + UInt32($1 - 0x30) }
    }

    /// The 6 ASCII digits, zero-padded (e.g. `"004217"`).
    public var ascii: [UInt8] {
        var out = [UInt8](repeating: 0x30, count: 6)
        var n = value
        for i in stride(from: 5, through: 0, by: -1) {
            out[i] = 0x30 + UInt8(n % 10)
            n /= 10
        }
        return out
    }

    /// The zero-padded 6-digit string.
    public var string: String { String(decoding: ascii, as: UTF8.self) }

    /// Redacted, so codes do not end up in logs.
    public var description: String { "PairingCode(******)" }
}

/// HKDF info for `K_pair`: `"vq/pair/v1" ‖ code digits` (16 bytes).
func pairInfo(_ code: PairingCode) -> [UInt8] { pairInfoPrefix + code.ascii }

/// RFC 5869 HKDF-SHA256 with `salt = saltA ‖ saltB` and L = 32.
func hkdf32(_ ikm: SymmetricKey, _ saltA: Bytes32, _ saltB: Bytes32, _ info: [UInt8]) -> SymmetricKey {
    HKDF<SHA256>.deriveKey(inputKeyMaterial: ikm, salt: saltA.bytes + saltB.bytes, info: info, outputByteCount: 32)
}

func macBytes(_ key: SymmetricKey, _ label: [UInt8], _ a: Bytes32, _ b: Bytes32) -> Bytes32 {
    var h = HMAC<SHA256>(key: key)
    h.update(data: label)
    h.update(data: a.bytes)
    h.update(data: b.bytes)
    return Bytes32(Array(h.finalize()))!
}

/// Constant-time MAC check (CryptoKit's `isValidAuthenticationCode`).
func macVerify(_ key: SymmetricKey, _ label: [UInt8], _ a: Bytes32, _ b: Bytes32, _ mac: Bytes32) throws(VQError) {
    let ok = HMAC<SHA256>.isValidAuthenticationCode(mac.bytes, authenticating: label + a.bytes + b.bytes, using: key)
    if !ok { throw .badMac }
}

/// `K_sess` for a shared secret and the two session nonces (phone's first).
func sessionKey(_ ss: SharedSecret, noncePhone: Bytes32, nonceDesktop: Bytes32) -> SymmetricKey {
    hkdf32(ss.key, noncePhone, nonceDesktop, sessionInfo)
}

/// The pairing key `K_pair` together with the transcript it was derived for.
/// Opaque: the key never leaves this type.
///
/// Both sides call ``derive(identity:ownRole:peerPublic:request:challenge:code:)``
/// with their **own** role; the type works out which public key is the
/// phone's and takes the nonces from the typed messages, so arguments cannot
/// be swapped by mistake.
public struct PairKey: Sendable, CustomStringConvertible {
    let key: SymmetricKey
    let pubPhone: Bytes32
    let pubDesktop: Bytes32

    /// `K_pair = HKDF-SHA256(ss, nonce_p ‖ nonce_d, "vq/pair/v1" ‖ C)`.
    /// Fails with `non_contributory` for a low-order peer key.
    public static func derive(identity: IdentityKeyPair, ownRole: Role, peerPublic: Bytes32,
                              request: PairRequest, challenge: PairChallenge,
                              code: PairingCode) throws(VQError) -> PairKey {
        let ss = try identity.sharedSecret(peerPublic: peerPublic)
        let own = identity.publicBytes
        let (pp, pd) = ownRole == .phone ? (own, peerPublic) : (peerPublic, own)
        return PairKey(key: hkdf32(ss.key, request.nonceP, challenge.nonceD, pairInfo(code)),
                       pubPhone: pp, pubDesktop: pd)
    }

    /// `mac_p = HMAC-SHA256(K_pair, "phone" ‖ pub_p ‖ pub_d)`.
    public var phoneMac: Bytes32 { macBytes(key, phoneMacLabel, pubPhone, pubDesktop) }

    /// `mac_d = HMAC-SHA256(K_pair, "desktop" ‖ pub_d ‖ pub_p)`.
    public var desktopMac: Bytes32 { macBytes(key, desktopMacLabel, pubDesktop, pubPhone) }

    /// The phone's `pair_confirm`.
    public func confirmMessage() -> PairConfirm { PairConfirm(mac: phoneMac) }

    /// The desktop's successful `pair_result`.
    public func successMessage() -> PairResult { .success(desktopMac) }

    /// Desktop side: constant-time check of `pair_confirm.mac`.
    public func verifyPhoneMac(_ mac: Bytes32) throws(VQError) {
        try macVerify(key, phoneMacLabel, pubPhone, pubDesktop, mac)
    }

    /// Phone side: constant-time check of `pair_result.mac`.
    public func verifyDesktopMac(_ mac: Bytes32) throws(VQError) {
        try macVerify(key, desktopMacLabel, pubDesktop, pubPhone, mac)
    }

    /// Raw key bytes (test vectors only).
    var keyBytesForTests: [UInt8] { key.withUnsafeBytes { Array($0) } }

    public var description: String { "PairKey(..)" }
}

// MARK: - Raw-bytes primitives: test vectors only (internal; `@testable import`)
//
// These take raw keys, so an argument-order mistake compiles. Production code
// uses `PairKey` and `SessionCipher.establish`.

/// `K_pair` as raw bytes (test vectors only).
func derivePairKeyForTests(_ ss: SharedSecret, nonceP: Bytes32, nonceD: Bytes32, code: PairingCode) -> [UInt8] {
    hkdf32(ss.key, nonceP, nonceD, pairInfo(code)).withUnsafeBytes { Array($0) }
}

/// `K_sess` as raw bytes (test vectors only).
func deriveSessionKeyForTests(_ ss: SharedSecret, noncePhone: Bytes32, nonceDesktop: Bytes32) -> [UInt8] {
    sessionKey(ss, noncePhone: noncePhone, nonceDesktop: nonceDesktop).withUnsafeBytes { Array($0) }
}

/// `mac_p` from a raw key (test vectors only).
func phoneConfirmMacForTests(kPair: [UInt8], pubPhone: Bytes32, pubDesktop: Bytes32) -> Bytes32 {
    macBytes(SymmetricKey(data: kPair), phoneMacLabel, pubPhone, pubDesktop)
}

/// `mac_d` from a raw key (test vectors only). Arguments are (phone, desktop).
func desktopResultMacForTests(kPair: [UInt8], pubPhone: Bytes32, pubDesktop: Bytes32) -> Bytes32 {
    macBytes(SymmetricKey(data: kPair), desktopMacLabel, pubDesktop, pubPhone)
}

/// Verify `mac_p` with a raw key (test vectors only).
func verifyPhoneConfirmMacForTests(kPair: [UInt8], pubPhone: Bytes32, pubDesktop: Bytes32,
                                   mac: Bytes32) throws(VQError) {
    try macVerify(SymmetricKey(data: kPair), phoneMacLabel, pubPhone, pubDesktop, mac)
}

/// Verify `mac_d` with a raw key (test vectors only). Arguments are (phone, desktop).
func verifyDesktopResultMacForTests(kPair: [UInt8], pubPhone: Bytes32, pubDesktop: Bytes32,
                                    mac: Bytes32) throws(VQError) {
    try macVerify(SymmetricKey(data: kPair), desktopMacLabel, pubDesktop, pubPhone, mac)
}
