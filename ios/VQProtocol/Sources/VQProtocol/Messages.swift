import Foundation

// MARK: - Message types (README §5)

/// Byte-exact string equality (Swift `String ==` uses canonical equivalence,
/// which is not what the wire compares).
@inline(__always)
func sameBytes(_ a: String, _ b: String) -> Bool { a.utf8.elementsEqual(b.utf8) }

/// `hello` (plaintext, both directions; README §5.2).
public struct Hello: Equatable, Sendable {
    /// Protocol version; always 1 for a decoded ``Message/hello(_:)``.
    /// Encoding any other value fails with `not_encodable`.
    public var v: UInt32
    /// Sender's random install id (UUID v4).
    public var deviceId: UUID
    /// Sender's display name, any UTF-8.
    public var name: String
    /// Sender's long-term X25519 public key (wire field `pub`).
    public var publicKey: Bytes32
    /// `true` iff the sender has a stored pairing for the receiver (README §7).
    public var paired: Bool
    /// Fresh 32-byte nonce for this connection (README §6.4).
    public var sessionNonce: Bytes32

    /// Memberwise initializer. Production code should use
    /// ``Hello/new(deviceId:name:publicKey:paired:)``, which draws the nonce.
    public init(v: UInt32 = VQ.protocolVersion, deviceId: UUID, name: String, publicKey: Bytes32,
                paired: Bool, sessionNonce: Bytes32) {
        self.v = v
        self.deviceId = deviceId
        self.name = name
        self.publicKey = publicKey
        self.paired = paired
        self.sessionNonce = sessionNonce
    }

    /// Our `hello` for a new connection, with a fresh CSPRNG `session_nonce`.
    ///
    /// Send `.hello`; keep `.nonce` for this connection only and pass it to
    /// ``SessionCipher/establish(identity:role:peerPublic:ownNonce:peerNonce:)``,
    /// which consumes it. ``SessionNonce`` is non-copyable.
    public static func new(deviceId: UUID, name: String, publicKey: Bytes32, paired: Bool) -> OwnHello {
        let nonce = SessionNonce.generate()
        let hello = Hello(deviceId: deviceId, name: name, publicKey: publicKey, paired: paired,
                          sessionNonce: nonce.bytes)
        return OwnHello(hello: hello, nonce: nonce)
    }

    public static func == (a: Hello, b: Hello) -> Bool {
        a.v == b.v && a.deviceId == b.deviceId && sameBytes(a.name, b.name) && a.publicKey == b.publicKey
            && a.paired == b.paired && a.sessionNonce == b.sessionNonce
    }
}

/// Our `hello` together with the non-copyable ``SessionNonce`` it carries.
///
/// Send ``hello``, then move the nonce out with ``takeNonce()`` (which
/// consumes this value) and keep it until the session is established.
public struct OwnHello: ~Copyable {
    /// The message to send.
    public let hello: Hello
    /// The nonce for ``SessionCipher/establish(identity:role:peerPublic:ownNonce:peerNonce:)``
    /// (borrow it to read ``SessionNonce/bytes``).
    public let nonce: SessionNonce

    /// Move the nonce out, consuming this value.
    public consuming func takeNonce() -> SessionNonce { nonce }
}

/// A `hello` carrying a `v` this implementation does not speak (receive-only).
public struct HelloUnsupported: Equatable, Sendable {
    /// The peer's protocol version.
    public var v: UInt64
    /// The peer's `name`, if it was present and a string.
    public var name: String?

    public init(v: UInt64, name: String?) {
        self.v = v
        self.name = name
    }

    public static func == (a: HelloUnsupported, b: HelloUnsupported) -> Bool {
        guard a.v == b.v else { return false }
        switch (a.name, b.name) {
        case (nil, nil): return true
        case let (x?, y?): return sameBytes(x, y)
        default: return false
        }
    }
}

/// `pair_request` (plaintext, phone → desktop; README §5.3).
public struct PairRequest: Equatable, Sendable {
    /// 32 random bytes chosen by the phone.
    public var nonceP: Bytes32
    public init(nonceP: Bytes32) { self.nonceP = nonceP }
    /// A request with a fresh CSPRNG `nonce_p`.
    public static func generate() -> PairRequest { PairRequest(nonceP: .random()) }
}

/// `pair_challenge` (plaintext, desktop → phone; README §5.4).
public struct PairChallenge: Equatable, Sendable {
    /// 32 random bytes chosen by the desktop.
    public var nonceD: Bytes32
    public init(nonceD: Bytes32) { self.nonceD = nonceD }
    /// A challenge with a fresh CSPRNG `nonce_d`.
    public static func generate() -> PairChallenge { PairChallenge(nonceD: .random()) }
}

/// `pair_confirm` (plaintext, phone → desktop; README §5.5).
public struct PairConfirm: Equatable, Sendable {
    /// `mac_p`.
    public var mac: Bytes32
    public init(mac: Bytes32) { self.mac = mac }
}

/// `pair_result` (plaintext, desktop → phone; README §5.6).
public struct PairResult: Equatable, Sendable {
    /// Whether the phone's MAC verified.
    public var ok: Bool
    /// `mac_d`; present iff `ok`.
    public var mac: Bytes32?
    public init(ok: Bool, mac: Bytes32?) {
        self.ok = ok
        self.mac = mac
    }
    /// Successful result carrying the desktop MAC.
    public static func success(_ mac: Bytes32) -> PairResult { PairResult(ok: true, mac: mac) }
    /// Failed result (no MAC).
    public static func failure() -> PairResult { PairResult(ok: false, mac: nil) }
}

/// `error` (plaintext, either direction; README §5.7).
///
/// When received in a plaintext envelope it is unauthenticated: it may end the
/// connection but MUST NOT change stored pairing state.
public struct ErrorMsg: Equatable, Sendable {
    /// Machine-readable code (open set).
    public var code: String
    /// Human-readable text; `""` when absent or `null`. Never build it from a
    /// local ``VQError``'s description.
    public var msg: String

    public init(code: String, msg: String = "") {
        self.code = code
        self.msg = msg
    }

    public static let unknownPeer = "unknown_peer"
    public static let badMac = "bad_mac"
    public static let decryptFailed = "decrypt_failed"
    public static let version = "version"
    public static let protocolViolation = "protocol"

    public static func == (a: ErrorMsg, b: ErrorMsg) -> Bool {
        sameBytes(a.code, b.code) && sameBytes(a.msg, b.msg)
    }
}

/// `utt.state`.
public enum UttState: String, Sendable, CaseIterable {
    case partial
    case final
    case edit
}

/// `utt` (encrypted, phone → desktop; README §5.8).
public struct Utt: Equatable, Sendable {
    public var id: UUID
    /// Revision (u32).
    public var rev: UInt32
    public var state: UttState
    /// Full current text; ≤ 32,000 UTF-8 bytes. Arbitrary Unicode including
    /// control characters: render inertly.
    public var text: String
    /// Start of the utterance, ms since the Unix epoch.
    public var ts: UInt64

    public init(id: UUID, rev: UInt32, state: UttState, text: String, ts: UInt64) {
        self.id = id
        self.rev = rev
        self.state = state
        self.text = text
        self.ts = ts
    }

    public static func == (a: Utt, b: Utt) -> Bool {
        a.id == b.id && a.rev == b.rev && a.state == b.state && sameBytes(a.text, b.text) && a.ts == b.ts
    }
}

/// `ack` (encrypted, desktop → phone; README §5.9).
public struct Ack: Equatable, Sendable {
    public var id: UUID
    public var rev: UInt32
    public init(id: UUID, rev: UInt32) {
        self.id = id
        self.rev = rev
    }
}

/// A decoded protocol message.
public enum Message: Equatable, Sendable {
    /// `hello` with `v == 1`.
    case hello(Hello)
    /// `hello` with an integer `v != 1` (receive-only).
    case helloUnsupported(HelloUnsupported)
    case pairRequest(PairRequest)
    case pairChallenge(PairChallenge)
    case pairConfirm(PairConfirm)
    case pairResult(PairResult)
    case error(ErrorMsg)
    case utt(Utt)
    case ack(Ack)
    case ping
    case pong
    /// Any other `t` (receive-only): log and drop.
    case unknown(t: String)

    public static func == (a: Message, b: Message) -> Bool {
        switch (a, b) {
        case let (.hello(x), .hello(y)): x == y
        case let (.helloUnsupported(x), .helloUnsupported(y)): x == y
        case let (.pairRequest(x), .pairRequest(y)): x == y
        case let (.pairChallenge(x), .pairChallenge(y)): x == y
        case let (.pairConfirm(x), .pairConfirm(y)): x == y
        case let (.pairResult(x), .pairResult(y)): x == y
        case let (.error(x), .error(y)): x == y
        case let (.utt(x), .utt(y)): x == y
        case let (.ack(x), .ack(y)): x == y
        case (.ping, .ping), (.pong, .pong): true
        case let (.unknown(x), .unknown(y)): sameBytes(x, y)
        default: false
        }
    }
}

/// Types allowed inside a plaintext envelope (README §4.3).
public let plaintextAllowedTypes: [String] = [
    "hello", "pair_request", "pair_challenge", "pair_confirm", "pair_result", "error",
]

/// Every `t` value v1 defines.
public let knownTypes: [String] = plaintextAllowedTypes + ["utt", "ack", "ping", "pong"]

private let plaintextAllowedBytes: [[UInt8]] = plaintextAllowedTypes.map { Array($0.utf8) }
private let knownTypeBytes: [[UInt8]] = knownTypes.map { Array($0.utf8) }

/// Whether `t` is one of the v1 message types (case-sensitive, byte-exact).
public func isKnownType(_ t: String) -> Bool { knownTypeBytes.contains(Array(t.utf8)) }

extension Message {
    /// The wire `t` value.
    public var typeName: String {
        switch self {
        case .hello, .helloUnsupported: "hello"
        case .pairRequest: "pair_request"
        case .pairChallenge: "pair_challenge"
        case .pairConfirm: "pair_confirm"
        case .pairResult: "pair_result"
        case .error: "error"
        case .utt: "utt"
        case .ack: "ack"
        case .ping: "ping"
        case .pong: "pong"
        case .unknown(let t): t
        }
    }

    /// Whether this message type may travel in a plaintext envelope.
    /// ``Message/unknown(t:)`` returns `false`.
    public var isPlaintextAllowed: Bool {
        if case .unknown = self { return false }
        return plaintextAllowedTypes.contains(typeName)
    }

    // MARK: Encoding

    /// Encode as compact UTF-8 JSON with `"t"` first (the canonical form the
    /// Rust encoder emits byte-for-byte).
    ///
    /// Fails, in order: `not_encodable` (receive-only variants, `hello.v ≠ 1`,
    /// `pair_result` with `ok` and `mac` inconsistent), `text_too_long`, then
    /// `message_too_large`.
    public func toJSON() throws(VQError) -> [UInt8] {
        var w = JSONWriter()
        switch self {
        case .hello(let m):
            guard m.v == VQ.protocolVersion else { throw .notEncodable("hello.v must be the protocol version") }
            w.begin("hello")
            w.key("v"); w.uint(UInt64(m.v))
            w.key("device_id"); w.string(UUIDText.format(m.deviceId))
            w.key("name"); w.string(m.name)
            w.key("pub"); w.string(m.publicKey.base64)
            w.key("paired"); w.bool(m.paired)
            w.key("session_nonce"); w.string(m.sessionNonce.base64)
        case .pairRequest(let m):
            w.begin("pair_request")
            w.key("nonce_p"); w.string(m.nonceP.base64)
        case .pairChallenge(let m):
            w.begin("pair_challenge")
            w.key("nonce_d"); w.string(m.nonceD.base64)
        case .pairConfirm(let m):
            w.begin("pair_confirm")
            w.key("mac"); w.string(m.mac.base64)
        case .pairResult(let m):
            guard m.ok == (m.mac != nil) else {
                throw .notEncodable("pair_result must carry a mac iff ok is true")
            }
            w.begin("pair_result")
            w.key("ok"); w.bool(m.ok)
            if let mac = m.mac {
                w.key("mac"); w.string(mac.base64)
            }
        case .error(let m):
            w.begin("error")
            w.key("code"); w.string(m.code)
            w.key("msg"); w.string(m.msg)
        case .utt(let m):
            try checkText(m.text)
            w.begin("utt")
            w.key("id"); w.string(UUIDText.format(m.id))
            w.key("rev"); w.uint(UInt64(m.rev))
            w.key("state"); w.string(m.state.rawValue)
            w.key("text"); w.string(m.text)
            w.key("ts"); w.uint(m.ts)
        case .ack(let m):
            w.begin("ack")
            w.key("id"); w.string(UUIDText.format(m.id))
            w.key("rev"); w.uint(UInt64(m.rev))
        case .ping:
            w.begin("ping")
        case .pong:
            w.begin("pong")
        case .helloUnsupported:
            throw .notEncodable("HelloUnsupported is receive-only")
        case .unknown:
            throw .notEncodable("Unknown is receive-only")
        }
        w.end()
        guard w.out.count <= VQ.maxMessageBytes else { throw .messageTooLarge(w.out.count) }
        return w.out
    }

    // MARK: Decoding

    /// Decode a JSON message body (no provenance; on a connection use
    /// ``decodeInbound(_:session:)``).
    ///
    /// Error precedence (README §9.1): `message_too_large`, `invalid_json`
    /// (whole document), `invalid_message` (shape and `t`), field errors
    /// (`invalid_message`), then `text_too_long`.
    public static func fromJSON(_ bytes: [UInt8]) throws(VQError) -> Message {
        try decode(bytes, policy: { _ throws(VQError) in })
    }

    /// ``fromJSON(_:)`` with a `t` policy check that runs after `t` is read
    /// and before any other field is validated.
    static func decode(_ bytes: [UInt8], policy: ([UInt8]) throws(VQError) -> Void) throws(VQError) -> Message {
        guard bytes.count <= VQ.maxMessageBytes else { throw .messageTooLarge(bytes.count) }
        let members: [(key: [UInt8], value: StrictJSON.Scalar)]
        switch try StrictJSON.parse(bytes) {
        case .object(let m): members = m
        case .notObject: throw .invalidMessage("message is not a JSON object")
        }
        let f = Fields(members: members)
        let t: [UInt8]
        switch f.get("t") {
        case .str(let s)?: t = s
        case nil: throw .invalidMessage("missing `t`")
        default: throw .invalidMessage("`t` is not a string")
        }
        try policy(t)
        switch String(decoding: t, as: UTF8.self) {
        case _ where !knownTypeBytes.contains(t):
            return .unknown(t: String(decoding: t, as: UTF8.self))
        case "hello":
            return try decodeHello(f)
        case "pair_request":
            return .pairRequest(PairRequest(nonceP: try f.b64("nonce_p")))
        case "pair_challenge":
            return .pairChallenge(PairChallenge(nonceD: try f.b64("nonce_d")))
        case "pair_confirm":
            return .pairConfirm(PairConfirm(mac: try f.b64("mac")))
        case "pair_result":
            // With ok false, `mac` is ignored entirely, whatever its type or content.
            if try f.bool("ok") {
                guard let mac = try f.optB64("mac") else {
                    throw .invalidMessage("pair_result: ok is true but mac is missing")
                }
                return .pairResult(.success(mac))
            }
            return .pairResult(.failure())
        case "error":
            return .error(ErrorMsg(code: try f.string("code"), msg: try f.optString("msg") ?? ""))
        case "utt":
            let u = Utt(
                id: try f.uuid("id"),
                rev: UInt32(try f.uint("rev", max: UInt64(UInt32.max))),
                state: try f.state("state"),
                text: try f.string("text"),
                ts: try f.uint("ts", max: UInt64.max))
            try checkText(u.text)
            return .utt(u)
        case "ack":
            return .ack(Ack(id: try f.uuid("id"), rev: UInt32(try f.uint("rev", max: UInt64(UInt32.max)))))
        case "ping":
            return .ping
        case "pong":
            return .pong
        default:
            return .unknown(t: String(decoding: t, as: UTF8.self))
        }
    }

    private static func decodeHello(_ f: Fields) throws(VQError) -> Message {
        let v = try f.uint("v", max: UInt64.max)
        if v != UInt64(VQ.protocolVersion) {
            var name: String?
            if case .str(let s)? = f.get("name") { name = String(decoding: s, as: UTF8.self) }
            return .helloUnsupported(HelloUnsupported(v: v, name: name))
        }
        return .hello(Hello(
            v: VQ.protocolVersion,
            deviceId: try f.uuid("device_id"),
            name: try f.string("name"),
            publicKey: try f.b64("pub"),
            paired: try f.bool("paired"),
            sessionNonce: try f.b64("session_nonce")))
    }
}

func checkText(_ text: String) throws(VQError) {
    let n = text.utf8.count
    if n > VQ.maxTextBytes { throw .textTooLong(n) }
}

/// Typed access to the members of a validated top-level object.
private struct Fields {
    let members: [(key: [UInt8], value: StrictJSON.Scalar)]

    func get(_ k: String) -> StrictJSON.Scalar? {
        let kb = Array(k.utf8)
        return members.first(where: { $0.key == kb })?.value
    }

    func invalid(_ k: String, _ what: String) -> VQError { .invalidMessage("`\(k)` \(what)") }

    /// Required: absent is an error; `null` counts as present with the wrong type.
    func req(_ k: String) throws(VQError) -> StrictJSON.Scalar {
        guard let v = get(k) else { throw invalid(k, "is missing") }
        return v
    }

    /// Optional: absent and `null` are both `nil`.
    func opt(_ k: String) -> StrictJSON.Scalar? {
        switch get(k) {
        case nil, .null?: nil
        case let v: v
        }
    }

    func string(_ k: String) throws(VQError) -> String {
        guard case .str(let s) = try req(k) else { throw invalid(k, "must be a string") }
        return String(decoding: s, as: UTF8.self)
    }

    func optString(_ k: String) throws(VQError) -> String? {
        switch opt(k) {
        case nil: return nil
        case .str(let s)?: return String(decoding: s, as: UTF8.self)
        default: throw invalid(k, "must be a string")
        }
    }

    func bool(_ k: String) throws(VQError) -> Bool {
        guard case .bool(let b) = try req(k) else { throw invalid(k, "must be a boolean") }
        return b
    }

    /// A plain JSON integer literal (no sign, fraction or exponent) ≤ `max`,
    /// parsed exactly (never through `Double`).
    func uint(_ k: String, max: UInt64) throws(VQError) -> UInt64 {
        guard case .num(let raw) = try req(k) else { throw invalid(k, "must be an integer") }
        guard let v = parseUInt(raw, max: max) else {
            throw invalid(k, "must be a non-negative integer in range")
        }
        return v
    }

    func b64(_ k: String) throws(VQError) -> Bytes32 {
        guard case .str(let s) = try req(k) else { throw invalid(k, "must be a base64 string") }
        guard let v = Base64.decode32(String(decoding: s, as: UTF8.self)) else {
            throw invalid(k, "is not canonical base64 of 32 bytes")
        }
        return v
    }

    func optB64(_ k: String) throws(VQError) -> Bytes32? {
        switch opt(k) {
        case nil: return nil
        case .str(let s)?:
            guard let v = Base64.decode32(String(decoding: s, as: UTF8.self)) else {
                throw invalid(k, "is not canonical base64 of 32 bytes")
            }
            return v
        default: throw invalid(k, "must be a base64 string")
        }
    }

    func uuid(_ k: String) throws(VQError) -> UUID {
        guard case .str(let s) = try req(k) else { throw invalid(k, "must be a UUID string") }
        let str = String(decoding: s, as: UTF8.self)
        guard let u = UUIDText.parse(str) else {
            throw invalid(k, "expected a hyphenated UUID, got \(excerpt(str))")
        }
        return u
    }

    func state(_ k: String) throws(VQError) -> UttState {
        guard case .str(let s) = try req(k) else { throw invalid(k, "must be a string") }
        for st in UttState.allCases where Array(st.rawValue.utf8) == s { return st }
        throw invalid(k, "must be \"partial\", \"final\" or \"edit\"")
    }
}

/// `raw` is a grammar-checked JSON number token.
func parseUInt(_ raw: String, max: UInt64) -> UInt64? {
    let b = Array(raw.utf8)
    guard !b.isEmpty, b.allSatisfy({ $0 >= 0x30 && $0 <= 0x39 }) else { return nil }
    var acc: UInt64 = 0
    for d in b {
        let (m, o1) = acc.multipliedReportingOverflow(by: 10)
        let (s, o2) = m.addingReportingOverflow(UInt64(d - 0x30))
        if o1 || o2 { return nil }
        acc = s
    }
    return acc <= max ? acc : nil
}

// MARK: - Canonical writer

/// Compact JSON writer emitting the canonical form of README §5.1: `"t"`
/// first, UTF-8 unescaped, and only the escapes JSON requires (`"`, `\`, the
/// short forms `\b \t \n \f \r`, and `\u00xx` with lowercase hex for other
/// U+0000–U+001F). It never escapes `/`, U+007F or non-ASCII, matching
/// ``escapedLength(_:)``.
struct JSONWriter {
    var out: [UInt8] = []

    mutating func begin(_ t: String) {
        out.append(UInt8(ascii: "{"))
        out.append(contentsOf: Array("\"t\":".utf8))
        string(t)
    }

    mutating func end() { out.append(UInt8(ascii: "}")) }

    mutating func key(_ k: String) {
        out.append(UInt8(ascii: ","))
        string(k)
        out.append(UInt8(ascii: ":"))
    }

    mutating func uint(_ v: UInt64) { out.append(contentsOf: Array(String(v).utf8)) }

    mutating func bool(_ v: Bool) { out.append(contentsOf: Array((v ? "true" : "false").utf8)) }

    mutating func string(_ s: String) {
        let hex = Array("0123456789abcdef".utf8)
        out.append(0x22)
        for c in s.utf8 {
            switch c {
            case 0x22: out.append(contentsOf: [0x5C, 0x22])
            case 0x5C: out.append(contentsOf: [0x5C, 0x5C])
            case 0x08: out.append(contentsOf: [0x5C, UInt8(ascii: "b")])
            case 0x09: out.append(contentsOf: [0x5C, UInt8(ascii: "t")])
            case 0x0A: out.append(contentsOf: [0x5C, UInt8(ascii: "n")])
            case 0x0C: out.append(contentsOf: [0x5C, UInt8(ascii: "f")])
            case 0x0D: out.append(contentsOf: [0x5C, UInt8(ascii: "r")])
            case 0x00...0x1F:
                out.append(contentsOf: Array("\\u00".utf8))
                out.append(hex[Int(c >> 4)])
                out.append(hex[Int(c & 0x0F)])
            default: out.append(c)
            }
        }
        out.append(0x22)
    }
}

// MARK: - Utterance sizing (README §5.8)

/// Bytes `text` occupies inside a JSON string with minimal escaping: `"` and
/// `\` and U+0008/9/A/C/D → 2; other U+0000–U+001F → 6; else UTF-8 length.
public func escapedLength(_ text: String) -> Int {
    text.unicodeScalars.reduce(0) { $0 + escapedScalarLength($1) }
}

private func escapedScalarLength(_ c: Unicode.Scalar) -> Int {
    switch c.value {
    case 0x22, 0x5C, 0x08, 0x09, 0x0A, 0x0C, 0x0D: 2
    case 0x00...0x1F: 6
    default: UTF8.width(c)
    }
}

/// Whether an utterance with this `text` can always be sent: at most 32,000
/// UTF-8 bytes **and** `126 + escapedLength(text) ≤ 65,511` (README §5.8).
public func uttTextFits(_ text: String) -> Bool {
    text.utf8.count <= VQ.maxTextBytes
        && VQ.uttMaxOverheadBytes + escapedLength(text) <= VQ.maxEncryptedJSONBytes
}

/// The longest prefix of `text`, cut at a Unicode scalar boundary, for which
/// ``uttTextFits(_:)`` holds. The phone sends it as the `final` and ends the
/// utterance when the recognized text grows past it.
public func maxTextPrefix(_ text: String) -> String {
    let budget = VQ.maxEncryptedJSONBytes - VQ.uttMaxOverheadBytes
    var raw = 0
    var esc = 0
    var count = 0
    for c in text.unicodeScalars {
        raw += UTF8.width(c)
        esc += escapedScalarLength(c)
        if raw > VQ.maxTextBytes || esc > budget {
            return String(String.UnicodeScalarView(text.unicodeScalars.prefix(count)))
        }
        count += 1
    }
    return text
}
