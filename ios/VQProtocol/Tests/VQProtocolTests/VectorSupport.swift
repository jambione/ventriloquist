import Foundation
import Testing
@testable import VQProtocol

// Loading and reading protocol/vectors/*.json.
//
// The vector files are read with a small JSON tree parser of our own (not
// JSONSerialization), so that numbers keep their exact source text (u64
// values such as 18446744073709551615 must not pass through Double) and
// strings compare by their UTF-8 bytes. It is independent of the library's
// strict reader under test.

/// A JSON value from a vector file.
indirect enum JV: CustomStringConvertible {
    case null
    case bool(Bool)
    case num(String)
    case str(String)
    case arr([JV])
    case obj([(String, JV)])

    subscript(_ k: String) -> JV {
        if case .obj(let m) = self, let v = m.first(where: { sameBytes($0.0, k) })?.1 { return v }
        return .null
    }

    func has(_ k: String) -> Bool {
        if case .obj(let m) = self { return m.contains { sameBytes($0.0, k) } }
        return false
    }

    var isNull: Bool { if case .null = self { true } else { false } }

    var str: String {
        guard case .str(let s) = self else { fatalError("not a string: \(self)") }
        return s
    }

    var strOrNil: String? { if case .str(let s) = self { s } else { nil } }

    var bool: Bool {
        guard case .bool(let b) = self else { fatalError("not a bool: \(self)") }
        return b
    }

    var array: [JV] {
        guard case .arr(let a) = self else { fatalError("not an array: \(self)") }
        return a
    }

    var keys: [String] {
        guard case .obj(let m) = self else { return [] }
        return m.map(\.0)
    }

    /// An unsigned JSON number, parsed exactly.
    var u64: UInt64 {
        guard case .num(let raw) = self, let v = UInt64(raw) else { fatalError("not a u64 number: \(self)") }
        return v
    }

    var int: Int { Int(exactly: u64)! }

    /// A u64 encoded as a decimal string (README §10.1).
    var u64s: UInt64 { UInt64(str)! }

    var description: String { String(decoding: serialized(), as: UTF8.self) }

    /// Compact JSON serialization (used to feed `expected` back into the decoder).
    func serialized() -> [UInt8] {
        var w = JSONWriter()
        write(into: &w)
        return w.out
    }

    private func write(into w: inout JSONWriter) {
        switch self {
        case .null: w.out += Array("null".utf8)
        case .bool(let b): w.bool(b)
        case .num(let raw): w.out += Array(raw.utf8)
        case .str(let s): w.string(s)
        case .arr(let a):
            w.out.append(UInt8(ascii: "["))
            for (i, v) in a.enumerated() {
                if i > 0 { w.out.append(UInt8(ascii: ",")) }
                v.write(into: &w)
            }
            w.out.append(UInt8(ascii: "]"))
        case .obj(let m):
            w.out.append(UInt8(ascii: "{"))
            for (i, (k, v)) in m.enumerated() {
                if i > 0 { w.out.append(UInt8(ascii: ",")) }
                w.string(k)
                w.out.append(UInt8(ascii: ":"))
                v.write(into: &w)
            }
            w.out.append(UInt8(ascii: "}"))
        }
    }

    /// Structural equality: objects compare as unordered maps, strings by
    /// UTF-8 bytes, numbers by their exact text.
    static func same(_ a: JV, _ b: JV) -> Bool {
        switch (a, b) {
        case (.null, .null): return true
        case let (.bool(x), .bool(y)): return x == y
        case let (.num(x), .num(y)): return x == y
        case let (.str(x), .str(y)): return x.utf8.elementsEqual(y.utf8)
        case let (.arr(x), .arr(y)): return x.count == y.count && zip(x, y).allSatisfy { same($0, $1) }
        case let (.obj(x), .obj(y)):
            guard x.count == y.count else { return false }
            return x.allSatisfy { kv in y.contains { $0.0.utf8.elementsEqual(kv.0.utf8) && same($0.1, kv.1) } }
        default: return false
        }
    }

    /// Parse JSON text (vector files and encoder output). Not strict; it is a
    /// test utility, not the implementation under test.
    static func parse(_ bytes: [UInt8]) -> JV {
        var p = TreeParser(b: bytes)
        p.ws()
        let v = p.value()
        p.ws()
        precondition(p.i == bytes.count, "trailing bytes in JSON")
        return v
    }

    /// The same object without member `k`.
    func removing(_ k: String) -> JV {
        guard case .obj(let m) = self else { return self }
        return .obj(m.filter { $0.0 != k })
    }
}

private struct TreeParser {
    let b: [UInt8]
    var i = 0

    mutating func ws() {
        while i < b.count, [0x20, 0x09, 0x0A, 0x0D].contains(b[i]) { i += 1 }
    }

    mutating func value() -> JV {
        switch b[i] {
        case UInt8(ascii: "{"):
            i += 1
            var m: [(String, JV)] = []
            ws()
            if b[i] == UInt8(ascii: "}") { i += 1; return .obj(m) }
            while true {
                ws()
                let k = string()
                ws(); precondition(b[i] == UInt8(ascii: ":")); i += 1; ws()
                m.append((k, value()))
                ws()
                if b[i] == UInt8(ascii: ",") { i += 1; continue }
                precondition(b[i] == UInt8(ascii: "}")); i += 1
                return .obj(m)
            }
        case UInt8(ascii: "["):
            i += 1
            var a: [JV] = []
            ws()
            if b[i] == UInt8(ascii: "]") { i += 1; return .arr(a) }
            while true {
                ws()
                a.append(value())
                ws()
                if b[i] == UInt8(ascii: ",") { i += 1; continue }
                precondition(b[i] == UInt8(ascii: "]")); i += 1
                return .arr(a)
            }
        case UInt8(ascii: "\""):
            return .str(string())
        case UInt8(ascii: "t"): i += 4; return .bool(true)
        case UInt8(ascii: "f"): i += 5; return .bool(false)
        case UInt8(ascii: "n"): i += 4; return .null
        default:
            let s = i
            while i < b.count, "-+.eE0123456789".utf8.contains(b[i]) { i += 1 }
            return .num(String(decoding: b[s..<i], as: UTF8.self))
        }
    }

    mutating func hex4() -> UInt32 {
        let v = UInt32(String(decoding: b[i..<(i + 4)], as: UTF8.self), radix: 16)!
        i += 4
        return v
    }

    mutating func string() -> String {
        precondition(b[i] == UInt8(ascii: "\""))
        i += 1
        var out: [UInt8] = []
        while b[i] != UInt8(ascii: "\"") {
            if b[i] == UInt8(ascii: "\\") {
                i += 1
                let e = b[i]
                i += 1
                switch e {
                case UInt8(ascii: "n"): out.append(0x0A)
                case UInt8(ascii: "t"): out.append(0x09)
                case UInt8(ascii: "r"): out.append(0x0D)
                case UInt8(ascii: "b"): out.append(0x08)
                case UInt8(ascii: "f"): out.append(0x0C)
                case UInt8(ascii: "u"):
                    var cp = hex4()
                    if (0xD800...0xDBFF).contains(cp) {
                        precondition(b[i] == UInt8(ascii: "\\") && b[i + 1] == UInt8(ascii: "u"))
                        i += 2
                        let lo = hex4()
                        cp = 0x10000 + ((cp - 0xD800) << 10) + (lo - 0xDC00)
                    }
                    out += Array(String(Character(Unicode.Scalar(cp)!)).utf8)
                default: out.append(e)
                }
            } else {
                out.append(b[i])
                i += 1
            }
        }
        i += 1
        return String(decoding: out, as: UTF8.self)
    }
}

// MARK: - Vector files

/// `protocol/vectors`, resolved from this source file's location.
let vectorsDir: URL = URL(fileURLWithPath: #filePath)
    .deletingLastPathComponent() // VQProtocolTests
    .deletingLastPathComponent() // Tests
    .deletingLastPathComponent() // VQProtocol
    .deletingLastPathComponent() // ios
    .deletingLastPathComponent() // repo root
    .appendingPathComponent("protocol/vectors")

/// Every vector file and the sections (top-level members other than
/// `description` and `vectors_version`) that the tests check. The coverage
/// test fails if a file or section exists that is not listed here, and
/// ``cases(_:_:)`` fails if a test reads a section that is not listed.
let coveredSections: [String: Set<String>] = [
    "framing.json": ["split", "split_large", "split_errors", "reassembly"],
    "envelope.json": ["plaintext", "encrypt", "open_errors", "decode", "in_session", "stack"],
    "replay.json": ["sequences", "send_sequences"],
    "crypto.json": [
        "x25519", "x25519_errors", "x25519_high_bit", "pair_key", "session_key", "pair_mac",
        "pair_mac_verify", "code_format", "code_parse", "full_pairing",
    ],
    "messages.json": ["decode", "encode", "encode_errors", "utt_max_overhead_bytes", "utt_fits"],
]

func loadVectors(_ file: String) throws -> JV {
    let data = try Data(contentsOf: vectorsDir.appendingPathComponent(file))
    let v = JV.parse(Array(data))
    #expect(v["vectors_version"].u64 == 1, "\(file)")
    return v
}

/// The cases of `section` in `file`: non-empty, and declared in ``coveredSections``.
func cases(_ v: JV, _ file: String, _ section: String) -> [JV] {
    #expect(coveredSections[file]?.contains(section) == true, "\(file): \(section) is not declared as covered")
    let a = v[section].array
    #expect(!a.isEmpty, "\(file): empty section \(section)")
    return a
}

// MARK: - Value helpers (README §10.1)

func hexBytes(_ s: String) -> [UInt8] {
    let c = Array(s.utf8)
    precondition(c.count % 2 == 0, "odd hex length")
    func nib(_ x: UInt8) -> UInt8 {
        switch x {
        case 0x30...0x39: x - 0x30
        case 0x61...0x66: x - 0x61 + 10
        case 0x41...0x46: x - 0x41 + 10
        default: fatalError("bad hex digit")
        }
    }
    return stride(from: 0, to: c.count, by: 2).map { nib(c[$0]) << 4 | nib(c[$0 + 1]) }
}

func hexString(_ b: some Sequence<UInt8>) -> String {
    let d = Array("0123456789abcdef".utf8)
    var out: [UInt8] = []
    for x in b { out.append(d[Int(x >> 4)]); out.append(d[Int(x & 15)]) }
    return String(decoding: out, as: UTF8.self)
}

/// A "bytes" value: a hex string or `{prefix_hex?, fill_hex, fill_count, suffix_hex?}`.
func bytes(_ v: JV) -> [UInt8] {
    switch v {
    case .str(let s): return hexBytes(s)
    case .obj:
        let fill = hexBytes(v["fill_hex"].str)
        precondition(fill.count == 1)
        var out = v.has("prefix_hex") ? hexBytes(v["prefix_hex"].str) : []
        out += [UInt8](repeating: fill[0], count: v["fill_count"].int)
        if v.has("suffix_hex") { out += hexBytes(v["suffix_hex"].str) }
        return out
    default: fatalError("bad bytes value \(v)")
    }
}

func b32(_ v: JV) -> Bytes32 { Bytes32(bytes(v))! }

func role(_ v: JV) -> Role {
    switch v.str {
    case "phone": .phone
    case "desktop": .desktop
    default: fatalError("role \(v)")
    }
}

func direction(_ v: JV) -> Direction {
    switch v.str {
    case "phone_to_desktop": .phoneToDesktop
    case "desktop_to_phone": .desktopToPhone
    default: fatalError("direction \(v)")
    }
}

/// `nil` for JSON null, else a u64 decimal string.
func optU64s(_ v: JV) -> UInt64? { v.isNull ? nil : v.u64s }

/// Run `body`, returning its typed error code or the value.
func result<T>(_ body: () throws(VQError) -> T) -> Result<T, VQError> {
    do { return .success(try body()) } catch { return .failure(error) }
}

extension Result where Failure == VQError {
    var errorCode: String? { if case .failure(let e) = self { e.code } else { nil } }
    var value: Success? { if case .success(let v) = self { v } else { nil } }
}

/// String equality as UTF-8 bytes (Q21), never Swift's canonical-equivalence
/// `String ==`, so a precomposed/decomposed or KELVIN SIGN mismatch fails.
func sameBytes(_ a: String?, _ b: String?) -> Bool {
    switch (a, b) {
    case (nil, nil): true
    case (let x?, let y?): x.utf8.elementsEqual(y.utf8)
    default: false
    }
}
