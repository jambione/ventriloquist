import Foundation

/// Exactly 32 bytes: X25519 public keys, nonces and MACs.
public struct Bytes32: Hashable, Sendable, CustomStringConvertible {
    /// The 32 bytes.
    public let bytes: [UInt8]

    /// `nil` unless `bytes` has exactly 32 elements.
    public init?(_ bytes: some Collection<UInt8>) {
        guard bytes.count == 32 else { return nil }
        self.bytes = Array(bytes)
    }

    /// 32 copies of `byte` (tests and placeholders).
    public init(repeating byte: UInt8) {
        bytes = [UInt8](repeating: byte, count: 32)
    }

    /// 32 bytes from the system CSPRNG.
    static func random() -> Bytes32 {
        var rng = SystemRandomNumberGenerator()
        var out = [UInt8](repeating: 0, count: 32)
        for i in 0..<32 { out[i] = rng.next() }
        return Bytes32(out)!
    }

    /// Standard padded base64 (44 characters).
    public var base64: String { Base64.encode(bytes) }

    public var description: String { "Bytes32(\(base64))" }
}

/// RFC 4648 §4 standard base64 with `=` padding; strict decoding (README §1).
public enum Base64 {
    private static let alphabet = Array("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/".utf8)

    private static let reverse: [Int8] = {
        var t = [Int8](repeating: -1, count: 256)
        for (i, c) in alphabet.enumerated() { t[Int(c)] = Int8(i) }
        return t
    }()

    /// Encode with the standard alphabet and `=` padding.
    public static func encode(_ bytes: some Collection<UInt8>) -> String {
        let b = Array(bytes)
        var out = [UInt8]()
        out.reserveCapacity((b.count + 2) / 3 * 4)
        var i = 0
        while i + 3 <= b.count {
            let n = UInt32(b[i]) << 16 | UInt32(b[i + 1]) << 8 | UInt32(b[i + 2])
            out.append(alphabet[Int(n >> 18 & 63)])
            out.append(alphabet[Int(n >> 12 & 63)])
            out.append(alphabet[Int(n >> 6 & 63)])
            out.append(alphabet[Int(n & 63)])
            i += 3
        }
        let rest = b.count - i
        if rest == 1 {
            let n = UInt32(b[i]) << 16
            out.append(alphabet[Int(n >> 18 & 63)])
            out.append(alphabet[Int(n >> 12 & 63)])
            out.append(UInt8(ascii: "="))
            out.append(UInt8(ascii: "="))
        } else if rest == 2 {
            let n = UInt32(b[i]) << 16 | UInt32(b[i + 1]) << 8
            out.append(alphabet[Int(n >> 18 & 63)])
            out.append(alphabet[Int(n >> 12 & 63)])
            out.append(alphabet[Int(n >> 6 & 63)])
            out.append(UInt8(ascii: "="))
        }
        return String(decoding: out, as: UTF8.self)
    }

    /// Strictly decode `s` into exactly `length` bytes, or `nil`.
    ///
    /// Rejects whitespace, the URL-safe alphabet, missing / extra / misplaced
    /// padding, non-zero trailing bits and any other decoded length.
    public static func decode(_ s: String, length: Int) -> [UInt8]? {
        let chars = Array(s.utf8)
        let pad = (3 - length % 3) % 3
        guard length >= 0, chars.count == (length + 2) / 3 * 4 else { return nil }
        let dataChars = chars.count - pad
        for j in dataChars..<chars.count where chars[j] != UInt8(ascii: "=") { return nil }
        var vals = [UInt8]()
        vals.reserveCapacity(dataChars)
        for j in 0..<dataChars {
            let v = reverse[Int(chars[j])]
            if v < 0 { return nil }
            vals.append(UInt8(v))
        }
        // Non-zero trailing bits in the last data character are not canonical.
        if pad == 1, vals[dataChars - 1] & 0x03 != 0 { return nil }
        if pad == 2, vals[dataChars - 1] & 0x0F != 0 { return nil }
        var out = [UInt8]()
        out.reserveCapacity(length)
        var acc: UInt32 = 0
        var bits = 0
        for v in vals {
            acc = acc << 6 | UInt32(v)
            bits += 6
            if bits >= 8 {
                bits -= 8
                out.append(UInt8(truncatingIfNeeded: acc >> UInt32(bits)))
                acc &= (1 << UInt32(bits)) - 1
            }
        }
        return out.count == length ? out : nil
    }

    /// Strictly decode a 32-byte binary field.
    public static func decode32(_ s: String) -> Bytes32? {
        decode(s, length: 32).flatMap { Bytes32($0) }
    }
}

/// Hyphenated UUID handling (README §1): strict parsing, lowercase output.
public enum UUIDText {
    /// Parse exactly the 36-character hyphenated form, either case. Every
    /// other form (no hyphens, braces, `urn:uuid:`, wrong length) is `nil`.
    public static func parse(_ s: String) -> UUID? {
        let b = Array(s.utf8)
        guard b.count == 36 else { return nil }
        for (i, c) in b.enumerated() {
            switch i {
            case 8, 13, 18, 23:
                if c != UInt8(ascii: "-") { return nil }
            default:
                let hex = (c >= 0x30 && c <= 0x39) || (c >= 0x41 && c <= 0x46) || (c >= 0x61 && c <= 0x66)
                if !hex { return nil }
            }
        }
        return UUID(uuidString: s)
    }

    /// Lowercase hyphenated form.
    public static func format(_ u: UUID) -> String {
        u.uuidString.lowercased()
    }
}
