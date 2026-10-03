/// Strict, bounded JSON reader used for every message decode (README §5.1).
///
/// This is deliberately our own code rather than `JSONSerialization` /
/// `JSONDecoder`, whose accept/reject boundary differs from the README
/// (depth, huge numbers, lone surrogates, duplicate keys, BOM, …). It
/// validates the **whole document**, including members the message layer
/// later ignores, and fails with ``VQError/invalidJSON(_:)`` when:
///
/// 1. the input is not valid UTF-8, or is not exactly one RFC 8259 value
///    surrounded by optional JSON whitespace (space, tab, LF, CR);
/// 2. objects and arrays nest more than 32 deep (outermost container = 1);
/// 3. any number, rounded to an IEEE 754 binary64 double, is not finite;
/// 4. any string contains a `\u` escape for a lone surrogate;
/// 5. any object, at any depth, has two members whose keys are equal after
///    unescaping (compared as raw UTF-8 bytes, never with Swift `String`
///    equality, which would treat canonically equivalent keys as equal).
///
/// Only the members of a top-level object are returned; nested containers are
/// validated and discarded.
enum StrictJSON {
    /// A top-level member value.
    enum Scalar: Equatable {
        /// A string, unescaped, as UTF-8 bytes.
        case str([UInt8])
        /// A number: its raw, grammar-checked, finite source text (ASCII).
        case num(String)
        case bool(Bool)
        case null
        case object
        case array
    }

    /// A parsed document.
    enum Document {
        /// Top-level object: members in source order (keys are unique).
        case object([(key: [UInt8], value: Scalar)])
        /// Valid JSON, but not an object.
        case notObject
    }

    static func parse(_ bytes: [UInt8]) throws(VQError) -> Document {
        guard isValidUTF8(bytes) else { throw bad("input is not valid UTF-8") }
        var p = Parser(b: bytes)
        p.ws()
        let doc: Document
        if p.peek() == UInt8(ascii: "{") {
            doc = .object(try p.object(depth: 1, keep: true))
        } else {
            _ = try p.value(depth: 0)
            doc = .notObject
        }
        p.ws()
        guard p.i == bytes.count else { throw bad("trailing characters after the JSON value") }
        return doc
    }

    /// Strict UTF-8 validation: no overlong forms, no encoded surrogates,
    /// nothing above U+10FFFF, no truncated sequences.
    static func isValidUTF8(_ b: [UInt8]) -> Bool {
        var i = 0
        let n = b.count
        while i < n {
            let c = b[i]
            if c < 0x80 {
                i += 1
                continue
            }
            func cont(_ k: Int) -> Bool { i + k < n && b[i + k] & 0xC0 == 0x80 }
            if c >= 0xC2 && c <= 0xDF {
                guard cont(1) else { return false }
                i += 2
            } else if c >= 0xE0 && c <= 0xEF {
                guard i + 1 < n else { return false }
                let c1 = b[i + 1]
                let lo: UInt8 = c == 0xE0 ? 0xA0 : 0x80
                let hi: UInt8 = c == 0xED ? 0x9F : 0xBF
                guard c1 >= lo && c1 <= hi, cont(2) else { return false }
                i += 3
            } else if c >= 0xF0 && c <= 0xF4 {
                guard i + 1 < n else { return false }
                let c1 = b[i + 1]
                let lo: UInt8 = c == 0xF0 ? 0x90 : 0x80
                let hi: UInt8 = c == 0xF4 ? 0x8F : 0xBF
                guard c1 >= lo && c1 <= hi, cont(2), cont(3) else { return false }
                i += 4
            } else {
                return false
            }
        }
        return true
    }

    fileprivate static func bad(_ why: String) -> VQError { .invalidJSON(why) }

    private struct Parser {
        let b: [UInt8]
        var i = 0

        init(b: [UInt8]) { self.b = b }

        func peek() -> UInt8? { i < b.count ? b[i] : nil }

        mutating func ws() {
            while let c = peek(), c == 0x20 || c == 0x09 || c == 0x0A || c == 0x0D { i += 1 }
        }

        mutating func eat(_ c: UInt8) throws(VQError) {
            guard peek() == c else { throw bad("unexpected character") }
            i += 1
        }

        /// One value; `depth` is the depth of the enclosing container (0 at top level).
        mutating func value(depth: Int) throws(VQError) -> Scalar {
            switch peek() {
            case UInt8(ascii: "{"):
                _ = try object(depth: depth + 1, keep: false)
                return .object
            case UInt8(ascii: "["):
                try array(depth: depth + 1)
                return .array
            case UInt8(ascii: "\""):
                return .str(try string())
            case UInt8(ascii: "t"):
                try literal("true")
                return .bool(true)
            case UInt8(ascii: "f"):
                try literal("false")
                return .bool(false)
            case UInt8(ascii: "n"):
                try literal("null")
                return .null
            case let c? where c == UInt8(ascii: "-") || (c >= 0x30 && c <= 0x39):
                return .num(try number())
            default:
                throw bad("expected a JSON value")
            }
        }

        mutating func literal(_ word: StaticString) throws(VQError) {
            let w = word.withUTF8Buffer { Array($0) }
            guard i + w.count <= b.count, Array(b[i..<(i + w.count)]) == w else {
                throw bad("invalid literal")
            }
            i += w.count
        }

        static func checkDepth(_ depth: Int) throws(VQError) {
            if depth > VQ.maxJSONDepth { throw bad("nesting deeper than 32 levels") }
        }

        mutating func object(depth: Int, keep: Bool) throws(VQError) -> [(key: [UInt8], value: Scalar)] {
            try Self.checkDepth(depth)
            try eat(UInt8(ascii: "{"))
            var seen = Set<[UInt8]>()
            var members: [(key: [UInt8], value: Scalar)] = []
            ws()
            if peek() == UInt8(ascii: "}") {
                i += 1
                return members
            }
            while true {
                ws()
                guard peek() == UInt8(ascii: "\"") else { throw bad("expected an object key") }
                let key = try string()
                ws()
                try eat(UInt8(ascii: ":"))
                ws()
                let v = try value(depth: depth)
                guard seen.insert(key).inserted else { throw bad("duplicate object key") }
                if keep { members.append((key, v)) }
                ws()
                switch peek() {
                case UInt8(ascii: ","): i += 1
                case UInt8(ascii: "}"):
                    i += 1
                    return members
                default: throw bad("expected ',' or '}'")
                }
            }
        }

        mutating func array(depth: Int) throws(VQError) {
            try Self.checkDepth(depth)
            try eat(UInt8(ascii: "["))
            ws()
            if peek() == UInt8(ascii: "]") {
                i += 1
                return
            }
            while true {
                ws()
                _ = try value(depth: depth)
                ws()
                switch peek() {
                case UInt8(ascii: ","): i += 1
                case UInt8(ascii: "]"):
                    i += 1
                    return
                default: throw bad("expected ',' or ']'")
                }
            }
        }

        mutating func digits() -> Int {
            let start = i
            while let c = peek(), c >= 0x30 && c <= 0x39 { i += 1 }
            return i - start
        }

        mutating func number() throws(VQError) -> String {
            let start = i
            if peek() == UInt8(ascii: "-") { i += 1 }
            switch peek() {
            case UInt8(ascii: "0"): i += 1
            case let c? where c >= 0x31 && c <= 0x39: _ = digits()
            default: throw bad("invalid number")
            }
            if peek() == UInt8(ascii: ".") {
                i += 1
                guard digits() > 0 else { throw bad("invalid number") }
            }
            if peek() == UInt8(ascii: "e") || peek() == UInt8(ascii: "E") {
                i += 1
                if peek() == UInt8(ascii: "+") || peek() == UInt8(ascii: "-") { i += 1 }
                guard digits() > 0 else { throw bad("invalid number") }
            }
            let raw = String(decoding: b[start..<i], as: UTF8.self)
            // Swift's Double(String) is correctly rounded (round-to-nearest-even)
            // and yields ±infinity on overflow. The token is already
            // grammar-checked, so the hex / "nan" / "inf" forms it would
            // otherwise accept cannot reach it.
            guard let d = Double(raw) else { throw bad("invalid number") }
            guard d.isFinite else { throw bad("number is not finite as a binary64 double") }
            return raw
        }

        mutating func hex4() throws(VQError) -> UInt32 {
            guard i + 4 <= b.count else { throw bad("truncated \\u escape") }
            var v: UInt32 = 0
            for k in 0..<4 {
                let c = b[i + k]
                let d: UInt32
                switch c {
                case 0x30...0x39: d = UInt32(c - 0x30)
                case 0x41...0x46: d = UInt32(c - 0x41 + 10)
                case 0x61...0x66: d = UInt32(c - 0x61 + 10)
                default: throw bad("invalid \\u escape")
                }
                v = v * 16 + d
            }
            i += 4
            return v
        }

        mutating func string() throws(VQError) -> [UInt8] {
            try eat(UInt8(ascii: "\""))
            var out: [UInt8] = []
            while true {
                guard let c = peek() else { throw bad("unterminated string") }
                switch c {
                case UInt8(ascii: "\""):
                    i += 1
                    return out
                case UInt8(ascii: "\\"):
                    i += 1
                    guard let e = peek() else { throw bad("unterminated string") }
                    i += 1
                    switch e {
                    case UInt8(ascii: "\""): out.append(0x22)
                    case UInt8(ascii: "\\"): out.append(0x5C)
                    case UInt8(ascii: "/"): out.append(0x2F)
                    case UInt8(ascii: "b"): out.append(0x08)
                    case UInt8(ascii: "f"): out.append(0x0C)
                    case UInt8(ascii: "n"): out.append(0x0A)
                    case UInt8(ascii: "r"): out.append(0x0D)
                    case UInt8(ascii: "t"): out.append(0x09)
                    case UInt8(ascii: "u"):
                        let hi = try hex4()
                        let cp: UInt32
                        switch hi {
                        case 0xD800...0xDBFF:
                            guard i + 2 <= b.count, b[i] == UInt8(ascii: "\\"), b[i + 1] == UInt8(ascii: "u") else {
                                throw bad("lone surrogate escape")
                            }
                            i += 2
                            let lo = try hex4()
                            guard (0xDC00...0xDFFF).contains(lo) else { throw bad("lone surrogate escape") }
                            cp = 0x10000 + ((hi - 0xD800) << 10) + (lo - 0xDC00)
                        case 0xDC00...0xDFFF:
                            throw bad("lone surrogate escape")
                        default:
                            cp = hi
                        }
                        guard let scalar = Unicode.Scalar(cp) else { throw bad("invalid \\u escape") }
                        out.append(contentsOf: UTF8.encode(scalar)!)
                    default:
                        throw bad("invalid escape")
                    }
                case 0x00...0x1F:
                    throw bad("unescaped control character in string")
                default:
                    out.append(c)
                    i += 1
                }
            }
        }
    }
}
