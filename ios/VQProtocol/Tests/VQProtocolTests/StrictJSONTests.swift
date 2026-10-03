import Foundation
import Testing
@testable import VQProtocol

@Suite("strict JSON reader (README §5.1)")
struct StrictJSONTests {
    func ok(_ s: String, sourceLocation: SourceLocation = #_sourceLocation) {
        #expect(throws: Never.self, "\(s.debugDescription)", sourceLocation: sourceLocation) {
            _ = try StrictJSON.parse(Array(s.utf8))
        }
    }

    func err(_ b: [UInt8], sourceLocation: SourceLocation = #_sourceLocation) {
        let r = result { () throws(VQError) in try StrictJSON.parse(b) }
        #expect(r.errorCode == "invalid_json", "\(hexString(b.prefix(40)))", sourceLocation: sourceLocation)
    }

    func err(_ s: String, sourceLocation: SourceLocation = #_sourceLocation) {
        err(Array(s.utf8), sourceLocation: sourceLocation)
    }

    @Test func grammar() {
        for s in [
            "{}", "[]", "0", "-0", "1.5e-3", "1E+2", "\"x\"", "null", "true", "false",
            " {\"a\" : [1, {\"b\": true}] } ", "1e308", "-1e-400", "123456789012345678901234567890",
            "\"\\u00e9\\/\\b\\f\\n\\r\\t\\\"\\\\\"", "\"\\uABCD\"",
        ] {
            ok(s)
        }
        for s in [
            "", " ", "{", "}", "[1,]", "{\"a\":1,}", "01", "-01", "+1", ".5", "1.", "1e", "1e+", "-", "--1",
            "NaN", "Infinity", "-Infinity", "inf", "nan", "0x10", "tru", "nul", "True", "{\"a\" 1}", "{a:1}",
            "'x'", "\"\\x\"", "\"\\u12\"", "\"a\nb\"", "\"a\tb\"", "{} {}", "\u{FEFF}{}", "\u{A0}{}",
            "\"\\u00G0\"", "[1 2]", "{\"a\":1 \"b\":2}", "\u{0B}{}", "\u{0C}{}", "\"\\U0041\"", "\"unterminated",
        ] {
            err(s)
        }
    }

    @Test func utf8Validation() {
        for hex in [
            "22ff22", // invalid byte
            "22c0af22", // overlong '/'
            "22e080af22", // overlong 3-byte
            "22f08080af22", // overlong 4-byte
            "22eda08022", // encoded surrogate U+D800
            "22edbfbf22", // encoded surrogate U+DFFF
            "22f490808022", // U+110000
            "22c322", // truncated 2-byte
            "22e282", // truncated at end
            "2280", // lone continuation
            "efbbbf7b7d", // BOM + {}
        ] {
            err(hexBytes(hex))
        }
        ok("\"\u{7F}\u{80}\u{7FF}\u{800}\u{FFFF}\u{10000}\u{10FFFF}\u{E000}\"")
    }

    @Test func depth() {
        func nest(_ n: Int) -> String { String(repeating: "[", count: n) + String(repeating: "]", count: n) }
        ok(nest(32))
        err(nest(33))
        ok("{\"x\":\(nest(31))}")
        err("{\"x\":\(nest(32))}")
        // Deep input is rejected without deep recursion.
        err(String(repeating: "[", count: 100_000))
        err(String(repeating: "{\"a\":", count: 100_000))
    }

    @Test func finiteNumbers() {
        err("1e400")
        err("-1e400")
        err("1e309")
        ok("1.7976931348623157e308")
        err("1.7976931348623159e308")
        ok("1.7976931348623158e308") // below the rounding midpoint 2^1024 − 2^970
        ok(String(repeating: "9", count: 300))
        err(String(repeating: "9", count: 400))
        ok("0e999999999999999999999")
        err("1e999999999999999999999")
        ok("1e-999999999999999999999")
        ok("-0.0")
        // Tokens longer than Swift's 16,384-byte Double(String) limit (C1):
        // finiteness is decided from the digits, as Rust's f64 parser does.
        let z = { (n: Int) in String(repeating: "0", count: n) }
        ok("1." + z(65_000))
        ok("0." + z(65_000) + "1")
        ok("0." + z(60_000) + "1e60300") // ≈ 1e299
        err("0." + z(60_000) + "1e60310") // ≈ 1e309
        ok("1e" + z(20_000) + "308")
        err("1e" + z(20_000) + "309")
        ok("1e-" + z(20_000) + "400")
        ok(String(repeating: "1", count: 20_000) + "e-19700") // ≈ 1.1e299
        err(String(repeating: "1", count: 20_000) + "e-19600") // ≈ 1.1e399
        ok(String(repeating: "9", count: 20_000) + "e-19692") // 9.99…e307
        // Around the overflow midpoint 2^1024 − 2^970 with long tails.
        let mid = "179769313486231580793728971405303415079934132710037826936173778980444968292764750946649017977587207096330286416692887910946555547851940402630657488671505820681908902000708383676273854845817711531764475730270069855571366959622842914819860834936475292719074168444365510704342711559699508093042880177904174497792"
        let below = String(mid.dropLast()) + "1." + String(repeating: "9", count: 20_000)
        err(mid)                              // exactly the midpoint: ties-to-even → ∞
        ok(below)                             // just below the midpoint
        err(mid + "." + z(20_000) + "1")      // just above
        ok("0." + String(mid.dropLast()) + "1" + String(repeating: "9", count: 20_000) + "e309")
        err("0." + mid + z(20_000) + "e309")
        err("0." + mid + z(20_000) + "1e309")
    }

    @Test func surrogates() {
        ok(#""\ud83d\ude00""#)
        ok(#""\uD83D\uDE00""#)
        for s in [
            #""\ud800""#, #""\udfff""#, #""\ud800A""#, #""\udc00\ud800""#, #""\ud800\u0041""#,
            #""\ud800\ud800""#, #""\ud800\""#, #""\ud83d\\ude00""#,
        ] {
            err(s)
        }
        err(#"{"\ud800":1}"#)
    }

    @Test func duplicateKeys() {
        err(#"{"a":1,"a":2}"#)
        err(#"{"t":1,"\u0074":2}"#)
        err(#"{"x":[{"k":1,"k":1}]}"#)
        ok(#"{"a":{"a":1},"b":{"a":1}}"#)
        // Keys compare as UTF-8 bytes, not with Swift's canonical-equivalence
        // String ==: KELVIN SIGN (U+212A) and "K", or precomposed and
        // decomposed "é", are different keys.
        ok("{\"K\":1,\"\u{212A}\":2}")
        ok("{\"\u{E9}\":1,\"e\u{301}\":2}")
        err("{\"\u{E9}\":1,\"\\u00e9\":2}")
    }

    @Test func topLevelMembers() throws {
        let doc = try StrictJSON.parse(Array(#"{"t":"p\u0069ng","n":-0,"o":{"x":[1]},"a":[],"b":false,"z":null}"#.utf8))
        guard case .object(let m) = doc else {
            Issue.record("not an object")
            return
        }
        #expect(m.map { String(decoding: $0.key, as: UTF8.self) } == ["t", "n", "o", "a", "b", "z"])
        #expect(m.map(\.value) == [.str(Array("ping".utf8)), .num("-0"), .object, .array, .bool(false), .null])
        guard case .notObject = try StrictJSON.parse(Array("[1]".utf8)) else {
            Issue.record("array should be notObject")
            return
        }
    }

    @Test func messageLevelUsesBytes() throws {
        // A JSON `\u` escape is decoded before `t` is matched: `\u0070ing` is
        // byte-equal to "ping" after unescaping.
        let m = try Message.fromJSON(Array(#"{"t":"\u0070ing"}"#.utf8))
        #expect(m == .ping)
        // A `t` canonically equivalent to, but not byte-equal to, a known type is unknown.
        let k = try Message.fromJSON(Array("{\"t\":\"\u{212A}\"}".utf8))
        guard case .unknown(let t) = k else {
            Issue.record("want unknown")
            return
        }
        #expect(Array(t.utf8) == [0xE2, 0x84, 0xAA])
        #expect(k != .unknown(t: "K"))
        // Decomposed vs precomposed text are different messages on the wire.
        let id = UUID()
        let a = Message.utt(Utt(id: id, rev: 0, state: .final, text: "\u{E9}", ts: 0))
        let b = Message.utt(Utt(id: id, rev: 0, state: .final, text: "e\u{301}", ts: 0))
        #expect(a != b)
        #expect(try Message.fromJSON(a.toJSON()) == a)
        #expect(try Message.fromJSON(b.toJSON()) == b)
    }
}
