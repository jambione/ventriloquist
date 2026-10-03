import Foundation
import Testing
@testable import VQProtocol

// M2 adversary suite: attacks on the Swift implementation of the
// Ventriloquist wire protocol (normative: protocol/README.md).
//
// * Crash hunting: inputs chosen to hit Swift traps (overflow, out-of-range
//   indexing, force-unwraps, deep recursion).
// * Differential: a corpus of inputs whose verdicts come from the Rust
//   reference crate (a helper binary in the session scratch dir). Every Swift
//   verdict must match. Skipped when the corpus file is absent.
// * Performance: every 64 KiB adversarial input decodes in < 200 ms.
// * Crypto / API misuse: replay, reorder, tampering, cross-direction,
//   counter exhaustion, wrong-length MACs, low-order points, code strictness.
//
// Trapping inputs are wrapped in exit tests (`#expect(processExitsWith:)`) so
// one trap cannot take down the rest of the run.

// MARK: - helpers

private func advHex(_ b: some Sequence<UInt8>) -> String {
    let d = Array("0123456789abcdef".utf8)
    var out = [UInt8]()
    for x in b {
        out.append(d[Int(x >> 4)])
        out.append(d[Int(x & 15)])
    }
    return String(decoding: out, as: UTF8.self)
}

private func advUnhex(_ s: Substring) -> [UInt8] {
    let u = Array(s.utf8)
    func v(_ c: UInt8) -> UInt8 {
        switch c {
        case 0x30...0x39: c - 0x30
        case 0x61...0x66: c - 0x61 + 10
        default: c - 0x41 + 10
        }
    }
    var out = [UInt8]()
    out.reserveCapacity(u.count / 2)
    var i = 0
    while i + 1 < u.count {
        out.append(v(u[i]) << 4 | v(u[i + 1]))
        i += 2
    }
    return out
}

private let advKey: [UInt8] = (0x80...0x9F).map { UInt8($0) }

private func code<T>(_ f: () throws(VQError) -> T) -> String? {
    do {
        _ = try f()
        return nil
    } catch {
        return error.code
    }
}

private func repr(_ m: Message) -> String {
    switch m {
    case .unknown(let t): return "unk:" + advHex(t.utf8)
    case .helloUnsupported(let h): return "hu:\(h.v):" + (h.name.map { advHex($0.utf8) } ?? "-")
    default:
        do { return "m:" + advHex(try m.toJSON()) } catch { return "menc_err:" + error.code }
    }
}

private func inboundVerdict(_ f: () throws(VQError) -> Inbound) -> String {
    do {
        let i = try f()
        let p = i.isAuthenticated ? "enc" : "pt"
        let chk: String
        do {
            try checkInSession(i)
            chk = "ok"
        } catch {
            chk = error.code
        }
        return "\(p):\(repr(i.message))|\(chk)"
    } catch {
        return "err:" + error.code
    }
}

private func timeMs(_ f: () -> Void) -> Double {
    let c = ContinuousClock()
    let d = c.measure(f)
    return Double(d.components.seconds) * 1000 + Double(d.components.attoseconds) / 1e15
}

private func decodeCode(_ s: String) -> String {
    switch Result(catching: { () throws(VQError) in try Message.fromJSON(Array(s.utf8)) }) {
    case .success(let m): "ok:" + repr(m)
    case .failure(let e): "err:" + e.code
    }
}

private func decodeCode(_ b: [UInt8]) -> String {
    switch Result(catching: { () throws(VQError) in try Message.fromJSON(b) }) {
    case .success(let m): "ok:" + repr(m)
    case .failure(let e): "err:" + e.code
    }
}

let advCorpusPath = "/private/tmp/claude-501/-Users-jonathanbrasfield-repo-ventriloquist/c5868579-10b1-4b67-ae25-dc122a0de512/scratchpad/m2adv/corpus.txt"

// MARK: - differential vs Rust

@Suite("Adversary: differential vs Rust reference")
struct AdversaryDifferentialTests {
    /// Swift's verdict for one corpus case, in the helper's format.
    static func verdict(kind: Substring, arg: Substring, data: Substring) -> String {
        switch kind {
        case "json":
            return decodeCode(advUnhex(data))
        case "inb":
            let b = advUnhex(data)
            return inboundVerdict { () throws(VQError) in try decodeInbound(b, session: nil) }
        case "env":
            let b = advUnhex(data)
            let s = SessionCipher(rawKeyForTests: advKey, role: .desktop)
            return inboundVerdict { () throws(VQError) in try decodeInbound(b, session: s) }
        case "replay":
            let s = SessionCipher(rawKeyForTests: advKey, role: .desktop)
            var steps: [String] = []
            for e in data.split(separator: ",", omittingEmptySubsequences: false) {
                do { steps.append("ok:" + advHex(try s.open(advUnhex(e)))) } catch { steps.append("e:" + error.code) }
            }
            let last = s.lastReceivedCounter.map { "Some(\($0))" } ?? "None"
            return steps.joined(separator: ",") + ";last=" + last
        case "frames":
            var r = Reassembler()
            var steps: [String] = []
            if !data.isEmpty {
                for f in data.split(separator: ",", omittingEmptySubsequences: false) {
                    do {
                        if let m = try r.push(advUnhex(f)) { steps.append("m:" + advHex(m)) } else { steps.append("n") }
                    } catch {
                        steps.append("e:" + error.code)
                    }
                }
            }
            return steps.joined(separator: ",") + "|p" + (r.hasPartial ? "1" : "0")
        case "split":
            let p = arg.split(separator: ",")
            var s = FrameSplitter(seq: UInt16(p[1])!)
            do {
                let fs = try s.split(advUnhex(data), mtu: Int(p[0])!)
                return "ok:" + fs.map { advHex($0) }.joined(separator: ",") + ";next=\(s.nextSeq)"
            } catch {
                return "err:" + error.code + ";next=\(s.nextSeq)"
            }
        case "code":
            let s = String(decoding: advUnhex(data), as: UTF8.self)
            do { return "ok:\(try PairingCode(parsing: s).value)" } catch { return "err:" + error.code }
        case "b64":
            let s = String(decoding: advUnhex(data), as: UTF8.self)
            return Base64.decode32(s).map { "ok:" + advHex($0.bytes) } ?? "err"
        case "uuid":
            let s = String(decoding: advUnhex(data), as: UTF8.self)
            return UUIDText.parse(s).map { "ok:" + UUIDText.format($0) } ?? "err"
        case "x25519":
            guard let id = IdentityKeyPair(secretBytes: advUnhex(arg)), let pub = Bytes32(advUnhex(data)) else {
                return "swift-setup-failed"
            }
            do { return "ok:" + advHex(try id.sharedSecret(peerPublic: pub).bytesForTests) } catch { return "err:" + error.code }
        default:
            return "unknown-kind"
        }
    }

    @Test func swiftAgreesWithRustOnEveryCorpusCase() throws {
        guard let text = try? String(contentsOfFile: advCorpusPath, encoding: .utf8) else {
            print("[adversary] corpus not found at \(advCorpusPath); differential test skipped")
            return
        }
        var total = 0
        var perKind: [String: Int] = [:]
        var mismatches: [String] = []
        for line in text.split(separator: "\n") {
            let f = line.split(separator: "\t", omittingEmptySubsequences: false)
            guard f.count == 4 else { continue }
            total += 1
            perKind[String(f[0]), default: 0] += 1
            let swift = Self.verdict(kind: f[0], arg: f[1], data: f[2])
            if swift != f[3] {
                let d = f[2].count > 400 ? f[2].prefix(400) + "…(\(f[2].count / 2) bytes)" : f[2]
                mismatches.append("kind=\(f[0]) arg=\(f[1]) input=\(d)\n   rust =\(f[3].prefix(300))\n   swift=\(swift.prefix(300))")
            }
        }
        print("[adversary] differential: \(total) cases \(perKind.sorted { $0.key < $1.key }), \(mismatches.count) mismatches")
        let report = mismatches.joined(separator: "\n")
        try? report.write(toFile: advCorpusPath + ".mismatches.txt", atomically: true, encoding: .utf8)
        for m in mismatches.prefix(40) { print("[adversary] MISMATCH " + m) }
        #expect(total > 1000, "corpus unexpectedly small")
        #expect(mismatches.isEmpty, "\(mismatches.count) Rust/Swift disagreements; first: \(mismatches.first ?? "")")
    }
}

// MARK: - crash hunting

@Suite("Adversary: crash hunting")
struct AdversaryCrashTests {
    @Test func framesOfSize0To3WithEveryFlagByte() {
        for size in 0...3 {
            for flags in 0...255 {
                var r = Reassembler()
                // prime a partial so discard paths run too
                _ = try? r.push([FrameFlags.first, 0xFF, 0xFF, 0x41])
                var f = [UInt8](repeating: 0xFF, count: size)
                if size > 0 { f[0] = UInt8(flags) }
                let res = Result { () throws(VQError) in try r.push(f) }
                if size < 3 {
                    #expect(res.errorCode == "frame_too_short")
                    #expect(!r.hasPartial)
                }
            }
        }
    }

    @Test func seqWrapAt0xFFFF() throws {
        var s = FrameSplitter(seq: 0xFFFF)
        let a = try s.split([1, 2, 3], mtu: 20)
        #expect(a == [[0x03, 0xFF, 0xFF, 1, 2, 3]])
        #expect(s.nextSeq == 0)
        _ = try s.split([], mtu: 20)
        #expect(s.nextSeq == 1)
        // reassembly across the wrap, interleaved restarts
        var r = Reassembler()
        #expect(try r.push([0x01, 0xFF, 0xFF, 9]) == nil)
        #expect(Result { () throws(VQError) in try r.push([0x02, 0x00, 0x00, 9]) }.errorCode == "seq_mismatch")
        #expect(try r.push([0x01, 0xFF, 0xFF, 9]) == nil)
        #expect(try r.push([0x02, 0xFF, 0xFF, 8]) == [9, 8])
    }

    @Test func splitterHugeMTUDoesNotOverflow() throws {
        var s = FrameSplitter()
        for mtu in [Int.max, Int.max - 2, Int.max - 3, 65_539, 65_540] {
            let fs = try s.split(Array(repeating: 7, count: 100), mtu: mtu)
            #expect(fs.count == 1)
        }
        for mtu in [Int.min, -1, 0, 19] {
            #expect(Result { () throws(VQError) in try s.split([1], mtu: mtu) }.errorCode == "mtu_too_small")
        }
    }

    @Test func reassemblerMaxSizeBoundaryAndOneByteChunks() throws {
        var r = Reassembler()
        #expect(try r.push([0x01, 0, 1]) == nil)
        for _ in 0..<65_535 { #expect(try r.push([0x00, 0, 1, 0x41]) == nil) }
        #expect(try r.push([0x02, 0, 1, 0x42])?.count == 65_536)
        #expect(try r.push([0x01, 0, 2] + [UInt8](repeating: 0, count: 65_536)) == nil)
        #expect(Result { () throws(VQError) in try r.push([0x02, 0, 2, 1]) }.errorCode == "message_too_large")
        #expect(!r.hasPartial)
    }

    @Test func deeplyNestedJSON100k() {
        let n = 100_000
        for doc in [
            String(repeating: "[", count: n),
            String(repeating: "[", count: n) + String(repeating: "]", count: n),
            String(repeating: "{\"a\":", count: n),
            "{\"t\":\"ping\",\"x\":" + String(repeating: "[", count: n),
            String(repeating: "[{\"a\":", count: n / 2),
        ] {
            // > 64 KiB is message_too_large first; the 64 KiB prefix must be invalid_json, without recursing 100k deep
            #expect(decodeCode(doc) == "err:message_too_large")
            #expect(decodeCode(Array(Array(doc.utf8).prefix(65_536))) == "err:invalid_json")
            let env = [UInt8(0)] + Array(doc.utf8).prefix(65_535)
            #expect(Result { () throws(VQError) in try decodeInbound(env, session: nil) }.errorCode == "invalid_json")
        }
        // exactly at the limit
        let d32 = String(repeating: "[", count: 31) + String(repeating: "]", count: 31)
        #expect(decodeCode("{\"t\":\"ping\",\"x\":" + d32 + "}") == "ok:m:" + advHex(Array("{\"t\":\"ping\"}".utf8)))
        let d33 = String(repeating: "[", count: 32) + String(repeating: "]", count: 32)
        #expect(decodeCode("{\"t\":\"ping\",\"x\":" + d33 + "}") == "err:invalid_json")
    }

    @Test func hugeNumericLiterals() {
        let digits = String(repeating: "9", count: 65_000)
        #expect(decodeCode("{\"t\":\"ping\",\"n\":\(digits)}") == "err:invalid_json") // > DBL_MAX
        let small = "0." + String(repeating: "0", count: 65_000) + "1"
        #expect(decodeCode("{\"t\":\"ping\",\"n\":\(small)}").hasPrefix("ok:"))
        let longExp = "1e" + String(repeating: "0", count: 65_000) + "1"
        #expect(decodeCode("{\"t\":\"ping\",\"n\":\(longExp)}").hasPrefix("ok:")) // 1e1
        let negExp = "1e-" + String(repeating: "9", count: 65_000)
        #expect(decodeCode("{\"t\":\"ping\",\"n\":\(negExp)}").hasPrefix("ok:")) // underflows to 0
        let posExp = "1e+" + String(repeating: "9", count: 65_000)
        #expect(decodeCode("{\"t\":\"ping\",\"n\":\(posExp)}") == "err:invalid_json")
        let zeroExp = "0e" + String(repeating: "9", count: 65_000)
        #expect(decodeCode("{\"t\":\"ping\",\"n\":\(zeroExp)}").hasPrefix("ok:")) // 0 * 10^big = 0
        let bigMant = "1" + String(repeating: "0", count: 400) + "e-100"
        #expect(decodeCode("{\"t\":\"ping\",\"n\":\(bigMant)}").hasPrefix("ok:")) // 1e300
        let tinyMant = "0." + String(repeating: "0", count: 400) + "1e400"
        #expect(decodeCode("{\"t\":\"ping\",\"n\":\(tinyMant)}").hasPrefix("ok:")) // ≈ 1e-1
    }

    /// FINDING: Swift's `Double(String)` returns nil for any string longer than
    /// 16,384 UTF-8 bytes, so `StrictJSON.number()` rejects a finite number
    /// token longer than that as `invalid_json`. Rust (and README §5.1: only
    /// non-finite numbers are rejected) accepts it. Boundary: 16,384 ok, 16,385 not.
    @Test func finiteNumberTokenLongerThan16KiBIsAccepted() {
        for len in [16_383, 16_384, 16_385, 16_386, 30_000] {
            let frac = "1." + String(repeating: "1", count: len - 2) // ≈ 1.111, finite
            let zeros = "0." + String(repeating: "0", count: len - 3) + "1" // tiny, finite
            for tok in [frac, zeros] {
                #expect(tok.utf8.count == len)
                let r = decodeCode("{\"t\":\"ping\",\"n\":\(tok)}")
                #expect(r == "ok:m:" + advHex(Array("{\"t\":\"ping\"}".utf8)), "finite token of \(len) bytes -> \(r)")
            }
        }
    }

    @Test func longDigitStringsInIntegerFields() {
        let id = "0f8fad5b-d9cb-469f-a165-70867728950e"
        for rev in ["4294967295", "4294967296", "18446744073709551615", "18446744073709551616",
                    String(repeating: "9", count: 300), "0" + String(repeating: "0", count: 300),
                    "00", "01", "-0", "1.0", "1e0", "1E0", "0.0"] {
            let r = decodeCode("{\"t\":\"ack\",\"id\":\"\(id)\",\"rev\":\(rev)}")
            #expect(r.hasPrefix("ok:") == (rev == "4294967295"), "\(rev) -> \(r)")
        }
        for ts in ["18446744073709551615", "18446744073709551616", String(repeating: "2", count: 20)] {
            let r = decodeCode("{\"t\":\"utt\",\"id\":\"\(id)\",\"rev\":0,\"state\":\"final\",\"text\":\"\",\"ts\":\(ts)}")
            #expect(r.hasPrefix("ok:") == (ts == "18446744073709551615"), "\(ts) -> \(r)")
        }
        for v in ["18446744073709551615", "18446744073709551616", "1.0", "-1", "1e0", "0"] {
            let r = decodeCode("{\"t\":\"hello\",\"v\":\(v)}")
            let expectOk = v == "18446744073709551615" || v == "0"
            #expect(r.hasPrefix("ok:hu:") == expectOk, "\(v) -> \(r)")
        }
    }

    @Test func escapesAndUTF8AtEndOfInput() {
        let cases: [[UInt8]] = [
            Array("\"\\u".utf8), Array("\"\\u1".utf8), Array("\"\\u12".utf8), Array("\"\\u123".utf8),
            Array("\"\\u1234".utf8), Array("\"\\ud800".utf8), Array("\"\\ud800\\".utf8), Array("\"\\ud800\\u".utf8),
            Array("\"\\ud800\\udc".utf8), Array("\"\\ud800\\udc00".utf8), Array("\"\\".utf8), Array("\"".utf8),
            Array("{\"t\":\"\\u".utf8), Array("{\"\\u".utf8), Array("{\"t\\ud83d".utf8),
            [0x22, 0xC3], [0x22, 0xE2, 0x82], [0x22, 0xF0, 0x9F, 0x98], [0xF0], [0xC3],
            Array("{\"t\":\"ping\"}".utf8) + [0xC3], Array("{\"t\":\"ping\"}".utf8) + [0xF4, 0x8F, 0xBF],
            [0x7B, 0x22, 0x74, 0x22, 0x3A, 0x22, 0xED, 0xA0, 0x80, 0x22, 0x7D], // encoded surrogate in value
            [0x7B, 0x22, 0xFF, 0x22, 0x3A, 0x31, 0x7D], // invalid byte in key
            [0x7B, 0x22, 0xC0, 0x80, 0x22, 0x3A, 0x31, 0x7D], // overlong NUL in key
            [0x7B, 0x22, 0xF4, 0x90, 0x80, 0x80, 0x22, 0x3A, 0x31, 0x7D], // > U+10FFFF
            Array("\"\\ud83d\" \"\\ude00\"".utf8), Array("[\"\\ud83d\",\"\\ude00\"]".utf8),
            Array("\"\\ud83d\\u0020\\ude00\"".utf8), Array("\"\\uDBFF\\uDFFF\"".utf8),
        ]
        for c in cases {
            let r = decodeCode(c)
            #expect(r.hasPrefix("err:"), "\(advHex(c)) -> \(r)")
        }
        // "\u0000" in keys: distinct from "" and from "\u0000\u0000", duplicates detected
        #expect(decodeCode("{\"t\":\"ping\",\"\\u0000\":1,\"\":2,\"\\u0000\\u0000\":3}").hasPrefix("ok:"))
        #expect(decodeCode("{\"t\":\"ping\",\"\\u0000\":1,\"\\u0000\":2}") == "err:invalid_json")
        // t with an embedded NUL is an unknown type, not "ping"
        #expect(decodeCode("{\"t\":\"ping\\u0000\"}") == "ok:unk:" + advHex(Array("ping\u{0}".utf8)))
        // canonically equivalent keys are distinct (é vs e + U+0301)
        #expect(decodeCode("{\"t\":\"ping\",\"\\u00e9\":1,\"e\\u0301\":2}").hasPrefix("ok:"))
        // escaped and literal key duplicates
        #expect(decodeCode("{\"t\":\"ping\",\"\\u00e9\":1,\"é\":2}") == "err:invalid_json")
        #expect(decodeCode("{\"t\":\"ping\",\"\\ud83d\\ude00\":1,\"😀\":2}") == "err:invalid_json")
    }

    @Test func oversizeInputsEverywhere() {
        let big = [UInt8](repeating: 0x20, count: 65_537)
        #expect(Result { () throws(VQError) in try Message.fromJSON(big) }.errorCode == "message_too_large")
        #expect(Result { () throws(VQError) in try Envelope.parse(big) }.errorCode == "message_too_large")
        #expect(Result { () throws(VQError) in try decodeInbound([1] + big, session: nil) }.errorCode == "message_too_large")
        let s = SessionCipher(rawKeyForTests: advKey, role: .phone)
        #expect(Result { () throws(VQError) in try s.seal([UInt8](repeating: 0, count: 65_512)) }.errorCode == "message_too_large")
        #expect(s.nextSendCounter == 0)
        #expect((try? s.seal([UInt8](repeating: 0, count: 65_511)))?.count == 65_536)
        #expect(Result { () throws(VQError) in try s.open([UInt8](repeating: 1, count: 1_000_000)) }.errorCode == "message_too_large")
    }

    @Test func encoderAPIHostileValues() {
        let id = UUID()
        // huge / control-heavy text: no trap, correct error codes
        let ctrl = String(repeating: "\u{0}", count: 32_000)
        #expect(escapedLength(ctrl) == 192_000)
        #expect(!uttTextFits(ctrl))
        #expect(maxTextPrefix(ctrl).utf8.count == (VQ.maxEncryptedJSONBytes - VQ.uttMaxOverheadBytes) / 6)
        let m = Message.utt(Utt(id: id, rev: .max, state: .partial, text: ctrl, ts: .max))
        #expect(Result { () throws(VQError) in try m.toJSON() }.errorCode == "message_too_large")
        let tooLong = Message.utt(Utt(id: id, rev: 0, state: .final, text: String(repeating: "é", count: 16_001), ts: 0))
        #expect(Result { () throws(VQError) in try tooLong.toJSON() }.errorCode == "text_too_long")
        let name = String(repeating: "\u{1}", count: 20_000)
        let h = Message.hello(Hello(deviceId: id, name: name, publicKey: Bytes32(repeating: 1), paired: false,
                                    sessionNonce: Bytes32(repeating: 2)))
        #expect(Result { () throws(VQError) in try h.toJSON() }.errorCode == "message_too_large")
        #expect(Result { () throws(VQError) in try encodePlaintext(h) }.errorCode == "message_too_large")
        // receive-only and inconsistent
        #expect(Result { () throws(VQError) in try Message.unknown(t: "x").toJSON() }.errorCode == "not_encodable")
        #expect(Result { () throws(VQError) in try encodePlaintext(.unknown(t: "hello")) }.errorCode == "plaintext_not_allowed")
        #expect(Result { () throws(VQError) in try encodePlaintext(.ping) }.errorCode == "plaintext_not_allowed")
        #expect(Result { () throws(VQError) in try Message.pairResult(PairResult(ok: true, mac: nil)).toJSON() }.errorCode == "not_encodable")
        #expect(Result { () throws(VQError) in
            try Message.hello(Hello(v: 0, deviceId: id, name: "", publicKey: Bytes32(repeating: 0), paired: false,
                                    sessionNonce: Bytes32(repeating: 0))).toJSON()
        }.errorCode == "not_encodable")
        // round trip of every scalar class through the canonical writer
        var all = ""
        for v in stride(from: 0, through: 0x10FFFF, by: 97) {
            if let u = Unicode.Scalar(UInt32(v)) { all.unicodeScalars.append(u) }
        }
        for v in 0...0x7F { all.unicodeScalars.append(Unicode.Scalar(UInt8(v))) }
        // One copy fits the 64 KiB message limit and must round-trip exactly; two copies exceed it
        // and the encoder must refuse (README §9), never emit an oversize message.
        let e = Message.error(ErrorMsg(code: all, msg: ""))
        let back = Result { () throws(VQError) in try Message.fromJSON(e.toJSON()) }
        #expect(back.errorCode == nil)
        #expect((try? back.get()) == e)
        let tooBig = Message.error(ErrorMsg(code: all, msg: all))
        #expect(Result { () throws(VQError) in try tooBig.toJSON() }.errorCode == "message_too_large")
    }

    @Test func base64AndUUIDPublicAPIEdges() {
        #expect(Base64.decode("", length: 0) == [])
        #expect(Base64.decode("", length: -1) == nil)
        #expect(Base64.decode("====", length: 1) == nil)
        #expect(Base64.decode("AA==", length: 1) == [0])
        #expect(Base64.decode("AB==", length: 1) == nil)
        #expect(Base64.decode32(String(repeating: "A", count: 43) + "=") != nil)
        #expect(Base64.decode32(String(repeating: "A", count: 43) + "B") == nil)
        #expect(Base64.decode32(String(repeating: "A", count: 42) + "==") == nil)
        #expect(Base64.decode32(String(repeating: "A", count: 42) + "B=") == nil)
        #expect(Base64.decode32(String(repeating: "Ａ", count: 43) + "=") == nil)
        #expect(Bytes32([UInt8](repeating: 0, count: 31)) == nil)
        #expect(Bytes32([UInt8](repeating: 0, count: 33)) == nil)
        #expect(UUIDText.parse("0f8fad5b-d9cb-469f-a165-70867728950\u{0301}") == nil)
        #expect(UUIDText.parse("０f8fad5b-d9cb-469f-a165-70867728950e") == nil)
    }

    /// FINDING candidate: `Base64.decode(_:length:)` is public and computes
    /// `(length + 2) / 3 * 4` with trapping arithmetic. Any `length` above
    /// roughly `Int.max / 4 * 3` overflows and crashes the process instead of
    /// returning `nil`. Run in a child process so the trap is observable.
    @Test func base64DecodeHugeLengthDoesNotTrap() async {
        await #expect(processExitsWith: .success) {
            _ = Base64.decode("", length: Int.max)
        }
        await #expect(processExitsWith: .success) {
            _ = Base64.decode("AAAA", length: Int.max / 4 * 3 + 10)
        }
    }

    @Test func pairingCodeAPIEdges() {
        #expect(PairingCode(value: 999_999)?.string == "999999")
        #expect(PairingCode(value: 1_000_000) == nil)
        #expect(PairingCode(value: .max) == nil)
        #expect(PairingCode(value: 0)?.string == "000000")
        #expect(IdentityKeyPair(secretBytes: [UInt8](repeating: 1, count: 31)) == nil)
        #expect(IdentityKeyPair(secretBytes: [UInt8](repeating: 1, count: 33)) == nil)
        #expect(IdentityKeyPair(secretBytes: [UInt8]()) == nil)
    }
}

// MARK: - performance

@Suite("Adversary: 64 KiB decode time")
struct AdversaryPerformanceTests {
    static func inputs() -> [(String, [UInt8])] {
        let budget = 65_536 - 32
        func obj(_ body: String) -> [UInt8] { Array(("{\"t\":\"ping\",\"x\":" + body + "}").utf8) }
        var v: [(String, [UInt8])] = []
        v.append(("u-escapes", obj("\"" + String(repeating: "\\u0041", count: budget / 6) + "\"")))
        v.append(("surrogate pairs", obj("\"" + String(repeating: "\\ud83d\\ude00", count: budget / 12) + "\"")))
        v.append(("short escapes", obj("\"" + String(repeating: "\\n", count: budget / 2) + "\"")))
        v.append(("multibyte", obj("\"" + String(repeating: "😀", count: budget / 4) + "\"")))
        v.append(("one huge number", obj(String(repeating: "1", count: budget))))
        v.append(("huge fraction", obj("0." + String(repeating: "1", count: budget))))
        v.append(("huge exponent", obj("1e" + String(repeating: "0", count: budget))))
        v.append(("many numbers", obj("[" + Array(repeating: "1.5e300", count: budget / 8).joined(separator: ",") + "]")))
        v.append(("many tiny numbers", obj("[" + Array(repeating: "1", count: budget / 2).joined(separator: ",") + "]")))
        var keys: [String] = []
        var n = 0
        var len = 0
        while len < budget - 20 {
            let k = "\"k\(n)\":0"
            keys.append(k)
            len += k.count + 1
            n += 1
        }
        v.append(("many nested keys", obj("{" + keys.joined(separator: ",") + "}")))
        v.append(("many top-level keys", Array(("{\"t\":\"ping\"," + keys.joined(separator: ",") + "}").utf8)))
        let longKey = String(repeating: "a", count: budget / 2 - 20)
        v.append(("two long near-equal keys", Array(("{\"t\":\"ping\",\"" + longKey + "b\":0,\"" + longKey + "c\":0}").utf8)))
        v.append(("many empty objects", obj("[" + Array(repeating: "{}", count: budget / 3).joined(separator: ",") + "]")))
        v.append(("depth-32 repeated", obj("[" + Array(repeating: String(repeating: "[", count: 30) + String(repeating: "]", count: 30),
                                                        count: budget / 62).joined(separator: ",") + "]")))
        v.append(("whitespace", Array(("{\"t\":\"ping\"" + String(repeating: " ", count: budget) + "}").utf8)))
        v.append(("long unknown t", Array(("{\"t\":\"" + String(repeating: "z", count: budget) + "\"}").utf8)))
        v.append(("long utt text", Array(("{\"t\":\"utt\",\"id\":\"0f8fad5b-d9cb-469f-a165-70867728950e\",\"rev\":1,\"state\":\"final\",\"ts\":1,\"text\":\""
                                          + String(repeating: "\\u0001", count: 5_000) + "\"}").utf8)))
        v.append(("all invalid at end", Array(String(repeating: "[1,", count: budget / 3).utf8)))
        v.append(("hello unsupported long name", Array(("{\"t\":\"hello\",\"v\":2,\"name\":\"" + String(repeating: "\\u00e9", count: budget / 6) + "\"}").utf8)))
        v.append(("utf8 2-byte", obj("\"" + String(repeating: "é", count: budget / 2) + "\"")))
        return v
    }

    @Test func every64KiBInputDecodesUnder200ms() {
        var slow: [String] = []
        for (name, b) in Self.inputs() {
            let body = Array(b.prefix(65_535))
            var r1 = ""
            let t1 = timeMs { r1 = decodeCode(body) }
            let env = [UInt8(0)] + body
            let t2 = timeMs { _ = try? decodeInbound(env, session: nil) }
            print("[adversary] perf \(name): \(body.count) B, fromJSON \(String(format: "%.1f", t1)) ms, decodeInbound \(String(format: "%.1f", t2)) ms -> \(r1.prefix(24))")
            if t1 >= 200 || t2 >= 200 { slow.append("\(name): \(Int(t1)) / \(Int(t2)) ms") }
        }
        #expect(slow.isEmpty, "slow: \(slow)")
    }

    @Test func framingAndCryptoUnder200ms() throws {
        let msg = [UInt8](repeating: 0x41, count: 65_536)
        var s = FrameSplitter()
        var frames: [[UInt8]] = []
        let t1 = timeMs { frames = (try? s.split(msg, mtu: 20)) ?? [] }
        var r = Reassembler()
        var out: [UInt8]?
        let t2 = timeMs { for f in frames { out = (try? r.push(f)) ?? out } }
        #expect(out == msg)
        let c = SessionCipher(rawKeyForTests: advKey, role: .phone)
        let d = SessionCipher(rawKeyForTests: advKey, role: .desktop)
        var env: [UInt8] = []
        let t3 = timeMs { env = (try? c.seal([UInt8](repeating: 0x20, count: 65_511))) ?? [] }
        let t4 = timeMs { _ = try? d.open(env) }
        print("[adversary] perf split \(t1) reassemble \(t2) seal \(t3) open \(t4) ms")
        #expect(t1 < 200 && t2 < 200 && t3 < 200 && t4 < 200)
    }
}

// MARK: - crypto / API misuse

@Suite("Adversary: crypto and session misuse")
struct AdversaryCryptoTests {
    func pair() -> (SessionCipher, SessionCipher) {
        (SessionCipher(rawKeyForTests: advKey, role: .phone), SessionCipher(rawKeyForTests: advKey, role: .desktop))
    }

    @Test func replayAndReorder() throws {
        let (p, d) = pair()
        let e0 = try p.seal(Array("{\"t\":\"ping\"}".utf8))
        let e1 = try p.seal(Array("{\"t\":\"pong\"}".utf8))
        let e2 = try p.seal(Array("{\"t\":\"ping\"}".utf8))
        _ = try d.open(e1)
        #expect(Result { () throws(VQError) in try d.open(e0) }.errorCode == "replay")
        #expect(Result { () throws(VQError) in try d.open(e1) }.errorCode == "replay")
        _ = try d.open(e2)
        #expect(Result { () throws(VQError) in try d.open(e2) }.errorCode == "replay")
        #expect(d.lastReceivedCounter == 2)
        // via decodeInbound too, and the window does not move on failure
        #expect(Result { () throws(VQError) in try decodeInbound(e0, session: d) }.errorCode == "replay")
        #expect(d.lastReceivedCounter == 2)
    }

    @Test func tamperEveryByteOfEveryEnvelope() throws {
        let (p, _) = pair()
        for json in ["{\"t\":\"ping\"}", "", "{\"t\":\"utt\",\"id\":\"0f8fad5b-d9cb-469f-a165-70867728950e\",\"rev\":0,\"state\":\"final\",\"text\":\"hi\",\"ts\":0}"] {
            let env = try p.seal(Array(json.utf8))
            for i in 0..<env.count {
                for bit in [0x01, 0x80] as [UInt8] {
                    var x = env
                    x[i] ^= bit
                    let d = SessionCipher(rawKeyForTests: advKey, role: .desktop)
                    let r = Result { () throws(VQError) in try decodeInbound(x, session: d) }
                    #expect(r.errorCode != nil, "byte \(i) bit \(bit) accepted")
                    #expect(d.lastReceivedCounter == nil, "byte \(i) moved the window")
                }
            }
            // truncation and extension
            for cut in 0..<env.count {
                let d = SessionCipher(rawKeyForTests: advKey, role: .desktop)
                #expect((try? d.open(Array(env.prefix(cut)))) == nil)
            }
            let d = SessionCipher(rawKeyForTests: advKey, role: .desktop)
            #expect(Result { () throws(VQError) in try d.open(env + [0]) }.errorCode == "decrypt_failed")
        }
    }

    @Test func crossDirectionAndReflection() throws {
        let (p, d) = pair()
        let e = try p.seal(Array("{\"t\":\"ping\"}".utf8))
        // reflected back to the sender
        #expect(Result { () throws(VQError) in try p.open(e) }.errorCode == "decrypt_failed")
        #expect(p.lastReceivedCounter == nil)
        let back = try d.seal(Array("{\"t\":\"pong\"}".utf8))
        #expect(Result { () throws(VQError) in try d.open(back) }.errorCode == "decrypt_failed")
        _ = try p.open(back)
        _ = try d.open(e)
        // wrong key entirely
        let other = SessionCipher(rawKeyForTests: [UInt8](repeating: 0, count: 32), role: .desktop)
        #expect(Result { () throws(VQError) in try other.open(e) }.errorCode == "decrypt_failed")
        // plaintext envelope to open()
        #expect(Result { () throws(VQError) in try d.open([0] + Array("{\"t\":\"ping\"}".utf8)) }.errorCode == "unknown_envelope_kind")
    }

    @Test func counterExhaustionAndMaxCounterReceive() throws {
        let (p, d) = pair()
        p.advanceSendCounterForTests(to: .max - 1)
        let a = try p.seal([1])
        let b = try p.seal([2])
        #expect(p.nextSendCounter == nil)
        #expect(Result { () throws(VQError) in try p.seal([3]) }.errorCode == "counter_exhausted")
        #expect(Result { () throws(VQError) in try p.sealMessage(.ping) }.errorCode == "counter_exhausted")
        #expect(Result { () throws(VQError) in try p.sealMessage(.unknown(t: "x")) }.errorCode == "not_encodable")
        #expect(Array(b[1..<9]) == [UInt8](repeating: 0xFF, count: 8))
        #expect(try d.open(b) == [2])
        #expect(d.lastReceivedCounter == .max)
        #expect(Result { () throws(VQError) in try d.open(a) }.errorCode == "replay")
        #expect(Result { () throws(VQError) in try d.open(b) }.errorCode == "replay")
    }

    @Test func wrongLengthAndForgedMACs() throws {
        let k = [UInt8](repeating: 7, count: 32)
        let pp = Bytes32(repeating: 1), pd = Bytes32(repeating: 2)
        let mac = phoneConfirmMacForTests(kPair: k, pubPhone: pp, pubDesktop: pd)
        try verifyPhoneConfirmMacForTests(kPair: k, pubPhone: pp, pubDesktop: pd, mac: mac)
        for i in 0..<32 {
            var m = mac.bytes
            m[i] ^= 1
            #expect(code { () throws(VQError) in
                try verifyPhoneConfirmMacForTests(kPair: k, pubPhone: pp, pubDesktop: pd, mac: Bytes32(m)!)
            } == "bad_mac")
        }
        // the desktop MAC is not accepted as a phone MAC (label binding), nor with swapped keys
        let dmac = desktopResultMacForTests(kPair: k, pubPhone: pp, pubDesktop: pd)
        #expect(code { () throws(VQError) in try verifyPhoneConfirmMacForTests(kPair: k, pubPhone: pp, pubDesktop: pd, mac: dmac) } == "bad_mac")
        #expect(code { () throws(VQError) in try verifyPhoneConfirmMacForTests(kPair: k, pubPhone: pd, pubDesktop: pp, mac: mac) } == "bad_mac")
        // wrong-length MACs on the wire
        for n in [0, 16, 31, 33, 48, 64] {
            let b64 = Base64.encode([UInt8](repeating: 9, count: n))
            #expect(decodeCode("{\"t\":\"pair_confirm\",\"mac\":\"\(b64)\"}") == "err:invalid_message", "\(n)")
            #expect(decodeCode("{\"t\":\"pair_result\",\"ok\":true,\"mac\":\"\(b64)\"}") == "err:invalid_message", "\(n)")
        }
        #expect(decodeCode("{\"t\":\"pair_result\",\"ok\":false,\"mac\":\"x\"}").hasPrefix("ok:"))
        #expect(decodeCode("{\"t\":\"pair_result\",\"ok\":true,\"mac\":null}") == "err:invalid_message")
    }

    static let lowOrder: [String] = [
        "0000000000000000000000000000000000000000000000000000000000000000",
        "0100000000000000000000000000000000000000000000000000000000000000",
        "e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800",
        "5f9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f1157",
        "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
        "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
        "eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
    ]

    @Test func lowOrderPointsRejectedEverywhere() throws {
        let me = IdentityKeyPair.generate()
        for h in Self.lowOrder {
            for hb in [false, true] {
                var b = advUnhex(Substring(h))
                if hb { b[31] |= 0x80 }
                let pub = Bytes32(b)!
                #expect(code { () throws(VQError) in try me.sharedSecret(peerPublic: pub) } == "non_contributory", "\(advHex(b))")
                #expect(code { () throws(VQError) in
                    try PairKey.derive(identity: me, ownRole: .desktop, peerPublic: pub, request: .generate(),
                                       challenge: .generate(), code: PairingCode(value: 1)!)
                } == "non_contributory")
                #expect(code { () throws(VQError) in
                    try SessionCipher.establish(identity: me, role: .phone, peerPublic: pub,
                                                ownNonce: SessionNonce.generate(), peerNonce: Bytes32(repeating: 0))
                } == "non_contributory")
            }
        }
    }

    @Test func pairingCodeStrictness() {
        let bad = ["12345", "1234567", " 123456", "123456 ", "+12345", "-12345", "12 456", "１２３４５６", "١٢٣٤٥٦",
                   "۱۲۳۴۵۶", "१२३४५६", "12345\u{661}", "12345\n", "\t12345", "0x1234", "¹²³⁴⁵⁶", "12345\u{0}",
                   "123456\u{0}", "", "abcdef", "12.456", "1e5", "123456\u{301}", "\u{FEFF}123456", "12345６",
                   "+123456", "-123456", "①②③④⑤⑥", "𝟏𝟐𝟑𝟒𝟓𝟔"]
        for s in bad {
            #expect(code { () throws(VQError) in try PairingCode(parsing: s) } == "invalid_code", "\(s.debugDescription)")
        }
        for (s, v) in [("000000", 0), ("999999", 999_999), ("004217", 4217)] as [(String, UInt32)] {
            #expect((try? PairingCode(parsing: s))?.value == v)
        }
        // A String backed by NSString (UTF-16 storage) behaves the same.
        let ns = NSString(string: "１２３４５６") as String
        #expect(code { () throws(VQError) in try PairingCode(parsing: ns) } == "invalid_code")
        let ok = NSString(string: "123456") as String
        #expect((try? PairingCode(parsing: ok))?.value == 123_456)
    }

    @Test func inSessionPolicyBypassAttempts() throws {
        let (p, d) = pair()
        // hello / pairing types inside an encrypted envelope are rejected by checkInSession
        for t in ["{\"t\":\"hello\",\"v\":7}", "{\"t\":\"pair_result\",\"ok\":false}",
                  "{\"t\":\"pair_request\",\"nonce_p\":\"" + Bytes32(repeating: 0).base64 + "\"}"] {
            let inbound = try decodeInbound(try p.seal(Array(t.utf8)), session: d)
            #expect(inbound.isAuthenticated)
            #expect(code { () throws(VQError) in try checkInSession(inbound) } == "not_allowed_in_session")
        }
        // utt in plaintext is refused before any field is validated, even with junk fields
        let junk = "{\"t\":\"utt\",\"id\":5,\"text\":" + String(repeating: "[", count: 2) + "]]}"
        #expect(Result { () throws(VQError) in try decodeInbound([0] + Array(junk.utf8), session: d) }.errorCode == "plaintext_not_allowed")
        // ...but whole-document JSON errors still come first
        #expect(Result { () throws(VQError) in try decodeInbound([0] + Array("{\"t\":\"utt\",\"t\":\"utt\"}".utf8), session: d) }.errorCode == "invalid_json")
        // escaped type names are the same type
        #expect(Result { () throws(VQError) in try decodeInbound([0] + Array("{\"t\":\"\\u0075tt\"}".utf8), session: d) }.errorCode == "plaintext_not_allowed")
        #expect(Result { () throws(VQError) in try decodeInbound([0] + Array("{\"t\":\"p\\u0069ng\"}".utf8), session: nil) }.errorCode == "plaintext_not_allowed")
        // encrypted without a session
        let e = try p.seal(Array("{\"t\":\"ping\"}".utf8))
        #expect(Result { () throws(VQError) in try decodeInbound(e, session: nil) }.errorCode == "no_session")
    }
}
