import Foundation
import Testing
@testable import VQProtocol

let uid = UUID(uuidString: "0f8fad5b-d9cb-469f-a165-70867728950e")!

func utt(_ text: String, rev: UInt32 = 3, state: UttState = .final) -> Message {
    .utt(Utt(id: uid, rev: rev, state: state, text: text, ts: 1_700_000_000_000))
}

/// The error code `body` throws, or `nil` if it succeeds.
func code<T>(_ body: () throws -> T) -> String? {
    do {
        _ = try body()
        return nil
    } catch let e as VQError {
        return e.code
    } catch {
        return "unexpected error type: \(error)"
    }
}

@Suite("messages")
struct MessageTests {
    static let allEncodable: [Message] = [
        .hello(Hello(deviceId: uid, name: "Jon's iPhone", publicKey: Bytes32(repeating: 7), paired: true,
                     sessionNonce: Bytes32(repeating: 9))),
        .pairRequest(PairRequest(nonceP: Bytes32(repeating: 1))),
        .pairChallenge(PairChallenge(nonceD: Bytes32(repeating: 2))),
        .pairConfirm(PairConfirm(mac: Bytes32(repeating: 3))),
        .pairResult(.success(Bytes32(repeating: 4))),
        .pairResult(.failure()),
        .error(ErrorMsg(code: "version", msg: "upgrade")),
        utt("hello \"world\"\n\u{1F600}\u{0}"),
        .ack(Ack(id: uid, rev: .max)),
        .ping,
        .pong,
    ]

    @Test func roundtripAll() throws {
        for m in Self.allEncodable {
            let j = try m.toJSON()
            #expect(j.starts(with: Array(#"{"t":""#.utf8)), "\(String(decoding: j, as: UTF8.self))")
            #expect(try Message.fromJSON(j) == m)
        }
    }

    @Test func exactEncodings() throws {
        #expect(try Message.ping.toJSON() == Array(#"{"t":"ping"}"#.utf8))
        #expect(try Message.pairResult(.failure()).toJSON() == Array(#"{"t":"pair_result","ok":false}"#.utf8))
        #expect(try String(decoding: utt("x").toJSON(), as: UTF8.self)
            == #"{"t":"utt","id":"0f8fad5b-d9cb-469f-a165-70867728950e","rev":3,"state":"final","text":"x","ts":1700000000000}"#)
        #expect(try String(decoding: utt("/\u{7F}\u{1}\u{1F}\u{8}\u{C}é").toJSON(), as: UTF8.self)
            .contains(#""text":"/\#u{7F}\u0001\u001f\b\fé""#))
    }

    @Test func unknownTypesAndFields() throws {
        #expect(try Message.fromJSON(Array(#"{"t":"future","x":1}"#.utf8)) == .unknown(t: "future"))
        #expect(try Message.fromJSON(Array(#"{"t":"ping","extra":[1,2,{}]}"#.utf8)) == .ping)
        #expect(!Message.unknown(t: "hello").isPlaintextAllowed)
        #expect(code { try Message.unknown(t: "x").toJSON() } == "not_encodable")
        #expect(code { try Message.helloUnsupported(HelloUnsupported(v: 2, name: nil)).toJSON() } == "not_encodable")
    }

    @Test func invalidShapes() {
        for (j, want) in [
            ("not json", "invalid_json"), ("", "invalid_json"), ("[]", "invalid_message"),
            ("\"ping\"", "invalid_message"), ("{}", "invalid_message"), (#"{"t":5}"#, "invalid_message"),
            (#"{"t":null}"#, "invalid_message"), (#"{"t":"ack","rev":1}"#, "invalid_message"),
            (#"{"t":"ack","id":"0f8fad5b-d9cb-469f-a165-70867728950e","rev":-1}"#, "invalid_message"),
            (#"{"t":"ack","id":"0f8fad5b-d9cb-469f-a165-70867728950e","rev":4294967296}"#, "invalid_message"),
            (#"{"t":"ack","id":"0f8fad5b-d9cb-469f-a165-70867728950e","rev":1.5}"#, "invalid_message"),
            (#"{"t":"pair_result","ok":true}"#, "invalid_message"),
            (#"{"t":"pair_request","nonce_p":"AAAA"}"#, "invalid_message"),
            (#"{"t":"hello","v":"1"}"#, "invalid_message"), (#"{"t":"hello"}"#, "invalid_message"),
            (#"{"t":"hello","v":1}"#, "invalid_message"), (#"{"t":"ping"} x"#, "invalid_json"),
        ] {
            #expect(code { try Message.fromJSON(Array(j.utf8)) } == want, "\(j)")
        }
        #expect(code { try Message.fromJSON([0xFF, 0xFE]) } == "invalid_json")
    }

    @Test func helloVersionMismatch() throws {
        let m = try Message.fromJSON(Array(#"{"t":"hello","v":2,"name":"Mac"}"#.utf8))
        #expect(m == .helloUnsupported(HelloUnsupported(v: 2, name: "Mac")))
        #expect(m.isPlaintextAllowed)
        #expect(m.typeName == "hello")
        var h = Hello(deviceId: uid, name: "a", publicKey: Bytes32(repeating: 1), paired: false,
                      sessionNonce: Bytes32(repeating: 2))
        h.v = 2
        #expect(code { try Message.hello(h).toJSON() } == "not_encodable")
    }

    @Test func pairResultNormalization() throws {
        for mac in [#""garbage""#, "123", "{}", "[]", "true", #""AAAA""#, "null",
                    #""AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=""#] {
            let j = #"{"t":"pair_result","ok":false,"mac":\#(mac)}"#
            #expect(try Message.fromJSON(Array(j.utf8)) == .pairResult(.failure()), "\(j)")
        }
        #expect(code { try Message.pairResult(PairResult(ok: false, mac: Bytes32(repeating: 0))).toJSON() } == "not_encodable")
        #expect(code { try Message.pairResult(PairResult(ok: true, mac: nil)).toJSON() } == "not_encodable")
    }

    @Test func textLimits() throws {
        #expect(throws: Never.self) { try utt(String(repeating: "a", count: VQ.maxTextBytes)).toJSON() }
        #expect(result { () throws(VQError) in try utt(String(repeating: "a", count: 32_001)).toJSON() }
            == .failure(.textTooLong(32_001)))
        let emoji = String(repeating: "\u{1F600}", count: 8000)
        #expect(throws: Never.self) { try utt(emoji).toJSON() }
        #expect(code { try utt(emoji + "a").toJSON() } == "text_too_long")
        let long = String(repeating: "a", count: 32_001)
        let j = #"{"t":"utt","id":"0f8fad5b-d9cb-469f-a165-70867728950e","rev":0,"state":"partial","text":"\#(long)","ts":0}"#
        #expect(code { try Message.fromJSON(Array(j.utf8)) } == "text_too_long")
        let nl = String(repeating: "\\n", count: VQ.maxTextBytes)
        let j2 = #"{"t":"utt","id":"0f8fad5b-d9cb-469f-a165-70867728950e","rev":0,"state":"partial","text":"\#(nl)","ts":0}"#
        #expect(throws: Never.self) { try Message.fromJSON(Array(j2.utf8)) }
    }

    @Test func messageSizeLimit() throws {
        #expect(code { try utt(String(repeating: "\u{1}", count: VQ.maxTextBytes)).toJSON() } == "message_too_large")
        var big = Array(#"{"t":"ping","pad":""#.utf8)
        big += [UInt8](repeating: UInt8(ascii: "a"), count: VQ.maxMessageBytes - 2 - big.count)
        big += Array("\"}".utf8)
        #expect(big.count == VQ.maxMessageBytes)
        #expect(try Message.fromJSON(big) == .ping)
        big.insert(UInt8(ascii: "a"), at: big.count - 2)
        #expect(code { try Message.fromJSON(big) } == "message_too_large")
    }

    @Test func plaintextAllowedSet() {
        #expect(Self.allEncodable.map(\.isPlaintextAllowed)
            == [true, true, true, true, true, true, true, false, false, false, false])
        #expect(knownTypes.count == 10)
        #expect(isKnownType("ping") && !isKnownType("PING") && !isKnownType("typing"))
    }

    @Test func uuidCaseInsensitiveLowercaseEmit() throws {
        let m = try Message.fromJSON(Array(#"{"t":"ack","id":"0F8FAD5B-D9CB-469F-A165-70867728950E","rev":1}"#.utf8))
        #expect(String(decoding: try m.toJSON(), as: UTF8.self).contains("0f8fad5b-d9cb-469f-a165-70867728950e"))
    }

    @Test func helloNewDrawsFreshNonces() throws {
        let pub = Bytes32(repeating: 1)
        let a = Hello.new(deviceId: uid, name: "a", publicKey: pub, paired: false)
        let b = Hello.new(deviceId: uid, name: "a", publicKey: pub, paired: false)
        #expect(a.hello.v == VQ.protocolVersion)
        #expect(a.hello.sessionNonce == a.nonce.bytes)
        #expect(a.nonce.bytes != b.nonce.bytes)
        #expect(a.hello.sessionNonce != b.hello.sessionNonce)
        #expect(throws: Never.self) { try Message.hello(a.hello).toJSON() }
    }

    @Test func integerRules() throws {
        func ack(_ rev: String) -> [UInt8] {
            Array(#"{"t":"ack","id":"0f8fad5b-d9cb-469f-a165-70867728950e","rev":\#(rev)}"#.utf8)
        }
        for bad in ["-0", "1.0", "1e0", "0e0", "-0.0", "4294967296", "1E2", "\"1\"", "true", "null"] {
            #expect(code { try Message.fromJSON(ack(bad)) } == "invalid_message", "\(bad)")
        }
        for bad in ["1e400", "-1e400"] {
            #expect(code { try Message.fromJSON(ack(bad)) } == "invalid_json", "\(bad)")
        }
        #expect(code { try Message.fromJSON(Array(#"{"t":"hello","v":-0}"#.utf8)) } == "invalid_message")
        #expect(code { try Message.fromJSON(Array(#"{"t":"hello","v":18446744073709551616}"#.utf8)) } == "invalid_message")
        #expect(try Message.fromJSON(Array(#"{"t":"hello","v":18446744073709551615}"#.utf8))
            == .helloUnsupported(HelloUnsupported(v: .max, name: nil)))
        // ts decodes exactly at the top of the u64 range (no Double round trip).
        let j = #"{"t":"utt","id":"0f8fad5b-d9cb-469f-a165-70867728950e","rev":0,"state":"final","text":"","ts":18446744073709551615}"#
        guard case .utt(let u)? = try? Message.fromJSON(Array(j.utf8)) else {
            Issue.record("utt did not decode")
            return
        }
        #expect(u.ts == .max)
        let j2 = #"{"t":"utt","id":"0f8fad5b-d9cb-469f-a165-70867728950e","rev":0,"state":"final","text":"","ts":9007199254740993}"#
        guard case .utt(let u2)? = try? Message.fromJSON(Array(j2.utf8)) else {
            Issue.record("utt did not decode")
            return
        }
        #expect(u2.ts == 9_007_199_254_740_993) // 2^53 + 1: not representable as a Double
        #expect(try Message.fromJSON(Array(#"{"t":"error","code":"x","msg":null}"#.utf8)) == .error(ErrorMsg(code: "x")))
        #expect(code { try Message.fromJSON(Array(#"{"t":"error","code":"x","msg":5}"#.utf8)) } == "invalid_message")
    }

    @Test func errorDescriptionIsBounded() {
        let long = String(repeating: "z", count: 50_000)
        for j in [
            #"{"t":"ack","id":"\#(long)","rev":1}"#,
            #"{"t":"pair_request","nonce_p":"\#(long)"}"#,
            #"{"t":"utt","id":"0f8fad5b-d9cb-469f-a165-70867728950e","rev":1,"state":"\#(long)","text":"","ts":0}"#,
        ] {
            let r = result { () throws(VQError) in try Message.fromJSON(Array(j.utf8)) }
            guard case .failure(let e) = r else {
                Issue.record("should fail")
                continue
            }
            #expect(e.description.count < 300, "\(e.description.count)")
        }
        #expect(VQError.plaintextNotAllowed(long).description.count < 300)
    }

    @Test func escapedLengthMatchesEncoder() throws {
        let base = try Message.utt(Utt(id: uid, rev: 0, state: .edit, text: "", ts: 0)).toJSON().count
        var samples = (0..<0x80).map { String(Character(Unicode.Scalar(UInt8($0)))) }
        samples += ["\u{7F}", "\u{2028}", "é", "日", "\u{1F600}", "/", "a\"b\\c\u{1}\n", "e\u{301}"]
        for t in samples {
            let n = try Message.utt(Utt(id: uid, rev: 0, state: .edit, text: t, ts: 0)).toJSON().count
            #expect(n - base == escapedLength(t), "\(t.debugDescription)")
        }
    }

    @Test func uttSizingHelpers() throws {
        let worst = Utt(id: uid, rev: .max, state: .partial, text: "", ts: .max)
        #expect(try Message.utt(worst).toJSON().count == VQ.uttMaxOverheadBytes)
        #expect(uttTextFits(""))
        #expect(uttTextFits(String(repeating: "a", count: VQ.maxTextBytes)))
        #expect(!uttTextFits(String(repeating: "a", count: VQ.maxTextBytes + 1)))
        #expect(uttTextFits(String(repeating: "\"", count: VQ.maxTextBytes)))
        let ctl = String(repeating: "\u{1}", count: VQ.maxTextBytes)
        #expect(!uttTextFits(ctl))
        let p = maxTextPrefix(ctl)
        #expect(p.utf8.count == 10_897)
        #expect(uttTextFits(p))
        #expect(!uttTextFits(p + "\u{1}"))
        var u = worst
        u.text = p
        let tx = SessionCipher(rawKeyForTests: [UInt8](repeating: 0, count: 32), role: .phone)
        #expect(throws: Never.self) { try tx.sealMessage(.utt(u)) }
        // Cut at scalar boundaries.
        #expect(maxTextPrefix(String(repeating: "\u{1F600}", count: 8001)).utf8.count == VQ.maxTextBytes)
        #expect(maxTextPrefix("abc") == "abc")
        #expect(maxTextPrefix(String(repeating: "a", count: VQ.maxTextBytes - 2) + "\u{1F600}").utf8.count
            == VQ.maxTextBytes - 2)
        // A combining mark may be split from its base (scalar, not grapheme, boundary — same as Rust chars).
        let combining = String(repeating: "a", count: VQ.maxTextBytes - 1) + "e\u{301}"
        #expect(maxTextPrefix(combining).utf8.count == VQ.maxTextBytes)
    }
}

@Suite("encodings")
struct EncodingTests {
    @Test func base64RoundtripAndStrictness() {
        let k = Bytes32(repeating: 0xAB)
        let s = k.base64
        #expect(s.utf8.count == 44 && s.hasSuffix("="))
        #expect(Base64.decode32(s) == k)
        #expect(Base64.encode([UInt8]()) == "")
        #expect(Base64.encode([0x66]) == "Zg==")
        #expect(Base64.encode([0x66, 0x6F]) == "Zm8=")
        #expect(Base64.encode(Array("foobar".utf8)) == "Zm9vYmFy")
        #expect(Base64.decode("Zg==", length: 1) == [0x66])
        #expect(Base64.decode("Zh==", length: 1) == nil) // non-zero trailing bits
        #expect(Base64.decode("Zm8=", length: 2) == [0x66, 0x6F])
        #expect(Base64.decode("Zm9=", length: 2) == nil)
        #expect(Base64.decode32(String(s.dropLast())) == nil)
        #expect(Base64.decode32(Base64.encode([UInt8](repeating: 0, count: 31))) == nil)
        #expect(Base64.decode32(Base64.encode([UInt8](repeating: 0, count: 33))) == nil)
        let urlsafe = Bytes32(repeating: 0xFB).base64.replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
        #expect(Base64.decode32(urlsafe) == nil)
        #expect(Base64.decode32(" " + s) == nil)
        let zeros = Bytes32(repeating: 0).base64
        #expect(zeros.hasSuffix("A="))
        #expect(Base64.decode32(String(zeros.dropLast(2)) + "B=") == nil)
        #expect(Base64.decode32(String(zeros.dropLast(2)) + "E=") != nil) // E = 000100: low 2 bits zero
        #expect(Base64.decode32(String(zeros.dropLast(2)) + "==") == nil)
        #expect(Base64.decode32(String(zeros.dropLast(1)) + "A") == nil)
        #expect(Base64.decode32("\u{00E9}" + String(zeros.dropFirst(2))) == nil)
    }

    @Test func uuidParsing() {
        let u = UUIDText.parse("1A2B3C4D-0000-4000-8000-00000000000F")
        #expect(u.map(UUIDText.format) == "1a2b3c4d-0000-4000-8000-00000000000f")
        for bad in [
            "1a2b3c4d000040008000000000000000", "{1a2b3c4d-0000-4000-8000-00000000000f}",
            "urn:uuid:1a2b3c4d-0000-4000-8000-00000000000f", "1a2b3c4d-0000-4000-8000-00000000000g", "",
            "1a2b3c4d-0000-4000-8000-00000000000", "1a2b3c4d-0000-4000-8000-00000000000f0",
            "1a2b3c4d00000-4000-8000-00000000000f", " 1a2b3c4d-0000-4000-8000-00000000000",
            "1a2b3c4d-0000-4000-8000-0000000000\u{FF10}",
        ] {
            #expect(UUIDText.parse(bad) == nil, "\(bad)")
        }
        // Version and variant nibbles are not checked.
        #expect(UUIDText.parse("00000000-0000-0000-0000-000000000000") != nil)
    }

    @Test func constants() {
        #expect(VQ.maxMessageBytes == 64 * 1024)
        #expect(VQ.maxEncryptedJSONBytes == 65_511)
        #expect(VQ.maxEncryptedJSONBytes == VQ.maxMessageBytes - Envelope.minEncryptedBytes)
        #expect(VQ.minMTU > VQ.frameHeaderBytes)
        #expect(UUIDText.format(VQ.serviceUUID) == "77608b26-7b68-49da-bb34-7f05d158e219")
        #expect(UUIDText.format(VQ.rxCharacteristicUUID) == "18489603-21ac-4cf2-9d31-62bd5d9c1635")
        #expect(UUIDText.format(VQ.txCharacteristicUUID) == "b01127eb-8819-42a7-a0e8-bdd6159d4e2a")
        let all = [VQ.serviceUUID, VQ.rxCharacteristicUUID, VQ.txCharacteristicUUID]
        #expect(Set(all).count == 3)
        for u in all { #expect(u.uuid.6 >> 4 == 4) }
    }

    @Test func errorCodesAreTheRustCodes() {
        let all: [VQError] = [
            .mtuTooSmall(1), .frameTooShort, .reservedFlags(4), .orphanFrame, .seqMismatch(expected: 1, got: 2),
            .messageTooLarge(1), .textTooLong(1), .invalidJSON(""), .invalidMessage(""), .notEncodable(""),
            .emptyEnvelope, .unknownEnvelopeKind(2), .envelopeTooShort(1), .decryptFailed,
            .replay(counter: 1, last: 1), .counterExhausted, .plaintextNotAllowed(""), .noSession,
            .notAllowedInSession(""), .nonContributory, .invalidCode, .badMac,
        ]
        #expect(all.map(\.code) == [
            "mtu_too_small", "frame_too_short", "reserved_flags", "orphan_frame", "seq_mismatch",
            "message_too_large", "text_too_long", "invalid_json", "invalid_message", "not_encodable",
            "empty_envelope", "unknown_envelope_kind", "envelope_too_short", "decrypt_failed", "replay",
            "counter_exhausted", "plaintext_not_allowed", "no_session", "not_allowed_in_session",
            "non_contributory", "invalid_code", "bad_mac",
        ])
    }
}
