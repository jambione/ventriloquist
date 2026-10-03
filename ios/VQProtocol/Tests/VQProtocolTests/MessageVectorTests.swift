import Foundation
import Testing
@testable import VQProtocol

/// The decode input: exactly one of `json`, `json_hex` or `json_fill`.
func messageInput(_ c: JV) -> [UInt8] {
    let forms = ["json", "json_hex", "json_fill"].filter { c.has($0) }
    precondition(forms.count == 1, "exactly one input form expected, got \(forms)")
    if c.has("json") { return Array(c["json"].str.utf8) }
    if c.has("json_hex") { return bytes(c["json_hex"]) }
    let f = c["json_fill"]
    let s = f["prefix"].str + String(repeating: f["fill"].str, count: f["count"].int) + f["suffix"].str
    return Array(s.utf8)
}

/// Build a message (possibly not encodable) from a vector's wire-form object;
/// `text_fill` supplies `utt.text`.
func messageFromObject(_ o: JV, textFill: JV?) -> Message {
    func uuid(_ k: String) -> UUID { UUIDText.parse(o[k].str)! }
    func b(_ k: String) -> Bytes32 { Base64.decode32(o[k].str)! }
    switch o["t"].str {
    case "utt":
        let text = textFill.map { String(repeating: $0["fill"].str, count: $0["count"].int) } ?? o["text"].str
        return .utt(Utt(id: uuid("id"), rev: UInt32(o["rev"].u64), state: UttState(rawValue: o["state"].str)!,
                        text: text, ts: o["ts"].u64))
    case "hello":
        return .hello(Hello(v: UInt32(o["v"].u64), deviceId: uuid("device_id"), name: o["name"].str,
                            publicKey: b("pub"), paired: o["paired"].bool, sessionNonce: b("session_nonce")))
    case "pair_result":
        return .pairResult(PairResult(ok: o["ok"].bool, mac: o.has("mac") ? b("mac") : nil))
    case let t:
        fatalError("encode_errors: unsupported type \(t)")
    }
}

@Suite("messages.json vectors")
struct MessageVectorTests {
    let file = "messages.json"

    @Test func decode() throws {
        let v = try loadVectors(file)
        for c in cases(v, file, "decode") {
            let name = c["name"].str
            let got = result { () throws(VQError) in try Message.fromJSON(messageInput(c)) }
            switch (c["result"].str, got) {
            case ("message", .success(let m)):
                switch m {
                case .unknown, .helloUnsupported: Issue.record("\(name): got \(m)")
                default: break
                }
                #expect(sameBytes(m.typeName, c["type"].str), "\(name)")
                try checkExpected(name, c, m)
            case ("unknown", .success(.unknown(let t))):
                #expect(sameBytes(t, c["type"].str), "\(name)")
            case ("hello_unsupported", .success(.helloUnsupported(let h))):
                #expect(h.v == c["v"].u64, "\(name)")
                #expect(sameBytes(h.name, c["peer_name"].strOrNil), "\(name)")
            case ("error", .failure(let e)):
                #expect(e.code == c["error"].str, "\(name): \(e)")
            case (let want, let got):
                Issue.record("\(name): want \(want), got \(got)")
            }
        }
    }

    @Test func encode() throws {
        let v = try loadVectors(file)
        for c in cases(v, file, "encode") {
            let j = Array(c["json"].str.utf8)
            let m = try Message.fromJSON(j)
            #expect(m.typeName == c["type"].str)
            // Byte-identical to the Rust canonical encoding.
            #expect(try m.toJSON() == j, "\(c["json"].str)")
            #expect(JV.same(JV.parse(j), c["object"]))
        }
    }

    @Test func encodeErrors() throws {
        let v = try loadVectors(file)
        for c in cases(v, file, "encode_errors") {
            let m = messageFromObject(c["message"], textFill: c.has("text_fill") ? c["text_fill"] : nil)
            let r = result { () throws(VQError) in try m.toJSON() }
            #expect(r.errorCode == c["error"].str, "\(c["name"].str)")
        }
    }

    @Test func uttMaxOverheadBytes() throws {
        let v = try loadVectors(file)
        #expect(coveredSections[file]?.contains("utt_max_overhead_bytes") == true)
        #expect(v["utt_max_overhead_bytes"].int == VQ.uttMaxOverheadBytes)
        // And it really is the worst-case utt with empty text.
        let worst = Message.utt(Utt(id: UUID(), rev: .max, state: .partial, text: "", ts: .max))
        #expect(try worst.toJSON().count == VQ.uttMaxOverheadBytes)
    }

    @Test func uttFits() throws {
        let v = try loadVectors(file)
        for c in cases(v, file, "utt_fits") {
            let name = c["name"].str
            let f = c["text_fill"]
            let text = String(repeating: f["fill"].str, count: f["count"].int)
            #expect(uttTextFits(text) == c["fits"].bool, "\(name)")
            let prefix = maxTextPrefix(text)
            #expect(prefix.utf8.count == c["max_prefix_bytes"].int, "\(name)")
            #expect(text.utf8.starts(with: prefix.utf8), "\(name)")
            #expect(uttTextFits(prefix), "\(name)")
            // The prefix always encodes and seals with worst-case other fields.
            let m = Message.utt(Utt(id: UUID(), rev: .max, state: .partial, text: prefix, ts: .max))
            #expect(try m.toJSON().count <= VQ.maxEncryptedJSONBytes, "\(name)")
            let tx = SessionCipher(rawKeyForTests: [UInt8](repeating: 0, count: 32), role: .phone)
            #expect(throws: Never.self, "\(name)") { try tx.sealMessage(m) }
        }
    }
}
