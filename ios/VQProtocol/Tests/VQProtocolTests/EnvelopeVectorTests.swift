import Testing
@testable import VQProtocol

/// A receiver for a vector's `session` (`null` = no session), after opening
/// every envelope in `session.prior`.
func sessionFrom(_ v: JV) throws -> SessionCipher? {
    if v.isNull { return nil }
    let c = SessionCipher(rawKeyForTests: bytes(v["key"]), role: role(v["role"]))
    for e in v["prior"].array { _ = try c.open(bytes(e)) }
    return c
}

/// Compare a decoded message with a vector's canonical `expected` object (or,
/// for large utts, `expected_without_text` + `text_bytes`).
func checkExpected(_ name: String, _ c: JV, _ m: Message) throws {
    let canon = JV.parse(try m.toJSON())
    if c.has("expected") {
        let exp = c["expected"]
        #expect(JV.same(canon, exp), "\(name): re-encoded \(canon) != expected \(exp)")
        // The canonical form decodes to the same message.
        #expect(try Message.fromJSON(exp.serialized()) == m, "\(name)")
    } else {
        guard case .utt(let u) = m else {
            Issue.record("\(name): no `expected` on a non-utt")
            return
        }
        #expect(u.text.utf8.count == c["text_bytes"].int, "\(name)")
        #expect(JV.same(canon.removing("text"), c["expected_without_text"]), "\(name)")
    }
}

/// Check a `decode`-style result against the vector `c`.
func checkInbound(_ name: String, _ c: JV, _ got: Result<Inbound, VQError>) throws {
    func auth(_ i: Inbound) {
        #expect(i.isAuthenticated == c["authenticated"].bool, "\(name)")
        let encrypted: Bool = if case .encrypted = i { true } else { false }
        #expect(encrypted == (bytes(c["envelope"])[0] == 0x01), "\(name)")
    }
    switch (c["result"].str, got) {
    case ("message", .success(let i)):
        auth(i)
        let m = i.message
        switch m {
        case .unknown, .helloUnsupported: Issue.record("\(name): got \(m)")
        default: break
        }
        #expect(m.typeName == c["type"].str, "\(name)")
        try checkExpected(name, c, m)
    case ("unknown", .success(let i)):
        auth(i)
        guard case .unknown(let t) = i.message else {
            Issue.record("\(name): want unknown, got \(i)")
            return
        }
        #expect(t == c["type"].str, "\(name)")
    case ("hello_unsupported", .success(let i)):
        auth(i)
        guard case .helloUnsupported(let h) = i.message else {
            Issue.record("\(name): want hello_unsupported, got \(i)")
            return
        }
        #expect(i.message.typeName == c["type"].str, "\(name)")
        #expect(h.v == c["v"].u64, "\(name)")
        #expect(h.name == c["peer_name"].strOrNil, "\(name)")
    case ("error", .failure(let e)):
        #expect(e.code == c["error"].str, "\(name): \(e)")
    case (let want, let got):
        Issue.record("\(name): want \(want), got \(got)")
    }
}

@Suite("envelope.json vectors")
struct EnvelopeVectorTests {
    let file = "envelope.json"

    @Test func plaintext() throws {
        let v = try loadVectors(file)
        for c in cases(v, file, "plaintext") {
            let name = c["name"].str
            let json = Array(c["json_utf8"].str.utf8)
            let env = bytes(c["envelope"])
            #expect(env[0] == 0x00, "\(name)")
            #expect(Array(env.dropFirst()) == json, "\(name)")
            let m = try Message.fromJSON(json)
            #expect(try encodePlaintext(m) == env, "\(name)")
            #expect(try decodeEnvelopeForTests(env, session: nil) == m, "\(name)")
        }
    }

    @Test func encrypt() throws {
        let v = try loadVectors(file)
        for c in cases(v, file, "encrypt") {
            let name = c["name"].str
            let key = bytes(c["key"])
            let dir = direction(c["direction"])
            let counter = c["counter"].u64s
            let pt = bytes(c["plaintext"])
            let env = bytes(c["envelope"])
            #expect(hexString(nonceForTests(dir, counter)) == c["nonce"].str, "\(name)")
            #expect(c["aad"].str == "01", "\(name)")
            #expect(try sealForTests(key: key, direction: dir, counter: counter, plaintext: pt) == env, "\(name)")
            // A stateful sender produces the same bytes.
            let sender: Role = dir == .phoneToDesktop ? .phone : .desktop
            let tx = SessionCipher(rawKeyForTests: key, role: sender)
            tx.advanceSendCounterForTests(to: counter)
            #expect(try tx.seal(pt) == env, "\(name)")
            let rx = SessionCipher(rawKeyForTests: key, role: sender == .phone ? .desktop : .phone)
            #expect(try rx.open(env) == pt, "\(name)")
            #expect(rx.lastReceivedCounter == counter, "\(name)")
        }
    }

    @Test func openErrors() throws {
        let v = try loadVectors(file)
        for c in cases(v, file, "open_errors") {
            let name = c["name"].str
            let rx = SessionCipher(rawKeyForTests: bytes(c["key"]), role: role(c["receiver_role"]))
            let got = result { () throws(VQError) in try rx.open(bytes(c["envelope"])) }
            if c["error"].isNull {
                #expect(got.value == bytes(c["plaintext"]), "\(name)")
            } else {
                #expect(got.errorCode == c["error"].str, "\(name)")
                #expect(rx.lastReceivedCounter == nil, "\(name)")
            }
        }
    }

    @Test func decode() throws {
        let v = try loadVectors(file)
        for c in cases(v, file, "decode") {
            let name = c["name"].str
            let env = bytes(c["envelope"])
            let sess = try sessionFrom(c["session"])
            let got = result { () throws(VQError) in try decodeInbound(env, session: sess) }
            try checkInbound(name, c, got)
            if let rx = sess {
                #expect(rx.lastReceivedCounter == optU64s(c["last_accepted_after"]), "\(name)")
            } else {
                #expect(!c.has("last_accepted_after"), "\(name)")
            }
            // The provenance-free test helper agrees.
            let sess2 = try sessionFrom(c["session"])
            let r2 = result { () throws(VQError) in try decodeEnvelopeForTests(env, session: sess2) }
            #expect((r2.value != nil) == (c["result"].str != "error"), "\(name)")
        }
    }

    @Test func inSession() throws {
        let v = try loadVectors(file)
        for c in cases(v, file, "in_session") {
            let name = c["name"].str
            let sess = try sessionFrom(c["session"])
            #expect(sess != nil, "\(name)")
            let got = result { () throws(VQError) -> Inbound in
                let i = try decodeInbound(bytes(c["envelope"]), session: sess)
                try checkInSession(i)
                return i
            }
            switch (c["result"].str, got) {
            case ("ok", .success(let i)):
                #expect(i.message.typeName == c["type"].str, "\(name)")
                #expect(i.isAuthenticated == c["authenticated"].bool, "\(name)")
            case ("error", .failure(let e)):
                #expect(e.code == c["error"].str, "\(name)")
            case (let want, let got):
                Issue.record("\(name): want \(want), got \(got)")
            }
        }
    }

    @Test func stack() throws {
        let v = try loadVectors(file)
        for c in cases(v, file, "stack") {
            let name = c["name"].str
            let key = bytes(c["key"])
            let sender = role(c["sender_role"])
            let pt = Array(c["plaintext_utf8"].str.utf8)
            let tx = SessionCipher(rawKeyForTests: key, role: sender)
            tx.advanceSendCounterForTests(to: c["counter"].u64s)
            let env = try tx.seal(pt)
            #expect(env == bytes(c["envelope"]), "\(name)")
            var sp = FrameSplitter(seq: UInt16(c["seq"].u64))
            let frames = try sp.split(env, mtu: c["mtu"].int)
            let want = c["frames"].array.map(bytes)
            #expect(frames == want, "\(name)")
            // Receive path: frames → envelope → message.
            var r = Reassembler()
            var out: [UInt8]?
            for f in want { out = try r.push(f) }
            let rx = SessionCipher(rawKeyForTests: key, role: sender == .phone ? .desktop : .phone)
            let m = try decodeEnvelopeForTests(try #require(out), session: rx)
            #expect(m == (try Message.fromJSON(pt)), "\(name)")
        }
    }
}
