import Testing
@testable import VQProtocol

func identity(_ v: JV) -> IdentityKeyPair { IdentityKeyPair(secretBytes: bytes(v))! }

@Suite("crypto.json vectors")
struct CryptoVectorTests {
    let file = "crypto.json"

    @Test func x25519() throws {
        let v = try loadVectors(file)
        for c in cases(v, file, "x25519") {
            let name = c["name"].str
            let a = identity(c["priv_a"])
            let b = identity(c["priv_b"])
            #expect(a.publicBytes == b32(c["pub_a"]), "\(name)")
            #expect(b.publicBytes == b32(c["pub_b"]), "\(name)")
            #expect(try a.sharedSecret(peerPublic: b.publicBytes).bytesForTests == bytes(c["shared"]), "\(name)")
            #expect(try b.sharedSecret(peerPublic: a.publicBytes).bytesForTests == bytes(c["shared"]), "\(name)")
        }
    }

    @Test func x25519Errors() throws {
        let v = try loadVectors(file)
        for c in cases(v, file, "x25519_errors") {
            let a = identity(c["priv"])
            let r = result { () throws(VQError) in try a.sharedSecret(peerPublic: b32(c["peer_pub"])) }
            #expect(r.errorCode == c["error"].str, "\(c["name"].str)")
        }
    }

    @Test func x25519HighBit() throws {
        let v = try loadVectors(file)
        for c in cases(v, file, "x25519_high_bit") {
            let name = c["name"].str
            let a = identity(c["priv"])
            let hi = bytes(c["peer_pub"])
            let lo = bytes(c["peer_pub_masked"])
            #expect(hi[31] & 0x80 == 0x80, "\(name)")
            var masked = hi
            masked[31] &= 0x7F
            #expect(lo == masked, "\(name)")
            for p in [hi, lo] {
                #expect(try a.sharedSecret(peerPublic: Bytes32(p)!).bytesForTests == bytes(c["shared"]), "\(name)")
            }
        }
    }

    @Test func pairKey() throws {
        let v = try loadVectors(file)
        for c in cases(v, file, "pair_key") {
            let name = c["name"].str
            let code = try PairingCode(parsing: c["code"].str)
            let np = b32(c["nonce_p"]), nd = b32(c["nonce_d"])
            #expect(bytes(c["salt"]) == np.bytes + nd.bytes, "\(name)")
            #expect(bytes(c["info"]) == pairInfo(code), "\(name)")
            #expect(bytes(c["info"]) == Array(c["info_ascii"].str.utf8), "\(name)")
            #expect(c["length"].int == 32, "\(name)")
            let ss = SharedSecret(bytesForTests: bytes(c["shared"]))
            #expect(derivePairKeyForTests(ss, nonceP: np, nonceD: nd, code: code) == bytes(c["k_pair"]), "\(name)")
        }
    }

    @Test func sessionKey() throws {
        let v = try loadVectors(file)
        for c in cases(v, file, "session_key") {
            let name = c["name"].str
            let a = b32(c["nonce_phone"]), b = b32(c["nonce_desktop"])
            #expect(bytes(c["salt"]) == a.bytes + b.bytes, "\(name)")
            #expect(bytes(c["info"]) == sessionInfo, "\(name)")
            #expect(Array(c["info_ascii"].str.utf8) == sessionInfo, "\(name)")
            #expect(c["length"].int == 32, "\(name)")
            let ss = SharedSecret(bytesForTests: bytes(c["shared"]))
            #expect(deriveSessionKeyForTests(ss, noncePhone: a, nonceDesktop: b) == bytes(c["k_sess"]), "\(name)")
        }
    }

    @Test func pairMac() throws {
        let v = try loadVectors(file)
        for c in cases(v, file, "pair_mac") {
            let name = c["name"].str
            let k = bytes(c["k_pair"])
            let pp = b32(c["pub_phone"]), pd = b32(c["pub_desktop"])
            #expect(bytes(c["phone_mac_input"]) == phoneMacLabel + pp.bytes + pd.bytes, "\(name)")
            #expect(bytes(c["desktop_mac_input"]) == desktopMacLabel + pd.bytes + pp.bytes, "\(name)")
            #expect(phoneConfirmMacForTests(kPair: k, pubPhone: pp, pubDesktop: pd) == b32(c["phone_mac"]), "\(name)")
            #expect(desktopResultMacForTests(kPair: k, pubPhone: pp, pubDesktop: pd) == b32(c["desktop_mac"]), "\(name)")
        }
    }

    @Test func pairMacVerify() throws {
        let v = try loadVectors(file)
        for c in cases(v, file, "pair_mac_verify") {
            let name = c["name"].str
            let k = bytes(c["k_pair"])
            let pp = b32(c["pub_phone"]), pd = b32(c["pub_desktop"]), mac = b32(c["mac"])
            let r = result { () throws(VQError) in
                switch c["kind"].str {
                case "phone": try verifyPhoneConfirmMacForTests(kPair: k, pubPhone: pp, pubDesktop: pd, mac: mac)
                case "desktop": try verifyDesktopResultMacForTests(kPair: k, pubPhone: pp, pubDesktop: pd, mac: mac)
                default: Issue.record("\(name): kind \(c["kind"])")
                }
            }
            #expect((r.errorCode == nil) == c["valid"].bool, "\(name)")
            if let code = r.errorCode { #expect(code == "bad_mac", "\(name)") }
        }
    }

    @Test func codeFormat() throws {
        let v = try loadVectors(file)
        for c in cases(v, file, "code_format") {
            let code = try #require(PairingCode(value: UInt32(c["value"].u64)))
            #expect(code.string == c["string"].str)
            #expect(code.ascii == Array(c["string"].str.utf8))
        }
    }

    @Test func codeParse() throws {
        let v = try loadVectors(file)
        for c in cases(v, file, "code_parse") {
            let input = c["input"].str
            let r = result { () throws(VQError) in try PairingCode(parsing: input) }
            if c["valid"].bool {
                #expect(r.value.map { UInt64($0.value) } == c["value"].u64, "\(input)")
            } else {
                #expect(r.errorCode == "invalid_code", "\(input.debugDescription)")
            }
        }
    }

    @Test func fullPairing() throws {
        let v = try loadVectors(file)
        for c in cases(v, file, "full_pairing") {
            let name = c["name"].str
            let phone = identity(c["phone_priv"])
            let desk = identity(c["desktop_priv"])
            let pp = phone.publicBytes, pd = desk.publicBytes
            #expect(pp == b32(c["phone_pub"]), "\(name)")
            #expect(pd == b32(c["desktop_pub"]), "\(name)")
            let ss = try phone.sharedSecret(peerPublic: pd)
            #expect(ss.bytesForTests == bytes(c["shared"]), "\(name)")

            // Walk the plaintext transcript and check every field against the scalars.
            let t = c["transcript"].array
            #expect(t.map { $0["from"].str } == ["desktop", "phone", "phone", "desktop", "phone", "desktop"], "\(name)")
            var msgs: [Message] = []
            for e in t {
                let env = bytes(e["envelope"])
                #expect(Array(env.dropFirst()) == Array(e["json_utf8"].str.utf8), "\(name)")
                let m = try decodeEnvelopeForTests(env, session: nil)
                #expect(try encodePlaintext(m) == env, "\(name)")
                msgs.append(m)
            }
            guard msgs.count == 6,
                  case .hello(let hd) = msgs[0], case .hello(let hp) = msgs[1],
                  case .pairRequest(let req) = msgs[2], case .pairChallenge(let ch) = msgs[3],
                  case .pairConfirm(let conf) = msgs[4], case .pairResult(let res) = msgs[5]
            else {
                Issue.record("\(name): unexpected transcript shape \(msgs)")
                continue
            }
            #expect(hd.publicKey == pd, "\(name)")
            #expect(hp.publicKey == pp, "\(name)")
            #expect(UUIDText.format(hd.deviceId) == c["desktop_device_id"].str, "\(name)")
            #expect(UUIDText.format(hp.deviceId) == c["phone_device_id"].str, "\(name)")
            #expect(req.nonceP == b32(c["nonce_p"]), "\(name)")
            #expect(ch.nonceD == b32(c["nonce_d"]), "\(name)")
            let code = try PairingCode(parsing: c["code"].str)
            let kPair = derivePairKeyForTests(ss, nonceP: req.nonceP, nonceD: ch.nonceD, code: code)
            #expect(kPair == bytes(c["k_pair"]), "\(name)")
            try verifyPhoneConfirmMacForTests(kPair: kPair, pubPhone: pp, pubDesktop: pd, mac: conf.mac)
            #expect(conf.mac == b32(c["phone_mac"]), "\(name)")
            #expect(res.ok, "\(name)")
            let resMac = try #require(res.mac)
            try verifyDesktopResultMacForTests(kPair: kPair, pubPhone: pp, pubDesktop: pd, mac: resMac)
            #expect(resMac == b32(c["desktop_mac"]), "\(name)")

            #expect(hp.sessionNonce == b32(c["session_nonce_phone"]), "\(name)")
            #expect(hd.sessionNonce == b32(c["session_nonce_desktop"]), "\(name)")
            let ssD = try desk.sharedSecret(peerPublic: pp)
            let kSess = deriveSessionKeyForTests(ssD, noncePhone: hp.sessionNonce, nonceDesktop: hd.sessionNonce)
            #expect(kSess == bytes(c["k_sess"]), "\(name)")

            // The production API reproduces the same keys and MACs.
            let pkPhone = try PairKey.derive(identity: phone, ownRole: .phone, peerPublic: pd,
                                             request: req, challenge: ch, code: code)
            let pkDesk = try PairKey.derive(identity: desk, ownRole: .desktop, peerPublic: pp,
                                            request: req, challenge: ch, code: code)
            #expect(pkPhone.keyBytesForTests == bytes(c["k_pair"]), "\(name)")
            #expect(pkDesk.keyBytesForTests == bytes(c["k_pair"]), "\(name)")
            #expect(pkPhone.confirmMessage() == conf, "\(name)")
            #expect(pkDesk.successMessage() == res, "\(name)")
            try pkDesk.verifyPhoneMac(conf.mac)
            try pkPhone.verifyDesktopMac(resMac)

            let phoneC = try SessionCipher.establish(
                identity: phone, role: .phone, peerPublic: hd.publicKey,
                ownNonce: SessionNonce(bytesForTests: hp.sessionNonce), peerNonce: hd.sessionNonce)
            let deskC = try SessionCipher.establish(
                identity: desk, role: .desktop, peerPublic: hp.publicKey,
                ownNonce: SessionNonce(bytesForTests: hd.sessionNonce), peerNonce: hp.sessionNonce)
            // ...and agrees with the raw key from the vector.
            let rawRx = SessionCipher(rawKeyForTests: kSess, role: .desktop)
            let uttPt = Array(c["first_utt_plaintext_utf8"].str.utf8)
            let uttEnv = try phoneC.seal(uttPt)
            #expect(uttEnv == bytes(c["first_utt_envelope"]), "\(name)")
            #expect(try rawRx.open(uttEnv) == uttPt, "\(name)")
            let gotUtt = try decodeInbound(uttEnv, session: deskC)
            #expect(gotUtt.isAuthenticated, "\(name)")
            guard case .utt = gotUtt.message else {
                Issue.record("\(name): want utt, got \(gotUtt)")
                continue
            }
            let ackPt = Array(c["first_ack_plaintext_utf8"].str.utf8)
            let ackEnv = try deskC.seal(ackPt)
            #expect(ackEnv == bytes(c["first_ack_envelope"]), "\(name)")
            guard case .ack = try decodeEnvelopeForTests(ackEnv, session: phoneC) else {
                Issue.record("\(name): want ack")
                continue
            }
        }
    }
}
