import CryptoKit
import Foundation
import Testing
@testable import VQProtocol

private let key = [UInt8](repeating: 0x42, count: 32)

private func pair() -> (phone: SessionCipher, desktop: SessionCipher) {
    (SessionCipher(rawKeyForTests: key, role: .phone), SessionCipher(rawKeyForTests: key, role: .desktop))
}

private func reassembleAll(_ frames: [[UInt8]]) throws -> [UInt8]? {
    var r = Reassembler()
    var out: [UInt8]?
    for (i, f) in frames.enumerated() {
        let got = try r.push(f)
        if i + 1 == frames.count { out = got } else { #expect(got == nil) }
    }
    return out
}

@Suite("framing")
struct FramingTests {
    @Test func basicLayout() throws {
        var s = FrameSplitter()
        let msg = (0..<40).map { UInt8($0) }
        let frames = try s.split(msg, mtu: 20)
        #expect(frames.count == 3)
        #expect(Array(frames[0].prefix(3)) == [0x01, 0, 0])
        #expect(Array(frames[1].prefix(3)) == [0x00, 0, 0])
        #expect(Array(frames[2].prefix(3)) == [0x02, 0, 0])
        #expect(frames[0].count == 20 && frames[2].count == 9)
        #expect(s.nextSeq == 1)
        #expect(try reassembleAll(frames) == msg)
    }

    @Test func sizesRoundtrip() throws {
        for mtu in [20, 21, 23, 64, 185, 244, 512, 70_000] {
            for len in [0, 1, 16, 17, 18, 34, 35, 1000, 65_536] {
                let msg = (0..<len).map { UInt8($0 * 31 % 251) }
                var s = FrameSplitter()
                let frames = try s.split(msg, mtu: mtu)
                #expect(frames.count == max(1, (len + mtu - 4) / (mtu - 3)), "mtu \(mtu) len \(len)")
                #expect(frames.allSatisfy { $0.count <= mtu })
                #expect(frames.dropLast().allSatisfy { $0.count == mtu })
                #expect(try reassembleAll(frames) == msg)
            }
        }
    }

    @Test func singleAndEmpty() throws {
        var s = FrameSplitter()
        #expect(try s.split(Array("abc".utf8), mtu: 20) == [[0x03, 0, 0] + Array("abc".utf8)])
        var e = FrameSplitter()
        let f = try e.split([], mtu: 20)
        #expect(f == [[0x03, 0, 0]])
        var r = Reassembler()
        #expect(try r.push(f[0]) == [])
    }

    @Test func errorsDoNotAdvanceSeq() {
        var s = FrameSplitter(seq: 5)
        #expect(result { () throws(VQError) in try s.split([1], mtu: 19) } == .failure(.mtuTooSmall(19)))
        #expect(result { () throws(VQError) in try s.split([UInt8](repeating: 0, count: 65_537), mtu: 20) }
            == .failure(.messageTooLarge(65_537)))
        #expect(s.nextSeq == 5)
    }

    @Test func seqWraps() throws {
        var s = FrameSplitter(seq: 0xFFFF)
        let a = try s.split([1], mtu: 20)
        let b = try s.split([2], mtu: 20)
        #expect(Array(a[0][1..<3]) == [0xFF, 0xFF])
        #expect(Array(b[0][1..<3]) == [0x00, 0x00])
        #expect(s.nextSeq == 1)
    }

    @Test func firstResetsPartial() throws {
        var r = Reassembler()
        #expect(try r.push([0x01, 0, 1, 0x78]) == nil)
        #expect(try r.push([0x01, 0, 2, 0x79]) == nil)
        #expect(try r.push([0x02, 0, 2, 0x7A]) == [0x79, 0x7A])
        #expect(try r.push([0x01, 0, 3, 0x61]) == nil)
        #expect(try r.push([0x03, 0, 3, 0x62]) == [0x62])
    }

    @Test func seqMismatchDiscards() throws {
        var r = Reassembler()
        _ = try r.push([0x01, 0, 1, 0x78])
        #expect(result { () throws(VQError) in try r.push([0x00, 0, 2, 0x79]) } == .failure(.seqMismatch(expected: 1, got: 2)))
        #expect(!r.hasPartial)
        #expect(result { () throws(VQError) in try r.push([0x02, 0, 1, 0x7A]) } == .failure(.orphanFrame))
    }

    @Test func malformedFrames() throws {
        var r = Reassembler()
        _ = try r.push([0x01, 0, 1, 0x78])
        #expect(result { () throws(VQError) in try r.push([0x02, 0]) } == .failure(.frameTooShort))
        #expect(!r.hasPartial)
        _ = try r.push([0x01, 0, 1, 0x78])
        #expect(result { () throws(VQError) in try r.push([0x06, 0, 1]) } == .failure(.reservedFlags(0x06)))
        #expect(!r.hasPartial)
        #expect(code { try r.push([0x83, 0, 1]) } == "reserved_flags")
        #expect(code { try r.push([]) } == "frame_too_short")
        #expect(try r.push([0x03, 0, 9, 1, 2]) == [1, 2])
    }

    @Test func oversizeReassembly() throws {
        var f: [UInt8] = [0x01, 0, 7] + [UInt8](repeating: 0xAA, count: 1000)
        var r = Reassembler()
        _ = try r.push(f)
        f[0] = 0x00
        for _ in 0..<64 { _ = try r.push(f) }
        #expect(try r.push([0x02, 0, 7] + [UInt8](repeating: 0xAA, count: 536))?.count == 65_536)

        var r2 = Reassembler()
        f[0] = 0x01
        _ = try r2.push(f)
        f[0] = 0x00
        for _ in 0..<64 { _ = try r2.push(f) }
        #expect(result { () throws(VQError) in try r2.push([0x00, 0, 7] + [UInt8](repeating: 0xAA, count: 537)) }
            == .failure(.messageTooLarge(65_537)))
        #expect(!r2.hasPartial)
        #expect(code { try r2.push([0x02, 0, 7, 1]) } == "orphan_frame")
    }

    @Test func orphansAndReset() throws {
        var r = Reassembler()
        #expect(code { try r.push([0x00, 0, 0, 1]) } == "orphan_frame")
        #expect(code { try r.push([0x02, 0, 0, 1]) } == "orphan_frame")
        _ = try r.push([0x01, 0, 0, 1])
        r.reset()
        #expect(code { try r.push([0x02, 0, 0, 1]) } == "orphan_frame")
    }
}

@Suite("envelope and session cipher")
struct SessionCipherTests {
    @Test func rfc8439AEAD() throws {
        // RFC 8439 §2.8.2, pinning the CryptoKit construction we rely on.
        let k = SymmetricKey(data: hexBytes("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f"))
        let nonce = try ChaChaPoly.Nonce(data: hexBytes("070000004041424344454647"))
        let aad = hexBytes("50515253c0c1c2c3c4c5c6c7")
        let pt = Array("Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.".utf8)
        let box = try ChaChaPoly.seal(pt, using: k, nonce: nonce, authenticating: aad)
        #expect(hexString(box.tag) == "1ae10b594f09e26a7e902ecbd0600691")
    }

    @Test func nonceLayout() {
        #expect(nonceForTests(.phoneToDesktop, 0x0102030405060708) == [1, 0, 0, 0, 1, 2, 3, 4, 5, 6, 7, 8])
        #expect(nonceForTests(.desktopToPhone, 0)[0] == 2)
    }

    @Test func roundtripAndCounterMonotonicity() throws {
        let (p, d) = pair()
        for i in UInt64(0)..<5 {
            #expect(p.nextSendCounter == i)
            let env = try p.sealMessage(utt("hi"))
            #expect(env[0] == 0x01)
            var be = [UInt8](repeating: 0, count: 8)
            for k in 0..<8 { be[k] = UInt8(truncatingIfNeeded: i >> UInt64(56 - 8 * k)) }
            #expect(Array(env[1..<9]) == be)
            #expect(try decodeInbound(env, session: d) == .encrypted(utt("hi")))
            let back = try d.sealMessage(.pong)
            #expect(try decodeInbound(back, session: p).message == .pong)
        }
        #expect(p.nextSendCounter == 5)
        #expect(d.lastReceivedCounter == 4)
        // Every seal uses a new counter, so the same plaintext never repeats a ciphertext.
        let e1 = try p.seal([1]), e2 = try p.seal([1])
        #expect(e1 != e2)
    }

    @Test func directionIsBound() throws {
        let (p, _) = pair()
        let env = try p.seal(Array("{}".utf8))
        let p2 = SessionCipher(rawKeyForTests: key, role: .phone)
        #expect(result { () throws(VQError) in try p2.open(env) } == .failure(.decryptFailed))
    }

    @Test func replayAndGaps() throws {
        let (p, d) = pair()
        let e0 = try p.seal([0x61]), e1 = try p.seal([0x62]), e2 = try p.seal([0x63]), e3 = try p.seal([0x64])
        #expect(try d.open(e0) == [0x61])
        #expect(result { () throws(VQError) in try d.open(e0) } == .failure(.replay(counter: 0, last: 0)))
        #expect(try d.open(e2) == [0x63])
        #expect(code { try d.open(e1) } == "replay")
        var forged = e3
        for i in 1..<9 { forged[i] = 0xFF }
        #expect(result { () throws(VQError) in try d.open(forged) } == .failure(.decryptFailed))
        #expect(d.lastReceivedCounter == 2)
        #expect(try d.open(e3) == [0x64])
        // Replays are rejected through decodeInbound too, before decryption.
        #expect(code { try decodeInbound(e3, session: d) } == "replay")
    }

    @Test func tamperDetection() throws {
        let p = SessionCipher(rawKeyForTests: key, role: .phone)
        let env = try p.seal(Array("hello".utf8))
        for i in 0..<env.count {
            var t = env
            t[i] ^= 0x01
            let d = SessionCipher(rawKeyForTests: key, role: .desktop)
            let c = code { try d.open(t) }
            #expect(c == "decrypt_failed" || c == "unknown_envelope_kind", "byte \(i): \(String(describing: c))")
            #expect(d.lastReceivedCounter == nil)
        }
        let other = SessionCipher(rawKeyForTests: [UInt8](repeating: 0x43, count: 32), role: .desktop)
        #expect(code { try other.open(env) } == "decrypt_failed")
    }

    @Test func counterExhaustion() throws {
        let p = SessionCipher(rawKeyForTests: key, role: .phone)
        p.advanceSendCounterForTests(to: .max - 1)
        let d = SessionCipher(rawKeyForTests: key, role: .desktop)
        let a = try p.seal([0x78]), b = try p.seal([0x79])
        #expect(result { () throws(VQError) in try p.seal([0x7A]) } == .failure(.counterExhausted))
        #expect(p.nextSendCounter == nil)
        #expect(try d.open(a) == [0x78])
        #expect(try d.open(b) == [0x79])
        #expect(d.lastReceivedCounter == .max)
        #expect(code { try d.open(b) } == "replay")
    }

    @Test func envelopeParseErrors() throws {
        #expect(result { () throws(VQError) in try Envelope.parse([]) } == .failure(.emptyEnvelope))
        #expect(result { () throws(VQError) in try Envelope.parse([0x02, 1]) } == .failure(.unknownEnvelopeKind(2)))
        #expect(result { () throws(VQError) in try Envelope.parse([UInt8](repeating: 1, count: 24)) }
            == .failure(.envelopeTooShort(24)))
        guard case .encrypted = try Envelope.parse([UInt8](repeating: 1, count: 25)) else {
            Issue.record("25 bytes should parse")
            return
        }
        #expect(try Envelope.parse([0x00]) == .plaintext([]))
        #expect(code { try Envelope.parse([UInt8](repeating: 0, count: VQ.maxMessageBytes + 1)) } == "message_too_large")
        let p = SessionCipher(rawKeyForTests: key, role: .phone)
        #expect(code { try p.open([0x00, 0x7B, 0x7D]) } == "unknown_envelope_kind")
    }

    @Test func plaintextPolicy() throws {
        let env = try encodePlaintext(.error(ErrorMsg(code: "bad_mac")))
        #expect(env[0] == 0)
        guard case .plaintext(.error) = try decodeInbound(env, session: nil) else {
            Issue.record("plaintext error should decode")
            return
        }
        #expect(code { try encodePlaintext(utt("x")) } == "plaintext_not_allowed")
        #expect(code { try encodePlaintext(.ping) } == "plaintext_not_allowed")
        #expect(code { try encodePlaintext(.unknown(t: "zzz")) } == "plaintext_not_allowed")
        let raw = [0x00] + (try utt("x").toJSON())
        #expect(result { () throws(VQError) in try decodeInbound(raw, session: nil) } == .failure(.plaintextNotAllowed("utt")))
        let (p, d) = pair()
        #expect(code { try decodeInbound(raw, session: d) } == "plaintext_not_allowed")
        for t in ["ack", "ping", "pong"] {
            let j = [0x00] + Array(#"{"t":"\#(t)","id":"00000000-0000-0000-0000-000000000000","rev":1}"#.utf8)
            #expect(code { try decodeInbound(j, session: nil) } == "plaintext_not_allowed")
        }
        #expect(try decodeInbound([0x00] + Array(#"{"t":"zzz"}"#.utf8), session: nil) == .plaintext(.unknown(t: "zzz")))
        // Encrypted without a session.
        let enc = try p.sealMessage(utt("x"))
        #expect(result { () throws(VQError) in try decodeInbound(enc, session: nil) } == .failure(.noSession))
        // Policy precedes field validation; JSON checks precede policy.
        #expect(code { try decodeInbound([0x00] + Array(#"{"t":"utt","rev":-1}"#.utf8), session: nil) } == "plaintext_not_allowed")
        #expect(code { try decodeInbound([0x00] + Array(#"{"t":"utt","x":1e400}"#.utf8), session: nil) } == "invalid_json")
    }

    @Test func sizeLimitsAndFailedSealKeepsCounter() throws {
        let p = SessionCipher(rawKeyForTests: key, role: .phone)
        let maxPt = VQ.maxMessageBytes - Envelope.minEncryptedBytes
        let env = try p.seal([UInt8](repeating: 0x20, count: maxPt))
        #expect(env.count == VQ.maxMessageBytes)
        #expect(code { try p.seal([UInt8](repeating: 0x20, count: maxPt + 1)) } == "message_too_large")
        #expect(p.nextSendCounter == 1)
        #expect(code { try p.sealMessage(utt(String(repeating: "a", count: 32_001))) } == "text_too_long")
        #expect(code { try p.sealMessage(.unknown(t: "x")) } == "not_encodable")
        #expect(p.nextSendCounter == 1)
        let d = SessionCipher(rawKeyForTests: key, role: .desktop)
        #expect(try d.open(env).count == maxPt)
    }

    @Test func establishDerivesMatchingCiphers() throws {
        let phone = IdentityKeyPair.generate(), desk = IdentityKeyPair.generate()
        let hp = Hello.new(deviceId: UUID(), name: "phone", publicKey: phone.publicBytes, paired: true)
        let hd = Hello.new(deviceId: UUID(), name: "desk", publicKey: desk.publicBytes, paired: false)
        let npBytes = hp.nonce.bytes, ndBytes = hd.nonce.bytes
        let peerHelloOfPhone = hd.hello, peerHelloOfDesk = hp.hello
        let p = try SessionCipher.establish(identity: phone, role: .phone, peerPublic: peerHelloOfPhone.publicKey,
                                            ownNonce: hp.takeNonce(), peerNonce: peerHelloOfPhone.sessionNonce)
        let d = try SessionCipher.establish(identity: desk, role: .desktop, peerPublic: peerHelloOfDesk.publicKey,
                                            ownNonce: hd.takeNonce(), peerNonce: peerHelloOfDesk.sessionNonce)
        #expect(p.nextSendCounter == 0 && p.lastReceivedCounter == nil)
        #expect(try decodeInbound(try p.sealMessage(.ping), session: d) == .encrypted(.ping))
        #expect(try decodeInbound(try d.sealMessage(.pong), session: p).message == .pong)
        // Same bytes as the raw derivation, phone nonce first.
        let ss = try phone.sharedSecret(peerPublic: desk.publicBytes)
        let raw = SessionCipher(rawKeyForTests: deriveSessionKeyForTests(ss, noncePhone: npBytes, nonceDesktop: ndBytes),
                                role: .desktop)
        let again = try SessionCipher.establish(identity: phone, role: .phone, peerPublic: desk.publicBytes,
                                                ownNonce: SessionNonce(bytesForTests: npBytes), peerNonce: ndBytes)
        #expect(try raw.open(again.seal([0x7B, 0x7D])) == [0x7B, 0x7D])
        // Swapping the nonce order gives a different key.
        let swapped = SessionCipher(rawKeyForTests: deriveSessionKeyForTests(ss, noncePhone: ndBytes, nonceDesktop: npBytes),
                                    role: .desktop)
        let again2 = try SessionCipher.establish(identity: phone, role: .phone, peerPublic: desk.publicBytes,
                                                 ownNonce: SessionNonce(bytesForTests: npBytes), peerNonce: ndBytes)
        #expect(code { try swapped.open(again2.seal([1])) } == "decrypt_failed")
        // Low-order peer key.
        #expect(code {
            try SessionCipher.establish(identity: phone, role: .phone, peerPublic: Bytes32(repeating: 0),
                                        ownNonce: SessionNonce.generate(), peerNonce: ndBytes)
        } == "non_contributory")
        // Nonce reuse is prevented by the type system: `SessionNonce` is
        // `~Copyable` and `establish` takes it `consuming`, so a second
        // `hp.takeNonce()` (or any later use of `hp`) above would not compile.
        // `K_sess` is never exposed by `SessionCipher`.
        #expect(!String(describing: p).contains(hexString(deriveSessionKeyForTests(ss, noncePhone: npBytes, nonceDesktop: ndBytes))))
    }

    @Test func provenanceAndInSessionPolicy() throws {
        let (p, d) = pair()
        let ptErr = try encodePlaintext(.error(ErrorMsg(code: "unknown_peer")))
        let got = try decodeInbound(ptErr, session: d)
        #expect(!got.isAuthenticated)
        #expect(got == .plaintext(.error(ErrorMsg(code: "unknown_peer"))))
        #expect(throws: Never.self) { try checkInSession(got) }
        let enc = try decodeInbound(try p.sealMessage(utt("x")), session: d)
        #expect(enc.isAuthenticated)
        #expect(throws: Never.self) { try checkInSession(enc) }
        let encErr = try decodeInbound(try p.sealMessage(.error(ErrorMsg(code: "x"))), session: d)
        #expect(encErr.isAuthenticated)
        #expect(throws: Never.self) { try checkInSession(encErr) }
        let pr = Message.pairRequest(PairRequest(nonceP: Bytes32(repeating: 0)))
        let ptPr = try decodeInbound(try encodePlaintext(pr), session: d)
        #expect(code { try checkInSession(ptPr) } == "not_allowed_in_session")
        let encPr = try decodeInbound(try p.sealMessage(pr), session: d)
        #expect(encPr.isAuthenticated)
        #expect(code { try checkInSession(encPr) } == "not_allowed_in_session")
        for m: Message in [.pairChallenge(PairChallenge(nonceD: Bytes32(repeating: 1))),
                           .pairConfirm(PairConfirm(mac: Bytes32(repeating: 1))), .pairResult(.failure())] {
            #expect(code { try checkInSession(.plaintext(m)) } == "not_allowed_in_session")
        }
        let helloV9 = try decodeInbound([0x00] + Array(#"{"t":"hello","v":9}"#.utf8), session: d)
        #expect(code { try checkInSession(helloV9) } == "not_allowed_in_session")
        let unknown = try decodeInbound([0x00] + Array(#"{"t":"zzz"}"#.utf8), session: d)
        #expect(throws: Never.self) { try checkInSession(unknown) }
    }

    @Test func fullStackOverFrames() throws {
        // phone utt → seal → split at a BLE-sized mtu → reassemble → decode, repeatedly.
        let (p, d) = pair()
        var tx = FrameSplitter()
        var rx = Reassembler()
        for i in 0..<20 {
            let m = utt(String(repeating: "word ", count: i * 50), rev: UInt32(i), state: .partial)
            var out: [UInt8]?
            for f in try tx.split(try p.sealMessage(m), mtu: 185) { out = try rx.push(f) }
            #expect(try decodeInbound(try #require(out), session: d) == .encrypted(m))
        }
        #expect(tx.nextSeq == 20)
    }
}

/// Deterministic generator for distribution tests (SplitMix64).
private struct SplitMix64: RandomNumberGenerator {
    var state: UInt64
    mutating func next() -> UInt64 {
        state &+= 0x9E37_79B9_7F4A_7C15
        var z = state
        z = (z ^ (z >> 30)) &* 0xBF58_476D_1CE4_E5B9
        z = (z ^ (z >> 27)) &* 0x94D0_49BB_1331_11EB
        return z ^ (z >> 31)
    }
}

@Suite("crypto")
struct CryptoTests {
    @Test func rfc7748X25519() throws {
        let a = IdentityKeyPair(secretBytes: hexBytes("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a"))!
        let b = IdentityKeyPair(secretBytes: hexBytes("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb"))!
        #expect(hexString(a.publicBytes.bytes) == "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a")
        #expect(hexString(b.publicBytes.bytes) == "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f")
        let want = "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742"
        #expect(hexString(try a.sharedSecret(peerPublic: b.publicBytes).bytesForTests) == want)
        #expect(hexString(try b.sharedSecret(peerPublic: a.publicBytes).bytesForTests) == want)
    }

    @Test func lowOrderPointRejected() {
        let a = IdentityKeyPair.generate()
        var one = [UInt8](repeating: 0, count: 32)
        one[0] = 1
        for p in [Bytes32(repeating: 0), Bytes32(one)!] {
            #expect(code { try a.sharedSecret(peerPublic: p) } == "non_contributory")
        }
    }

    @Test func secretRoundtripAndRedaction() throws {
        let a = IdentityKeyPair.generate()
        let b = try #require(IdentityKeyPair(secretBytes: a.secretBytes))
        #expect(a.publicBytes == b.publicBytes)
        #expect(IdentityKeyPair(secretBytes: [UInt8](repeating: 1, count: 31)) == nil)
        let secretHex = hexString(a.secretBytes)
        #expect(!String(describing: a).contains(secretHex))
        let ss = try a.sharedSecret(peerPublic: IdentityKeyPair.generate().publicBytes)
        #expect(String(describing: ss) == "SharedSecret(..)")
        #expect(String(describing: PairingCode(value: 1)!) == "PairingCode(******)")
    }

    @Test func hkdfMatchesRFC5869Construction() {
        // PRK = HMAC(salt, ikm); OKM = T(1) = HMAC(PRK, info ‖ 0x01) — computed independently.
        for (ikm, a, b, info) in [
            ([UInt8](repeating: 0, count: 32), Bytes32(repeating: 1), Bytes32(repeating: 2), Array("vq/session/v1".utf8)),
            ([UInt8](repeating: 0xFF, count: 32), Bytes32(repeating: 0x10), Bytes32(repeating: 0x77), Array("vq/pair/v1123456".utf8)),
        ] {
            let prk = HMAC<SHA256>.authenticationCode(for: ikm, using: SymmetricKey(data: a.bytes + b.bytes))
            let okm = HMAC<SHA256>.authenticationCode(for: info + [1], using: SymmetricKey(data: Array(prk)))
            #expect(hkdf32(SymmetricKey(data: ikm), a, b, info).withUnsafeBytes { Array($0) } == Array(okm))
        }
    }

    @Test func rfc5869Case1() {
        let okm = HKDF<SHA256>.deriveKey(
            inputKeyMaterial: SymmetricKey(data: [UInt8](repeating: 0x0B, count: 22)),
            salt: hexBytes("000102030405060708090a0b0c"), info: hexBytes("f0f1f2f3f4f5f6f7f8f9"), outputByteCount: 42)
        #expect(okm.withUnsafeBytes { hexString($0) }
            == "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865")
    }

    @Test func pairKeyAPIMatchesRawAndFixesOrder() throws {
        let phone = IdentityKeyPair.generate(), desk = IdentityKeyPair.generate()
        let req = PairRequest.generate(), ch = PairChallenge.generate()
        let pc = PairingCode.generate()
        let kp = try PairKey.derive(identity: phone, ownRole: .phone, peerPublic: desk.publicBytes,
                                    request: req, challenge: ch, code: pc)
        let kd = try PairKey.derive(identity: desk, ownRole: .desktop, peerPublic: phone.publicBytes,
                                    request: req, challenge: ch, code: pc)
        #expect(kp.keyBytesForTests == kd.keyBytesForTests)
        let ss = try phone.sharedSecret(peerPublic: desk.publicBytes)
        #expect(kp.keyBytesForTests == derivePairKeyForTests(ss, nonceP: req.nonceP, nonceD: ch.nonceD, code: pc))
        let (pp, pd) = (phone.publicBytes, desk.publicBytes)
        #expect(kp.phoneMac == phoneConfirmMacForTests(kPair: kp.keyBytesForTests, pubPhone: pp, pubDesktop: pd))
        #expect(kd.desktopMac == desktopResultMacForTests(kPair: kd.keyBytesForTests, pubPhone: pp, pubDesktop: pd))
        try kd.verifyPhoneMac(kp.confirmMessage().mac)
        try kp.verifyDesktopMac(try #require(kd.successMessage().mac))
        #expect(code { try kd.verifyDesktopMac(kp.phoneMac) } == "bad_mac")
        #expect(code { try kd.verifyPhoneMac(kd.desktopMac) } == "bad_mac")
        #expect(String(describing: kp) == "PairKey(..)")
        // Wrong code on one side.
        let wrong = PairingCode(value: (pc.value + 1) % 1_000_000)!
        let kw = try PairKey.derive(identity: desk, ownRole: .desktop, peerPublic: pp, request: req, challenge: ch, code: wrong)
        #expect(code { try kw.verifyPhoneMac(kp.phoneMac) } == "bad_mac")
        // Swapped nonces give a different key.
        let swapped = try PairKey.derive(identity: phone, ownRole: .phone, peerPublic: pd,
                                         request: PairRequest(nonceP: ch.nonceD), challenge: PairChallenge(nonceD: req.nonceP),
                                         code: pc)
        #expect(swapped.keyBytesForTests != kp.keyBytesForTests)
        // Pair and session keys differ.
        #expect(deriveSessionKeyForTests(ss, noncePhone: req.nonceP, nonceDesktop: ch.nonceD) != kp.keyBytesForTests)
        // Low-order peer key.
        #expect(code {
            try PairKey.derive(identity: phone, ownRole: .phone, peerPublic: Bytes32(repeating: 0),
                               request: req, challenge: ch, code: pc)
        } == "non_contributory")
    }

    @Test func codeFormatAndParse() throws {
        #expect(PairingCode(value: 7)?.string == "000007")
        #expect(PairingCode(value: 42)?.ascii == Array("000042".utf8))
        #expect(PairingCode(value: 999_999)?.string == "999999")
        #expect(PairingCode(value: 1_000_000) == nil)
        #expect(try PairingCode(parsing: "000000").value == 0)
        #expect(try PairingCode(parsing: "123456").value == 123_456)
        for bad in ["12345", "1234567", "12a456", " 12345", "123 456", "+12345", "-12345", "", "١٢٣٤٥٦",
                    "１２３４５６", "12345\u{0}", "123456\n"] {
            #expect(result { () throws(VQError) in try PairingCode(parsing: bad) } == .failure(.invalidCode), "\(bad.debugDescription)")
        }
        #expect(pairInfo(PairingCode(value: 1234)!) == Array("vq/pair/v1001234".utf8))
    }

    @Test func codeGenerationIsUniform() {
        var rng = SplitMix64(state: 1)
        var buckets = [Int](repeating: 0, count: 10)
        let n = 200_000
        for _ in 0..<n {
            let c = PairingCode.generate(using: &rng)
            if c.value >= 1_000_000 { Issue.record("out of range: \(c.value)") }
            buckets[Int(c.value / 100_000)] += 1
        }
        for b in buckets { #expect(abs(b - n / 10) < n / 200, "\(buckets)") }
        #expect((0..<1000).allSatisfy { _ in PairingCode.generate().value < 1_000_000 })
    }
}
