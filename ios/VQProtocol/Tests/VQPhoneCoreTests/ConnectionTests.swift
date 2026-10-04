import Foundation
import Testing
import VQPhoneCore
import VQProtocol

@Suite("hello and the Secure table (README §7.1, §7.2)")
struct HelloAndSecureTableTests {
    @Test func unknownDesktopAppearsAsNearbyUnpaired() {
        let h = Harness()
        let d = h.desktop("Mac")
        h.net.connect(d)
        #expect(d.hellosFromPhone.count == 1)
        let hello = d.hellosFromPhone[0]
        #expect(hello.paired == false)
        #expect(hello.deviceId == h.identity.deviceId)
        #expect(hello.name == "Test iPhone")
        #expect(hello.publicKey == h.identity.keyPair.publicBytes)
        let row = h.engine.hosts.first { $0.id == d.deviceId }
        #expect(row?.isPaired == false)
        #expect(row?.isOnline == true)
        #expect(row?.state == .unpaired)
        #expect(h.engine.indicator == .none)
        #expect(!d.isSecure)
    }

    @Test func hostIsListedOnlyAfterHello() {
        let h = Harness()
        h.engine.peerConnected(PeerID("silent"))
        #expect(h.engine.hosts.isEmpty)
    }

    @Test func row1BothKnowEachOtherGoSecure() {
        let h = Harness()
        let d = h.pairedDesktop("Mac")
        h.net.connect(d)
        #expect(d.hellosFromPhone.first?.paired == true)
        #expect(d.isSecure)
        let row = h.engine.hosts.first { $0.id == d.deviceId }
        #expect(row?.state == .secure)
        #expect(row?.isPaired == true)
    }

    @Test func row2DesktopKnowsPhoneButPhoneForgotPairsAgainAndReplaces() {
        let h = Harness()
        let d = h.desktop("Mac")
        d.knownPhones[h.identity.deviceId] = h.identity.keyPair.publicBytes
        h.net.connect(d)
        #expect(d.hellosFromPhone.first?.paired == false)
        #expect(!d.isSecure)
        #expect(h.engine.hosts.first?.state == .unpaired)
        h.pair(d)
        #expect(d.isSecure)
        #expect(h.hostStore.hosts.count == 1)
        #expect(h.engine.indicator == .secure)
    }

    @Test func row3PhoneKnowsDesktopButDesktopDoesNot() throws {
        let h = Harness()
        let d = h.pairedDesktop("Mac")
        d.knownPhones = [:]
        let before = h.hostStore.hosts
        let peer = h.net.connect(d)
        #expect(d.hellosFromPhone.first?.paired == true)
        #expect(!h.net.isConnected(peer))
        // The unauthenticated unknown_peer keeps the stored record (README §7.4).
        #expect(h.hostStore.hosts == before)
        let row = try #require(h.engine.hosts.first { $0.id == d.deviceId })
        #expect(row.notRecognized)
        #expect(row.isPaired)
        #expect(!row.isOnline)
        #expect(h.notices.contains(.notRecognized(hostId: d.deviceId, hostName: "Mac")))
        // Forget, reconnect: now paired:false, and pairing works.
        h.engine.forgetHost(d.deviceId)
        h.net.connect(d)
        #expect(d.hellosFromPhone.last?.paired == false)
        h.pair(d)
        #expect(d.isSecure)
        #expect(h.engine.hosts.first { $0.id == d.deviceId }?.notRecognized == false)
    }

    @Test func row4NeitherKnowsWaitsForPairing() {
        let h = Harness()
        let d = h.desktop("Mac")
        h.net.connect(d)
        #expect(!d.isSecure)
        #expect(d.pairRequests == 0)
    }

    @Test func storedDeviceIdWithDifferentKeyIsNotKnown() throws {
        let h = Harness()
        let d = h.desktop("Mac")
        h.hostStore.hosts = [PairedHost(deviceId: d.deviceId, name: "Old Mac",
                                        publicKey: IdentityKeyPair.generate().publicBytes, pairedAt: Date())]
        let h2 = Harness(hosts: h.hostStore.hosts, identity: h.identity)
        h2.net.connect(d)
        #expect(d.hellosFromPhone.first?.paired == false)
        let row = try #require(h2.engine.hosts.first { $0.id == d.deviceId })
        #expect(!row.isPaired)
        #expect(row.keyChanged)
        #expect(row.isOnline)
        h2.pair(d)
        #expect(h2.hostStore.hosts.count == 1)
        #expect(h2.hostStore.hosts[0].publicBytes == d.identity.publicBytes)
    }

    @Test func plaintextUnknownPeerInSessionNeverChangesStore() {
        let h = Harness()
        let d = h.pairedDesktop("Mac")
        let peer = h.net.connect(d)
        let before = h.hostStore.hosts
        d.sendPlain(.error(ErrorMsg(code: "unknown_peer", msg: "spoofed")))
        h.net.pump()
        #expect(h.hostStore.hosts == before)
        #expect(!h.net.isConnected(peer))
    }

    @Test func secondHelloIsProtocolError() {
        let h = Harness()
        let d = h.pairedDesktop("Mac")
        let peer = h.net.connect(d)
        d.sendPlain(.hello(Hello.new(deviceId: d.deviceId, name: "Mac", publicKey: d.identity.publicBytes,
                                     paired: true).hello))
        h.net.pump()
        #expect(!h.net.isConnected(peer))
        #expect(h.net.disconnectedByPhone.contains(peer))
    }

    @Test func secondHelloBeforeSessionIsProtocolError() {
        let h = Harness()
        let d = h.desktop("Mac")
        let peer = h.net.connect(d)
        d.sendPlain(.hello(Hello.new(deviceId: d.deviceId, name: "Mac", publicKey: d.identity.publicBytes,
                                     paired: false).hello))
        h.net.pump()
        #expect(!h.net.isConnected(peer))
        #expect(h.engine.hosts.isEmpty)
    }

    @Test func pairingMessagesInSessionAreDropped() {
        let h = Harness()
        let d = h.pairedDesktop("Mac")
        let peer = h.net.connect(d)
        d.sendPlain(.pairChallenge(PairChallenge.generate()))
        d.sendPlain(.pairResult(.failure()))
        h.net.pump()
        #expect(h.net.isConnected(peer))
        #expect(h.engine.indicator == .none)  // connected but not active
    }

    @Test func unsupportedVersionHelloGetsVersionErrorAndNotice() {
        let h = Harness()
        let d = h.desktop("Future Mac")
        d.rawHelloJSON = #"{"t":"hello","v":2,"name":"Future Mac"}"#
        let peer = h.net.connect(d)
        #expect(!h.net.isConnected(peer))
        #expect(d.errorsReceived.map(\.code) == ["version"])
        #expect(h.notices == [.versionMismatch(hostName: "Future Mac", updatePhone: false)])
        #expect(d.hellosFromPhone.isEmpty)
    }

    @Test func versionErrorFromDesktopMeansUpdateThisPhone() {
        let h = Harness()
        let d = h.desktop("Mac")
        let peer = h.net.connect(d)
        d.sendPlain(.error(ErrorMsg(code: "version", msg: "")))
        d.sendPlain(.error(ErrorMsg(code: "version", msg: "")))
        h.net.pump()
        #expect(!h.net.isConnected(peer))
        #expect(h.notices.first == .versionMismatch(hostName: "Mac", updatePhone: true))
        #expect(PhoneNotice.versionMismatch(hostName: "Mac", updatePhone: true).text
            == "Update Ventriloquist on this iPhone")
    }

    @Test func plaintextUttAndAckAreRejected() {
        let h = Harness()
        let d = h.pairedDesktop("Mac")
        h.engine.selectHost(d.deviceId)
        h.net.connect(d)
        d.autoAck = false
        h.engine.beginUtterance()
        let f = h.engine.finishUtterance("hello")!
        h.net.pump()
        // A plaintext ack (forged) must not count.
        let ackJSON = #"{"t":"ack","id":"\#(f.id.uuidString.lowercased())","rev":0}"#
        d.sendEnvelope([0x00] + Array(ackJSON.utf8))
        h.net.pump()
        #expect(h.engine.deliveryStatus(of: f.id) == .pending)
    }

    @Test func decryptFailureSendsErrorAndDisconnects() {
        let h = Harness()
        let d = h.pairedDesktop("Mac")
        let peer = h.net.connect(d)
        var env = d.sealOnly(.ping)
        env[env.count - 1] ^= 0xFF
        d.sendEnvelope(env)
        h.net.pump()
        #expect(!h.net.isConnected(peer))
        #expect(d.errorsReceived.last?.code == "decrypt_failed")
    }

    @Test func replayIsDroppedSilently() {
        let h = Harness()
        let d = h.pairedDesktop("Mac")
        let peer = h.net.connect(d)
        let env = d.sealOnly(.ping)
        d.sendEnvelope(env)
        d.sendEnvelope(env)
        h.net.pump()
        #expect(h.net.isConnected(peer))
        #expect(d.pongsReceived == 1)
    }

    @Test func duplicateConnectionFromSameDesktopReplacesOld() {
        let h = Harness()
        let d = h.pairedDesktop("Mac")
        let first = h.net.connect(d)
        let d2 = d  // same desktop, second link (the fake keeps one connection's state)
        let second = h.net.connect(d2)
        #expect(first != second)
        #expect(h.net.disconnectedByPhone.contains(first))
        #expect(h.net.isConnected(second))
        #expect(d.isSecure)
        #expect(h.engine.hosts.filter { $0.id == d.deviceId }.count == 1)
    }

    @Test func smallMtuMultiFrameExchangeWorks() {
        let h = Harness()
        let d = h.desktop("Tiny", mtu: 20)
        h.net.connect(d)
        h.pair(d)
        #expect(d.isSecure)
        h.engine.beginUtterance()
        let f = h.engine.finishUtterance(String(repeating: "word ", count: 200))!
        h.net.pump()
        #expect(d.finals.first?.text == f.text)
        #expect(h.engine.deliveryStatus(of: f.id) == .acked)
        // Every phone frame respects the mtu.
        #expect(h.net.framesSent.values.joined().allSatisfy { $0.count <= 20 })
    }
}

@Suite("pairing (README §7.3)")
struct PairingTests {
    @Test func successStoresActivatesAndRemembers() throws {
        let h = Harness()
        let d = h.desktop("Mac")
        h.net.connect(d)
        h.engine.startPairing(with: d.deviceId)
        h.net.pump()
        #expect(d.pairRequests == 1)
        #expect(h.engine.pairing?.phase == .enterCode(error: nil))
        h.engine.submitPairingCode(d.sessionCode!)
        h.net.pump()
        #expect(h.engine.pairing?.phase == .succeeded)
        #expect(d.isSecure)
        #expect(d.knownPhones[h.identity.deviceId] == h.identity.keyPair.publicBytes)
        let rec = try #require(h.hostStore.hosts.first)
        #expect(rec.deviceId == d.deviceId)
        #expect(rec.publicBytes == d.identity.publicBytes)
        #expect(rec.name == "Mac")
        #expect(h.engine.activeHostId == d.deviceId)
        #expect(h.settings.lastHostId == d.deviceId)
        #expect(h.engine.indicator == .secure)
        #expect(h.events.contains(.paired(hostId: d.deviceId, name: "Mac")))
        h.engine.cancelPairing()
        #expect(h.engine.pairing == nil)

        // Next connection: both sides go Secure straight from the hellos.
        let peer = h.net.connect(d)
        #expect(d.hellosFromPhone.last?.paired == true)
        #expect(d.isSecure)
        #expect(h.net.isConnected(peer))
    }

    @Test func wrongCodeThenRightCodeWithSameNonces() {
        let h = Harness()
        let d = h.desktop("Mac")
        h.net.connect(d)
        h.engine.startPairing(with: d.deviceId)
        h.net.pump()
        h.engine.submitPairingCode(wrongCode(d.sessionCode!))
        h.net.pump()
        guard case .enterCode(let err) = h.engine.pairing?.phase else {
            Issue.record("expected enterCode")
            return
        }
        #expect(err?.contains("Wrong code") == true)
        #expect(h.hostStore.hosts.isEmpty)
        h.engine.submitPairingCode(d.sessionCode!)
        h.net.pump()
        #expect(h.engine.pairing?.phase == .succeeded)
        #expect(d.pairRequests == 1)
        #expect(d.pairConfirms == 2)
    }

    @Test func threeWrongCodesRestartWithNewRequest() {
        let h = Harness()
        let d = h.desktop("Mac")
        h.net.connect(d)
        h.engine.startPairing(with: d.deviceId)
        h.net.pump()
        for _ in 0..<3 {
            h.engine.submitPairingCode(wrongCode(d.sessionCode ?? "123456"))
            h.net.pump()
        }
        #expect(d.pairRequests == 2)
        #expect(h.engine.pairing?.phase == .enterCode(error: nil))
        #expect(h.engine.pairing?.note?.contains("Too many wrong codes") == true)
        h.engine.submitPairingCode(d.sessionCode!)
        h.net.pump()
        #expect(h.engine.pairing?.phase == .succeeded)
    }

    @Test func expiredCodeRequestsANewOne() {
        let h = Harness()
        let d = h.desktop("Mac")
        h.net.connect(d)
        h.engine.startPairing(with: d.deviceId)
        h.net.pump()
        let old = d.sessionCode!
        h.clock.advance(121)
        h.engine.submitPairingCode(old)
        h.net.pump()
        #expect(d.pairRequests == 2)
        #expect(d.pairConfirms == 0)
        #expect(h.engine.pairing?.note?.contains("expired") == true)
        h.engine.submitPairingCode(d.sessionCode!)
        h.net.pump()
        #expect(h.engine.pairing?.phase == .succeeded)
    }

    @Test func malformedCodeIsRejectedLocally() {
        let h = Harness()
        let d = h.desktop("Mac")
        h.net.connect(d)
        h.engine.startPairing(with: d.deviceId)
        h.net.pump()
        for bad in ["12345", "1234567", "12 456", "１２３４５６", "abcdef"] {
            h.engine.submitPairingCode(bad)
            h.net.pump()
            guard case .enterCode(let err) = h.engine.pairing?.phase else {
                Issue.record("expected enterCode for \(bad)")
                continue
            }
            #expect(err != nil)
        }
        #expect(d.pairConfirms == 0)
    }

    @Test func badDesktopMacSendsBadMacDisconnectsStoresNothing() {
        let h = Harness()
        let d = h.desktop("Mac")
        d.corruptDesktopMac = true
        let peer = h.net.connect(d)
        h.pair(d)
        #expect(!h.net.isConnected(peer))
        #expect(h.hostStore.hosts.isEmpty)
        #expect(h.engine.activeHostId == nil)
        #expect(d.errorsReceived.map(\.code) == ["bad_mac"])
        guard case .failed = h.engine.pairing?.phase else {
            Issue.record("expected failed")
            return
        }
    }

    @Test(arguments: ["rate_limited", "busy"])
    func refusalIsSurfacedAndNonFatal(code: String) {
        let h = Harness()
        let d = h.desktop("Mac")
        d.errorOnPairRequest = code
        let peer = h.net.connect(d)
        h.engine.startPairing(with: d.deviceId)
        h.net.pump()
        // README §7.3: non-fatal, the connection stays open.
        #expect(h.net.isConnected(peer))
        #expect(!h.net.disconnectedByPhone.contains(peer))
        guard case .failed(let msg) = h.engine.pairing?.phase else {
            Issue.record("expected failed")
            return
        }
        #expect(msg.contains("Try again later"))
        #expect(h.notices.contains { if case .peerError(_, code, _) = $0 { true } else { false } })
        #expect(h.hostStore.hosts.isEmpty)
        #expect(h.engine.hosts.first?.state == .unpaired)
        // Later, a new pair_request on the same connection succeeds.
        d.errorOnPairRequest = nil
        h.engine.cancelPairing()
        h.pair(d)
        #expect(d.pairRequests == 2)
        #expect(h.engine.pairing?.phase == .succeeded)
        #expect(d.isSecure)
    }

    @Test func refusalWithDisconnectIsHandled() {
        let h = Harness()
        let d = h.desktop("Mac")
        d.errorOnPairRequest = "rate_limited"
        d.closeAfterRefusal = true
        let peer = h.net.connect(d)
        h.engine.startPairing(with: d.deviceId)
        h.net.pump()
        #expect(!h.net.isConnected(peer))
        #expect(h.engine.hosts.isEmpty)
        guard case .failed(let msg) = h.engine.pairing?.phase else {
            Issue.record("expected failed")
            return
        }
        #expect(msg.contains("Try again later"))
    }

    @Test func rateLimitedHelloRefusalDisconnects() {
        let h = Harness()
        let d = h.desktop("Mac")
        let peer = h.net.connect(d)
        // The desktop refuses this device after its hello and disconnects.
        d.sendPlain(.error(ErrorMsg(code: "rate_limited", msg: "")))
        h.net.pump()
        h.net.drop(peer)
        #expect(h.notices.contains { if case .peerError(_, "rate_limited", _) = $0 { true } else { false } })
        #expect(h.engine.hosts.isEmpty)
    }

    @Test func disconnectMidPairingFailsTheSheet() {
        let h = Harness()
        let d = h.desktop("Mac")
        let peer = h.net.connect(d)
        h.engine.startPairing(with: d.deviceId)
        h.net.pump()
        h.net.drop(peer)
        guard case .failed = h.engine.pairing?.phase else {
            Issue.record("expected failed")
            return
        }
    }

    @Test func cancelPairingReturnsToUnpaired() {
        let h = Harness()
        let d = h.desktop("Mac")
        h.net.connect(d)
        h.engine.startPairing(with: d.deviceId)
        h.net.pump()
        h.engine.cancelPairing()
        #expect(h.engine.pairing == nil)
        #expect(h.engine.hosts.first?.state == .unpaired)
    }

    @Test func storageFailureStillPairsForThisConnection() {
        let h = Harness()
        h.hostStore.failSaves = true
        let d = h.desktop("Mac")
        h.net.connect(d)
        h.pair(d)
        #expect(d.isSecure)
        #expect(h.notices.contains(.storageFailed))
    }

    @Test func selectingUnpairedHostStartsPairing() {
        let h = Harness()
        let d = h.desktop("Mac")
        h.net.connect(d)
        h.engine.selectHost(d.deviceId)
        h.net.pump()
        #expect(d.pairRequests == 1)
        #expect(h.engine.pairing?.hostId == d.deviceId)
    }
}

@Suite("keepalive (README §5.10)")
struct KeepaliveTests {
    @Test func pingsEvery15sAndAnswersPings() {
        let h = Harness()
        let d = h.pairedDesktop("Mac")
        let peer = h.net.connect(d)
        h.advance(14.9)
        #expect(d.pingsReceived == 0)
        h.advance(0.2)
        #expect(d.pingsReceived == 1)
        h.advance(44.5)
        #expect(d.pingsReceived == 3)
        #expect(h.net.isConnected(peer))
        d.sendSealed(.ping)
        h.net.pump()
        #expect(d.pongsReceived == 1)
    }

    @Test func threeUnansweredPingsDisconnect() {
        let h = Harness()
        let d = h.pairedDesktop("Mac")
        d.answerPings = false
        let peer = h.net.connect(d)
        h.advance(59.5)
        #expect(h.net.isConnected(peer))
        #expect(d.pingsReceived == 3)
        h.advance(1)
        #expect(!h.net.isConnected(peer))
        #expect(h.notices.contains(.keepaliveTimeout(hostName: "Mac")))
    }
}

@Suite("host list and selection")
struct HostListTests {
    @Test func mergesOnlineAndOfflinePaired() {
        let h = Harness()
        let a = h.pairedDesktop("Alpha")
        _ = h.pairedDesktop("Beta")
        let c = h.desktop("Gamma")
        let h2 = Harness(hosts: h.hostStore.hosts, identity: h.identity)
        a.knownPhones[h2.identity.deviceId] = h2.identity.keyPair.publicBytes
        h2.net.connect(a)
        h2.net.connect(c)
        let rows = h2.engine.hosts
        #expect(rows.map(\.name) == ["Alpha", "Beta", "Gamma"])
        #expect(rows.map(\.isOnline) == [true, false, true])
        #expect(rows.map(\.isPaired) == [true, true, false])
        #expect(rows.map(\.state) == [.secure, .offline, .unpaired])
    }

    @Test func rememberedHostIsActiveAtLaunchAndGoesGreenOnConnect() {
        let seed = Harness()
        let d = seed.pairedDesktop("Mac")
        let h = Harness(hosts: seed.hostStore.hosts, lastHostId: d.deviceId, identity: seed.identity)
        #expect(h.engine.activeHostId == d.deviceId)
        #expect(h.engine.indicator == .connecting)
        h.net.connect(d)
        #expect(h.engine.indicator == .secure)
    }

    @Test func rememberedHostThatWasForgottenIsIgnored() {
        let h = Harness(lastHostId: UUID())
        #expect(h.engine.activeHostId == nil)
        #expect(h.engine.indicator == .none)
    }

    @Test func forgetClosesSessionAndClearsActive() {
        let h = Harness()
        let d = h.pairedDesktop("Mac")
        h.engine.selectHost(d.deviceId)
        let peer = h.net.connect(d)
        #expect(h.engine.indicator == .secure)
        h.engine.forgetHost(d.deviceId)
        #expect(h.hostStore.hosts.isEmpty)
        #expect(h.engine.activeHostId == nil)
        #expect(h.settings.lastHostId == nil)
        #expect(!h.net.isConnected(peer))
    }

    @Test func disconnectAllDropsEverything() {
        let h = Harness()
        let a = h.pairedDesktop("A")
        let b = h.desktop("B")
        let pa = h.net.connect(a)
        let pb = h.net.connect(b)
        h.engine.disconnectAll()
        #expect(!h.net.isConnected(pa))
        #expect(!h.net.isConnected(pb))
        #expect(h.engine.hosts.allSatisfy { !$0.isOnline })
    }
}

@Suite("support types")
struct SupportTests {
    @Test func tcpCodecRoundTripsAcrossArbitraryChunks() {
        let frames: [[UInt8]] = [[1, 2, 3], [], Array(repeating: 9, count: 512), [0x03, 0, 0]]
        let stream = frames.flatMap { TCPFrameCodec.encode($0)! }
        var dec = TCPFrameCodec.Decoder()
        var out: [[UInt8]] = []
        var i = 0
        let sizes = [1, 2, 5, 100, 7, 1000]
        var k = 0
        while i < stream.count {
            let n = min(sizes[k % sizes.count], stream.count - i)
            out += dec.push(stream[i..<(i + n)])
            i += n
            k += 1
        }
        #expect(out == frames)
        #expect(dec.pendingByteCount == 0)
        #expect(TCPFrameCodec.encode([UInt8](repeating: 0, count: 65_536)) == nil)
        #expect(TCPFrameCodec.encode([UInt8](repeating: 0, count: 65_535))?.prefix(2) == [0xFF, 0xFF])
    }

    @Test func identityIsCreatedOnceAndReused() throws {
        let store = InMemoryIdentityStore()
        let a = try PhoneIdentity.loadOrCreate(from: store)
        let b = try PhoneIdentity.loadOrCreate(from: store)
        #expect(a.deviceId == b.deviceId)
        #expect(a.keyPair.publicBytes == b.keyPair.publicBytes)
    }

    @Test func unreadableIdentityIsNotSilentlyReplaced() {
        let store = InMemoryIdentityStore()
        store.failLoad = true
        #expect(throws: StoreError.self) { try PhoneIdentity.loadOrCreate(from: store) }
        #expect(store.identity == nil)
    }

    @Test func noticeTexts() {
        #expect(PhoneNotice.versionMismatch(hostName: "Mac", updatePhone: false).text == "Update Ventriloquist on Mac")
        #expect(PhoneNotice.peerError(hostName: "Mac", code: "busy", message: "").text.contains("busy"))
    }

    @Test func peerErrorTextIsClipped() {
        let h = Harness()
        let d = h.desktop("Mac")
        h.net.connect(d)
        d.sendPlain(.error(ErrorMsg(code: "weird", msg: String(repeating: "x", count: 5000))))
        h.net.pump()
        guard case .peerError(_, "weird", let msg)? = h.notices.first else {
            Issue.record("expected peerError")
            return
        }
        #expect(msg.count <= 201)
    }
}
