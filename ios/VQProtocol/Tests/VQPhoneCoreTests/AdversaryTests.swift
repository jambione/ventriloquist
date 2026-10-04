import Foundation
import Testing
import VQPhoneCore
import VQProtocol

// M6 adversary suite: a malicious / buggy desktop and a hostile environment
// against `PhoneEngine`. Every test asserts behaviour required by
// protocol/README.md or SPEC.md, or obviously required for safety (no trap,
// bounded memory, no misdelivery). Failing tests are findings.
//
// This file has its own fully scriptable desktop (`EvilDesktop`) and
// transport (`TapTransport`) so a test can send anything, in any state, on
// any connection id, including stale ones.

// MARK: - Harness

/// Records everything the engine sends; never re-enters the engine.
final class TapTransport: PhoneTransport {
    var sent: [PeerID: [[UInt8]]] = [:]
    var disconnected: [PeerID] = []
    var mtuValue = 185
    func send(frame: [UInt8], to peer: PeerID) { sent[peer, default: []].append(frame) }
    func disconnect(_ peer: PeerID) { disconnected.append(peer) }
    func mtu(for peer: PeerID) -> Int { mtuValue }
}

/// A desktop that can be honest or hostile. One connection at a time.
final class EvilDesktop {
    let identity: IdentityKeyPair
    var deviceId: UUID
    var name: String
    unowned let world: AdvWorld

    var knownPhones: [UUID: Bytes32] = [:]
    var autoAck = true
    var answerPings = true
    /// Reply to pair_request with a challenge and generate a code.
    var autoChallenge = true
    /// Verify pair_confirm and answer with pair_result.
    var autoPairResult = true
    /// Answer pair_request with error{code} instead.
    var refusePairRequest: String?

    private(set) var peer: PeerID?
    private var cursor = 0
    private var splitter = FrameSplitter()
    private var reassembler = Reassembler()
    private var ownNonce: SessionNonce?
    private(set) var phoneHello: Hello?
    private(set) var cipher: SessionCipher?
    private(set) var code: PairingCode?
    private var request: PairRequest?
    private var challenge: PairChallenge?
    var toPhone: [[UInt8]] = []

    // Records (across connections).
    private(set) var inbound: [Inbound] = []
    private(set) var inboundByPeer: [PeerID: [Inbound]] = [:]
    private(set) var utts: [Utt] = []
    private(set) var uttsByPeer: [PeerID: [Utt]] = [:]
    private(set) var errorsReceived: [ErrorMsg] = []
    private(set) var pairRequests = 0
    private(set) var pairConfirms = 0
    private(set) var pings = 0

    init(world: AdvWorld, name: String, identity: IdentityKeyPair = .generate(), deviceId: UUID = UUID()) {
        self.world = world
        self.name = name
        self.identity = identity
        self.deviceId = deviceId
    }

    var isSecure: Bool { cipher != nil }
    var isOpen: Bool {
        guard let peer else { return false }
        return !world.transport.disconnected.contains(peer)
    }
    var finals: [Utt] { utts.filter { $0.state == .final } }
    var partials: [Utt] { utts.filter { $0.state == .partial } }
    var edits: [Utt] { utts.filter { $0.state == .edit } }
    var hellosFromPhone: [Hello] { inbound.compactMap { if case .hello(let h) = $0.message { h } else { nil } } }
    var pairConfirmCount: Int { pairConfirms }

    /// New connection with a fresh PeerID; sends `hello` unless `sendHello` is false.
    @discardableResult
    func connect(sendHello: Bool = true, helloDeviceId: UUID? = nil, helloPub: Bytes32? = nil) -> PeerID {
        world.counter += 1
        let p = PeerID("evil:\(name)#\(world.counter)")
        peer = p
        cursor = world.transport.sent[p]?.count ?? 0
        splitter = FrameSplitter()
        reassembler = Reassembler()
        phoneHello = nil
        cipher = nil
        code = nil
        request = nil
        challenge = nil
        toPhone = []
        world.engine.peerConnected(p)
        if sendHello { self.sendHello(deviceId: helloDeviceId, pub: helloPub) }
        world.pump()
        return p
    }

    func sendHello(deviceId: UUID? = nil, pub: Bytes32? = nil) {
        let own = Hello.new(deviceId: deviceId ?? self.deviceId, name: name,
                            publicKey: pub ?? identity.publicBytes, paired: false)
        let h = own.hello
        ownNonce = own.takeNonce()
        sendPlain(.hello(h))
    }

    /// The desktop drops the link (engine is told).
    func hangUp() {
        guard let p = peer else { return }
        peer = nil
        cipher = nil
        _ = ownNonce.take()
        world.engine.peerDisconnected(p)
    }

    /// Read everything the engine sent on the current connection.
    @discardableResult
    func pull() -> Bool {
        guard let p = peer else { return false }
        let frames = world.transport.sent[p] ?? []
        guard cursor < frames.count else { return false }
        let new = frames[cursor...]
        cursor = frames.count
        for f in new {
            guard let msg = try? reassembler.push(f) else { continue }
            guard let ib = try? decodeInbound(msg, session: cipher) else { continue }
            handle(ib, on: p)
        }
        if world.transport.disconnected.contains(p) {
            peer = nil
            cipher = nil
        }
        return true
    }

    private func handle(_ ib: Inbound, on p: PeerID) {
        inbound.append(ib)
        inboundByPeer[p, default: []].append(ib)
        if isSecure {
            switch ib.message {
            case .utt(let u):
                utts.append(u)
                uttsByPeer[p, default: []].append(u)
                if autoAck, u.state != .partial { sendSealed(.ack(Ack(id: u.id, rev: u.rev))) }
            case .ping:
                pings += 1
                if answerPings { sendSealed(.pong) }
            case .error(let e): errorsReceived.append(e)
            default: break
            }
            return
        }
        switch ib.message {
        case .hello(let h):
            phoneHello = h
            if knownPhones[h.deviceId] == h.publicKey && h.paired { establish() }
        case .pairRequest(let r):
            pairRequests += 1
            if let refusal = refusePairRequest {
                sendPlain(.error(ErrorMsg(code: refusal, msg: "nope")))
                return
            }
            request = r
            guard autoChallenge else { return }
            let ch = PairChallenge.generate()
            challenge = ch
            code = PairingCode.generate()
            sendPlain(.pairChallenge(ch))
        case .pairConfirm(let c):
            pairConfirms += 1
            guard autoPairResult else { return }
            guard let k = pairKey() else { sendPlain(.pairResult(.failure())); return }
            if (try? k.verifyPhoneMac(c.mac)) != nil {
                knownPhones[phoneHello!.deviceId] = phoneHello!.publicKey
                sendPlain(.pairResult(k.successMessage()))
                establish()
            } else {
                sendPlain(.pairResult(.failure()))
            }
        case .error(let e): errorsReceived.append(e)
        default: break
        }
    }

    func pairKey() -> PairKey? {
        guard let h = phoneHello, let request, let challenge, let code else { return nil }
        return try? PairKey.derive(identity: identity, ownRole: .desktop, peerPublic: h.publicKey,
                                   request: request, challenge: challenge, code: code)
    }

    /// Manually send a challenge (for scripted pairing).
    func sendChallenge() {
        let ch = PairChallenge.generate()
        challenge = ch
        code = PairingCode.generate()
        sendPlain(.pairChallenge(ch))
    }

    func establish() {
        guard let h = phoneHello, let n = ownNonce.take() else { return }
        cipher = try? SessionCipher.establish(identity: identity, role: .desktop, peerPublic: h.publicKey,
                                             ownNonce: n, peerNonce: h.sessionNonce)
    }

    func sendPlain(_ m: Message) { sendEnvelope(try! encodePlaintext(m)) }
    func sendRawPlainJSON(_ json: String) { sendEnvelope([0x00] + Array(json.utf8)) }
    func sendSealed(_ m: Message) {
        guard let cipher else { return }
        sendEnvelope(try! cipher.sealMessage(m))
    }
    func seal(_ m: Message) -> [UInt8] { try! cipher!.sealMessage(m) }
    func sendSealedRaw(_ json: String) {
        guard let cipher else { return }
        sendEnvelope(try! cipher.seal(Array(json.utf8)))
    }
    func sendEnvelope(_ env: [UInt8]) { toPhone.append(contentsOf: try! splitter.split(env, mtu: 185)) }
    /// Raw frame, no framing applied.
    func sendFrame(_ f: [UInt8]) { toPhone.append(f) }

    /// Deliver queued frames to the engine on the current connection.
    @discardableResult
    func deliver() -> Bool {
        guard !toPhone.isEmpty, let p = peer else { return false }
        let frames = toPhone
        toPhone = []
        for f in frames { world.engine.peerReceived(frame: f, from: p) }
        return true
    }
}

/// Engine + transport + clock + scripted desktops.
final class AdvWorld {
    let clock = ManualClock()
    let transport = TapTransport()
    let hostStore: InMemoryPairedHostStore
    let settings = InMemorySettingsStore()
    let identity = StoredIdentity(deviceId: UUID(), keyPair: .generate())
    let partials: Bool
    var counter = 0
    var desktops: [EvilDesktop] = []
    private(set) var events: [PhoneEvent] = []

    lazy var engine: PhoneEngine = {
        let e = PhoneEngine(identity: identity, deviceName: "Adv iPhone", partialStreamingEnabled: partials,
                            hostStore: hostStore, settings: settings, transport: transport, clock: clock)
        e.onEvent = { [unowned self] in events.append($0) }
        return e
    }()

    init(partials: Bool = true) {
        self.partials = partials
        hostStore = InMemoryPairedHostStore()
    }

    func desktop(_ name: String) -> EvilDesktop {
        let d = EvilDesktop(world: self, name: name)
        desktops.append(d)
        return d
    }

    /// Paired on both sides (seed before the engine is created).
    func pairedDesktop(_ name: String) -> EvilDesktop {
        let d = desktop(name)
        d.knownPhones[identity.deviceId] = identity.keyPair.publicBytes
        hostStore.hosts.append(PairedHost(deviceId: d.deviceId, name: name, publicKey: d.identity.publicBytes,
                                          pairedAt: Date()))
        return d
    }

    func pump() {
        var progress = true
        var guardCount = 0
        while progress {
            guardCount += 1
            precondition(guardCount < 100_000, "pump livelock")
            progress = false
            for d in desktops {
                if d.pull() { progress = true }
                if d.deliver() { progress = true }
            }
        }
    }

    func advance(_ seconds: Double, step: Double = 0.1) {
        var t = 0.0
        while t < seconds - 1e-9 {
            clock.now += step
            clock.epochMillis += UInt64(step * 1000)
            t += step
            engine.tick()
            pump()
        }
    }

    var notices: [PhoneNotice] { events.compactMap { if case .notice(let n) = $0 { n } else { nil } } }

    func status(_ id: UUID) -> DeliveryStatus? { engine.deliveryStatus(of: id) }
}

/// One paired, active, Secure desktop.
private func securePair(partials: Bool = true) -> (AdvWorld, EvilDesktop, PeerID) {
    let w = AdvWorld(partials: partials)
    let d = w.pairedDesktop("Mac")
    w.engine.selectHost(d.deviceId)
    let p = d.connect()
    precondition(d.isSecure)
    return (w, d, p)
}

/// One unpaired desktop connected (hellos exchanged).
private func unpaired() -> (AdvWorld, EvilDesktop, PeerID) {
    let w = AdvWorld()
    let d = w.desktop("Mac")
    let p = d.connect()
    return (w, d, p)
}

// MARK: - Session attacks

@Suite("adversary: session (README §7.1, §7.2, §7.4)")
struct AdversarySessionTests {
    @Test func secondPlaintextHelloBeforeSessionIsProtocolError() {
        let (w, d, p) = unpaired()
        d.sendHello()
        w.pump()
        #expect(d.errorsReceived.map(\.code) == ["protocol"])
        #expect(w.transport.disconnected.contains(p))
    }

    @Test func secondHelloInSessionPlainAndEncryptedIsProtocolError() {
        do {
            let (w, d, p) = securePair()
            d.sendSealed(.hello(Hello.new(deviceId: d.deviceId, name: "x", publicKey: d.identity.publicBytes,
                                          paired: true).hello))
            w.pump()
            #expect(w.transport.disconnected.contains(p))
        }
        do {
            let (w, d, p) = securePair()
            let before = w.hostStore.hosts
            d.sendHello()
            w.pump()
            #expect(w.transport.disconnected.contains(p))
            #expect(w.hostStore.hosts == before)
        }
    }

    @Test func storedDeviceIdWithDifferentPubIsUnknownAndStoreUnchanged() throws {
        let w = AdvWorld()
        let real = w.pairedDesktop("Mac")
        let impostor = w.desktop("Mac")
        let before = w.hostStore.hosts
        w.engine.selectHost(real.deviceId)
        impostor.connect(helloDeviceId: real.deviceId)
        let h = try #require(impostor.hellosFromPhone.last)
        #expect(h.paired == false)  // README §7.1: not known → paired:false
        #expect(w.hostStore.hosts == before)
        #expect(w.engine.indicator != .secure)
        let row = try #require(w.engine.hosts.first { $0.id == real.deviceId })
        #expect(row.isPaired == false)
        #expect(row.keyChanged)
        // Nothing utterance-like may reach the impostor.
        w.engine.resend(text: "secret")
        w.pump()
        #expect(impostor.utts.isEmpty)
        #expect(w.engine.pendingDeliveryCount == 1)
    }

    /// Hostile environment: an unauthenticated hello that merely *claims* a
    /// paired desktop's device_id (with another key) must not tear down that
    /// desktop's live, authenticated session. (README §7.1: such a peer is
    /// "not known"; §7.4: unauthenticated input must not change pairing state.)
    @Test func impostorHelloDoesNotKillRealSecureSession() {
        let (w, real, realPeer) = securePair()
        let impostor = w.desktop("Evil")
        impostor.connect(helloDeviceId: real.deviceId)
        #expect(!w.transport.disconnected.contains(realPeer))
        #expect(w.engine.indicator == .secure)
        w.engine.resend(text: "hello")
        w.pump()
        #expect(real.finals.map(\.text) == ["hello"])
    }

    @Test func plaintextUnknownPeerAndBadMacMidSessionLeaveStoreUnchanged() throws {
        for code in [ErrorMsg.unknownPeer, ErrorMsg.badMac, ErrorMsg.decryptFailed, "rate_limited", "busy", "zzz"] {
            let (w, d, _) = securePair()
            let before = w.hostStore.hosts
            d.sendPlain(.error(ErrorMsg(code: code, msg: "spoofed")))
            w.pump()
            #expect(w.hostStore.hosts == before, "code \(code)")
            #expect(w.engine.pairedHostRecords.count == 1, "code \(code)")
            // Reconnect still goes Secure with the kept record.
            if !d.isOpen || code == ErrorMsg.unknownPeer {
                d.hangUp()
                d.connect()
                #expect(d.isSecure, "code \(code)")
                #expect(d.hellosFromPhone.last?.paired == true, "code \(code)")
            }
        }
    }

    @Test func uttLikeMessagesFromDesktopAreIgnored() {
        let (w, d, p) = securePair()
        let id = UUID()
        d.sendSealed(.utt(Utt(id: id, rev: 0, state: .final, text: "inject", ts: 0)))
        d.sendRawPlainJSON(#"{"t":"utt","id":"3b241101-e2bb-4255-8caf-4136c566a962","rev":0,"state":"final","text":"x","ts":1}"#)
        d.sendSealed(.pairRequest(PairRequest.generate()))
        d.sendSealedRaw(#"{"t":"PING"}"#)
        d.sendSealedRaw(#"{"t":"ack","id":"nope","rev":-1}"#)
        d.sendSealedRaw(#"{"t":"ack","id":"3b241101-e2bb-4255-8caf-4136c566a962","rev":1e400}"#)
        d.sendSealedRaw("[1,2,3]")
        w.pump()
        #expect(!w.transport.disconnected.contains(p))
        #expect(w.engine.deliveryStatus(of: id) == nil)
        #expect(w.engine.pendingDeliveryCount == 0)
        #expect(w.engine.indicator == .secure)
    }

    @Test func garbageFramesNeverTrapAndNeverTouchStore() {
        var rng = SystemRandomNumberGenerator()
        for round in 0..<4 {
            let (w, d, _) = round % 2 == 0 ? securePair() : unpaired()
            let before = w.hostStore.hosts
            for i in 0..<3000 {
                let len = Int.random(in: 0...200, using: &rng)
                var f = (0..<len).map { _ in UInt8.random(in: 0...255, using: &rng) }
                if i % 3 == 0, !f.isEmpty { f[0] &= 0x03 }  // valid flags, garbage body
                d.sendFrame(f)
                if d.peer == nil { break }
                d.deliver()
            }
            // Oversized multi-frame message that never completes.
            for _ in 0..<1000 where d.peer != nil { d.sendFrame([0x01, 0x07] + [UInt8](repeating: 0x41, count: 180)) }
            d.deliver()
            #expect(w.hostStore.hosts == before)
        }
    }

    @Test func framesForStaleConnectionAfterReconnectAreIgnored() {
        let (w, d, oldPeer) = securePair()
        w.engine.resend(text: "one")
        d.autoAck = false
        w.pump()
        // Desktop reconnects before the phone noticed the old link died.
        let staleAck = d.seal(.ack(Ack(id: UUID(), rev: 0)))
        let newPeer = d.connect()
        #expect(d.isSecure)
        // Late frames and a late disconnect for the old connection.
        var s = FrameSplitter()
        for f in try! s.split(staleAck, mtu: 185) { w.engine.peerReceived(frame: f, from: oldPeer) }
        w.engine.peerDisconnected(oldPeer)
        w.pump()
        #expect(!w.transport.disconnected.contains(newPeer))
        #expect(w.engine.indicator == .secure)
        #expect(w.engine.pendingDeliveryCount == 1)
        #expect(w.transport.sent[oldPeer, default: []].count < w.transport.sent[newPeer, default: []].count + 100)
    }

    @Test func replayedEncryptedAckIsDroppedSilently() {
        let (w, d, p) = securePair()
        d.autoAck = false
        let f = w.engine.resend(text: "a")
        w.pump()
        let env = d.seal(.ack(Ack(id: f.id, rev: 0)))
        d.sendEnvelope(env)
        w.pump()
        #expect(w.status(f.id) == .acked)
        let e2 = w.engine.sendEdit(id: f.id, text: "b")
        #expect(e2 == "b")
        w.pump()
        d.sendEnvelope(env)  // replay
        d.sendEnvelope(env)
        w.pump()
        #expect(!w.transport.disconnected.contains(p))  // §7.4: replay silently dropped
        #expect(w.status(f.id) == .pending)
    }

    @Test func neverAnsweringPingsDisconnectsWithinBound() {
        let (w, d, p) = securePair()
        d.answerPings = false
        w.advance(44)
        #expect(!w.transport.disconnected.contains(p))
        w.advance(30)
        #expect(w.transport.disconnected.contains(p))
        #expect(w.notices.contains(.keepaliveTimeout(hostName: "Mac")))
        #expect(d.pings == 3)
    }

    @Test func pingFloodIsAnsweredWithoutTrap() {
        let (w, d, p) = securePair()
        for _ in 0..<5000 { d.sendSealed(.ping) }
        w.pump()
        #expect(!w.transport.disconnected.contains(p))
        let pongs = d.inbound.filter { if case .encrypted(.pong) = $0 { true } else { false } }.count
        #expect(pongs == 5000)
    }

    @Test func peerDisconnectForUnknownOrRepeatedPeerIsHarmless() {
        let (w, d, p) = securePair()
        w.engine.peerDisconnected(PeerID("never"))
        w.engine.peerReceived(frame: [0, 0, 0], from: PeerID("never"))
        w.engine.peerDisconnected(p)
        w.engine.peerDisconnected(p)
        d.hangUp()
        d.connect()
        #expect(d.isSecure)
    }
}

// MARK: - Pairing attacks

@Suite("adversary: pairing (README §7.3)")
struct AdversaryPairingTests {
    @Test func unsolicitedChallengeAndResultAreIgnored() {
        let (w, d, p) = unpaired()
        d.sendChallenge()
        d.sendPlain(.pairResult(.success(Bytes32(repeating: 1))))
        d.sendPlain(.pairResult(.failure()))
        w.pump()
        #expect(w.hostStore.hosts.isEmpty)
        #expect(w.engine.pairing == nil)
        #expect(!w.transport.disconnected.contains(p))
        // Normal pairing still works afterwards.
        w.engine.startPairing(with: d.deviceId)
        w.pump()
        w.engine.submitPairingCode(d.code!.string)
        w.pump()
        #expect(d.isSecure)
        #expect(w.hostStore.hosts.count == 1)
    }

    @Test func okTrueWithWrongMacSendsBadMacDisconnectsStoresNothing() {
        let (w, d, p) = unpaired()
        d.autoPairResult = false
        w.engine.startPairing(with: d.deviceId)
        w.pump()
        w.engine.submitPairingCode(d.code!.string)
        w.pump()
        #expect(d.pairConfirmCount == 1)
        d.sendPlain(.pairResult(.success(Bytes32(repeating: 9))))
        w.pump()
        #expect(d.errorsReceived.map(\.code) == ["bad_mac"])
        #expect(w.transport.disconnected.contains(p))
        #expect(w.hostStore.hosts.isEmpty)
        #expect(w.engine.pairedHostRecords.isEmpty)
        #expect(w.engine.activeHostId == nil)
        if case .failed = w.engine.pairing?.phase {} else { Issue.record("pairing not failed") }
    }

    @Test func okTrueWithMacFromAnotherCodeIsRejected() {
        // A MITM that knows nonces but guessed the wrong code.
        let (w, d, p) = unpaired()
        d.autoPairResult = false
        w.engine.startPairing(with: d.deviceId)
        w.pump()
        w.engine.submitPairingCode(d.code!.string)
        w.pump()
        let wrong = PairingCode(value: (d.code!.value + 1) % 1_000_000)!
        let h = d.phoneHello!
        let k = try! PairKey.derive(identity: d.identity, ownRole: .desktop, peerPublic: h.publicKey,
                                    request: PairRequest(nonceP: Bytes32(repeating: 0)),
                                    challenge: PairChallenge(nonceD: Bytes32(repeating: 0)), code: wrong)
        d.sendPlain(.pairResult(k.successMessage()))
        w.pump()
        #expect(w.transport.disconnected.contains(p))
        #expect(w.hostStore.hosts.isEmpty)
    }

    @Test func okTrueWithoutMacOrNullMacStoresNothing() {
        for json in [#"{"t":"pair_result","ok":true}"#, #"{"t":"pair_result","ok":true,"mac":null}"#] {
            let (w, d, _) = unpaired()
            d.autoPairResult = false
            w.engine.startPairing(with: d.deviceId)
            w.pump()
            w.engine.submitPairingCode(d.code!.string)
            w.pump()
            d.sendRawPlainJSON(json)
            w.pump()
            #expect(w.hostStore.hosts.isEmpty)
            #expect(w.engine.indicator != .secure)
            #expect(w.engine.pairedHostRecords.isEmpty)
        }
    }

    enum Stage: CaseIterable { case beforeHello, awaitingChallenge, awaitingCode, awaitingResult, secure }

    @Test(arguments: Stage.allCases, ["rate_limited", "busy"])
    func refusalAtEveryStageIsNonFatalAndStoreUnchanged(stage: Stage, code: String) {
        let w = AdvWorld()
        let d: EvilDesktop
        var p: PeerID
        switch stage {
        case .secure:
            d = w.pairedDesktop("Mac")
            w.engine.selectHost(d.deviceId)
            p = d.connect()
        case .beforeHello:
            d = w.desktop("Mac")
            p = d.connect(sendHello: false)
        default:
            d = w.desktop("Mac")
            p = d.connect()
        }
        let before = w.hostStore.hosts
        switch stage {
        case .awaitingChallenge:
            d.autoChallenge = false
            w.engine.startPairing(with: d.deviceId)
            w.pump()
        case .awaitingCode:
            w.engine.startPairing(with: d.deviceId)
            w.pump()
        case .awaitingResult:
            d.autoPairResult = false
            w.engine.startPairing(with: d.deviceId)
            w.pump()
            w.engine.submitPairingCode(d.code!.string)
            w.pump()
        default: break
        }
        d.sendPlain(.error(ErrorMsg(code: code, msg: "later")))
        w.pump()
        #expect(!w.transport.disconnected.contains(p), "\(stage) \(code): §7.3 non-fatal")
        #expect(w.hostStore.hosts == before)
        #expect(w.notices.contains { if case .peerError(_, code, _) = $0 { true } else { false } })
        if stage == .beforeHello {
            d.sendHello()
            w.pump()
            #expect(d.hellosFromPhone.count == 1)
            return
        }
        if stage == .secure {
            #expect(w.engine.indicator == .secure)
            return
        }
        // The user may try again later on the same connection.
        d.autoChallenge = true
        d.autoPairResult = true
        w.clock.now += 11
        w.engine.startPairing(with: d.deviceId)
        w.pump()
        #expect(d.code != nil)
        w.engine.submitPairingCode(d.code!.string)
        w.pump()
        #expect(d.isSecure, "\(stage) \(code): retry after refusal")
        #expect(w.hostStore.hosts.count == 1)
    }

    @Test func refusalWithDisconnectFailsPairingCleanly() {
        let (w, d, _) = unpaired()
        d.refusePairRequest = "rate_limited"
        w.engine.startPairing(with: d.deviceId)
        w.pump()
        d.hangUp()
        w.engine.submitPairingCode("123456")
        w.pump()
        #expect(w.hostStore.hosts.isEmpty)
        if case .failed = w.engine.pairing?.phase {} else { Issue.record("pairing not failed") }
    }

    @Test func twoDesktopsPairingConcurrentlyOnlyTheChosenOneIsStored() {
        let w = AdvWorld()
        let a = w.desktop("A")
        let b = w.desktop("B")
        a.connect()
        b.connect()
        a.autoPairResult = false
        w.engine.startPairing(with: a.deviceId)
        w.pump()
        let codeA = a.code!.string
        w.engine.startPairing(with: b.deviceId)
        w.pump()
        // The user types A's code anyway: only B may see a pair_confirm.
        w.engine.submitPairingCode(codeA)
        w.pump()
        #expect(a.pairConfirmCount == 0)
        // A, abandoned, now sends a forged ok:true and a challenge.
        a.sendPlain(.pairResult(.success(Bytes32(repeating: 3))))
        a.sendChallenge()
        w.pump()
        #expect(!w.hostStore.hosts.contains { $0.deviceId == a.deviceId })
        // B completes with its own code.
        w.engine.submitPairingCode(b.code!.string)
        w.pump()
        if case .enterCode = w.engine.pairing?.phase {
            w.engine.submitPairingCode(b.code!.string)
            w.pump()
        }
        #expect(b.isSecure)
        #expect(w.hostStore.hosts.map(\.deviceId) == [b.deviceId])
        #expect(w.engine.activeHostId == b.deviceId)
    }

    @Test func codeEnteredAfterDesktopDisconnectedSendsNothing() {
        let (w, d, p) = unpaired()
        w.engine.startPairing(with: d.deviceId)
        w.pump()
        let code = d.code!.string
        d.hangUp()
        let sentBefore = w.transport.sent.values.map(\.count).reduce(0, +)
        w.engine.submitPairingCode(code)
        w.engine.requestNewPairingCode()
        w.pump()
        #expect(w.transport.sent.values.map(\.count).reduce(0, +) == sentBefore)
        #expect(w.hostStore.hosts.isEmpty)
    }

    @Test func pairingMessagesInSessionAreDroppedNotStored() {
        let (w, d, p) = securePair()
        let before = w.hostStore.hosts
        d.sendSealed(.pairResult(.success(Bytes32(repeating: 2))))
        d.sendPlain(.pairChallenge(.generate()))
        d.sendSealed(.pairConfirm(PairConfirm(mac: Bytes32(repeating: 4))))
        w.pump()
        #expect(w.hostStore.hosts == before)
        #expect(!w.transport.disconnected.contains(p))
    }
}

// MARK: - Delivery attacks

@Suite("adversary: delivery (README §5.8, §5.11)")
struct AdversaryDeliveryTests {
    @Test func acksForUnknownIdsAndLowerRevsChangeNothing() {
        let (w, d, _) = securePair()
        d.autoAck = false
        let id = w.engine.beginUtterance()
        w.engine.updatePartial("p")
        w.advance(0.3)
        let f = w.engine.finishUtterance("final")!
        w.pump()
        let finalRev = d.finals.last!.rev
        #expect(finalRev >= 1)
        d.sendSealed(.ack(Ack(id: UUID(), rev: finalRev)))
        d.sendSealed(.ack(Ack(id: id, rev: finalRev - 1)))  // the partial's rev
        w.pump()
        #expect(w.status(f.id) == .pending)
        #expect(w.engine.pendingDeliveryCount == 1)
    }

    /// An ack for a revision the phone never sent is not an ack of the pending
    /// message (README §5.9/§5.11: the desktop acks the (id, rev) it received).
    @Test func ackForFutureRevDoesNotMarkDelivered() {
        let (w, d, _) = securePair()
        d.autoAck = false
        let f = w.engine.resend(text: "x")
        w.pump()
        let rev = d.finals.last!.rev
        d.sendSealed(.ack(Ack(id: f.id, rev: rev + 7)))
        w.pump()
        #expect(w.status(f.id) == .pending)
    }

    @Test func ackFloodIsBoundedAndHarmless() {
        let (w, d, p) = securePair()
        d.autoAck = false
        let f = w.engine.resend(text: "x")
        w.pump()
        let start = Date()
        for i in 0..<20_000 {
            d.sendSealed(.ack(Ack(id: i % 2 == 0 ? UUID() : UUID(uuidString: "00000000-0000-4000-8000-000000000000")!,
                                  rev: UInt32.random(in: 0...UInt32.max))))
        }
        w.pump()
        #expect(Date().timeIntervalSince(start) < 30)
        #expect(!w.transport.disconnected.contains(p))
        #expect(w.status(f.id) == .pending)
        d.sendSealed(.ack(Ack(id: f.id, rev: d.finals.last!.rev)))
        d.sendSealed(.ack(Ack(id: f.id, rev: d.finals.last!.rev)))
        w.pump()
        #expect(w.status(f.id) == .acked)
        #expect(w.engine.pendingDeliveryCount == 0)
    }

    @Test func burstOfThousandsOfPartialsIsThrottledLatestWinsBounded() {
        let (w, d, _) = securePair()
        let id = w.engine.beginUtterance()
        var sendTimes: [Double] = []
        var last = ""
        for step in 0..<50 {  // 5 s at 100 ms ticks
            var before = d.partials.count
            for j in 0..<2000 {
                last = "burst \(step) \(j)"
                w.engine.updatePartial(last)
            }
            w.pump()
            for _ in before..<d.partials.count { sendTimes.append(w.clock.now) }
            before = d.partials.count
            w.clock.now += 0.1
            w.engine.tick()
            w.pump()
            for _ in before..<d.partials.count { sendTimes.append(w.clock.now) }
        }
        w.advance(0.5)
        #expect(d.partials.last?.text == last)
        #expect(d.partials.count <= 5 * 6)
        for t in sendTimes {
            #expect(sendTimes.filter { $0 >= t - 1e-6 && $0 < t + 1.0 - 1e-6 }.count <= 5)
        }
        let f = w.engine.finishUtterance(last)
        w.pump()
        #expect(f?.id == id)
        #expect(d.finals.count == 1)
    }

    @Test func finalSupersedesThrottledPartialNoStalePartialAfter() {
        let (w, d, _) = securePair()
        let id = w.engine.beginUtterance()
        w.engine.updatePartial("one")
        w.pump()
        w.engine.updatePartial("one two")  // throttled
        w.engine.finishUtterance("one two three")
        w.pump()
        w.advance(3)
        let mine = d.utts.filter { $0.id == id }
        #expect(mine.last?.state == .final)
        #expect(mine.filter { $0.state == .partial }.allSatisfy { $0.rev < mine.last!.rev })
        #expect(!mine.contains { $0.state == .partial && $0.text == "one two" })
        // Next utterance's partials are a different id.
        let id2 = w.engine.beginUtterance()
        w.engine.updatePartial("x")
        w.advance(0.3)
        #expect(d.utts.filter { $0.id == id }.last?.state == .final)
        #expect(d.partials.last?.id == id2)
    }

    @Test func editBeforeFinalAckedOnlyEditSettles() {
        let (w, d, _) = securePair()
        d.autoAck = false
        let f = w.engine.resend(text: "helo")
        w.pump()
        _ = w.engine.sendEdit(id: f.id, text: "hello")
        w.pump()
        // Late ack of the final must not settle the edit.
        d.sendSealed(.ack(Ack(id: f.id, rev: d.finals[0].rev)))
        w.pump()
        #expect(w.status(f.id) == .pending)
        w.advance(2.1)
        // The retry is the edit, never the old final.
        #expect(d.finals.count == 1)
        #expect(d.edits.count >= 2)
        #expect(d.edits.allSatisfy { $0.text == "hello" && $0.rev > d.finals[0].rev })
        d.sendSealed(.ack(Ack(id: f.id, rev: d.edits.last!.rev)))
        w.pump()
        #expect(w.status(f.id) == .acked)
    }

    @Test func resendWhilePendingCreatesNewIdBothDelivered() {
        let (w, d, _) = securePair()
        d.autoAck = false
        let a = w.engine.resend(text: "same")
        let b = w.engine.resend(text: "same")
        w.pump()
        #expect(a.id != b.id)
        #expect(Set(d.finals.map(\.id)) == [a.id, b.id])
        #expect(d.finals.allSatisfy { $0.rev == 0 })
    }

    /// Items must only ever go to the active, Secure host; after a switch the
    /// old host gets nothing new (no partials, no finals, no retries).
    @Test func switchActiveHostMidUtteranceNothingMoreToOldHost() {
        let w = AdvWorld()
        let a = w.pairedDesktop("A")
        let b = w.pairedDesktop("B")
        w.engine.selectHost(a.deviceId)
        a.connect()
        b.connect()
        a.autoAck = false
        let id = w.engine.beginUtterance()
        w.engine.updatePartial("to A")
        w.pump()
        let pending = w.engine.resend(text: "pending for A")
        w.pump()
        let aCount = a.utts.count
        w.engine.selectHost(b.deviceId)
        w.pump()
        w.engine.updatePartial("to B now")
        w.advance(0.3)
        w.engine.finishUtterance("done")
        w.advance(15)
        #expect(a.utts.count == aCount)
        #expect(b.utts.contains { $0.id == id && $0.state == .final && $0.text == "done" })
        #expect(b.finals.contains { $0.id == pending.id })
        #expect(w.status(id) == .acked)
    }

    @Test func activeHostDropsWithPendingFinalDifferentHostBecomesActive() {
        let w = AdvWorld()
        let a = w.pairedDesktop("A")
        let b = w.pairedDesktop("B")
        w.engine.selectHost(a.deviceId)
        a.connect()
        a.autoAck = false
        let f = w.engine.resend(text: "x")
        w.pump()
        a.hangUp()
        b.connect()
        // B is connected but not active: it must not receive A's pending item.
        #expect(b.utts.isEmpty)
        // A reconnects but is no longer the target after the user picks B.
        w.engine.selectHost(b.deviceId)
        w.pump()
        let aBefore = a.utts.count
        a.connect()
        w.advance(15)
        #expect(a.utts.count == aBefore)
        #expect(b.finals.filter { $0.id == f.id }.count == 1)
        #expect(w.status(f.id) == .acked)
    }

    @Test func retryExhaustionThenFailedThenLateAck() {
        let (w, d, _) = securePair()
        d.autoAck = false
        let f = w.engine.resend(text: "r")
        w.pump()
        w.advance(30)
        #expect(d.finals.count == 6)  // 1 send + 5 retries
        #expect(w.status(f.id) == .failed)
        let times = d.finals.count
        w.advance(30)
        #expect(d.finals.count == times)  // no more while connected
        d.sendSealed(.ack(Ack(id: f.id, rev: 0)))
        w.pump()
        #expect(w.status(f.id) == .acked)
        #expect(w.engine.pendingDeliveryCount == 0)
    }

    @Test func revNeverReusedWithDifferentTextAcrossReconnects() {
        let (w, d, _) = securePair()
        var seen: [UUID: [UInt32: String]] = [:]
        var ids: [UUID] = []
        for round in 0..<20 {
            d.autoAck = round % 3 == 0
            let id = w.engine.beginUtterance()
            ids.append(id)
            w.engine.updatePartial("r\(round) a")
            w.advance(0.3)
            if round % 4 == 1 { d.hangUp() }
            w.engine.updatePartial("r\(round) ab")
            w.engine.finishUtterance("r\(round) abc")
            if d.peer == nil { d.connect() }
            w.pump()
            for old in ids.suffix(3) { _ = w.engine.sendEdit(id: old, text: "edit \(round) \(old)") }
            w.advance(2.5)
            if round % 5 == 2 { d.hangUp(); w.advance(1); d.connect() }
        }
        w.advance(5)
        for u in d.utts {
            if let t = seen[u.id]?[u.rev] { #expect(t == u.text, "rev \(u.rev) reused with different text") }
            seen[u.id, default: [:]][u.rev] = u.text
        }
        for id in ids {
            let mine = d.utts.filter { $0.id == id }
            var maxByText: [String: UInt32] = [:]
            for u in mine { maxByText[u.text] = max(maxByText[u.text] ?? 0, u.rev) }
            // Every final/edit for this id is newer than every partial.
            let lastPartial = mine.filter { $0.state == .partial }.map(\.rev).max() ?? 0
            #expect(mine.filter { $0.state != .partial }.allSatisfy { $0.rev > lastPartial || mine.allSatisfy { $0.state != .partial } })
        }
    }

    @Test func boundaryTextsAreDeliveredIntact() {
        let (w, d, p) = securePair()
        w.transport.mtuValue = 20
        let maxEscapes = String(repeating: "\u{1}", count: 10_897)  // 126 + 6·10897 = 65,508
        #expect(uttTextFits(maxEscapes))
        #expect(!uttTextFits(maxEscapes + "\u{1}"))
        let maxBytes = String(repeating: "a", count: 32_000)
        let mixed = String(repeating: "\u{0}\u{202E}\"\\😀é\u{1F}\n", count: 1500)
        for text in [maxEscapes, maxBytes, mixed, "", "\u{FEFF}"] {
            let f = w.engine.resend(text: text)
            w.pump()
            #expect(d.finals.last?.id == f.id, "text of \(text.utf8.count) bytes not delivered")
            #expect(d.finals.last?.text == f.text)
            #expect(w.status(f.id) == .acked)
        }
        #expect(!w.transport.disconnected.contains(p))
        // Over the limit: truncated at a scalar boundary, still delivered.
        let over = String(repeating: "a", count: 31_998) + "😀"
        let f = w.engine.resend(text: over)
        w.pump()
        #expect(f.truncated)
        #expect(d.finals.last?.text == String(repeating: "a", count: 31_998))
        let overEsc = maxEscapes + "\u{1}\u{1}"
        let id = w.engine.beginUtterance()
        w.engine.updatePartial(overEsc)
        w.pump()
        #expect(!w.engine.isUtteranceOpen)
        #expect(d.finals.last?.id == id)
        #expect(d.finals.last?.text == maxEscapes)
        // Edit of an over-limit text.
        let e = w.engine.sendEdit(id: id, text: overEsc + "zzz")
        w.pump()
        #expect(e == maxEscapes)
        #expect(d.edits.last?.text == maxEscapes)
    }

    @Test func partialAtBoundaryIsSentNotDroppedSilently() {
        let (w, d, _) = securePair()
        let maxEscapes = String(repeating: "\u{1}", count: 10_897)
        w.engine.beginUtterance()
        w.engine.updatePartial(maxEscapes)
        w.pump()
        #expect(d.partials.last?.text == maxEscapes)
    }

    @Test func clockJumpsDoNotTrapAndFinalsStayImmediate() {
        let (w, d, p) = securePair()
        d.autoAck = false
        w.engine.beginUtterance()
        w.engine.updatePartial("a")
        w.pump()
        // Backwards.
        w.clock.now -= 10_000
        w.clock.epochMillis = 0
        w.engine.updatePartial("ab")
        w.engine.tick()
        let f1 = w.engine.finishUtterance("abc")!
        w.pump()
        #expect(d.finals.last?.id == f1.id)
        // Forwards, huge.
        w.clock.now += 1e12
        w.clock.epochMillis = UInt64.max
        w.engine.tick()
        w.pump()
        let id2 = w.engine.beginUtterance()
        w.engine.updatePartial("z")
        let f2 = w.engine.finishUtterance("zz")
        w.pump()
        #expect(f2?.id == id2)
        #expect(d.finals.last?.ts == UInt64.max)
        w.engine.tick()
        w.pump()
        _ = p
    }

    /// README §5.11 / §8: partials ≤ 5 per second on the wire, also across
    /// back-to-back utterances.
    @Test func partialRateHoldsAcrossBackToBackUtterances() {
        let (w, d, _) = securePair()
        for i in 0..<10 {
            w.engine.beginUtterance()
            w.engine.updatePartial("u\(i)")
            w.pump()
            w.engine.finishUtterance("u\(i)!")
            w.pump()
            w.clock.now += 0.05
        }
        #expect(d.partials.count <= 5)
    }
}

// MARK: - Resource attacks

@Suite("adversary: resources")
struct AdversaryResourceTests {
    @Test func tenThousandConnectDisconnectCyclesStayBounded() {
        let w = AdvWorld()
        let d = w.pairedDesktop("Mac")
        w.engine.selectHost(d.deviceId)
        let start = Date()
        for i in 0..<10_000 {
            d.connect()
            if i % 2 == 0 { d.hangUp() } else { w.engine.disconnectAll() }
            w.transport.sent = [:]
            w.transport.disconnected = []
        }
        #expect(w.engine.hosts.count == 1)
        #expect(Date().timeIntervalSince(start) < 60)
        d.connect()
        #expect(d.isSecure)
    }

    @Test func tenThousandDistinctUnpairedDesktopsLeaveNoTrace() {
        let w = AdvWorld()
        for i in 0..<10_000 {
            let d = EvilDesktop(world: w, name: "D\(i)")
            w.desktops = [d]
            d.connect()
            d.sendPlain(.error(ErrorMsg(code: ErrorMsg.unknownPeer)))
            d.deliver()
            d.hangUp()
            w.transport.sent = [:]
            w.transport.disconnected = []
        }
        #expect(w.engine.hosts.isEmpty)
        #expect(w.hostStore.hosts.isEmpty)
    }

    /// The phone keeps per-utterance state (statuses / revisions / ts) for
    /// every utterance forever. SPEC §5.1 caps history at 1,000 entries and the
    /// app's prune does not call forgetDelivery, so acked deliveries must not
    /// be retained by the engine without bound.
    @Test func ackedDeliveryStateIsNotRetainedForever() {
        let (w, _, _) = securePair()
        let first = w.engine.resend(text: "first").id
        w.pump()
        for i in 0..<3_000 {
            w.engine.resend(text: "n\(i)")
            w.pump()
        }
        #expect(w.status(first) == nil, "engine still tracks the delivery of an utterance 3,000 entries ago")
    }

    /// `forgetDelivery` (history delete) must release all per-id state; it
    /// keeps the revision counter and ts, so every utterance leaks forever.
    @Test func forgetDeliveryReleasesAllPerIdState() {
        let (w, _, _) = securePair()
        let f = w.engine.resend(text: "x")
        w.pump()
        w.engine.forgetDelivery(f.id)
        #expect(w.engine.deliveryStatus(of: f.id) == nil)
        #expect(w.engine.sendEdit(id: f.id, text: "y") == nil, "per-id rev state survived forgetDelivery")
    }

    /// Pending items while no host is reachable for a long time: the queue
    /// must be bounded (SPEC §5.1 history cap 1,000).
    @Test func pendingQueueWithNoHostIsBounded() {
        let w = AdvWorld()
        for i in 0..<5_000 { w.engine.resend(text: "q\(i)") }
        #expect(w.engine.pendingDeliveryCount <= 1_000)
    }

    @Test func manyPendingDeliveredOnceWhenHostAppears() {
        let w = AdvWorld()
        let d = w.pairedDesktop("Mac")
        w.engine.selectHost(d.deviceId)
        var ids: [UUID] = []
        for i in 0..<500 { ids.append(w.engine.resend(text: "q\(i)").id) }
        d.connect()
        #expect(Set(d.finals.map(\.id)) == Set(ids))
        #expect(d.finals.count == 500)
        #expect(w.engine.pendingDeliveryCount == 0)
    }

    @Test func connectionsThatNeverSendHelloDoNotAppearOrBlock() {
        let w = AdvWorld()
        for i in 0..<5_000 { w.engine.peerConnected(PeerID("silent\(i)")) }
        #expect(w.engine.hosts.isEmpty)
    }
}
