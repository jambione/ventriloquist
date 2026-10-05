import Foundation
import VQPhoneCore
import VQProtocol

/// An in-memory desktop built only from VQProtocol's public API. It follows
/// README §7 from the desktop side, with switches for misbehaviour.
final class FakeDesktop {
    let identity = IdentityKeyPair.generate()
    let deviceId = UUID()
    var name: String
    let clock: ManualClock

    /// Persistent pairing store: phone device_id → pub.
    var knownPhones: [UUID: Bytes32] = [:]

    // Behaviour switches.
    var autoAck = true
    var answerPings = true
    var corruptDesktopMac = false
    /// Reply to `pair_request` with `error{code}` (e.g. "rate_limited"); the
    /// link stays open unless `closeAfterRefusal` (README §7.3).
    var errorOnPairRequest: String?
    var closeAfterRefusal = false
    /// Send this raw JSON as the plaintext hello instead of a real one.
    var rawHelloJSON: String?
    /// Enforce the desktop's real pairing limits (README §7.3, D10; mirrors
    /// desktop/core/src/pairing_guard.rs): 10 s between accepted requests,
    /// more than 5 in 10 minutes refuses the device for 10 minutes, and a
    /// global lockout (30 s doubling, max 1 h) after each invalidated code.
    var enforcePairingLimits = true
    private var requestTimes: [Double] = []
    private var lastAccepted: Double?
    private var refusedUntil: Double = 0
    private var invalidations = 0
    private var lockedUntil: Double = 0

    // Per-connection state.
    private(set) var peer: PeerID?
    private var splitter = FrameSplitter()
    private var reassembler = Reassembler()
    private var ownNonce: SessionNonce?
    private(set) var phoneHello: Hello?
    private(set) var cipher: SessionCipher?
    private(set) var code: PairingCode?
    private var codeAt: Double = 0
    private var failures = 0
    private var request: PairRequest?
    private var challenge: PairChallenge?
    private(set) var closedByDesktop = false

    // Records.
    private(set) var inbound: [Inbound] = []
    private(set) var utts: [Utt] = []
    private(set) var pairRequests = 0
    /// `pair_request`s that were not refused by the limits.
    private(set) var acceptedPairRequests = 0
    /// How many requests the limits answered with `rate_limited`.
    private(set) var rateLimitedAnswers = 0
    private(set) var pairConfirms = 0
    private(set) var pingsReceived = 0
    private(set) var pongsReceived = 0
    private(set) var errorsReceived: [ErrorMsg] = []

    /// Frames waiting to go to the phone.
    var toPhone: [[UInt8]] = []
    let mtu: Int

    init(name: String, clock: ManualClock, mtu: Int = 185) {
        self.name = name
        self.clock = clock
        self.mtu = mtu
    }

    var isSecure: Bool { cipher != nil }
    var sessionCode: String? { code?.string }

    // MARK: connection lifecycle

    func startConnection(peer: PeerID) {
        self.peer = peer
        splitter = FrameSplitter()
        reassembler = Reassembler()
        phoneHello = nil
        cipher = nil
        code = nil
        failures = 0
        request = nil
        challenge = nil
        closedByDesktop = false
        toPhone = []
        if let raw = rawHelloJSON {
            sendEnvelope([0x00] + Array(raw.utf8))
            return
        }
        let own = Hello.new(deviceId: deviceId, name: name, publicKey: identity.publicBytes, paired: false)
        let hello = own.hello
        ownNonce = own.takeNonce()
        sendPlain(.hello(hello))
    }

    func connectionClosed(_ closing: PeerID) {
        guard closing == peer else { return }
        peer = nil
        cipher = nil
        _ = ownNonce.take()
    }

    // MARK: receive

    func receive(frame: [UInt8]) {
        guard let msg = try? reassembler.push(frame) else { return }
        let ib: Inbound
        do { ib = try decodeInbound(msg, session: cipher) } catch { return }
        inbound.append(ib)
        if isSecure {
            guard (try? checkInSession(ib)) != nil else { return }
            switch ib.message {
            case .utt(let u):
                utts.append(u)
                if autoAck, u.state != .partial { sendSealed(.ack(Ack(id: u.id, rev: u.rev))) }
            case .ping:
                pingsReceived += 1
                if answerPings { sendSealed(.pong) }
            case .pong: pongsReceived += 1
            case .error(let e): errorsReceived.append(e)
            default: break
            }
            return
        }
        switch ib.message {
        case .hello(let h):
            phoneHello = h
            let knows = knownPhones[h.deviceId] == h.publicKey
            if enforcePairingLimits, refusedUntil > clock.now, !(knows && h.paired) {
                rateLimitedAnswers += 1
                sendPlain(.error(ErrorMsg(code: "rate_limited", msg: "")))
                closedByDesktop = true
                return
            }
            if knows && h.paired {
                establish()
            } else if !knows && h.paired {
                sendPlain(.error(ErrorMsg(code: ErrorMsg.unknownPeer, msg: "Unknown phone")))
                closedByDesktop = true
            }
        case .pairRequest(let r):
            pairRequests += 1
            if let code = errorOnPairRequest {
                sendPlain(.error(ErrorMsg(code: code, msg: "Try later")))
                closedByDesktop = closeAfterRefusal
                return
            }
            if enforcePairingLimits, let verdict = judgePairRequest() {
                rateLimitedAnswers += 1
                sendPlain(.error(ErrorMsg(code: "rate_limited", msg: "Try later")))
                closedByDesktop = verdict
                return
            }
            acceptedPairRequests += 1
            lastAccepted = clock.now
            request = r
            let ch = PairChallenge.generate()
            challenge = ch
            code = PairingCode.generate()
            codeAt = clock.now
            failures = 0
            sendPlain(.pairChallenge(ch))
        case .pairConfirm(let c):
            pairConfirms += 1
            guard let h = phoneHello, let request, let challenge, let code,
                  clock.now - codeAt < 120, failures < 3,
                  let key = try? PairKey.derive(identity: identity, ownRole: .desktop, peerPublic: h.publicKey,
                                                request: request, challenge: challenge, code: code)
            else {
                sendPlain(.pairResult(.failure()))
                return
            }
            if (try? key.verifyPhoneMac(c.mac)) != nil {
                knownPhones[h.deviceId] = h.publicKey
                invalidations = 0
                lockedUntil = 0
                let ok = corruptDesktopMac ? PairResult.success(Bytes32(repeating: 7)) : key.successMessage()
                sendPlain(.pairResult(ok))
                establish()
            } else {
                failures += 1
                if failures >= 3 {
                    self.code = nil
                    invalidations += 1
                    lockedUntil = clock.now + min(30 * pow(2, Double(min(invalidations - 1, 16))), 3_600)
                }
                sendPlain(.pairResult(.failure()))
            }
        case .error(let e):
            errorsReceived.append(e)
            closedByDesktop = true
        default:
            break
        }
    }

    /// `nil` = allow; otherwise whether the desktop also disconnects.
    private func judgePairRequest() -> Bool? {
        let now = clock.now
        if refusedUntil > now { return true }
        requestTimes.append(now)
        requestTimes.removeAll { now - $0 >= 600 }
        if requestTimes.count > 5 {
            requestTimes = []
            refusedUntil = now + 600
            return true
        }
        if let last = lastAccepted, now - last < 10 { return false }
        if lockedUntil > now { return false }
        return nil
    }

    private func establish() {
        guard let h = phoneHello, let n = ownNonce.take() else { return }
        cipher = try? SessionCipher.establish(identity: identity, role: .desktop, peerPublic: h.publicKey,
                                             ownNonce: n, peerNonce: h.sessionNonce)
    }

    // MARK: send

    func sendPlain(_ m: Message) {
        sendEnvelope(try! encodePlaintext(m))
    }

    func sendSealed(_ m: Message) {
        guard let cipher else { return }
        sendEnvelope(try! cipher.sealMessage(m))
    }

    func sendEnvelope(_ env: [UInt8]) {
        toPhone.append(contentsOf: try! splitter.split(env, mtu: mtu))
    }

    /// Seal without sending (to replay it later).
    func sealOnly(_ m: Message) -> [UInt8] { try! cipher!.sealMessage(m) }

    // MARK: inspection

    var hellosFromPhone: [Hello] {
        inbound.compactMap { if case .hello(let h) = $0.message { h } else { nil } }
    }
    var finals: [Utt] { utts.filter { $0.state == .final } }
    var partials: [Utt] { utts.filter { $0.state == .partial } }
    var edits: [Utt] { utts.filter { $0.state == .edit } }
}

/// In-memory transport connecting one engine to several fake desktops.
final class FakeNetwork: PhoneTransport {
    weak var engine: PhoneEngine?
    private(set) var desktops: [PeerID: FakeDesktop] = [:]
    private var toDesktop: [PeerID: [[UInt8]]] = [:]
    private(set) var disconnectedByPhone: [PeerID] = []
    private(set) var framesSent: [PeerID: [[UInt8]]] = [:]
    private var counter = 0
    /// `true` (default): a close from the phone still delivers frames that
    /// were already sent, like the transports' documented graceful close
    /// (a socket close flushes written bytes; the BLE queue sends what it
    /// holds, see the transport). `false` models an
    /// abrupt close that discards queued frames.
    var gracefulDisconnect = true

    func send(frame: [UInt8], to peer: PeerID) {
        guard desktops[peer] != nil else { return }
        toDesktop[peer, default: []].append(frame)
        framesSent[peer, default: []].append(frame)
    }

    /// Frames already queued still reach the desktop when `gracefulDisconnect`
    /// is on, then the link closes.
    func disconnect(_ peer: PeerID) {
        disconnectedByPhone.append(peer)
        if gracefulDisconnect, let d = desktops[peer] {
            for f in toDesktop[peer] ?? [] { d.receive(frame: f) }
        }
        desktops[peer]?.connectionClosed(peer)
        desktops[peer] = nil
        toDesktop[peer] = nil
    }

    func mtu(for peer: PeerID) -> Int { desktops[peer]?.mtu ?? 20 }

    /// Connect `d` as a new connection and run the hello exchange.
    @discardableResult
    func connect(_ d: FakeDesktop) -> PeerID {
        counter += 1
        let peer = PeerID("fake:\(d.name)#\(counter)")
        // The fake serves one link at a time: an older link of the same
        // desktop goes stale silently (the phone has not noticed yet).
        for (old, od) in desktops where od === d {
            desktops[old] = nil
            toDesktop[old] = nil
        }
        desktops[peer] = d
        engine?.peerConnected(peer)
        d.startConnection(peer: peer)
        pump()
        return peer
    }

    /// The desktop side drops the link.
    func drop(_ peer: PeerID) {
        guard let d = desktops[peer] else { return }
        d.connectionClosed(peer)
        desktops[peer] = nil
        toDesktop[peer] = nil
        engine?.peerDisconnected(peer)
    }

    func isConnected(_ peer: PeerID) -> Bool { desktops[peer] != nil }

    /// Deliver queued frames both ways until quiet. A desktop that decided to
    /// close (after sending `error`) is disconnected once its frames are out.
    func pump() {
        var progress = true
        while progress {
            progress = false
            for peer in Array(toDesktop.keys) {
                guard let frames = toDesktop[peer], !frames.isEmpty, let d = desktops[peer] else { continue }
                toDesktop[peer] = []
                for f in frames { d.receive(frame: f) }
                progress = true
            }
            for (peer, d) in desktops where !d.toPhone.isEmpty && d.peer == peer {
                let frames = d.toPhone
                d.toPhone = []
                for f in frames where desktops[peer] != nil { engine?.peerReceived(frame: f, from: peer) }
                progress = true
            }
            for (peer, d) in desktops where d.closedByDesktop && d.toPhone.isEmpty {
                drop(peer)
                progress = true
            }
        }
    }
}

/// Engine + network + clock + stores.
final class Harness {
    let clock = ManualClock()
    private let network = FakeNetwork()
    /// The network; touching it creates the engine (after any `pairedDesktop`).
    var net: FakeNetwork {
        _ = engine
        return network
    }
    let hostStore: InMemoryPairedHostStore
    let settings: InMemorySettingsStore
    let identity: StoredIdentity
    let partials: Bool
    private(set) var events: [PhoneEvent] = []

    /// Created on first use, so `pairedDesktop` can seed the store first.
    lazy var engine: PhoneEngine = {
        let e = PhoneEngine(identity: identity, deviceName: "Test iPhone", partialStreamingEnabled: partials,
                            hostStore: hostStore, settings: settings, transport: network, clock: clock)
        network.engine = e
        e.onEvent = { [unowned self] in events.append($0) }
        return e
    }()

    init(hosts: [PairedHost] = [], lastHostId: UUID? = nil, identity: StoredIdentity? = nil,
         partials: Bool = true) {
        hostStore = InMemoryPairedHostStore(hosts: hosts)
        settings = InMemorySettingsStore(lastHostId: lastHostId)
        self.identity = identity ?? StoredIdentity(deviceId: UUID(), keyPair: .generate())
        self.partials = partials
    }

    func desktop(_ name: String, mtu: Int = 185) -> FakeDesktop { FakeDesktop(name: name, clock: clock, mtu: mtu) }

    /// A desktop already paired on both sides.
    func pairedDesktop(_ name: String, mtu: Int = 185) -> FakeDesktop {
        precondition(network.engine == nil, "seed paired desktops before using the engine")
        let d = desktop(name, mtu: mtu)
        d.knownPhones[identity.deviceId] = identity.keyPair.publicBytes
        var hosts = hostStore.hosts
        hosts.append(PairedHost(deviceId: d.deviceId, name: name, publicKey: d.identity.publicBytes, pairedAt: Date()))
        hostStore.hosts = hosts
        return d
    }

    /// Run the user-driven pairing flow with the code the desktop shows.
    func pair(_ d: FakeDesktop) {
        engine.startPairing(with: d.deviceId)
        net.pump()
        engine.submitPairingCode(d.sessionCode!)
        net.pump()
    }

    /// Advance time in 100 ms ticks.
    func advance(_ seconds: Double, step: Double = 0.1) {
        var t = 0.0
        while t < seconds - 1e-9 {
            clock.advance(step)
            t += step
            engine.tick()
            net.pump()
        }
    }

    var notices: [PhoneNotice] {
        events.compactMap { if case .notice(let n) = $0 { n } else { nil } }
    }

    func statusEvents(_ id: UUID) -> [DeliveryStatus] {
        events.compactMap { if case .deliveryChanged(id, let s) = $0 { s } else { nil } }
    }
}

/// A wrong code that differs from `code`.
func wrongCode(_ code: String) -> String { code == "000000" ? "000001" : "000000" }
