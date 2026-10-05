import Foundation
import VQProtocol

/// The phone side of Ventriloquist, independent of any transport or UI.
///
/// * Per-desktop connection state machine (README §7): one `hello` each way,
///   the Secure decision from our own store (§7.2), pairing (§7.3), the
///   in-session policy (§7.4) and keepalive (§5.10).
/// * The host list (SPEC §3.1) and the active host, remembered across launches.
/// * The utterance pipeline (SPEC §4.6, README §5.8/§5.11): ids, revisions,
///   partial throttling, finals, edits, re-sends, size limits, retries, the
///   queue while no host is active, and delivery status.
///
/// Threading: not thread-safe and not `Sendable`. Confine it to one isolation
/// domain (the app: the main actor) and deliver transport events there.
/// Time comes only from the injected ``PhoneClock``; call ``tick()`` often
/// (the app uses 10 Hz) so timers fire.
public final class PhoneEngine {
    // MARK: Tunables (README §8)

    /// Minimum spacing of partials: at most 5 per second.
    public static let partialInterval: Double = 0.2
    /// Retry spacing for unacked `final`/`edit`.
    public static let retryInterval: Double = 2
    /// Retries per connection before the delivery is marked failed.
    public static let maxRetries = 5
    public static let pingInterval = Double(VQ.pingIntervalSeconds)
    public static let maxMissedPings = VQ.pingMaxMissed
    public static let codeLifetime = Double(VQ.pairCodeTTLSeconds)
    /// Wrong codes after which the desktop invalidates its code (README §6.2).
    public static let maxCodeFailures = VQ.pairMaxFailures
    /// Upper bound for peer-supplied text shown in the UI (e.g. `error.msg`).
    static let maxPeerTextShown = 200
    /// Deliveries waiting for an ack (or a host). On overflow the oldest
    /// becomes `failed` and leaves the queue; the user can Re-send it.
    public static let maxPendingDeliveries = 1_000
    /// Settled (acked or dropped) utterance ids whose state is kept, so a late
    /// status or an edit still works; the oldest are forgotten beyond this.
    public static let maxSettledTracked = 1_000
    /// A connection that has not sent its `hello` by then is closed.
    public static let helloTimeout: Double = 30
    /// Connections that are not yet proven (no hello, not paired/pairing, or
    /// Secure without an authenticated message) kept at most; the oldest go first.
    public static let maxUnprovenConnections = 8
    /// Name shown when a desktop sends none.
    static let unnamedDesktop = "Unnamed desktop"

    // Pairing limits as the desktop enforces them (README §7.3, desktop
    // `pairing_guard.rs`). The phone keeps within them, so it never provokes
    // a lockout by itself.
    /// Minimum spacing of `pair_request`s to one desktop.
    public static let pairRequestMinInterval: Double = 10
    /// Window for ``pairRequestsPerWindow``.
    public static let pairRequestWindow: Double = 600
    /// `pair_request`s one desktop tolerates per window before it refuses us for 10 minutes.
    public static let pairRequestsPerWindow = 5
    /// The desktop refuses a device that exceeded the window for this long.
    static let deviceRefusal: Double = 600
    /// Global lockout after the n-th invalidated code: 30 s doubling, max 1 h.
    static func lockoutDuration(_ n: Int) -> Double {
        min(30 * pow(2, Double(min(max(n - 1, 0), 16))), 3_600)
    }

    // MARK: Dependencies

    public let identity: StoredIdentity
    private let hostStore: PairedHostStore
    private let settings: PhoneSettingsStore
    private let transport: PhoneTransport
    private let clock: PhoneClock
    private let relayStore: PairedRelayDesktopStore?
    private let relaySecrets: RelaySecretStore?
    private let relayRooms: RelayRoomControl?

    // MARK: Observation

    /// Called after any state change visible through the public properties.
    public var onChange: (() -> Void)?
    /// Discrete events (delivery changes, notices, size limit).
    public var onEvent: ((PhoneEvent) -> Void)?
    /// Local diagnostics. Never contains secrets or pairing codes.
    public var log: ((String) -> Void)?

    // MARK: Settings

    /// Name sent in our `hello` (SPEC §5.1 Settings). Applies to new connections.
    public var deviceName: String
    /// SPEC §5.1: when off, only `final`/`edit` are sent.
    public var partialStreamingEnabled: Bool

    // MARK: State

    private var connections: [PeerID: Connection] = [:]
    private var pairedHosts: [PairedHost]
    private var relayDesktops: [PairedRelayDesktop] = []
    /// QR pairing code per relay peer, used once when its challenge arrives.
    private var autoPairCodes: [PeerID: String] = [:]
    private var notRecognized: Set<UUID> = []
    public private(set) var activeHostId: UUID?
    public private(set) var pairing: PairingStatus?
    private var pairingPeer: PeerID?
    private var connectionCounter = 0

    /// Our own client-side view of one desktop's pairing limits.
    private struct PairBudget {
        var requestTimes: [Double] = []
        /// No `pair_request` before this (rate limit / lockout answers).
        var blockedUntil: Double = 0
        /// Codes invalidated by 3 wrong entries since the last success.
        var invalidations = 0
    }
    private var pairBudgets: [UUID: PairBudget] = [:]
    /// When the failed-pairing sheet may try again (drives `retryIn`).
    private var pairingRetryAt: Double?
    /// Preferred connection of the active host, to notice when it changes.
    private var activePeer: PeerID?
    private var lastPartialAt: Double?
    /// Settled ids in settle order, for bounding per-id state.
    private var settledOrder: [UUID] = []
    private var settledHead = 0
    /// The paired-host file existed but could not be read at launch.
    public private(set) var pairedHostsUnreadable = false
    private var hostFileNeedsBackup = false

    private struct CurrentUtterance {
        let id: UUID
        let ts: UInt64
        var pendingPartial: String?
        var lastSentPartial: String?
    }

    private struct PendingDelivery {
        let id: UUID
        let rev: UInt32
        let state: UttState
        let text: String
        let ts: UInt64
        /// Connection it was last sent on; `nil` = not yet sent on any.
        var sentOn: PeerID?
        var lastSentAt: Double = 0
        var retries = 0
        var failed = false
    }

    private var current: CurrentUtterance?
    private var nextRevs: [UUID: UInt64] = [:]
    private var outbox: [PendingDelivery] = []
    private var statuses: [UUID: DeliveryStatus] = [:]

    // MARK: Init

    public init(identity: StoredIdentity, deviceName: String, partialStreamingEnabled: Bool = true,
                hostStore: PairedHostStore, settings: PhoneSettingsStore,
                transport: PhoneTransport, clock: PhoneClock,
                relayStore: PairedRelayDesktopStore? = nil, relaySecrets: RelaySecretStore? = nil,
                relayRooms: RelayRoomControl? = nil) {
        self.relayStore = relayStore
        self.relaySecrets = relaySecrets
        self.relayRooms = relayRooms
        self.identity = identity
        self.deviceName = deviceName
        self.partialStreamingEnabled = partialStreamingEnabled
        self.hostStore = hostStore
        self.settings = settings
        self.transport = transport
        self.clock = clock
        do {
            let loaded = try hostStore.loadHosts()
            pairedHosts = loaded.filter { $0.publicBytes != nil }
            if pairedHosts.count != loaded.count {
                pairedHostsUnreadable = true
                hostFileNeedsBackup = true
            }
        } catch {
            // Never treat an unreadable list as empty and overwrite it later:
            // the file is backed up before the first save (M10).
            pairedHosts = []
            pairedHostsUnreadable = true
            hostFileNeedsBackup = true
        }
        if let last = settings.lastHostId, pairedHosts.contains(where: { $0.deviceId == last }) {
            activeHostId = last
        }
        // Reconnect to every relay desktop (SPEC_V3 §5).
        relayDesktops = ((try? relayStore?.loadRelayDesktops()) ?? []).filter { $0.pinnedPub.count == 32 }
        for r in relayDesktops {
            if let url = URL(string: r.relayURL), let secret = (try? relaySecrets?.get(roomId: r.roomId)) ?? nil {
                relayRooms?.startRoom(relayURL: url, roomId: r.roomId, secret: secret)
            }
        }
    }

    /// Pair with the desktop in a scanned QR code: save its relay record and
    /// room secret, join the room, and when its `hello` arrives run the pairing
    /// flow with the code from the QR. The desktop key is pinned.
    public func pair(using uri: PairingURI) {
        let record = PairedRelayDesktop(uri)
        relayDesktops.removeAll { $0.roomId == record.roomId }
        relayDesktops.append(record)
        do {
            try relaySecrets?.set(uri.roomSecret, roomId: uri.roomId)
            try relayStore?.saveRelayDesktops(relayDesktops)
        } catch {
            log?("saving relay desktop failed")
            relayDesktops.removeAll { $0.roomId == record.roomId }
            emit(.notice(.storageFailed))
            return
        }
        autoPairCodes[record.peer] = uri.code
        relayRooms?.startRoom(relayURL: uri.relayURL, roomId: uri.roomId, secret: uri.roomSecret)
        changed()
    }

    private func removeRelayDesktop(roomId: String) {
        relayDesktops.removeAll { $0.roomId == roomId }
        autoPairCodes[RelayTransport.peerID(roomId: roomId)] = nil
        try? relayStore?.saveRelayDesktops(relayDesktops)
        try? relaySecrets?.delete(roomId: roomId)
        relayRooms?.stopRoom(roomId: roomId)
    }

    // MARK: - Public read model

    /// Identified connected desktops ∪ paired desktops that are offline,
    /// sorted by name.
    public var hosts: [HostInfo] {
        var out: [HostInfo] = []
        var seen = Set<UUID>()
        // One row per desktop, taken from its preferred connection, so a
        // second (possibly hostile) connection claiming the same device_id
        // cannot change what the row shows.
        var byDevice: [UUID: [Connection]] = [:]
        for c in connections.values { if let id = c.deviceId { byDevice[id, default: []].append(c) } }
        for (id, cs) in byDevice {
            guard let c = preferred(cs), let h = c.peerHello else { continue }
            seen.insert(id)
            let record = pairedHosts.first { $0.deviceId == h.deviceId }
            let known = record?.publicBytes == h.publicKey
            let state: HostLinkState = switch c.phase {
            case .secure: .secure
            case .pairing: .pairing
            case .awaitingHello, .unpaired: .unpaired
            }
            out.append(HostInfo(id: h.deviceId, name: known ? cleanName(record!.name) : cleanName(h.name),
                                isPaired: known,
                                isOnline: true, state: state, isActive: h.deviceId == activeHostId,
                                notRecognized: notRecognized.contains(h.deviceId),
                                keyChanged: record != nil && !known))
        }
        for r in pairedHosts where !seen.contains(r.deviceId) {
            out.append(HostInfo(id: r.deviceId, name: cleanName(r.name), isPaired: true, isOnline: false,
                                state: .offline,
                                isActive: r.deviceId == activeHostId,
                                notRecognized: notRecognized.contains(r.deviceId), keyChanged: false))
        }
        return out.sorted {
            $0.name.localizedStandardCompare($1.name) == .orderedAscending
                || ($0.name == $1.name && $0.id.uuidString < $1.id.uuidString)
        }
    }

    /// The active desktop's row, if any.
    public var activeHost: HostInfo? {
        guard let id = activeHostId else { return nil }
        return hosts.first { $0.id == id }
    }

    /// Header status dot (SPEC §5.1).
    public var indicator: ConnectionIndicator {
        guard activeHostId != nil else { return .none }
        return activeSecureConnection() != nil ? .secure : .connecting
    }

    /// Paired desktops (persisted).
    public var pairedHostRecords: [PairedHost] { pairedHosts }

    /// Delivery status of utterance `id` (`nil` before its final is queued).
    public func deliveryStatus(of id: UUID) -> DeliveryStatus? { statuses[id] }

    /// Number of `final`/`edit` messages not yet acked.
    public var pendingDeliveryCount: Int { outbox.count }

    /// Deliveries still being retried (not `failed`). The app waits for this to
    /// reach 0 (bounded) before it goes to the background.
    public var inFlightDeliveryCount: Int { outbox.reduce(0) { $0 + ($1.failed ? 0 : 1) } }

    /// Whether an utterance is in progress (between begin and finish).
    public var isUtteranceOpen: Bool { current != nil }

    // MARK: - Transport events

    /// A desktop connected (BLE: subscribed to TX; TCP: accepted). It will
    /// send `hello` first (README §7.1).
    public func peerConnected(_ peer: PeerID) {
        if let old = connections[peer] { drop(old, reason: "duplicate connect", notify: false) }
        connectionCounter += 1
        connections[peer] = Connection(peer: peer, seq: connectionCounter, connectedAt: clock.now)
        log?("connect \(peer)")
        enforceConnectionCap(keeping: peer)
        changed()
    }

    /// Keep the number of unproven connections bounded: the oldest silent one
    /// goes first (M20).
    private func enforceConnectionCap(keeping keep: PeerID) {
        while true {
            let unproven = connections.values.filter { !$0.authenticated && !$0.isPairing }
            guard unproven.count > Self.maxUnprovenConnections else { return }
            func order(_ c: Connection) -> Int {
                if c.peerHello == nil { return 0 }
                return c.isSecure ? 2 : 1
            }
            guard let victim = unproven.filter({ $0.peer != keep })
                .min(by: { (order($0), $0.seq) < (order($1), $1.seq) })
            else { return }
            drop(victim, reason: "too many unproven connections", notify: victim.peerHello != nil)
        }
    }

    /// One frame arrived from `peer`.
    public func peerReceived(frame: [UInt8], from peer: PeerID) {
        guard let c = connections[peer] else { return }
        let message: [UInt8]?
        do { message = try c.reassembler.push(frame) } catch {
            log?("framing \(peer): \(error.code)")
            return
        }
        if let message { handleEnvelope(message, on: c) }
    }

    /// The transport lost `peer`.
    public func peerDisconnected(_ peer: PeerID) {
        guard let c = connections[peer] else { return }
        teardown(c)
        log?("disconnect \(peer)")
        changed()
    }

    /// Drop every connection (the app is going to the background).
    ///
    /// The transport closes gracefully (frames already sent still go out), and
    /// no `error` is sent: the service disappearing is what tells a desktop.
    public func disconnectAll() {
        for c in Array(connections.values) { drop(c, reason: "disconnect all", notify: false) }
        changed()
    }

    /// Drive timers: partial throttling, retries and keepalive.
    public func tick() {
        let now = clock.now
        for c in Array(connections.values) where c.peerHello == nil && connections[c.peer] != nil {
            if now - c.connectedAt >= Self.helloTimeout { drop(c, reason: "no hello", notify: false) }
        }
        for c in Array(connections.values) where c.isSecure && connections[c.peer] != nil {
            guard now >= c.nextPingAt else { continue }
            if c.unansweredPings >= Self.maxMissedPings {
                emit(.notice(.keepaliveTimeout(hostName: displayName(c))))
                drop(c, reason: "keepalive timeout", notify: false)  // the link is already dead
                continue
            }
            c.unansweredPings += 1
            c.nextPingAt = now + Self.pingInterval
            _ = sendSealed(.ping, on: c)
        }
        flushPartial()
        if let c = activeSecureConnection() {
            flushOutbox(to: c)
            retryOutbox(on: c, now: now)
        }
        updatePairingRetry(now: now)
        changed()
    }

    /// Whole seconds left until the failed pairing sheet may try again.
    private func updatePairingRetry(now: Double) {
        guard var p = pairing, case .failed = p.phase else { return }
        let left = max(0, Int(ceil((pairingRetryAt ?? now) - now)))
        if p.retryIn != left {
            p.retryIn = left
            pairing = p
        }
    }

    // MARK: - Host selection

    /// Tap on a host row (SPEC §5.1 Host picker): a paired host becomes active
    /// and is remembered; an unpaired online host starts pairing.
    public func selectHost(_ id: UUID) {
        if let row = hosts.first(where: { $0.id == id }), row.isPaired {
            setActive(id)
        } else {
            startPairing(with: id)
        }
        changed()
    }

    private func setActive(_ id: UUID?) {
        guard activeHostId != id else { return }
        activeHostId = id
        settings.lastHostId = id
        if let c = activeSecureConnection() { activeBecameSecure(c) }
    }

    /// Remove a paired desktop (SPEC §5.1 swipe to Forget).
    public func forgetHost(_ id: UUID) {
        for r in relayDesktops where r.deviceId == id { removeRelayDesktop(roomId: r.roomId) }
        pairedHosts.removeAll { $0.deviceId == id }
        persistHosts()
        notRecognized.remove(id)
        if activeHostId == id {
            activeHostId = nil
            settings.lastHostId = nil
        }
        // A live session was keyed for the old record: close it, so the next
        // connection sends `paired:false` and can pair again.
        for c in Array(connections.values) where c.deviceId == id && c.isSecure {
            drop(c, reason: "forgotten")
        }
        changed()
    }

    // MARK: - Pairing (README §7.3)

    /// Send `pair_request` to the unpaired desktop `id`, unless the desktop's
    /// pairing limits (README §7.3) say it would be refused: then the sheet
    /// shows a "wait, then try again" state with a countdown (`retryIn`).
    public func startPairing(with id: UUID) {
        guard let c = connections.values.filter({ $0.deviceId == id && !$0.isSecure && $0.peerHello != nil })
            .max(by: { $0.seq < $1.seq })
        else {
            log?("pairing: \(id) is not connected")
            return
        }
        if let other = pairingPeer, other != c.peer, let oc = connections[other], oc.isPairing {
            oc.phase = .unpaired
        }
        let wait = pairWait(id)
        if wait > 0 {
            pairing = PairingStatus(hostId: id, hostName: displayName(c), phase: .requesting, note: nil)
            pairingPeer = nil
            failPairing("\(displayName(c)) limits how often you can pair. Wait a moment, then try again.")
            changed()
            return
        }
        pairing = PairingStatus(hostId: id, hostName: displayName(c), phase: .requesting, note: nil)
        pairingPeer = c.peer
        pairingRetryAt = nil
        sendPairRequest(on: c)
        changed()
    }

    private func sendPairRequest(on c: Connection) {
        let req = PairRequest.generate()
        c.phase = .pairing(.awaitingChallenge(req))
        c.pairFailures = 0
        if let id = c.deviceId {
            let now = clock.now
            var b = pairBudgets[id, default: PairBudget()]
            b.requestTimes.append(now)
            b.requestTimes.removeAll { now - $0 >= Self.pairRequestWindow }
            pairBudgets[id] = b
            if pairBudgets.count > 64 { prunePairBudgets(now: now) }
        }
        _ = sendPlain(.pairRequest(req), on: c)
    }

    /// Seconds until a `pair_request` to `id` is within the desktop's limits
    /// (0 = now): 10 s between requests, at most 5 per 10 minutes, and the
    /// backoff after a refusal or an invalidated code.
    private func pairWait(_ id: UUID) -> Double {
        guard let b = pairBudgets[id] else { return 0 }
        let now = clock.now
        var wait = max(0, b.blockedUntil - now)
        if let last = b.requestTimes.last, last <= now {
            wait = max(wait, last + Self.pairRequestMinInterval - now)
        }
        let recent = b.requestTimes.filter { $0 <= now && now - $0 < Self.pairRequestWindow }
        if recent.count >= Self.pairRequestsPerWindow {
            wait = max(wait, recent[recent.count - Self.pairRequestsPerWindow] + Self.pairRequestWindow - now)
        }
        return wait
    }

    private func block(pairingTo id: UUID, for seconds: Double) {
        var b = pairBudgets[id, default: PairBudget()]
        b.blockedUntil = max(b.blockedUntil, clock.now + seconds)
        pairBudgets[id] = b
    }

    private func prunePairBudgets(now: Double) {
        pairBudgets = pairBudgets.filter { _, b in
            b.blockedUntil > now || b.invalidations > 0
                || b.requestTimes.contains { now - $0 < Self.pairRequestWindow }
        }
    }

    /// The user typed the code. Accepts exactly 6 ASCII digits.
    public func submitPairingCode(_ text: String) {
        defer { changed() }
        guard let peer = pairingPeer, let c = connections[peer], let hello = c.peerHello,
              case .pairing(.awaitingCode(let req, let ch, let at)) = c.phase
        else { return }
        let code: PairingCode
        do { code = try PairingCode(parsing: text) } catch {
            pairing?.phase = .enterCode(error: "Enter the 6 digits shown on \(displayName(c)).")
            return
        }
        if clock.now - at >= Self.codeLifetime {
            restartPairing(on: c, note: "The code expired. Enter the new code shown on \(displayName(c)).")
            return
        }
        let key: PairKey
        do {
            key = try PairKey.derive(identity: identity.keyPair, ownRole: .phone, peerPublic: hello.publicKey,
                                     request: req, challenge: ch, code: code)
        } catch {
            failPairing("\(displayName(c)) sent an invalid key.")
            _ = sendPlain(.error(ErrorMsg(code: ErrorMsg.protocolViolation, msg: "Invalid public key")), on: c)
            drop(c, reason: "low-order key", notify: false)
            return
        }
        c.phase = .pairing(.awaitingResult(req, ch, key, challengeAt: at))
        pairing?.phase = .verifying
        pairing?.note = nil
        _ = sendPlain(.pairConfirm(key.confirmMessage()), on: c)
    }

    /// Ask the desktop for a fresh code (e.g. a "New code" button). Within the
    /// desktop's limits only; otherwise the sheet says how long to wait.
    public func requestNewPairingCode() {
        guard let peer = pairingPeer, let c = connections[peer], c.isPairing else { return }
        let wait = pairWait(c.deviceId ?? UUID())
        if wait > 0 {
            pairing?.note = "Wait \(Int(ceil(wait))) seconds before asking \(displayName(c)) for a new code."
        } else {
            restartPairing(on: c, note: "Enter the new code shown on \(displayName(c)).")
        }
        changed()
    }

    /// Close the pairing sheet. An unfinished pairing is abandoned.
    public func cancelPairing() {
        if let peer = pairingPeer, let c = connections[peer], c.isPairing { c.phase = .unpaired }
        pairing = nil
        pairingPeer = nil
        changed()
    }

    private func restartPairing(on c: Connection, note: String) {
        if let id = c.deviceId, pairWait(id) > 0 {
            c.phase = .unpaired
            failPairing("\(displayName(c)) limits how often you can pair. Wait a moment, then try again.")
            return
        }
        sendPairRequest(on: c)
        pairing?.phase = .requesting
        pairing?.note = note
    }

    private func failPairing(_ message: String) {
        guard var p = pairing else { return }
        if case .succeeded = p.phase { return }
        p.phase = .failed(message: message)
        let wait = pairWait(p.hostId)
        pairingRetryAt = clock.now + wait
        p.retryIn = Int(ceil(wait))
        pairing = p
        pairingPeer = nil
    }

    private func handleChallenge(_ ch: PairChallenge, on c: Connection) {
        guard case .pairing(.awaitingChallenge(let req)) = c.phase else {
            log?("unexpected pair_challenge on \(c.peer)")
            return
        }
        c.phase = .pairing(.awaitingCode(req, ch, challengeAt: clock.now))
        if pairingPeer == c.peer { pairing?.phase = .enterCode(error: nil) }
        if let code = autoPairCodes.removeValue(forKey: c.peer), pairingPeer == c.peer {
            submitPairingCode(code)
        }
    }

    private func handlePairResult(_ result: PairResult, on c: Connection) {
        guard let hello = c.peerHello,
              case .pairing(.awaitingResult(let req, let ch, let key, let at)) = c.phase
        else {
            log?("unexpected pair_result on \(c.peer)")
            return
        }
        let name = displayName(c)
        guard result.ok else {
            c.pairFailures += 1
            if c.pairFailures >= Self.maxCodeFailures {
                // The desktop invalidated the code and started a global
                // lockout (30 s, doubling). A new request now would only be
                // refused and count against the 5-per-10-minutes budget, so
                // wait (M7).
                var budget = pairBudgets[hello.deviceId, default: PairBudget()]
                budget.invalidations += 1
                pairBudgets[hello.deviceId] = budget
                block(pairingTo: hello.deviceId,
                      for: max(Self.pairRequestMinInterval, Self.lockoutDuration(budget.invalidations)))
                c.phase = .unpaired
                failPairing("Too many wrong codes. \(name) is not accepting new codes for a moment. Wait, then try again.")
            } else {
                c.phase = .pairing(.awaitingCode(req, ch, challengeAt: at))
                pairing?.phase = .enterCode(error: "Wrong code. Check the code on \(name) and try again.")
            }
            return
        }
        // ok:true — verify mac_d (README §7.3); on failure send bad_mac, store nothing.
        guard let mac = result.mac, (try? key.verifyDesktopMac(mac)) != nil else {
            failPairing("\(name) could not be verified. Nothing was saved; try pairing again.")
            _ = sendPlain(.error(ErrorMsg(code: ErrorMsg.badMac, msg: "Pairing verification failed")), on: c)
            drop(c, reason: "bad mac_d", notify: false)
            return
        }
        let record = PairedHost(deviceId: hello.deviceId, name: cleanName(hello.name), publicKey: hello.publicKey,
                                pairedAt: Date())
        pairedHosts.removeAll { $0.deviceId == hello.deviceId }
        pairedHosts.append(record)
        pairBudgets[hello.deviceId]?.invalidations = 0
        pairBudgets[hello.deviceId]?.blockedUntil = 0
        if !persistHosts() { emit(.notice(.storageFailed)) }
        notRecognized.remove(hello.deviceId)
        pairing?.phase = .succeeded
        pairing?.hostName = record.name
        pairing?.note = nil
        pairing?.retryIn = 0
        pairingPeer = nil
        activeHostId = hello.deviceId
        settings.lastHostId = hello.deviceId
        if establish(c) {
            emit(.paired(hostId: hello.deviceId, name: record.name))
        }
    }

    // MARK: - Utterances (SPEC §4.6, README §5.8/§5.11)

    /// Start a new utterance (recording started). Returns its id.
    @discardableResult
    public func beginUtterance() -> UUID {
        let u = CurrentUtterance(id: UUID(), ts: clock.epochMillis)
        current = u
        return u.id
    }

    /// The recognizer's current full text. Sent as a throttled `partial`
    /// (latest text wins). If the text no longer fits (README §5.8), the
    /// longest fitting prefix is sent as the `final`, the utterance ends and
    /// ``PhoneEvent/utteranceLimitReached(id:text:)`` is emitted.
    public func updatePartial(_ text: String) {
        guard var cur = current else { return }
        guard uttTextFits(text) else {
            let prefix = maxTextPrefix(text)
            current = nil
            enqueue(id: cur.id, state: .final, text: prefix, ts: cur.ts)
            emit(.utteranceLimitReached(id: cur.id, text: prefix))
            changed()
            return
        }
        guard partialStreamingEnabled else { return }
        cur.pendingPartial = text
        current = cur
        flushPartial()
    }

    /// The outcome of finishing an utterance.
    public struct Finished: Equatable, Sendable {
        public let id: UUID
        /// The text actually sent (truncated if it did not fit).
        public let text: String
        public let truncated: Bool
    }

    /// Recording stopped: send the `final` now. Returns `nil` when no
    /// utterance is open (e.g. it already ended at the size limit), or when
    /// the text is empty and nothing was ever sent for it.
    @discardableResult
    public func finishUtterance(_ text: String) -> Finished? {
        guard let cur = current else { return nil }
        current = nil
        if text.isEmpty && cur.lastSentPartial == nil { return nil }
        let sent = uttTextFits(text) ? text : maxTextPrefix(text)
        enqueue(id: cur.id, state: .final, text: sent, ts: cur.ts)
        changed()
        return Finished(id: cur.id, text: sent, truncated: !sent.utf8.elementsEqual(text.utf8))
    }

    /// Drop the open utterance without sending a final.
    public func cancelUtterance() {
        guard let cur = current else { return }
        current = nil
        // Nothing was queued for it: release what its partials allocated.
        if statuses[cur.id] == nil, !outbox.contains(where: { $0.id == cur.id }) {
            nextRevs[cur.id] = nil
            tsById[cur.id] = nil
        }
    }

    /// "Send correction": an `edit` with a higher `rev` for utterance `id`
    /// (sent earlier in this run). Returns the text sent, or `nil` if `id`
    /// was never sent.
    @discardableResult
    public func sendEdit(id: UUID, text: String) -> String? {
        guard nextRevs[id] != nil else { return nil }
        let ts = outbox.first { $0.id == id }?.ts ?? tsById[id] ?? clock.epochMillis
        let sent = uttTextFits(text) ? text : maxTextPrefix(text)
        enqueue(id: id, state: .edit, text: sent, ts: ts)
        changed()
        return sent
    }

    /// "Re-send" from history: a **new** id with a single `final`.
    @discardableResult
    public func resend(text: String) -> Finished {
        let id = UUID()
        let sent = uttTextFits(text) ? text : maxTextPrefix(text)
        enqueue(id: id, state: .final, text: sent, ts: clock.epochMillis)
        changed()
        return Finished(id: id, text: sent, truncated: !sent.utf8.elementsEqual(text.utf8))
    }

    /// Stop tracking (and retrying) utterance `id`, e.g. deleted from history.
    ///
    /// Releases everything held for `id`: afterwards ``deliveryStatus(of:)`` is
    /// `nil` and ``sendEdit(id:text:)`` returns `nil` for it.
    public func forgetDelivery(_ id: UUID) {
        outbox.removeAll { $0.id == id }
        statuses[id] = nil
        nextRevs[id] = nil
        tsById[id] = nil
        if current?.id == id { current = nil }
    }

    private var tsById: [UUID: UInt64] = [:]

    /// `id` will not be delivered or retried any more (acked, or dropped as
    /// failed): keep its state for a while, then release the oldest.
    private func markSettled(_ id: UUID) {
        settledOrder.append(id)
        while settledOrder.count - settledHead > Self.maxSettledTracked {
            let old = settledOrder[settledHead]
            settledHead += 1
            guard !outbox.contains(where: { $0.id == old }), current?.id != old else { continue }
            statuses[old] = nil
            nextRevs[old] = nil
            tsById[old] = nil
        }
        if settledHead > 4_096 {
            settledOrder.removeFirst(settledHead)
            settledHead = 0
        }
    }

    /// Next revision for `id`; `nil` once u32 is exhausted.
    private func allocRev(_ id: UUID) -> UInt32? {
        let r = nextRevs[id, default: 0]
        guard r <= UInt64(UInt32.max) else { return nil }
        nextRevs[id] = r + 1
        return UInt32(r)
    }

    private func enqueue(id: UUID, state: UttState, text: String, ts: UInt64) {
        guard let rev = allocRev(id) else {
            log?("utterance \(id): revisions exhausted")
            return
        }
        tsById[id] = ts
        // Only the newest revision matters: it carries the full text.
        outbox.removeAll { $0.id == id }
        outbox.append(PendingDelivery(id: id, rev: rev, state: state, text: text, ts: ts))
        setStatus(id, .pending)
        // No host for a long time: the oldest wait becomes failed (the user can
        // Re-send it from history) instead of growing without bound (V6).
        while outbox.count > Self.maxPendingDeliveries {
            let dropped = outbox.removeFirst()
            setStatus(dropped.id, .failed)
            markSettled(dropped.id)
        }
        if let c = activeSecureConnection() { flushOutbox(to: c) }
    }

    private func flushPartial() {
        guard partialStreamingEnabled, var cur = current, let text = cur.pendingPartial,
              let c = activeSecureConnection()
        else { return }
        let now = clock.now
        // One limit for the whole connection, across utterances (README §8).
        if let last = lastPartialAt, now >= last, now - last < Self.partialInterval { return }
        cur.pendingPartial = nil
        if let prev = cur.lastSentPartial, prev.utf8.elementsEqual(text.utf8) {
            current = cur
            return
        }
        if text.isEmpty && cur.lastSentPartial == nil {
            current = cur
            return
        }
        // Keep revisions for the final and edits: partials stop well before u32 runs out.
        guard nextRevs[cur.id, default: 0] < UInt64(UInt32.max) - 1_000_000, let rev = allocRev(cur.id) else {
            current = cur
            return
        }
        tsById[cur.id] = cur.ts
        if sendSealed(.utt(Utt(id: cur.id, rev: rev, state: .partial, text: text, ts: cur.ts)), on: c) {
            lastPartialAt = now
            cur.lastSentPartial = text
        }
        current = cur
    }

    /// Send every pending delivery not yet sent on this connection.
    private func flushOutbox(to c: Connection) {
        let now = clock.now
        for i in outbox.indices where outbox[i].sentOn != c.peer {
            guard connections[c.peer] != nil else { return }
            let p = outbox[i]
            outbox[i].sentOn = c.peer
            outbox[i].lastSentAt = now
            outbox[i].retries = 0
            if p.failed {
                outbox[i].failed = false
                setStatus(p.id, .pending)
            }
            _ = sendSealed(.utt(Utt(id: p.id, rev: p.rev, state: p.state, text: p.text, ts: p.ts)), on: c)
        }
    }

    private func retryOutbox(on c: Connection, now: Double) {
        for i in outbox.indices where outbox[i].sentOn == c.peer && !outbox[i].failed {
            guard connections[c.peer] != nil else { return }
            guard now - outbox[i].lastSentAt >= Self.retryInterval else { continue }
            let p = outbox[i]
            if p.retries >= Self.maxRetries {
                outbox[i].failed = true
                setStatus(p.id, .failed)
                continue
            }
            outbox[i].retries += 1
            outbox[i].lastSentAt = now
            _ = sendSealed(.utt(Utt(id: p.id, rev: p.rev, state: p.state, text: p.text, ts: p.ts)), on: c)
        }
    }

    /// An ack settles a delivery only when it names exactly the revision we
    /// are waiting for (README §5.9: the desktop acks the `(id, rev)` it got).
    /// Lower revisions are stale; higher ones were never sent.
    private func handleAck(_ ack: Ack) {
        guard let i = outbox.firstIndex(where: { $0.id == ack.id }) else { return }
        guard ack.rev == outbox[i].rev else { return }
        outbox.remove(at: i)
        setStatus(ack.id, .acked)
        markSettled(ack.id)
    }

    private func setStatus(_ id: UUID, _ s: DeliveryStatus) {
        guard statuses[id] != s else { return }
        statuses[id] = s
        emit(.deliveryChanged(id: id, status: s))
    }

    /// The active host just became Secure (or became active while Secure):
    /// re-send everything pending, with fresh retry budgets (README §5.11).
    private func activeBecameSecure(_ c: Connection) {
        activePeer = c.peer
        for i in outbox.indices { outbox[i].sentOn = nil }
        flushOutbox(to: c)
        flushPartial()
    }

    /// The active host's preferred Secure connection may have changed (a
    /// connection was proven, replaced or lost): re-send on the new one.
    private func refreshActive() {
        guard let c = activeSecureConnection() else {
            activePeer = nil
            return
        }
        if c.peer != activePeer { activeBecameSecure(c) }
    }

    // MARK: - Receive path

    private func handleEnvelope(_ bytes: [UInt8], on c: Connection) {
        let inbound: Inbound
        do { inbound = try decodeInbound(bytes, session: c.cipher) } catch {
            switch error {
            case .decryptFailed where c.isSecure:
                _ = sendPlain(.error(ErrorMsg(code: ErrorMsg.decryptFailed, msg: "Decryption failed")), on: c)
                drop(c, reason: "decrypt_failed", notify: false)
                changed()
            case .replay:
                break  // README §7.4: silently dropped
            default:
                log?("drop from \(c.peer): \(error.code)")
            }
            return
        }

        if c.isSecure {
            if !c.authenticated { markAuthenticated(c) }
            guard connections[c.peer] != nil else { return }
            do { try checkInSession(inbound) } catch {
                switch inbound.message {
                case .hello, .helloUnsupported:
                    protocolViolation(on: c, "second hello")
                default:
                    log?("drop \(inbound.message.typeName) in session")
                }
                return
            }
            switch inbound.message {
            case .ack(let a): handleAck(a)
            case .ping: _ = sendSealed(.pong, on: c)
            case .pong: c.unansweredPings = 0
            case .error(let e): handlePeerError(e, on: c)
            default: log?("drop \(inbound.message.typeName) in session")
            }
            changed()
            return
        }

        switch inbound.message {
        case .hello(let h):
            if c.peerHello != nil { protocolViolation(on: c, "second hello") } else { handleHello(h, on: c) }
        case .helloUnsupported(let hu):
            if c.peerHello != nil {
                protocolViolation(on: c, "second hello")
            } else {
                _ = sendPlain(.error(ErrorMsg(code: ErrorMsg.version, msg: "Update Ventriloquist")), on: c)
                emit(.notice(.versionMismatch(hostName: hu.name.map(clip), updatePhone: false)))
                drop(c, reason: "unsupported version \(hu.v)", notify: false)
            }
        case .pairChallenge(let ch): handleChallenge(ch, on: c)
        case .pairResult(let r): handlePairResult(r, on: c)
        case .error(let e): handlePeerError(e, on: c)
        default: log?("drop \(inbound.message.typeName) before session")
        }
        changed()
    }

    /// A message decrypted under this connection's `K_sess`: the peer holds the
    /// paired key. Only now does it replace an older connection of the same
    /// desktop; an unauthenticated `hello` that merely claims a device_id never
    /// can (README §7.1, §7.4).
    private func markAuthenticated(_ c: Connection) {
        c.authenticated = true
        guard let id = c.deviceId else { return }
        for other in Array(connections.values) where other !== c && other.deviceId == id && other.seq < c.seq {
            drop(other, reason: "replaced by \(c.peer)")
        }
        refreshActive()
    }

    private func handleHello(_ h: Hello, on c: Connection) {
        c.peerHello = h
        if let r = relayDesktops.first(where: { $0.peer == c.peer }),
           r.deviceId != h.deviceId || r.pinnedPub != Data(h.publicKey.bytes) {
            // The QR code named another desktop: store nothing (SPEC_V3 §5).
            emit(.notice(.pairingCodeMismatch))
            drop(c, reason: "relay desktop does not match the QR code")
            if autoPairCodes[c.peer] != nil { removeRelayDesktop(roomId: r.roomId) }
            changed()
            return
        }
        let known = isKnown(h)
        if known { autoPairCodes[c.peer] = nil }
        let own = Hello.new(deviceId: identity.deviceId, name: PhoneNames.clean(deviceName, fallback: "iPhone"),
                            publicKey: identity.keyPair.publicBytes, paired: known)
        let hello = own.hello
        c.ownNonce = own.takeNonce()
        guard sendPlain(.hello(hello), on: c) else {
            drop(c, reason: "hello not sendable", notify: false)
            return
        }
        // README §7.2: the phone is Secure iff its store knows the desktop.
        if known {
            _ = establish(c)
        } else {
            c.phase = .unpaired
            if autoPairCodes[c.peer] != nil { startPairing(with: h.deviceId) }
        }
    }

    /// Derive `K_sess` from this connection's hellos and go Secure.
    @discardableResult
    private func establish(_ c: Connection) -> Bool {
        guard let h = c.peerHello, let nonce = c.ownNonce.take() else { return false }
        do {
            c.cipher = try SessionCipher.establish(identity: identity.keyPair, role: .phone,
                                                   peerPublic: h.publicKey, ownNonce: nonce,
                                                   peerNonce: h.sessionNonce)
        } catch {
            _ = sendPlain(.error(ErrorMsg(code: ErrorMsg.protocolViolation, msg: "Invalid public key")), on: c)
            drop(c, reason: "low-order key", notify: false)
            return false
        }
        c.phase = .secure
        c.unansweredPings = 0
        // A second connection of a desktop we already talk to: ping at once,
        // so a live peer proves itself (and replaces the old link) quickly.
        let rival = connections.values.contains { $0 !== c && $0.deviceId == h.deviceId && $0.isSecure }
        c.nextPingAt = rival ? clock.now : clock.now + Self.pingInterval
        log?("secure \(c.peer)")
        if h.deviceId == activeHostId { refreshActive() }
        return true
    }

    private func handlePeerError(_ e: ErrorMsg, on c: Connection) {
        let name: String? = c.peerHello == nil ? nil : clip(displayName(c))
        let notice: PhoneNotice
        switch e.code {
        case ErrorMsg.unknownPeer:
            if let id = c.deviceId {
                // Unauthenticated: never touch the stored pairing (README §7.4).
                notRecognized.insert(id)
                notice = .notRecognized(hostId: id, hostName: name ?? "The desktop")
            } else {
                notice = .peerError(hostName: name, code: e.code, message: clip(e.msg))
            }
        case ErrorMsg.version:
            notice = .versionMismatch(hostName: name, updatePhone: true)
        default:
            notice = .peerError(hostName: name, code: clip(e.code), message: clip(e.msg))
        }
        if e.code == Self.rateLimited, let id = c.deviceId, !c.isPairing, pairingPeer != c.peer, !c.isSecure {
            // `rate_limited` outside a pairing exchange is a refused `hello`: the
            // desktop refuses this device for 10 minutes (README §7.3).
            block(pairingTo: id, for: Self.deviceRefusal)
        }
        if pairingPeer == c.peer { failPairing(notice.text) }
        emit(.notice(notice))
        // README §5.7/§7.3: `rate_limited` and `busy` refuse a pair_request but
        // are non-fatal; the desktop keeps the link open unless it closes it
        // itself. The phone may send a new pair_request later.
        if e.code == Self.rateLimited || e.code == Self.busy {
            if c.isPairing { c.phase = .unpaired }
            return
        }
        drop(c, reason: "peer error \(clip(e.code))", notify: false)
    }

    /// Pairing refusals (README §7.3 "Pairing rate limits").
    public static let rateLimited = "rate_limited"
    public static let busy = "busy"

    private func protocolViolation(on c: Connection, _ why: String) {
        _ = sendPlain(.error(ErrorMsg(code: ErrorMsg.protocolViolation, msg: "Protocol error")), on: c)
        drop(c, reason: why, notify: false)
    }

    // MARK: - Sending

    @discardableResult
    private func sendPlain(_ m: Message, on c: Connection) -> Bool {
        do { return sendEnvelope(try encodePlaintext(m), on: c) } catch {
            log?("encode \(m.typeName): \(error.code)")
            return false
        }
    }

    @discardableResult
    private func sendSealed(_ m: Message, on c: Connection) -> Bool {
        guard let cipher = c.cipher else { return false }
        let env: [UInt8]
        do { env = try cipher.sealMessage(m) } catch {
            log?("seal \(m.typeName): \(error.code)")
            if error == .counterExhausted { drop(c, reason: "counter exhausted") }
            return false
        }
        return sendEnvelope(env, on: c)
    }

    private func sendEnvelope(_ env: [UInt8], on c: Connection) -> Bool {
        guard connections[c.peer] != nil else { return false }
        let mtu = max(VQ.minMTU, transport.mtu(for: c.peer))
        let frames: [[UInt8]]
        do { frames = try c.splitter.split(env, mtu: mtu) } catch {
            log?("split: \(error.code)")
            return false
        }
        for f in frames { transport.send(frame: f, to: c.peer) }
        return true
    }

    // MARK: - Helpers

    private func isKnown(_ h: Hello) -> Bool {
        pairedHosts.contains { $0.deviceId == h.deviceId && $0.publicBytes == h.publicKey }
    }

    private func activeSecureConnection() -> Connection? {
        guard let id = activeHostId else { return nil }
        return preferred(connections.values.filter { $0.deviceId == id && $0.isSecure })
    }

    /// The connection that stands for a desktop when several claim its
    /// device_id. Secure beats not Secure; an authenticated one beats an
    /// unproven one; then the older beats the newer (a newcomer must prove
    /// itself first). Among connections that are not Secure the pairing one,
    /// then the newest.
    private func preferred(_ cs: [Connection]) -> Connection? {
        let secure = cs.filter(\.isSecure)
        if !secure.isEmpty {
            return secure.min { a, b in
                if a.authenticated != b.authenticated { return a.authenticated }
                return a.seq < b.seq
            }
        }
        return cs.max { a, b in
            if a.isPairing != b.isPairing { return b.isPairing }
            return a.seq < b.seq
        }
    }

    private func cleanName(_ s: String) -> String { PhoneNames.clean(s, fallback: Self.unnamedDesktop) }

    private func displayName(_ c: Connection) -> String {
        guard let h = c.peerHello else { return "the desktop" }
        if let r = pairedHosts.first(where: { $0.deviceId == h.deviceId && $0.publicBytes == h.publicKey }) {
            return cleanName(r.name)
        }
        return cleanName(h.name)
    }

    /// Bound peer-supplied text before it reaches the UI.
    private func clip(_ s: String) -> String {
        s.unicodeScalars.count <= Self.maxPeerTextShown
            ? s : String(String.UnicodeScalarView(s.unicodeScalars.prefix(Self.maxPeerTextShown))) + "…"
    }

    /// Close locally and tell the transport. Unless `notify` is false, a
    /// plaintext `error{protocol}` goes first (the transport closes
    /// gracefully, so it is delivered), so the desktop does not believe the
    /// link is up until its keepalive runs out. Closes that follow an `error`
    /// we already sent, a dead link or the app going to the background pass
    /// `false`.
    private func drop(_ c: Connection, reason: String, notify: Bool = true) {
        guard connections[c.peer] != nil else { return }
        log?("close \(c.peer): \(reason)")
        if notify, c.peerHello != nil {
            _ = sendPlain(.error(ErrorMsg(code: ErrorMsg.protocolViolation, msg: "Connection closed")), on: c)
        }
        teardown(c)
        transport.disconnect(c.peer)
    }

    private func teardown(_ c: Connection) {
        connections[c.peer] = nil
        c.cipher = nil
        c.reassembler.reset()
        _ = c.ownNonce.take()
        if pairingPeer == c.peer { failPairing("The connection to \(displayName(c)) was lost.") }
        if activePeer == c.peer {
            activePeer = nil
            refreshActive()
        }
    }

    @discardableResult
    private func persistHosts() -> Bool {
        do {
            if hostFileNeedsBackup {
                // Keep the unreadable file before replacing it (M10).
                try hostStore.backUpUnreadableHosts()
                hostFileNeedsBackup = false
            }
            try hostStore.saveHosts(pairedHosts)
            return true
        } catch {
            log?("saving paired hosts failed")
            return false
        }
    }

    private func emit(_ e: PhoneEvent) { onEvent?(e) }
    private func changed() { onChange?() }
}
