import Foundation

// The phone's relay transport (SPEC_V3): one `RelayClientState` per desktop
// room, with its actions executed through an injected `RelayNetworking`.
// Everything runs on the main actor, the engine's isolation domain in the app.

// MARK: - Networking abstraction

public enum RelayWebSocketEvent: Sendable, Equatable {
    case opened
    case text(String)
    case data(Data)
    /// The socket ended with a close code (4003 = room deleted, ...).
    case closed(code: Int)
    /// The socket failed (connect error, network loss) without a close code.
    case failed(String)
}

@MainActor public protocol RelayWebSocket: AnyObject {
    func send(text: String)
    func close()
}

@MainActor public protocol RelayNetworking: AnyObject {
    /// Open a WebSocket. Events arrive on the main actor, in order.
    func openWebSocket(url: URL, headers: [String: String],
                       onEvent: @escaping @MainActor (RelayWebSocketEvent) -> Void) -> RelayWebSocket
    func longPollSend(url: URL, headers: [String: String], body: Data) async throws -> (status: Int, data: Data)
    func longPollReceive(url: URL, headers: [String: String]) async throws -> (status: Int, data: Data)
}

/// Runs a block later on the main actor (injected so tests can drive time).
@MainActor public protocol RelayScheduler: AnyObject {
    func schedule(after seconds: Double, _ block: @escaping @MainActor () -> Void)
}

public final class TaskRelayScheduler: RelayScheduler {
    public init() {}
    public func schedule(after seconds: Double, _ block: @escaping @MainActor () -> Void) {
        Task { @MainActor in
            try? await Task.sleep(for: .seconds(seconds))
            block()
        }
    }
}

/// The engine side of the transport (`PhoneEngine` conforms).
public protocol RelayPeerEvents: AnyObject {
    func peerConnected(_ peer: PeerID)
    func peerReceived(frame: [UInt8], from peer: PeerID)
    func peerDisconnected(_ peer: PeerID)
}

extension PhoneEngine: RelayPeerEvents {}

// MARK: - Room

@MainActor final class RelayRoom {
    let roomId: String
    let relayURL: URL
    let secret: String
    unowned let owner: RelayPhoneTransport
    var state = RelayClientState()
    var socket: RelayWebSocket?
    var socketGen = 0
    var pollTask: Task<Void, Never>?
    var sendChain: Task<Void, Never>?
    var stopped = false

    init(roomId: String, relayURL: URL, secret: String, owner: RelayPhoneTransport) {
        self.roomId = roomId; self.relayURL = relayURL; self.secret = secret; self.owner = owner
    }

    var headers: [String: String] { ["Authorization": "Bearer \(secret)"] }

    func url(_ path: String, ws: Bool = false, query: [(String, String)]) -> URL {
        var c = URLComponents(url: relayURL, resolvingAgainstBaseURL: false) ?? URLComponents()
        if ws { c.scheme = (c.scheme == "http") ? "ws" : "wss" }
        var base = c.path
        while base.hasSuffix("/") { base.removeLast() }
        c.path = base + "/v1/rooms/\(roomId)/\(path)"
        c.queryItems = [URLQueryItem(name: "role", value: "phone")] + query.map { URLQueryItem(name: $0.0, value: $0.1) }
        return c.url ?? relayURL
    }

    func feed(_ input: RelayClientInput) {
        guard !stopped else { return }
        let actions = state.handle(input, now: owner.clock.now)
        for a in actions { run(a) }
    }

    func run(_ a: RelayClientAction) {
        switch a {
        case .openWebSocket: openSocket()
        case .startLongPoll(let session, let cursor): startPoll(session: session, cursor: cursor)
        case .cancelLongPoll: pollTask?.cancel(); pollTask = nil
        case .sendWS(let text): socket?.send(text: text)
        case .sendPoll(let session, let frames): sendPoll(session: session, frames: frames)
        case .scheduleRetry(let after):
            owner.scheduler.schedule(after: after) { [weak self] in self?.feed(.tick) }
        case .peerConnected: owner.events?.peerConnected(RelayTransport.peerID(roomId: roomId))
        case .peerDisconnected: owner.events?.peerDisconnected(RelayTransport.peerID(roomId: roomId))
        case .deliverFrame(let d): owner.events?.peerReceived(frame: [UInt8](d), from: RelayTransport.peerID(roomId: roomId))
        case .closeAll: closeTransports()
        case .roomDeleted:
            stopped = true
            owner.onRoomStopped?(roomId)
        }
    }

    func closeTransports() {
        socketGen += 1
        socket?.close(); socket = nil
        pollTask?.cancel(); pollTask = nil
        sendChain = nil
    }

    func openSocket() {
        socketGen += 1
        socket?.close()
        let gen = socketGen
        socket = owner.net.openWebSocket(url: url("ws", ws: true, query: []), headers: headers) { [weak self] e in
            guard let self, gen == self.socketGen else { return }
            switch e {
            case .opened: self.feed(.wsOpened)
            case .text(let s): self.feed(.wsText(s))
            case .data(let d): self.feed(.wsMessage(d))
            case .closed(let code): self.feed(.wsClosed(code))
            case .failed(let why): self.feed(.wsFailed(why))
            }
        }
    }

    func startPoll(session: String, cursor: Int) {
        pollTask?.cancel()
        let u = url("poll", query: [("session", session), ("cursor", String(cursor))])
        let h = headers
        pollTask = Task { [weak self] in
            guard let net = self?.owner.net else { return }
            let result: (status: Int, data: Data)?
            do { result = try await net.longPollReceive(url: u, headers: h) } catch { result = nil }
            guard !Task.isCancelled, let self else { return }
            if let result, result.status == 200, let r = RelayCodec.decodePoll(result.data) {
                self.feed(.pollResponse(r))
            } else {
                self.feed(.pollFailed(status: result?.status))
            }
        }
    }

    func sendPoll(session: String, frames: [Data]) {
        let u = url("send", query: [("session", session)])
        let h = headers
        let body = RelayCodec.encodeSend(frames)
        let prev = sendChain
        sendChain = Task { [weak self] in
            await prev?.value
            guard !Task.isCancelled, let net = self?.owner.net else { return }
            _ = try? await net.longPollSend(url: u, headers: h, body: body)
        }
    }
}

// MARK: - Transport

/// Phone transport over the relay. Peer ids are `relay:<room_id>`, so one
/// `PhoneEngine` can talk to any number of desktops. Call everything from the
/// main actor.
public final class RelayPhoneTransport: PhoneTransport, @unchecked Sendable {  // state is main-actor isolated
    /// Relay frames may be up to 64 KiB; the engine chunks at this size.
    public static let mtu = 8192

    /// Receives peer events (set to the `PhoneEngine`).
    @MainActor public weak var events: (any RelayPeerEvents)?
    /// Called when a room's relay connection ended for good (replaced or deleted).
    @MainActor public var onRoomStopped: ((String) -> Void)?

    @MainActor let net: RelayNetworking
    @MainActor let clock: PhoneClock
    @MainActor let scheduler: RelayScheduler
    @MainActor private var rooms: [String: RelayRoom] = [:]
    @MainActor private var paused = false

    @MainActor public init(networking: RelayNetworking, clock: PhoneClock = SystemClock(),
                           scheduler: RelayScheduler = TaskRelayScheduler()) {
        self.net = networking; self.clock = clock; self.scheduler = scheduler
    }

    /// Start (or restart) a room. Connects at once unless the app is paused.
    @MainActor public func addRoom(relayURL: URL, roomId: String, secret: String) {
        removeRoom(roomId: roomId)
        let room = RelayRoom(roomId: roomId, relayURL: relayURL, secret: secret, owner: self)
        rooms[roomId] = room
        if !paused { room.feed(.connectRequested) }
    }

    @MainActor public func removeRoom(roomId: String) {
        guard let room = rooms.removeValue(forKey: roomId) else { return }
        room.feed(.disconnectRequested)
        room.stopped = true
        room.closeTransports()
    }

    @MainActor public func hasRoom(_ roomId: String) -> Bool { rooms[roomId] != nil }
    @MainActor public func mode(ofRoom roomId: String) -> RelayClientState.Mode? { rooms[roomId]?.state.mode }

    /// App went to the background: drop every connection.
    @MainActor public func pauseAll() {
        paused = true
        for r in rooms.values { r.feed(.backgrounded) }
    }

    /// App is active again: reconnect every room.
    @MainActor public func resumeAll() {
        paused = false
        for r in rooms.values { r.feed(.connectRequested) }
    }

    // MARK: PhoneTransport (called by the engine on the main actor)

    public func send(frame: [UInt8], to peer: PeerID) {
        MainActor.assumeIsolated { room(for: peer)?.feed(.send(Data(frame))) }
    }

    /// The engine dropped the connection: cycle the room so the desktop sees a fresh phone.
    public func disconnect(_ peer: PeerID) {
        MainActor.assumeIsolated {
            guard let r = room(for: peer), !r.stopped else { return }
            r.feed(.disconnectRequested)
            r.feed(.connectRequested)
        }
    }

    public func mtu(for peer: PeerID) -> Int { Self.mtu }

    @MainActor private func room(for peer: PeerID) -> RelayRoom? {
        guard peer.raw.hasPrefix("relay:") else { return nil }
        return rooms[String(peer.raw.dropFirst("relay:".count))]
    }
}

extension RelayPhoneTransport: RelayRoomControl {
    public func startRoom(relayURL: URL, roomId: String, secret: String) {
        MainActor.assumeIsolated { addRoom(relayURL: relayURL, roomId: roomId, secret: secret) }
    }
    public func stopRoom(roomId: String) {
        MainActor.assumeIsolated { removeRoom(roomId: roomId) }
    }
}

// MARK: - URLSession implementation

@MainActor public final class URLSessionRelayNetworking: RelayNetworking {
    private let session: URLSession

    /// Uses the system proxy, PAC and certificate settings (the default configuration).
    public init(configuration: URLSessionConfiguration = .default) {
        let c = configuration
        c.timeoutIntervalForRequest = 40   // above the relay's 25 s poll hold
        self.session = URLSession(configuration: c)
    }

    public func openWebSocket(url: URL, headers: [String: String],
                              onEvent: @escaping @MainActor (RelayWebSocketEvent) -> Void) -> RelayWebSocket {
        URLSessionRelaySocket(url: url, headers: headers, onEvent: onEvent)
    }

    public func longPollSend(url: URL, headers: [String: String], body: Data) async throws -> (status: Int, data: Data) {
        var req = URLRequest(url: url)
        req.httpMethod = "POST"
        req.httpBody = body
        req.setValue("application/json", forHTTPHeaderField: "Content-Type")
        return try await run(req, headers)
    }

    public func longPollReceive(url: URL, headers: [String: String]) async throws -> (status: Int, data: Data) {
        try await run(URLRequest(url: url), headers)
    }

    private func run(_ request: URLRequest, _ headers: [String: String]) async throws -> (status: Int, data: Data) {
        var req = request
        for (k, v) in headers { req.setValue(v, forHTTPHeaderField: k) }
        let (data, resp) = try await session.data(for: req)
        return ((resp as? HTTPURLResponse)?.statusCode ?? 0, data)
    }
}

@MainActor final class URLSessionRelaySocket: NSObject, RelayWebSocket, URLSessionWebSocketDelegate {
    private let handler: @MainActor (RelayWebSocketEvent) -> Void
    private var task: URLSessionWebSocketTask?
    private var session: URLSession?
    private var ended = false

    init(url: URL, headers: [String: String], onEvent: @escaping @MainActor (RelayWebSocketEvent) -> Void) {
        handler = onEvent
        super.init()
        var req = URLRequest(url: url)
        for (k, v) in headers { req.setValue(v, forHTTPHeaderField: k) }
        let s = URLSession(configuration: .default, delegate: self, delegateQueue: nil)
        session = s
        let t = s.webSocketTask(with: req)
        task = t
        t.resume()
        Task { @MainActor [weak self] in await self?.receiveLoop(t) }
    }

    private func receiveLoop(_ t: URLSessionWebSocketTask) async {
        while !ended {
            do {
                switch try await t.receive() {
                case .string(let s): if !ended { handler(.text(s)) }
                case .data(let d): if !ended { handler(.data(d)) }
                @unknown default: break
                }
            } catch {
                let code = t.closeCode.rawValue
                finish(code > 0 ? .closed(code: code) : .failed(error.localizedDescription))
                return
            }
        }
    }

    private func finish(_ e: RelayWebSocketEvent) {
        guard !ended else { return }
        ended = true
        session?.invalidateAndCancel(); session = nil; task = nil
        handler(e)
    }

    func send(text: String) { task?.send(.string(text)) { _ in } }

    func close() {
        guard !ended else { return }
        ended = true
        task?.cancel(with: .normalClosure, reason: nil)
        session?.invalidateAndCancel(); session = nil; task = nil
    }

    nonisolated func urlSession(_ session: URLSession, webSocketTask: URLSessionWebSocketTask,
                                didOpenWithProtocol protocol: String?) {
        Task { @MainActor [weak self] in
            guard let self, !self.ended else { return }
            self.handler(.opened)
        }
    }

    nonisolated func urlSession(_ session: URLSession, task: URLSessionTask, didCompleteWithError error: Error?) {
        let why = error?.localizedDescription ?? "closed"
        Task { @MainActor [weak self] in self?.finish(.failed(why)) }
    }
}
