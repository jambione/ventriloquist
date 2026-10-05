import Foundation

// The relay wire protocol for the phone role (relay/README.md) and a pure
// client state machine. No networking: the host app performs the actions and
// feeds the results back as inputs.

/// Namespace for relay transport constants shared with the app layer.
public enum RelayTransport {
    /// The one peer the phone has on a relay: the desktop of the room.
    public static func peerID(roomId: String) -> PeerID { PeerID("relay:\(roomId)") }
    /// A WebSocket that drops sooner than this after opening counts as unusable.
    public static let stableAfter: Double = 10
    /// While on long-poll, try the WebSocket again this often.
    public static let wsRetryInterval: Double = 300
}

// MARK: - Messages

public struct RelayClose: Codable, Equatable, Sendable {
    public var code: Int
    public var reason: String?
    public init(code: Int, reason: String? = nil) { self.code = code; self.reason = reason }
}

/// Relay to client. Decoding never throws on an unknown `type` (it is `.unknown`).
public enum RelayServerMessage: Equatable, Sendable, Decodable {
    case frame(from: String?, data: Data)
    case desktopPresent(Bool)
    case peerJoined(String)
    case peerLeft(String)
    case pong
    case unknown

    enum Keys: String, CodingKey { case type, from, data, present, connId = "conn_id" }

    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: Keys.self)
        switch try c.decode(String.self, forKey: .type) {
        case "frame":
            guard let s = try c.decodeIfPresent(String.self, forKey: .data), let d = RelayCodec.base64(s)
            else { self = .unknown; return }
            self = .frame(from: try c.decodeIfPresent(String.self, forKey: .from), data: d)
        case "desktop_present": self = .desktopPresent(try c.decode(Bool.self, forKey: .present))
        case "peer_joined": self = .peerJoined(try c.decode(String.self, forKey: .connId))
        case "peer_left": self = .peerLeft(try c.decode(String.self, forKey: .connId))
        default: self = .unknown
        }
    }
}

/// One frame of a `POST send` body (`type` is optional; phones omit `to`).
public struct RelayOutFrame: Codable, Equatable, Sendable {
    public var type: String? = "frame"
    public var to: String?
    public var data: String
    public init(data: Data, to: String? = nil) { self.data = data.base64EncodedString(); self.to = to }
}

public struct RelaySendRequest: Codable, Equatable, Sendable {
    public var frames: [RelayOutFrame]
}

public struct RelaySendResponse: Codable, Equatable, Sendable {
    public var ok: Bool
    public var accepted: Int
    public var connId: String
    enum CodingKeys: String, CodingKey { case ok, accepted, connId = "conn_id" }
}

public struct RelayPollResponse: Decodable, Equatable, Sendable {
    public var connId: String
    public var cursor: Int
    public var events: [RelayServerMessage]
    public var closed: RelayClose?
    enum CodingKeys: String, CodingKey { case connId = "conn_id", cursor, events, closed }

    public init(connId: String, cursor: Int, events: [RelayServerMessage], closed: RelayClose? = nil) {
        self.connId = connId; self.cursor = cursor; self.events = events; self.closed = closed
    }
}

// MARK: - Codec

public enum RelayCodec {
    /// Standard base64, padding optional.
    public static func base64(_ s: String) -> Data? {
        var t = s
        while t.count % 4 != 0 { t += "=" }
        return Data(base64Encoded: t)
    }

    /// A phone frame as WebSocket text: `{"type":"frame","data":"<base64>"}`.
    public static func encodeFrame(_ data: Data) -> String {
        "{\"type\":\"frame\",\"data\":\"\(data.base64EncodedString())\"}"
    }

    public static let ping = "ping"

    /// Body of `POST send` for one or more frames.
    public static func encodeSend(_ frames: [Data]) -> Data {
        let enc = JSONEncoder()
        enc.outputFormatting = [.sortedKeys]
        return (try? enc.encode(RelaySendRequest(frames: frames.map { RelayOutFrame(data: $0) }))) ?? Data()
    }

    /// A WebSocket message (text or binary). Text `pong` is `.pong`; garbage is nil.
    public static func decodeMessage(_ data: Data) -> RelayServerMessage? {
        if data == Data("pong".utf8) { return .pong }
        return try? JSONDecoder().decode(RelayServerMessage.self, from: data)
    }

    public static func decodeMessage(_ text: String) -> RelayServerMessage? { decodeMessage(Data(text.utf8)) }

    public static func decodePoll(_ data: Data) -> RelayPollResponse? {
        try? JSONDecoder().decode(RelayPollResponse.self, from: data)
    }

    public static func decodeSendResponse(_ data: Data) -> RelaySendResponse? {
        try? JSONDecoder().decode(RelaySendResponse.self, from: data)
    }

    /// Session ids: 8 to 64 characters of `[A-Za-z0-9_-]`.
    public static func randomSession() -> String {
        Base64URL.encode((0..<16).map { _ in UInt8.random(in: 0...255) })
    }
}

// MARK: - State machine

public enum RelayClientInput {
    case connectRequested
    case disconnectRequested
    case backgrounded
    case wsOpened
    case wsFailed(String)
    case wsClosed(Int)
    case wsMessage(Data)
    case wsText(String)
    case pollResponse(RelayPollResponse)
    /// HTTP status when there was one (410 means the session expired).
    case pollFailed(status: Int?)
    /// Send one frame to the desktop.
    case send(Data)
    case tick
}

public enum RelayClientAction: Equatable, Sendable {
    case openWebSocket
    case startLongPoll(session: String, cursor: Int)
    case cancelLongPoll
    case sendWS(String)
    case sendPoll(session: String, frames: [Data])
    /// Call `tick` after this many seconds (the machine keeps the deadline itself).
    case scheduleRetry(after: Double)
    case peerConnected
    case peerDisconnected
    case deliverFrame(Data)
    case closeAll
    /// The room is gone (4001/4003); reconnecting is pointless.
    case roomDeleted
}

public struct RelayClientState: Sendable {
    public enum Mode: Equatable, Sendable {
        case idle, connectingWS, wsOpen, polling, retryingWS, retryingPoll, backgrounded, stopped
    }

    public private(set) var mode: Mode = .idle
    public private(set) var session: String?
    public private(set) var cursor = 0
    public private(set) var peerPresent = false
    public private(set) var backoff = ReconnectBackoff()
    var openedAt = 0.0
    var retryAt: Double?
    var probeAt: Double?
    var probing = false
    let makeSession: @Sendable () -> String
    /// Never open a WebSocket: use the long-poll fallback from the start
    /// (`VQ_RELAY_FORCE_LONGPOLL`, for tests and restrictive networks).
    let forceLongPoll: Bool

    public init(makeSession: @escaping @Sendable () -> String = RelayCodec.randomSession,
                forceLongPoll: Bool = false) {
        self.makeSession = makeSession
        self.forceLongPoll = forceLongPoll
    }

    static func isDeleted(_ code: Int) -> Bool { code == 4001 || code == 4003 }

    public mutating func handle(_ input: RelayClientInput, now: Double) -> [RelayClientAction] {
        switch input {
        case .connectRequested:
            guard mode == .idle || mode == .backgrounded else { return [] }
            backoff.reset()
            if forceLongPoll {
                mode = .polling; probing = false; probeAt = nil
                startFreshSession()
                return [.startLongPoll(session: session!, cursor: 0)]
            }
            mode = .connectingWS
            return [.openWebSocket]
        case .disconnectRequested: return shutdown(.idle)
        case .backgrounded: return shutdown(.backgrounded)
        case .wsOpened:
            if mode == .connectingWS {
                mode = .wsOpen; openedAt = now
                return []
            }
            if mode == .polling || mode == .retryingPoll, probing {
                probing = false; probeAt = nil; session = nil
                mode = .wsOpen; openedAt = now
                return [.cancelLongPoll] + dropPeer()
            }
            return []
        case .wsFailed: return connectionLost(code: nil, now: now)
        case .wsClosed(let code): return connectionLost(code: code, now: now)
        case .wsMessage(let d): return mode == .wsOpen ? apply(RelayCodec.decodeMessage(d)) : []
        case .wsText(let s): return mode == .wsOpen ? apply(RelayCodec.decodeMessage(s)) : []
        case .send(let d):
            switch mode {
            case .wsOpen: return [.sendWS(RelayCodec.encodeFrame(d))]
            case .polling: return session.map { [.sendPoll(session: $0, frames: [d])] } ?? []
            default: return []
            }
        case .pollResponse(let r): return pollResponse(r, now: now)
        case .pollFailed(let status): return pollFailed(status, now: now)
        case .tick: return tick(now: now)
        }
    }

    // MARK: pieces

    private mutating func dropPeer() -> [RelayClientAction] {
        guard peerPresent else { return [] }
        peerPresent = false
        return [.peerDisconnected]
    }

    private mutating func shutdown(_ to: Mode) -> [RelayClientAction] {
        guard mode != .stopped, mode != to else { return [] }
        let a = dropPeer()
        mode = to; session = nil; cursor = 0; retryAt = nil; probeAt = nil; probing = false
        return a + [.closeAll]
    }

    private mutating func stop() -> [RelayClientAction] {
        let a = dropPeer()
        mode = .stopped; session = nil; retryAt = nil; probeAt = nil; probing = false
        return a + [.closeAll, .roomDeleted]
    }

    private mutating func startFreshSession() {
        session = makeSession(); cursor = 0
    }

    private mutating func fallbackToPoll(now: Double) -> [RelayClientAction] {
        let a = dropPeer()
        mode = .polling; probing = false
        startFreshSession()
        probeAt = now + RelayTransport.wsRetryInterval
        return a + [.startLongPoll(session: session!, cursor: 0), .scheduleRetry(after: RelayTransport.wsRetryInterval)]
    }

    private mutating func connectionLost(code: Int?, now: Double) -> [RelayClientAction] {
        if let code, Self.isDeleted(code), mode == .connectingWS || mode == .wsOpen || ((mode == .polling || mode == .retryingPoll) && probing) {
            return stop()
        }
        switch mode {
        case .connectingWS:
            return fallbackToPoll(now: now)
        case .wsOpen:
            if now - openedAt < RelayTransport.stableAfter { return fallbackToPoll(now: now) }
            backoff.reset()
            let a = dropPeer()
            let d = backoff.nextDelay()
            mode = .retryingWS; retryAt = now + d
            return a + [.scheduleRetry(after: d)]
        case .polling where probing, .retryingPoll where probing:
            probing = false
            probeAt = now + RelayTransport.wsRetryInterval
            return [.scheduleRetry(after: RelayTransport.wsRetryInterval)]
        default:
            return []
        }
    }

    private mutating func apply(_ m: RelayServerMessage?) -> [RelayClientAction] {
        switch m {
        case .frame(_, let d): return [.deliverFrame(d)]
        case .desktopPresent(true):
            guard !peerPresent else { return [] }
            peerPresent = true
            return [.peerConnected]
        case .desktopPresent(false): return dropPeer()
        default: return []
        }
    }

    private mutating func pollResponse(_ r: RelayPollResponse, now: Double) -> [RelayClientAction] {
        guard mode == .polling, let session else { return [] }
        backoff.reset()
        // Events are numbered; the last one has number `r.cursor`. Skip repeats.
        let first = r.cursor - r.events.count + 1
        var out: [RelayClientAction] = []
        for (i, e) in r.events.enumerated() where first + i > cursor { out += apply(e) }
        cursor = max(cursor, r.cursor)
        if let closed = r.closed {
            if Self.isDeleted(closed.code) { return out + stop() }
            out += dropPeer()
            startFreshSession()
            let d = backoff.nextDelay()
            mode = .retryingPoll; retryAt = now + d
            return out + [.scheduleRetry(after: d)]
        }
        return out + [.startLongPoll(session: session, cursor: cursor)]
    }

    private mutating func pollFailed(_ status: Int?, now: Double) -> [RelayClientAction] {
        guard mode == .polling else { return [] }
        if status == 410 {
            let a = dropPeer()
            startFreshSession()
            return a + [.startLongPoll(session: session!, cursor: 0)]
        }
        let d = backoff.nextDelay()
        mode = .retryingPoll; retryAt = now + d
        return [.scheduleRetry(after: d)]
    }

    private mutating func tick(now: Double) -> [RelayClientAction] {
        switch mode {
        case .retryingWS:
            guard let t = retryAt, now >= t else { return [] }
            retryAt = nil; mode = .connectingWS
            return [.openWebSocket]
        case .retryingPoll:
            guard let t = retryAt, now >= t, let session else { return [] }
            retryAt = nil; mode = .polling
            return [.startLongPoll(session: session, cursor: cursor)]
        case .polling:
            guard !probing, let t = probeAt, now >= t else { return [] }
            probing = true; probeAt = nil
            return [.openWebSocket]
        default:
            return []
        }
    }
}
