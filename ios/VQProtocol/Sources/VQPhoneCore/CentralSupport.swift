import Foundation

/// Reconnect backoff for the central role (v2.3): 1, 2, 4, 8, then 15 s.
public struct ReconnectBackoff: Equatable, Sendable {
    public let maxDelay: Double
    private(set) public var attempt = 0

    public init(maxDelay: Double = 15) { self.maxDelay = maxDelay }

    /// The delay before the next attempt; advances the schedule.
    public mutating func nextDelay() -> Double {
        let d = min(maxDelay, pow(2, Double(min(attempt, 30))))
        attempt += 1
        return d
    }

    /// A connection was confirmed: start over.
    public mutating func reset() { attempt = 0 }
}

/// Outgoing frames of one central link: one write in flight, the rest wait
/// in a bounded FIFO (pure logic; the transport only moves bytes).
public struct SerialWriteQueue: Sendable {
    public enum EnqueueResult: Equatable, Sendable {
        /// Send this frame now (nothing was in flight).
        case sendNow([UInt8])
        /// Another write is in flight; the frame waits.
        case queued
        /// The queue is full; the caller should disconnect.
        case overflow
    }

    public let maxQueued: Int
    private var waiting: [[UInt8]] = []
    private var head = 0
    private(set) public var inFlight = false

    public init(maxQueued: Int = 12_000) { self.maxQueued = maxQueued }

    public var waitingCount: Int { waiting.count - head }
    public var isIdle: Bool { !inFlight && waitingCount == 0 }

    public mutating func enqueue(_ frame: [UInt8]) -> EnqueueResult {
        if !inFlight {
            inFlight = true
            return .sendNow(frame)
        }
        guard waitingCount < maxQueued else { return .overflow }
        waiting.append(frame)
        return .queued
    }

    /// The in-flight write finished; returns the next frame to send, if any.
    public mutating func writeCompleted() -> [UInt8]? {
        guard inFlight else { return nil }
        guard head < waiting.count else {
            inFlight = false
            waiting = []
            head = 0
            return nil
        }
        let f = waiting[head]
        head += 1
        if head > 1_024 { waiting.removeFirst(head); head = 0 }
        return f
    }

    public mutating func reset() {
        waiting = []
        head = 0
        inFlight = false
    }
}

/// Routes the engine's single `PhoneTransport` to several transports by
/// `PeerID` prefix, so peers of different transports can share one engine and
/// never collide (v2.3). Unknown prefixes go to the first route.
public final class CompositeTransport: PhoneTransport {
    private let routes: [(prefix: String, transport: PhoneTransport)]

    public init(routes: [(prefix: String, transport: PhoneTransport)]) {
        precondition(!routes.isEmpty)
        self.routes = routes
    }

    private func transport(for peer: PeerID) -> PhoneTransport {
        routes.first { peer.raw.hasPrefix($0.prefix) }?.transport ?? routes[0].transport
    }

    public func send(frame: [UInt8], to peer: PeerID) { transport(for: peer).send(frame: frame, to: peer) }
    public func disconnect(_ peer: PeerID) { transport(for: peer).disconnect(peer) }
    public func mtu(for peer: PeerID) -> Int { transport(for: peer).mtu(for: peer) }
}
