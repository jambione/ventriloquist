import Foundation

/// Per-peer outgoing frames and activity clock for BLE **polling mode**
/// (protocol README §2, "Polling mode (v2.2)"): a central that cannot
/// subscribe to `TX` reads it instead, and each read takes exactly one frame.
///
/// Pure logic (no CoreBluetooth, no clock of its own: callers pass `now`), so
/// ordering, caps, graceful close and the 60 s inactivity rule are unit-tested.
public struct PollQueue {
    public enum EnqueueResult: Equatable, Sendable {
        case queued
        /// The peer already has `maxPerPeer` frames waiting; not queued.
        case overflow
        /// The peer is closing; not queued.
        case closed
    }

    /// A poll peer with no RX write and no TX read for this long is dropped.
    public static let inactivityTimeout: TimeInterval = 60

    private struct State {
        var frames: [[UInt8]] = []
        var head = 0
        var lastActivity: TimeInterval
        var closing = false
        var count: Int { frames.count - head }
    }

    public let maxPerPeer: Int
    private var peers: [PeerID: State] = [:]

    public init(maxPerPeer: Int = 12_000) {
        self.maxPerPeer = maxPerPeer
    }

    /// Frames waiting, over all peers.
    public var totalCount: Int { peers.values.reduce(0) { $0 + $1.count } }
    public var isEmpty: Bool { totalCount == 0 }
    public func count(for peer: PeerID) -> Int { peers[peer]?.count ?? 0 }
    public func isTracking(_ peer: PeerID) -> Bool { peers[peer] != nil }

    /// Start tracking `peer` (idempotent; keeps queued frames).
    public mutating func add(_ peer: PeerID, now: TimeInterval) {
        if peers[peer] == nil { peers[peer] = State(lastActivity: now) }
    }

    /// Record an RX write or TX read by `peer`.
    public mutating func touch(_ peer: PeerID, now: TimeInterval) {
        peers[peer]?.lastActivity = now
    }

    @discardableResult
    public mutating func enqueue(_ frame: [UInt8], for peer: PeerID) -> EnqueueResult {
        guard var s = peers[peer] else { return .closed }
        if s.closing { return .closed }
        guard s.count < maxPerPeer else { return .overflow }
        s.frames.append(frame)
        peers[peer] = s
        return .queued
    }

    /// The next frame for `peer` (one per TX read), or `nil` (answer with an
    /// empty value). Counts as activity.
    public mutating func pop(for peer: PeerID, now: TimeInterval) -> [UInt8]? {
        guard var s = peers[peer] else { return nil }
        s.lastActivity = now
        guard s.head < s.frames.count else {
            peers[peer] = s
            return nil
        }
        let f = s.frames[s.head]
        s.head += 1
        if s.head >= s.frames.count {
            s.frames.removeAll(keepingCapacity: true)
            s.head = 0
        }
        peers[peer] = s
        return f
    }

    /// Stop accepting frames; the queued ones can still be read.
    public mutating func closeAfterFlush(_ peer: PeerID) {
        peers[peer]?.closing = true
    }

    /// `true` once `peer` is closing and its last frame has been read.
    public func isFinished(_ peer: PeerID) -> Bool {
        guard let s = peers[peer] else { return false }
        return s.closing && s.count == 0
    }

    public mutating func discard(_ peer: PeerID) { peers[peer] = nil }
    public mutating func discardAll() { peers = [:] }

    /// Remove and return the peers idle for at least ``inactivityTimeout``.
    public mutating func removeExpired(now: TimeInterval) -> [PeerID] {
        let gone = peers.filter { now - $0.value.lastActivity >= Self.inactivityTimeout }.map(\.key)
        for p in gone { peers[p] = nil }
        return gone
    }
}
