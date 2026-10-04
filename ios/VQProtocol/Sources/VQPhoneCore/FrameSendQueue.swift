import Foundation

/// The outgoing frame queue of a transport whose link applies backpressure
/// (BLE: `updateValue` returns `false` until `peripheralManagerIsReady`).
///
/// Pure logic, so ordering, limits and close semantics are unit-tested without
/// CoreBluetooth:
/// * one FIFO over all peers (backpressure is shared), so frames to one peer
///   keep their order;
/// * a per-peer cap, with O(1) counting;
/// * ``closeAfterFlush(_:)`` ends a link *gracefully*: it takes no new frames
///   and is reported finished once the frames already queued have been sent
///   (so an `error` queued before a close still goes out), and
///   ``discard(_:)`` ends it abruptly.
public struct FrameSendQueue {
    public enum EnqueueResult: Equatable, Sendable {
        case queued
        /// The peer already has `maxPerPeer` frames waiting; the frame was not queued.
        case overflow
        /// The peer is closing; the frame was not queued.
        case closed
    }

    private struct Entry {
        let peer: PeerID
        let frame: [UInt8]
    }

    public let maxPerPeer: Int
    private var buffer: [Entry] = []
    private var head = 0
    private var counts: [PeerID: Int] = [:]
    private var closing: Set<PeerID> = []

    public init(maxPerPeer: Int = 12_000) {
        self.maxPerPeer = maxPerPeer
    }

    /// Frames waiting, over all peers.
    public var totalCount: Int { buffer.count - head }
    public var isEmpty: Bool { totalCount == 0 }
    /// Frames waiting for `peer`.
    public func count(for peer: PeerID) -> Int { counts[peer] ?? 0 }
    public func isClosing(_ peer: PeerID) -> Bool { closing.contains(peer) }

    /// Append one frame for `peer`.
    @discardableResult
    public mutating func enqueue(_ frame: [UInt8], for peer: PeerID) -> EnqueueResult {
        if closing.contains(peer) { return .closed }
        let n = counts[peer, default: 0]
        guard n < maxPerPeer else { return .overflow }
        counts[peer] = n + 1
        buffer.append(Entry(peer: peer, frame: frame))
        return .queued
    }

    /// Stop accepting frames for `peer`; the frames already queued still go
    /// out. Returns `true` when nothing was queued, i.e. the link is closed now.
    /// Otherwise ``drain(send:)`` reports the peer once its last frame is out.
    @discardableResult
    public mutating func closeAfterFlush(_ peer: PeerID) -> Bool {
        if counts[peer, default: 0] == 0 { return true }
        closing.insert(peer)
        return false
    }

    /// Forget `peer` and every frame queued for it.
    public mutating func discard(_ peer: PeerID) {
        closing.remove(peer)
        guard counts.removeValue(forKey: peer) != nil else { return }
        let rest = buffer[head...].filter { $0.peer != peer }
        buffer = Array(rest)
        head = 0
    }

    /// Forget everything.
    public mutating func discardAll() {
        buffer = []
        head = 0
        counts = [:]
        closing = []
    }

    /// Hand frames to `send` in order until it returns `false` (the stack is
    /// full: call again when it is ready). `send` returns `true` when the frame
    /// was taken or can be dropped (e.g. its link is gone). Returns the peers
    /// that were closing and have now sent their last frame.
    public mutating func drain(send: (PeerID, [UInt8]) -> Bool) -> [PeerID] {
        var finished: [PeerID] = []
        while head < buffer.count {
            let e = buffer[head]
            guard send(e.peer, e.frame) else { break }
            head += 1
            let left = counts[e.peer, default: 1] - 1
            if left <= 0 {
                counts[e.peer] = nil
                if closing.remove(e.peer) != nil { finished.append(e.peer) }
            } else {
                counts[e.peer] = left
            }
        }
        if head > 0, head >= buffer.count || head > 1_024 {
            buffer.removeFirst(head)
            head = 0
        }
        return finished
    }
}
