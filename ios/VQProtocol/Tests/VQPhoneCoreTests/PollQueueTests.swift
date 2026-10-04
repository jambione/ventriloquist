import Testing
import VQPhoneCore

@Suite("PollQueue (BLE polling mode)")
struct PollQueueTests {
    let a = PeerID("a"), b = PeerID("b")

    @Test func oneFramePerPopInOrderThenEmpty() {
        var q = PollQueue()
        q.add(a, now: 0)
        q.enqueue([1], for: a)
        q.enqueue([2, 2], for: a)
        #expect(q.pop(for: a, now: 1) == [1])
        #expect(q.pop(for: a, now: 1) == [2, 2])
        #expect(q.pop(for: a, now: 1) == nil)
        #expect(q.isEmpty)
    }

    @Test func peersAreIndependentAndUnknownIsEmpty() {
        var q = PollQueue()
        q.add(a, now: 0)
        q.add(b, now: 0)
        q.enqueue([1], for: a)
        #expect(q.pop(for: b, now: 0) == nil)
        #expect(q.pop(for: PeerID("zzz"), now: 0) == nil)
        #expect(q.enqueue([9], for: PeerID("zzz")) == .closed)
        #expect(q.pop(for: a, now: 0) == [1])
    }

    @Test func capOverflows() {
        var q = PollQueue(maxPerPeer: 2)
        q.add(a, now: 0)
        #expect(q.enqueue([1], for: a) == .queued)
        #expect(q.enqueue([2], for: a) == .queued)
        #expect(q.enqueue([3], for: a) == .overflow)
        _ = q.pop(for: a, now: 0)
        #expect(q.enqueue([3], for: a) == .queued)
    }

    @Test func closeAfterFlushKeepsQueuedFramesReadable() {
        var q = PollQueue()
        q.add(a, now: 0)
        q.enqueue([1], for: a)
        q.closeAfterFlush(a)
        #expect(q.enqueue([2], for: a) == .closed)
        #expect(!q.isFinished(a))
        #expect(q.pop(for: a, now: 0) == [1])
        #expect(q.isFinished(a))
    }

    @Test func inactivityExpiresAfter60SecondsAndActivityResets() {
        var q = PollQueue()
        q.add(a, now: 0)
        q.add(b, now: 0)
        q.touch(b, now: 30)
        _ = q.pop(for: a, now: 10)  // a read counts as activity
        #expect(q.removeExpired(now: 59).isEmpty)
        #expect(q.removeExpired(now: 70) == [a])
        #expect(!q.isTracking(a))
        #expect(q.isTracking(b))
        #expect(q.removeExpired(now: 90) == [b])
    }

    @Test func discardForgetsFrames() {
        var q = PollQueue()
        q.add(a, now: 0)
        q.enqueue([1], for: a)
        q.discard(a)
        #expect(q.isEmpty)
        #expect(q.pop(for: a, now: 0) == nil)
    }
}
