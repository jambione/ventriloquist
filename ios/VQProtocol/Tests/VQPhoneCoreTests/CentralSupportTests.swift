import Testing
import VQPhoneCore

@Suite("Central transport support (v2.3)")
struct CentralSupportTests {
    @Test func backoffSequenceAndReset() {
        var b = ReconnectBackoff()
        #expect((0..<7).map { _ in b.nextDelay() } == [1, 2, 4, 8, 15, 15, 15])
        b.reset()
        #expect(b.nextDelay() == 1)
    }

    @Test func oneWriteInFlightThenInOrder() {
        var q = SerialWriteQueue(maxQueued: 10)
        #expect(q.enqueue([1]) == .sendNow([1]))
        #expect(q.enqueue([2]) == .queued)
        #expect(q.enqueue([3]) == .queued)
        #expect(q.writeCompleted() == [2])
        #expect(q.enqueue([4]) == .queued)
        #expect(q.writeCompleted() == [3])
        #expect(q.writeCompleted() == [4])
        #expect(!q.isIdle)
        #expect(q.writeCompleted() == nil)
        #expect(q.isIdle)
        #expect(q.enqueue([5]) == .sendNow([5]))
    }

    @Test func overflowAndReset() {
        var q = SerialWriteQueue(maxQueued: 2)
        _ = q.enqueue([0])
        #expect(q.enqueue([1]) == .queued)
        #expect(q.enqueue([2]) == .queued)
        #expect(q.enqueue([3]) == .overflow)
        q.reset()
        #expect(q.isIdle)
        #expect(q.writeCompleted() == nil)
    }

    final class Recorder: PhoneTransport {
        var sent: [String] = []
        var closed: [String] = []
        let name: String
        let mtuValue: Int
        init(_ name: String, mtu: Int) { self.name = name; mtuValue = mtu }
        func send(frame: [UInt8], to peer: PeerID) { sent.append(peer.raw) }
        func disconnect(_ peer: PeerID) { closed.append(peer.raw) }
        func mtu(for peer: PeerID) -> Int { mtuValue }
    }

    @Test func compositeRoutesByPrefix() {
        let p = Recorder("p", mtu: 100), c = Recorder("c", mtu: 200)
        let t = CompositeTransport(routes: [("ble:", p), ("gc:", c)])
        t.send(frame: [1], to: PeerID("ble:1"))
        t.send(frame: [1], to: PeerID("gc:1"))
        t.disconnect(PeerID("gc:2"))
        t.disconnect(PeerID("ble:2"))
        t.send(frame: [1], to: PeerID("other"))
        #expect(p.sent == ["ble:1", "other"])
        #expect(c.sent == ["gc:1"])
        #expect(c.closed == ["gc:2"])
        #expect(p.closed == ["ble:2"])
        #expect(t.mtu(for: PeerID("gc:9")) == 200)
        #expect(t.mtu(for: PeerID("ble:9")) == 100)
    }
}
