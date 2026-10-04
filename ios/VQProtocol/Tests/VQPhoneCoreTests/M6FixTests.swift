import Foundation
import Testing
import VQPhoneCore
import VQProtocol

@Suite("M6 fixer regressions")
struct M6FixTests {
    // M8: engine-initiated drops tell the desktop.
    @Test func forgetHostTellsTheDesktop() {
        let h = Harness()
        let d = h.pairedDesktop("Mac")
        h.net.connect(d)
        h.engine.forgetHost(d.deviceId)
        #expect(d.errorsReceived.map(\.code) == ["protocol"])
    }

    @Test func abruptCloseStillTearsDownEngineState() {
        let h = Harness()
        let d = h.pairedDesktop("Mac")
        h.net.gracefulDisconnect = false
        let peer = h.net.connect(d)
        h.engine.forgetHost(d.deviceId)
        #expect(!h.net.isConnected(peer))
        #expect(d.errorsReceived.isEmpty)  // discarded, as on an abrupt BLE close
        #expect(h.engine.hosts.allSatisfy { !$0.isOnline })
    }

    // M10: unreadable host list.
    @Test func unreadableHostFileIsFlaggedAndBackedUpBeforeSave() {
        let h = Harness()
        h.hostStore.failLoads = true
        let d = h.desktop("Mac")
        #expect(h.engine.pairedHostsUnreadable)
        h.hostStore.failLoads = false
        h.net.connect(d)
        #expect(h.hostStore.backups == 0)
        h.pair(d)
        #expect(h.hostStore.backups == 1)
        #expect(h.hostStore.hosts.count == 1)
    }

    @Test func failedBackupCancelsTheSave() {
        let h = Harness()
        h.hostStore.failLoads = true
        h.hostStore.failBackups = true
        let d = h.desktop("Mac")
        _ = h.engine
        h.hostStore.failLoads = false
        h.net.connect(d)
        h.pair(d)
        #expect(h.hostStore.hosts.isEmpty)
        #expect(h.notices.contains(.storageFailed))
    }

    // M14 / M15: names.
    @Test func hugeDeviceNameStillProducesHello() {
        let h = Harness()
        h.engine.deviceName = String(repeating: "N", count: 100_000)
        let d = h.desktop("Mac")
        h.net.connect(d)
        #expect(d.hellosFromPhone.count == 1)
        #expect(d.hellosFromPhone[0].name.unicodeScalars.count <= 64)
    }

    @Test func peerNamesAreSanitized() {
        let h = Harness()
        let d = h.desktop("\u{202E}Evil\u{0007}\nMac" + String(repeating: "x", count: 200))
        h.net.connect(d)
        let name = h.engine.hosts.first?.name ?? ""
        #expect(name.unicodeScalars.count <= 64)
        #expect(!name.unicodeScalars.contains { $0.value == 0x202E || $0.value < 0x20 })
        #expect(PhoneNames.clean("\u{200E}\n", fallback: "Unnamed") == "Unnamed")
    }

    // M20: silent connections.
    @Test func connectionsWithoutHelloAreReapedAfter30s() {
        let h = Harness()
        let net = h.net
        _ = net
        let e = h.engine
        e.peerConnected(PeerID("silent"))
        h.advance(31)
        // A hello for it is now ignored: the connection is gone.
        e.peerReceived(frame: [0], from: PeerID("silent"))
        #expect(e.hosts.isEmpty)
    }

    @Test func unprovenConnectionsAreCapped() {
        let h = Harness()
        _ = h.net
        let e = h.engine
        for i in 0..<50 { e.peerConnected(PeerID("s\(i)")) }
        #expect(h.net.disconnectedByPhone.count == 50 - PhoneEngine.maxUnprovenConnections)
    }

    // M7: client-side window budget.
    @Test func sixthRequestInTenMinutesIsHeldBack() {
        let h = Harness()
        let d = h.desktop("Mac")
        h.net.connect(d)
        for _ in 0..<5 {
            h.engine.startPairing(with: d.deviceId)
            h.net.pump()
            h.advance(11)
        }
        #expect(d.pairRequests == 5)
        h.engine.startPairing(with: d.deviceId)
        h.net.pump()
        #expect(d.pairRequests == 5)
        #expect(d.rateLimitedAnswers == 0)
        #expect((h.engine.pairing?.retryIn ?? 0) > 400)
    }
}

@Suite("FrameSendQueue (M25)")
struct FrameSendQueueTests {
    let a = PeerID("a"), b = PeerID("b")

    @Test func preservesOrderAndCountsPerPeer() {
        var q = FrameSendQueue(maxPerPeer: 10)
        for i in 0..<3 { q.enqueue([UInt8(i)], for: a) }
        q.enqueue([9], for: b)
        #expect(q.count(for: a) == 3 && q.count(for: b) == 1 && q.totalCount == 4)
        var out: [[UInt8]] = []
        _ = q.drain { _, f in out.append(f); return true }
        #expect(out == [[0], [1], [2], [9]])
        #expect(q.isEmpty && q.count(for: a) == 0)
    }

    @Test func backpressureStopsAndResumes() {
        var q = FrameSendQueue()
        for i in 0..<4 { q.enqueue([UInt8(i)], for: a) }
        var taken = 0
        _ = q.drain { _, _ in taken += 1; return taken <= 2 }
        #expect(q.totalCount == 2)
        var out: [[UInt8]] = []
        _ = q.drain { _, f in out.append(f); return true }
        #expect(out == [[2], [3]])
    }

    @Test func capPerPeerOnly() {
        var q = FrameSendQueue(maxPerPeer: 2)
        #expect(q.enqueue([1], for: a) == .queued)
        #expect(q.enqueue([2], for: a) == .queued)
        #expect(q.enqueue([3], for: a) == .overflow)
        #expect(q.enqueue([3], for: b) == .queued)
    }

    @Test func discardRemovesOnlyThatPeer() {
        var q = FrameSendQueue()
        q.enqueue([1], for: a); q.enqueue([2], for: b); q.enqueue([3], for: a)
        q.discard(a)
        var out: [[UInt8]] = []
        _ = q.drain { _, f in out.append(f); return true }
        #expect(out == [[2]])
    }

    @Test func closeAfterFlushDeliversQueuedThenReports() {
        var q = FrameSendQueue()
        q.enqueue([1], for: a); q.enqueue([2], for: a)
        let closedNow = q.closeAfterFlush(a)
        #expect(!closedNow)
        #expect(q.enqueue([3], for: a) == .closed)
        var out: [[UInt8]] = []
        let done = q.drain { _, f in out.append(f); return true }
        #expect(out == [[1], [2]] && done == [a])
        let otherClosedNow = q.closeAfterFlush(b)
        #expect(otherClosedNow)  // nothing queued: closed at once
    }

    @Test func manyFramesDrainInLinearTime() {
        var q = FrameSendQueue(maxPerPeer: 100_000)
        for i in 0..<50_000 { q.enqueue([UInt8(i & 0xFF)], for: a) }
        var n = 0
        _ = q.drain { _, _ in n += 1; return true }
        #expect(n == 50_000)
    }
}
