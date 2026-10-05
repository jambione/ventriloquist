import Foundation
import Testing
import VQProtocol
@testable import VQPhoneCore

// R5 fixer tests: X2 rulings for the phone (loopback-only http, engine-drop
// hold-off, queued frames, room gone on 401/404).

@Suite struct RelayFixTests {
    @Test func httpRelayOnlyForLoopback() throws {
        for ok in ["http://127.0.0.1:8787", "http://localhost:8787", "http://[::1]:8787", "https://relay.example.com"] {
            _ = try PairingURI.parse(PairingURITests.replacing("r", ok))
        }
        for bad in ["http://relay.example.com", "http://127.0.0.1.evil.com", "http://10.0.0.5:8787"] {
            #expect(throws: PairingURIError.invalid("r"), "\(bad)") {
                try PairingURI.parse(PairingURITests.replacing("r", bad))
            }
        }
    }

    @Test func engineDropBackoffIs5sDoublingToFiveMinutesAndResets() {
        var b = EngineDropBackoff()
        #expect((0..<8).map { _ in b.nextDelay() } == [5, 10, 20, 40, 80, 160, 300, 300])
        b.reset()
        #expect(b.nextDelay() == 5)
    }

    @Test func engineDropsWaitForTheHoldOffAndSecureResetsIt() {
        var m = RelayClientState(makeSession: { "s" })
        _ = m.handle(.connectRequested, now: 0)
        _ = m.handle(.wsOpened, now: 0)
        #expect(m.handle(.engineDropped, now: 1) == [.closeAll, .scheduleRetry(after: 5)])
        #expect(m.mode == .engineBackoff)
        #expect(m.handle(.engineDropped, now: 2).isEmpty)          // already waiting
        #expect(m.handle(.tick, now: 5).isEmpty)                   // too early (due at 6)
        #expect(m.handle(.tick, now: 6) == [.openWebSocket])
        _ = m.handle(.wsOpened, now: 6)
        #expect(m.handle(.engineDropped, now: 7) == [.closeAll, .scheduleRetry(after: 10)])
        _ = m.handle(.tick, now: 17)
        _ = m.handle(.wsOpened, now: 17)
        _ = m.handle(.sessionSecure, now: 18)
        #expect(m.handle(.engineDropped, now: 19) == [.closeAll, .scheduleRetry(after: 5)])
    }

    @Test func engineDropsWhileBackgroundedDoNothing() {
        var m = RelayClientState(makeSession: { "s" })
        _ = m.handle(.connectRequested, now: 0)
        _ = m.handle(.backgrounded, now: 1)
        #expect(m.handle(.engineDropped, now: 2).isEmpty)
        #expect(m.mode == .backgrounded)
    }

    @Test func pollingRoomGoneOn401Or404StopsTheRoom() {
        for status in [401, 404] {
            var m = RelayClientState(makeSession: { "s" })
            _ = m.handle(.connectRequested, now: 0)
            _ = m.handle(.wsFailed("x"), now: 0)
            let a = m.handle(.pollFailed(status: status), now: 1)
            #expect(a.contains(.roomDeleted), "\(status)")
            #expect(m.mode == .stopped)
        }
    }

    @Test func framesQueuedWhilePollRetriesAreBoundedAndSentOnceItWorks() {
        var m = RelayClientState(makeSession: { "s" })
        _ = m.handle(.connectRequested, now: 0)
        _ = m.handle(.wsFailed("x"), now: 0)
        _ = m.handle(.pollResponse(RelayPollResponse(connId: "c", cursor: 1, events: [.desktopPresent(true)])), now: 1)
        _ = m.handle(.pollFailed(status: 502), now: 2)
        for i in 0..<300 { _ = m.handle(.send(Data([UInt8(i % 256)])), now: 2) }
        _ = m.handle(.tick, now: 4)
        let a = m.handle(.pollResponse(RelayPollResponse(connId: "c", cursor: 1, events: [])), now: 4)
        guard case .sendPoll(_, let frames)? = a.first else { Issue.record("no send: \(a)"); return }
        #expect(frames.count == 256)
        #expect(frames.last == Data([UInt8(299 % 256)]))
    }

    @Test func failedSendReportsTheDesktopGoneAndRestartsTheSession() {
        let n = Counter()
        var m = RelayClientState(makeSession: { "s\(n.next())" })
        _ = m.handle(.connectRequested, now: 0)
        _ = m.handle(.wsFailed("x"), now: 0)
        _ = m.handle(.pollResponse(RelayPollResponse(connId: "c", cursor: 1, events: [.desktopPresent(true)])), now: 1)
        let a = m.handle(.sendFailed(session: "s2", status: 429), now: 2)
        #expect(a.contains(.peerDisconnected))
        #expect(m.mode == .retryingPoll)
        #expect(m.session == "s3")
        // A stale failure from an old session is ignored.
        #expect(m.handle(.sendFailed(session: "s1", status: 500), now: 3).isEmpty)
    }
}

private final class Counter: @unchecked Sendable {
    private var v = 1
    func next() -> Int { v += 1; return v }
}
