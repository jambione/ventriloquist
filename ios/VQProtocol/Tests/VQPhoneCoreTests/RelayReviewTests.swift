import Foundation
import Testing
import VQPhoneCore

// v3 review (R5): failing tests for defects in the phone relay transport.
// Reuses the fakes of RelayPhoneTransportTests.swift (FakeNet, Rig, ...).

@Suite("Relay review") @MainActor
struct RelayReviewTests {
    static let pollUp = "{\"conn_id\":\"c\",\"cursor\":1,\"events\":[{\"type\":\"desktop_present\",\"present\":true}]}"
    static let peer = PeerID("relay:room1")

    /// Finding 4 (MAJOR). On long-poll, a failed poll (network glitch, 502
    /// from a proxy, cellular hand-over) puts the room in `.retryingPoll`
    /// for 1, 2, 4, 8, 30 s but keeps the desktop "present": no
    /// `peerDisconnected` is emitted. Frames the engine sends meanwhile are
    /// dropped by `RelayClientState.handle(.send)` (it only sends in
    /// `.wsOpen` / `.polling`). The engine retries a final 5 times at 2 s and
    /// then marks it `failed`; when the poll recovers on the same session
    /// there is no reconnect, so `flushOutbox` never runs and the final stays
    /// failed although the link works. Either report the peer down on a poll
    /// failure or queue the frames until the session is polling again.
    @Test func framesSentWhileThePollIsRetryingAreNotSilentlyDropped() async {
        let r = Rig()
        r.t.addRoom(relayURL: Rig.url, roomId: "room1", secret: "sek")
        r.net.sockets[0].emit(.failed("refused"))   // WebSocket blocked: long-poll
        await r.settle()
        r.net.reply(Self.pollUp)
        await r.settle()
        #expect(r.rec.log == ["up relay:room1"])
        r.net.reply(status: 502, "bad gateway")      // the next poll fails
        await r.settle()
        r.t.send(frame: [9, 9], to: Self.peer)       // the engine sends a final
        await r.settle()
        r.sched.advance(1)                           // the poll is retried and works
        await r.settle()
        r.net.reply("{\"conn_id\":\"c\",\"cursor\":1,\"events\":[]}")
        await r.settle()
        let reportedDown = r.rec.log.contains("down relay:room1")
        let delivered = r.net.sends.contains { String(decoding: $0.body, as: UTF8.self).contains(Data([9, 9]).base64EncodedString()) }
        #expect(reportedDown || delivered, "the frame vanished while the peer stayed 'up': \(r.rec.log), sends=\(r.net.sends.count)")
    }

    /// Finding 5 (MAJOR). `RelayPhoneTransport.disconnect` (called by
    /// `PhoneEngine.drop`) cycles the room with `.disconnectRequested` +
    /// `.connectRequested`, which resets the backoff and opens a new
    /// WebSocket at once. Every engine-side drop that repeats on reconnect
    /// becomes a hot loop with no delay: the desktop forgot this phone
    /// (`error unknown_peer` on every hello; the desktop's `reconnect_after`
    /// hold-off is ignored by the relay transport), a pin mismatch
    /// (`pairingCodeMismatch` for an already paired desktop whose key
    /// changed), a protocol violation. Each turn is a WebSocket handshake
    /// through Cloudflare plus a notice, until the user acts. SPEC_V3 §6:
    /// reconnects back off 1, 2, 4, 8, max 30 s.
    @Test func engineDropsBackOffInsteadOfReconnectingInAHotLoop() {
        let r = Rig()
        r.t.addRoom(relayURL: Rig.url, roomId: "room1", secret: "sek")
        for _ in 0..<5 {
            let s = r.net.sockets.last!
            s.emit(.opened)
            s.desktop(true)
            // The desktop answers our hello with unknown_peer; the engine drops.
            r.t.disconnect(Self.peer)
        }
        // No time has passed: 5 drops must not mean 6 WebSocket handshakes.
        #expect(r.net.sockets.count <= 2, "opened \(r.net.sockets.count) sockets with no delay")
    }

    /// Finding 8 (MINOR). `AppModel.enterBackground` calls
    /// `engine.disconnectAll()` before `relay.pauseAll()`. `disconnectAll`
    /// drops each connection, `disconnect` cycles its room, and a brand new
    /// WebSocket is opened just before the app is paused (then cancelled).
    /// The desktop may see a phantom `peer_joined`/`peer_left` and send a
    /// `hello` into the void. Backgrounding must never open a connection.
    @Test func backgroundingDoesNotOpenANewConnection() {
        let r = Rig()
        r.t.addRoom(relayURL: Rig.url, roomId: "room1", secret: "sek")
        let s = r.net.sockets[0]
        s.emit(.opened)
        s.desktop(true)
        // AppModel.enterBackground: engine.disconnectAll() -> transport.disconnect, then pauseAll().
        r.t.disconnect(Self.peer)
        r.t.pauseAll()
        #expect(r.net.sockets.count == 1, "a WebSocket was opened while going to the background")
    }
}
