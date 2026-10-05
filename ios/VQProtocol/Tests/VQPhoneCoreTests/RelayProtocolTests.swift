import Foundation
import Testing
@testable import VQPhoneCore

private func json(_ s: String) -> Data { Data(s.utf8) }
private let hello = Data([1, 2, 3, 250])

private func machine() -> RelayClientState {
    let n = Counter()
    return RelayClientState(makeSession: { "session-\(n.next())" })
}

private final class Counter: @unchecked Sendable {
    private var v = 0
    func next() -> Int { v += 1; return v }
}

private func poll(_ cursor: Int, _ events: [RelayServerMessage], closed: RelayClose? = nil) -> RelayClientInput {
    .pollResponse(RelayPollResponse(connId: "c1", cursor: cursor, events: events, closed: closed))
}

/// A machine with an open WebSocket that has been up since t=0.
private func openWS() -> RelayClientState {
    var m = machine()
    _ = m.handle(.connectRequested, now: 0)
    _ = m.handle(.wsOpened, now: 0)
    return m
}

/// A machine that fell back to long-poll at t=0 (session-1).
private func polling() -> RelayClientState {
    var m = machine()
    _ = m.handle(.connectRequested, now: 0)
    _ = m.handle(.wsFailed("x"), now: 0)
    return m
}

@Suite struct RelayCodecTests {
    @Test func decodesFrameEvent() {
        let m = RelayCodec.decodeMessage(#"{ "type": "frame", "from": "abc", "data": "AQID+g==" }"#)
        #expect(m == .frame(from: "abc", data: hello))
    }

    @Test func decodesUnpaddedBase64() {
        #expect(RelayCodec.decodeMessage(#"{"type":"frame","from":"a","data":"AQID+g"}"#) == .frame(from: "a", data: hello))
    }

    @Test func decodesDesktopPresentAndPeers() {
        #expect(RelayCodec.decodeMessage(#"{ "type": "desktop_present", "present": true }"#) == .desktopPresent(true))
        #expect(RelayCodec.decodeMessage(#"{"type":"desktop_present","present":false}"#) == .desktopPresent(false))
        #expect(RelayCodec.decodeMessage(#"{ "type": "peer_joined", "conn_id": "x" }"#) == .peerJoined("x"))
        #expect(RelayCodec.decodeMessage(#"{ "type": "peer_left",   "conn_id": "x" }"#) == .peerLeft("x"))
    }

    @Test func pongGarbageAndUnknown() {
        #expect(RelayCodec.decodeMessage("pong") == .pong)
        #expect(RelayCodec.decodeMessage("not json") == nil)
        #expect(RelayCodec.decodeMessage(#"{"type":"future"}"#) == .unknown)
        #expect(RelayCodec.decodeMessage(#"{"type":"frame","data":"!!!"}"#) == .unknown)
    }

    @Test func binaryWebSocketMessage() {
        #expect(RelayCodec.decodeMessage(json(#"{"type":"desktop_present","present":true}"#)) == .desktopPresent(true))
    }

    @Test func encodeFrameRoundTrips() throws {
        let text = RelayCodec.encodeFrame(hello)
        let o = try JSONSerialization.jsonObject(with: json(text)) as? [String: String]
        #expect(o == ["type": "frame", "data": "AQID+g=="])
        #expect(RelayCodec.decodeMessage(text) == .frame(from: nil, data: hello))
    }

    @Test func encodeSendBody() throws {
        let body = RelayCodec.encodeSend([hello, Data()])
        let o = try JSONSerialization.jsonObject(with: body) as? [String: [[String: String]]]
        #expect(o?["frames"]?.count == 2)
        #expect(o?["frames"]?[0]["data"] == "AQID+g==")
        #expect(o?["frames"]?[0]["type"] == "frame")
        #expect(o?["frames"]?[0]["to"] == nil)
    }

    @Test func decodesPollResponse() {
        let body = json(#"{ "conn_id": "..", "cursor": 7, "events": [ { "type": "frame", "from": "d", "data": "AQID+g==" }, { "type": "desktop_present", "present": true } ] }"#)
        let r = RelayCodec.decodePoll(body)
        #expect(r?.cursor == 7)
        #expect(r?.connId == "..")
        #expect(r?.events == [.frame(from: "d", data: hello), .desktopPresent(true)])
        #expect(r?.closed == nil)
    }

    @Test func decodesPollClosed() {
        let r = RelayCodec.decodePoll(json(#"{"conn_id":"c","cursor":2,"events":[],"closed":{"code":4001,"reason":"replaced"}}"#))
        #expect(r?.closed == RelayClose(code: 4001, reason: "replaced"))
    }

    @Test func decodesSendResponse() {
        let r = RelayCodec.decodeSendResponse(json(#"{"ok":true,"accepted":2,"conn_id":"zz"}"#))
        #expect(r == RelaySendResponse(ok: true, accepted: 2, connId: "zz"))
    }

    @Test func randomSessionIsValid() {
        let s = RelayCodec.randomSession()
        #expect((8...64).contains(s.count) && PairingURI.isIdChars(s))
    }
}

@Suite struct RelayClientStateTests {
    @Test func webSocketFirst() {
        var m = machine()
        #expect(m.handle(.connectRequested, now: 0) == [.openWebSocket])
        #expect(m.handle(.connectRequested, now: 0) == [])
        #expect(m.handle(.wsOpened, now: 1) == [])
        #expect(m.mode == .wsOpen)
    }

    @Test func forcedLongPollNeverOpensAWebSocket() {
        var m = RelayClientState(makeSession: { "session-f" }, forceLongPoll: true)
        #expect(m.handle(.connectRequested, now: 0) == [.startLongPoll(session: "session-f", cursor: 0)])
        #expect(m.mode == .polling)
        // No WebSocket probe is ever scheduled, even long after.
        #expect(m.handle(.tick, now: 100_000) == [])
        let sent = m.handle(.send(hello), now: 1)
        #expect(sent == [.sendPoll(session: "session-f", frames: [hello])])
    }

    @Test func presenceAndFramesOverWS() {
        var m = openWS()
        #expect(m.handle(.wsText(#"{"type":"desktop_present","present":true}"#), now: 1) == [.peerConnected])
        #expect(m.handle(.wsText(#"{"type":"desktop_present","present":true}"#), now: 1) == [])
        #expect(m.handle(.wsMessage(json(#"{"type":"frame","from":"d","data":"AQID+g=="}"#)), now: 1) == [.deliverFrame(hello)])
        #expect(m.handle(.wsText("pong"), now: 1) == [])
        #expect(m.handle(.wsText("junk"), now: 1) == [])
        #expect(m.handle(.send(hello), now: 1) == [.sendWS(RelayCodec.encodeFrame(hello))])
        #expect(m.handle(.wsText(#"{"type":"desktop_present","present":false}"#), now: 2) == [.peerDisconnected])
        #expect(m.handle(.wsText(#"{"type":"desktop_present","present":false}"#), now: 2) == [])
    }

    @Test func connectFailureFallsBackToPoll() {
        var m = machine()
        _ = m.handle(.connectRequested, now: 0)
        let a = m.handle(.wsFailed("proxy"), now: 1)
        #expect(a == [.startLongPoll(session: "session-1", cursor: 0), .scheduleRetry(after: 300)])
        #expect(m.mode == .polling)
    }

    @Test func quickDropFallsBackToPollAndDropsPeer() {
        var m = openWS()
        _ = m.handle(.wsText(#"{"type":"desktop_present","present":true}"#), now: 1)
        let a = m.handle(.wsClosed(1006), now: 9.9)
        #expect(a == [.peerDisconnected, .startLongPoll(session: "session-1", cursor: 0), .scheduleRetry(after: 300)])
    }

    @Test func stableDropReconnectsWithBackoff() {
        var m = openWS()
        #expect(m.handle(.wsClosed(1006), now: 10) == [.scheduleRetry(after: 1)])
        #expect(m.handle(.tick, now: 10.5) == [])
        #expect(m.handle(.tick, now: 11) == [.openWebSocket])
        _ = m.handle(.wsOpened, now: 11)
        // A second stable drop starts the schedule over.
        #expect(m.handle(.wsFailed("x"), now: 30) == [.scheduleRetry(after: 1)])
    }

    @Test func backoffSchedule() {
        var b = ReconnectBackoff()
        #expect((0..<7).map { _ in b.nextDelay() } == [1, 2, 4, 8, 30, 30, 30])
        b.reset()
        #expect(b.nextDelay() == 1)
    }

    @Test func pollFailuresBackOff() {
        var m = polling()
        var delays: [Double] = []
        var t = 1.0
        for _ in 0..<6 {
            let a = m.handle(.pollFailed(status: 502), now: t)
            if case .scheduleRetry(let d) = a.first { delays.append(d) }
            t += delays.last!
            #expect(m.handle(.tick, now: t) == [.startLongPoll(session: "session-1", cursor: 0)])
        }
        #expect(delays == [1, 2, 4, 8, 30, 30])
        // A good response resets it.
        _ = m.handle(poll(0, []), now: t)
        #expect(m.handle(.pollFailed(status: nil), now: t) == [.scheduleRetry(after: 1)])
    }

    @Test func deletedCodesStopReconnecting() {
        for code in [4001, 4003] {
            var m = openWS()
            _ = m.handle(.wsText(#"{"type":"desktop_present","present":true}"#), now: 1)
            #expect(m.handle(.wsClosed(code), now: 2) == [.peerDisconnected, .closeAll, .roomDeleted])
            #expect(m.mode == .stopped)
            #expect(m.handle(.tick, now: 1000) == [])
            #expect(m.handle(.connectRequested, now: 1001) == [])
        }
    }

    @Test func deletedWhileConnectingStops() {
        var m = machine()
        _ = m.handle(.connectRequested, now: 0)
        #expect(m.handle(.wsClosed(4003), now: 0).contains(.roomDeleted))
    }

    @Test func otherCloseCodesReconnect() {
        for code in [4002, 4008, 4029, 1008, 1009, 1000] {
            var m = openWS()
            #expect(m.handle(.wsClosed(code), now: 20) == [.scheduleRetry(after: 1)], "code \(code)")
            #expect(m.mode == .retryingWS)
        }
    }

    @Test func longPollDeliversAndAdvancesCursor() {
        var m = polling()
        let a = m.handle(poll(2, [.desktopPresent(true), .frame(from: "d", data: hello)]), now: 1)
        #expect(a == [.peerConnected, .deliverFrame(hello), .startLongPoll(session: "session-1", cursor: 2)])
        #expect(m.cursor == 2)
        #expect(m.handle(.send(hello), now: 2) == [.sendPoll(session: "session-1", frames: [hello])])
        let b = m.handle(poll(2, []), now: 30)
        #expect(b == [.startLongPoll(session: "session-1", cursor: 2)])
    }

    @Test func repeatedPollEventsAreDeduplicated() {
        var m = polling()
        _ = m.handle(poll(2, [.desktopPresent(true), .frame(from: "d", data: hello)]), now: 1)
        // The same response again, and a longer one overlapping it.
        #expect(m.handle(poll(2, [.desktopPresent(true), .frame(from: "d", data: hello)]), now: 2)
            == [.startLongPoll(session: "session-1", cursor: 2)])
        let a = m.handle(poll(3, [.frame(from: "d", data: hello), .frame(from: "d", data: Data([9]))]), now: 3)
        #expect(a == [.deliverFrame(Data([9])), .startLongPoll(session: "session-1", cursor: 3)])
    }

    @Test func pollDesktopAbsentDisconnects() {
        var m = polling()
        _ = m.handle(poll(1, [.desktopPresent(true)]), now: 1)
        let a = m.handle(poll(2, [.desktopPresent(false)]), now: 2)
        #expect(a == [.peerDisconnected, .startLongPoll(session: "session-1", cursor: 2)])
    }

    @Test func gone410StartsNewSession() {
        var m = polling()
        _ = m.handle(poll(5, [.desktopPresent(true)]), now: 1)
        let a = m.handle(.pollFailed(status: 410), now: 100)
        #expect(a == [.peerDisconnected, .startLongPoll(session: "session-2", cursor: 0)])
        #expect(m.cursor == 0)
        #expect(m.session == "session-2")
        // The new session sends with its own id.
        #expect(m.handle(.send(hello), now: 101) == [.sendPoll(session: "session-2", frames: [hello])])
    }

    @Test func pollClosedDeletedStops() {
        var m = polling()
        let a = m.handle(poll(1, [], closed: RelayClose(code: 4003, reason: "deleted")), now: 1)
        #expect(a == [.closeAll, .roomDeleted])
        #expect(m.mode == .stopped)
    }

    @Test func pollClosedOtherStartsNewSessionWithBackoff() {
        var m = polling()
        _ = m.handle(poll(1, [.desktopPresent(true)]), now: 1)
        let a = m.handle(poll(2, [], closed: RelayClose(code: 4008, reason: "overflow")), now: 2)
        #expect(a == [.peerDisconnected, .scheduleRetry(after: 1)])
        #expect(m.handle(.tick, now: 3) == [.startLongPoll(session: "session-2", cursor: 0)])
    }

    @Test func webSocketRetriedEvery300sWhilePolling() {
        var m = polling()
        #expect(m.handle(.tick, now: 299) == [])
        #expect(m.handle(.tick, now: 300) == [.openWebSocket])
        #expect(m.handle(.tick, now: 301) == [])  // probe in flight
        // The probe fails: keep polling, try again in 300 s.
        #expect(m.handle(.wsFailed("x"), now: 302) == [.scheduleRetry(after: 300)])
        #expect(m.mode == .polling)
        #expect(m.handle(.tick, now: 601) == [])
        #expect(m.handle(.tick, now: 602) == [.openWebSocket])
    }

    @Test func probeSuccessSwitchesToWebSocket() {
        var m = polling()
        _ = m.handle(poll(1, [.desktopPresent(true)]), now: 1)
        _ = m.handle(.tick, now: 300)
        let a = m.handle(.wsOpened, now: 301)
        #expect(a == [.cancelLongPoll, .peerDisconnected])
        #expect(m.mode == .wsOpen)
        #expect(m.handle(.wsText(#"{"type":"desktop_present","present":true}"#), now: 301) == [.peerConnected])
    }

    @Test func probeDeletedStops() {
        var m = polling()
        _ = m.handle(.tick, now: 300)
        #expect(m.handle(.wsClosed(4003), now: 300).contains(.roomDeleted))
    }

    @Test func backgroundedClosesAndResumes() {
        var m = openWS()
        _ = m.handle(.wsText(#"{"type":"desktop_present","present":true}"#), now: 1)
        #expect(m.handle(.backgrounded, now: 2) == [.peerDisconnected, .closeAll])
        #expect(m.handle(.backgrounded, now: 2) == [])
        #expect(m.handle(.wsClosed(1000), now: 3) == [])  // late event ignored
        #expect(m.handle(.tick, now: 100) == [])
        #expect(m.handle(.connectRequested, now: 200) == [.openWebSocket])
    }

    @Test func backgroundedWhilePollingCancels() {
        var m = polling()
        #expect(m.handle(.backgrounded, now: 5) == [.closeAll])
        #expect(m.handle(.send(hello), now: 5) == [])
        #expect(m.handle(.tick, now: 400) == [])
    }

    @Test func sendWhileNotConnectedIsDropped() {
        var m = machine()
        #expect(m.handle(.send(hello), now: 0) == [])
        _ = m.handle(.connectRequested, now: 0)
        #expect(m.handle(.send(hello), now: 0) == [])
    }
}
