import Foundation
import Testing
import VQPhoneCore

// A fake relay network: sockets and long-polls the test drives by hand.

@MainActor final class FakeSocket: RelayWebSocket {
    let url: URL
    let headers: [String: String]
    let onEvent: @MainActor (RelayWebSocketEvent) -> Void
    var sent: [String] = []
    var closed = false
    init(url: URL, headers: [String: String], onEvent: @escaping @MainActor (RelayWebSocketEvent) -> Void) {
        self.url = url; self.headers = headers; self.onEvent = onEvent
    }
    func send(text: String) { sent.append(text) }
    func close() { closed = true }
    func emit(_ e: RelayWebSocketEvent) { onEvent(e) }
    func desktop(_ present: Bool) { emit(.text("{\"type\":\"desktop_present\",\"present\":\(present)}")) }
}

@MainActor final class FakeNet: RelayNetworking {
    struct Poll { let id: Int; let url: URL; let headers: [String: String]; let cont: CheckedContinuation<(status: Int, data: Data), Error> }
    var sockets: [FakeSocket] = []
    var polls: [Poll] = []
    var sends: [(url: URL, body: Data)] = []
    private var nextId = 0

    func openWebSocket(url: URL, headers: [String: String],
                       onEvent: @escaping @MainActor (RelayWebSocketEvent) -> Void) -> RelayWebSocket {
        let s = FakeSocket(url: url, headers: headers, onEvent: onEvent)
        sockets.append(s)
        return s
    }

    func longPollSend(url: URL, headers: [String: String], body: Data) async throws -> (status: Int, data: Data) {
        sends.append((url, body))
        return (200, Data())
    }

    func longPollReceive(url: URL, headers: [String: String]) async throws -> (status: Int, data: Data) {
        nextId += 1
        let id = nextId
        return try await withTaskCancellationHandler {
            try await withCheckedThrowingContinuation { c in
                polls.append(Poll(id: id, url: url, headers: headers, cont: c))
            }
        } onCancel: {
            Task { @MainActor in
                if let i = self.polls.firstIndex(where: { $0.id == id }) {
                    self.polls.remove(at: i).cont.resume(throwing: CancellationError())
                }
            }
        }
    }

    func reply(status: Int = 200, _ json: String) {
        polls.removeLast().cont.resume(returning: (status, Data(json.utf8)))
    }
}

@MainActor final class ManualScheduler: RelayScheduler {
    var pending: [(due: Double, block: @MainActor () -> Void)] = []
    let clock: ManualClock
    init(clock: ManualClock) { self.clock = clock }
    func schedule(after seconds: Double, _ block: @escaping @MainActor () -> Void) {
        pending.append((clock.now + seconds, block))
    }
    func advance(_ seconds: Double) {
        clock.advance(seconds)
        let due = pending.filter { $0.due <= clock.now }
        pending.removeAll { $0.due <= clock.now }
        for d in due { d.block() }
    }
}

final class Recorder: RelayPeerEvents {
    var log: [String] = []
    func peerConnected(_ peer: PeerID) { log.append("up \(peer)") }
    func peerReceived(frame: [UInt8], from peer: PeerID) { log.append("frame \(peer) \(frame)") }
    func peerDisconnected(_ peer: PeerID) { log.append("down \(peer)") }
}

@MainActor struct Rig {
    let net = FakeNet()
    let clock = ManualClock()
    let sched: ManualScheduler
    let t: RelayPhoneTransport
    let rec = Recorder()
    var stopped: [String] { stoppedBox.v }
    let stoppedBox = Box()
    final class Box { var v: [String] = [] }
    static let url = URL(string: "https://relay.test")!

    init() {
        sched = ManualScheduler(clock: clock)
        t = RelayPhoneTransport(networking: net, clock: clock, scheduler: sched)
        t.events = rec
        let box = stoppedBox
        t.onRoomStopped = { box.v.append($0) }
    }

    func settle() async { for _ in 0..<30 { await Task.yield() } }
}

@Suite("RelayPhoneTransport") @MainActor
struct RelayPhoneTransportTests {
    static let pollUp = "{\"conn_id\":\"c\",\"cursor\":1,\"events\":[{\"type\":\"desktop_present\",\"present\":true}]}"

    @Test func webSocketHappyPath() {
        let r = Rig()
        r.t.addRoom(relayURL: Rig.url, roomId: "room1", secret: "sek")
        let s = r.net.sockets[0]
        #expect(s.url.absoluteString == "wss://relay.test/v1/rooms/room1/ws?role=phone")
        #expect(s.headers["Authorization"] == "Bearer sek")
        s.emit(.opened)
        s.desktop(true)
        #expect(r.rec.log == ["up relay:room1"])
        r.t.send(frame: [1, 2, 3], to: PeerID("relay:room1"))
        #expect(s.sent == [RelayCodec.encodeFrame(Data([1, 2, 3]))])
        s.emit(.text("{\"type\":\"frame\",\"from\":\"x\",\"data\":\"BAUG\"}"))
        #expect(r.rec.log.last == "frame relay:room1 [4, 5, 6]")
        #expect(r.t.mtu(for: PeerID("relay:room1")) == 8192)
        s.desktop(false)
        #expect(r.rec.log.last == "down relay:room1")
    }

    @Test func fallsBackToLongPollAfterEarlyWebSocketFailure() async {
        let r = Rig()
        r.t.addRoom(relayURL: Rig.url, roomId: "room1", secret: "sek")
        r.net.sockets[0].emit(.failed("refused"))
        await r.settle()
        #expect(r.t.mode(ofRoom: "room1") == .polling)
        let p = r.net.polls[0]
        #expect(p.url.path == "/v1/rooms/room1/poll")
        #expect(p.url.query?.contains("role=phone") == true)
        #expect(p.url.query?.contains("cursor=0") == true)
        #expect(p.headers["Authorization"] == "Bearer sek")
        r.net.reply(Self.pollUp)
        await r.settle()
        #expect(r.rec.log == ["up relay:room1"])
        #expect(r.net.polls.last?.url.query?.contains("cursor=1") == true)
        r.t.send(frame: [9], to: PeerID("relay:room1"))
        await r.settle()
        #expect(r.net.sends.count == 1)
        #expect(r.net.sends[0].url.path == "/v1/rooms/room1/send")
        #expect(String(decoding: r.net.sends[0].body, as: UTF8.self) == String(decoding: RelayCodec.encodeSend([Data([9])]), as: UTF8.self))
    }

    @Test func poll410StartsNewSession() async {
        let r = Rig()
        r.t.addRoom(relayURL: Rig.url, roomId: "room1", secret: "sek")
        r.net.sockets[0].emit(.failed("x"))
        await r.settle()
        let first = r.net.polls[0].url.query ?? ""
        r.net.reply(Self.pollUp)
        await r.settle()
        r.net.reply(status: 410, "{\"error\":\"session_expired\"}")
        await r.settle()
        #expect(r.rec.log == ["up relay:room1", "down relay:room1"])
        let q = r.net.polls.last?.url.query ?? ""
        #expect(q.contains("cursor=0"))
        #expect(q != first)
    }

    @Test func close4003StopsTheRoom() async {
        let r = Rig()
        r.t.addRoom(relayURL: Rig.url, roomId: "room1", secret: "sek")
        let s = r.net.sockets[0]
        s.emit(.opened)
        s.desktop(true)
        s.emit(.closed(code: 4003))
        await r.settle()
        #expect(r.stopped == ["room1"])
        #expect(r.t.mode(ofRoom: "room1") == .stopped)
        #expect(r.rec.log == ["up relay:room1", "down relay:room1"])
        r.t.send(frame: [1], to: PeerID("relay:room1"))
        r.sched.advance(60)
        #expect(r.net.sockets.count == 1)
        #expect(r.net.polls.isEmpty)
    }

    @Test func stableWebSocketReconnectsAfterBackoff() {
        let r = Rig()
        r.t.addRoom(relayURL: Rig.url, roomId: "room1", secret: "sek")
        let s = r.net.sockets[0]
        s.emit(.opened)
        r.clock.advance(30)
        s.emit(.closed(code: 1006))
        #expect(r.t.mode(ofRoom: "room1") == .retryingWS)
        r.sched.advance(1)
        #expect(r.net.sockets.count == 2)
    }

    @Test func pauseAndResume() {
        let r = Rig()
        r.t.addRoom(relayURL: Rig.url, roomId: "room1", secret: "sek")
        let s = r.net.sockets[0]
        s.emit(.opened)
        s.desktop(true)
        r.t.pauseAll()
        #expect(s.closed)
        #expect(r.rec.log == ["up relay:room1", "down relay:room1"])
        #expect(r.t.mode(ofRoom: "room1") == .backgrounded)
        s.desktop(true) // a late event from the old socket is ignored
        #expect(r.rec.log.count == 2)
        r.t.resumeAll()
        #expect(r.net.sockets.count == 2)
        r.net.sockets[1].emit(.opened)
        r.net.sockets[1].desktop(true)
        #expect(r.rec.log.last == "up relay:room1")
    }

    @Test func twoRoomsAreIndependent() {
        let r = Rig()
        r.t.addRoom(relayURL: Rig.url, roomId: "roomA", secret: "a")
        r.t.addRoom(relayURL: Rig.url, roomId: "roomB", secret: "b")
        let a = r.net.sockets[0], b = r.net.sockets[1]
        #expect(b.headers["Authorization"] == "Bearer b")
        a.emit(.opened); b.emit(.opened)
        b.desktop(true)
        #expect(r.rec.log == ["up relay:roomB"])
        r.t.send(frame: [7], to: PeerID("relay:roomB"))
        #expect(a.sent.isEmpty)
        #expect(b.sent.count == 1)
        a.desktop(true)
        a.emit(.text("{\"type\":\"frame\",\"data\":\"AQ==\"}"))
        #expect(r.rec.log.last == "frame relay:roomA [1]")
        r.t.removeRoom(roomId: "roomB")
        #expect(b.closed)
        #expect(!a.closed)
        #expect(!r.t.hasRoom("roomB"))
        r.t.send(frame: [7], to: PeerID("relay:roomB"))
        #expect(b.sent.count == 1)
    }
}
