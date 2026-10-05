import Foundation
import Testing
import VQPhoneCore
import VQProtocol

/// A fake relay: one desktop per room, peer ids `relay:<room>` as the real
/// transport names them. Doubles as the engine's `RelayRoomControl`.
private final class RelayStubTransport: PhoneTransport, RelayRoomControl {
    weak var engine: PhoneEngine?
    var rooms: [String: String] = [:]
    var removed: [String] = []
    var desktops: [PeerID: FakeDesktop] = [:]
    var toDesktop: [PeerID: [[UInt8]]] = [:]
    var disconnected: [PeerID] = []

    func startRoom(relayURL: URL, roomId: String, secret: String) { rooms[roomId] = secret }
    func stopRoom(roomId: String) { rooms[roomId] = nil; removed.append(roomId) }
    func send(frame: [UInt8], to peer: PeerID) { toDesktop[peer, default: []].append(frame) }
    func disconnect(_ peer: PeerID) {
        disconnected.append(peer)
        for f in toDesktop[peer] ?? [] { desktops[peer]?.receive(frame: f) }  // graceful close
        desktops[peer] = nil
        toDesktop[peer] = nil
    }
    func mtu(for peer: PeerID) -> Int { 8192 }

    func connect(_ d: FakeDesktop, room: String) {
        let peer = RelayTransport.peerID(roomId: room)
        desktops[peer] = d
        engine?.peerConnected(peer)
        d.startConnection(peer: peer)
        pump()
    }

    func pump() {
        var progress = true
        while progress {
            progress = false
            for (peer, d) in desktops {
                if let frames = toDesktop[peer], !frames.isEmpty {
                    toDesktop[peer] = []
                    for f in frames { d.receive(frame: f) }
                    progress = true
                }
                if !d.toPhone.isEmpty {
                    let frames = d.toPhone
                    d.toPhone = []
                    for f in frames where desktops[peer] != nil { engine?.peerReceived(frame: f, from: peer) }
                    progress = true
                }
            }
        }
    }
}

private final class RelayRig {
    let relay = RelayStubTransport()
    let hostStore = InMemoryPairedHostStore()
    let relayStore = InMemoryPairedRelayDesktopStore()
    let secrets = InMemoryRelaySecretStore()
    let settings = InMemorySettingsStore()
    let identity = StoredIdentity(deviceId: UUID(), keyPair: .generate())
    let clock = ManualClock()
    var events: [PhoneEvent] = []
    let room = "room-0123456789abcdef"
    lazy var engine: PhoneEngine = makeEngine()

    func makeEngine() -> PhoneEngine {
        let e = PhoneEngine(identity: identity, deviceName: "Test iPhone", hostStore: hostStore, settings: settings,
                            transport: relay, clock: clock, relayStore: relayStore, relaySecrets: secrets,
                            relayRooms: relay)
        relay.engine = e
        e.onEvent = { [unowned self] in events.append($0) }
        return e
    }

    func uri(for d: FakeDesktop, pub: Bytes32? = nil) -> PairingURI {
        PairingURI(relayURL: URL(string: "https://relay.example")!, roomId: room, roomSecret: "secret-0123456789abcdef",
                   desktopDeviceId: d.deviceId, desktopPublicKey: pub ?? d.identity.publicBytes,
                   code: "123456", name: d.name)
    }

    var notices: [PhoneNotice] { events.compactMap { if case .notice(let n) = $0 { n } else { nil } } }
}

@Suite("relay pairing by QR (SPEC_V3 §5)")
struct RelayPairingTests {
    @Test func autoPairsWithTheQRCode() {
        let r = RelayRig()
        let d = FakeDesktop(name: "Mac", clock: r.clock)
        d.fixedCode = "123456"
        r.engine.pair(using: r.uri(for: d))
        #expect(r.relay.rooms[r.room] == "secret-0123456789abcdef")
        #expect(r.relayStore.desktops.count == 1)
        #expect(r.secrets.secrets[r.room] == "secret-0123456789abcdef")
        r.relay.connect(d, room: r.room)
        #expect(d.isSecure)
        #expect(r.hostStore.hosts.map(\.deviceId) == [d.deviceId])
        #expect(r.engine.indicator == .secure)
        #expect(r.events.contains(.paired(hostId: d.deviceId, name: "Mac")))
    }

    @Test func pinMismatchStoresNothing() {
        let r = RelayRig()
        let d = FakeDesktop(name: "Mac", clock: r.clock)
        r.engine.pair(using: r.uri(for: d, pub: IdentityKeyPair.generate().publicBytes))
        r.relay.connect(d, room: r.room)
        #expect(r.notices == [.pairingCodeMismatch])
        #expect(PhoneNotice.pairingCodeMismatch.text == "This QR code doesn't match the desktop")
        #expect(!d.isSecure)
        #expect(d.errorsReceived.first?.code == ErrorMsg.protocolViolation)
        #expect(d.pairRequests == 0)
        #expect(r.relay.disconnected.count == 1)
        #expect(r.hostStore.hosts.isEmpty)
        #expect(r.relayStore.desktops.isEmpty)
        #expect(r.secrets.secrets.isEmpty)
        #expect(r.relay.removed == [r.room])
    }

    @Test func forgetRemovesRecordSecretAndRoom() {
        let r = RelayRig()
        let d = FakeDesktop(name: "Mac", clock: r.clock)
        d.fixedCode = "123456"
        r.engine.pair(using: r.uri(for: d))
        r.relay.connect(d, room: r.room)
        r.engine.forgetHost(d.deviceId)
        #expect(r.hostStore.hosts.isEmpty)
        #expect(r.relayStore.desktops.isEmpty)
        #expect(r.secrets.secrets.isEmpty)
        #expect(r.relay.rooms.isEmpty)
        #expect(r.relay.removed == [r.room])
    }

    @Test func reloadsRoomsOnStart() {
        let r = RelayRig()
        let d = FakeDesktop(name: "Mac", clock: r.clock)
        let u = r.uri(for: d)
        r.relayStore.desktops = [PairedRelayDesktop(u)]
        try? r.secrets.set(u.roomSecret, roomId: u.roomId)
        // A record without a secret is skipped.
        r.relayStore.desktops.append(PairedRelayDesktop(relayURL: "https://relay.example", roomId: "other-room-0123456789",
                                                        deviceId: UUID(), pinnedPub: Data(count: 32), name: "X"))
        _ = r.engine
        #expect(r.relay.rooms == [r.room: u.roomSecret])
    }
}
