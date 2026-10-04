@preconcurrency import CoreBluetooth
import Foundation
import VQPhoneCore
import VQProtocol

/// The phone as GATT peripheral (SPEC §3.1, README §2).
///
/// * One service with `RX` (write with response, desktop → phone) and `TX`
///   (notify, phone → desktop). Each write / notification is one frame.
/// * A desktop "connects" when it subscribes to `TX` and "disconnects" when it
///   unsubscribes. Each subscription gets a fresh ``PeerID``.
/// * Frames go to one central only (`updateValue(_:for:onSubscribedCentrals:)`).
///   When the stack's queue is full (`updateValue` returns `false`), frames
///   wait in a FIFO until `peripheralManagerIsReady(toUpdateSubscribers:)`.
/// * Advertising runs in the foreground only. Going to the background removes
///   the service (so desktops notice and later reconnect) and stops
///   advertising; returning to the foreground restores both.
///
/// All CoreBluetooth callbacks arrive on the main queue (`queue: nil`).
@MainActor
final class BLEPeripheralTransport: NSObject {
    enum RadioState: Equatable {
        case unknown, poweredOff, unauthorized, unsupported, ready
    }

    /// Engine to deliver events to (set by the app model).
    weak var engine: PhoneEngine?
    /// Called when the radio state changes.
    var onStateChange: ((RadioState) -> Void)?
    private(set) var radioState: RadioState = .unknown

    private var manager: CBPeripheralManager?
    private var txCharacteristic: CBMutableCharacteristic?
    private var serviceAdded = false
    private var wantsForeground = true

    private struct Link {
        let peer: PeerID
        let central: CBCentral
        /// `false` after the engine closed it; writes are then ignored until
        /// the central subscribes again.
        var open: Bool
    }

    private var links: [UUID: Link] = [:]
    private var peerToCentral: [PeerID: UUID] = [:]
    private var counter = 0

    /// Frames waiting for `peripheralManagerIsReady`.
    private var sendQueue: [(peer: PeerID, frame: Data)] = []
    /// Per-link cap on queued frames (≈ 2 MiB at 185-byte frames).
    private let maxQueuedPerPeer = 12_000

    private let serviceUUID = CBUUID(nsuuid: VQ.serviceUUID)
    private let rxUUID = CBUUID(nsuuid: VQ.rxCharacteristicUUID)
    private let txUUID = CBUUID(nsuuid: VQ.txCharacteristicUUID)

    /// Create the peripheral manager. This triggers the Bluetooth permission
    /// prompt on first use.
    func start() {
        guard manager == nil else { return }
        manager = CBPeripheralManager(delegate: self, queue: nil,
                                      options: [CBPeripheralManagerOptionShowPowerAlertKey: true])
    }

    /// Scene went to the background: stop advertising and drop the service.
    func enterBackground() {
        wantsForeground = false
        guard let manager else { return }
        manager.stopAdvertising()
        if serviceAdded {
            manager.removeAllServices()
            serviceAdded = false
        }
        closeAllLinks()
    }

    /// Scene is active again: restore the service and advertising.
    func enterForeground() {
        wantsForeground = true
        setUpIfReady()
    }

    private func setUpIfReady() {
        guard let manager, manager.state == .poweredOn, wantsForeground else { return }
        if !serviceAdded {
            let rx = CBMutableCharacteristic(type: rxUUID, properties: [.write],
                                             value: nil, permissions: [.writeable])
            let tx = CBMutableCharacteristic(type: txUUID, properties: [.notify],
                                             value: nil, permissions: [.readable])
            let service = CBMutableService(type: serviceUUID, primary: true)
            service.characteristics = [rx, tx]
            txCharacteristic = tx
            manager.add(service)
            serviceAdded = true
            // Advertising starts in `didAdd`.
        } else if !manager.isAdvertising {
            advertise()
        }
    }

    private func advertise() {
        guard let manager, wantsForeground, !manager.isAdvertising else { return }
        manager.startAdvertising([
            CBAdvertisementDataServiceUUIDsKey: [serviceUUID],
            CBAdvertisementDataLocalNameKey: "Ventriloquist",
        ])
    }

    private func closeAllLinks() {
        let peers = links.values.filter(\.open).map(\.peer)
        links.removeAll()
        peerToCentral.removeAll()
        sendQueue.removeAll()
        for p in peers { engine?.peerDisconnected(p) }
    }

    private func openLink(for central: CBCentral) -> PeerID {
        counter += 1
        let peer = PeerID("ble:\(central.identifier.uuidString.prefix(8))#\(counter)")
        if let old = links[central.identifier] {
            peerToCentral[old.peer] = nil
            if old.open { engine?.peerDisconnected(old.peer) }
        }
        links[central.identifier] = Link(peer: peer, central: central, open: true)
        peerToCentral[peer] = central.identifier
        engine?.peerConnected(peer)
        return peer
    }

    private func drainQueue() {
        guard let manager, let tx = txCharacteristic else { return }
        while let next = sendQueue.first {
            guard let id = peerToCentral[next.peer], let link = links[id], link.open else {
                sendQueue.removeFirst()
                continue
            }
            if manager.updateValue(next.frame, for: tx, onSubscribedCentrals: [link.central]) {
                sendQueue.removeFirst()
            } else {
                return  // wait for peripheralManagerIsReady
            }
        }
    }
}

extension BLEPeripheralTransport: @preconcurrency PhoneTransport {
    func send(frame: [UInt8], to peer: PeerID) {
        guard let id = peerToCentral[peer], links[id]?.open == true else { return }
        let queued = sendQueue.reduce(0) { $0 + ($1.peer == peer ? 1 : 0) }
        guard queued < maxQueuedPerPeer else {
            // The desktop is not draining notifications; give up on it.
            // Report it after the engine's current call returns (no re-entry).
            disconnect(peer)
            Task { @MainActor [weak self] in self?.engine?.peerDisconnected(peer) }
            return
        }
        sendQueue.append((peer, Data(frame)))
        if sendQueue.count == 1 { drainQueue() }
    }

    /// A peripheral cannot drop a central. The link is marked closed: its
    /// frames are discarded and its writes ignored until it subscribes again
    /// (the desktop disconnects after our `error`, or on keepalive timeout).
    func disconnect(_ peer: PeerID) {
        guard let id = peerToCentral[peer] else { return }
        links[id]?.open = false
        sendQueue.removeAll { $0.peer == peer }
    }

    func mtu(for peer: PeerID) -> Int {
        guard let id = peerToCentral[peer], let link = links[id] else { return VQ.minMTU }
        return max(VQ.minMTU, link.central.maximumUpdateValueLength)
    }
}

extension BLEPeripheralTransport: @preconcurrency CBPeripheralManagerDelegate {
    func peripheralManagerDidUpdateState(_ peripheral: CBPeripheralManager) {
        let state: RadioState = switch peripheral.state {
        case .poweredOn: .ready
        case .poweredOff: .poweredOff
        case .unauthorized: .unauthorized
        case .unsupported: .unsupported
        default: .unknown
        }
        radioState = state
        if state == .ready {
            setUpIfReady()
        } else {
            serviceAdded = false
            closeAllLinks()
        }
        onStateChange?(state)
    }

    func peripheralManager(_ peripheral: CBPeripheralManager, didAdd service: CBService, error: (any Error)?) {
        if error != nil {
            serviceAdded = false
            return
        }
        advertise()
    }

    func peripheralManager(_ peripheral: CBPeripheralManager, central: CBCentral,
                           didSubscribeTo characteristic: CBCharacteristic) {
        guard characteristic.uuid == txUUID else { return }
        _ = openLink(for: central)
    }

    func peripheralManager(_ peripheral: CBPeripheralManager, central: CBCentral,
                           didUnsubscribeFrom characteristic: CBCharacteristic) {
        guard characteristic.uuid == txUUID, let link = links.removeValue(forKey: central.identifier) else { return }
        peerToCentral[link.peer] = nil
        sendQueue.removeAll { $0.peer == link.peer }
        if link.open { engine?.peerDisconnected(link.peer) }
    }

    func peripheralManager(_ peripheral: CBPeripheralManager, didReceiveWrite requests: [CBATTRequest]) {
        guard let first = requests.first else { return }
        // Validate the whole batch before acting on any of it.
        for r in requests where r.characteristic.uuid != rxUUID {
            peripheral.respond(to: first, withResult: .requestNotSupported)
            return
        }
        for r in requests where r.offset != 0 {
            peripheral.respond(to: first, withResult: .invalidOffset)
            return
        }
        peripheral.respond(to: first, withResult: .success)
        for r in requests {
            let central = r.central
            let peer: PeerID
            if let link = links[central.identifier] {
                guard link.open else { continue }
                peer = link.peer
            } else {
                // A write before the subscription: treat it as the connect.
                peer = openLink(for: central)
            }
            engine?.peerReceived(frame: [UInt8](r.value ?? Data()), from: peer)
        }
    }

    func peripheralManager(_ peripheral: CBPeripheralManager, didReceiveRead request: CBATTRequest) {
        peripheral.respond(to: request, withResult: .readNotPermitted)
    }

    func peripheralManagerIsReady(toUpdateSubscribers peripheral: CBPeripheralManager) {
        drainQueue()
    }
}
