@preconcurrency import CoreBluetooth
import Foundation
import VQPhoneCore
import VQProtocol

/// The phone as GATT central, for Windows hosts (SPEC_V2 v2.3).
///
/// The PC hosts `hostServiceUUID` with `H_RX` (phone writes, with response) and
/// `H_TX` (PC notifies). The phone scans, connects to every desktop it sees,
/// discovers the service and subscribes to `H_TX`. A peer is *connected* once
/// the subscription is confirmed, then gets a fresh ``PeerID`` (prefix `gc:`,
/// so it can never collide with the peripheral transport's `ble:` ids).
///
/// * Writes are serialized per peer (``SerialWriteQueue``); on queue overflow
///   or a write error the link is dropped.
/// * A lost link is retried with ``ReconnectBackoff`` (1, 2, 4, 8, 15 s).
/// * Foreground only: the background stops the scan and cancels connections.
///
/// All CoreBluetooth callbacks arrive on the main queue (`queue: nil`).
@MainActor
final class BLECentralTransport: NSObject {
    static let peerPrefix = "gc:"

    weak var engine: PhoneEngine?

    private var manager: CBCentralManager?
    private var wantsForeground = true
    private var counter = 0

    private final class Link {
        let peripheral: CBPeripheral
        var rx: CBCharacteristic?
        var tx: CBCharacteristic?
        /// Set once the `H_TX` subscription is confirmed.
        var peer: PeerID?
        var queue = SerialWriteQueue()
        var backoff = ReconnectBackoff()
        var reconnectTask: Task<Void, Never>?
        /// A connect is in progress or established.
        var active = false
        /// The engine (not the radio) ended the last connection.
        var engineClosed = false
        init(_ p: CBPeripheral) { peripheral = p }
    }

    private var links: [UUID: Link] = [:]
    private var peerToLink: [PeerID: UUID] = [:]

    private let serviceUUID = CBUUID(nsuuid: VQ.hostServiceUUID)
    private let rxUUID = CBUUID(nsuuid: VQ.hostRxUUID)
    private let txUUID = CBUUID(nsuuid: VQ.hostTxUUID)

    /// Frames not yet written. The app waits for this before backgrounding.
    var hasQueuedFrames: Bool { links.values.contains { !$0.queue.isIdle } }

    func start() {
        guard manager == nil else { return }
        manager = CBCentralManager(delegate: self, queue: nil,
                                   options: [CBCentralManagerOptionShowPowerAlertKey: true])
    }

    func enterBackground() {
        wantsForeground = false
        manager?.stopScan()
        for (_, link) in links {
            link.reconnectTask?.cancel()
            link.reconnectTask = nil
            teardown(link, cancel: true)
        }
    }

    func enterForeground() {
        wantsForeground = true
        guard manager?.state == .poweredOn else { return }
        for (_, link) in links where !link.active && link.reconnectTask == nil {
            link.backoff.reset()
            connect(link)
        }
        scan()
    }

    private func scan() {
        guard let manager, manager.state == .poweredOn, wantsForeground else { return }
        manager.scanForPeripherals(withServices: [serviceUUID], options: nil)
    }

    private func connect(_ link: Link) {
        guard let manager, manager.state == .poweredOn, wantsForeground, !link.active else { return }
        link.active = true
        manager.connect(link.peripheral, options: nil)
    }

    /// Forget the connection state; report the peer to the engine if it was connected.
    private func teardown(_ link: Link, cancel: Bool) {
        link.active = false
        link.rx = nil
        link.tx = nil
        link.queue.reset()
        let peer = link.peer
        link.peer = nil
        if let peer {
            peerToLink[peer] = nil
            engine?.peerDisconnected(peer)
        }
        if cancel, link.peripheral.state != .disconnected {
            manager?.cancelPeripheralConnection(link.peripheral)
        }
    }

    private func scheduleReconnect(_ link: Link) {
        guard wantsForeground, link.reconnectTask == nil else { return }
        let delay = link.backoff.nextDelay()
        link.reconnectTask = Task { @MainActor [weak self, weak link] in
            try? await Task.sleep(for: .seconds(delay))
            guard !Task.isCancelled, let self, let link else { return }
            link.reconnectTask = nil
            connect(link)
        }
    }

    /// The connection ended (radio or us): clean up and retry with backoff.
    private func connectionEnded(_ link: Link) {
        teardown(link, cancel: true)
        scheduleReconnect(link)
    }

    private func drop(_ link: Link) {
        // Report after the engine's current call returns (no re-entry): the
        // disconnect callback does the teardown.
        manager?.cancelPeripheralConnection(link.peripheral)
    }

    private func write(_ frame: [UInt8], on link: Link) {
        guard let rx = link.rx else { return }
        link.peripheral.writeValue(Data(frame), for: rx, type: .withResponse)
    }
}

extension BLECentralTransport: @preconcurrency PhoneTransport {
    func send(frame: [UInt8], to peer: PeerID) {
        guard let id = peerToLink[peer], let link = links[id] else { return }
        switch link.queue.enqueue(frame) {
        case .sendNow(let f): write(f, on: link)
        case .queued: break
        case .overflow: drop(link)
        }
    }

    /// The engine closed the connection: cancel it, and reconnect with backoff
    /// (without resetting the backoff, so a desktop the engine keeps rejecting
    /// is not retried every second).
    func disconnect(_ peer: PeerID) {
        guard let id = peerToLink[peer], let link = links[id] else { return }
        link.engineClosed = true
        peerToLink[peer] = nil
        link.peer = nil
        link.queue.reset()
        manager?.cancelPeripheralConnection(link.peripheral)
    }

    func mtu(for peer: PeerID) -> Int {
        guard let id = peerToLink[peer], let link = links[id] else { return VQ.minMTU }
        let n = link.peripheral.maximumWriteValueLength(for: .withResponse)
        return max(VQ.minMTU, min(512, n))
    }
}

extension BLECentralTransport: @preconcurrency CBCentralManagerDelegate {
    func centralManagerDidUpdateState(_ central: CBCentralManager) {
        if central.state == .poweredOn {
            for (_, link) in links where !link.active && link.reconnectTask == nil { connect(link) }
            scan()
        } else {
            central.stopScan()
            for (_, link) in links {
                link.reconnectTask?.cancel()
                link.reconnectTask = nil
                teardown(link, cancel: false)
            }
        }
    }

    func centralManager(_ central: CBCentralManager, didDiscover peripheral: CBPeripheral,
                        advertisementData: [String: Any], rssi RSSI: NSNumber) {
        if let link = links[peripheral.identifier] {
            // Known: reconnect handles it unless nothing is pending.
            if !link.active, link.reconnectTask == nil { connect(link) }
            return
        }
        let link = Link(peripheral)
        peripheral.delegate = self
        links[peripheral.identifier] = link
        connect(link)
    }

    func centralManager(_ central: CBCentralManager, didConnect peripheral: CBPeripheral) {
        guard links[peripheral.identifier] != nil else { return }
        peripheral.discoverServices([serviceUUID])
    }

    func centralManager(_ central: CBCentralManager, didFailToConnect peripheral: CBPeripheral, error: (any Error)?) {
        guard let link = links[peripheral.identifier] else { return }
        connectionEnded(link)
    }

    func centralManager(_ central: CBCentralManager, didDisconnectPeripheral peripheral: CBPeripheral,
                        error: (any Error)?) {
        guard let link = links[peripheral.identifier] else { return }
        connectionEnded(link)
    }
}

extension BLECentralTransport: @preconcurrency CBPeripheralDelegate {
    func peripheral(_ peripheral: CBPeripheral, didDiscoverServices error: (any Error)?) {
        guard let link = links[peripheral.identifier] else { return }
        guard error == nil, let service = peripheral.services?.first(where: { $0.uuid == serviceUUID }) else {
            drop(link)
            return
        }
        peripheral.discoverCharacteristics([rxUUID, txUUID], for: service)
    }

    func peripheral(_ peripheral: CBPeripheral, didDiscoverCharacteristicsFor service: CBService,
                    error: (any Error)?) {
        guard let link = links[peripheral.identifier] else { return }
        link.rx = service.characteristics?.first { $0.uuid == rxUUID }
        link.tx = service.characteristics?.first { $0.uuid == txUUID }
        guard error == nil, link.rx != nil, let tx = link.tx else {
            drop(link)
            return
        }
        peripheral.setNotifyValue(true, for: tx)
    }

    func peripheral(_ peripheral: CBPeripheral, didUpdateNotificationStateFor characteristic: CBCharacteristic,
                    error: (any Error)?) {
        guard let link = links[peripheral.identifier], characteristic.uuid == txUUID else { return }
        guard error == nil, characteristic.isNotifying else {
            if link.peer != nil || error != nil { drop(link) }
            return
        }
        guard link.peer == nil else { return }
        counter += 1
        let peer = PeerID("\(Self.peerPrefix)\(peripheral.identifier.uuidString.prefix(8))#\(counter)")
        link.peer = peer
        peerToLink[peer] = peripheral.identifier
        if link.engineClosed {
            link.engineClosed = false
        } else {
            link.backoff.reset()
        }
        engine?.peerConnected(peer)
    }

    func peripheral(_ peripheral: CBPeripheral, didUpdateValueFor characteristic: CBCharacteristic,
                    error: (any Error)?) {
        guard error == nil, characteristic.uuid == txUUID,
              let link = links[peripheral.identifier], let peer = link.peer,
              let value = characteristic.value else { return }
        engine?.peerReceived(frame: [UInt8](value), from: peer)
    }

    func peripheral(_ peripheral: CBPeripheral, didWriteValueFor characteristic: CBCharacteristic,
                    error: (any Error)?) {
        guard let link = links[peripheral.identifier], link.peer != nil else { return }
        if error != nil {
            drop(link)
            return
        }
        if let next = link.queue.writeCompleted() { write(next, on: link) }
    }
}
