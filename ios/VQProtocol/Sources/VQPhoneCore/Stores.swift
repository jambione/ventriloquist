import Foundation
import VQProtocol

// Persistence seams. The app supplies Keychain / file / UserDefaults
// implementations; tests and simulators use the in-memory ones below.

/// This install's long-term identity (README §6.1).
public struct StoredIdentity: Sendable {
    /// Random install id (UUID v4), sent as `hello.device_id`.
    public let deviceId: UUID
    /// Long-term X25519 key pair.
    public let keyPair: IdentityKeyPair

    public init(deviceId: UUID, keyPair: IdentityKeyPair) {
        self.deviceId = deviceId
        self.keyPair = keyPair
    }
}

/// Where the identity lives (the app: Keychain, `ThisDeviceOnly`).
public protocol IdentityKeyStore: AnyObject {
    /// The stored identity, `nil` if none was ever saved. Throws if one exists
    /// but cannot be read; callers must then **not** silently create a new one,
    /// because that would break every pairing.
    func loadIdentity() throws -> StoredIdentity?
    func saveIdentity(_ identity: StoredIdentity) throws
}

public enum PhoneIdentity {
    /// Load the identity, or create and save a new one on first run.
    public static func loadOrCreate(from store: IdentityKeyStore) throws -> StoredIdentity {
        if let existing = try store.loadIdentity() { return existing }
        let fresh = StoredIdentity(deviceId: newDeviceId(), keyPair: .generate())
        try store.saveIdentity(fresh)
        return fresh
    }
}

/// A desktop this phone has paired with (README §7.1: known iff `device_id`
/// **and** `pub` match).
public struct PairedHost: Codable, Hashable, Sendable, Identifiable {
    public var deviceId: UUID
    /// Display name from the desktop's `hello` at pairing time.
    public var name: String
    /// The desktop's 32-byte X25519 public key.
    public var publicKey: Data
    public var pairedAt: Date

    public var id: UUID { deviceId }

    public init(deviceId: UUID, name: String, publicKey: Bytes32, pairedAt: Date) {
        self.deviceId = deviceId
        self.name = name
        self.publicKey = Data(publicKey.bytes)
        self.pairedAt = pairedAt
    }

    /// The public key as `Bytes32`; `nil` if the stored value is corrupt.
    public var publicBytes: Bytes32? { Bytes32(publicKey) }
}

/// Persisted list of paired desktops.
public protocol PairedHostStore: AnyObject {
    func loadHosts() throws -> [PairedHost]
    func saveHosts(_ hosts: [PairedHost]) throws
    /// Called once, before the first save that follows an unreadable
    /// ``loadHosts()``: keep the old data somewhere (a renamed copy) so a save
    /// never silently destroys it. Throwing cancels that save. Default: nothing.
    func backUpUnreadableHosts() throws
}

public extension PairedHostStore {
    func backUpUnreadableHosts() throws {}
}

/// A desktop reached through the relay (SPEC_V3 §5). `pinnedPub` is the
/// desktop key from the QR code: its `hello` must carry exactly this key.
/// The room secret lives in a ``RelaySecretStore``, never here.
public struct PairedRelayDesktop: Codable, Hashable, Sendable, Identifiable {
    public var relayURL: String
    public var roomId: String
    public var deviceId: UUID
    public var pinnedPub: Data
    public var name: String

    public var id: UUID { deviceId }

    public init(relayURL: String, roomId: String, deviceId: UUID, pinnedPub: Data, name: String) {
        self.relayURL = relayURL
        self.roomId = roomId
        self.deviceId = deviceId
        self.pinnedPub = pinnedPub
        self.name = name
    }

    public init(_ uri: PairingURI) {
        self.init(relayURL: uri.relayURL.absoluteString, roomId: uri.roomId, deviceId: uri.desktopDeviceId,
                  pinnedPub: Data(uri.desktopPublicKey.bytes), name: uri.name)
    }

    /// The relay connection's peer id.
    public var peer: PeerID { RelayTransport.peerID(roomId: roomId) }
}

/// Persisted list of relay desktops (the app: next to the paired-host file).
public protocol PairedRelayDesktopStore: AnyObject {
    func loadRelayDesktops() throws -> [PairedRelayDesktop]
    func saveRelayDesktops(_ desktops: [PairedRelayDesktop]) throws
}

/// Room secrets by room id (the app: Keychain, `ThisDeviceOnly`).
public protocol RelaySecretStore: AnyObject {
    func get(roomId: String) throws -> String?
    func set(_ secret: String, roomId: String) throws
    func delete(roomId: String) throws
}

/// Small persisted engine settings.
public protocol PhoneSettingsStore: AnyObject {
    /// The desktop last made active (SPEC §5.1: selected again when it connects).
    var lastHostId: UUID? { get set }
}

// MARK: - In-memory implementations

public final class InMemoryIdentityStore: IdentityKeyStore {
    public var identity: StoredIdentity?
    public var failLoad = false
    public init(identity: StoredIdentity? = nil) { self.identity = identity }
    public func loadIdentity() throws -> StoredIdentity? {
        if failLoad { throw StoreError.unreadable }
        return identity
    }
    public func saveIdentity(_ identity: StoredIdentity) throws { self.identity = identity }
}

public final class InMemoryPairedHostStore: PairedHostStore {
    public var hosts: [PairedHost]
    /// Make `saveHosts` throw (tests).
    public var failSaves = false
    /// Make `loadHosts` throw, as for a corrupt file (tests).
    public var failLoads = false
    /// Make `backUpUnreadableHosts` throw (tests).
    public var failBackups = false
    /// How often `backUpUnreadableHosts` ran (tests).
    public private(set) var backups = 0
    public init(hosts: [PairedHost] = []) { self.hosts = hosts }
    public func loadHosts() throws -> [PairedHost] {
        if failLoads { throw StoreError.unreadable }
        return hosts
    }
    public func backUpUnreadableHosts() throws {
        if failBackups { throw StoreError.unwritable }
        backups += 1
    }
    public func saveHosts(_ hosts: [PairedHost]) throws {
        if failSaves { throw StoreError.unwritable }
        self.hosts = hosts
    }
}

public final class InMemoryRelaySecretStore: RelaySecretStore {
    public var secrets: [String: String] = [:]
    public var failSets = false
    public init() {}
    public func get(roomId: String) throws -> String? { secrets[roomId] }
    public func set(_ secret: String, roomId: String) throws {
        if failSets { throw StoreError.unwritable }
        secrets[roomId] = secret
    }
    public func delete(roomId: String) throws { secrets[roomId] = nil }
}

public final class InMemoryPairedRelayDesktopStore: PairedRelayDesktopStore {
    public var desktops: [PairedRelayDesktop]
    public var failSaves = false
    public init(desktops: [PairedRelayDesktop] = []) { self.desktops = desktops }
    public func loadRelayDesktops() throws -> [PairedRelayDesktop] { desktops }
    public func saveRelayDesktops(_ d: [PairedRelayDesktop]) throws {
        if failSaves { throw StoreError.unwritable }
        desktops = d
    }
}

public final class InMemorySettingsStore: PhoneSettingsStore {
    public var lastHostId: UUID?
    public init(lastHostId: UUID? = nil) { self.lastHostId = lastHostId }
}

public enum StoreError: Error, Sendable {
    case unreadable
    case unwritable
}
