import Foundation
import VQProtocol

/// Base64url without padding (RFC 4648 §5), as the QR payload uses for `k`.
public enum Base64URL {
    public static func decode(_ s: String) -> Data? {
        var t = s.replacingOccurrences(of: "-", with: "+").replacingOccurrences(of: "_", with: "/")
        switch t.count % 4 {
        case 0: break
        case 2: t += "=="
        case 3: t += "="
        default: return nil
        }
        return Data(base64Encoded: t)
    }

    public static func encode(_ d: some Sequence<UInt8>) -> String {
        Data(d).base64EncodedString()
            .replacingOccurrences(of: "+", with: "-").replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }
}

public enum PairingURIError: Error, Equatable, Sendable {
    case notAPairingLink
    case unsupportedVersion
    case missing(String)
    case invalid(String)

    public var text: String {
        switch self {
        case .notAPairingLink: "This is not a Ventriloquist pairing code."
        case .unsupportedVersion: "This pairing code needs a newer Ventriloquist."
        case .missing, .invalid: "This pairing code is damaged. Show a new one on the desktop."
        }
    }
}

/// The QR payload of SPEC_V3 §5:
/// `vq://pair?v=3&r=<relay url>&room=<room_id>&s=<room_secret>&d=<device_id>&k=<pub b64url>&c=<code>&n=<name>`.
public struct PairingURI: Equatable, Sendable {
    public var relayURL: URL
    public var roomId: String
    public var roomSecret: String
    public var desktopDeviceId: UUID
    public var desktopPublicKey: Bytes32
    public var code: String
    public var name: String

    public init(relayURL: URL, roomId: String, roomSecret: String, desktopDeviceId: UUID,
                desktopPublicKey: Bytes32, code: String, name: String) {
        self.relayURL = relayURL
        self.roomId = roomId
        self.roomSecret = roomSecret
        self.desktopDeviceId = desktopDeviceId
        self.desktopPublicKey = desktopPublicKey
        self.code = code
        self.name = name
    }

    /// `http://` relays are accepted only on loopback (development): the room
    /// secret would otherwise travel in clear text.
    static func isLoopbackHost(_ host: String) -> Bool {
        let h = host.lowercased().trimmingCharacters(in: CharacterSet(charactersIn: "[]"))
        if h == "localhost" || h == "::1" { return true }
        let parts = h.split(separator: ".", omittingEmptySubsequences: false)
        return parts.count == 4 && parts[0] == "127" && parts.allSatisfy { UInt8($0) != nil }
    }

    static func isIdChars(_ s: String) -> Bool {
        s.utf8.allSatisfy { ($0 >= 0x30 && $0 <= 0x39) || ($0 >= 0x41 && $0 <= 0x5A) || ($0 >= 0x61 && $0 <= 0x7A) || $0 == 0x2D || $0 == 0x5F }
    }

    public static func parse(_ string: String) throws(PairingURIError) -> PairingURI {
        let trimmed = string.trimmingCharacters(in: .whitespacesAndNewlines)
        guard let c = URLComponents(string: trimmed), c.scheme?.lowercased() == "vq", c.host?.lowercased() == "pair"
        else { throw .notAPairingLink }
        var q: [String: String] = [:]
        for item in c.queryItems ?? [] {
            guard q[item.name] == nil else { throw .invalid("duplicate \(item.name)") }
            q[item.name] = item.value ?? ""
        }
        func need(_ k: String) throws(PairingURIError) -> String {
            guard let v = q[k], !v.isEmpty else { throw .missing(k) }
            return v
        }
        guard try need("v") == "3" else { throw .unsupportedVersion }
        guard let url = URL(string: try need("r")), let scheme = url.scheme?.lowercased(),
              let host = url.host, !host.isEmpty,
              scheme == "https" || (scheme == "http" && isLoopbackHost(host))
        else { throw .invalid("r") }
        let room = try need("room")
        guard (16...64).contains(room.utf8.count), isIdChars(room) else { throw .invalid("room") }
        let secret = try need("s")
        guard (16...128).contains(secret.utf8.count), isIdChars(secret) else { throw .invalid("s") }
        guard let id = UUID(uuidString: try need("d")) else { throw .invalid("d") }
        guard let kd = Base64URL.decode(try need("k")), let key = Bytes32(kd) else { throw .invalid("k") }
        let code = try need("c")
        guard code.utf8.count == 6, code.utf8.allSatisfy({ $0 >= 0x30 && $0 <= 0x39 }) else { throw .invalid("c") }
        let name = PhoneNames.clean(q["n"] ?? "", fallback: "Desktop")
        return PairingURI(relayURL: url, roomId: room, roomSecret: secret, desktopDeviceId: id,
                          desktopPublicKey: key, code: code, name: name)
    }
}

/// A paired desktop's relay record (the room secret is stored separately,
/// in the Keychain on iOS).
public struct RelayDesktop: Codable, Hashable, Sendable, Identifiable {
    public var relayURL: String
    public var roomId: String
    public var deviceId: UUID
    public var publicKey: Data
    public var name: String

    public var id: UUID { deviceId }

    public init(relayURL: String, roomId: String, deviceId: UUID, publicKey: Data, name: String) {
        self.relayURL = relayURL
        self.roomId = roomId
        self.deviceId = deviceId
        self.publicKey = publicKey
        self.name = name
    }

    public init(_ uri: PairingURI) {
        self.init(relayURL: uri.relayURL.absoluteString, roomId: uri.roomId, deviceId: uri.desktopDeviceId,
                  publicKey: Data(uri.desktopPublicKey.bytes), name: uri.name)
    }

    public var peer: PeerID { RelayTransport.peerID(roomId: roomId) }
}

/// Persistence of relay desktops; secrets live in a secret store.
public protocol RelayDesktopStore: AnyObject {
    func loadDesktops() throws -> [RelayDesktop]
    func saveDesktops(_ desktops: [RelayDesktop]) throws
    func loadSecret(roomId: String) throws -> String?
    func saveSecret(_ secret: String, roomId: String) throws
    func deleteSecret(roomId: String) throws
}

public final class InMemoryRelayDesktopStore: RelayDesktopStore {
    public var desktops: [RelayDesktop] = []
    public var secrets: [String: String] = [:]
    public init() {}
    public func loadDesktops() throws -> [RelayDesktop] { desktops }
    public func saveDesktops(_ d: [RelayDesktop]) throws { desktops = d }
    public func loadSecret(roomId: String) throws -> String? { secrets[roomId] }
    public func saveSecret(_ s: String, roomId: String) throws { secrets[roomId] = s }
    public func deleteSecret(roomId: String) throws { secrets[roomId] = nil }
}
