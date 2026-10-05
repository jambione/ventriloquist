import Foundation
import Security
import VQPhoneCore

/// Paired relay desktops as JSON in Application Support. The room secret is
/// not in this file (see ``KeychainRelaySecretStore``).
final class FilePairedRelayDesktopStore: PairedRelayDesktopStore {
    private let url: URL

    init(directory: URL = URL.applicationSupportDirectory) {
        url = directory.appending(path: "paired-relay-desktops.json")
    }

    func loadRelayDesktops() throws -> [PairedRelayDesktop] {
        guard FileManager.default.fileExists(atPath: url.path()) else { return [] }
        return try JSONDecoder().decode([PairedRelayDesktop].self, from: Data(contentsOf: url))
    }

    func saveRelayDesktops(_ desktops: [PairedRelayDesktop]) throws {
        try FileManager.default.createDirectory(at: url.deletingLastPathComponent(),
                                                withIntermediateDirectories: true)
        let data = try JSONEncoder().encode(desktops)
        try data.write(to: url, options: [.atomic, .completeFileProtectionUntilFirstUserAuthentication])
    }
}

/// Room secrets in the Keychain, one generic-password item per room id,
/// `AfterFirstUnlockThisDeviceOnly` (the app reconnects in the background
/// after a reboot only once the phone was unlocked).
final class KeychainRelaySecretStore: RelaySecretStore {
    private let service = "com.ventriloquist.app.relay-room"

    enum KeychainError: Error { case status(OSStatus), corrupt }

    private func query(_ roomId: String) -> [String: Any] {
        [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: roomId,
        ]
    }

    func get(roomId: String) throws -> String? {
        var q = query(roomId)
        q[kSecReturnData as String] = true
        q[kSecMatchLimit as String] = kSecMatchLimitOne
        var item: CFTypeRef?
        let status = SecItemCopyMatching(q as CFDictionary, &item)
        if status == errSecItemNotFound { return nil }
        guard status == errSecSuccess else { throw KeychainError.status(status) }
        guard let data = item as? Data, let s = String(data: data, encoding: .utf8) else { throw KeychainError.corrupt }
        return s
    }

    func set(_ secret: String, roomId: String) throws {
        var add = query(roomId)
        add[kSecValueData as String] = Data(secret.utf8)
        add[kSecAttrAccessible as String] = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
        add[kSecAttrSynchronizable as String] = false
        SecItemDelete(query(roomId) as CFDictionary)
        let status = SecItemAdd(add as CFDictionary, nil)
        guard status == errSecSuccess else { throw KeychainError.status(status) }
    }

    func delete(roomId: String) throws {
        let status = SecItemDelete(query(roomId) as CFDictionary)
        guard status == errSecSuccess || status == errSecItemNotFound else { throw KeychainError.status(status) }
    }
}
