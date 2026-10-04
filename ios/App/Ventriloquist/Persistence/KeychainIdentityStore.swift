import Foundation
import Security
import VQPhoneCore
import VQProtocol

/// Stores the X25519 identity in the Keychain (SPEC §4.4: `ThisDeviceOnly`).
///
/// One generic-password item: `kSecValueData` holds the raw 32-byte private
/// key (lent by `IdentityKeyPair.withSecretBytes`), and `kSecAttrGeneric`
/// holds the 16-byte `device_id`, which is not secret.
final class KeychainIdentityStore: IdentityKeyStore {
    private let service = "com.ventriloquist.app.identity"
    private let account = "x25519"

    enum KeychainError: Error {
        case status(OSStatus)
        case corrupt
    }

    private var baseQuery: [String: Any] {
        [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
        ]
    }

    func loadIdentity() throws -> StoredIdentity? {
        var query = baseQuery
        query[kSecReturnData as String] = true
        query[kSecReturnAttributes as String] = true
        query[kSecMatchLimit as String] = kSecMatchLimitOne
        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        if status == errSecItemNotFound { return nil }
        guard status == errSecSuccess else { throw KeychainError.status(status) }
        guard let attrs = item as? [String: Any],
              let secret = attrs[kSecValueData as String] as? Data,
              let idData = attrs[kSecAttrGeneric as String] as? Data, idData.count == 16,
              let keyPair = IdentityKeyPair(secretBytes: secret)
        else { throw KeychainError.corrupt }
        let deviceId = idData.withUnsafeBytes { raw in
            UUID(uuid: raw.loadUnaligned(as: uuid_t.self))
        }
        return StoredIdentity(deviceId: deviceId, keyPair: keyPair)
    }

    func saveIdentity(_ identity: StoredIdentity) throws {
        let idData = withUnsafeBytes(of: identity.deviceId.uuid) { Data($0) }
        let status: OSStatus = identity.keyPair.withSecretBytes { secret in
            var add = baseQuery
            add[kSecValueData as String] = Data(secret)
            add[kSecAttrGeneric as String] = idData
            add[kSecAttrAccessible as String] = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
            add[kSecAttrSynchronizable as String] = false
            SecItemDelete(baseQuery as CFDictionary)
            return SecItemAdd(add as CFDictionary, nil)
        }
        guard status == errSecSuccess else { throw KeychainError.status(status) }
    }
}
