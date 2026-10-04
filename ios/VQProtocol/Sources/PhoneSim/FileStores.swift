import Foundation
import VQPhoneCore
import VQProtocol

// File-backed stores for `--state-dir`, so a second run reuses the identity,
// the paired desktops and the last active desktop. Files are written
// atomically with mode 0600. They hold a private key: test use only.

private func writePrivate(_ data: Data, to url: URL) throws {
    try data.write(to: url, options: .atomic)
    try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: url.path)
}

private func readIfExists(_ url: URL) throws -> Data? {
    guard FileManager.default.fileExists(atPath: url.path) else { return nil }
    return try Data(contentsOf: url)
}

/// `identity.json`: `{"device_id": UUID, "private_key": base64(32 bytes)}`.
final class FileIdentityStore: IdentityKeyStore {
    private struct Record: Codable {
        var device_id: UUID
        var private_key: String
    }

    let url: URL
    init(dir: URL) { url = dir.appendingPathComponent("identity.json") }

    func loadIdentity() throws -> StoredIdentity? {
        guard let data = try readIfExists(url) else { return nil }
        let r = try JSONDecoder().decode(Record.self, from: data)
        guard let secret = Data(base64Encoded: r.private_key), secret.count == 32,
              let pair = IdentityKeyPair(secretBytes: secret)
        else { throw StoreError.unreadable }
        return StoredIdentity(deviceId: r.device_id, keyPair: pair)
    }

    func saveIdentity(_ identity: StoredIdentity) throws {
        let secret = identity.keyPair.withSecretBytes { Data($0) }
        let r = Record(device_id: identity.deviceId, private_key: secret.base64EncodedString())
        try writePrivate(try JSONEncoder().encode(r), to: url)
    }
}

/// `paired-hosts.json`: the `PairedHost` records (Codable).
final class FilePairedHostStore: PairedHostStore {
    let url: URL
    init(dir: URL) { url = dir.appendingPathComponent("paired-hosts.json") }

    func loadHosts() throws -> [PairedHost] {
        guard let data = try readIfExists(url) else { return [] }
        return try JSONDecoder().decode([PairedHost].self, from: data)
    }

    func saveHosts(_ hosts: [PairedHost]) throws {
        try writePrivate(try JSONEncoder().encode(hosts), to: url)
    }
}

/// `settings.json`: `{"last_host_id": UUID?}`.
final class FileSettingsStore: PhoneSettingsStore {
    private struct Record: Codable { var last_host_id: UUID? }

    let url: URL
    private var cached: UUID?

    init(dir: URL) {
        url = dir.appendingPathComponent("settings.json")
        if let data = try? readIfExists(url), let r = try? JSONDecoder().decode(Record.self, from: data) {
            cached = r.last_host_id
        }
    }

    var lastHostId: UUID? {
        get { cached }
        set {
            cached = newValue
            do { try writePrivate(try JSONEncoder().encode(Record(last_host_id: newValue)), to: url) } catch {
                Out.diag("cannot write \(url.path): \(error)")
            }
        }
    }
}
