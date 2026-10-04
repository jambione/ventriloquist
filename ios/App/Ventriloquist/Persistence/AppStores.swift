import Foundation
import UIKit
import VQPhoneCore

/// Paired desktops as JSON in Application Support. Public keys are not
/// secret; the file is still protected until first unlock.
final class FilePairedHostStore: PairedHostStore {
    private let url: URL

    init(directory: URL = URL.applicationSupportDirectory) {
        url = directory.appending(path: "paired-hosts.json")
    }

    func loadHosts() throws -> [PairedHost] {
        guard FileManager.default.fileExists(atPath: url.path()) else { return [] }
        return try JSONDecoder().decode([PairedHost].self, from: Data(contentsOf: url))
    }

    func saveHosts(_ hosts: [PairedHost]) throws {
        try FileManager.default.createDirectory(at: url.deletingLastPathComponent(),
                                                withIntermediateDirectories: true)
        let data = try JSONEncoder().encode(hosts)
        try data.write(to: url, options: [.atomic, .completeFileProtectionUntilFirstUserAuthentication])
    }
}

/// User settings in `UserDefaults` (SPEC §5.1 Settings, plus the last host).
final class AppSettings: PhoneSettingsStore {
    private let defaults: UserDefaults

    private enum Key {
        static let lastHost = "lastHostId"
        static let deviceName = "deviceName"
        static let partials = "partialStreaming"
        static let vocabulary = "customVocabulary"
    }

    init(defaults: UserDefaults = .standard) {
        self.defaults = defaults
    }

    var lastHostId: UUID? {
        get { defaults.string(forKey: Key.lastHost).flatMap(UUID.init(uuidString:)) }
        set { defaults.set(newValue?.uuidString, forKey: Key.lastHost) }
    }

    /// Name shown to desktops; defaults to the iPhone's name.
    @MainActor var deviceName: String {
        get {
            let stored = defaults.string(forKey: Key.deviceName)?.trimmingCharacters(in: .whitespacesAndNewlines)
            if let stored, !stored.isEmpty { return stored }
            return UIDevice.current.name
        }
        set { defaults.set(newValue, forKey: Key.deviceName) }
    }

    var partialStreaming: Bool {
        get { defaults.object(forKey: Key.partials) as? Bool ?? true }
        set { defaults.set(newValue, forKey: Key.partials) }
    }

    /// Custom vocabulary passed to the recognizer as contextual strings.
    var vocabulary: [String] {
        get { defaults.stringArray(forKey: Key.vocabulary) ?? [] }
        set { defaults.set(newValue, forKey: Key.vocabulary) }
    }
}
