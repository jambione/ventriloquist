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

    /// Keep an unreadable file under a new name before it is replaced (M10).
    func backUpUnreadableHosts() throws {
        guard FileManager.default.fileExists(atPath: url.path()) else { return }
        let stamp = Int(Date().timeIntervalSince1970)
        let backup = url.deletingLastPathComponent().appending(path: "paired-hosts.unreadable-\(stamp).json")
        try FileManager.default.moveItem(at: url, to: backup)
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
        static let nameChosen = "deviceNameChosen"
    }

    init(defaults: UserDefaults = .standard) {
        self.defaults = defaults
    }

    var lastHostId: UUID? {
        get { defaults.string(forKey: Key.lastHost).flatMap(UUID.init(uuidString:)) }
        set { defaults.set(newValue?.uuidString, forKey: Key.lastHost) }
    }

    /// Name shown to desktops, at most 64 scalars. `UIDevice.name` is the
    /// generic "iPhone" without a special entitlement (iOS 16+), so the first
    /// run asks the user for a name, prefilled with it (M14).
    @MainActor var deviceName: String {
        get {
            let stored = defaults.string(forKey: Key.deviceName) ?? UIDevice.current.name
            return PhoneNames.clean(stored, fallback: "iPhone")
        }
        set { defaults.set(PhoneNames.clean(newValue, fallback: "iPhone"), forKey: Key.deviceName) }
    }

    /// Whether the user has confirmed a device name (first-run prompt).
    var deviceNameChosen: Bool {
        get { defaults.bool(forKey: Key.nameChosen) }
        set { defaults.set(newValue, forKey: Key.nameChosen) }
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
