import AVFAudio
import Foundation
import Observation
import Speech
import SwiftData
import UIKit
import VQPhoneCore
import VQProtocol

/// The app's state, on the main actor. It owns the transport-agnostic
/// ``PhoneEngine`` (VQPhoneCore), the BLE peripheral transport and the
/// dictation engine, and mirrors the engine's state for SwiftUI.
@MainActor
@Observable
final class AppModel {
    enum PermissionProblem: Equatable {
        case microphone, speech, bluetooth

        var title: String {
            switch self {
            case .microphone: "Microphone access is off"
            case .speech: "Speech recognition is off"
            case .bluetooth: "Bluetooth access is off"
            }
        }

        var explanation: String {
            switch self {
            case .microphone:
                "Ventriloquist needs the microphone to hear what you dictate. Audio is transcribed on this iPhone and never stored or sent."
            case .speech:
                "Ventriloquist needs speech recognition to turn your voice into text on this iPhone."
            case .bluetooth:
                "Ventriloquist needs Bluetooth to send your text to your paired computer."
            }
        }
    }

    // MARK: Owned components

    @ObservationIgnored let settings: AppSettings
    @ObservationIgnored let engine: PhoneEngine
    @ObservationIgnored let ble: BLEPeripheralTransport
    let dictation = DictationEngine()
    @ObservationIgnored private var history: HistoryStore?
    @ObservationIgnored private var tickTask: Task<Void, Never>?
    @ObservationIgnored private var interruptionObserver: (any NSObjectProtocol)?

    // MARK: Mirrored engine state

    private(set) var hosts: [HostInfo] = []
    private(set) var indicator: ConnectionIndicator = .none
    private(set) var activeHostName: String?
    private(set) var pairing: PairingStatus?
    private(set) var radioState: BLEPeripheralTransport.RadioState = .unknown

    // MARK: UI state

    var alertMessage: String?
    var permissionProblem: PermissionProblem?
    private(set) var identityProblem: String?
    /// The paired-desktop list could not be read at launch (M10).
    private(set) var hostsProblem: String?
    /// First run: ask for a device name (M14).
    var needsDeviceName = false
    /// Starting a recording would drop an unsent correction (M13).
    var confirmDiscardCorrection = false
    private(set) var isRecording = false
    /// Set synchronously when a start begins, so a double tap cannot start two
    /// utterances (M24).
    @ObservationIgnored private var isStarting = false
    /// Bumped on every scene change; stale background work checks it (M3).
    @ObservationIgnored private var sceneGeneration = 0
    /// The utterance shown in the editor after stopping.
    private(set) var currentId: UUID?
    /// What was last sent for `currentId` (final or correction).
    private(set) var sentText = ""
    /// The editable transcript after stopping.
    var editText = ""

    var canSendCorrection: Bool {
        currentId != nil && !isRecording && !editText.utf8.elementsEqual(sentText.utf8)
    }

    // MARK: Settings mirrors

    var deviceName: String {
        didSet {
            settings.deviceName = deviceName
            engine.deviceName = settings.deviceName
        }
    }

    var partialStreaming: Bool {
        didSet {
            settings.partialStreaming = partialStreaming
            engine.partialStreamingEnabled = partialStreaming
        }
    }

    var vocabulary: [String] {
        didSet { settings.vocabulary = vocabulary }
    }

    init() {
        let settings = AppSettings()
        self.settings = settings
        let identity: StoredIdentity
        var problem: String?
        var temporary = false
        do {
            identity = try PhoneIdentity.loadOrCreate(from: KeychainIdentityStore())
        } catch {
            // Never silently replace a stored identity: that would break every
            // pairing. Run with a temporary one and say so.
            identity = StoredIdentity(deviceId: newDeviceId(), keyPair: .generate())
            problem = "This iPhone's identity could not be read from the Keychain. Pairings made now will not be kept."
            temporary = true
        }
        let ble = BLEPeripheralTransport()
        self.ble = ble
        // With a temporary identity the real paired-host file must stay
        // untouched: a pairing made under the wrong identity would otherwise
        // replace or hide valid ones (M9).
        let hostStore: PairedHostStore = temporary ? InMemoryPairedHostStore() : FilePairedHostStore()
        let settingsStore: PhoneSettingsStore = temporary ? InMemorySettingsStore() : settings
        engine = PhoneEngine(identity: identity, deviceName: settings.deviceName,
                             partialStreamingEnabled: settings.partialStreaming,
                             hostStore: hostStore, settings: settingsStore,
                             transport: ble, clock: SystemClock())
        needsDeviceName = !settings.deviceNameChosen
        if engine.pairedHostsUnreadable {
            hostsProblem = "The list of paired computers could not be read. The old file was kept; pair again."
        }
        deviceName = settings.deviceName
        partialStreaming = settings.partialStreaming
        vocabulary = settings.vocabulary
        identityProblem = problem
        ble.engine = engine
        ble.onStateChange = { [weak self] state in self?.radioChanged(state) }
        engine.onChange = { [weak self] in self?.syncFromEngine() }
        engine.onEvent = { [weak self] event in self?.handle(event) }
        syncFromEngine()
    }

    /// Attach SwiftData and start Bluetooth and timers.
    func start(context: ModelContext) {
        guard history == nil else { return }
        var store = HistoryStore(context: context)
        store.onRemove = { [engine] id in engine.forgetDelivery(id) }
        store.failStalePending()
        history = store
        ble.start()
        // Fetch the speech model on first run, with the progress overlay (M11).
        Task { [weak self] in try? await self?.dictation.prepareModel() }
        dictation.onInterrupted = { [weak self] in
            guard let self else { return }
            Task { await self.stopRecording() }
        }
        tickTask = Task { [weak self] in
            while !Task.isCancelled {
                try? await Task.sleep(for: .milliseconds(100))
                self?.engine.tick()
            }
        }
        interruptionObserver = NotificationCenter.default.addObserver(
            forName: AVAudioSession.interruptionNotification, object: nil, queue: .main
        ) { [weak self] note in
            let began = (note.userInfo?[AVAudioSessionInterruptionTypeKey] as? UInt)
                == AVAudioSession.InterruptionType.began.rawValue
            guard began else { return }
            MainActor.assumeIsolated {
                guard let self else { return }
                Task { await self.stopRecording() }
            }
        }
    }

    // MARK: - Scene phase (SPEC §5.2: foreground only)

    /// Stops the recording, gives the final a bounded moment to be acked and
    /// flushed (BLE queue), then tears the connections down. A quick return to
    /// the foreground cancels the teardown (M3, M4).
    func enterBackground() {
        sceneGeneration += 1
        let gen = sceneGeneration
        let bgTask = UIApplication.shared.beginBackgroundTask(withName: "finish-dictation")
        Task {
            await stopRecording()
            let deadline = ContinuousClock.now + .seconds(5)
            while ContinuousClock.now < deadline, gen == sceneGeneration,
                  ble.hasQueuedFrames || (engine.indicator == .secure && engine.inFlightDeliveryCount > 0) {
                try? await Task.sleep(for: .milliseconds(100))
            }
            if gen == sceneGeneration {
                engine.disconnectAll()
                ble.enterBackground()
            }
            UIApplication.shared.endBackgroundTask(bgTask)
        }
    }

    func enterForeground() {
        sceneGeneration += 1
        ble.enterForeground()
    }

    func confirmDeviceName(_ name: String) {
        deviceName = name
        settings.deviceNameChosen = true
        needsDeviceName = false
    }

    // MARK: - Engine mirroring

    private func syncFromEngine() {
        let newHosts = engine.hosts
        if newHosts != hosts { hosts = newHosts }
        let ind = engine.indicator
        if ind != indicator { indicator = ind }
        let name = engine.activeHost?.name
        if name != activeHostName { activeHostName = name }
        let p = engine.pairing
        if p != pairing { pairing = p }
    }

    private func handle(_ event: PhoneEvent) {
        switch event {
        case .deliveryChanged(let id, let status):
            history?.update(id, status: status)
        case .utteranceLimitReached(let id, let text):
            record(id: id, text: text)
            alertMessage = "The utterance reached the maximum length, so recording stopped."
            Task { await stopRecording() }
        case .paired:
            break
        case .notice(let notice):
            // Problems with the desktop being paired are shown in the pairing sheet.
            if let p = pairing, case .peerError(let name, _, _) = notice, name == p.hostName { return }
            alertMessage = notice.text
        }
    }

    private func radioChanged(_ state: BLEPeripheralTransport.RadioState) {
        radioState = state
        if state == .unauthorized { permissionProblem = .bluetooth }
    }

    // MARK: - Hosts and pairing

    func select(_ host: HostInfo) {
        engine.selectHost(host.id)
    }

    func forget(_ host: HostInfo) {
        engine.forgetHost(host.id)
    }

    func submitCode(_ code: String) { engine.submitPairingCode(code) }
    func requestNewCode() { engine.requestNewPairingCode() }
    func retryPairing() {
        guard let id = pairing?.hostId else { return }
        engine.startPairing(with: id)
    }
    func dismissPairing() { engine.cancelPairing() }

    // MARK: - Recording (SPEC §5.1 Main)

    var hasUnsentCorrection: Bool { canSendCorrection }

    func toggleRecording() async {
        if isRecording || dictation.phase != .idle {
            await stopRecording()
        } else if hasUnsentCorrection {
            confirmDiscardCorrection = true
        } else {
            await startRecording()
        }
    }

    func startRecording() async {
        guard !isRecording, !isStarting, dictation.phase == .idle else { return }
        isStarting = true
        defer { isStarting = false }
        guard await ensurePermissions() else { return }
        // Starting a new recording commits the current entry (already in history).
        currentId = nil
        sentText = ""
        editText = ""
        engine.beginUtterance()
        dictation.onTextChange = { [weak self] text in self?.engine.updatePartial(text) }
        isRecording = true
        do {
            try await dictation.start(vocabulary: vocabulary)
        } catch {
            isRecording = false
            engine.cancelUtterance()
            if !(error is CancellationError) {
                alertMessage = "Dictation is unavailable: \(error.localizedDescription)"
            }
        }
    }

    /// Works in every phase: a stop during start cancels the start.
    func stopRecording() async {
        guard isRecording else { return }
        isRecording = false
        let text = await dictation.stop()
        if let finished = engine.finishUtterance(text) {
            record(id: finished.id, text: finished.text)
        }
    }

    private func record(id: UUID, text: String) {
        currentId = id
        sentText = text
        editText = text
        history?.add(id: id, text: text, status: engine.deliveryStatus(of: id) ?? .pending,
                     hostName: activeHostName)
    }

    /// "Send correction": an `edit` replacing the desktop entry.
    func sendCorrection() {
        guard canSendCorrection, let id = currentId,
              let sent = engine.sendEdit(id: id, text: editText) else { return }
        sentText = sent
        editText = sent
        history?.update(id, text: sent, status: engine.deliveryStatus(of: id))
    }

    // MARK: - History

    func resend(_ entry: HistoryEntry) {
        let f = engine.resend(text: entry.text)
        history?.add(id: f.id, text: f.text, status: engine.deliveryStatus(of: f.id) ?? .pending,
                     hostName: activeHostName)
    }

    func delete(_ entry: HistoryEntry, context: ModelContext) {
        engine.forgetDelivery(entry.utteranceId)
        context.delete(entry)
        try? context.save()
    }

    func clearHistory(_ entries: [HistoryEntry]) {
        for e in entries { engine.forgetDelivery(e.utteranceId) }
        history?.deleteAll()
    }

    // MARK: - Permissions (SPEC §5.2)

    private func ensurePermissions() async -> Bool {
        switch AVAudioApplication.shared.recordPermission {
        case .granted: break
        case .denied:
            permissionProblem = .microphone
            return false
        default:
            guard await AVAudioApplication.requestRecordPermission() else {
                permissionProblem = .microphone
                return false
            }
        }
        switch SFSpeechRecognizer.authorizationStatus() {
        case .authorized: return true
        case .notDetermined:
            let status = await Self.requestSpeechAuthorization()
            if status == .authorized { return true }
            permissionProblem = .speech
            return false
        default:
            permissionProblem = .speech
            return false
        }
    }

    /// Nonisolated, so the completion closure is not `@MainActor`: Speech calls
    /// it on a background queue, and a main-actor closure would trap (M1).
    nonisolated private static func requestSpeechAuthorization() async -> SFSpeechRecognizerAuthorizationStatus {
        await withCheckedContinuation { (c: CheckedContinuation<SFSpeechRecognizerAuthorizationStatus, Never>) in
            SFSpeechRecognizer.requestAuthorization { @Sendable status in c.resume(returning: status) }
        }
    }

    func openSettings() {
        if let url = URL(string: UIApplication.openSettingsURLString) {
            UIApplication.shared.open(url)
        }
    }
}
