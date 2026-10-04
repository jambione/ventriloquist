import AVFAudio
import Foundation
import Observation
import Speech

/// On-device dictation (SPEC §5.2) with `SpeechAnalyzer` + `DictationTranscriber`.
///
/// Why `DictationTranscriber` and not `SpeechTranscriber`: the iOS SDK's own
/// documentation of `AnalysisContext.contextualStrings` says "With the
/// `DictationTranscriber` module, you can use this property to specify short
/// custom phrases…", and says nothing equivalent for `SpeechTranscriber`.
/// SPEC §5.2's fallback therefore applies (see docs/SPEC_QUESTIONS.md, M6).
///
/// Audio flows `AVAudioEngine` input tap → `AVAudioConverter` (to the
/// analyzer's best format) → `AsyncStream<AnalyzerInput>` → `SpeechAnalyzer`.
/// Buffers live only in memory; nothing is written to disk.
@MainActor
@Observable
final class DictationEngine {
    enum Phase: Equatable {
        case idle
        /// Downloading the speech model; fraction 0…1 when known.
        case preparingModel(Double?)
        case starting
        case recording
        case stopping
    }

    enum DictationError: LocalizedError {
        case localeUnsupported
        case modelUnavailable
        case noAudioFormat
        case noMicrophone

        var errorDescription: String? {
            switch self {
            case .localeUnsupported: "English (US) dictation is not supported on this device."
            case .modelUnavailable: "The speech model is not available on this device."
            case .noAudioFormat: "The speech analyzer has no compatible audio format."
            case .noMicrophone: "No microphone input is available."
            }
        }
    }

    static let locale = Locale(identifier: "en-US")
    /// SDK guidance: at most 100 contextual phrases.
    nonisolated static let maxContextualStrings = 100

    private(set) var phase: Phase = .idle
    /// Finalized (stable) text of the current recording.
    private(set) var finalizedText = ""
    /// Volatile (may still change) text after `finalizedText`.
    private(set) var volatileText = ""
    /// Called on every change with the full current text.
    @ObservationIgnored var onTextChange: ((String) -> Void)?

    var fullText: String { Self.join(finalizedText, volatileText) }

    @ObservationIgnored private var analyzer: SpeechAnalyzer?
    @ObservationIgnored private var audioEngine: AVAudioEngine?
    @ObservationIgnored private var continuation: AsyncStream<AnalyzerInput>.Continuation?
    @ObservationIgnored private var resultsTask: Task<Void, Never>?

    /// Start recording. Throws if dictation cannot run (e.g. in the Simulator).
    func start(vocabulary: [String]) async throws {
        guard phase == .idle else { return }
        phase = .starting
        finalizedText = ""
        volatileText = ""
        do {
            try await startPipeline(vocabulary: vocabulary)
            phase = .recording
        } catch {
            await tearDown()
            phase = .idle
            throw error
        }
    }

    private func startPipeline(vocabulary: [String]) async throws {
        guard let locale = await DictationTranscriber.supportedLocale(equivalentTo: Self.locale) else {
            throw DictationError.localeUnsupported
        }
        let transcriber = DictationTranscriber(locale: locale, contentHints: [],
                                               transcriptionOptions: [.punctuation],
                                               reportingOptions: [.volatileResults],
                                               attributeOptions: [])
        try await ensureModel(for: transcriber, locale: locale)
        phase = .starting

        let analyzer = SpeechAnalyzer(modules: [transcriber])
        self.analyzer = analyzer
        let terms = vocabulary.map { $0.trimmingCharacters(in: .whitespacesAndNewlines) }.filter { !$0.isEmpty }
        if !terms.isEmpty {
            let context = AnalysisContext()
            context.contextualStrings[.general] = Array(terms.prefix(Self.maxContextualStrings))
            try await analyzer.setContext(context)
        }
        guard let format = await SpeechAnalyzer.bestAvailableAudioFormat(compatibleWith: [transcriber]) else {
            throw DictationError.noAudioFormat
        }
        try await analyzer.prepareToAnalyze(in: format)

        let session = AVAudioSession.sharedInstance()
        try session.setCategory(.record, mode: .measurement)
        try session.setActive(true, options: .notifyOthersOnDeactivation)

        let (stream, continuation) = AsyncStream.makeStream(of: AnalyzerInput.self, bufferingPolicy: .unbounded)
        self.continuation = continuation
        resultsTask = Task { [weak self] in
            do {
                for try await result in transcriber.results {
                    self?.handle(text: String(result.text.characters), isFinal: result.isFinal)
                }
            } catch {
                // Analysis ended with an error; the final text so far stands.
            }
        }
        try await analyzer.start(inputSequence: stream)

        let engine = AVAudioEngine()
        let input = engine.inputNode
        let inputFormat = input.outputFormat(forBus: 0)
        guard inputFormat.sampleRate > 0, inputFormat.channelCount > 0 else { throw DictationError.noMicrophone }
        guard let feeder = AudioFeeder(from: inputFormat, to: format, continuation: continuation) else {
            throw DictationError.noAudioFormat
        }
        AudioTap.install(on: input, format: inputFormat, feeder: feeder)
        engine.prepare()
        audioEngine = engine
        try engine.start()
    }

    private func ensureModel(for transcriber: DictationTranscriber, locale: Locale) async throws {
        let status = await AssetInventory.status(forModules: [transcriber])
        guard status != .unsupported else { throw DictationError.modelUnavailable }
        guard status != .installed else { return }
        _ = try? await AssetInventory.reserve(locale: locale)
        guard let request = try await AssetInventory.assetInstallationRequest(supporting: [transcriber]) else { return }
        phase = .preparingModel(0)
        let poll = Task { [weak self] in
            while !Task.isCancelled {
                self?.phase = .preparingModel(request.progress.fractionCompleted)
                try? await Task.sleep(for: .milliseconds(200))
            }
        }
        defer { poll.cancel() }
        try await request.downloadAndInstall()
    }

    /// Download the model ahead of the first recording (Settings / first run).
    func prepareModel() async throws {
        guard phase == .idle else { return }
        guard let locale = await DictationTranscriber.supportedLocale(equivalentTo: Self.locale) else {
            throw DictationError.localeUnsupported
        }
        let transcriber = DictationTranscriber(locale: locale, contentHints: [],
                                               transcriptionOptions: [.punctuation],
                                               reportingOptions: [.volatileResults], attributeOptions: [])
        defer { phase = .idle }
        try await ensureModel(for: transcriber, locale: locale)
    }

    private func handle(text: String, isFinal: Bool) {
        if isFinal {
            finalizedText = Self.join(finalizedText, text)
            volatileText = ""
        } else {
            volatileText = text
        }
        onTextChange?(fullText)
    }

    /// Stop recording, finalize, and return the full text.
    func stop() async -> String {
        guard phase == .recording || phase == .starting else { return fullText }
        phase = .stopping
        await tearDown()
        let text = fullText
        phase = .idle
        return text
    }

    private func tearDown() async {
        if let engine = audioEngine {
            engine.inputNode.removeTap(onBus: 0)
            engine.stop()
        }
        audioEngine = nil
        continuation?.finish()
        continuation = nil
        if let analyzer {
            // Finalize what was heard; give up after a few seconds.
            let finish = Task { try? await analyzer.finalizeAndFinishThroughEndOfInput() }
            let watchdog = Task {
                try? await Task.sleep(for: .seconds(4))
                if !Task.isCancelled { await analyzer.cancelAndFinishNow() }
            }
            await finish.value
            watchdog.cancel()
        }
        analyzer = nil
        if let resultsTask {
            let guardTask = Task {
                try? await Task.sleep(for: .seconds(2))
                if !Task.isCancelled { resultsTask.cancel() }
            }
            await resultsTask.value
            guardTask.cancel()
        }
        resultsTask = nil
        try? AVAudioSession.sharedInstance().setActive(false, options: .notifyOthersOnDeactivation)
        // A leftover volatile tail counts as said.
        if !volatileText.isEmpty {
            finalizedText = fullText
            volatileText = ""
        }
    }

    /// Join two transcript pieces with one space when neither side has one.
    nonisolated static func join(_ a: String, _ b: String) -> String {
        guard !a.isEmpty else { return b }
        guard !b.isEmpty else { return a }
        if a.last?.isWhitespace == true || b.first?.isWhitespace == true { return a + b }
        return a + " " + b
    }
}

/// Converts tap buffers to the analyzer's format and feeds the stream. Runs on
/// the audio render thread; it only touches its own immutable state and the
/// thread-safe continuation.
final class AudioFeeder: @unchecked Sendable {
    private let converter: AVAudioConverter?
    private let outFormat: AVAudioFormat
    private let continuation: AsyncStream<AnalyzerInput>.Continuation

    init?(from input: AVAudioFormat, to output: AVAudioFormat,
          continuation: AsyncStream<AnalyzerInput>.Continuation) {
        outFormat = output
        self.continuation = continuation
        if input == output {
            converter = nil
        } else {
            guard let c = AVAudioConverter(from: input, to: output) else { return nil }
            c.primeMethod = .none
            converter = c
        }
    }

    func feed(_ buffer: AVAudioPCMBuffer) {
        guard let converter else {
            continuation.yield(AnalyzerInput(buffer: buffer))
            return
        }
        let ratio = outFormat.sampleRate / buffer.format.sampleRate
        let capacity = AVAudioFrameCount((Double(buffer.frameLength) * ratio).rounded(.up)) + 16
        guard let out = AVAudioPCMBuffer(pcmFormat: outFormat, frameCapacity: capacity) else { return }
        let supplied = SuppliedFlag()
        var error: NSError?
        let status = converter.convert(to: out, error: &error) { _, inputStatus in
            if supplied.done {
                inputStatus.pointee = .noDataNow
                return nil
            }
            supplied.done = true
            inputStatus.pointee = .haveData
            return buffer
        }
        if status != .error, out.frameLength > 0 {
            continuation.yield(AnalyzerInput(buffer: out))
        }
    }

    private final class SuppliedFlag: @unchecked Sendable {
        var done = false
    }
}

/// Installs the input tap from a nonisolated context, so the tap block is not
/// main-actor isolated (it runs on the audio thread).
enum AudioTap {
    nonisolated static func install(on node: AVAudioInputNode, format: AVAudioFormat, feeder: AudioFeeder) {
        node.installTap(onBus: 0, bufferSize: 4_096, format: format) { buffer, _ in
            feeder.feed(buffer)
        }
    }
}
