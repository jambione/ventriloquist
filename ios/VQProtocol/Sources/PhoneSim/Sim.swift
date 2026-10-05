import Foundation
import VQPhoneCore
import VQProtocol

/// PhoneSim's command interpreter and main loop. Single-threaded: the
/// engine, the TCP server and the command queue are only touched from
/// `run()`. See PhoneSim-README.md for the command language.
final class Sim {
    struct Options {
        var host = "127.0.0.1"
        var port: UInt16 = VQ.tcpDefaultPort
        var name = "PhoneSim"
        var stateDir: URL?
        var script: URL?
        var verbose = false
        /// Relay mode: pair through this `vq://pair?...` link instead of listening on TCP.
        var relayPairURI: PairingURI?
        /// Relay mode without a new pairing: reconnect to the desktops saved in `--state-dir`.
        var relayMode = false
    }

    /// One utterance sent by this run (`start` … `final`, or a `resend`).
    private struct Entry {
        let index: Int
        let id: UUID
        var text: String
    }

    private enum Step {
        case pending
        case done([(String, J)])
        case failed(String)
    }

    private struct Running {
        let seq: Int
        let name: String
        let deadline: Double
        let poll: () -> Step
    }

    static let defaultTimeoutMs = 10_000

    private let options: Options
    private let clock = SystemClock()
    /// TCP mode only.
    private let server: TCPServer?
    /// Relay mode only. Kept alive here; the engine holds it too.
    private let relay: RelayPhoneTransport?
    private let engine: PhoneEngine

    private var queue: [(seq: Int, line: String)] = []
    private var running: Running?
    private var seq = 0
    private var failures = 0
    private var history: [Entry] = []
    private var openIndex: Int?
    private var readingStdin: Bool
    private var stdinBuffer: [UInt8] = []
    private var quit = false
    private var lastHosts = ""
    private var lastPairing = ""

    /// `VQ_RELAY_FORCE_LONGPOLL` set to anything but empty or `0`: no WebSocket.
    static func forceLongPollFromEnv() -> Bool {
        guard let v = ProcessInfo.processInfo.environment["VQ_RELAY_FORCE_LONGPOLL"] else { return false }
        return !v.isEmpty && v != "0"
    }

    init(options: Options) throws {
        self.options = options
        let idStore: IdentityKeyStore
        let hostStore: PairedHostStore
        let settings: PhoneSettingsStore
        let relayStore: PairedRelayDesktopStore
        let relaySecrets: RelaySecretStore
        if let dir = options.stateDir {
            try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
            idStore = FileIdentityStore(dir: dir)
            hostStore = FilePairedHostStore(dir: dir)
            settings = FileSettingsStore(dir: dir)
            let files = FileRelayStores(dir: dir)
            relayStore = files
            relaySecrets = files
        } else {
            idStore = InMemoryIdentityStore()
            hostStore = InMemoryPairedHostStore()
            settings = InMemorySettingsStore()
            relayStore = InMemoryPairedRelayDesktopStore()
            relaySecrets = InMemoryRelaySecretStore()
        }
        let identity = try PhoneIdentity.loadOrCreate(from: idStore)
        let transport: PhoneTransport
        if options.relayPairURI != nil || options.relayMode {
            // Relay mode runs on the main thread/run loop (see `run`).
            let c = SystemClock()
            let r = MainActor.assumeIsolated {
                RelayPhoneTransport(networking: URLSessionRelayNetworking(), clock: c,
                                    forceLongPoll: Self.forceLongPollFromEnv())
            }
            relay = r
            server = nil
            transport = r
        } else {
            let s = try TCPServer(host: options.host, port: options.port)
            server = s
            relay = nil
            transport = s
        }
        engine = PhoneEngine(identity: identity, deviceName: options.name, hostStore: hostStore,
                             settings: settings, transport: transport, clock: clock,
                             relayStore: relayStore, relaySecrets: relaySecrets, relayRooms: relay)
        if let r = relay {
            // Single-threaded on the main thread, so this is safe.
            nonisolated(unsafe) let e = engine
            MainActor.assumeIsolated { r.events = e }
        }
        readingStdin = options.script == nil
        if let script = options.script {
            let text = try String(contentsOf: script, encoding: .utf8)
            for line in text.split(separator: "\n", omittingEmptySubsequences: false) { enqueue(String(line)) }
        }
        wire()
    }

    // MARK: Wiring

    private func wire() {
        server?.delegate = TCPServer.Delegate(
            connected: { [unowned self] peer in
                Out.event("tcp_connected", [("peer", .s(peer.raw))])
                engine.peerConnected(peer)
            },
            received: { [unowned self] frame, peer in engine.peerReceived(frame: frame, from: peer) },
            disconnected: { [unowned self] peer, reason in
                Out.event("tcp_disconnected", [("peer", .s(peer.raw)), ("reason", .s(reason))])
                engine.peerDisconnected(peer)
            },
            closedByEngine: { peer in
                Out.event("tcp_disconnected", [("peer", .s(peer.raw)), ("reason", .s("closed by engine"))])
            })
        engine.onChange = { [unowned self] in reportState() }
        engine.onEvent = { [unowned self] e in report(e) }
        if options.verbose { engine.log = { Out.diag($0) } }
    }

    private func report(_ e: PhoneEvent) {
        switch e {
        case .deliveryChanged(let id, let status):
            Out.event("delivery", [("id", .s(uuid(id))), ("index", indexJ(id)), ("status", .s(status.rawValue))])
        case .utteranceLimitReached(let id, let text):
            Out.event("utterance_limit", [("id", .s(uuid(id))), ("text_bytes", .i(text.utf8.count))])
        case .paired(let hostId, let name):
            Out.event("paired", [("host_id", .s(uuid(hostId))), ("name", .s(name))])
        case .notice(let n):
            Out.event("notice", [("kind", .s(noticeKind(n))), ("text", .s(n.text))])
        }
    }

    private func noticeKind(_ n: PhoneNotice) -> String {
        switch n {
        case .versionMismatch: "version_mismatch"
        case .notRecognized: "not_recognized"
        case .peerError(_, let code, _): "peer_error:\(code)"
        case .keepaliveTimeout: "keepalive_timeout"
        case .storageFailed: "storage_failed"
        case .pairingCodeMismatch: "pairing_code_mismatch"
        }
    }

    private func reportState() {
        let hosts = hostsJ().encoded()
        if hosts != lastHosts {
            lastHosts = hosts
            Out.event("hosts_changed", [("hosts", hostsJ()), ("indicator", .s(indicator()))])
        }
        let pairing = pairingJ()
        let p = pairing.encoded()
        if p != lastPairing {
            lastPairing = p
            if case .o(let fields) = pairing { Out.event("pairing", fields) }
        }
    }

    private func indicator() -> String {
        switch engine.indicator {
        case .none: "none"
        case .connecting: "connecting"
        case .secure: "secure"
        }
    }

    private func hostsJ() -> J {
        .a(engine.hosts.map { h in
            let state: String = switch h.state {
            case .offline: "offline"
            case .unpaired: "unpaired"
            case .pairing: "pairing"
            case .secure: "secure"
            }
            return .o([("id", .s(uuid(h.id))), ("name", .s(h.name)), ("paired", .b(h.isPaired)),
                       ("online", .b(h.isOnline)), ("state", .s(state)), ("active", .b(h.isActive)),
                       ("not_recognized", .b(h.notRecognized)), ("key_changed", .b(h.keyChanged))])
        })
    }

    private func pairingJ() -> J {
        guard let p = engine.pairing else { return .o([("phase", .null)]) }
        var error: String?
        let phase: String
        switch p.phase {
        case .requesting: phase = "requesting"
        case .enterCode(let e):
            phase = "enter_code"
            error = e
        case .verifying: phase = "verifying"
        case .succeeded: phase = "succeeded"
        case .failed(let m):
            phase = "failed"
            error = m
        }
        return .o([("phase", .s(phase)), ("host_id", .s(uuid(p.hostId))), ("host_name", .s(p.hostName)),
                   ("error", .str(error)), ("note", .str(p.note))])
    }

    // MARK: Main loop

    func run() -> Int32 {
        Out.event("started", [
            ("device_id", .s(uuid(engine.identity.deviceId))),
            ("name", .s(options.name)),
            ("state_dir", .str(options.stateDir?.path)),
            ("paired_hosts", .a(engine.pairedHostRecords.map {
                .o([("device_id", .s(uuid($0.deviceId))), ("name", .s($0.name))])
            })),
            ("active_host_id", .str(engine.activeHostId.map(uuid))),
        ])
        if let server {
            Out.event("listening", [("host", .s(options.host)), ("port", .i(Int(server.port)))])
        } else if options.relayPairURI == nil {
            Out.event("relay_mode", [])
        } else if let uri = options.relayPairURI {
            Out.event("relay_pairing", [("relay", .s(uri.relayURL.absoluteString)), ("room", .s(uri.roomId)),
                                        ("desktop", .s(uri.name))])
            engine.pair(using: uri)
        }
        if readingStdin { _ = fcntl(0, F_SETFL, fcntl(0, F_GETFL) | O_NONBLOCK) }
        while !quit {
            progress()
            if quit { break }
            if let server {
                if server.pollOnce(timeoutMs: 20, extraFD: readingStdin ? 0 : nil) { readStdin() }
            } else {
                // Relay mode: the transport's work is posted to the main queue,
                // which only the main run loop drains. Called from the main thread.
                var fd = pollfd(fd: 0, events: Int16(POLLIN), revents: 0)
                if readingStdin, poll(&fd, 1, 0) > 0 { readStdin() }
                RunLoop.main.run(mode: .default, before: Date(timeIntervalSinceNow: 0.02))
            }
            engine.tick()
        }
        // Let queued frames go out before closing.
        server?.shutdown()
        Out.event("exited", [("failed_commands", .i(failures))])
        return failures == 0 ? 0 : 1
    }

    private func readStdin() {
        var buf = [UInt8](repeating: 0, count: 65_536)
        while true {
            let n = buf.withUnsafeMutableBytes { read(0, $0.baseAddress, $0.count) }
            if n > 0 {
                stdinBuffer += buf[0..<n]
                while let nl = stdinBuffer.firstIndex(of: 0x0A) {
                    enqueue(String(decoding: stdinBuffer[..<nl], as: UTF8.self))
                    stdinBuffer.removeSubrange(...nl)
                }
                continue
            }
            if n < 0 && (errno == EAGAIN || errno == EINTR) { return }
            if !stdinBuffer.isEmpty { enqueue(String(decoding: stdinBuffer, as: UTF8.self)) }
            stdinBuffer = []
            readingStdin = false  // EOF: finish the queue, then exit
            return
        }
    }

    private func enqueue(_ raw: String) {
        let line = raw.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !line.isEmpty, !line.hasPrefix("#") else { return }
        seq += 1
        queue.append((seq, line))
    }

    /// Start queued commands and step the running one until one blocks.
    private func progress() {
        while true {
            if let r = running {
                let step = r.poll()
                switch step {
                case .pending:
                    guard clock.now >= r.deadline else { return }
                    finish(r, .failed("timeout"))
                case .done, .failed:
                    finish(r, step)
                }
                running = nil
                if quit { return }
                continue
            }
            guard !quit, !queue.isEmpty else {
                if !readingStdin { quit = true }
                return
            }
            let (s, line) = queue.removeFirst()
            running = start(seq: s, line: line)
        }
    }

    private func finish(_ r: Running, _ step: Step) {
        switch step {
        case .done(let extra):
            Out.event("command_done", [("seq", .i(r.seq)), ("cmd", .s(r.name))] + extra)
        case .failed(let reason):
            failures += 1
            Out.event("command_failed", [("seq", .i(r.seq)), ("cmd", .s(r.name)), ("reason", .s(reason))])
        case .pending:
            break
        }
    }

    // MARK: Commands

    private struct Args {
        var cmd: String
        /// Text after the command word (plain form), or named members (JSON form).
        var rest: String
        var named: [String: Any]

        func string(_ key: String) -> String? { named[key] as? String }
        func int(_ key: String) -> Int? { (named[key] as? NSNumber)?.intValue }
    }

    private func parse(_ line: String) throws -> Args {
        if line.hasPrefix("{") {
            guard let obj = try JSONSerialization.jsonObject(with: Data(line.utf8)) as? [String: Any],
                  let cmd = obj["cmd"] as? String
            else { throw SimError("JSON command needs a string \"cmd\"") }
            return Args(cmd: cmd, rest: "", named: obj)
        }
        let parts = line.split(separator: " ", maxSplits: 1, omittingEmptySubsequences: true)
        let rest = parts.count > 1 ? String(parts[1]).trimmingCharacters(in: .whitespaces) : ""
        return Args(cmd: String(parts[0]), rest: rest, named: [:])
    }

    /// The text argument: JSON form `text`, else the rest of the line, which
    /// is decoded as a JSON string if it starts with `"`.
    private func text(_ a: Args) throws -> String {
        if let t = a.string("text") { return t }
        guard a.rest.hasPrefix("\"") else { return a.rest }
        guard let s = try JSONSerialization.jsonObject(with: Data(a.rest.utf8), options: [.fragmentsAllowed])
            as? String
        else { throw SimError("text is not a JSON string") }
        return s
    }

    /// Plain-form words after the command.
    private func words(_ a: Args) -> [String] { a.rest.split(separator: " ").map(String.init) }

    private func timeoutMs(_ a: Args, word: Int) -> Int {
        if let t = a.int("timeout_ms") { return t }
        let w = words(a)
        if w.count > word, let t = Int(w[word]) { return t }
        return Self.defaultTimeoutMs
    }

    private func entry(_ ref: String?) -> Entry? {
        guard let ref, !ref.isEmpty, ref != "last" else { return history.last }
        if let n = Int(ref) { return history.indices.contains(n) ? history[n] : nil }
        guard let id = UUID(uuidString: ref) else { return nil }
        return history.first { $0.id == id }
    }

    private func start(seq: Int, line: String) -> Running {
        let a: Args
        do { a = try parse(line) } catch {
            return Running(seq: seq, name: "?", deadline: 0) { .failed("\(error)") }
        }
        let now = clock.now
        func immediate(_ step: Step) -> Running {
            Running(seq: seq, name: a.cmd, deadline: now) { step }
        }
        func waiting(_ ms: Int, _ poll: @escaping () -> Step) -> Running {
            Running(seq: seq, name: a.cmd, deadline: now + Double(ms) / 1000, poll: poll)
        }
        do {
            switch a.cmd {
            case "wait-connected":
                return waiting(timeoutMs(a, word: 0)) { [unowned self] in
                    guard let h = engine.hosts.first(where: { $0.isOnline }) else { return .pending }
                    return .done([("host_id", .s(uuid(h.id))), ("name", .s(h.name)), ("paired", .b(h.isPaired))])
                }
            case "wait-secure":
                return waiting(timeoutMs(a, word: 0)) { [unowned self] in
                    guard engine.indicator == .secure, let h = engine.activeHost else { return .pending }
                    return .done([("host_id", .s(uuid(h.id))), ("name", .s(h.name))])
                }
            case "wait-disconnected":
                return waiting(timeoutMs(a, word: 0)) { [unowned self] in
                    (server?.connectionCount ?? engine.hosts.filter(\.isOnline).count) == 0 ? .done([]) : .pending
                }
            case "select":
                let target = a.string("target") ?? words(a).first ?? "first"
                return waiting(timeoutMs(a, word: 1)) { [unowned self] in
                    let paired = engine.hosts.filter(\.isPaired)
                    let match = target == "first"
                        ? paired.first
                        : paired.first { $0.id.uuidString.lowercased() == target.lowercased() || $0.name == target }
                    guard let h = match else { return .pending }
                    engine.selectHost(h.id)
                    return engine.activeHostId == h.id ? .done([("host_id", .s(uuid(h.id)))]) : .failed("not selected")
                }
            case "pair":
                let code = a.string("code") ?? words(a).first ?? ""
                return waiting(timeoutMs(a, word: 1), pairStepper(code: code))
            case "start":
                if engine.isUtteranceOpen { throw SimError("an utterance is already open") }
                let id = engine.beginUtterance()
                history.append(Entry(index: history.count, id: id, text: ""))
                openIndex = history.count - 1
                return immediate(.done([("id", .s(uuid(id))), ("index", .i(history.count - 1))]))
            case "partial":
                guard engine.isUtteranceOpen, let i = openIndex else { throw SimError("no open utterance") }
                engine.updatePartial(try text(a))
                return immediate(.done([("id", .s(uuid(history[i].id))), ("index", .i(i))]))
            case "final":
                guard engine.isUtteranceOpen, let i = openIndex else { throw SimError("no open utterance") }
                openIndex = nil
                guard let f = engine.finishUtterance(try text(a)) else { throw SimError("nothing to send") }
                history[i].text = f.text
                return immediate(.done([("id", .s(uuid(f.id))), ("index", .i(i)), ("truncated", .b(f.truncated))]))
            case "edit":
                guard let e = entry(a.string("ref")) else { throw SimError("no such utterance") }
                guard let sent = engine.sendEdit(id: e.id, text: try text(a)) else {
                    throw SimError("utterance was never sent")
                }
                history[e.index].text = sent
                return immediate(.done([("id", .s(uuid(e.id))), ("index", .i(e.index))]))
            case "resend":
                guard let e = entry(a.string("ref") ?? words(a).first) else { throw SimError("no such utterance") }
                let f = engine.resend(text: e.text)
                history.append(Entry(index: history.count, id: f.id, text: f.text))
                return immediate(.done([("id", .s(uuid(f.id))), ("index", .i(history.count - 1)),
                                        ("of", .i(e.index))]))
            case "wait-acked":
                guard let e = entry(a.string("ref") ?? words(a).first) else { throw SimError("no such utterance") }
                return waiting(timeoutMs(a, word: 1)) { [unowned self] in
                    engine.deliveryStatus(of: e.id) == .acked
                        ? .done([("id", .s(uuid(e.id))), ("index", .i(e.index))]) : .pending
                }
            case "status":
                guard let e = entry(a.string("ref") ?? words(a).first) else { throw SimError("no such utterance") }
                let s = engine.deliveryStatus(of: e.id)?.rawValue
                return immediate(.done([("id", .s(uuid(e.id))), ("index", .i(e.index)), ("status", .str(s))]))
            case "drop-connection":
                let server = try tcp()
                let n = server.connectionCount
                server.dropAll(reason: "dropped by script")
                return immediate(.done([("closed", .i(n))]))
            case "tx-pause", "tx-resume":
                try tcp().setTxPaused(a.cmd == "tx-pause")
                return immediate(.done([]))
            case "rx-pause", "rx-resume":
                try tcp().setRxPaused(a.cmd == "rx-pause")
                return immediate(.done([]))
            case "inject-plaintext-utt":
                let id = UUID()
                let utt = Utt(id: id, rev: 0, state: .final, text: try text(a), ts: clock.epochMillis)
                let envelope = [Envelope.kindPlaintext] + (try Message.utt(utt).toJSON())
                var splitter = FrameSplitter(seq: 0x7000)
                let n = try tcp().injectFrames(splitter.split(envelope, mtu: TCPFrameCodec.mtu))
                return immediate(.done([("id", .s(uuid(id))), ("connections", .i(n))]))
            case "hosts":
                return immediate(.done([("hosts", hostsJ()), ("indicator", .s(indicator()))]))
            case "sleep":
                let ms = a.int("ms") ?? Int(words(a).first ?? "") ?? 0
                let until = now + Double(ms) / 1000
                return waiting(ms + 1_000) { [unowned self] in clock.now >= until ? .done([]) : .pending }
            case "quit":
                quit = true
                return immediate(.done([]))
            default:
                throw SimError("unknown command \(a.cmd)")
            }
        } catch {
            return immediate(.failed("\(error)"))
        }
    }

    /// `pair <code|@file>`: start pairing with the (first) unpaired online
    /// desktop, wait for its challenge, submit the code (read from the file
    /// once it exists, for `@file`), and report `pair_result`.
    private func pairStepper(code: String) -> () -> Step {
        enum Phase { case findHost, awaitChallenge, awaitCode, awaitResult }
        var phase = Phase.findHost
        var hostId: UUID?
        return { [unowned self] in
            while true {
                switch phase {
                case .findHost:
                    guard let h = engine.hosts.first(where: { $0.isOnline && (!$0.isPaired || $0.keyChanged) })
                    else { return .pending }
                    hostId = h.id
                    engine.startPairing(with: h.id)
                    phase = .awaitChallenge
                case .awaitChallenge:
                    guard let p = engine.pairing else { return .failed("pairing not started") }
                    switch p.phase {
                    case .enterCode: phase = .awaitCode
                    case .failed(let m): return pairResult(ok: false, hostId: hostId, message: m)
                    default: return .pending
                    }
                case .awaitCode:
                    var value = code
                    if code.hasPrefix("@") {
                        let path = String(code.dropFirst())
                        guard let data = FileManager.default.contents(atPath: path) else { return .pending }
                        value = String(decoding: data, as: UTF8.self).trimmingCharacters(in: .whitespacesAndNewlines)
                        if value.isEmpty { return .pending }
                    }
                    engine.submitPairingCode(value)
                    phase = .awaitResult
                case .awaitResult:
                    guard let p = engine.pairing else { return .failed("pairing ended") }
                    switch p.phase {
                    case .succeeded: return pairResult(ok: true, hostId: hostId, message: nil)
                    case .enterCode(let e?): return pairResult(ok: false, hostId: hostId, message: e)
                    case .failed(let m): return pairResult(ok: false, hostId: hostId, message: m)
                    case .requesting: return pairResult(ok: false, hostId: hostId, message: p.note)
                    default: return .pending
                    }
                }
            }
        }
    }

    private func pairResult(ok: Bool, hostId: UUID?, message: String?) -> Step {
        let fields: [(String, J)] = [("ok", .b(ok)), ("host_id", .str(hostId.map(uuid))), ("message", .str(message))]
        Out.event("pair_result", fields)
        return .done(fields)
    }

    // MARK: Helpers

    private func tcp() throws -> TCPServer {
        guard let server else { throw SimError("only available in TCP mode") }
        return server
    }

    private func uuid(_ id: UUID) -> String { id.uuidString.lowercased() }

    private func indexJ(_ id: UUID) -> J {
        history.first { $0.id == id }.map { .i($0.index) } ?? .null
    }
}
