import Foundation
import VQProtocol

// PhoneSim: a scripted fake phone for the E2E test (SPEC §8, gate 3).
// Runs the real `PhoneEngine` over the TCP dev transport (README §2.1) as
// the TCP server. Usage and commands: ios/VQProtocol/PhoneSim-README.md.

let usage = """
    usage: PhoneSim [--port N] [--bind ADDR] [--name NAME] [--state-dir DIR] [--script FILE] [--verbose]
      --port       TCP port to listen on (default \(VQ.tcpDefaultPort); 0 picks a free port)
      --bind       IPv4 address to listen on (default 127.0.0.1)
      --name       name sent in hello (default PhoneSim)
      --state-dir  keep identity, paired desktops and the last desktop here (default: in memory)
      --script     read commands from FILE instead of stdin
      --verbose    engine diagnostics on stderr
    Events: one JSON object per line on stdout. Exit status 1 if any command failed.
    """

func parseOptions() -> Sim.Options? {
    var o = Sim.Options()
    var it = CommandLine.arguments.dropFirst().makeIterator()
    while let flag = it.next() {
        func value() -> String? {
            guard let v = it.next() else {
                Out.diag("\(flag) needs a value")
                return nil
            }
            return v
        }
        switch flag {
        case "--port":
            guard let v = value(), let p = UInt16(v) else { return nil }
            o.port = p
        case "--bind":
            guard let v = value() else { return nil }
            o.host = v
        case "--name":
            guard let v = value() else { return nil }
            o.name = v
        case "--state-dir":
            guard let v = value() else { return nil }
            o.stateDir = URL(fileURLWithPath: v)
        case "--script":
            guard let v = value() else { return nil }
            o.script = URL(fileURLWithPath: v)
        case "--verbose":
            o.verbose = true
        default:
            Out.diag("unknown argument \(flag)")
            return nil
        }
    }
    return o
}

signal(SIGPIPE, SIG_IGN)
guard let options = parseOptions() else {
    Out.diag(usage)
    exit(2)
}
do {
    let sim = try Sim(options: options)
    exit(sim.run())
} catch {
    Out.diag("cannot start: \(error)")
    exit(1)
}
