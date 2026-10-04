import Foundation

/// A tiny JSON value for PhoneSim's JSON-lines output. Strings are emitted
/// with UTF-8 left unescaped and only the escapes JSON requires, so a text
/// survives byte-exact through any JSON parser.
indirect enum J {
    case s(String)
    case i(Int)
    case b(Bool)
    case null
    case a([J])
    case o([(String, J)])

    static func str(_ v: String?) -> J { v.map(J.s) ?? .null }

    func encoded() -> String {
        var out = ""
        write(into: &out)
        return out
    }

    private func write(into out: inout String) {
        switch self {
        case .s(let v): J.quote(v, into: &out)
        case .i(let v): out += String(v)
        case .b(let v): out += v ? "true" : "false"
        case .null: out += "null"
        case .a(let items):
            out += "["
            for (n, item) in items.enumerated() {
                if n > 0 { out += "," }
                item.write(into: &out)
            }
            out += "]"
        case .o(let members):
            out += "{"
            for (n, (k, v)) in members.enumerated() {
                if n > 0 { out += "," }
                J.quote(k, into: &out)
                out += ":"
                v.write(into: &out)
            }
            out += "}"
        }
    }

    private static func quote(_ s: String, into out: inout String) {
        out += "\""
        for u in s.unicodeScalars {
            switch u {
            case "\"": out += "\\\""
            case "\\": out += "\\\\"
            case "\n": out += "\\n"
            case "\r": out += "\\r"
            case "\t": out += "\\t"
            case "\u{08}": out += "\\b"
            case "\u{0C}": out += "\\f"
            default:
                if u.value < 0x20 {
                    out += String(format: "\\u%04x", u.value)
                } else {
                    out.unicodeScalars.append(u)
                }
            }
        }
        out += "\""
    }
}

/// Writes one JSON object per line to stdout (unbuffered, so a reader sees
/// every event as soon as it happens).
enum Out {
    static func event(_ name: String, _ fields: [(String, J)] = []) {
        let line = J.o([("event", .s(name))] + fields).encoded() + "\n"
        writeAll(1, Array(line.utf8))
    }

    static func diag(_ message: String) {
        writeAll(2, Array("PhoneSim: \(message)\n".utf8))
    }

    private static func writeAll(_ fd: Int32, _ bytes: [UInt8]) {
        var off = 0
        while off < bytes.count {
            let n = bytes[off...].withUnsafeBytes { write(fd, $0.baseAddress, $0.count) }
            if n < 0 {
                if errno == EINTR || errno == EAGAIN { continue }
                return
            }
            off += n
        }
    }
}
