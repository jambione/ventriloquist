import Foundation
import Testing
import VQProtocol
@testable import VQPhoneCore

@Suite struct PairingURITests {
    static let key = Base64URL.encode([UInt8](repeating: 7, count: 32))
    static let base: [(String, String)] = [
        ("v", "3"), ("r", "https://relay.example.com"), ("room", "abcdefghijklmnop_-ABCD"),
        ("s", "0123456789abcdefABCDEF_-0123456789"), ("d", "123E4567-E89B-12D3-A456-426614174000"),
        ("k", key), ("c", "123456"), ("n", "Work PC"),
    ]

    static func uri(_ edit: (inout [(String, String)]) -> Void = { _ in }) -> String {
        var p = base
        edit(&p)
        var c = URLComponents()
        c.scheme = "vq"; c.host = "pair"
        c.queryItems = p.map { URLQueryItem(name: $0.0, value: $0.1) }
        return c.string!
    }

    static func replacing(_ k: String, _ v: String) -> String {
        uri { $0 = $0.map { $0.0 == k ? (k, v) : $0 } }
    }

    static func removing(_ k: String) -> String { uri { $0.removeAll { $0.0 == k } } }

    @Test func parsesValid() throws {
        let u = try PairingURI.parse(Self.uri())
        #expect(u.relayURL.absoluteString == "https://relay.example.com")
        #expect(u.roomId == "abcdefghijklmnop_-ABCD")
        #expect(u.desktopDeviceId == UUID(uuidString: "123E4567-E89B-12D3-A456-426614174000"))
        #expect(u.desktopPublicKey.bytes == [UInt8](repeating: 7, count: 32))
        #expect(u.code == "123456")
        #expect(u.name == "Work PC")
        #expect(RelayDesktop(u).peer == RelayTransport.peerID(roomId: u.roomId))
    }

    @Test func parsesWithWhitespaceAndMissingName() throws {
        let u = try PairingURI.parse("  " + Self.removing("n") + "\n")
        #expect(u.name == "Desktop")
    }

    @Test func notAPairingLink() {
        for s in ["", "hello", "https://relay.example.com", "vq://other?v=3", "vq://pair"] {
            if s == "vq://pair" {
                #expect(throws: PairingURIError.missing("v")) { try PairingURI.parse(s) }
            } else {
                #expect(throws: PairingURIError.notAPairingLink) { try PairingURI.parse(s) }
            }
        }
    }

    @Test func wrongVersion() {
        for v in ["2", "4", "03"] {
            #expect(throws: PairingURIError.unsupportedVersion) { try PairingURI.parse(Self.replacing("v", v)) }
        }
    }

    @Test func missingFields() {
        for k in ["v", "r", "room", "s", "d", "k", "c"] {
            #expect(throws: PairingURIError.missing(k)) { try PairingURI.parse(Self.removing(k)) }
            #expect(throws: PairingURIError.missing(k)) { try PairingURI.parse(Self.replacing(k, "")) }
        }
    }

    @Test func malformedFields() {
        let bad: [(String, String)] = [
            ("r", "ftp://relay.example.com"), ("r", "not a url"), ("r", "https://"),
            ("room", "short"), ("room", String(repeating: "a", count: 65)), ("room", "abcdefghijklmnop!!"),
            ("s", "tooshort"), ("s", String(repeating: "a", count: 129)), ("s", "abcdefghijklmnopq rst"),
            ("d", "not-a-uuid"),
            ("k", "AAAA"), ("k", "***"), ("k", Base64URL.encode([UInt8](repeating: 1, count: 31))),
            ("c", "12345"), ("c", "1234567"), ("c", "12345a"),
        ]
        for (k, v) in bad {
            #expect(throws: PairingURIError.invalid(k), "\(k)=\(v)") { try PairingURI.parse(Self.replacing(k, v)) }
        }
    }

    @Test func duplicateField() {
        #expect(throws: PairingURIError.invalid("duplicate c")) {
            try PairingURI.parse(Self.uri() + "&c=654321")
        }
    }

    @Test func base64URLRoundTrip() {
        for n in 0..<8 {
            let b = (0..<n).map { UInt8(truncatingIfNeeded: $0 * 37 + 200) }
            #expect(Base64URL.decode(Base64URL.encode(b)) == Data(b))
        }
        #expect(Base64URL.decode("A") == nil)
    }
}
