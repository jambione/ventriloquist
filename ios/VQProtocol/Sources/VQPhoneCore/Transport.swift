import Foundation

// Transport and clock abstractions for the phone engine.
//
// The engine works on *frames* (README §3): every call to
// `PhoneTransport.send(frame:to:)` carries exactly one frame, which BLE sends
// as one notification and TCP as one `u16 length ‖ frame` record (README §2.1).
// Framing, envelopes and sessions live in the engine, so a new transport only
// has to move frames and report connects and disconnects.

/// Names one *connection* (not one desktop). A reconnect gets a new id, so
/// late events for a closed connection can never be confused with a new one.
public struct PeerID: Hashable, Sendable, CustomStringConvertible {
    public let raw: String
    public init(_ raw: String) { self.raw = raw }
    public var description: String { raw }
}

/// A byte pipe to any number of desktops (the phone is the BLE peripheral or
/// the TCP server, README §2).
///
/// The transport reports events by calling ``PhoneEngine/peerConnected(_:)``,
/// ``PhoneEngine/peerReceived(frame:from:)`` and
/// ``PhoneEngine/peerDisconnected(_:)``, always from the engine's isolation
/// domain (the app uses the main actor).
public protocol PhoneTransport: AnyObject {
    /// Queue one frame for `peer`. Frames to one peer must be delivered in order.
    func send(frame: [UInt8], to peer: PeerID)
    /// Close the connection. The engine has already forgotten it, so the
    /// transport need not (but may) report a disconnect for it.
    func disconnect(_ peer: PeerID)
    /// Usable frame size for `peer` (README §2): `maximumUpdateValueLength` on
    /// BLE, 512 on TCP. Values below 20 are raised to 20 by the engine.
    func mtu(for peer: PeerID) -> Int
    /// A session with `peer` just became Secure (the transport may reset its
    /// reconnect hold-off). Optional: the default does nothing.
    func sessionBecameSecure(_ peer: PeerID)
}

public extension PhoneTransport {
    func sessionBecameSecure(_ peer: PeerID) {}
}

/// What the engine needs from a relay transport: start and stop a room.
/// (``RelayPhoneTransport`` conforms; call from the main actor.)
public protocol RelayRoomControl: AnyObject {
    func startRoom(relayURL: URL, roomId: String, secret: String)
    func stopRoom(roomId: String)
}

/// Time source, injectable for tests.
public protocol PhoneClock: AnyObject {
    /// Monotonic seconds, for timers (throttling, retries, keepalive).
    var now: Double { get }
    /// Wall-clock milliseconds since the Unix epoch, for `utt.ts`.
    var epochMillis: UInt64 { get }
}

/// The real clock.
public final class SystemClock: PhoneClock {
    public init() {}
    public var now: Double { ProcessInfo.processInfo.systemUptime }
    public var epochMillis: UInt64 { UInt64(max(0, Date().timeIntervalSince1970 * 1000)) }
}

/// A clock that only moves when told to (tests, simulators).
public final class ManualClock: PhoneClock {
    public var now: Double
    public var epochMillis: UInt64
    public init(now: Double = 1_000, epochMillis: UInt64 = 1_759_500_000_000) {
        self.now = now
        self.epochMillis = epochMillis
    }
    /// Move both clocks forward by `seconds`.
    public func advance(_ seconds: Double) {
        now += seconds
        epochMillis += UInt64(seconds * 1000)
    }
}

/// The TCP dev transport's record format (README §2.1): `length (u16 BE) ‖ frame`.
/// Pure byte handling, so a TCP server transport (PhoneSim, M4) only adds sockets.
public enum TCPFrameCodec {
    /// Frame size on TCP (README §2.1).
    public static let mtu = 512

    /// Prefix one frame with its length. `nil` if it does not fit in a u16.
    public static func encode(_ frame: [UInt8]) -> [UInt8]? {
        guard frame.count <= Int(UInt16.max) else { return nil }
        return [UInt8(frame.count >> 8), UInt8(frame.count & 0xFF)] + frame
    }

    /// Splits a TCP byte stream back into frames.
    public struct Decoder: Sendable {
        private var buffer: [UInt8] = []
        public init() {}

        /// Feed received bytes; returns every frame that is now complete.
        public mutating func push(_ bytes: some Sequence<UInt8>) -> [[UInt8]] {
            buffer.append(contentsOf: bytes)
            var out: [[UInt8]] = []
            var start = 0
            while buffer.count - start >= 2 {
                let len = Int(buffer[start]) << 8 | Int(buffer[start + 1])
                guard buffer.count - start - 2 >= len else { break }
                out.append(Array(buffer[(start + 2)..<(start + 2 + len)]))
                start += 2 + len
            }
            if start > 0 { buffer.removeFirst(start) }
            return out
        }

        /// Bytes received but not yet part of a complete frame.
        public var pendingByteCount: Int { buffer.count }
    }
}
