import Foundation

/// Reconnect backoff for the relay transport (SPEC_V3 §6): 1, 2, 4, 8, then 30 s (as the desktop).
public struct ReconnectBackoff: Equatable, Sendable {
    public let maxDelay: Double
    private(set) public var attempt = 0

    public init(maxDelay: Double = 30) { self.maxDelay = maxDelay }

    /// The delay before the next attempt; advances the schedule.
    public mutating func nextDelay() -> Double {
        let d = attempt < 4 ? min(maxDelay, pow(2, Double(attempt))) : maxDelay
        attempt += 1
        return d
    }

    /// A connection was confirmed: start over.
    public mutating func reset() { attempt = 0 }
}

/// Hold-off after the phone itself drops a relay connection (unknown_peer,
/// pin mismatch, protocol error; R5 X2): 5 s, doubling, capped at 5 min, and
/// reset only when a session became Secure. Stops a reconnect hot loop.
public struct EngineDropBackoff: Equatable, Sendable {
    public let base: Double
    public let maxDelay: Double
    private(set) public var attempt = 0

    public init(base: Double = 5, maxDelay: Double = 300) { self.base = base; self.maxDelay = maxDelay }

    /// The delay before the next reconnect; advances the schedule.
    public mutating func nextDelay() -> Double {
        let d = min(maxDelay, base * pow(2, Double(min(attempt, 20))))
        attempt += 1
        return d
    }

    public mutating func reset() { attempt = 0 }
}
