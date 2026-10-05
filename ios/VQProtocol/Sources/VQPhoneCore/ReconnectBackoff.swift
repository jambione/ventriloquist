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
