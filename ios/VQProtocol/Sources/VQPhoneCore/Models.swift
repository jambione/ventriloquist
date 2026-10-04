import Foundation

/// Where a desktop stands from the phone's point of view.
public enum HostLinkState: Equatable, Sendable {
    /// Paired, not connected.
    case offline
    /// Connected and identified, not paired (README §7.2 pairing state).
    case unpaired
    /// A pairing exchange is in progress on this connection.
    case pairing
    /// Session established: utterances can flow.
    case secure
}

/// One row of the host list: identified connected desktops ∪ remembered
/// paired desktops that are offline (SPEC §3.1).
public struct HostInfo: Identifiable, Equatable, Sendable {
    /// The desktop's `device_id`.
    public let id: UUID
    public let name: String
    /// The phone *knows* this desktop (stored `device_id` and `pub` match, or
    /// a stored record when offline).
    public let isPaired: Bool
    /// Connected and has sent its `hello`.
    public let isOnline: Bool
    public let state: HostLinkState
    public let isActive: Bool
    /// The desktop answered our `paired:true` with `unknown_peer` (README
    /// §7.2 row 3). The record is kept; the user may Forget it and pair again.
    public let notRecognized: Bool
    /// A record with this `device_id` exists but the online desktop shows a
    /// different key: it must be paired again (README §7.1).
    public let keyChanged: Bool
}

/// The header status dot (SPEC §5.1).
public enum ConnectionIndicator: Equatable, Sendable {
    /// No active desktop (grey).
    case none
    /// An active desktop that is not (yet) secure (amber).
    case connecting
    /// The active desktop is connected and secure (green).
    case secure
}

/// Delivery of one utterance's latest `final`/`edit` (SPEC §5.1 History).
public enum DeliveryStatus: String, Equatable, Sendable, Codable {
    case pending
    case acked
    case failed
}

/// The phone-side pairing flow shown by the code-entry sheet.
public struct PairingStatus: Equatable, Sendable {
    public enum Phase: Equatable, Sendable {
        /// `pair_request` sent; waiting for the desktop's challenge.
        case requesting
        /// Waiting for the user to type the 6-digit code. `error` explains the
        /// previous failed attempt, if any.
        case enterCode(error: String?)
        /// `pair_confirm` sent; waiting for `pair_result`.
        case verifying
        /// Paired; the desktop is now active.
        case succeeded
        /// Pairing ended; the sheet should show `message` and let the user close.
        case failed(message: String)
    }

    public let hostId: UUID
    public internal(set) var hostName: String
    public var phase: Phase
    /// Extra information, e.g. "A new code is shown on <desktop>".
    public var note: String?
}

/// Discrete things the UI should react to.
public enum PhoneEvent: Equatable, Sendable {
    /// The delivery status of utterance `id` changed.
    case deliveryChanged(id: UUID, status: DeliveryStatus)
    /// The utterance reached the size limit (README §5.8). Its `final` with the
    /// truncated `text` has been queued; the UI should stop recording.
    case utteranceLimitReached(id: UUID, text: String)
    /// Pairing with `hostId` succeeded.
    case paired(hostId: UUID, name: String)
    /// A user-visible problem with a desktop.
    case notice(PhoneNotice)
}

public enum PhoneNotice: Equatable, Sendable {
    /// Versions differ. `updatePhone` says which side is old: `true` when the
    /// desktop reported `error{version}`, `false` when its `hello.v` ≠ 1.
    case versionMismatch(hostName: String?, updatePhone: Bool)
    /// The desktop no longer knows this phone (`unknown_peer`).
    case notRecognized(hostId: UUID, hostName: String)
    /// The desktop refused, e.g. `rate_limited` or `busy`, or another code.
    case peerError(hostName: String?, code: String, message: String)
    /// Three pings in a row went unanswered.
    case keepaliveTimeout(hostName: String)
    /// The pairing was made but could not be saved.
    case storageFailed

    /// Text for an alert or banner.
    public var text: String {
        switch self {
        case .versionMismatch(let name, let updatePhone):
            if updatePhone { return "Update Ventriloquist on this iPhone" }
            return "Update Ventriloquist on \(name ?? "the desktop")"
        case .notRecognized(_, let name):
            return "\(name) does not recognise this iPhone. Forget it and pair again."
        case .peerError(let name, let code, let message):
            let who = name ?? "The desktop"
            switch code {
            case "rate_limited": return "\(who) is refusing pairing attempts for now. Try again later."
            case "busy": return "\(who) is busy with another pairing. Try again later."
            case "bad_mac": return "\(who) rejected the pairing (verification failed)."
            case "decrypt_failed": return "\(who) could not decrypt a message; the connection was reset."
            case "protocol": return "\(who) reported a protocol error; the connection was reset."
            default:
                return message.isEmpty ? "\(who) reported an error (\(code))." : "\(who): \(message) (\(code))"
            }
        case .keepaliveTimeout(let name):
            return "Lost contact with \(name)."
        case .storageFailed:
            return "The pairing could not be saved. It works until you disconnect."
        }
    }
}
