import Foundation
import VQProtocol

/// Per-connection state (README §7). Internal to the engine.
final class Connection {
    enum Phase {
        /// Waiting for the desktop's `hello`.
        case awaitingHello
        /// Hellos exchanged; the phone does not know the desktop (README §7.2).
        case unpaired
        /// Pairing in progress (README §7.3).
        case pairing(PairingStep)
        /// `K_sess` derived (README §7.4).
        case secure
    }

    enum PairingStep {
        case awaitingChallenge(PairRequest)
        case awaitingCode(PairRequest, PairChallenge, challengeAt: Double)
        case awaitingResult(PairRequest, PairChallenge, PairKey, challengeAt: Double)
    }

    let peer: PeerID
    var splitter = FrameSplitter()
    var reassembler = Reassembler()
    var phase: Phase = .awaitingHello
    /// The desktop's `hello` (exactly one per connection, README §7.1).
    var peerHello: Hello?
    /// Our `hello`'s nonce, kept until the session is established. It is
    /// non-copyable, so it can key at most one session.
    var ownNonce: SessionNonce?
    var cipher: SessionCipher?
    /// Wrong codes on the current challenge (the desktop invalidates at 3).
    var pairFailures = 0

    // Keepalive (README §5.10).
    var nextPingAt: Double = 0
    var unansweredPings = 0

    init(peer: PeerID) { self.peer = peer }

    var deviceId: UUID? { peerHello?.deviceId }

    var isSecure: Bool {
        if case .secure = phase { return true }
        return false
    }

    var isPairing: Bool {
        if case .pairing = phase { return true }
        return false
    }
}
