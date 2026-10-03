import Foundation

/// Protocol constants (README §2, §8). Mirrors the constants of the Rust crate `vq-protocol`.
public enum VQ {
    /// Protocol version carried in `hello.v`.
    public static let protocolVersion: UInt32 = 1

    /// Maximum size, in bytes, of a reassembled message, an envelope or a JSON
    /// message body (64 KiB). Anything strictly larger is rejected.
    public static let maxMessageBytes = 65_536

    /// Encrypted envelope overhead: kind (1) + counter (8) + tag (16).
    public static let encryptedOverheadBytes = 25

    /// Largest JSON body that fits an encrypted envelope (65,536 − 25).
    public static let maxEncryptedJSONBytes = maxMessageBytes - encryptedOverheadBytes

    /// Maximum nesting depth of objects and arrays in received JSON (outermost = 1).
    public static let maxJSONDepth = 32

    /// Maximum `utt.text` length, in UTF-8 bytes.
    public static let maxTextBytes = 32_000

    /// Worst-case encoded `utt` with empty text (README §5.8).
    public static let uttMaxOverheadBytes = 126

    /// Minimum frame size (`mtu`) a splitter accepts, and the desktop fallback.
    public static let minMTU = 20

    /// `mtu` the desktop uses when the negotiated ATT MTU is unknown.
    public static let fallbackMTU = minMTU

    /// Frame size used on the TCP dev transport.
    public static let tcpMTU = 512

    /// Default TCP port of the phone side (the server) of the TCP dev transport.
    public static let tcpDefaultPort: UInt16 = 47_800

    /// Frame header size (flags + u16 msg_seq).
    public static let frameHeaderBytes = 3

    /// Length of every nonce (`nonce_p`, `nonce_d`, `session_nonce`).
    public static let nonceBytes = 32

    /// Length of an X25519 key, `K_pair`, `K_sess` and a MAC.
    public static let keyBytes = 32

    /// Pairing code lifetime, in seconds.
    public static let pairCodeTTLSeconds: UInt64 = 120

    /// Failed `pair_confirm` verifications after which the code is invalidated.
    public static let pairMaxFailures = 3

    /// Keepalive interval, in seconds.
    public static let pingIntervalSeconds: UInt64 = 15

    /// Missed keepalives after which the peer is treated as disconnected.
    public static let pingMaxMissed = 3

    /// GATT service UUID advertised by the phone.
    public static let serviceUUID = UUID(uuidString: "77608b26-7b68-49da-bb34-7f05d158e219")!

    /// GATT `RX` characteristic: Write (with response), desktop → phone.
    public static let rxCharacteristicUUID = UUID(uuidString: "18489603-21ac-4cf2-9d31-62bd5d9c1635")!

    /// GATT `TX` characteristic: Notify, phone → desktop.
    public static let txCharacteristicUUID = UUID(uuidString: "b01127eb-8819-42a7-a0e8-bdd6159d4e2a")!
}
