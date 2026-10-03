//! `vq-protocol` — the Ventriloquist wire protocol (SPEC.md §4).
//!
//! Pure library: no I/O, no async, no global state. Layers, bottom-up:
//!
//! * [`framing`] — splits envelopes into MTU-sized frames and reassembles them (§4.2).
//! * [`envelope`] — plaintext / ChaCha20-Poly1305 encrypted envelopes with
//!   per-direction counters and replay rejection (§4.3).
//! * [`message`] — JSON application messages (§4.1, §4.4–4.6).
//! * [`crypto`] — X25519 identity, pairing code, pairing key + MACs, and
//!   session key derivation (§4.4, §4.5).
//!
//! `protocol/README.md` is the normative byte-level description; the
//! vectors in `protocol/vectors/` are authoritative examples.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod b64;
pub mod crypto;
pub mod envelope;
mod error;
pub mod framing;
pub mod message;

pub use crypto::{
    derive_pair_key, derive_session_key, desktop_result_mac, phone_confirm_mac,
    verify_desktop_result_mac, verify_phone_confirm_mac, IdentityKeyPair, PairingCode,
    SharedSecret,
};
pub use envelope::{decode_envelope, encode_plaintext, Direction, Envelope, Role, SessionCipher};
pub use error::{Error, Result};
pub use framing::{FrameSplitter, Reassembler};
pub use message::{
    Ack, ErrorMsg, Hello, HelloUnsupported, Message, PairChallenge, PairConfirm, PairRequest,
    PairResult, Utt, UttState,
};

use uuid::{uuid, Uuid};

/// Protocol version carried in `hello.v`.
pub const PROTOCOL_VERSION: u32 = 1;

/// Maximum size, in bytes, of a decoded message: a reassembled envelope or a
/// JSON message body (64 KiB). Anything strictly larger is rejected.
pub const MAX_MESSAGE_BYTES: usize = 65_536;

/// Maximum length of `utt.text`, in UTF-8 bytes.
pub const MAX_TEXT_BYTES: usize = 32_000;

/// Minimum ATT payload size a [`FrameSplitter`] accepts.
pub const MIN_MTU: usize = 20;

/// Size of the frame header (flags + u16 msg_seq).
pub const FRAME_HEADER_BYTES: usize = 3;

/// Length of every nonce (`nonce_p`, `nonce_d`, `session_nonce`), in bytes.
pub const NONCE_BYTES: usize = 32;

/// Length of an X25519 public or private key, in bytes.
pub const KEY_BYTES: usize = 32;

/// Pairing code lifetime (§4.4 step 3).
pub const PAIR_CODE_TTL_SECS: u64 = 120;

/// Failed `pair_confirm` attempts after which the code is invalidated (§4.4 step 5).
pub const PAIR_MAX_FAILURES: u32 = 3;

/// Keepalive interval (§4.6).
pub const PING_INTERVAL_SECS: u64 = 15;

/// Missed keepalives after which the peer is considered disconnected (§4.6).
pub const PING_MAX_MISSED: u32 = 3;

/// GATT service UUID advertised by the phone (§3.2).
pub const SERVICE_UUID: Uuid = uuid!("77608b26-7b68-49da-bb34-7f05d158e219");

/// GATT `RX` characteristic: Write (with response), desktop → phone (§3.2).
pub const RX_CHAR_UUID: Uuid = uuid!("18489603-21ac-4cf2-9d31-62bd5d9c1635");

/// GATT `TX` characteristic: Notify, phone → desktop (§3.2).
pub const TX_CHAR_UUID: Uuid = uuid!("b01127eb-8819-42a7-a0e8-bdd6159d4e2a");

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn uuids_are_distinct_v4() {
        for u in [SERVICE_UUID, RX_CHAR_UUID, TX_CHAR_UUID] {
            assert_eq!(u.get_version_num(), 4);
        }
        assert_ne!(SERVICE_UUID, RX_CHAR_UUID);
        assert_ne!(SERVICE_UUID, TX_CHAR_UUID);
        assert_ne!(RX_CHAR_UUID, TX_CHAR_UUID);
    }

    #[test]
    fn limits_are_consistent() {
        assert_eq!(MAX_MESSAGE_BYTES, 64 * 1024);
        const { assert!(MIN_MTU > FRAME_HEADER_BYTES) };
        const { assert!(MAX_TEXT_BYTES < MAX_MESSAGE_BYTES) };
    }
}
