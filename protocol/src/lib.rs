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
//!
//! # Intended use on a connection
//!
//! 1. Send `hello` built with [`Hello::new`], which draws a fresh
//!    [`crypto::SessionNonce`]. Keep that nonce for this connection only.
//! 2. Decode every reassembled envelope with [`decode_inbound`]. The result
//!    says whether the message was authenticated ([`Inbound::Encrypted`]) or
//!    not ([`Inbound::Plaintext`]). A plaintext `error` is unauthenticated: it
//!    may end the connection but must never change stored pairing state.
//! 3. Pair with [`PairKey::derive`] (both sides, each with its own role).
//! 4. Once both sides know each other, call [`SessionCipher::establish`] with
//!    the nonce from step 1 (consumed) and the peer's `session_nonce`. Never
//!    keep a `SessionCipher` across connections.
//! 5. While Secure, also apply [`check_in_session`] to every decoded message.
//!
//! Raw-key helpers (`SessionCipher::new`, `seal_with`, `derive_pair_key`, …)
//! exist only with the `test-vectors` feature, for vectors and tests.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod b64;
pub mod crypto;
pub mod envelope;
mod error;
pub mod framing;
mod json;
pub mod message;

pub use crypto::{IdentityKeyPair, PairKey, PairingCode, SessionNonce, SharedSecret};
pub use envelope::{
    check_in_session, decode_inbound, encode_plaintext, Direction, Envelope, Inbound, Role,
    SessionCipher,
};
pub use error::{Error, Result};
pub use framing::{FrameSplitter, Reassembler};
pub use message::{
    max_text_prefix, utt_text_fits, Ack, ErrorMsg, Hello, HelloUnsupported, Message, PairChallenge,
    PairConfirm, PairRequest, PairResult, Utt, UttState,
};

use uuid::{uuid, Uuid};

/// Protocol version carried in `hello.v`.
pub const PROTOCOL_VERSION: u32 = 1;

/// Maximum size, in bytes, of a decoded message: a reassembled envelope or a
/// JSON message body (64 KiB). Anything strictly larger is rejected.
pub const MAX_MESSAGE_BYTES: usize = 65_536;

/// Maximum JSON body of an encrypted envelope: 65,536 − 25 bytes of
/// envelope overhead.
pub const MAX_ENCRYPTED_JSON_BYTES: usize = MAX_MESSAGE_BYTES - 25;

/// Maximum nesting depth of objects and arrays in a received JSON document
/// (the outermost object is depth 1). Deeper input is `invalid_json`.
pub const MAX_JSON_DEPTH: usize = 32;

/// Frame size limit (`mtu`) used on the TCP dev transport.
pub const TCP_MTU: usize = 512;

/// Default TCP port of the phone side (the server) of the TCP dev transport.
pub const TCP_DEFAULT_PORT: u16 = 47_800;

/// `mtu` the desktop uses when the negotiated ATT MTU is unknown.
pub const FALLBACK_MTU: usize = MIN_MTU;

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

/// v2.3 reversed roles (Windows hosts): the GATT service the **desktop** hosts
/// as a peripheral; the iPhone is the central. See protocol/README.md §2.3.
pub const HOST_SERVICE_UUID: Uuid = uuid!("63431f70-7c79-402d-8f72-77621879d200");

/// Phone → desktop on the host service: Write (with response).
pub const HOST_RX_CHAR_UUID: Uuid = uuid!("bb4ae2cb-17d6-4a2b-8f54-c8cbe6051923");

/// Desktop → phone on the host service: Notify.
pub const HOST_TX_CHAR_UUID: Uuid = uuid!("ded38a53-a1e3-4113-bb80-f577d057e5f3");

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
        assert_eq!(
            MAX_ENCRYPTED_JSON_BYTES,
            MAX_MESSAGE_BYTES - envelope::MIN_ENCRYPTED_BYTES
        );
    }
}
