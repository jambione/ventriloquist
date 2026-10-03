//! The framework-agnostic event/command API used by the Tauri app (M5) and
//! printed as JSON lines by `vq-host` (see `desktop/core/README.md`).

use std::path::PathBuf;

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::pairing_store::PairedPeer;
use crate::transcript::Entry;

/// Opaque transport-level identifier of one connection to one phone
/// (e.g. `ble:<peripheral id>` or `tcp:127.0.0.1:47800#3`).
pub type PeerId = String;

/// Connection state of one peer (README §7; SPEC §7).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PeerState {
    /// Transport connected, our `hello` sent, waiting for the phone's.
    Connected,
    /// Hellos exchanged, not Secure: waiting for `pair_request`.
    HelloExchanged,
    /// A pairing code is active.
    Pairing,
    /// Session established; encrypted traffic flows.
    Secure,
    /// The connection is gone.
    Closed,
}

/// Bluetooth adapter state (SPEC §6.3), or the TCP transport's equivalent.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AdapterState {
    /// Not yet known.
    Unknown,
    /// No Bluetooth adapter found.
    NoAdapter,
    /// Bluetooth is switched off.
    PoweredOff,
    /// The app is not allowed to use Bluetooth.
    Unauthorized,
    /// Scanning for phones.
    Scanning,
}

/// Why a pairing code stopped being valid.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CodeEndReason {
    /// 120 s elapsed.
    Expired,
    /// 3 wrong `pair_confirm`s.
    TooManyFailures,
    /// The user pressed Cancel.
    Cancelled,
    /// The connection closed.
    Disconnected,
}

/// Events emitted by the core.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(tag = "event", rename_all = "snake_case")]
pub enum HostEvent {
    /// Emitted once at start-up.
    Started {
        /// This desktop's `device_id`.
        device_id: Uuid,
        /// Display name sent in `hello`.
        name: String,
        /// Current log directory.
        log_dir: PathBuf,
        /// Paired phones.
        paired_peers: Vec<PairedPeer>,
    },
    /// An entry was created or changed (a newer revision was accepted).
    EntryUpserted {
        /// The entry after the change.
        entry: Entry,
    },
    /// An entry was evicted from the in-memory store (500-entry cap).
    EntryEvicted {
        /// The evicted entry's id.
        id: Uuid,
    },
    /// A peer's connection state changed.
    ConnectionStatus {
        /// Connection id.
        peer: PeerId,
        /// New state.
        state: PeerState,
        /// The phone's `device_id`, once its `hello` arrived.
        device_id: Option<Uuid>,
        /// The phone's name, once its `hello` arrived.
        name: Option<String>,
        /// Whether our store knows this phone (device id and key match).
        paired: bool,
        /// For `closed` (and protocol rejections): a short machine-readable reason.
        reason: Option<String>,
    },
    /// Show the pairing modal with this code (replaces any previous code).
    PairingCodeShown {
        /// Connection id.
        peer: PeerId,
        /// Requesting phone's `device_id`.
        device_id: Uuid,
        /// Requesting phone's name.
        phone_name: String,
        /// Exactly 6 ASCII digits.
        code: String,
        /// Seconds until expiry (120).
        expires_in_secs: u64,
    },
    /// The code shown for `peer` is no longer valid; close the modal.
    PairingCodeEnded {
        /// Connection id.
        peer: PeerId,
        /// Why.
        reason: CodeEndReason,
    },
    /// Outcome of one `pair_confirm`.
    PairingResult {
        /// Connection id.
        peer: PeerId,
        /// Phone's `device_id`.
        device_id: Option<Uuid>,
        /// Phone's name.
        phone_name: Option<String>,
        /// Whether pairing succeeded.
        ok: bool,
        /// Attempts left on the current code (0 when none is active).
        attempts_remaining: u32,
    },
    /// The set of paired phones changed (pairing, forget).
    PairedPeersChanged {
        /// Paired phones.
        peers: Vec<PairedPeer>,
    },
    /// The peer sent `error{code,msg}` (it will disconnect). `authenticated`
    /// is false for a plaintext error; it never changes pairing state.
    PeerError {
        /// Connection id.
        peer: PeerId,
        /// Error code.
        code: String,
        /// Peer-supplied message (render inertly).
        message: String,
        /// Whether it arrived encrypted.
        authenticated: bool,
    },
    /// Protocol version mismatch: show "Update Ventriloquist on <device>".
    VersionMismatch {
        /// Connection id.
        peer: PeerId,
        /// The device that must be updated (peer name, or this desktop's name).
        device: String,
    },
    /// A frame or message from a peer was dropped (diagnostics only).
    MessageRejected {
        /// Connection id.
        peer: PeerId,
        /// `vq-protocol` error code (`plaintext_not_allowed`, `text_too_long`, …).
        code: String,
    },
    /// The log could not be written. Non-blocking: transcription continues.
    LogWarning {
        /// Human-readable description.
        message: String,
    },
    /// A non-log storage problem (pairing store, config).
    StorageWarning {
        /// Human-readable description.
        message: String,
    },
    /// Bluetooth adapter state.
    AdapterState {
        /// New state.
        state: AdapterState,
    },
    /// Log directory or display name changed.
    ConfigChanged {
        /// Current log directory.
        log_dir: PathBuf,
        /// Current display name.
        name: String,
    },
}

/// Commands accepted by the core. "Clear view" is UI-only and has no command.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "command", rename_all = "snake_case")]
pub enum HostCommand {
    /// Remove a paired phone; any live connection to it is closed.
    ForgetPeer {
        /// Phone's `device_id`.
        device_id: Uuid,
    },
    /// Change (and persist) the log directory.
    SetLogDir {
        /// New directory.
        path: PathBuf,
    },
    /// Change (and persist) the display name; used for future `hello`s.
    SetName {
        /// New name; empty resets to the host name.
        name: String,
    },
    /// Invalidate the active pairing code on `peer`.
    CancelPairing {
        /// Connection id.
        peer: PeerId,
    },
    /// Stop the host.
    Shutdown,
}
