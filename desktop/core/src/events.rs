//! The framework-agnostic event/command API used by the Tauri app (M5) and
//! printed as JSON lines by `vq-host` (see `desktop/core/README.md`).

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize, Serializer};
use uuid::Uuid;

use crate::pairing_store::PairedPeer;
use crate::transcript::Entry;

/// Paths are serialized lossily (invalid UTF-8 becomes U+FFFD), so an
/// event can always be serialized.
fn lossy_path<S: Serializer>(p: &Path, s: S) -> Result<S::Ok, S::Error> {
    s.serialize_str(&p.to_string_lossy())
}

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
        #[serde(serialize_with = "lossy_path")]
        log_dir: PathBuf,
        /// Paired phones.
        paired_peers: Vec<PairedPeer>,
    },
    /// The complete current state, in answer to [`HostCommand::Snapshot`]
    /// (e.g. after a UI reload).
    Snapshot {
        /// This desktop's `device_id`.
        device_id: Uuid,
        /// Display name sent in `hello`.
        name: String,
        /// Current log directory.
        #[serde(serialize_with = "lossy_path")]
        log_dir: PathBuf,
        /// Paired phones.
        paired_peers: Vec<PairedPeer>,
        /// Last reported adapter state.
        adapter_state: AdapterState,
        /// Advertisements seen since the current scan started.
        devices_seen: u64,
        /// Live connections.
        peers: Vec<PeerStatus>,
        /// Transcript entries, oldest first.
        entries: Vec<Entry>,
        /// Latest log-write warning while the log is failing, else `None`
        /// (`log_warning` is only emitted on the transition).
        log_warning: Option<String>,
    },
    /// An entry was created or changed (a newer revision was accepted).
    EntryUpserted {
        /// The entry after the change.
        entry: Entry,
    },
    /// The first `final` for an utterance id was accepted: emitted exactly
    /// once per id, right after its `entry_upserted`. Never emitted for
    /// partials, edits, duplicate or stale revisions, ids evicted from the
    /// transcript, or a `final` the log's dedupe index (arrival day and the
    /// day before) already holds (re-delivery after a restart). It fires
    /// when the I/O worker takes the log job, not when the write succeeds:
    /// a failing or deferred log write does not delay or suppress it.
    /// The outbox never coalesces or drops it. Intended as the only
    /// trigger for automatic delivery of text.
    FinalAccepted {
        /// The entry (state `final`).
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
    /// The log could not be written. Non-blocking: transcription continues
    /// and failed entries are retried.
    LogWarning {
        /// Human-readable description.
        message: String,
    },
    /// Every entry that failed to be logged has now been written: clear
    /// the log warning banner.
    LogRecovered,
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
    /// Advertisements seen since the current scan started (at most once per
    /// second, latest wins).
    DevicesSeen {
        /// The count.
        count: u64,
    },
    /// Log directory or display name changed (in effect for this run).
    ConfigChanged {
        /// Current log directory.
        #[serde(serialize_with = "lossy_path")]
        log_dir: PathBuf,
        /// Current display name.
        name: String,
        /// Whether the change was saved to `config.json` (if not, a
        /// `storage_warning` says why and it is lost on restart).
        persisted: bool,
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
    /// Change (and persist) the log directory. It must be absolute;
    /// otherwise the command is refused with a `storage_warning`.
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
    /// Ask for a [`HostEvent::Snapshot`] of the current state.
    Snapshot,
    /// Stop the host.
    Shutdown,
}

/// One live connection, as reported in [`HostEvent::Snapshot`].
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct PeerStatus {
    /// Connection id.
    pub peer: PeerId,
    /// State.
    pub state: PeerState,
    /// The phone's `device_id`, once its `hello` arrived.
    pub device_id: Option<Uuid>,
    /// The phone's name, once its `hello` arrived.
    pub name: Option<String>,
    /// Whether our store knows this phone.
    pub paired: bool,
    /// The pairing code shown for this connection, if one is active.
    pub pairing: Option<PairingStatus>,
}

/// An active pairing code (for restoring the modal).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PairingStatus {
    /// Exactly 6 ASCII digits.
    pub code: String,
    /// Requesting phone's name.
    pub phone_name: String,
    /// Seconds until expiry.
    pub expires_in_secs: u64,
}
