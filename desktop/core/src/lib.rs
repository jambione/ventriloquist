//! `vq-host-core` — the Ventriloquist desktop core (SPEC §7).
//!
//! * [`session::SessionManager`]: per-peer state machine (README §7),
//!   framing, crypto, acks and keepalive.
//! * [`transcript::TranscriptStore`]: entries keyed by id, highest
//!   revision wins, 500-entry cap.
//! * [`logger::Logger`]: append-only daily Markdown log with dedupe.
//! * [`pairing_store::PairingStore`] / [`pairing_store::Identity`]: persisted
//!   peers and this desktop's key.
//! * [`transport`]: the [`transport::Transport`] trait, the BLE central
//!   (feature `ble`, default) and the TCP dev client (feature `dev-tcp`).
//! * [`core::Core`] (sans I/O) and [`host`] (tokio runtime): the
//!   framework-agnostic event/command API ([`events`]).
//!
//! No Tauri dependencies. Uses only the production API of `vq-protocol`.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod clock;
pub mod config;
pub mod core;
pub mod events;
mod fsutil;
pub mod host;
pub mod logger;
pub mod pairing_store;
pub mod session;
pub mod transcript;
pub mod transport;

pub use crate::core::{Core, CoreOptions, CoreOutput};
pub use clock::{Clock, ManualClock, SystemClock};
pub use events::{AdapterState, CodeEndReason, HostCommand, HostEvent, PeerId, PeerState};
pub use host::{spawn_host, HostHandle};
