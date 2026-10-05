//! `vq-host-core` — the Ventriloquist desktop core (SPEC §7).
//!
//! * [`session::SessionManager`]: per-peer state machine (README §7),
//!   framing, crypto, acks and keepalive.
//! * [`transcript::TranscriptStore`]: entries keyed by id, highest
//!   revision wins, 500-entry cap.
//! * [`logger::Logger`]: append-only daily Markdown log with dedupe.
//! * [`pairing_store::PairingStore`] / [`pairing_store::Identity`]: persisted
//!   peers and this desktop's key.
//! * [`transport`]: the [`transport::Transport`] trait, the cloud relay
//!   transport (feature `relay`, default; SPEC_V3) and the TCP dev client
//!   (feature `dev-tcp`).
//! * [`relay_room`] / [`pairing_uri`]: the relay room this desktop owns and
//!   the QR payload (SPEC_V3 §3, §5).
//! * [`core::Core`] (sans I/O) and [`host`] (tokio runtime): the
//!   framework-agnostic event/command API ([`events`]); file writes run on
//!   the [`io_worker`] thread and events leave through the coalescing
//!   [`outbox`].
//! * [`pairing_guard`]: pairing rate limits and lockout.
//!
//! No Tauri dependencies. Uses only the production API of `vq-protocol`.
//!
//! The `dev-tcp` feature (TCP dev transport) is refused in release builds:
//! it must never ship in the app (docs/SPEC_QUESTIONS.md D14).

// Unsafe code is only allowed in the OS proxy bindings (`transport::proxy::sys`).
#![deny(unsafe_code)]
#![warn(missing_docs)]

#[cfg(all(feature = "dev-tcp", not(debug_assertions)))]
compile_error!(
    "feature `dev-tcp` (unauthenticated TCP dev transport) must not be enabled in release builds; \
     build the tests and `vq-host` in debug, and never enable `dev-tcp` for the app"
);

pub mod clock;
pub mod config;
pub mod core;
pub mod events;
mod fsutil;
pub mod host;
pub mod io_worker;
pub mod logger;
pub mod outbox;
pub mod pairing_guard;
pub mod pairing_store;
pub mod pairing_uri;
pub mod relay_room;
pub mod session;
pub mod transcript;
pub mod transport;

pub use crate::core::{Core, CoreOptions, CoreOutput};
pub use clock::{Clock, ManualClock, SystemClock};
pub use events::{
    CodeEndReason, HostCommand, HostEvent, PeerId, PeerState, RelayLink, RelayReason, RelayStatus,
};
pub use host::{spawn_host, spawn_host_with_io, HostHandle};
