//! Transports: deliver per-peer byte frames and connect/disconnect events.
//!
//! A transport runs as a tokio task. It receives [`TransportCommand`]s and
//! emits [`TransportEvent`]s. Each event for one peer is emitted in order
//! (`Connected`, then `Frame`s, then `Disconnected`), and a [`PeerId`]
//! names one connection: a reconnect gets a new id.

use std::time::Duration;

use tokio::sync::mpsc;
use tokio::task::JoinHandle;

use crate::events::{AdapterState, PeerId};

pub mod policy;

#[cfg(feature = "ble")]
pub mod ble;
#[cfg(all(windows, feature = "ble"))]
pub mod ble_peripheral;
#[cfg(feature = "dev-tcp")]
pub mod tcp;

/// Capacity of the transport → host event channel (back-pressure on
/// a flooding peer).
pub const EVENT_CHANNEL_CAPACITY: usize = 1024;

/// Something that happened on the transport.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TransportEvent {
    /// A phone is connected and subscribed; the host now sends `hello`.
    Connected {
        /// Connection id.
        peer: PeerId,
        /// Frame size limit for frames we send (≥ 20).
        mtu: usize,
    },
    /// One frame from the phone.
    Frame {
        /// Connection id.
        peer: PeerId,
        /// The frame bytes.
        frame: Vec<u8>,
    },
    /// The connection is gone (no more events for this id).
    Disconnected {
        /// Connection id.
        peer: PeerId,
        /// Short description.
        reason: String,
    },
    /// Adapter state changed.
    Adapter(AdapterState),
    /// Advertisements seen since the current scan started (diagnostics).
    DevicesSeen(u64),
    /// A phone advertising our name was found, but it has no Ventriloquist
    /// GATT service (the iPhone app is not in the foreground). The host
    /// clears the hint on the next `Connected`.
    PhoneAppNotOpen,
}

/// Something the host wants the transport to do.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TransportCommand {
    /// Send frames, in order, to one peer (each ≤ that peer's `mtu`).
    Send {
        /// Connection id.
        peer: PeerId,
        /// Frames.
        frames: Vec<Vec<u8>>,
    },
    /// Close the connection after the frames already queued for it.
    /// `reconnect_after` asks the transport not to reconnect to the same
    /// phone sooner than that; `None` means the normal backoff.
    Disconnect {
        /// Connection id.
        peer: PeerId,
        /// Minimum delay before reconnecting to this phone.
        reconnect_after: Option<Duration>,
    },
    /// Close everything and stop.
    Shutdown,
}

/// A transport implementation.
pub trait Transport: Send + 'static {
    /// Start the transport task.
    fn start(
        self: Box<Self>,
        commands: mpsc::UnboundedReceiver<TransportCommand>,
        events: mpsc::Sender<TransportEvent>,
    ) -> JoinHandle<()>;
}

/// The BLE transport for this platform (v2.3): on Windows the GATT
/// peripheral ([`ble_peripheral::BlePeripheralTransport`]), elsewhere the
/// btleplug central. `VQ_BLE_MODE=central|peripheral` overrides it for
/// diagnostics (peripheral only exists on Windows). The choice is logged.
#[cfg(feature = "ble")]
pub fn platform_ble_transport() -> Box<dyn Transport> {
    let env = std::env::var("VQ_BLE_MODE").ok();
    let mode = policy::ble_mode(env.as_deref(), cfg!(windows));
    log::info!("ble: mode {mode:?} (VQ_BLE_MODE={env:?}, windows={})", cfg!(windows));
    match mode {
        #[cfg(all(windows, feature = "ble"))]
        policy::BleMode::Peripheral => Box::new(ble_peripheral::BlePeripheralTransport::new()),
        _ => Box::new(ble::BleCentralTransport::new()),
    }
}
