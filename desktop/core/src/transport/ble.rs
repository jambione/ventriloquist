//! BLE central transport (SPEC §3.1, §6.3) on `btleplug`.
//!
//! * Scans for the Ventriloquist service UUID and connects to **every**
//!   advertising phone.
//! * Per connection: discover services, subscribe to `TX` (notify), write
//!   frames to `RX` **with response**, one frame per write, in order.
//! * `mtu` = negotiated ATT MTU − 3, or 20 when unknown ([`ble_frame_mtu`]).
//! * Reconnects with backoff 1, 2, 4, 8, max 15 s ([`next_attempt_delay`])
//!   whenever a phone disappears, honouring any hold-off the session layer
//!   asked for (idle unpaired drop, `unknown_peer`).
//! * Reports the adapter state: no adapter, powered off, unauthorized,
//!   scanning.
//!
//! The idle-drop decision itself (unpaired, 5 minutes) is made by the
//! session layer, which knows the pairing state ([`super::policy::idle_drop_due`]).
//!
//! Cross-platform: only the portable `btleplug` API is used (CoreBluetooth
//! on macOS, WinRT on Windows). This module cannot be exercised by the
//! automated tests; its decisions live in [`super::policy`], which is tested.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use btleplug::api::{
    Central, CentralEvent, CentralState, Characteristic, Manager as _, Peripheral as _, ScanFilter,
    WriteType,
};
use btleplug::platform::{Adapter, Manager, PeripheralId};
use futures::StreamExt;
use tokio::sync::{mpsc, Notify};
use tokio::task::JoinHandle;
use tokio::time::Instant;
use vq_protocol::{RX_CHAR_UUID, SERVICE_UUID, TX_CHAR_UUID};

use super::policy::{ble_frame_mtu, next_attempt_delay};
use super::{Transport, TransportCommand, TransportEvent};
use crate::events::{AdapterState, PeerId};

/// Timeout for connecting and discovering services.
pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(15);
/// How often to retry getting a usable adapter.
pub const ADAPTER_RETRY: Duration = Duration::from_secs(5);

/// The BLE central transport.
#[derive(Debug, Default, Clone)]
pub struct BleCentralTransport;

impl BleCentralTransport {
    /// A new transport (nothing happens until [`Transport::start`]).
    pub fn new() -> Self {
        Self
    }
}

impl Transport for BleCentralTransport {
    fn start(
        self: Box<Self>,
        commands: mpsc::UnboundedReceiver<TransportCommand>,
        events: mpsc::Sender<TransportEvent>,
    ) -> JoinHandle<()> {
        tokio::spawn(run(commands, events))
    }
}

enum PeerCmd {
    Frames(Vec<Vec<u8>>),
    Close,
}

struct Active {
    peer: PeerId,
    writer: mpsc::UnboundedSender<PeerCmd>,
    abort: Arc<Notify>,
}

#[derive(Default)]
struct Slot {
    active: Option<Active>,
    failures: u32,
    not_before: Option<Instant>,
    holdoff: Option<Duration>,
    /// Ever connected or seen advertising: keep retrying it.
    wanted: bool,
}

/// Sent by a connection task when it ends.
struct Ended {
    pid: PeripheralId,
    was_connected: bool,
}

enum Flow {
    Continue,
    Shutdown,
}

async fn emit(events: &mpsc::Sender<TransportEvent>, state: AdapterState) -> bool {
    events.send(TransportEvent::Adapter(state)).await.is_ok()
}

/// Wait `d`, returning `false` if Shutdown arrived (or the host is gone).
async fn wait_or_shutdown(
    cmds: &mut mpsc::UnboundedReceiver<TransportCommand>,
    d: Duration,
) -> bool {
    let sleep = tokio::time::sleep(d);
    tokio::pin!(sleep);
    loop {
        tokio::select! {
            _ = &mut sleep => return true,
            c = cmds.recv() => match c {
                None | Some(TransportCommand::Shutdown) => return false,
                Some(_) => {}
            },
        }
    }
}

async fn acquire_adapter(
    cmds: &mut mpsc::UnboundedReceiver<TransportCommand>,
    events: &mpsc::Sender<TransportEvent>,
) -> Option<Adapter> {
    loop {
        let state = match Manager::new().await {
            Ok(m) => match m.adapters().await {
                Ok(list) => match list.into_iter().next() {
                    Some(a) => return Some(a),
                    None => AdapterState::NoAdapter,
                },
                Err(e) => error_state(&e),
            },
            Err(e) => error_state(&e),
        };
        if !emit(events, state).await || !wait_or_shutdown(cmds, ADAPTER_RETRY).await {
            return None;
        }
    }
}

fn error_state(e: &btleplug::Error) -> AdapterState {
    log::warn!("bluetooth: {e}");
    match e {
        btleplug::Error::PermissionDenied => AdapterState::Unauthorized,
        btleplug::Error::NoAdapterAvailable => AdapterState::NoAdapter,
        _ => AdapterState::Unknown,
    }
}

async fn run(
    mut cmds: mpsc::UnboundedReceiver<TransportCommand>,
    events: mpsc::Sender<TransportEvent>,
) {
    'adapter: loop {
        let Some(central) = acquire_adapter(&mut cmds, &events).await else {
            return;
        };
        let mut central_events = match central.events().await {
            Ok(s) => s,
            Err(e) => {
                if !emit(&events, error_state(&e)).await
                    || !wait_or_shutdown(&mut cmds, ADAPTER_RETRY).await
                {
                    return;
                }
                continue 'adapter;
            }
        };
        let mut ble = Ble {
            central,
            events: events.clone(),
            slots: HashMap::new(),
            conn_no: 0,
            ended_tx: mpsc::unbounded_channel().0,
            scanning: false,
        };
        let (ended_tx, mut ended_rx) = mpsc::unbounded_channel();
        ble.ended_tx = ended_tx;
        match ble.central.adapter_state().await {
            Ok(state) => {
                if !ble.on_state(state).await {
                    return;
                }
            }
            Err(e) => {
                if !emit(&events, error_state(&e)).await {
                    return;
                }
            }
        }
        let mut timer = tokio::time::interval(Duration::from_secs(1));
        timer.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            tokio::select! {
                ev = central_events.next() => match ev {
                    Some(ev) => {
                        if !ble.on_central_event(ev).await {
                            return;
                        }
                    }
                    None => {
                        // The adapter event stream ended: start over.
                        ble.close_all();
                        if !wait_or_shutdown(&mut cmds, ADAPTER_RETRY).await {
                            return;
                        }
                        continue 'adapter;
                    }
                },
                c = cmds.recv() => {
                    if let Flow::Shutdown = ble.on_command(c) {
                        ble.close_all();
                        let _ = ble.central.stop_scan().await;
                        // Let connection tasks send their final writes and
                        // Disconnected events.
                        let _ = tokio::time::timeout(Duration::from_secs(2), async {
                            while ble.slots.values().any(|s| s.active.is_some()) {
                                match ended_rx.recv().await {
                                    Some(e) => {
                                        if let Some(s) = ble.slots.get_mut(&e.pid) {
                                            s.active = None;
                                        }
                                    }
                                    None => break,
                                }
                            }
                        }).await;
                        return;
                    }
                },
                Some(ended) = ended_rx.recv() => ble.on_ended(ended),
                _ = timer.tick() => ble.retry_due(),
            }
        }
    }
}

struct Ble {
    central: Adapter,
    events: mpsc::Sender<TransportEvent>,
    slots: HashMap<PeripheralId, Slot>,
    conn_no: u64,
    ended_tx: mpsc::UnboundedSender<Ended>,
    scanning: bool,
}

impl Ble {
    async fn on_state(&mut self, state: CentralState) -> bool {
        match state {
            CentralState::PoweredOn => {
                if !self.scanning {
                    match self
                        .central
                        .start_scan(ScanFilter {
                            services: vec![SERVICE_UUID],
                        })
                        .await
                    {
                        Ok(()) => self.scanning = true,
                        Err(e) => return emit(&self.events, error_state(&e)).await,
                    }
                }
                emit(&self.events, AdapterState::Scanning).await
            }
            CentralState::PoweredOff => {
                self.scanning = false;
                emit(&self.events, AdapterState::PoweredOff).await
            }
            CentralState::Unknown => emit(&self.events, AdapterState::Unknown).await,
        }
    }

    async fn on_central_event(&mut self, ev: CentralEvent) -> bool {
        match ev {
            CentralEvent::StateUpdate(state) => return self.on_state(state).await,
            CentralEvent::DeviceDiscovered(id)
            | CentralEvent::DeviceUpdated(id)
            | CentralEvent::ServicesAdvertisement { id, .. } => {
                if self.advertises_service(&id).await {
                    self.slots.entry(id.clone()).or_default().wanted = true;
                    self.try_connect(&id);
                }
            }
            CentralEvent::DeviceDisconnected(id) => {
                if let Some(a) = self.slots.get(&id).and_then(|s| s.active.as_ref()) {
                    a.abort.notify_one();
                }
            }
            _ => {}
        }
        true
    }

    async fn advertises_service(&self, id: &PeripheralId) -> bool {
        // Some platforms ignore the scan filter: check the advertisement.
        match self.central.peripheral(id).await {
            Ok(p) => {
                matches!(p.properties().await, Ok(Some(props)) if props.services.contains(&SERVICE_UUID))
            }
            Err(_) => false,
        }
    }

    fn on_command(&mut self, c: Option<TransportCommand>) -> Flow {
        match c {
            None | Some(TransportCommand::Shutdown) => return Flow::Shutdown,
            Some(TransportCommand::Send { peer, frames }) => {
                if let Some(a) = self.find_active(&peer) {
                    let _ = a.writer.send(PeerCmd::Frames(frames));
                }
            }
            Some(TransportCommand::Disconnect {
                peer,
                reconnect_after,
            }) => {
                if let Some(slot) = self
                    .slots
                    .values_mut()
                    .find(|s| s.active.as_ref().is_some_and(|a| a.peer == peer))
                {
                    slot.holdoff = reconnect_after;
                    if let Some(a) = &slot.active {
                        let _ = a.writer.send(PeerCmd::Close);
                    }
                }
            }
        }
        Flow::Continue
    }

    fn find_active(&self, peer: &str) -> Option<&Active> {
        self.slots
            .values()
            .filter_map(|s| s.active.as_ref())
            .find(|a| a.peer == peer)
    }

    fn close_all(&mut self) {
        for s in self.slots.values() {
            if let Some(a) = &s.active {
                let _ = a.writer.send(PeerCmd::Close);
            }
        }
        self.scanning = false;
    }

    fn on_ended(&mut self, ended: Ended) {
        let now = Instant::now();
        if let Some(slot) = self.slots.get_mut(&ended.pid) {
            slot.active = None;
            slot.failures = if ended.was_connected {
                1
            } else {
                slot.failures.saturating_add(1)
            };
            slot.not_before = Some(now + next_attempt_delay(slot.failures, slot.holdoff.take()));
        }
    }

    fn retry_due(&mut self) {
        let due: Vec<PeripheralId> = self
            .slots
            .iter()
            .filter(|(_, s)| s.wanted && s.active.is_none())
            .filter(|(_, s)| s.not_before.is_none_or(|t| Instant::now() >= t))
            .map(|(id, _)| id.clone())
            .collect();
        for id in due {
            self.try_connect(&id);
        }
    }

    fn try_connect(&mut self, id: &PeripheralId) {
        if !self.scanning {
            return;
        }
        let slot = self.slots.entry(id.clone()).or_default();
        if slot.active.is_some() || slot.not_before.is_some_and(|t| Instant::now() < t) {
            return;
        }
        self.conn_no += 1;
        let peer: PeerId = format!("ble:{id}#{}", self.conn_no);
        let (writer, rx) = mpsc::unbounded_channel();
        let abort = Arc::new(Notify::new());
        slot.active = Some(Active {
            peer: peer.clone(),
            writer,
            abort: abort.clone(),
        });
        let central = self.central.clone();
        let events = self.events.clone();
        let ended = self.ended_tx.clone();
        let pid = id.clone();
        tokio::spawn(async move {
            let was_connected = connection(central, pid.clone(), peer, rx, abort, events).await;
            let _ = ended.send(Ended { pid, was_connected });
        });
    }
}

fn find_char(
    chars: &std::collections::BTreeSet<Characteristic>,
    uuid: uuid::Uuid,
) -> Option<Characteristic> {
    chars
        .iter()
        .find(|c| c.uuid == uuid && c.service_uuid == SERVICE_UUID)
        .cloned()
}

/// One connection. Returns whether it got as far as `Connected`.
async fn connection(
    central: Adapter,
    pid: PeripheralId,
    peer: PeerId,
    mut cmds: mpsc::UnboundedReceiver<PeerCmd>,
    abort: Arc<Notify>,
    events: mpsc::Sender<TransportEvent>,
) -> bool {
    let p = match central.peripheral(&pid).await {
        Ok(p) => p,
        Err(e) => {
            log::debug!("{peer}: {e}");
            return false;
        }
    };
    let setup = async {
        p.connect().await?;
        p.discover_services().await?;
        let chars = p.characteristics();
        let (Some(rx), Some(tx)) = (
            find_char(&chars, RX_CHAR_UUID),
            find_char(&chars, TX_CHAR_UUID),
        ) else {
            return Err(btleplug::Error::NoSuchCharacteristic);
        };
        let notifications = p.notifications().await?;
        p.subscribe(&tx).await?;
        Ok::<_, btleplug::Error>((rx, notifications))
    };
    let (rx_char, mut notifications) = match tokio::time::timeout(CONNECT_TIMEOUT, setup).await {
        Ok(Ok(v)) => v,
        Ok(Err(e)) => {
            log::info!("{peer}: connect failed: {e}");
            let _ = p.disconnect().await;
            return false;
        }
        Err(_) => {
            log::info!("{peer}: connect timed out");
            let _ = p.disconnect().await;
            return false;
        }
    };
    let mtu = ble_frame_mtu(p.mtu());
    if events
        .send(TransportEvent::Connected {
            peer: peer.clone(),
            mtu,
        })
        .await
        .is_err()
    {
        let _ = p.disconnect().await;
        return true;
    }
    let reason = loop {
        tokio::select! {
            n = notifications.next() => match n {
                Some(n) if n.uuid == TX_CHAR_UUID => {
                    if events.send(TransportEvent::Frame { peer: peer.clone(), frame: n.value }).await.is_err() {
                        break "host stopped".to_owned();
                    }
                }
                Some(_) => {}
                None => break "notifications ended".to_owned(),
            },
            c = cmds.recv() => match c {
                Some(PeerCmd::Frames(frames)) => {
                    let mut failed = None;
                    for f in frames {
                        if let Err(e) = p.write(&rx_char, &f, WriteType::WithResponse).await {
                            failed = Some(format!("write failed: {e}"));
                            break;
                        }
                    }
                    if let Some(r) = failed {
                        break r;
                    }
                }
                Some(PeerCmd::Close) | None => break "closed by host".to_owned(),
            },
            _ = abort.notified() => break "peripheral disconnected".to_owned(),
        }
    };
    let _ = p.disconnect().await;
    let _ = events
        .send(TransportEvent::Disconnected { peer, reason })
        .await;
    true
}
