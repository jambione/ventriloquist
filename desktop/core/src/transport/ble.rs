//! BLE central transport (SPEC §3.1, §6.3) on `btleplug`.
//!
//! * Scans for the Ventriloquist service UUID and connects to **every**
//!   advertising phone.
//! * Per connection: discover services, subscribe to `TX` (notify), write
//!   frames to `RX` **with response**, one frame per write, in order.
//! * `mtu` = negotiated ATT MTU − 3, or 20 when unknown ([`ble_frame_mtu`]).
//! * Reconnects with backoff 1, 2, 4, 8, max 15 s ([`next_attempt_delay`])
//!   whenever a phone disappears, honouring any hold-off the session layer
//!   asked for (idle unpaired drop, `unknown_peer`, pairing refusal).
//! * Reports the adapter state: no adapter, powered off, unauthorized,
//!   scanning (only changes are reported).
//!
//! Robustness (docs/SPEC_QUESTIONS.md D12, D13):
//! * Writes run in a per-connection writer task fed by a bounded queue
//!   ([`SEND_QUEUE_CAPACITY`]); a full queue or a write slower than
//!   [`WRITE_TIMEOUT`] disconnects the phone, so notifications, closes and
//!   aborts are never stuck behind a write.
//! * Peripheral slots that are neither connected nor seen advertising for
//!   [`super::policy::BLE_SLOT_TTL`] are forgotten (rotating addresses).
//! * A failed `start_scan` is retried every second while the adapter is
//!   on; while the adapter state stays unknown (e.g. permission not yet
//!   granted) the adapter is re-acquired every few seconds.
//! * When the adapter is restarted, connection tasks are drained (each
//!   reports `Disconnected`) before the new adapter is used.
//!
//! The idle-drop decision itself (unpaired, 5 minutes) is made by the
//! session layer, which knows the pairing state ([`super::policy::idle_drop_due`]).
//!
//! Cross-platform: only the portable `btleplug` API is used (CoreBluetooth
//! on macOS, WinRT on Windows). This module cannot be exercised by the
//! automated tests; its decisions live in [`super::policy`], which is tested.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
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

use super::policy::{
    adapter_reacquire_due, ble_frame_mtu, ble_slot_expired, next_attempt_delay, scan_retry_due,
};
use super::{Transport, TransportCommand, TransportEvent};
use crate::events::{AdapterState, PeerId};

/// Timeout for connecting and discovering services.
pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(15);
/// How often to retry getting a usable adapter.
pub const ADAPTER_RETRY: Duration = Duration::from_secs(5);
/// Longest time one frame write (with response) may take.
pub const WRITE_TIMEOUT: Duration = Duration::from_secs(10);
/// Queued `Send` batches per connection before the phone is disconnected.
pub const SEND_QUEUE_CAPACITY: usize = 64;
/// How long to wait for connection tasks to end on shutdown or restart.
pub const DRAIN_TIMEOUT: Duration = Duration::from_secs(2);

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

/// Ends a connection from outside, with a reason.
#[derive(Default)]
struct Abort {
    notify: Notify,
    reason: Mutex<Option<String>>,
}

impl Abort {
    fn trigger(&self, reason: &str) {
        let mut r = self.reason.lock().unwrap_or_else(|e| e.into_inner());
        r.get_or_insert_with(|| reason.to_owned());
        self.notify.notify_one();
    }

    fn reason(&self) -> String {
        self.reason
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
            .unwrap_or_else(|| "aborted".to_owned())
    }
}

struct Active {
    peer: PeerId,
    writer: mpsc::Sender<PeerCmd>,
    abort: Arc<Abort>,
}

struct Slot {
    active: Option<Active>,
    failures: u32,
    not_before: Option<Instant>,
    holdoff: Option<Duration>,
    /// Ever connected or seen advertising: keep retrying it.
    wanted: bool,
    /// Last advertisement or end of connection.
    last_seen: Instant,
}

impl Slot {
    fn new(now: Instant) -> Self {
        Self {
            active: None,
            failures: 0,
            not_before: None,
            holdoff: None,
            wanted: false,
            last_seen: now,
        }
    }
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
    last: &mut Option<AdapterState>,
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
        if !emit_changed(events, last, state).await
            || !wait_or_shutdown(cmds, ADAPTER_RETRY).await
        {
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

/// Emit `state` if it differs from the last one emitted. `false` if the
/// host is gone.
async fn emit_changed(
    events: &mpsc::Sender<TransportEvent>,
    last: &mut Option<AdapterState>,
    state: AdapterState,
) -> bool {
    if *last == Some(state) {
        return true;
    }
    *last = Some(state);
    events.send(TransportEvent::Adapter(state)).await.is_ok()
}

async fn run(
    mut cmds: mpsc::UnboundedReceiver<TransportCommand>,
    events: mpsc::Sender<TransportEvent>,
) {
    let mut last_state = None;
    'adapter: loop {
        let Some(central) = acquire_adapter(&mut cmds, &events, &mut last_state).await else {
            return;
        };
        let mut central_events = match central.events().await {
            Ok(s) => s,
            Err(e) => {
                if !emit_changed(&events, &mut last_state, error_state(&e)).await
                    || !wait_or_shutdown(&mut cmds, ADAPTER_RETRY).await
                {
                    return;
                }
                continue 'adapter;
            }
        };
        let (ended_tx, mut ended_rx) = mpsc::unbounded_channel();
        let now = Instant::now();
        let mut ble = Ble {
            central,
            events: events.clone(),
            last_state,
            slots: HashMap::new(),
            conn_no: 0,
            ended_tx,
            scanning: false,
            powered_on: false,
            unknown_since: Some(now),
            last_scan_attempt: now,
        };
        let initial = match ble.central.adapter_state().await {
            Ok(state) => ble.on_state(state).await,
            Err(e) => {
                let s = error_state(&e);
                ble.emit(s).await
            }
        };
        if !initial {
            return;
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
                    // The adapter event stream ended: start over.
                    None => break,
                },
                c = cmds.recv() => {
                    if let Flow::Shutdown = ble.on_command(c) {
                        ble.close_all();
                        let _ = ble.central.stop_scan().await;
                        // Let connection tasks send their final writes and
                        // Disconnected events.
                        ble.drain(&mut ended_rx).await;
                        return;
                    }
                },
                Some(ended) = ended_rx.recv() => ble.on_ended(ended),
                _ = timer.tick() => {
                    let now = Instant::now();
                    ble.expire_slots(now);
                    ble.retry_due(now);
                    if scan_retry_due(ble.powered_on, ble.scanning, now - ble.last_scan_attempt)
                        && !ble.start_scan().await
                    {
                        return;
                    }
                    if adapter_reacquire_due(
                        ble.unknown_since.is_some(),
                        ble.scanning,
                        ble.unknown_since.map_or(Duration::ZERO, |t| now - t),
                    ) {
                        log::info!("bluetooth state still unknown: re-acquiring the adapter");
                        break;
                    }
                }
            }
        }
        // Restart: end every connection (each reports Disconnected) before
        // the new adapter is used.
        ble.close_all();
        let _ = ble.central.stop_scan().await;
        ble.drain(&mut ended_rx).await;
        last_state = ble.last_state;
        if !wait_or_shutdown(&mut cmds, ADAPTER_RETRY).await {
            return;
        }
    }
}

struct Ble {
    central: Adapter,
    events: mpsc::Sender<TransportEvent>,
    last_state: Option<AdapterState>,
    slots: HashMap<PeripheralId, Slot>,
    conn_no: u64,
    ended_tx: mpsc::UnboundedSender<Ended>,
    scanning: bool,
    powered_on: bool,
    /// Since when the adapter state has been unknown (None when known).
    unknown_since: Option<Instant>,
    last_scan_attempt: Instant,
}

impl Ble {
    async fn emit(&mut self, state: AdapterState) -> bool {
        emit_changed(&self.events, &mut self.last_state, state).await
    }

    /// Try to start scanning; `false` if the host is gone.
    async fn start_scan(&mut self) -> bool {
        self.last_scan_attempt = Instant::now();
        match self
            .central
            .start_scan(ScanFilter {
                services: vec![SERVICE_UUID],
            })
            .await
        {
            Ok(()) => {
                self.scanning = true;
                self.emit(AdapterState::Scanning).await
            }
            Err(e) => {
                let s = error_state(&e);
                self.emit(s).await
            }
        }
    }

    async fn on_state(&mut self, state: CentralState) -> bool {
        match state {
            CentralState::PoweredOn => {
                self.powered_on = true;
                self.unknown_since = None;
                if self.scanning {
                    self.emit(AdapterState::Scanning).await
                } else {
                    self.start_scan().await
                }
            }
            CentralState::PoweredOff => {
                self.powered_on = false;
                self.scanning = false;
                self.unknown_since = None;
                self.emit(AdapterState::PoweredOff).await
            }
            CentralState::Unknown => {
                self.powered_on = false;
                self.unknown_since.get_or_insert_with(Instant::now);
                self.emit(AdapterState::Unknown).await
            }
        }
    }

    async fn on_central_event(&mut self, ev: CentralEvent) -> bool {
        match ev {
            CentralEvent::StateUpdate(state) => return self.on_state(state).await,
            CentralEvent::DeviceDiscovered(id)
            | CentralEvent::DeviceUpdated(id)
            | CentralEvent::ServicesAdvertisement { id, .. } => {
                if self.advertises_service(&id).await {
                    let now = Instant::now();
                    let slot = self.slots.entry(id.clone()).or_insert_with(|| Slot::new(now));
                    slot.wanted = true;
                    slot.last_seen = now;
                    self.try_connect(&id);
                }
            }
            CentralEvent::DeviceDisconnected(id) => {
                if let Some(a) = self.slots.get(&id).and_then(|s| s.active.as_ref()) {
                    a.abort.trigger("peripheral disconnected");
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
                    if a.writer.try_send(PeerCmd::Frames(frames)).is_err() {
                        a.abort.trigger("send queue full (phone not reading)");
                    }
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
                        if a.writer.try_send(PeerCmd::Close).is_err() {
                            a.abort.trigger("closed by host");
                        }
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
                if a.writer.try_send(PeerCmd::Close).is_err() {
                    a.abort.trigger("closed by host");
                }
            }
        }
        self.scanning = false;
    }

    /// Wait (bounded) until every connection task has ended.
    async fn drain(&mut self, ended_rx: &mut mpsc::UnboundedReceiver<Ended>) {
        let _ = tokio::time::timeout(DRAIN_TIMEOUT, async {
            while self.slots.values().any(|s| s.active.is_some()) {
                match ended_rx.recv().await {
                    Some(e) => {
                        if let Some(s) = self.slots.get_mut(&e.pid) {
                            s.active = None;
                        }
                    }
                    None => break,
                }
            }
        })
        .await;
        for s in self.slots.values() {
            if let Some(a) = &s.active {
                a.abort.trigger("bluetooth adapter restarted");
            }
        }
    }

    fn on_ended(&mut self, ended: Ended) {
        let now = Instant::now();
        if let Some(slot) = self.slots.get_mut(&ended.pid) {
            slot.active = None;
            slot.last_seen = now;
            slot.failures = if ended.was_connected {
                1
            } else {
                slot.failures.saturating_add(1)
            };
            slot.not_before = Some(now + next_attempt_delay(slot.failures, slot.holdoff.take()));
        }
    }

    fn expire_slots(&mut self, now: Instant) {
        self.slots
            .retain(|_, s| !ble_slot_expired(s.active.is_some(), now - s.last_seen));
    }

    fn retry_due(&mut self, now: Instant) {
        let due: Vec<PeripheralId> = self
            .slots
            .iter()
            .filter(|(_, s)| s.wanted && s.active.is_none())
            .filter(|(_, s)| s.not_before.is_none_or(|t| now >= t))
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
        let now = Instant::now();
        let slot = self.slots.entry(id.clone()).or_insert_with(|| Slot::new(now));
        if slot.active.is_some() || slot.not_before.is_some_and(|t| now < t) {
            return;
        }
        self.conn_no += 1;
        let peer: PeerId = format!("ble:{id}#{}", self.conn_no);
        let (writer, rx) = mpsc::channel(SEND_QUEUE_CAPACITY);
        let abort = Arc::new(Abort::default());
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

/// Write queued frames in order (each within [`WRITE_TIMEOUT`]); returns
/// why it stopped.
async fn write_loop(
    p: btleplug::platform::Peripheral,
    rx_char: Characteristic,
    mut queue: mpsc::Receiver<PeerCmd>,
) -> String {
    loop {
        match queue.recv().await {
            Some(PeerCmd::Frames(frames)) => {
                for f in frames {
                    match tokio::time::timeout(
                        WRITE_TIMEOUT,
                        p.write(&rx_char, &f, WriteType::WithResponse),
                    )
                    .await
                    {
                        Ok(Ok(())) => {}
                        Ok(Err(e)) => return format!("write failed: {e}"),
                        Err(_) => {
                            return format!("write timed out after {} s", WRITE_TIMEOUT.as_secs())
                        }
                    }
                }
            }
            Some(PeerCmd::Close) | None => return "closed by host".to_owned(),
        }
    }
}

/// One connection. Returns whether it got as far as `Connected`.
async fn connection(
    central: Adapter,
    pid: PeripheralId,
    peer: PeerId,
    cmds: mpsc::Receiver<PeerCmd>,
    abort: Arc<Abort>,
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
    let setup = async {
        tokio::select! {
            r = tokio::time::timeout(CONNECT_TIMEOUT, setup) => Some(r),
            _ = abort.notify.notified() => None,
        }
    };
    let (rx_char, mut notifications) = match setup.await {
        Some(Ok(Ok(v))) => v,
        Some(Ok(Err(e))) => {
            log::info!("{peer}: connect failed: {e}");
            let _ = p.disconnect().await;
            return false;
        }
        Some(Err(_)) => {
            log::info!("{peer}: connect timed out");
            let _ = p.disconnect().await;
            return false;
        }
        None => {
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
    let mut writer = tokio::spawn(write_loop(p.clone(), rx_char, cmds));
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
            w = &mut writer => break w.unwrap_or_else(|_| "writer stopped".to_owned()),
            _ = abort.notify.notified() => break abort.reason(),
        }
    };
    writer.abort();
    let _ = p.disconnect().await;
    let _ = events
        .send(TransportEvent::Disconnected { peer, reason })
        .await;
    true
}
