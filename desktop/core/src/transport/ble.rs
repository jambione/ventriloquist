//! BLE central transport (SPEC §3.1, §6.3) on `btleplug`.
//!
//! * Scans with an **empty** filter (some Windows drivers drop filtered
//!   advertisements) and matches ourselves with [`policy::is_candidate`]: the
//!   service UUID **or** the local name `Ventriloquist` (iOS may put the UUID
//!   in the scan response). Connects to **every** such phone; a name-only
//!   match without the GATT service is dropped for 5 minutes.
//! * Logs (info) the adapter, scan start/stop/errors, every discovered
//!   device (once per id per 60 s), every connect attempt, the services
//!   found, the subscribe result and every error with its Debug text.
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

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use btleplug::api::{
    Central, CentralEvent, CentralState, Characteristic, Manager as _, Peripheral as _,
    PeripheralProperties, ScanFilter, WriteType,
};
use btleplug::platform::{Adapter, Manager, PeripheralId};
use futures::StreamExt;
use tokio::sync::{mpsc, Notify};
use tokio::task::JoinHandle;
use tokio::time::Instant;
use vq_protocol::{RX_CHAR_UUID, SERVICE_UUID, TX_CHAR_UUID};

use super::policy::{
    self, adapter_reacquire_due, ble_frame_mtu, ble_slot_expired, device_log_due,
    next_attempt_delay, poll_wait, scan_retry_due, NAME_ONLY_BLOCK,
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
    /// Matched by local name only (the UUID was not advertised): the GATT
    /// service is verified after connecting.
    name_only: bool,
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
            name_only: false,
        }
    }
}

/// Sent by a connection task when it ends.
struct Ended {
    pid: PeripheralId,
    was_connected: bool,
    /// A name-only match without the Ventriloquist GATT service.
    not_ours: bool,
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

/// The one `Manager` of this transport, created once and kept alive for the
/// whole run (R16). `None` while creating it fails; it is retried then.
async fn acquire_adapter(
    cmds: &mut mpsc::UnboundedReceiver<TransportCommand>,
    events: &mpsc::Sender<TransportEvent>,
    last: &mut Option<AdapterState>,
    manager: &mut Option<Manager>,
) -> Option<Adapter> {
    loop {
        if manager.is_none() {
            match Manager::new().await {
                Ok(m) => *manager = Some(m),
                Err(e) => {
                    if !emit_changed(events, last, error_state(&e)).await
                        || !wait_or_shutdown(cmds, ADAPTER_RETRY).await
                    {
                        return None;
                    }
                    continue;
                }
            }
        }
        let state = match manager.as_ref() {
            Some(m) => match m.adapters().await {
                Ok(list) => match list.into_iter().next() {
                    Some(a) => {
                        match a.adapter_info().await {
                            Ok(info) => log::info!("ble: adapter acquired: {info}"),
                            Err(e) => log::info!("ble: adapter acquired (adapter_info failed: {e:?})"),
                        }
                        return Some(a);
                    }
                    None => AdapterState::NoAdapter,
                },
                Err(e) => error_state(&e),
            },
            None => AdapterState::Unknown,
        };
        if !emit_changed(events, last, state).await
            || !wait_or_shutdown(cmds, ADAPTER_RETRY).await
        {
            return None;
        }
    }
}

fn error_state(e: &btleplug::Error) -> AdapterState {
    log::warn!("ble: bluetooth error: {e} ({e:?})");
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
    let mut manager: Option<Manager> = None;
    'adapter: loop {
        let Some(central) = acquire_adapter(&mut cmds, &events, &mut last_state, &mut manager).await else {
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
            devices_seen: HashSet::new(),
            devices_reported: 0,
            device_logged: HashMap::new(),
            blocked: HashMap::new(),
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
                        ble.stop_scan_logged().await;
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
                    if !ble.flush_seen().await {
                        return;
                    }
                    if scan_retry_due(ble.powered_on, ble.scanning, now - ble.last_scan_attempt)
                        && !ble.start_scan().await
                    {
                        return;
                    }
                    if adapter_reacquire_due(
                        ble.unknown_since.is_some(),
                        ble.scanning,
                        ble.unknown_since.map_or(Duration::ZERO, |t| now - t),
                        ble.live_connections(),
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
        ble.stop_scan_logged().await;
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
    /// Unique peripheral ids seen since the scan started.
    devices_seen: HashSet<PeripheralId>,
    /// Last count sent to the host.
    devices_reported: u64,
    /// When each device was last logged.
    device_logged: HashMap<PeripheralId, Instant>,
    /// Name-only matches that lacked the GATT service: ignored until then.
    blocked: HashMap<PeripheralId, Instant>,
}

/// The scan filter: empty, so nothing is filtered by the OS or the library;
/// matching is done by [`matches_advertisement`].
fn scan_filter() -> ScanFilter {
    ScanFilter { services: Vec::new() }
}

/// The advertised services (merged with `extra`) and local name of a device.
fn advert_parts(props: &PeripheralProperties, extra: &[uuid::Uuid]) -> (Vec<uuid::Uuid>, Option<String>) {
    let mut services = props.services.clone();
    for u in extra {
        if !services.contains(u) {
            services.push(*u);
        }
    }
    let name = props.local_name.clone().or_else(|| props.advertisement_name.clone());
    (services, name)
}

/// Whether a device's advertisement makes it one of ours (the policy code
/// decides).
fn matches_advertisement(props: &PeripheralProperties, extra: &[uuid::Uuid]) -> bool {
    let (services, name) = advert_parts(props, extra);
    policy::is_candidate(&services, name.as_deref())
}

impl Ble {
    async fn emit(&mut self, state: AdapterState) -> bool {
        emit_changed(&self.events, &mut self.last_state, state).await
    }

    /// Try to start scanning; `false` if the host is gone.
    async fn start_scan(&mut self) -> bool {
        self.last_scan_attempt = Instant::now();
        match self.central.start_scan(scan_filter()).await {
            Ok(()) => {
                log::info!("ble: scan started (empty filter; matching by service UUID or local name)");
                self.scanning = true;
                self.devices_seen.clear();
                self.device_logged.clear();
                self.emit(AdapterState::Scanning).await && self.flush_seen().await
            }
            Err(e) => {
                log::warn!("ble: scan start failed: {e:?}");
                let s = error_state(&e);
                self.emit(s).await
            }
        }
    }

    async fn stop_scan_logged(&mut self) {
        match self.central.stop_scan().await {
            Ok(()) => log::info!("ble: scan stopped"),
            Err(e) => log::info!("ble: scan stop failed: {e:?}"),
        }
    }

    /// Tell the host the advertisement count if it changed.
    async fn flush_seen(&mut self) -> bool {
        let count = self.devices_seen.len() as u64;
        if count == self.devices_reported {
            return true;
        }
        self.devices_reported = count;
        self.events
            .send(TransportEvent::DevicesSeen(count))
            .await
            .is_ok()
    }

    async fn on_state(&mut self, state: CentralState) -> bool {
        match state {
            CentralState::PoweredOn => {
                log::info!("ble: adapter powered on");
                self.powered_on = true;
                self.unknown_since = None;
                if self.scanning {
                    self.emit(AdapterState::Scanning).await
                } else {
                    self.start_scan().await
                }
            }
            CentralState::PoweredOff => {
                log::info!("ble: adapter powered off (scan stopped)");
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
            CentralEvent::DeviceDiscovered(id) | CentralEvent::DeviceUpdated(id) => {
                self.on_advertisement(id, &[]).await;
            }
            CentralEvent::ServicesAdvertisement { id, services } => {
                self.on_advertisement(id, &services).await;
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

    /// One advertisement (or update) of `id`: count its id once, log it (once per
    /// minute per device) and, if it is one of ours, mark it wanted and try
    /// to connect.
    async fn on_advertisement(&mut self, id: PeripheralId, extra: &[uuid::Uuid]) {
        policy::note_seen(&mut self.devices_seen, id.clone());
        let props = match self.central.peripheral(&id).await {
            Ok(p) => match p.properties().await {
                Ok(Some(props)) => props,
                Ok(None) => PeripheralProperties::default(),
                Err(e) => {
                    log::info!("ble: properties of {id:?} failed: {e:?}");
                    PeripheralProperties::default()
                }
            },
            Err(e) => {
                log::info!("ble: peripheral {id:?} lookup failed: {e:?}");
                return;
            }
        };
        let (services, name) = advert_parts(&props, extra);
        let candidate = matches_advertisement(&props, extra);
        let now = Instant::now();
        if device_log_due(self.device_logged.get(&id).map(|t| now - *t)) {
            self.device_logged.insert(id.clone(), now);
            log::info!(
                "ble: device {id:?} local_name={name:?} rssi={:?} services={services:?} matched={candidate}",
                props.rssi
            );
        }
        if !candidate {
            return;
        }
        // The block only holds back name-only matches. An advertisement that
        // carries the service UUID means the phone app is (again) in the
        // foreground with its service published, so it clears the block at once.
        let name_only = policy::is_name_only(&services, name.as_deref());
        if name_only && self.blocked.get(&id).is_some_and(|until| now < *until) {
            return;
        }
        self.blocked.remove(&id);
        let slot = self.slots.entry(id.clone()).or_insert_with(|| Slot::new(now));
        slot.wanted = true;
        slot.last_seen = now;
        slot.name_only = name_only;
        self.try_connect(&id);
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

    /// Connection tasks that have not ended yet (each holds this adapter).
    fn live_connections(&self) -> usize {
        self.slots.values().filter(|s| s.active.is_some()).count()
    }

    /// Wait (bounded) until every connection task has ended; tasks still
    /// running after the first wait are aborted and waited for once more, so
    /// no task keeps using the adapter that is about to be replaced.
    async fn drain(&mut self, ended_rx: &mut mpsc::UnboundedReceiver<Ended>) {
        for round in 0..2 {
            let wait = if round == 0 { DRAIN_TIMEOUT } else { DRAIN_TIMEOUT / 2 };
            let _ = tokio::time::timeout(wait, async {
                while self.live_connections() > 0 {
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
            if round == 0 {
                for s in self.slots.values() {
                    if let Some(a) = &s.active {
                        a.abort.trigger("bluetooth adapter restarted");
                    }
                }
            }
        }
    }

    fn on_ended(&mut self, ended: Ended) {
        let now = Instant::now();
        if ended.not_ours {
            log::info!(
                "ble: {:?} advertises our name but has no Ventriloquist service: ignoring it for {} s",
                ended.pid,
                NAME_ONLY_BLOCK.as_secs()
            );
            self.slots.remove(&ended.pid);
            self.blocked.insert(ended.pid, now + NAME_ONLY_BLOCK);
            return;
        }
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
        self.blocked.retain(|_, until| now < *until);
        self.device_logged.retain(|_, t| now - *t < 10 * policy::DEVICE_LOG_INTERVAL);
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
        let hint_events = self.events.clone();
        let ended = self.ended_tx.clone();
        let pid = id.clone();
        let name_only = slot.name_only;
        tokio::spawn(async move {
            let (was_connected, not_ours) =
                connection(central, pid.clone(), peer, rx, abort, events, name_only).await;
            if not_ours {
                // Tell the host before the slot is blocked: the UI says
                // "iPhone found — open Ventriloquist on it".
                let _ = hint_events.send(TransportEvent::PhoneAppNotOpen).await;
            }
            let _ = ended.send(Ended { pid, was_connected, not_ours });
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

/// Whether `VQ_BLE_FORCE_POLL=1` forces polling mode (testing).
fn force_poll() -> bool {
    std::env::var("VQ_BLE_FORCE_POLL").is_ok_and(|v| v == "1")
}

/// Polling mode: read TX; data is delivered and read again at once, an empty
/// value waits [`policy::POLL_IDLE`]. Returns why it stopped (read error or
/// host gone). Cancel-safe: dropping it just abandons the pending read.
async fn poll_loop(
    p: &btleplug::platform::Peripheral,
    tx: &Characteristic,
    events: &mpsc::Sender<TransportEvent>,
    peer: &PeerId,
) -> String {
    loop {
        let data = match tokio::time::timeout(WRITE_TIMEOUT, p.read(tx)).await {
            Ok(Ok(d)) => d,
            Ok(Err(e)) => return format!("poll read failed: {e}"),
            Err(_) => return format!("poll read timed out after {} s", WRITE_TIMEOUT.as_secs()),
        };
        let wait = poll_wait(data.len());
        if !data.is_empty()
            && events
                .send(TransportEvent::Frame { peer: peer.clone(), frame: data })
                .await
                .is_err()
        {
            return "host stopped".to_owned();
        }
        if !wait.is_zero() {
            tokio::time::sleep(wait).await;
        }
    }
}

/// One connection. Returns `(got as far as Connected, name-only match
/// without the Ventriloquist GATT service)`.
async fn connection(
    central: Adapter,
    pid: PeripheralId,
    peer: PeerId,
    cmds: mpsc::Receiver<PeerCmd>,
    abort: Arc<Abort>,
    events: mpsc::Sender<TransportEvent>,
    name_only: bool,
) -> (bool, bool) {
    log::info!("ble: {peer}: connect attempt (name_only={name_only})");
    let p = match central.peripheral(&pid).await {
        Ok(p) => p,
        Err(e) => {
            log::info!("ble: {peer}: peripheral lookup failed: {e:?}");
            return (false, false);
        }
    };
    let not_ours = std::sync::atomic::AtomicBool::new(false);
    let setup = async {
        p.connect().await.inspect_err(|e| log::info!("ble: {peer}: connect error: {e:?}"))?;
        log::info!("ble: {peer}: connected; discovering services");
        p.discover_services()
            .await
            .inspect_err(|e| log::info!("ble: {peer}: discover_services error: {e:?}"))?;
        let services = p.services();
        let listing: Vec<String> = services
            .iter()
            .map(|s| {
                let chars: Vec<String> = s.characteristics.iter().map(|c| c.uuid.to_string()).collect();
                format!("{} [{}]", s.uuid, chars.join(", "))
            })
            .collect();
        log::info!("ble: {peer}: services found: {listing:?}");
        if name_only && !services.iter().any(|s| s.uuid == SERVICE_UUID) {
            not_ours.store(true, std::sync::atomic::Ordering::SeqCst);
            return Err(btleplug::Error::NoSuchCharacteristic);
        }
        let chars = p.characteristics();
        let (Some(rx), Some(tx)) = (
            find_char(&chars, RX_CHAR_UUID),
            find_char(&chars, TX_CHAR_UUID),
        ) else {
            log::info!("ble: {peer}: RX/TX characteristics missing");
            return Err(btleplug::Error::NoSuchCharacteristic);
        };
        let notifications = p
            .notifications()
            .await
            .inspect_err(|e| log::info!("ble: {peer}: notifications error: {e:?}"))?;
        let poll = if force_poll() {
            log::info!("ble: {peer}: polling mode (forced by VQ_BLE_FORCE_POLL)");
            true
        } else {
            match p.subscribe(&tx).await {
                Ok(()) => {
                    log::info!("ble: {peer}: subscribed to TX");
                    false
                }
                Err(e) => {
                    log::info!("ble: {peer}: polling mode (subscribe failed: {e:?})");
                    true
                }
            }
        };
        Ok::<_, btleplug::Error>((rx, tx, notifications, poll))
    };
    let setup = async {
        tokio::select! {
            r = tokio::time::timeout(CONNECT_TIMEOUT, setup) => Some(r),
            _ = abort.notify.notified() => None,
        }
    };
    let (rx_char, tx_char, mut notifications, poll) = match setup.await {
        Some(Ok(Ok(v))) => v,
        Some(Ok(Err(e))) => {
            log::info!("ble: {peer}: connect failed: {e:?}");
            let _ = p.disconnect().await;
            return (false, not_ours.load(std::sync::atomic::Ordering::SeqCst));
        }
        Some(Err(_)) => {
            log::info!("ble: {peer}: connect timed out after {} s", CONNECT_TIMEOUT.as_secs());
            let _ = p.disconnect().await;
            return (false, false);
        }
        None => {
            log::info!("ble: {peer}: connect aborted: {}", abort.reason());
            let _ = p.disconnect().await;
            return (false, false);
        }
    };
    let mtu = ble_frame_mtu(p.mtu());
    log::info!("ble: {peer}: ready (frame mtu {mtu})");
    if events
        .send(TransportEvent::Connected {
            peer: peer.clone(),
            mtu,
        })
        .await
        .is_err()
    {
        let _ = p.disconnect().await;
        return (true, false);
    }
    let mut writer = tokio::spawn(write_loop(p.clone(), rx_char, cmds));
    let poll_peer = peer.clone();
    let poll_fut = async {
        if poll {
            poll_loop(&p, &tx_char, &events, &poll_peer).await
        } else {
            std::future::pending().await
        }
    };
    tokio::pin!(poll_fut);
    let reason = loop {
        tokio::select! {
            r = &mut poll_fut, if poll => break r,
            n = notifications.next(), if !poll => match n {
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
    log::info!("ble: {peer}: disconnected: {reason}");
    writer.abort();
    let _ = p.disconnect().await;
    let _ = events
        .send(TransportEvent::Disconnected { peer, reason })
        .await;
    (true, false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scan_filter_is_empty() {
        assert!(scan_filter().services.is_empty());
    }

    #[test]
    fn matching_uses_the_policy() {
        let mut props = PeripheralProperties::default();
        assert!(!matches_advertisement(&props, &[]));
        props.services = vec![SERVICE_UUID];
        assert!(matches_advertisement(&props, &[]));
        props.services.clear();
        props.local_name = Some(policy::BLE_LOCAL_NAME.to_owned());
        assert!(matches_advertisement(&props, &[]));
        props.local_name = None;
        props.advertisement_name = Some(policy::BLE_LOCAL_NAME.to_owned());
        assert!(matches_advertisement(&props, &[]));
        props.advertisement_name = Some("Other".to_owned());
        assert!(!matches_advertisement(&props, &[]));
        // A services advertisement event carries the UUID itself.
        assert!(matches_advertisement(&props, &[SERVICE_UUID]));
    }
}
