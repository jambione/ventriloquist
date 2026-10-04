//! Windows BLE **peripheral** transport (SPEC_V2 v2.3, protocol README §2.3).
//!
//! On iOS 26.1+ the iPhone refuses app-level GATT access from non-Apple
//! centrals, so on Windows the roles are reversed: the PC is the GATT
//! peripheral and the iPhone is the central.
//!
//! * A WinRT `GattServiceProvider` publishes [`HOST_SERVICE_UUID`] with
//!   `H_RX` (Write with response, protection Plain) and `H_TX` (Notify,
//!   protection Plain) and advertises it (connectable, discoverable).
//! * Each client that subscribes to `H_TX` becomes a peer: a `Connected`
//!   event with `mtu = MaxPduSize − 3` (cap 512, [`peripheral_frame_mtu`]),
//!   after which the core sends `hello` (same as the central transport).
//!   Writes to `H_RX` from that client's session are its frames; every write
//!   request is answered. Frames to the phone are `NotifyValueForSubscribedClientAsync(value,
//!   client)`, in order, from a per-peer writer task with a bounded queue
//!   ([`SEND_QUEUE_CAPACITY`]); a full queue or a notification slower than
//!   [`WRITE_TIMEOUT`] drops the peer. Unsubscribing or closing the GATT
//!   session is a disconnect.
//! * WinRT cannot disconnect a central, so a dropped client that is still
//!   subscribed is ignored until it unsubscribes (`ClientBook`).
//! * Not supported by the adapter ([`AdapterState::PeripheralUnsupported`]),
//!   radio off, or an aborted advertisement are reported as adapter states;
//!   a failed or aborted advertisement restarts with backoff
//!   ([`advertising_restart_delay`]).
//!
//! Everything is logged at info. All WinRT use is in this file; no `unsafe`
//! is needed. Cannot be exercised by the automated tests on macOS: its
//! decisions (client bookkeeping, MTU, backoff) live in [`super::policy`].

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::sync::{mpsc, Notify};
use tokio::task::JoinHandle;
use tokio::time::Instant;
use vq_protocol::{HOST_RX_CHAR_UUID, HOST_SERVICE_UUID, HOST_TX_CHAR_UUID};
use windows::core::{Error, Result as WinResult, GUID};
use windows::Devices::Bluetooth::BluetoothAdapter;
use windows::Devices::Bluetooth::BluetoothError;
use windows::Devices::Bluetooth::GenericAttributeProfile::{
    GattCharacteristicProperties, GattClientNotificationResult, GattCommunicationStatus, GattLocalCharacteristic,
    GattLocalCharacteristicParameters, GattProtocolError, GattProtectionLevel,
    GattServiceProvider, GattServiceProviderAdvertisementStatus,
    GattServiceProviderAdvertisementStatusChangedEventArgs,
    GattServiceProviderAdvertisingParameters, GattSessionStatus, GattSessionStatusChangedEventArgs,
    GattSession, GattSubscribedClient, GattWriteOption, GattWriteRequestedEventArgs,
};
use windows::core::IInspectable;
use windows::Foundation::TypedEventHandler;
use windows_future::AsyncOperationCompletedHandler;
use windows::Storage::Streams::{DataReader, DataWriter, IBuffer};

use super::policy::{
    advertising_failures_after, advertising_restart_delay, peripheral_frame_mtu, ClientBook,
    MAX_BACKOFF,
};
use super::{Transport, TransportCommand, TransportEvent};
use crate::events::{AdapterState, PeerId};

/// Longest time one notification may take before the peer is dropped.
pub const WRITE_TIMEOUT: Duration = Duration::from_secs(10);
/// Queued `Send` batches per peer before it is dropped.
pub const SEND_QUEUE_CAPACITY: usize = 64;

/// The Windows BLE peripheral transport.
#[derive(Debug, Default, Clone)]
pub struct BlePeripheralTransport;

impl BlePeripheralTransport {
    /// A new transport (nothing happens until [`Transport::start`]).
    pub fn new() -> Self {
        Self
    }
}

impl Transport for BlePeripheralTransport {
    fn start(
        self: Box<Self>,
        commands: mpsc::UnboundedReceiver<TransportCommand>,
        events: mpsc::Sender<TransportEvent>,
    ) -> JoinHandle<()> {
        tokio::spawn(run(commands, events))
    }
}

/// Messages from WinRT callbacks and peer tasks to the main loop. `gen` is
/// the provider generation: events of an older provider are ignored.
enum Ev {
    /// The subscribed-client list of `H_TX` changed.
    Resync { gen: u64 },
    /// A client's GATT session closed.
    ClientGone { gen: u64, device: String },
    /// The advertisement aborted (or stopped by itself).
    AdvertisingEnded { gen: u64, status: String },
    /// A peer's writer task ended.
    PeerEnded { peer: PeerId, reason: String },
}

enum PeerCmd {
    Frames(Vec<Vec<u8>>),
    Close,
}

/// Ends a peer from outside, with a reason.
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

struct PeerRec {
    writer: mpsc::Sender<PeerCmd>,
    abort: Arc<Abort>,
    session: GattSession,
    session_token: i64,
}

impl Drop for PeerRec {
    fn drop(&mut self) {
        let _ = self.session.RemoveSessionStatusChanged(self.session_token);
    }
}

/// The published GATT service. Dropping it stops advertising and removes
/// the event handlers.
struct Provider {
    gen: u64,
    service: GattServiceProvider,
    rx: GattLocalCharacteristic,
    tx: GattLocalCharacteristic,
    write_token: i64,
    subscribed_token: i64,
    status_token: i64,
}

impl Drop for Provider {
    fn drop(&mut self) {
        let _ = self.service.StopAdvertising();
        let _ = self.rx.RemoveWriteRequested(self.write_token);
        let _ = self.tx.RemoveSubscribedClientsChanged(self.subscribed_token);
        let _ = self.service.RemoveAdvertisementStatusChanged(self.status_token);
    }
}

/// Why a provider could not be started.
struct StartError {
    state: AdapterState,
    /// Wait this long before trying again (None: the normal backoff).
    retry_after: Option<Duration>,
    text: String,
}

impl StartError {
    fn new(state: AdapterState, text: impl Into<String>) -> Self {
        Self { state, retry_after: None, text: text.into() }
    }
}

fn guid(u: uuid::Uuid) -> GUID {
    GUID::from_u128(u.as_u128())
}

fn bt_error_state(e: BluetoothError) -> AdapterState {
    if e == BluetoothError::RadioNotAvailable || e == BluetoothError::DisabledByUser {
        AdapterState::PoweredOff
    } else if e == BluetoothError::DisabledByPolicy || e == BluetoothError::ConsentRequired {
        AdapterState::Unauthorized
    } else if e == BluetoothError::NotSupported || e == BluetoothError::TransportNotSupported {
        AdapterState::PeripheralUnsupported
    } else {
        AdapterState::Unknown
    }
}

fn device_id(session: &GattSession) -> WinResult<String> {
    Ok(session.DeviceId()?.Id()?.to_string())
}

fn read_buffer(buf: &IBuffer) -> WinResult<Vec<u8>> {
    let len = buf.Length()? as usize;
    let mut out = vec![0u8; len];
    if len > 0 {
        DataReader::FromBuffer(buf)?.ReadBytes(&mut out)?;
    }
    Ok(out)
}

fn make_buffer(bytes: &[u8]) -> WinResult<IBuffer> {
    let w = DataWriter::new()?;
    w.WriteBytes(bytes)?;
    w.DetachBuffer()
}

/// Create the service, its characteristics and the handlers, and start
/// advertising.
async fn start_provider(
    gen: u64,
    ev_tx: &mpsc::UnboundedSender<Ev>,
    events: &mpsc::Sender<TransportEvent>,
    book: &Arc<tokio::sync::Mutex<ClientBook>>,
) -> Result<Provider, StartError> {
    let unknown = |what: &str, e: Error| StartError::new(AdapterState::Unknown, format!("{what}: {e}"));

    let adapter = BluetoothAdapter::GetDefaultAsync()
        .map_err(|e| unknown("GetDefaultAsync", e))?
        .await
        .map_err(|e| unknown("GetDefaultAsync", e))?;
    let supported = adapter
        .IsPeripheralRoleSupported()
        .map_err(|e| unknown("IsPeripheralRoleSupported", e))?;
    log::info!(
        "ble-peripheral: adapter present, IsPeripheralRoleSupported={supported}, IsLowEnergySupported={:?}",
        adapter.IsLowEnergySupported()
    );
    if !supported {
        return Err(StartError {
            state: AdapterState::PeripheralUnsupported,
            retry_after: Some(MAX_BACKOFF),
            text: "the Bluetooth adapter does not support the peripheral role".to_owned(),
        });
    }

    let created = GattServiceProvider::CreateAsync(guid(HOST_SERVICE_UUID))
        .map_err(|e| unknown("GattServiceProvider::CreateAsync", e))?
        .await
        .map_err(|e| unknown("GattServiceProvider::CreateAsync", e))?;
    let err = created.Error().map_err(|e| unknown("provider Error", e))?;
    if err != BluetoothError::Success {
        return Err(StartError::new(
            bt_error_state(err),
            format!("GattServiceProvider::CreateAsync failed: BluetoothError({})", err.0),
        ));
    }
    let service = created.ServiceProvider().map_err(|e| unknown("ServiceProvider", e))?;
    let gatt = service.Service().map_err(|e| unknown("Service", e))?;

    let rx_params = GattLocalCharacteristicParameters::new().map_err(|e| unknown("params", e))?;
    rx_params
        .SetCharacteristicProperties(GattCharacteristicProperties::Write)
        .and_then(|()| rx_params.SetWriteProtectionLevel(GattProtectionLevel::Plain))
        .map_err(|e| unknown("H_RX params", e))?;
    let rx = char_result(
        gatt.CreateCharacteristicAsync(guid(HOST_RX_CHAR_UUID), &rx_params)
            .map_err(|e| unknown("CreateCharacteristicAsync(H_RX)", e))?
            .await,
        "H_RX",
    )?;

    let tx_params = GattLocalCharacteristicParameters::new().map_err(|e| unknown("params", e))?;
    tx_params
        .SetCharacteristicProperties(GattCharacteristicProperties::Notify)
        .and_then(|()| tx_params.SetReadProtectionLevel(GattProtectionLevel::Plain))
        .map_err(|e| unknown("H_TX params", e))?;
    let tx = char_result(
        gatt.CreateCharacteristicAsync(guid(HOST_TX_CHAR_UUID), &tx_params)
            .map_err(|e| unknown("CreateCharacteristicAsync(H_TX)", e))?
            .await,
        "H_TX",
    )?;

    // Handlers (they run on WinRT threadpool threads).
    let write_token = {
        let events = events.clone();
        let book = book.clone();
        rx.WriteRequested(&TypedEventHandler::new(
            move |_sender: windows::core::Ref<GattLocalCharacteristic>,
                  args: windows::core::Ref<GattWriteRequestedEventArgs>| {
                if let Some(args) = args.as_ref() {
                    on_write_requested(args, &events, &book);
                }
                Ok(())
            },
        ))
        .map_err(|e| unknown("WriteRequested", e))?
    };
    let subscribed_token = {
        let ev_tx = ev_tx.clone();
        tx.SubscribedClientsChanged(&TypedEventHandler::new(
            move |_sender: windows::core::Ref<GattLocalCharacteristic>,
                  _args: windows::core::Ref<IInspectable>| {
                let _ = ev_tx.send(Ev::Resync { gen });
                Ok(())
            },
        ))
        .map_err(|e| unknown("SubscribedClientsChanged", e))?
    };
    let status_token = {
        let ev_tx = ev_tx.clone();
        service
            .AdvertisementStatusChanged(&TypedEventHandler::new(
                move |_sender: windows::core::Ref<GattServiceProvider>,
                      args: windows::core::Ref<GattServiceProviderAdvertisementStatusChangedEventArgs>| {
                    if let Some(a) = args.as_ref() {
                        let status = a.Status()?;
                        log::info!("ble-peripheral: advertisement status {}", status_name(status));
                        if status == GattServiceProviderAdvertisementStatus::Aborted
                            || status == GattServiceProviderAdvertisementStatus::Stopped
                        {
                            let _ = ev_tx.send(Ev::AdvertisingEnded {
                                gen,
                                status: status_name(status),
                            });
                        }
                    }
                    Ok(())
                },
            ))
            .map_err(|e| unknown("AdvertisementStatusChanged", e))?
    };

    let provider = Provider { gen, service, rx, tx, write_token, subscribed_token, status_token };

    let adv = GattServiceProviderAdvertisingParameters::new().map_err(|e| unknown("adv params", e))?;
    adv.SetIsConnectable(true)
        .and_then(|()| adv.SetIsDiscoverable(true))
        .map_err(|e| unknown("adv params", e))?;
    provider
        .service
        .StartAdvertisingWithParameters(&adv)
        .map_err(|e| unknown("StartAdvertising", e))?;
    log::info!(
        "ble-peripheral: advertising service {HOST_SERVICE_UUID} (H_RX {HOST_RX_CHAR_UUID} write, H_TX {HOST_TX_CHAR_UUID} notify; connectable, discoverable); status {}",
        provider
            .service
            .AdvertisementStatus()
            .map(status_name)
            .unwrap_or_else(|e| format!("?({e})"))
    );
    Ok(provider)
}

fn status_name(s: GattServiceProviderAdvertisementStatus) -> String {
    if s == GattServiceProviderAdvertisementStatus::Created {
        "Created".into()
    } else if s == GattServiceProviderAdvertisementStatus::Stopped {
        "Stopped".into()
    } else if s == GattServiceProviderAdvertisementStatus::Started {
        "Started".into()
    } else if s == GattServiceProviderAdvertisementStatus::Aborted {
        "Aborted".into()
    } else if s == GattServiceProviderAdvertisementStatus::StartedWithoutAllAdvertisementData {
        "StartedWithoutAllAdvertisementData".into()
    } else {
        format!("Unknown({})", s.0)
    }
}

fn char_result(
    r: WinResult<windows::Devices::Bluetooth::GenericAttributeProfile::GattLocalCharacteristicResult>,
    name: &str,
) -> Result<GattLocalCharacteristic, StartError> {
    let fail = |e: Error| StartError::new(AdapterState::Unknown, format!("{name}: {e}"));
    let r = r.map_err(fail)?;
    let err = r.Error().map_err(fail)?;
    if err != BluetoothError::Success {
        return Err(StartError::new(
            bt_error_state(err),
            format!("creating {name} failed: BluetoothError({})", err.0),
        ));
    }
    r.Characteristic().map_err(fail)
}

/// `H_RX` write handler (WinRT thread). Always responds to a write that
/// asks for a response, with a protocol error on any failure; the frame is
/// delivered to the host while the client book is locked so that it can
/// never overtake `Connected` or follow `Disconnected`.
fn on_write_requested(
    args: &GattWriteRequestedEventArgs,
    events: &mpsc::Sender<TransportEvent>,
    book: &Arc<tokio::sync::Mutex<ClientBook>>,
) {
    let deferral = args.GetDeferral();
    let request = args.GetRequestAsync().and_then(|op| op.join());
    let request = match request {
        Ok(r) => r,
        Err(e) => {
            log::info!("ble-peripheral: GetRequestAsync failed: {e}");
            if let Ok(d) = deferral {
                let _ = d.Complete();
            }
            return;
        }
    };
    let with_response = request
        .Option()
        .map(|o| o == GattWriteOption::WriteWithResponse)
        .unwrap_or(true);
    let result = (|| -> Result<(), String> {
        let device = args
            .Session()
            .and_then(|s| device_id(&s))
            .map_err(|e| format!("session lookup failed: {e}"))?;
        let data = request
            .Value()
            .and_then(|b| read_buffer(&b))
            .map_err(|e| format!("reading the value failed: {e}"))?;
        let book = book.blocking_lock();
        let Some(peer) = book.peer_for(&device) else {
            return Err(format!("write from {device}, which is not subscribed to H_TX"));
        };
        if data.is_empty() {
            return Ok(());
        }
        events
            .blocking_send(TransportEvent::Frame { peer: peer.to_owned(), frame: data })
            .map_err(|_| "host stopped".to_owned())
    })();
    let responded = match &result {
        Ok(()) => {
            if with_response {
                request.Respond()
            } else {
                Ok(())
            }
        }
        Err(why) => {
            log::info!("ble-peripheral: rejecting an H_RX write: {why}");
            if with_response {
                GattProtocolError::UnlikelyError().and_then(|c| request.RespondWithProtocolError(c))
            } else {
                Ok(())
            }
        }
    };
    if let Err(e) = responded {
        log::info!("ble-peripheral: responding to an H_RX write failed: {e}");
    }
    if let Ok(d) = deferral {
        let _ = d.Complete();
    }
}

/// Send one frame as a notification to one client.
async fn notify(
    tx: &GattLocalCharacteristic,
    client: &GattSubscribedClient,
    frame: &[u8],
) -> Result<(), String> {
    let (done_tx, done_rx) = tokio::sync::oneshot::channel::<Result<i32, String>>();
    start_notify(tx, client, frame, done_tx)?;
    let status = done_rx
        .await
        .map_err(|_| "notify: completion lost".to_owned())??;
    if status == GattCommunicationStatus::Success.0 {
        Ok(())
    } else {
        Err(format!("notify status {status}"))
    }
}

/// Start the notification; the result (the status code) goes to `done_tx`.
fn start_notify(
    tx: &GattLocalCharacteristic,
    client: &GattSubscribedClient,
    frame: &[u8],
    done_tx: tokio::sync::oneshot::Sender<Result<i32, String>>,
) -> Result<(), String> {
    let buf = make_buffer(frame).map_err(|e| format!("buffer: {e}"))?;
    let op = tx
        .NotifyValueForSubscribedClientAsync(&buf, client)
        .map_err(|e| format!("notify: {e}"))?;
    // The WinRT async future is not `Send`; a completion handler feeding a
    // oneshot channel is, and needs no unsafe.
    let done_tx = Mutex::new(Some(done_tx));
    op.SetCompleted(&AsyncOperationCompletedHandler::new(move |op, _status| {
        let r = match op.as_ref() {
            Some(op) => op
                .GetResults()
                .and_then(|r: GattClientNotificationResult| r.Status())
                .map(|s| s.0)
                .map_err(|e| format!("notify: {e}")),
            None => Err("notify: no result".to_owned()),
        };
        if let Some(t) = done_tx.lock().unwrap_or_else(|e| e.into_inner()).take() {
            let _ = t.send(r);
        }
        Ok(())
    }))
    .map_err(|e| format!("notify: {e}"))
}

/// Notify queued frames in order (each within [`WRITE_TIMEOUT`]); returns why
/// it stopped.
async fn write_loop(
    tx: GattLocalCharacteristic,
    client: GattSubscribedClient,
    mut queue: mpsc::Receiver<PeerCmd>,
) -> String {
    loop {
        match queue.recv().await {
            Some(PeerCmd::Frames(frames)) => {
                for f in frames {
                    match tokio::time::timeout(WRITE_TIMEOUT, notify(&tx, &client, &f)).await {
                        Ok(Ok(())) => {}
                        Ok(Err(e)) => return format!("notification failed: {e}"),
                        Err(_) => {
                            return format!(
                                "notification timed out after {} s",
                                WRITE_TIMEOUT.as_secs()
                            )
                        }
                    }
                }
            }
            Some(PeerCmd::Close) | None => return "closed by host".to_owned(),
        }
    }
}

struct Main {
    events: mpsc::Sender<TransportEvent>,
    ev_tx: mpsc::UnboundedSender<Ev>,
    book: Arc<tokio::sync::Mutex<ClientBook>>,
    provider: Option<Provider>,
    started_at: Instant,
    gen: u64,
    failures: u32,
    retry_at: Option<Instant>,
    peers: HashMap<PeerId, PeerRec>,
    last_state: Option<AdapterState>,
}

impl Main {
    async fn emit_state(&mut self, state: AdapterState) {
        if self.last_state != Some(state) {
            self.last_state = Some(state);
            log::info!("ble-peripheral: adapter state {state:?}");
            let _ = self.events.send(TransportEvent::Adapter(state)).await;
        }
    }

    async fn try_start(&mut self) {
        self.gen += 1;
        match start_provider(self.gen, &self.ev_tx, &self.events, &self.book).await {
            Ok(p) => {
                self.provider = Some(p);
                self.started_at = Instant::now();
                self.retry_at = None;
                self.emit_state(AdapterState::Advertising).await;
            }
            Err(e) => {
                self.failures = advertising_failures_after(self.failures, Duration::ZERO);
                let delay = e
                    .retry_after
                    .unwrap_or_else(|| advertising_restart_delay(self.failures));
                log::info!(
                    "ble-peripheral: cannot advertise ({}); state {:?}; retrying in {} s",
                    e.text,
                    e.state,
                    delay.as_secs()
                );
                self.retry_at = Some(Instant::now() + delay);
                self.emit_state(e.state).await;
            }
        }
    }

    /// Forget a peer and tell the host. Does not touch the client book.
    async fn end_peer(&mut self, peer: &str, reason: &str) {
        if let Some(rec) = self.peers.remove(peer) {
            rec.abort.trigger(reason);
            log::info!("ble-peripheral: {peer}: disconnected ({reason})");
            let _ = self
                .events
                .send(TransportEvent::Disconnected { peer: peer.to_owned(), reason: reason.to_owned() })
                .await;
        }
    }

    /// End every peer (provider gone or shutdown).
    async fn end_all(&mut self, reason: &str) {
        let book_arc = self.book.clone();
        let mut book = book_arc.lock().await;
        *book = ClientBook::new();
        let ids: Vec<PeerId> = self.peers.keys().cloned().collect();
        for id in ids {
            self.end_peer(&id, reason).await;
        }
    }

    async fn resync(&mut self) {
        let Some(provider) = &self.provider else { return };
        let clients: Vec<GattSubscribedClient> = match provider.tx.SubscribedClients() {
            Ok(list) => list.into_iter().collect(),
            Err(e) => {
                log::info!("ble-peripheral: SubscribedClients failed: {e}");
                return;
            }
        };
        let mut by_device: HashMap<String, GattSubscribedClient> = HashMap::new();
        for c in clients {
            match c.Session().and_then(|s| device_id(&s)) {
                Ok(d) => {
                    by_device.insert(d, c);
                }
                Err(e) => log::info!("ble-peripheral: a subscribed client has no session: {e}"),
            }
        }
        let devices: Vec<String> = by_device.keys().cloned().collect();
        let tx = provider.tx.clone();
        let gen = provider.gen;
        let book_arc = self.book.clone();
        let mut book = book_arc.lock().await;
        let diff = book.sync(&devices);
        for (device, peer) in diff.removed {
            log::info!("ble-peripheral: {device} unsubscribed from H_TX");
            self.end_peer(&peer, "client unsubscribed").await;
        }
        for (device, peer) in diff.added {
            let Some(client) = by_device.remove(&device) else { continue };
            if let Err(e) = self.add_peer(&mut book, gen, &tx, &device, &peer, client).await {
                log::info!("ble-peripheral: {peer}: cannot accept {device}: {e}");
                book.ban_peer(&peer);
            }
        }
    }

    async fn add_peer(
        &mut self,
        _book: &mut ClientBook,
        gen: u64,
        tx: &GattLocalCharacteristic,
        device: &str,
        peer: &str,
        client: GattSubscribedClient,
    ) -> WinResult<()> {
        let session = client.Session()?;
        let pdu = session.MaxPduSize().unwrap_or(0);
        let mtu = peripheral_frame_mtu(pdu);
        let session_token = {
            let ev_tx = self.ev_tx.clone();
            let device = device.to_owned();
            session.SessionStatusChanged(&TypedEventHandler::new(
                move |_s: windows::core::Ref<GattSession>,
                      args: windows::core::Ref<GattSessionStatusChangedEventArgs>| {
                    if let Some(a) = args.as_ref() {
                        if a.Status()? == GattSessionStatus::Closed {
                            let _ = ev_tx.send(Ev::ClientGone { gen, device: device.clone() });
                        }
                    }
                    Ok(())
                },
            ))?
        };
        log::info!(
            "ble-peripheral: {peer}: {device} subscribed to H_TX (MaxPduSize {pdu}, mtu {mtu}, MaxNotificationSize {:?})",
            client.MaxNotificationSize()
        );
        let (writer, queue) = mpsc::channel(SEND_QUEUE_CAPACITY);
        let abort = Arc::new(Abort::default());
        self.peers.insert(
            peer.to_owned(),
            PeerRec { writer, abort: abort.clone(), session, session_token },
        );
        let _ = self
            .events
            .send(TransportEvent::Connected { peer: peer.to_owned(), mtu })
            .await;
        let ev_tx = self.ev_tx.clone();
        let tx = tx.clone();
        let peer = peer.to_owned();
        tokio::spawn(async move {
            let reason = tokio::select! {
                r = write_loop(tx, client, queue) => r,
                _ = abort.notify.notified() => abort.reason(),
            };
            let _ = ev_tx.send(Ev::PeerEnded { peer, reason });
        });
        Ok(())
    }

    /// A peer ended on its own (write failure, timeout, host close).
    async fn peer_ended(&mut self, peer: &str, reason: &str) {
        if !self.peers.contains_key(peer) {
            return;
        }
        let book_arc = self.book.clone();
        let mut book = book_arc.lock().await;
        book.ban_peer(peer);
        self.end_peer(peer, reason).await;
    }

    async fn client_gone(&mut self, device: &str) {
        let book_arc = self.book.clone();
        let mut book = book_arc.lock().await;
        if let Some(peer) = book.remove(device) {
            log::info!("ble-peripheral: {device}: GATT session closed");
            self.end_peer(&peer, "GATT session closed").await;
        }
    }

    /// The advertisement ended without us stopping it: drop the provider
    /// and restart with backoff.
    async fn advertising_ended(&mut self, status: &str) {
        log::info!("ble-peripheral: advertisement {status}; restarting");
        self.end_all(&format!("advertisement {status}")).await;
        self.provider = None;
        self.failures = advertising_failures_after(self.failures, self.started_at.elapsed());
        let delay = advertising_restart_delay(self.failures);
        log::info!("ble-peripheral: restarting advertising in {} s", delay.as_secs());
        self.retry_at = Some(Instant::now() + delay);
        self.emit_state(AdapterState::Unknown).await;
    }

    fn command(&mut self, cmd: TransportCommand) -> bool {
        match cmd {
            TransportCommand::Send { peer, frames } => {
                if let Some(rec) = self.peers.get(&peer) {
                    if rec.writer.try_send(PeerCmd::Frames(frames)).is_err() {
                        rec.abort.trigger("send queue full");
                    }
                }
            }
            TransportCommand::Disconnect { peer, .. } => {
                if let Some(rec) = self.peers.get(&peer) {
                    if rec.writer.try_send(PeerCmd::Close).is_err() {
                        rec.abort.trigger("closed by host");
                    }
                }
            }
            TransportCommand::Shutdown => return false,
        }
        true
    }
}

async fn run(
    mut commands: mpsc::UnboundedReceiver<TransportCommand>,
    events: mpsc::Sender<TransportEvent>,
) {
    log::info!("ble-peripheral: transport starting (the PC is the GATT peripheral)");
    let (ev_tx, mut ev_rx) = mpsc::unbounded_channel::<Ev>();
    let mut m = Main {
        events,
        ev_tx,
        book: Arc::new(tokio::sync::Mutex::new(ClientBook::new())),
        provider: None,
        started_at: Instant::now(),
        gen: 0,
        failures: 0,
        retry_at: Some(Instant::now()),
        peers: HashMap::new(),
        last_state: None,
    };
    loop {
        if m.events.is_closed() {
            break;
        }
        let retry = m.retry_at;
        tokio::select! {
            cmd = commands.recv() => match cmd {
                Some(c) => if !m.command(c) { break },
                None => break,
            },
            ev = ev_rx.recv() => match ev {
                Some(Ev::Resync { gen }) => {
                    if m.provider.as_ref().is_some_and(|p| p.gen == gen) {
                        m.resync().await;
                    }
                }
                Some(Ev::ClientGone { gen, device }) => {
                    if m.provider.as_ref().is_some_and(|p| p.gen == gen) {
                        m.client_gone(&device).await;
                    }
                }
                Some(Ev::AdvertisingEnded { gen, status }) => {
                    if m.provider.as_ref().is_some_and(|p| p.gen == gen) {
                        m.advertising_ended(&status).await;
                    }
                }
                Some(Ev::PeerEnded { peer, reason }) => m.peer_ended(&peer, &reason).await,
                None => break,
            },
            () = async {
                match retry {
                    Some(t) => tokio::time::sleep_until(t).await,
                    None => std::future::pending().await,
                }
            } => {
                m.retry_at = None;
                m.try_start().await;
            }
        }
    }
    log::info!("ble-peripheral: shutting down");
    m.end_all("transport stopped").await;
    m.provider = None;
}
