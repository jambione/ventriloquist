//! [`Core`]: the sans-I/O heart of the desktop host. It combines the
//! [`SessionManager`], [`PairingStore`], [`TranscriptStore`] and config,
//! consumes transport events, commands and I/O results, and produces
//! transport commands, [`IoJob`]s and [`HostEvent`]s. After
//! [`Core::open`] it never touches the disk: every write is an [`IoJob`]
//! run by an [`crate::io_worker::IoExecutor`] off the async loop (D11).
//! [`crate::host`] runs it on tokio; tests drive it directly with a
//! [`crate::clock::ManualClock`] and a synchronous [`IoWorker`].

use std::fs::{File, OpenOptions, TryLockError};
use std::io;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use crate::clock::Clock;
use crate::config::{normalize_name, ConfigStore};
use crate::events::{
    HostCommand, HostEvent, PhonePairing, PhonePairingEnd, RelayLink, RelayStatus,
};
use crate::io_worker::{IoJob, IoResult, IoWorker, LogJob, PeersOp};
use crate::pairing_store::{Identity, PairingStore};
use crate::pairing_uri::PairingUri;
use crate::relay_room::RelayRoomStore;
use crate::session::{SessionManager, SessionOutput, PAIR_CODE_TTL};
use crate::transcript::TranscriptStore;
use crate::transport::{TransportCommand, TransportEvent};

/// How to open a [`Core`].
pub struct CoreOptions {
    /// Directory holding `identity.json`, `peers.json` and `config.json`.
    pub config_dir: PathBuf,
    /// Use this log directory for this run instead of the configured one
    /// (not persisted).
    pub log_dir_override: Option<PathBuf>,
    /// Use this display name for this run (not persisted).
    pub name_override: Option<String>,
    /// Time source.
    pub clock: Arc<dyn Clock>,
    /// The relay room (id, secret, URL) for QR pairing. `None` for the TCP
    /// dev transport: "Add phone" then reports that no relay is configured.
    pub relay: Option<Arc<RelayRoomStore>>,
}

/// Output of the core.
#[derive(Debug, Clone, PartialEq)]
pub enum CoreOutput {
    /// For the transport.
    Transport(TransportCommand),
    /// For the UI.
    Event(HostEvent),
    /// For the I/O worker; its results go to [`Core::handle_io`].
    Io(IoJob),
}

/// The desktop host core.
pub struct Core {
    clock: Arc<dyn Clock>,
    sessions: SessionManager,
    store: PairingStore,
    transcript: TranscriptStore,
    config: ConfigStore,
    log_dir: PathBuf,
    relay_status: RelayStatus,
    relay: Option<Arc<RelayRoomStore>>,
    /// "Add phone" is open: the QR is regenerated every 120 s.
    qr_open: bool,
    /// The QR on offer and when it was started (monotonic).
    qr_current: Option<(String, Duration)>,
    startup_warnings: Vec<String>,
    /// Latest log-write warning while the logger is failing (R2).
    log_warning: Option<String>,
    /// Exclusive advisory lock on `<config_dir>/.lock`, held while this
    /// core exists (one host per config directory).
    _lock: File,
}

/// Take the single-instance lock of `config_dir` (created if needed).
fn lock_config_dir(config_dir: &Path) -> io::Result<File> {
    crate::fsutil::create_private_dir_all(config_dir)?;
    let file = OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .open(config_dir.join(".lock"))?;
    match file.try_lock() {
        Ok(()) => Ok(file),
        Err(TryLockError::WouldBlock) => Err(io::Error::new(
            io::ErrorKind::AddrInUse,
            "Ventriloquist is already running (its settings folder is locked by another process)",
        )),
        Err(TryLockError::Error(e)) => Err(e),
    }
}

impl std::fmt::Debug for Core {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Core")
            .field("sessions", &self.sessions)
            .field("log_dir", &self.log_dir)
            .finish_non_exhaustive()
    }
}

impl Core {
    /// Load (or create) identity and pairing store (errors are fatal) and
    /// config (a corrupt `config.json` falls back to the defaults with a
    /// `storage_warning`).
    pub fn open(opts: CoreOptions) -> io::Result<Self> {
        let lock = lock_config_dir(&opts.config_dir)?;
        let identity = Identity::load_or_create(&opts.config_dir)?;
        let store = PairingStore::load(&opts.config_dir)?;
        let (config, config_warning) = ConfigStore::load(&opts.config_dir);
        let log_dir = opts.log_dir_override.unwrap_or_else(|| config.log_dir());
        let name = opts
            .name_override
            .map(|n| normalize_name(&n))
            .filter(|n| !n.is_empty())
            .unwrap_or_else(|| config.name());
        Ok(Self {
            clock: opts.clock,
            sessions: SessionManager::new(identity, name),
            store,
            transcript: TranscriptStore::default(),
            config,
            log_dir,
            relay_status: RelayStatus::of(RelayLink::Idle),
            relay: opts.relay,
            qr_open: false,
            qr_current: None,
            startup_warnings: config_warning.into_iter().collect(),
            log_warning: None,
            _lock: lock,
        })
    }

    /// A worker for this core's files (run it with
    /// [`crate::io_worker::IoExecutor`]).
    pub fn io_worker(&self) -> IoWorker {
        IoWorker::new(
            self.log_dir.clone(),
            self.store.path().to_path_buf(),
            self.config.path().to_path_buf(),
        )
    }

    /// What to do at start-up: the `started` event, any load warnings, and
    /// creating the log directory.
    pub fn startup(&mut self) -> Vec<CoreOutput> {
        let mut out = vec![CoreOutput::Event(self.started_event())];
        for message in self.startup_warnings.drain(..) {
            out.push(CoreOutput::Event(HostEvent::StorageWarning { message }));
        }
        out.push(CoreOutput::Io(IoJob::SetLogDir(self.log_dir.clone())));
        out
    }

    /// The `started` event describing the initial state.
    pub fn started_event(&self) -> HostEvent {
        HostEvent::Started {
            device_id: self.sessions.identity().device_id,
            name: self.sessions.name().to_owned(),
            log_dir: self.log_dir.clone(),
            paired_peers: self.store.peers().to_vec(),
        }
    }

    /// The complete current state.
    pub fn snapshot(&self) -> HostEvent {
        HostEvent::Snapshot {
            device_id: self.sessions.identity().device_id,
            name: self.sessions.name().to_owned(),
            log_dir: self.log_dir.clone(),
            paired_peers: self.store.peers().to_vec(),
            relay: self.relay_status.clone(),
            phone_pairing: self.phone_pairing(),
            peers: self.sessions.statuses(&self.store, self.clock.as_ref()),
            entries: self.transcript.entries().cloned().collect(),
            log_warning: self.log_warning.clone(),
        }
    }

    fn phone_pairing(&self) -> Option<PhonePairing> {
        let (uri, started) = self.qr_current.as_ref().filter(|_| self.qr_open)?;
        let age = self.clock.mono().saturating_sub(*started);
        Some(PhonePairing {
            uri: uri.clone(),
            expires_in_secs: PAIR_CODE_TTL.saturating_sub(age).as_secs(),
        })
    }

    /// Start a fresh QR code and describe it. Without a relay room the QR
    /// cannot be built: a `storage_warning` says so.
    fn new_qr(&mut self) -> Vec<CoreOutput> {
        let Some(relay) = self.relay.clone() else {
            self.qr_open = false;
            return vec![CoreOutput::Event(HostEvent::StorageWarning {
                message: "Phone pairing by QR needs the relay transport, which is not running."
                    .to_owned(),
            })];
        };
        let room = relay.get();
        let code = self.sessions.start_qr_pairing(self.clock.as_ref());
        let identity = self.sessions.identity();
        let uri = PairingUri {
            relay_url: &room.url,
            room_id: &room.room_id,
            room_secret: &room.room_secret,
            device_id: identity.device_id,
            public_key: identity.keypair.public_bytes(),
            code: &code.to_string(),
            name: self.sessions.name(),
        }
        .to_uri();
        self.qr_open = true;
        self.qr_current = Some((uri.clone(), self.clock.mono()));
        vec![CoreOutput::Event(HostEvent::PhonePairingQr {
            uri,
            expires_in_secs: PAIR_CODE_TTL.as_secs(),
        })]
    }

    fn end_qr(&mut self, reason: PhonePairingEnd) -> Vec<CoreOutput> {
        if !self.qr_open {
            return Vec::new();
        }
        self.qr_open = false;
        self.qr_current = None;
        let mut out = Vec::new();
        if reason == PhonePairingEnd::Closed {
            let o = self.sessions.stop_qr_pairing(&self.store);
            out.extend(self.apply(o));
        }
        out.push(CoreOutput::Event(HostEvent::PhonePairingEnded { reason }));
        out
    }

    /// The session manager (read-only).
    pub fn sessions(&self) -> &SessionManager {
        &self.sessions
    }

    /// The pairing store (read-only).
    pub fn pairing_store(&self) -> &PairingStore {
        &self.store
    }

    /// The transcript (read-only).
    pub fn transcript(&self) -> &TranscriptStore {
        &self.transcript
    }

    /// Current log directory.
    pub fn log_dir(&self) -> PathBuf {
        self.log_dir.clone()
    }

    /// Last reported relay link state.
    pub fn relay_status(&self) -> &RelayStatus {
        &self.relay_status
    }

    /// The QR code now on offer, while it is active (tests).
    pub fn active_qr_code(&self) -> Option<vq_protocol::PairingCode> {
        self.sessions.active_qr_code(self.clock.as_ref())
    }

    /// Handle one transport event.
    pub fn handle_transport(&mut self, ev: TransportEvent) -> Vec<CoreOutput> {
        match ev {
            TransportEvent::Connected { peer, mtu } => {
                let o = self.sessions.on_connected(peer, mtu, self.clock.as_ref());
                self.apply(o)
            }
            TransportEvent::Frame { peer, frame } => {
                let o = self
                    .sessions
                    .on_frame(&peer, &frame, self.clock.as_ref(), &mut self.store);
                self.apply(o)
            }
            TransportEvent::Disconnected { peer, reason } => {
                let o = self.sessions.on_disconnected(&peer, &reason, &self.store);
                let mut out = self.apply(o);
                // K18: live partials of this connection will never get
                // their final here; settle them.
                for entry in self.transcript.interrupt_partials_from(&peer) {
                    out.push(CoreOutput::Event(HostEvent::EntryUpserted { entry }));
                }
                out
            }
            TransportEvent::Relay(status) => {
                if self.relay_status == status {
                    return Vec::new();
                }
                self.relay_status = status.clone();
                vec![CoreOutput::Event(HostEvent::RelayStatus { status })]
            }
        }
    }

    /// Handle one command.
    pub fn handle_command(&mut self, cmd: HostCommand) -> Vec<CoreOutput> {
        match cmd {
            HostCommand::ForgetPeer { device_id } => {
                let mut out = Vec::new();
                if let Some(peers) = self.store.begin_remove(&device_id) {
                    out.push(CoreOutput::Io(IoJob::SavePeers {
                        op: PeersOp::Forget { device_id },
                        peers,
                    }));
                    out.push(CoreOutput::Event(HostEvent::PairedPeersChanged {
                        peers: self.store.peers().to_vec(),
                    }));
                }
                let o = self.sessions.disconnect_device(&device_id);
                out.extend(self.apply(o));
                out
            }
            HostCommand::SetLogDir { path } => {
                if !path.is_absolute() {
                    return vec![CoreOutput::Event(HostEvent::StorageWarning {
                        message: format!(
                            "The log folder must be an absolute path (got {:?}); unchanged.",
                            path.to_string_lossy()
                        ),
                    })];
                }
                self.log_dir = path.clone();
                let file = self.config.set_log_dir(path.clone());
                vec![
                    CoreOutput::Io(IoJob::SetLogDir(path)),
                    CoreOutput::Io(IoJob::SaveConfig(file)),
                ]
            }
            HostCommand::SetName { name } => {
                let file = self.config.set_name(&name);
                let n = normalize_name(&name);
                let n = if n.is_empty() { self.config.name() } else { n };
                self.sessions.set_name(n);
                vec![CoreOutput::Io(IoJob::SaveConfig(file))]
            }
            HostCommand::CancelPairing { peer } => {
                let o = self.sessions.cancel_pairing(&peer, &self.store);
                self.apply(o)
            }
            HostCommand::StartPhonePairing => self.new_qr(),
            HostCommand::StopPhonePairing => self.end_qr(PhonePairingEnd::Closed),
            HostCommand::Snapshot => vec![CoreOutput::Event(self.snapshot())],
            HostCommand::Shutdown => vec![CoreOutput::Transport(TransportCommand::Shutdown)],
        }
    }

    /// Handle the result of an [`IoJob`].
    pub fn handle_io(&mut self, r: IoResult) -> Vec<CoreOutput> {
        match r {
            IoResult::Event(e) => {
                match &e {
                    HostEvent::LogWarning { message } => self.log_warning = Some(message.clone()),
                    HostEvent::LogRecovered => self.log_warning = None,
                    _ => {}
                }
                vec![CoreOutput::Event(e)]
            }
            IoResult::ConfigSaved { error } => {
                let mut out = Vec::new();
                if let Some(e) = &error {
                    out.push(CoreOutput::Event(HostEvent::StorageWarning {
                        message: format!("Could not save the settings: {e}"),
                    }));
                }
                out.push(CoreOutput::Event(HostEvent::ConfigChanged {
                    log_dir: self.log_dir.clone(),
                    name: self.sessions.name().to_owned(),
                    persisted: error.is_none(),
                }));
                out
            }
            IoResult::PeersSaved {
                op: PeersOp::Pair { peer, record },
                error,
            } => {
                self.store.finish_upsert(&record.device_id, error.is_none());
                let o = self.sessions.on_pairing_persisted(
                    &peer,
                    error.as_deref(),
                    &self.store,
                    self.clock.as_ref(),
                );
                self.apply(o)
            }
            IoResult::PeersSaved {
                op: PeersOp::Forget { .. },
                error: Some(e),
            } => vec![CoreOutput::Event(HostEvent::StorageWarning {
                message: format!(
                    "Could not save that the phone was forgotten ({e}); it may reappear after a restart."
                ),
            })],
            IoResult::PeersSaved { error: None, .. } => Vec::new(),
        }
    }

    /// Run timers (call about once a second).
    pub fn tick(&mut self) -> Vec<CoreOutput> {
        let o = self.sessions.tick(self.clock.as_ref(), &self.store);
        let mut out = self.apply(o);
        // The QR is regenerated every 120 s while "Add phone" is open (and
        // right away if its code was used up by wrong confirmations).
        if self.qr_open && self.sessions.active_qr_code(self.clock.as_ref()).is_none() {
            out.extend(self.new_qr());
        }
        out
    }

    fn apply(&mut self, outs: Vec<SessionOutput>) -> Vec<CoreOutput> {
        let mut result = Vec::with_capacity(outs.len());
        for o in outs {
            match o {
                SessionOutput::Send { peer, frames } => {
                    result.push(CoreOutput::Transport(TransportCommand::Send {
                        peer,
                        frames,
                    }))
                }
                SessionOutput::Disconnect {
                    peer,
                    reconnect_after,
                } => result.push(CoreOutput::Transport(TransportCommand::Disconnect {
                    peer,
                    reconnect_after,
                })),
                SessionOutput::Event(e) => {
                    let paired =
                        matches!(&e, HostEvent::PairingResult { ok: true, .. }) && self.qr_open;
                    result.push(CoreOutput::Event(e));
                    if paired {
                        // A phone paired while "Add phone" was open: close it.
                        result.extend(self.end_qr(PhonePairingEnd::Paired));
                    }
                }
                SessionOutput::PersistPairing { peer, record } => {
                    let peers = self.store.begin_upsert(record.clone());
                    result.push(CoreOutput::Io(IoJob::SavePeers {
                        op: PeersOp::Pair { peer, record },
                        peers,
                    }));
                }
                SessionOutput::Deliver {
                    peer,
                    device_id,
                    device_name,
                    utt,
                } => {
                    let now = self.clock.local_now();
                    let outcome =
                        self.transcript
                            .upsert(&utt, device_id, &device_name, &peer, now);
                    let Some(entry) = outcome.entry else {
                        // Duplicate or older revision: ignored (already acked).
                        continue;
                    };
                    let outcome_entry = Some(entry.clone());
                    result.push(CoreOutput::Event(HostEvent::EntryUpserted { entry }));
                    for id in outcome.evicted {
                        result.push(CoreOutput::Event(HostEvent::EntryEvicted { id }));
                    }
                    if utt.state != vq_protocol::UttState::Partial {
                        let announce = outcome
                            .first_final
                            .then(|| outcome_entry.clone())
                            .flatten();
                        result.push(CoreOutput::Io(IoJob::Log(LogJob {
                            utt,
                            device_name,
                            arrived: now,
                            announce,
                        })));
                    }
                }
            }
        }
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::clock::ManualClock;
    use chrono::DateTime;

    fn opts(dir: &Path) -> CoreOptions {
        CoreOptions {
            config_dir: dir.to_path_buf(),
            log_dir_override: Some(dir.join("log")),
            name_override: Some("T".into()),
            clock: Arc::new(ManualClock::new(
                DateTime::parse_from_rfc3339("2026-10-03T14:00:00+02:00").unwrap(),
            )),
            relay: Some(Arc::new(RelayRoomStore::load_or_create(dir).unwrap())),
        }
    }

    #[test]
    fn second_core_on_the_same_config_dir_is_refused_until_the_first_drops() {
        let dir = tempfile::tempdir().unwrap();
        let first = Core::open(opts(dir.path())).unwrap();
        let err = Core::open(opts(dir.path())).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::AddrInUse);
        assert!(err.to_string().contains("already running"), "{err}");
        drop(first);
        Core::open(opts(dir.path())).expect("the lock is released on drop");
    }

    fn qr_events(out: &[CoreOutput]) -> Vec<(String, u64)> {
        out.iter()
            .filter_map(|o| match o {
                CoreOutput::Event(HostEvent::PhonePairingQr { uri, expires_in_secs }) => {
                    Some((uri.clone(), *expires_in_secs))
                }
                _ => None,
            })
            .collect()
    }

    fn query(uri: &str) -> std::collections::HashMap<String, String> {
        let u = url::Url::parse(uri).unwrap();
        assert_eq!((u.scheme(), u.host_str()), ("vq", Some("pair")));
        u.query_pairs().map(|(k, v)| (k.into_owned(), v.into_owned())).collect()
    }

    /// SPEC_V3 §5: the URI carries the room, the desktop's identity and the
    /// code that is *active* in the session layer.
    #[test]
    fn qr_uri_fields_are_correct_and_its_code_is_the_active_code() {
        let dir = tempfile::tempdir().unwrap();
        let mut core = Core::open(opts(dir.path())).unwrap();
        assert!(core.active_qr_code().is_none());
        let out = core.handle_command(HostCommand::StartPhonePairing);
        let [(uri, ttl)] = qr_events(&out).try_into().unwrap();
        assert_eq!(ttl, 120);
        let q = query(&uri);
        let room = RelayRoomStore::load_or_create(dir.path()).unwrap().get();
        let identity = core.sessions().identity();
        assert_eq!(q["v"], "3");
        assert_eq!(q["r"], room.url);
        assert_eq!(q["room"], room.room_id);
        assert_eq!(q["s"], *room.room_secret);
        assert_eq!(q["d"], identity.device_id.to_string());
        let k = base64::Engine::decode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, &q["k"]).unwrap();
        assert_eq!(k, identity.keypair.public_bytes().to_vec());
        assert_eq!(q["n"], "T");
        assert_eq!(q["c"].len(), 6);
        assert_eq!(q["c"], core.active_qr_code().expect("active").to_string());
        // The snapshot restores the dialog.
        match core.snapshot() {
            HostEvent::Snapshot { phone_pairing: Some(p), .. } => {
                assert_eq!(p.uri, uri);
                assert_eq!(p.expires_in_secs, 120);
            }
            e => panic!("{e:?}"),
        }
    }

    #[test]
    fn qr_is_regenerated_after_120_seconds_while_open_and_not_after_close() {
        let dir = tempfile::tempdir().unwrap();
        let o = opts(dir.path());
        let clock = Arc::new(ManualClock::new(
            DateTime::parse_from_rfc3339("2026-10-03T14:00:00+02:00").unwrap(),
        ));
        let mut core = Core::open(CoreOptions { clock: clock.clone(), ..o }).unwrap();
        let first = qr_events(&core.handle_command(HostCommand::StartPhonePairing))[0].0.clone();
        clock.advance(Duration::from_secs(119));
        assert!(qr_events(&core.tick()).is_empty());
        clock.advance(Duration::from_secs(2));
        let second = qr_events(&core.tick());
        assert_eq!(second.len(), 1);
        assert_ne!(query(&second[0].0)["c"], query(&first)["c"]);
        assert_eq!(query(&second[0].0)["c"], core.active_qr_code().unwrap().to_string());
        // Closing ends it: no more codes, no more regenerations.
        let out = core.handle_command(HostCommand::StopPhonePairing);
        assert!(out.iter().any(|o| matches!(
            o,
            CoreOutput::Event(HostEvent::PhonePairingEnded { reason: PhonePairingEnd::Closed })
        )));
        assert!(core.active_qr_code().is_none());
        clock.advance(Duration::from_secs(500));
        assert!(qr_events(&core.tick()).is_empty());
    }

    #[test]
    fn qr_needs_a_relay_room() {
        let dir = tempfile::tempdir().unwrap();
        let mut core = Core::open(CoreOptions { relay: None, ..opts(dir.path()) }).unwrap();
        let out = core.handle_command(HostCommand::StartPhonePairing);
        assert!(qr_events(&out).is_empty());
        assert!(matches!(&out[..], [CoreOutput::Event(HostEvent::StorageWarning { .. })]));
    }

    #[test]
    fn relay_status_is_emitted_on_change_only_and_kept_for_snapshots() {
        let dir = tempfile::tempdir().unwrap();
        let mut core = Core::open(opts(dir.path())).unwrap();
        let st = RelayStatus::of(RelayLink::Fallback);
        let out = core.handle_transport(TransportEvent::Relay(st.clone()));
        assert!(matches!(&out[..], [CoreOutput::Event(HostEvent::RelayStatus { .. })]));
        assert!(core.handle_transport(TransportEvent::Relay(st.clone())).is_empty());
        match core.snapshot() {
            HostEvent::Snapshot { relay, .. } => assert_eq!(relay, st),
            e => panic!("{e:?}"),
        }
    }

    #[test]
    fn snapshot_carries_the_log_warning_until_recovery() {
        let dir = tempfile::tempdir().unwrap();
        let mut core = Core::open(opts(dir.path())).unwrap();
        let warning = |c: &Core| match c.snapshot() {
            HostEvent::Snapshot { log_warning, .. } => log_warning,
            e => panic!("{e:?}"),
        };
        assert_eq!(warning(&core), None);
        core.handle_io(IoResult::Event(HostEvent::LogWarning {
            message: "disk full".into(),
        }));
        assert_eq!(warning(&core).as_deref(), Some("disk full"));
        core.handle_io(IoResult::Event(HostEvent::LogRecovered));
        assert_eq!(warning(&core), None);
    }
}
