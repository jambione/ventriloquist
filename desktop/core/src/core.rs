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

use crate::clock::Clock;
use crate::config::{normalize_name, ConfigStore};
use crate::events::{AdapterState, HostCommand, HostEvent};
use crate::io_worker::{IoJob, IoResult, IoWorker, LogJob, PeersOp};
use crate::pairing_store::{Identity, PairingStore};
use crate::session::{SessionManager, SessionOutput};
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
    adapter_state: AdapterState,
    devices_seen: u64,
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
            adapter_state: AdapterState::Unknown,
            devices_seen: 0,
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
            adapter_state: self.adapter_state,
            devices_seen: self.devices_seen,
            peers: self.sessions.statuses(&self.store, self.clock.as_ref()),
            entries: self.transcript.entries().cloned().collect(),
            log_warning: self.log_warning.clone(),
        }
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

    /// Last reported adapter state.
    pub fn adapter_state(&self) -> AdapterState {
        self.adapter_state
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
            TransportEvent::Adapter(state) => {
                self.adapter_state = state;
                vec![CoreOutput::Event(HostEvent::AdapterState { state })]
            }
            TransportEvent::DevicesSeen(count) => {
                self.devices_seen = count;
                vec![CoreOutput::Event(HostEvent::DevicesSeen { count })]
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
        self.apply(o)
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
                SessionOutput::Event(e) => result.push(CoreOutput::Event(e)),
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
