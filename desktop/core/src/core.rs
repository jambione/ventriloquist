//! [`Core`]: the sans-I/O heart of the desktop host. It combines the
//! [`SessionManager`], [`PairingStore`], [`TranscriptStore`], [`Logger`] and
//! config, consumes transport events and commands, and produces transport
//! commands and [`HostEvent`]s. [`crate::host`] runs it on tokio; tests
//! drive it directly with a [`crate::clock::ManualClock`].

use std::io;
use std::path::PathBuf;
use std::sync::Arc;

use crate::clock::Clock;
use crate::config::{normalize_name, ConfigStore};
use crate::events::{HostCommand, HostEvent};
use crate::logger::Logger;
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
}

/// The desktop host core.
pub struct Core {
    clock: Arc<dyn Clock>,
    sessions: SessionManager,
    store: PairingStore,
    transcript: TranscriptStore,
    logger: Logger,
    config: ConfigStore,
}

impl std::fmt::Debug for Core {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Core")
            .field("sessions", &self.sessions)
            .field("log_dir", &self.logger.dir())
            .finish_non_exhaustive()
    }
}

impl Core {
    /// Load (or create) identity, pairing store and config.
    pub fn open(opts: CoreOptions) -> io::Result<Self> {
        let identity = Identity::load_or_create(&opts.config_dir)?;
        let store = PairingStore::load(&opts.config_dir)?;
        let config = ConfigStore::load(&opts.config_dir)?;
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
            logger: Logger::new(log_dir),
            config,
        })
    }

    /// The `started` event describing the initial state.
    pub fn started_event(&self) -> HostEvent {
        HostEvent::Started {
            device_id: self.sessions.identity().device_id,
            name: self.sessions.name().to_owned(),
            log_dir: self.logger.dir().to_path_buf(),
            paired_peers: self.store.peers().to_vec(),
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
        self.logger.dir().to_path_buf()
    }

    /// Handle one transport event.
    pub fn handle_transport(&mut self, ev: TransportEvent) -> Vec<CoreOutput> {
        let outs = match ev {
            TransportEvent::Connected { peer, mtu } => {
                self.sessions.on_connected(peer, mtu, self.clock.as_ref())
            }
            TransportEvent::Frame { peer, frame } => {
                self.sessions
                    .on_frame(&peer, &frame, self.clock.as_ref(), &mut self.store)
            }
            TransportEvent::Disconnected { peer, reason } => {
                self.sessions.on_disconnected(&peer, &reason, &self.store)
            }
            TransportEvent::Adapter(state) => {
                return vec![CoreOutput::Event(HostEvent::AdapterState { state })]
            }
        };
        self.apply(outs)
    }

    /// Handle one command.
    pub fn handle_command(&mut self, cmd: HostCommand) -> Vec<CoreOutput> {
        match cmd {
            HostCommand::ForgetPeer { device_id } => {
                let mut out = Vec::new();
                match self.store.remove(&device_id) {
                    Ok(true) => out.push(CoreOutput::Event(HostEvent::PairedPeersChanged {
                        peers: self.store.peers().to_vec(),
                    })),
                    Ok(false) => {}
                    Err(e) => out.push(CoreOutput::Event(HostEvent::StorageWarning {
                        message: format!("Could not forget the phone: {e}"),
                    })),
                }
                let o = self.sessions.disconnect_device(&device_id);
                out.extend(self.apply(o));
                out
            }
            HostCommand::SetLogDir { path } => {
                let mut out = Vec::new();
                if let Err(e) = self.config.set_log_dir(path.clone()) {
                    out.push(CoreOutput::Event(HostEvent::StorageWarning {
                        message: format!("Could not save the settings: {e}"),
                    }));
                }
                self.logger.set_dir(path);
                out.push(self.config_changed());
                out
            }
            HostCommand::SetName { name } => {
                let mut out = Vec::new();
                if let Err(e) = self.config.set_name(&name) {
                    out.push(CoreOutput::Event(HostEvent::StorageWarning {
                        message: format!("Could not save the settings: {e}"),
                    }));
                }
                let n = normalize_name(&name);
                let n = if n.is_empty() { self.config.name() } else { n };
                self.sessions.set_name(n);
                out.push(self.config_changed());
                out
            }
            HostCommand::CancelPairing { peer } => {
                let o = self.sessions.cancel_pairing(&peer, &self.store);
                self.apply(o)
            }
            HostCommand::Shutdown => vec![CoreOutput::Transport(TransportCommand::Shutdown)],
        }
    }

    /// Run timers (call about once a second).
    pub fn tick(&mut self) -> Vec<CoreOutput> {
        let o = self.sessions.tick(self.clock.as_ref(), &self.store);
        self.apply(o)
    }

    fn config_changed(&self) -> CoreOutput {
        CoreOutput::Event(HostEvent::ConfigChanged {
            log_dir: self.logger.dir().to_path_buf(),
            name: self.sessions.name().to_owned(),
        })
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
                SessionOutput::Deliver {
                    peer: _,
                    device_id,
                    device_name,
                    utt,
                } => {
                    let now = self.clock.local_now();
                    let outcome = self.transcript.upsert(&utt, device_id, &device_name, now);
                    let Some(entry) = outcome.entry else {
                        // Duplicate or older revision: ignored (already acked).
                        continue;
                    };
                    result.push(CoreOutput::Event(HostEvent::EntryUpserted { entry }));
                    for id in outcome.evicted {
                        result.push(CoreOutput::Event(HostEvent::EntryEvicted { id }));
                    }
                    if let Err(e) = self.logger.log(&utt, &device_name, now) {
                        log::warn!("{e}");
                        result.push(CoreOutput::Event(HostEvent::LogWarning {
                            message: e.to_string(),
                        }));
                    }
                }
            }
        }
        result
    }
}
