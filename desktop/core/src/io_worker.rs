//! Blocking file I/O, kept off the async host loop (docs/SPEC_QUESTIONS.md
//! D11).
//!
//! [`crate::core::Core`] never touches the disk after start-up. It emits
//! [`IoJob`]s; an [`IoExecutor`] (normally [`IoWorker`] on a dedicated
//! thread, see [`crate::host`]) runs them in order and reports
//! [`IoResult`]s, which go back into the core. Tests run the same worker
//! synchronously.
//!
//! The worker keeps log entries that could not be written in a bounded
//! queue ([`MAX_PENDING_LOG`]) and retries them before every new entry and
//! on every [`IoExecutor::tick`]; it reports a `log_warning` when logging
//! starts failing and `log_recovered` once the queue is empty again.

use std::collections::VecDeque;
use std::fs;
use std::path::{Path, PathBuf};

use chrono::{DateTime, FixedOffset};
use uuid::Uuid;
use vq_protocol::Utt;

use crate::config::{save_config, ConfigFile};
use crate::events::{HostEvent, PeerId};
use crate::logger::Logger;
use crate::pairing_store::{write_peers, PairedPeer};
use crate::transcript::Entry;

/// Log entries kept for retry at most (the oldest are dropped beyond).
pub const MAX_PENDING_LOG: usize = 1000;

/// One accepted `final`/`edit` to append to the Markdown log.
#[derive(Debug, Clone, PartialEq)]
pub struct LogJob {
    /// The revision.
    pub utt: Utt,
    /// Sending phone's name.
    pub device_name: String,
    /// Local arrival time (picks the day file and the line's time).
    pub arrived: DateTime<FixedOffset>,
    /// Set for the first accepted `final` of an id: the worker then
    /// reports [`HostEvent::FinalAccepted`] with this entry unless the log
    /// already holds this (`id`, `rev`) (a re-delivery after a restart).
    /// It is reported when the worker takes the job, whether or not the
    /// write succeeds or is deferred for retry.
    pub announce: Option<Entry>,
}

/// Why `peers.json` is being written.
#[derive(Debug, Clone, PartialEq)]
pub enum PeersOp {
    /// A pairing on connection `peer` waits for this write before
    /// answering `pair_result{ok:true}`.
    Pair {
        /// Connection id.
        peer: PeerId,
        /// The new record.
        record: PairedPeer,
    },
    /// The user forgot a phone.
    Forget {
        /// Its `device_id`.
        device_id: Uuid,
    },
}

/// Work for the I/O worker.
#[derive(Debug, Clone, PartialEq)]
pub enum IoJob {
    /// Append to the log.
    Log(LogJob),
    /// Switch the log directory (and create it).
    SetLogDir(PathBuf),
    /// Replace `peers.json` with `peers`.
    SavePeers {
        /// Why.
        op: PeersOp,
        /// Full contents.
        peers: Vec<PairedPeer>,
    },
    /// Replace `config.json`.
    SaveConfig(ConfigFile),
}

/// Outcome of a job, for the core.
#[derive(Debug, Clone, PartialEq)]
pub enum IoResult {
    /// [`IoJob::SavePeers`] finished; `error` is `None` on success.
    PeersSaved {
        /// The job's purpose.
        op: PeersOp,
        /// Failure description.
        error: Option<String>,
    },
    /// [`IoJob::SaveConfig`] finished.
    ConfigSaved {
        /// Failure description.
        error: Option<String>,
    },
    /// An event for the UI (log warnings and recovery).
    Event(HostEvent),
}

/// Runs [`IoJob`]s. Implemented by [`IoWorker`]; tests wrap it (e.g. to
/// make it slow).
pub trait IoExecutor: Send + 'static {
    /// Run one job.
    fn execute(&mut self, job: IoJob) -> Vec<IoResult>;
    /// Periodic work (about once a second): retry failed log entries.
    fn tick(&mut self) -> Vec<IoResult>;
}

impl IoExecutor for Box<dyn IoExecutor> {
    fn execute(&mut self, job: IoJob) -> Vec<IoResult> {
        (**self).execute(job)
    }
    fn tick(&mut self) -> Vec<IoResult> {
        (**self).tick()
    }
}

/// The real worker: logger, `peers.json` and `config.json`.
#[derive(Debug)]
pub struct IoWorker {
    logger: Logger,
    peers_path: PathBuf,
    config_path: PathBuf,
    pending: VecDeque<LogJob>,
    failing: bool,
}

impl IoWorker {
    /// A worker logging into `log_dir` and writing the given files.
    pub fn new(log_dir: PathBuf, peers_path: PathBuf, config_path: PathBuf) -> Self {
        Self {
            logger: Logger::new(log_dir),
            peers_path,
            config_path,
            pending: VecDeque::new(),
            failing: false,
        }
    }

    /// Current log directory.
    pub fn log_dir(&self) -> &Path {
        self.logger.dir()
    }

    /// Entries waiting for a retry.
    pub fn pending_log_entries(&self) -> usize {
        self.pending.len()
    }

    fn flush_log(&mut self, out: &mut Vec<IoResult>) {
        let had_pending = !self.pending.is_empty();
        while let Some(job) = self.pending.front() {
            match self.logger.log(&job.utt, &job.device_name, job.arrived) {
                Ok(_) => {
                    self.pending.pop_front();
                }
                Err(e) => {
                    log::warn!("{e}");
                    if !self.failing {
                        self.failing = true;
                        out.push(IoResult::Event(HostEvent::LogWarning {
                            message: format!("{e} (will retry)"),
                        }));
                    }
                    break;
                }
            }
        }
        for w in self.logger.take_warnings() {
            log::warn!("{w}");
            out.push(IoResult::Event(HostEvent::LogWarning { message: w }));
        }
        if had_pending && self.pending.is_empty() && self.failing {
            self.failing = false;
            out.push(IoResult::Event(HostEvent::LogRecovered));
        }
    }
}

impl IoExecutor for IoWorker {
    fn execute(&mut self, job: IoJob) -> Vec<IoResult> {
        let mut out = Vec::new();
        match job {
            IoJob::Log(j) => {
                if let Some(entry) = &j.announce {
                    // Same dedupe the logger applies, decided before the
                    // write so a failing or backed-up log cannot delay or
                    // lose the announcement.
                    if !self.logger.is_logged(&j.utt, j.arrived) {
                        out.push(IoResult::Event(HostEvent::FinalAccepted {
                            entry: entry.clone(),
                        }));
                    }
                    for w in self.logger.take_warnings() {
                        log::warn!("{w}");
                        out.push(IoResult::Event(HostEvent::LogWarning { message: w }));
                    }
                }
                if self.pending.len() >= MAX_PENDING_LOG {
                    self.pending.pop_front();
                    out.push(IoResult::Event(HostEvent::LogWarning {
                        message: format!(
                            "more than {MAX_PENDING_LOG} entries could not be logged; the oldest was dropped"
                        ),
                    }));
                }
                self.pending.push_back(j);
                self.flush_log(&mut out);
            }
            IoJob::SetLogDir(dir) => {
                if let Err(e) = fs::create_dir_all(&dir) {
                    out.push(IoResult::Event(HostEvent::LogWarning {
                        message: format!("cannot create log folder {}: {e}", dir.display()),
                    }));
                }
                self.logger.set_dir(dir);
                self.flush_log(&mut out);
            }
            IoJob::SavePeers { op, peers } => {
                let error = write_peers(&self.peers_path, &peers)
                    .err()
                    .map(|e| e.to_string());
                out.push(IoResult::PeersSaved { op, error });
            }
            IoJob::SaveConfig(file) => {
                let error = save_config(&self.config_path, &file)
                    .err()
                    .map(|e| e.to_string());
                out.push(IoResult::ConfigSaved { error });
            }
        }
        out
    }

    fn tick(&mut self) -> Vec<IoResult> {
        let mut out = Vec::new();
        if !self.pending.is_empty() {
            self.flush_log(&mut out);
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use vq_protocol::UttState;

    fn job(text: &str) -> IoJob {
        IoJob::Log(LogJob {
            utt: Utt {
                id: Uuid::new_v4(),
                rev: 0,
                state: UttState::Final,
                text: text.into(),
                ts: 0,
            },
            device_name: "P".into(),
            arrived: DateTime::parse_from_rfc3339("2026-10-03T10:00:00+00:00").unwrap(),
            announce: None,
        })
    }

    fn events(r: &[IoResult]) -> Vec<&HostEvent> {
        r.iter()
            .filter_map(|r| match r {
                IoResult::Event(e) => Some(e),
                _ => None,
            })
            .collect()
    }

    #[test]
    fn failed_entries_are_retried_in_order_and_recovery_reported() {
        let dir = tempfile::tempdir().unwrap();
        let blocker = dir.path().join("blocker");
        fs::write(&blocker, b"").unwrap();
        let logs = blocker.join("logs");
        let mut w = IoWorker::new(logs.clone(), dir.path().join("p"), dir.path().join("c"));
        let r = w.execute(job("one"));
        assert!(matches!(events(&r)[..], [HostEvent::LogWarning { .. }]));
        // still failing: no second warning
        assert!(events(&w.execute(job("two"))).is_empty());
        assert_eq!(w.pending_log_entries(), 2);
        fs::remove_file(&blocker).unwrap();
        let r = w.tick();
        assert_eq!(events(&r), vec![&HostEvent::LogRecovered]);
        let log = fs::read_to_string(logs.join("2026-10-03.md")).unwrap();
        assert!(log.find("  one\n").unwrap() < log.find("  two\n").unwrap());
        assert!(w.tick().is_empty());
    }

    #[test]
    fn pending_queue_is_bounded() {
        let dir = tempfile::tempdir().unwrap();
        let blocker = dir.path().join("blocker");
        fs::write(&blocker, b"").unwrap();
        let mut w = IoWorker::new(blocker.join("l"), dir.path().join("p"), dir.path().join("c"));
        for _ in 0..(MAX_PENDING_LOG + 3) {
            w.execute(job("x"));
        }
        assert_eq!(w.pending_log_entries(), MAX_PENDING_LOG);
    }
}
