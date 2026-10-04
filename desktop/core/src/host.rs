//! Tokio runtime for [`Core`]: pumps transport events, commands, I/O
//! results and a 1 s timer, and publishes [`HostEvent`]s on a bounded
//! channel. Framework-agnostic: the Tauri app forwards the events to its
//! web view and turns UI actions into [`HostCommand`]s.
//!
//! The loop never blocks (docs/SPEC_QUESTIONS.md D11):
//! * file I/O runs on a dedicated thread ([`IoExecutor`]) fed by a bounded
//!   queue ([`IO_QUEUE_CAPACITY`]); results come back as messages;
//! * events go through an [`EventOutbox`] that coalesces while the UI is
//!   slow, and are handed to the bounded event channel
//!   ([`EVENT_QUEUE_CAPACITY`]) as it frees up.

use std::io;
use std::sync::mpsc as std_mpsc;
use std::time::Duration;

use tokio::sync::mpsc;
use tokio::task::JoinHandle;

use crate::core::{Core, CoreOptions, CoreOutput};
use crate::events::{HostCommand, HostEvent};
use crate::io_worker::{IoExecutor, IoJob, IoResult, IoWorker};
use crate::outbox::EventOutbox;
use crate::transport::{Transport, TransportCommand, EVENT_CHANNEL_CAPACITY};

/// Timer resolution of the host loop (and of the I/O worker's retries).
pub const TICK: Duration = Duration::from_secs(1);

/// Capacity of the host → UI event channel.
pub const EVENT_QUEUE_CAPACITY: usize = 256;

/// Capacity of the host → I/O worker job queue.
pub const IO_QUEUE_CAPACITY: usize = 1024;

/// Sends commands to a running host. Dropping every handle stops the host.
#[derive(Debug, Clone)]
pub struct HostHandle {
    tx: mpsc::UnboundedSender<HostCommand>,
}

impl HostHandle {
    /// Queue a command. Returns `false` if the host has stopped.
    pub fn send(&self, cmd: HostCommand) -> bool {
        self.tx.send(cmd).is_ok()
    }
}

/// The values returned by [`spawn_host`].
pub type Spawned = (HostHandle, mpsc::Receiver<HostEvent>, JoinHandle<()>);

/// Open the core and run it with `transport` on the current tokio runtime.
///
/// Returns the command handle, the event stream (the first event is
/// [`HostEvent::Started`]) and the host task, which ends after
/// [`HostCommand::Shutdown`] or when every [`HostHandle`] is dropped.
pub fn spawn_host(opts: CoreOptions, transport: Box<dyn Transport>) -> io::Result<Spawned> {
    spawn_host_with_io(opts, transport, |w| Box::new(w))
}

/// Like [`spawn_host`], but `wrap_io` may wrap the real [`IoWorker`]
/// (tests use it to inject a slow disk).
pub fn spawn_host_with_io(
    opts: CoreOptions,
    transport: Box<dyn Transport>,
    wrap_io: impl FnOnce(IoWorker) -> Box<dyn IoExecutor>,
) -> io::Result<Spawned> {
    let core = Core::open(opts)?;
    let exec = wrap_io(core.io_worker());
    let (job_tx, job_rx) = std_mpsc::sync_channel::<IoJob>(IO_QUEUE_CAPACITY);
    let (res_tx, res_rx) = mpsc::unbounded_channel();
    std::thread::Builder::new()
        .name("vq-io".into())
        .spawn(move || io_thread(exec, job_rx, res_tx))?;
    let (cmd_tx, cmd_rx) = mpsc::unbounded_channel();
    let (ev_tx, ev_rx) = mpsc::channel(EVENT_QUEUE_CAPACITY);
    let task = tokio::spawn(run(core, transport, cmd_rx, ev_tx, job_tx, res_rx));
    Ok((HostHandle { tx: cmd_tx }, ev_rx, task))
}

/// The I/O thread: runs jobs in order, ticks once a second, and ends when
/// the host drops the job queue.
fn io_thread(
    mut exec: Box<dyn IoExecutor>,
    jobs: std_mpsc::Receiver<IoJob>,
    results: mpsc::UnboundedSender<IoResult>,
) {
    loop {
        let out = match jobs.recv_timeout(TICK) {
            Ok(job) => exec.execute(job),
            Err(std_mpsc::RecvTimeoutError::Timeout) => exec.tick(),
            Err(std_mpsc::RecvTimeoutError::Disconnected) => return,
        };
        for r in out {
            if results.send(r).is_err() {
                return;
            }
        }
    }
}

/// What to report when the I/O queue is full (the worker is far behind).
fn io_overflow(job: IoJob) -> Vec<IoResult> {
    let busy = "the disk is not keeping up".to_owned();
    let one = match job {
        IoJob::Log(j) => {
            // The log index cannot be consulted, so the dedupe check
            // (a re-delivery after a restart) cannot run: do NOT announce
            // `FinalAccepted` (it would be delivered into a bound app a second
            // time). Drop the announce and warn instead.
            let announce_note = if j.announce.is_some() { " (final not announced)" } else { "" };
            return vec![IoResult::Event(HostEvent::LogWarning {
                message: format!(
                    "log entry id={} rev={} dropped: {busy}{announce_note}",
                    &j.utt.id.simple().to_string()[..8],
                    j.utt.rev
                ),
            })];
        }
        IoJob::SetLogDir(dir) => IoResult::Event(HostEvent::LogWarning {
            message: format!("cannot switch the log folder to {}: {busy}", dir.display()),
        }),
        IoJob::SavePeers { op, .. } => IoResult::PeersSaved {
            op,
            error: Some(busy),
        },
        IoJob::SaveConfig(_) => IoResult::ConfigSaved { error: Some(busy) },
    };
    vec![one]
}

async fn run(
    mut core: Core,
    transport: Box<dyn Transport>,
    mut cmd_rx: mpsc::UnboundedReceiver<HostCommand>,
    ev_tx: mpsc::Sender<HostEvent>,
    job_tx: std_mpsc::SyncSender<IoJob>,
    mut res_rx: mpsc::UnboundedReceiver<IoResult>,
) {
    let (tcmd_tx, tcmd_rx) = mpsc::unbounded_channel();
    let (tev_tx, mut tev_rx) = mpsc::channel(EVENT_CHANNEL_CAPACITY);
    let transport_task = transport.start(tcmd_rx, tev_tx);
    let mut outbox = EventOutbox::new();
    // Results of jobs the queue refused, fed back on the next turn.
    let mut refused: Vec<IoResult> = Vec::new();

    let dispatch = |outs: Vec<CoreOutput>, outbox: &mut EventOutbox, refused: &mut Vec<IoResult>| {
        for o in outs {
            match o {
                CoreOutput::Transport(c) => {
                    let _ = tcmd_tx.send(c);
                }
                CoreOutput::Event(e) => outbox.push(e),
                CoreOutput::Io(job) => match job_tx.try_send(job) {
                    Ok(()) => {}
                    Err(std_mpsc::TrySendError::Full(job))
                    | Err(std_mpsc::TrySendError::Disconnected(job)) => {
                        log::warn!("I/O queue full or stopped");
                        refused.extend(io_overflow(job));
                    }
                },
            }
        }
    };

    let start = core.startup();
    dispatch(start, &mut outbox, &mut refused);

    let mut tick = tokio::time::interval(TICK);
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        while let Some(r) = refused.pop() {
            let o = core.handle_io(r);
            dispatch(o, &mut outbox, &mut refused);
        }
        tokio::select! {
            Some(ev) = tev_rx.recv() => {
                let o = core.handle_transport(ev);
                dispatch(o, &mut outbox, &mut refused);
            }
            cmd = cmd_rx.recv() => match cmd {
                Some(HostCommand::Shutdown) | None => break,
                Some(c) => {
                    let o = core.handle_command(c);
                    dispatch(o, &mut outbox, &mut refused);
                }
            },
            Some(r) = res_rx.recv() => {
                let o = core.handle_io(r);
                dispatch(o, &mut outbox, &mut refused);
            }
            permit = ev_tx.reserve(), if !outbox.is_empty() => match permit {
                Ok(p) => {
                    if let Some(e) = outbox.pop() {
                        p.send(e);
                    }
                }
                // Nobody listens any more: drop events, keep running.
                Err(_) => while outbox.pop().is_some() {},
            },
            _ = tick.tick() => {
                let o = core.tick();
                dispatch(o, &mut outbox, &mut refused);
            }
        }
    }
    let _ = tcmd_tx.send(TransportCommand::Shutdown);
    let _ = tokio::time::timeout(Duration::from_secs(3), transport_task).await;
    // Let the I/O thread finish queued writes (it stops when the queue is
    // dropped) and forward the last events.
    drop(job_tx);
    let _ = tokio::time::timeout(Duration::from_secs(2), async {
        while let Some(r) = res_rx.recv().await {
            if let IoResult::Event(e) = r {
                outbox.push(e);
            }
        }
    })
    .await;
    let _ = tokio::time::timeout(Duration::from_secs(1), async {
        while let Some(e) = outbox.pop() {
            if ev_tx.send(e).await.is_err() {
                break;
            }
        }
    })
    .await;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::io_worker::LogJob;
    use crate::transcript::{Entry, EntryState};
    use uuid::Uuid;
    use vq_protocol::{Utt, UttState};

    /// R11: when the I/O queue is full the dedupe check cannot run, so the
    /// overflow path must not emit `FinalAccepted` (only a warning).
    #[test]
    fn io_overflow_never_announces_final_accepted() {
        let id = Uuid::new_v4();
        let entry = Entry {
            id,
            rev: 1,
            state: EntryState::Final,
            text: "hello".into(),
            ts: 0,
            device_id: Uuid::nil(),
            device_name: "Phone".into(),
            first_received_at: String::new(),
            received_at: String::new(),
            time: String::new(),
            partial: false,
            edited: false,
        };
        let job = IoJob::Log(LogJob {
            utt: Utt { id, rev: 1, state: UttState::Final, text: "hello".into(), ts: 0 },
            device_name: "Phone".into(),
            arrived: chrono::DateTime::parse_from_rfc3339("2026-01-01T00:00:00+00:00").unwrap(),
            announce: Some(entry),
        });
        let out = io_overflow(job);
        assert!(
            !out.iter().any(|r| matches!(r, IoResult::Event(HostEvent::FinalAccepted { .. }))),
            "{out:?}"
        );
        assert!(out.iter().any(|r| matches!(r, IoResult::Event(HostEvent::LogWarning { .. }))));
    }
}
