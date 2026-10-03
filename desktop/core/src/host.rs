//! Tokio runtime for [`Core`]: pumps transport events, commands and a 1 s
//! timer, and publishes [`HostEvent`]s on a channel. Framework-agnostic:
//! the Tauri app forwards the events to its web view and turns UI actions
//! into [`HostCommand`]s.

use std::io;
use std::time::Duration;

use tokio::sync::mpsc;
use tokio::task::JoinHandle;

use crate::core::{Core, CoreOptions, CoreOutput};
use crate::events::{HostCommand, HostEvent};
use crate::transport::{Transport, TransportCommand, EVENT_CHANNEL_CAPACITY};

/// Timer resolution of the host loop.
pub const TICK: Duration = Duration::from_secs(1);

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

/// Open the core and run it with `transport` on the current tokio runtime.
///
/// Returns the command handle, the event stream (the first event is
/// [`HostEvent::Started`]) and the host task, which ends after
/// [`HostCommand::Shutdown`] or when every [`HostHandle`] is dropped.
pub fn spawn_host(
    opts: CoreOptions,
    transport: Box<dyn Transport>,
) -> io::Result<(
    HostHandle,
    mpsc::UnboundedReceiver<HostEvent>,
    JoinHandle<()>,
)> {
    let core = Core::open(opts)?;
    let (cmd_tx, cmd_rx) = mpsc::unbounded_channel();
    let (ev_tx, ev_rx) = mpsc::unbounded_channel();
    let task = tokio::spawn(run(core, transport, cmd_rx, ev_tx));
    Ok((HostHandle { tx: cmd_tx }, ev_rx, task))
}

async fn run(
    mut core: Core,
    transport: Box<dyn Transport>,
    mut cmd_rx: mpsc::UnboundedReceiver<HostCommand>,
    ev_tx: mpsc::UnboundedSender<HostEvent>,
) {
    let (tcmd_tx, tcmd_rx) = mpsc::unbounded_channel();
    let (tev_tx, mut tev_rx) = mpsc::channel(EVENT_CHANNEL_CAPACITY);
    let transport_task = transport.start(tcmd_rx, tev_tx);
    let _ = ev_tx.send(core.started_event());

    let dispatch = |outs: Vec<CoreOutput>| {
        for o in outs {
            match o {
                CoreOutput::Transport(c) => {
                    let _ = tcmd_tx.send(c);
                }
                CoreOutput::Event(e) => {
                    let _ = ev_tx.send(e);
                }
            }
        }
    };

    let mut tick = tokio::time::interval(TICK);
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        tokio::select! {
            Some(ev) = tev_rx.recv() => dispatch(core.handle_transport(ev)),
            cmd = cmd_rx.recv() => match cmd {
                Some(HostCommand::Shutdown) | None => break,
                Some(c) => dispatch(core.handle_command(c)),
            },
            _ = tick.tick() => dispatch(core.tick()),
        }
    }
    let _ = tcmd_tx.send(TransportCommand::Shutdown);
    let _ = tokio::time::timeout(Duration::from_secs(3), transport_task).await;
}
