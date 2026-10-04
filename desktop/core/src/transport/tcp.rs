//! TCP dev transport (README §2.1), desktop side = **client**.
//!
//! Each frame travels as `length (u16 BE) ‖ frame`; `mtu` is 512. The
//! transport connects to the phone simulator's server, reports
//! `Connected` (the equivalent of subscribing to `TX`), and reconnects with
//! the same backoff as BLE (1, 2, 4, 8, max 15 s) whenever the connection
//! drops or cannot be made. Each connection gets a new peer id
//! `tcp:<addr>#<n>`.
//!
//! Writes never block the connection loop (docs/SPEC_QUESTIONS.md D12): a
//! per-connection writer task drains a bounded queue
//! ([`SEND_QUEUE_CAPACITY`] batches). A full queue or a write that takes
//! longer than [`WRITE_TIMEOUT`] disconnects the phone, and `Disconnect`
//! waits at most [`CLOSE_GRACE`] for queued frames to go out.
//!
//! Feature `dev-tcp` only; refused in release builds (lib.rs).

use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::TcpStream;
use tokio::sync::{mpsc, oneshot};
use tokio::task::JoinHandle;
use vq_protocol::TCP_MTU;

use super::policy::next_attempt_delay;
use super::{Transport, TransportCommand, TransportEvent};
use crate::events::{AdapterState, PeerId};

/// Connect timeout for one attempt.
pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
/// Longest time one queued batch of frames may take to write.
pub const WRITE_TIMEOUT: Duration = Duration::from_secs(10);
/// Queued `Send` batches per connection before the phone is disconnected.
pub const SEND_QUEUE_CAPACITY: usize = 64;
/// How long `Disconnect` waits for already-queued frames.
pub const CLOSE_GRACE: Duration = Duration::from_secs(1);

/// TCP client transport.
#[derive(Debug, Clone)]
pub struct TcpTransport {
    addr: String,
    write_timeout: Duration,
}

impl TcpTransport {
    /// Connect to `addr` (`host:port`; the phone simulator's default port is
    /// [`vq_protocol::TCP_DEFAULT_PORT`]).
    pub fn new(addr: impl Into<String>) -> Self {
        Self {
            addr: addr.into(),
            write_timeout: WRITE_TIMEOUT,
        }
    }

    /// Override the per-write timeout (tests).
    pub fn with_write_timeout(mut self, d: Duration) -> Self {
        self.write_timeout = d;
        self
    }
}

impl Transport for TcpTransport {
    fn start(
        self: Box<Self>,
        commands: mpsc::UnboundedReceiver<TransportCommand>,
        events: mpsc::Sender<TransportEvent>,
    ) -> JoinHandle<()> {
        tokio::spawn(run(self.addr, self.write_timeout, commands, events))
    }
}

/// Encode frames for the wire: `len ‖ frame` each.
pub fn encode_frames(frames: &[Vec<u8>]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(frames.iter().map(|f| f.len() + 2).sum());
    for f in frames {
        let len = u16::try_from(f.len()).expect("frame longer than 65535 bytes");
        buf.extend_from_slice(&len.to_be_bytes());
        buf.extend_from_slice(f);
    }
    buf
}

enum Exit {
    Shutdown,
    Reconnect,
}

async fn run(
    addr: String,
    write_timeout: Duration,
    mut cmds: mpsc::UnboundedReceiver<TransportCommand>,
    events: mpsc::Sender<TransportEvent>,
) {
    if events
        .send(TransportEvent::Adapter(AdapterState::Scanning))
        .await
        .is_err()
    {
        return;
    }
    let mut failures: u32 = 0;
    let mut holdoff: Option<Duration> = None;
    let mut conn_no: u64 = 0;
    loop {
        // Wait for the backoff while still honouring Shutdown.
        let sleep = tokio::time::sleep(next_attempt_delay(failures, holdoff.take()));
        tokio::pin!(sleep);
        loop {
            tokio::select! {
                _ = &mut sleep => break,
                c = cmds.recv() => match c {
                    None | Some(TransportCommand::Shutdown) => return,
                    Some(_) => {} // nothing is connected: stale command
                },
            }
        }
        let stream = match tokio::time::timeout(CONNECT_TIMEOUT, TcpStream::connect(&addr)).await {
            Ok(Ok(s)) => s,
            Ok(Err(e)) => {
                log::debug!("tcp connect {addr}: {e}");
                failures = failures.saturating_add(1);
                continue;
            }
            Err(_) => {
                failures = failures.saturating_add(1);
                continue;
            }
        };
        let _ = stream.set_nodelay(true);

        conn_no += 1;
        let peer: PeerId = format!("tcp:{addr}#{conn_no}");
        match connection(stream, peer, write_timeout, &mut cmds, &events, &mut holdoff).await {
            Exit::Shutdown => return,
            Exit::Reconnect => failures = 1,
        }
    }
}

enum WriterMsg {
    Frames(Vec<Vec<u8>>),
    Close,
}

async fn connection(
    stream: TcpStream,
    peer: PeerId,
    write_timeout: Duration,
    cmds: &mut mpsc::UnboundedReceiver<TransportCommand>,
    events: &mpsc::Sender<TransportEvent>,
    holdoff: &mut Option<Duration>,
) -> Exit {
    if events
        .send(TransportEvent::Connected {
            peer: peer.clone(),
            mtu: TCP_MTU,
        })
        .await
        .is_err()
    {
        return Exit::Shutdown;
    }
    let (rd, wr) = stream.into_split();
    let (done_tx, mut done_rx) = oneshot::channel();
    let reader = tokio::spawn(read_loop(rd, peer.clone(), events.clone(), done_tx));
    let (wq_tx, wq_rx) = mpsc::channel(SEND_QUEUE_CAPACITY);
    let (wdone_tx, mut wdone_rx) = oneshot::channel();
    let writer = tokio::spawn(write_loop(wr, wq_rx, write_timeout, wdone_tx));
    let close_deadline = tokio::time::sleep(Duration::from_secs(365 * 24 * 3600));
    tokio::pin!(close_deadline);
    let mut closing = false;
    let (exit, reason) = loop {
        tokio::select! {
            c = cmds.recv(), if !closing => match c {
                None | Some(TransportCommand::Shutdown) => break (Exit::Shutdown, "shutdown".to_owned()),
                Some(TransportCommand::Send { peer: p, frames }) if p == peer => {
                    if wq_tx.try_send(WriterMsg::Frames(frames)).is_err() {
                        break (Exit::Reconnect, "send queue full (phone not reading)".to_owned());
                    }
                }
                Some(TransportCommand::Disconnect { peer: p, reconnect_after }) if p == peer => {
                    *holdoff = reconnect_after;
                    if wq_tx.try_send(WriterMsg::Close).is_err() {
                        break (Exit::Reconnect, "closed by host".to_owned());
                    }
                    // Flush what is queued, but never wait on a stalled phone.
                    closing = true;
                    close_deadline.as_mut().reset(tokio::time::Instant::now() + CLOSE_GRACE);
                }
                Some(_) => {} // command for an older connection
            },
            w = &mut wdone_rx => {
                break (Exit::Reconnect, w.unwrap_or_else(|_| "writer stopped".to_owned()));
            }
            _ = &mut close_deadline, if closing => {
                break (Exit::Reconnect, "closed by host".to_owned());
            }
            r = &mut done_rx, if !closing => {
                break (Exit::Reconnect, r.unwrap_or_else(|_| "reader stopped".to_owned()));
            }
        }
    };
    writer.abort();
    reader.abort();
    let _ = writer.await;
    let _ = reader.await;
    let _ = events
        .send(TransportEvent::Disconnected { peer, reason })
        .await;
    exit
}

/// Write queued batches in order; each must finish within `timeout`.
async fn write_loop(
    mut wr: OwnedWriteHalf,
    mut queue: mpsc::Receiver<WriterMsg>,
    timeout: Duration,
    done: oneshot::Sender<String>,
) {
    let reason = loop {
        match queue.recv().await {
            Some(WriterMsg::Frames(frames)) => {
                match tokio::time::timeout(timeout, write_frames(&mut wr, &frames)).await {
                    Ok(Ok(())) => {}
                    Ok(Err(e)) => break format!("write failed: {e}"),
                    Err(_) => break format!("write timed out after {} ms", timeout.as_millis()),
                }
            }
            Some(WriterMsg::Close) | None => {
                let _ = tokio::time::timeout(CLOSE_GRACE, wr.shutdown()).await;
                break "closed by host".to_owned();
            }
        }
    };
    let _ = done.send(reason);
}

async fn write_frames(wr: &mut OwnedWriteHalf, frames: &[Vec<u8>]) -> std::io::Result<()> {
    wr.write_all(&encode_frames(frames)).await?;
    wr.flush().await
}

async fn read_loop(
    mut rd: OwnedReadHalf,
    peer: PeerId,
    events: mpsc::Sender<TransportEvent>,
    done: oneshot::Sender<String>,
) {
    let reason = loop {
        let len = match rd.read_u16().await {
            Ok(n) => usize::from(n),
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
                break "peer closed".to_owned()
            }
            Err(e) => break format!("read failed: {e}"),
        };
        let mut frame = vec![0u8; len];
        if let Err(e) = rd.read_exact(&mut frame).await {
            break format!("read failed: {e}");
        }
        if events
            .send(TransportEvent::Frame {
                peer: peer.clone(),
                frame,
            })
            .await
            .is_err()
        {
            break "host stopped".to_owned();
        }
    };
    let _ = done.send(reason);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frame_encoding() {
        assert_eq!(
            encode_frames(&[vec![3, 0, 0, 0xAA], vec![]]),
            vec![0, 4, 3, 0, 0, 0xAA, 0, 0]
        );
    }
}
