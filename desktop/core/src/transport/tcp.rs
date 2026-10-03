//! TCP dev transport (README §2.1), desktop side = **client**.
//!
//! Each frame travels as `length (u16 BE) ‖ frame`; `mtu` is 512. The
//! transport connects to the phone simulator's server, reports
//! `Connected` (the equivalent of subscribing to `TX`), and reconnects with
//! the same backoff as BLE (1, 2, 4, 8, max 15 s) whenever the connection
//! drops or cannot be made. Each connection gets a new peer id
//! `tcp:<addr>#<n>`.
//!
//! Feature `dev-tcp` only; never enabled in release builds of the app.

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

/// TCP client transport.
#[derive(Debug, Clone)]
pub struct TcpTransport {
    addr: String,
}

impl TcpTransport {
    /// Connect to `addr` (`host:port`; the phone simulator's default port is
    /// [`vq_protocol::TCP_DEFAULT_PORT`]).
    pub fn new(addr: impl Into<String>) -> Self {
        Self { addr: addr.into() }
    }
}

impl Transport for TcpTransport {
    fn start(
        self: Box<Self>,
        commands: mpsc::UnboundedReceiver<TransportCommand>,
        events: mpsc::Sender<TransportEvent>,
    ) -> JoinHandle<()> {
        tokio::spawn(run(self.addr, commands, events))
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
        match connection(stream, peer, &mut cmds, &events, &mut holdoff).await {
            Exit::Shutdown => return,
            Exit::Reconnect => failures = 1,
        }
    }
}

async fn connection(
    stream: TcpStream,
    peer: PeerId,
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
    let (rd, mut wr) = stream.into_split();
    let (done_tx, mut done_rx) = oneshot::channel();
    let reader = tokio::spawn(read_loop(rd, peer.clone(), events.clone(), done_tx));
    let (exit, reason) = loop {
        tokio::select! {
            c = cmds.recv() => match c {
                None | Some(TransportCommand::Shutdown) => break (Exit::Shutdown, "shutdown".to_owned()),
                Some(TransportCommand::Send { peer: p, frames }) if p == peer => {
                    if let Err(e) = write_frames(&mut wr, &frames).await {
                        break (Exit::Reconnect, format!("write failed: {e}"));
                    }
                }
                Some(TransportCommand::Disconnect { peer: p, reconnect_after }) if p == peer => {
                    *holdoff = reconnect_after;
                    break (Exit::Reconnect, "closed by host".to_owned());
                }
                Some(_) => {} // command for an older connection
            },
            r = &mut done_rx => {
                break (Exit::Reconnect, r.unwrap_or_else(|_| "reader stopped".to_owned()));
            }
        }
    };
    let _ = wr.shutdown().await;
    reader.abort();
    let _ = reader.await;
    let _ = events
        .send(TransportEvent::Disconnected { peer, reason })
        .await;
    exit
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
