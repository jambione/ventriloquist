//! In-process end-to-end test: the real host runtime and `TcpTransport`
//! against a fake phone (built from `vq-protocol`) serving TCP. Covers
//! pairing, partial/final/edit, a dropped connection with automatic
//! reconnect, and duplicate re-delivery. Also a smoke test of the
//! `vq-host` binary's JSON-lines output.

#![cfg(feature = "dev-tcp")]

mod common;

use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use common::{acks, FakePhone};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc::Receiver;
use tokio::time::timeout;
use uuid::Uuid;
use vq_host_core::events::PeerState;
use vq_host_core::transport::tcp::{encode_frames, TcpTransport};
use vq_host_core::{spawn_host, CoreOptions, HostCommand, HostEvent, SystemClock};
use vq_protocol::{Inbound, Message, UttState, TCP_MTU};

const T: Duration = Duration::from_secs(10);

async fn send(stream: &mut TcpStream, frames: Vec<Vec<u8>>) {
    stream.write_all(&encode_frames(&frames)).await.unwrap();
}

/// Read frames until `n` messages are decoded (pings are skipped).
async fn recv(stream: &mut TcpStream, phone: &mut FakePhone, n: usize) -> Vec<Inbound> {
    let mut out = Vec::new();
    timeout(T, async {
        while out.len() < n {
            let len = stream.read_u16().await.unwrap();
            let mut f = vec![0; usize::from(len)];
            stream.read_exact(&mut f).await.unwrap();
            for m in phone.receive(&[f]) {
                if !matches!(m, Inbound::Encrypted(Message::Ping)) {
                    out.push(m);
                }
            }
        }
    })
    .await
    .expect("timed out waiting for desktop messages");
    out
}

async fn wait_for<F: FnMut(&HostEvent) -> bool>(
    rx: &mut Receiver<HostEvent>,
    seen: &mut Vec<HostEvent>,
    mut pred: F,
) -> HostEvent {
    timeout(T, async {
        loop {
            let e = rx.recv().await.expect("host stopped");
            seen.push(e.clone());
            if pred(&e) {
                return e;
            }
        }
    })
    .await
    .expect("timed out waiting for host event")
}

fn read_logs(dir: &Path) -> String {
    let mut files: Vec<_> = std::fs::read_dir(dir)
        .unwrap()
        .map(|e| e.unwrap().path())
        .filter(|p| p.extension().is_some_and(|x| x == "md"))
        .collect();
    files.sort();
    files
        .iter()
        .map(|p| std::fs::read_to_string(p).unwrap())
        .collect()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn pair_stream_reconnect_and_redeliver_over_tcp() {
    let dir = tempfile::tempdir().unwrap();
    let log_dir = dir.path().join("logs");
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    let (handle, mut events, task) = spawn_host(
        CoreOptions {
            config_dir: dir.path().join("config"),
            log_dir_override: Some(log_dir.clone()),
            name_override: Some("E2E Desktop".into()),
            clock: Arc::new(SystemClock::new()),
        },
        Box::new(TcpTransport::new(addr)),
    )
    .unwrap();
    let mut seen = Vec::new();
    let mut phone = FakePhone::new("Sim Phone");

    // ---- first connection: pairing and streaming
    let (mut s, _) = timeout(T, listener.accept()).await.unwrap().unwrap();
    phone.connect(TCP_MTU);
    let m = recv(&mut s, &mut phone, 1).await;
    assert!(matches!(&m[0], Inbound::Plaintext(Message::Hello(h)) if h.name == "E2E Desktop"));
    let f = phone.hello(None);
    send(&mut s, f).await;
    let f = phone.pair_request();
    send(&mut s, f).await;
    let m = recv(&mut s, &mut phone, 1).await;
    assert!(matches!(
        &m[0],
        Inbound::Plaintext(Message::PairChallenge(_))
    ));
    let HostEvent::PairingCodeShown { code, .. } = wait_for(&mut events, &mut seen, |e| {
        matches!(e, HostEvent::PairingCodeShown { .. })
    })
    .await
    else {
        unreachable!()
    };
    let f = phone.pair_confirm(&code);
    send(&mut s, f).await;
    let m = recv(&mut s, &mut phone, 1).await;
    let Inbound::Plaintext(Message::PairResult(r)) = &m[0] else {
        panic!("{m:?}")
    };
    assert!(phone.on_pair_result(r));

    let id = Uuid::new_v4();
    let mut f = phone.utt(id, 0, UttState::Partial, "kube");
    f.extend(phone.utt(id, 1, UttState::Partial, "kubectl get"));
    f.extend(phone.utt(id, 2, UttState::Final, "kubectl get pods\n  -n default"));
    send(&mut s, f).await;
    assert_eq!(acks(&recv(&mut s, &mut phone, 1).await), vec![(id, 2)]);
    wait_for(
        &mut events,
        &mut seen,
        |e| matches!(e, HostEvent::EntryUpserted { entry } if entry.rev == 2 && !entry.partial),
    )
    .await;

    // ---- the phone drops the connection; the host reconnects by itself
    drop(s);
    let (mut s, _) = timeout(T, listener.accept()).await.unwrap().unwrap();
    phone.connect(TCP_MTU);
    recv(&mut s, &mut phone, 1).await; // hello
    let f = phone.hello(None); // paired:true now
    phone.establish();
    send(&mut s, f).await;
    // Pending final re-sent (duplicate) plus a new edit.
    let mut f = phone.utt(id, 2, UttState::Final, "kubectl get pods\n  -n default");
    f.extend(phone.utt(id, 3, UttState::Edit, "kubectl get pods -A"));
    f.extend(phone.utt(id, 3, UttState::Edit, "kubectl get pods -A"));
    send(&mut s, f).await;
    assert_eq!(
        acks(&recv(&mut s, &mut phone, 3).await),
        vec![(id, 2), (id, 3), (id, 3)]
    );
    wait_for(
        &mut events,
        &mut seen,
        |e| matches!(e, HostEvent::EntryUpserted { entry } if entry.edited),
    )
    .await;

    handle.send(HostCommand::Shutdown);
    timeout(T, task).await.unwrap().unwrap();
    while let Ok(e) = events.try_recv() {
        seen.push(e);
    }

    let secure = seen
        .iter()
        .filter(|e| {
            matches!(
                e,
                HostEvent::ConnectionStatus {
                    state: PeerState::Secure,
                    ..
                }
            )
        })
        .count();
    assert_eq!(secure, 2);
    let revs: Vec<u32> = seen
        .iter()
        .filter_map(|e| match e {
            HostEvent::EntryUpserted { entry } => Some(entry.rev),
            _ => None,
        })
        .collect();
    // Duplicates are not re-upserted. Queued partials of the same entry may
    // be coalesced while the consumer lags (latest wins, D11); finals and
    // edits never are.
    assert!(revs.windows(2).all(|w| w[0] < w[1]), "{revs:?}");
    assert!(revs.ends_with(&[2, 3]), "{revs:?}");
    assert!(revs.contains(&1), "the latest partial is kept: {revs:?}");
    let log = read_logs(&log_dir);
    assert_eq!(log.matches("\n- **").count(), 2, "{log}");
    assert!(log.contains(" · Sim Phone · `id="));
    assert!(log.contains("\n  kubectl get pods\n    -n default\n"));
    assert!(log.contains("· edited\n  kubectl get pods -A\n"));
    assert!(!log.contains("kube\n"), "partials are not logged");
}

async fn next_json<R: tokio::io::AsyncBufRead + Unpin>(
    lines: &mut tokio::io::Lines<R>,
) -> serde_json::Value {
    let l = timeout(T, lines.next_line())
        .await
        .unwrap()
        .unwrap()
        .expect("stdout open");
    serde_json::from_str(&l).unwrap_or_else(|e| panic!("{l:?}: {e}"))
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn vq_host_binary_prints_json_lines() {
    let dir = tempfile::tempdir().unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    let mut child = tokio::process::Command::new(env!("CARGO_BIN_EXE_vq-host"))
        .args(["--connect", &addr, "--name", "Bin Desktop"])
        .arg("--log-dir")
        .arg(dir.path().join("logs"))
        .arg("--config-dir")
        .arg(dir.path().join("cfg"))
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .unwrap();
    let mut lines = tokio::io::BufReader::new(child.stdout.take().unwrap()).lines();
    let first = next_json(&mut lines).await;
    assert_eq!(first["event"], "started");
    assert_eq!(first["name"], "Bin Desktop");

    let mut phone = FakePhone::new("Bin Phone");
    let (mut s, _) = timeout(T, listener.accept()).await.unwrap().unwrap();
    phone.connect(TCP_MTU);
    recv(&mut s, &mut phone, 1).await;
    let f = phone.hello(None);
    send(&mut s, f).await;
    let f = phone.pair_request();
    send(&mut s, f).await;
    recv(&mut s, &mut phone, 1).await;
    let code = loop {
        let v = next_json(&mut lines).await;
        if v["event"] == "pairing_code_shown" {
            assert_eq!(v["phone_name"], "Bin Phone");
            break v["code"].as_str().unwrap().to_owned();
        }
    };
    let f = phone.pair_confirm(&code);
    send(&mut s, f).await;
    let m = recv(&mut s, &mut phone, 1).await;
    let Inbound::Plaintext(Message::PairResult(r)) = &m[0] else {
        panic!()
    };
    assert!(phone.on_pair_result(r));
    let id = Uuid::new_v4();
    let f = phone.utt(id, 0, UttState::Final, "echo hi");
    send(&mut s, f).await;
    let entry = loop {
        let v = next_json(&mut lines).await;
        if v["event"] == "entry_upserted" {
            break v["entry"].clone();
        }
    };
    assert_eq!(entry["id"], id.to_string());
    assert_eq!(entry["rev"], 0);
    assert_eq!(entry["state"], "final");
    assert_eq!(entry["text"], "echo hi");
    assert_eq!(entry["partial"], false);
    assert_eq!(entry["edited"], false);
    assert_eq!(entry["device_name"], "Bin Phone");

    // A command on stdin is accepted.
    let mut stdin = child.stdin.take().unwrap();
    stdin
        .write_all(
            format!(
                "{{\"command\":\"forget_peer\",\"device_id\":\"{}\"}}\n",
                phone.device_id
            )
            .as_bytes(),
        )
        .await
        .unwrap();
    loop {
        let v = next_json(&mut lines).await;
        if v["event"] == "paired_peers_changed" {
            assert_eq!(v["peers"].as_array().unwrap().len(), 0);
            break;
        }
    }
    child.kill().await.unwrap();
}
