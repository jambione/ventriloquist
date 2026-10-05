//! RelayTransport against a mock relay (tests/relay_transport/mock.rs):
//! connect, room creation, join, routing, reconnect, WebSocket → long-poll
//! fallback and back, proxy tunnelling, categorised failures, and QR
//! pairing end to end through the host.

#![cfg(feature = "relay")]
#![allow(dead_code)]

#[path = "../common/mod.rs"]
mod common;
mod mock;

use std::collections::HashMap;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::http::HeaderValue;
use tokio_tungstenite::tungstenite::Message;
use vq_host_core::events::{RelayLink, RelayReason, RelayStatus};
use vq_host_core::relay_room::RelayRoomStore;
use vq_host_core::transport::proxy::NoOsProxy;
use vq_host_core::transport::relay::{RelayHandle, RelayOptions, RelayTransport, Timing, RELAY_MTU};
use vq_host_core::transport::{Transport, TransportCommand, TransportEvent};

use mock::{ProxyMode, Running, OWNER};

const WAIT: Duration = Duration::from_secs(10);

fn fast() -> Timing {
    Timing {
        backoff_unit: Duration::from_millis(20),
        connect_timeout: Duration::from_secs(2),
        ws_retry_every: Duration::from_secs(300),
        poll_timeout: Duration::from_secs(5),
        write_timeout: Duration::from_secs(2),
        ..Timing::default()
    }
}

struct Rig {
    mock: Running,
    store: Arc<RelayRoomStore>,
    handle: RelayHandle,
    cmd: mpsc::UnboundedSender<TransportCommand>,
    ev: mpsc::Receiver<TransportEvent>,
    task: JoinHandle<()>,
    _dir: tempfile::TempDir,
}

fn options(owner: Option<&str>, timing: Timing, env: HashMap<&'static str, String>) -> RelayOptions {
    RelayOptions {
        owner_token: owner.map(str::to_owned),
        os_proxy: Box::new(NoOsProxy),
        env: Arc::new(move |k| env.get(k).cloned()),
        timing,
    }
}

async fn rig_with(opts: impl FnOnce(&mock::Running) -> RelayOptions, precreate: bool) -> Rig {
    rig_with_room(opts, precreate.then_some(None)).await
}

/// `precreate`: `Some(None)` creates the room with our secret, `Some(Some(s))` with another one.
async fn rig_with_room(opts: impl FnOnce(&mock::Running) -> RelayOptions, precreate: Option<Option<&str>>) -> Rig {
    let mock = mock::start().await;
    let dir = tempfile::tempdir().unwrap();
    let store = Arc::new(RelayRoomStore::load_or_create(dir.path()).unwrap());
    store.set_url(&mock.url()).unwrap();
    if let Some(other) = precreate {
        let r = store.get();
        mock.mock.create_room(&r.room_id, other.unwrap_or(&r.room_secret), Some(&r.desktop_secret));
    }
    let o = opts(&mock);
    let (transport, handle) = RelayTransport::new(store.clone(), o);
    let (cmd, cmd_rx) = mpsc::unbounded_channel();
    let (ev_tx, ev) = mpsc::channel(256);
    let task = Box::new(transport).start(cmd_rx, ev_tx);
    Rig { mock, store, handle, cmd, ev, task, _dir: dir }
}

async fn rig(owner: Option<&'static str>) -> Rig {
    rig_with(|_| options(owner, fast(), HashMap::new()), false).await
}

impl Rig {
    /// The next event matching `f` (others are skipped).
    async fn next<T>(&mut self, mut f: impl FnMut(&TransportEvent) -> Option<T>) -> T {
        let deadline = tokio::time::Instant::now() + WAIT;
        loop {
            let e = tokio::time::timeout_at(deadline, self.ev.recv())
                .await
                .expect("timed out waiting for a transport event")
                .expect("transport stopped");
            if let Some(t) = f(&e) {
                return t;
            }
        }
    }

    async fn link(&mut self, want: RelayLink) -> RelayStatus {
        self.next(|e| match e {
            TransportEvent::Relay(s) if s.link == want => Some(s.clone()),
            _ => None,
        })
        .await
    }

    async fn unreachable(&mut self) -> RelayStatus {
        self.link(RelayLink::Unreachable).await
    }

    async fn connected(&mut self) -> String {
        self.next(|e| match e {
            TransportEvent::Connected { peer, mtu } => {
                assert_eq!(*mtu, RELAY_MTU);
                Some(peer.clone())
            }
            _ => None,
        })
        .await
    }

    async fn stop(self) {
        let _ = self.cmd.send(TransportCommand::Shutdown);
        tokio::time::timeout(WAIT, self.task).await.expect("transport stops").unwrap();
    }

    /// Wait until the mock has registered the desktop connection.
    async fn desktop_registered(&self) {
        let (room, _) = self.room();
        for _ in 0..200 {
            if self.mock.mock.desktop_present(&room) {
                return;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        panic!("the desktop never registered");
    }

    fn room(&self) -> (String, String) {
        let r = self.store.get();
        (r.room_id, r.room_secret.to_string())
    }
}

type PhoneWs = tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>;

async fn phone(rig: &Rig) -> PhoneWs {
    let (room, secret) = rig.room();
    let url = format!("ws://{}/v1/rooms/{room}/ws?role=phone", rig.mock.addr);
    let mut req = url.into_client_request().unwrap();
    req.headers_mut().insert("Authorization", HeaderValue::from_str(&format!("Bearer {secret}")).unwrap());
    let (ws, _) = tokio_tungstenite::connect_async(req).await.expect("phone connects");
    ws
}

fn b64(bytes: &[u8]) -> String {
    base64::Engine::encode(&base64::engine::general_purpose::STANDARD, bytes)
}

async fn phone_send(ws: &mut PhoneWs, bytes: &[u8]) {
    let m = serde_json::json!({"type":"frame","to":"ignored","data":b64(bytes)});
    ws.send(Message::text(m.to_string())).await.unwrap();
}

/// The next frame the phone receives (other messages are skipped).
async fn phone_recv(ws: &mut PhoneWs) -> Vec<u8> {
    loop {
        let m = tokio::time::timeout(WAIT, ws.next()).await.expect("phone timed out").expect("closed").unwrap();
        if let Message::Text(t) = m {
            let v: serde_json::Value = serde_json::from_str(t.as_str()).unwrap();
            if v["type"] == "frame" {
                return base64::Engine::decode(&base64::engine::general_purpose::STANDARD, v["data"].as_str().unwrap())
                    .unwrap();
            }
        }
    }
}

// ------------------------------------------------------------------ tests

#[tokio::test]
async fn connects_over_websocket_creates_the_room_and_routes_frames() {
    let mut r = rig(Some(OWNER)).await;
    let st = r.link(RelayLink::Websocket).await;
    assert_eq!((st.reason, st.detail), (None, None));
    // The room was created with the hash of our secret.
    let (room, secret) = r.room();
    assert_eq!(r.mock.mock.room_hash(&room).unwrap(), vq_host_core::relay_room::secret_hash(&secret));
    // X1: the relay also learned the desktop secret's hash (never the QR's).
    let ds = r.store.get();
    assert_eq!(r.mock.mock.desktop_hash(&room).unwrap(), ds.desktop_secret_hash());
    assert_ne!(ds.desktop_secret_hash(), ds.secret_hash());
    assert_eq!(r.mock.mock.0.put_calls.load(Ordering::SeqCst), 1);

    let mut p = phone(&r).await;
    let peer = r.connected().await;
    assert!(peer.starts_with("relay:"), "{peer}");

    // phone -> desktop
    phone_send(&mut p, b"hello desktop").await;
    let (from, frame) = r
        .next(|e| match e {
            TransportEvent::Frame { peer, frame } => Some((peer.clone(), frame.clone())),
            _ => None,
        })
        .await;
    assert_eq!((from.as_str(), frame.as_slice()), (peer.as_str(), &b"hello desktop"[..]));

    // desktop -> phone (several frames, in order)
    r.cmd
        .send(TransportCommand::Send { peer: peer.clone(), frames: vec![b"one".to_vec(), b"two".to_vec()] })
        .unwrap();
    assert_eq!(phone_recv(&mut p).await, b"one");
    assert_eq!(phone_recv(&mut p).await, b"two");

    // The phone leaves: Disconnected.
    p.close(None).await.unwrap();
    let gone = r
        .next(|e| match e {
            TransportEvent::Disconnected { peer, reason } => Some((peer.clone(), reason.clone())),
            _ => None,
        })
        .await;
    assert_eq!(gone.0, peer);
    r.stop().await;
}

#[tokio::test]
async fn routing_goes_to_the_right_phone_and_unknown_peers_are_ignored() {
    let mut r = rig(Some(OWNER)).await;
    r.link(RelayLink::Websocket).await;
    let mut a = phone(&r).await;
    let pa = r.connected().await;
    let mut b = phone(&r).await;
    let pb = r.connected().await;
    assert_ne!(pa, pb);
    r.cmd.send(TransportCommand::Send { peer: "relay:nobody".into(), frames: vec![b"x".to_vec()] }).unwrap();
    r.cmd.send(TransportCommand::Send { peer: "tcp:1".into(), frames: vec![b"x".to_vec()] }).unwrap();
    r.cmd.send(TransportCommand::Send { peer: pb.clone(), frames: vec![b"for-b".to_vec()] }).unwrap();
    r.cmd.send(TransportCommand::Send { peer: pa.clone(), frames: vec![b"for-a".to_vec()] }).unwrap();
    assert_eq!(phone_recv(&mut b).await, b"for-b");
    assert_eq!(phone_recv(&mut a).await, b"for-a");
    r.stop().await;
}

#[tokio::test]
async fn host_disconnect_reports_the_peer_gone_and_ignores_its_frames() {
    let mut r = rig(Some(OWNER)).await;
    r.link(RelayLink::Websocket).await;
    let mut p = phone(&r).await;
    let peer = r.connected().await;
    r.cmd.send(TransportCommand::Disconnect { peer: peer.clone(), reconnect_after: None }).unwrap();
    r.next(|e| matches!(e, TransportEvent::Disconnected { .. }).then_some(())).await;
    phone_send(&mut p, b"ignored").await;
    // A later phone still works and the banned one's frame never shows up.
    let mut q = phone(&r).await;
    let pq = r.connected().await;
    phone_send(&mut q, b"from-q").await;
    let f = r
        .next(|e| match e {
            TransportEvent::Frame { peer, frame } => Some((peer.clone(), frame.clone())),
            _ => None,
        })
        .await;
    assert_eq!(f, (pq, b"from-q".to_vec()));
    r.stop().await;
}

#[tokio::test]
async fn peers_already_in_the_room_are_announced_on_connect() {
    let mut r = rig_with(|_| options(None, fast(), HashMap::new()), true).await;
    // Join before the desktop (the transport is already running; wait for it first).
    r.link(RelayLink::Websocket).await;
    let _p = phone(&r).await;
    r.connected().await;
    // Drop the desktop link: the phone stays; the reconnected desktop gets peer_joined again.
    let (room, _) = r.room();
    r.desktop_registered().await;
    r.mock.mock.kick_desktop(&room);
    r.next(|e| matches!(e, TransportEvent::Disconnected { .. }).then_some(())).await;
    r.connected().await;
    r.stop().await;
}

#[tokio::test]
async fn reconnects_with_backoff_after_the_relay_drops_the_socket() {
    let mut r = rig(Some(OWNER)).await;
    r.link(RelayLink::Websocket).await;
    let (room, _) = r.room();
    // One drop: reported as not connected, then connected again. (A second
    // drop within 10 s would switch to the long-poll fallback instead; see
    // `a_websocket_that_keeps_dropping_quickly_triggers_the_fallback`.)
    r.desktop_registered().await;
    r.mock.mock.kick_desktop(&room);
    r.link(RelayLink::Connecting).await;
    r.link(RelayLink::Websocket).await;
    // Still routes after the reconnects.
    let mut p = phone(&r).await;
    let peer = r.connected().await;
    r.cmd.send(TransportCommand::Send { peer, frames: vec![b"again".to_vec()] }).unwrap();
    assert_eq!(phone_recv(&mut p).await, b"again");
    r.stop().await;
}

#[tokio::test]
async fn a_blocked_websocket_falls_back_to_long_poll_and_still_routes() {
    let mut r = rig(Some(OWNER)).await;
    r.mock.mock.0.ws_blocked.store(false, Ordering::SeqCst);
    r.link(RelayLink::Websocket).await;
    r.stop().await;

    // New rig with the WebSocket blocked from the start.
    let mut r = rig_with(
        |m| {
            m.mock.0.ws_blocked.store(true, Ordering::SeqCst);
            options(Some(OWNER), fast(), HashMap::new())
        },
        false,
    )
    .await;
    let st = r.link(RelayLink::Fallback).await;
    assert_eq!(st.reason, None);
    // A phone on a WebSocket and a desktop on long-poll interoperate.
    r.mock.mock.0.ws_blocked.store(true, Ordering::SeqCst); // desktop role only matters; phone uses `role=phone`
    let (room, secret) = r.room();
    let url = format!("ws://{}/v1/rooms/{room}/ws?role=phone", r.mock.addr);
    let mut req = url.into_client_request().unwrap();
    req.headers_mut().insert("Authorization", HeaderValue::from_str(&format!("Bearer {secret}")).unwrap());
    // `ws_blocked` blocks every upgrade in the mock; unblock for the phone.
    r.mock.mock.0.ws_blocked.store(false, Ordering::SeqCst);
    let (mut p, _) = tokio_tungstenite::connect_async(req).await.expect("phone connects");
    let peer = r.connected().await;
    phone_send(&mut p, b"via-poll").await;
    let f = r
        .next(|e| match e {
            TransportEvent::Frame { frame, .. } => Some(frame.clone()),
            _ => None,
        })
        .await;
    assert_eq!(f, b"via-poll");
    r.cmd
        .send(TransportCommand::Send { peer: peer.clone(), frames: vec![b"a".to_vec(), b"b".to_vec()] })
        .unwrap();
    assert_eq!(phone_recv(&mut p).await, b"a");
    assert_eq!(phone_recv(&mut p).await, b"b");
    // The phone leaves: peer_left arrives over long-poll.
    p.close(None).await.unwrap();
    r.next(|e| matches!(e, TransportEvent::Disconnected { .. }).then_some(())).await;
    r.stop().await;
}

#[tokio::test]
async fn the_websocket_is_retried_after_the_fallback_interval() {
    let timing = Timing { ws_retry_every: Duration::from_millis(500), ..fast() };
    let mut r = rig_with(
        |m| {
            m.mock.0.ws_blocked.store(true, Ordering::SeqCst);
            options(Some(OWNER), timing.clone(), HashMap::new())
        },
        false,
    )
    .await;
    r.link(RelayLink::Fallback).await;
    r.mock.mock.0.ws_blocked.store(false, Ordering::SeqCst);
    r.link(RelayLink::Websocket).await;
    r.stop().await;
}

#[tokio::test]
async fn a_websocket_that_keeps_dropping_quickly_triggers_the_fallback() {
    let mut r = rig_with(
        |m| {
            m.mock.0.ws_drop_immediately.store(true, Ordering::SeqCst);
            options(Some(OWNER), fast(), HashMap::new())
        },
        false,
    )
    .await;
    r.link(RelayLink::Fallback).await;
    assert!(r.mock.mock.0.ws_attempts.load(Ordering::SeqCst) >= 2);
    r.stop().await;
}

#[tokio::test]
async fn failures_are_categorised() {
    // No owner token and no room.
    let mut r = rig(None).await;
    let st = r.unreachable().await;
    assert_eq!(st.reason, Some(RelayReason::OwnerTokenRejected));
    // Setting the token fixes it without a restart.
    r.handle.set_owner_token(Some(OWNER.into()));
    r.link(RelayLink::Websocket).await;
    r.stop().await;

    // Wrong owner token.
    let mut r = rig_with(|_| options(Some("wrong"), fast(), HashMap::new()), false).await;
    assert_eq!(r.unreachable().await.reason, Some(RelayReason::OwnerTokenRejected));
    r.stop().await;

    // The room id exists with another secret.
    let mut r = rig_with_room(|_| options(Some(OWNER), fast(), HashMap::new()), Some(Some("someone else's"))).await;
    let st = r.unreachable().await;
    assert_eq!(st.reason, Some(RelayReason::RoomConflict), "{st:?}");
    r.stop().await;

    // Nothing listens there.
    let mut r = rig(Some(OWNER)).await;
    r.store.set_url("http://127.0.0.1:1").unwrap();
    r.handle.set_url("http://127.0.0.1:1").unwrap();
    let st = r.unreachable().await;
    assert!(st.reason.is_some() && st.detail.is_some());
    r.stop().await;
}

#[tokio::test]
async fn uses_an_http_connect_tunnel_through_the_proxy() {
    let proxy = mock::start_proxy(ProxyMode::Allow).await;
    let paddr = proxy.addr;
    let mut r = rig_with(
        move |_| {
            let mut env = HashMap::new();
            env.insert("HTTP_PROXY", format!("http://{paddr}"));
            options(None, fast(), env)
        },
        true,
    )
    .await;
    r.link(RelayLink::Websocket).await;
    let seen = proxy.connects.lock().unwrap().clone();
    assert_eq!(seen, vec![r.mock.addr.to_string()]);
    // Frames flow through the tunnel.
    let mut p = phone(&r).await;
    let peer = r.connected().await;
    r.cmd.send(TransportCommand::Send { peer, frames: vec![b"tunnelled".to_vec()] }).unwrap();
    assert_eq!(phone_recv(&mut p).await, b"tunnelled");
    r.stop().await;
}

/// X1: a room created before desktop secrets existed is upgraded by the
/// next PUT (valid owner token and room secret), then the desktop connects.
#[tokio::test]
async fn a_room_without_a_desktop_hash_is_upgraded_by_the_put() {
    let mock = mock::start().await;
    let dir = tempfile::tempdir().unwrap();
    let store = Arc::new(RelayRoomStore::load_or_create(dir.path()).unwrap());
    store.set_url(&mock.url()).unwrap();
    let room = store.get();
    mock.mock.create_room(&room.room_id, &room.room_secret, None);
    assert!(mock.mock.desktop_hash(&room.room_id).is_none());
    let o = options(Some(OWNER), fast(), HashMap::new());
    let (transport, handle) = RelayTransport::new(store.clone(), o);
    let (cmd, cmd_rx) = mpsc::unbounded_channel();
    let (ev_tx, ev) = mpsc::channel(256);
    let task = Box::new(transport).start(cmd_rx, ev_tx);
    let mut r = Rig { mock, store, handle, cmd, ev, task, _dir: dir };
    r.link(RelayLink::Websocket).await;
    assert_eq!(r.mock.mock.desktop_hash(&room.room_id).unwrap(), room.desktop_secret_hash());
    r.stop().await;
}

#[tokio::test]
async fn proxy_refusals_are_categorised() {
    for (mode, reason) in [
        (ProxyMode::Deny407, RelayReason::ProxyAuthRequired),
        (ProxyMode::Deny407Ntlm, RelayReason::ProxyAuthUnsupported),
        (ProxyMode::Deny403, RelayReason::ProxyBlocked),
    ] {
        let proxy = mock::start_proxy(mode).await;
        let paddr = proxy.addr;
        let mut r = rig_with(
            move |_| {
                let mut env = HashMap::new();
                env.insert("HTTP_PROXY", format!("http://{paddr}"));
                options(None, fast(), env)
            },
            true,
        )
        .await;
        let st = r.unreachable().await;
        assert_eq!(st.reason, Some(reason), "{st:?}");
        r.stop().await;
    }
}

#[tokio::test]
async fn no_proxy_bypasses_the_proxy() {
    let proxy = mock::start_proxy(ProxyMode::Deny403).await;
    let paddr = proxy.addr;
    let mut r = rig_with(
        move |_| {
            let mut env = HashMap::new();
            env.insert("HTTP_PROXY", format!("http://{paddr}"));
            env.insert("NO_PROXY", "127.0.0.1".to_owned());
            options(None, fast(), env)
        },
        true,
    )
    .await;
    r.link(RelayLink::Websocket).await;
    assert!(proxy.connects.lock().unwrap().is_empty());
    r.stop().await;
}

#[tokio::test]
async fn test_connection_reports_ok_fallback_and_errors() {
    let r = rig(Some(OWNER)).await;
    let rep = r.handle.test_connection().await;
    assert_eq!(rep.status.link, RelayLink::Websocket, "{rep:?}");
    assert_eq!(rep.checked, ["health", "room", "websocket"]);
    r.mock.mock.0.ws_blocked.store(true, Ordering::SeqCst);
    let rep = r.handle.test_connection().await;
    assert_eq!(rep.status.link, RelayLink::Fallback, "{rep:?}");
    r.mock.mock.0.ws_blocked.store(false, Ordering::SeqCst);
    r.handle.set_owner_token(Some("bad".into()));
    let rep = r.handle.test_connection().await;
    assert_eq!(rep.status.reason, Some(RelayReason::OwnerTokenRejected), "{rep:?}");
    r.handle.set_url("http://127.0.0.1:1").unwrap();
    let rep = r.handle.test_connection().await;
    assert_eq!(rep.status.link, RelayLink::Unreachable, "{rep:?}");
    assert_eq!(rep.checked, ["health"]);
    r.stop().await;
}

#[tokio::test]
async fn reset_room_rotates_credentials_recreates_the_room_and_deletes_the_old_one() {
    let mut r = rig(Some(OWNER)).await;
    r.link(RelayLink::Websocket).await;
    let (old, _) = r.room();
    r.handle.reset_room().unwrap();
    let (new, _) = r.room();
    assert_ne!(old, new);
    // Reconnects to the new room (a fresh PUT) ...
    r.link(RelayLink::Connecting).await;
    r.link(RelayLink::Websocket).await;
    assert!(r.mock.mock.has_room(&new));
    // ... and the old one is deleted on the relay.
    for _ in 0..100 {
        if r.mock.mock.0.deleted.lock().unwrap().contains(&old) {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(r.mock.mock.0.deleted.lock().unwrap().contains(&old));
    r.stop().await;
}

// ------------------------------------------------- QR pairing end to end

#[tokio::test]
async fn qr_pairing_through_the_host_uses_the_code_from_the_uri() {
    use common::FakePhone;
    use vq_host_core::events::PhonePairingEnd;
    use vq_host_core::{spawn_host, CoreOptions, HostCommand, HostEvent, SystemClock};
    use vq_protocol::{Inbound, Message as ProtoMsg};

    let mock = mock::start().await;
    let dir = tempfile::tempdir().unwrap();
    let store = Arc::new(RelayRoomStore::load_or_create(&dir.path().join("config")).unwrap());
    store.set_url(&mock.url()).unwrap();
    let (transport, _handle) = RelayTransport::new(store.clone(), options(Some(OWNER), fast(), HashMap::new()));
    let (host, mut events, task) = spawn_host(
        CoreOptions {
            config_dir: dir.path().join("config"),
            log_dir_override: Some(dir.path().join("logs")),
            name_override: Some("QR Desktop".into()),
            clock: Arc::new(SystemClock::new()),
            relay: Some(store.clone()),
        },
        Box::new(transport),
    )
    .unwrap();

    async fn next_event<T>(events: &mut mpsc::Receiver<HostEvent>, mut f: impl FnMut(&HostEvent) -> Option<T>) -> T {
        loop {
            let e = tokio::time::timeout(WAIT, events.recv()).await.expect("host event").expect("host stopped");
            if let Some(t) = f(&e) {
                return t;
            }
        }
    }

    next_event(&mut events, |e| match e {
        HostEvent::RelayStatus { status } if status.link == RelayLink::Websocket => Some(()),
        _ => None,
    })
    .await;
    host.send(HostCommand::StartPhonePairing);
    let uri = next_event(&mut events, |e| match e {
        HostEvent::PhonePairingQr { uri, expires_in_secs } => {
            assert_eq!(*expires_in_secs, 120);
            Some(uri.clone())
        }
        _ => None,
    })
    .await;
    let q: HashMap<String, String> =
        url::Url::parse(&uri).unwrap().query_pairs().map(|(k, v)| (k.into_owned(), v.into_owned())).collect();
    assert_eq!(q["room"], store.get().room_id);
    assert_eq!(q["s"], *store.get().room_secret);

    // The phone joins the room from the QR's credentials.
    let url = format!("ws://{}/v1/rooms/{}/ws?role=phone", mock.addr, q["room"]);
    let mut req = url.into_client_request().unwrap();
    req.headers_mut().insert("Authorization", HeaderValue::from_str(&format!("Bearer {}", q["s"])).unwrap());
    let (mut ws, _) = tokio_tungstenite::connect_async(req).await.unwrap();

    let mut phone = FakePhone::new("Jon's iPhone");
    phone.connect(RELAY_MTU);
    async fn recv_frames(ws: &mut PhoneWs, phone: &mut FakePhone, want: usize) -> Vec<Inbound> {
        let mut out = Vec::new();
        while out.len() < want {
            let f = phone_recv(ws).await;
            out.extend(phone.receive(&[f]));
        }
        out
    }
    let hello = recv_frames(&mut ws, &mut phone, 1).await;
    assert!(matches!(hello.as_slice(), [Inbound::Plaintext(ProtoMsg::Hello(_))]));
    // Key pinning: the hello's key is the `k` of the QR.
    let pinned = base64::Engine::decode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, &q["k"]).unwrap();
    assert_eq!(phone.conn.as_ref().unwrap().desktop_hello.as_ref().unwrap().public_key.to_vec(), pinned);

    for f in phone.hello(Some(false)) {
        phone_send(&mut ws, &f).await;
    }
    for f in phone.pair_request() {
        phone_send(&mut ws, &f).await;
    }
    let ch = recv_frames(&mut ws, &mut phone, 1).await;
    assert!(matches!(ch.as_slice(), [Inbound::Plaintext(ProtoMsg::PairChallenge(_))]));
    // The code comes from the QR; the user types nothing.
    for f in phone.pair_confirm(&q["c"]) {
        phone_send(&mut ws, &f).await;
    }
    let res = recv_frames(&mut ws, &mut phone, 1).await;
    match res.as_slice() {
        [Inbound::Plaintext(ProtoMsg::PairResult(r))] => assert!(phone.on_pair_result(r)),
        other => panic!("{other:?}"),
    }
    // The host reports the pairing and closes "Add phone"; no code modal was shown.
    let mut shown = false;
    let ended = next_event(&mut events, |e| match e {
        HostEvent::PairingCodeShown { .. } => {
            shown = true;
            None
        }
        HostEvent::PhonePairingEnded { reason } => Some(*reason),
        _ => None,
    })
    .await;
    assert_eq!(ended, PhonePairingEnd::Paired);
    assert!(!shown, "a QR pairing must not show the code modal");
    host.send(HostCommand::Shutdown);
    let _ = tokio::time::timeout(WAIT, task).await;
}
