//! A mock relay (axum) implementing relay/README.md closely enough for the
//! transport tests: rooms, owner token, WebSocket and long-poll sessions,
//! routing and presence. Plus a tiny CONNECT proxy.

#![allow(dead_code)]

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post, put};
use axum::{Json, Router};
use serde_json::{json, Value};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, Notify};

pub const OWNER: &str = "owner-token-1";

type Tx = mpsc::UnboundedSender<Value>;

struct PollSession {
    events: Vec<(u64, Value)>,
    next: u64,
    notify: Arc<Notify>,
}

struct Conn {
    id: String,
    role: String,
    /// WebSocket connections receive events here; long-poll sessions have none.
    ws: Option<Tx>,
    session: Option<String>,
    kick: Arc<Notify>,
}

#[derive(Default)]
struct Room {
    hash: String,
    conns: Vec<Conn>,
    sessions: HashMap<String, PollSession>,
}

#[derive(Default)]
pub struct Inner {
    rooms: Mutex<HashMap<String, Room>>,
    next_conn: AtomicUsize,
    /// WebSocket upgrades answer 403 (a proxy that blocks them).
    pub ws_blocked: AtomicBool,
    /// Close each new desktop WebSocket right after accepting it.
    pub ws_drop_immediately: AtomicBool,
    /// Long-poll hold, in ms.
    pub hold_ms: AtomicUsize,
    pub ws_attempts: AtomicUsize,
    pub put_calls: AtomicUsize,
    pub deleted: Mutex<Vec<String>>,
}

#[derive(Clone)]
pub struct Mock(pub Arc<Inner>);

pub struct Running {
    pub mock: Mock,
    pub addr: SocketAddr,
}

impl Running {
    pub fn url(&self) -> String {
        format!("http://{}", self.addr)
    }
}

pub async fn start() -> Running {
    let inner = Arc::new(Inner::default());
    inner.hold_ms.store(400, Ordering::SeqCst);
    let app = Router::new()
        .route("/v1/health", get(|| async { "ok" }))
        .route("/v1/rooms/{id}", put(put_room).delete(delete_room))
        .route("/v1/rooms/{id}/ws", get(ws_route))
        .route("/v1/rooms/{id}/send", post(send_route))
        .route("/v1/rooms/{id}/poll", get(poll_route))
        .with_state(Mock(inner.clone()));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    Running { mock: Mock(inner), addr }
}

fn bearer(h: &HeaderMap) -> Option<String> {
    h.get("authorization")?.to_str().ok()?.strip_prefix("Bearer ").map(str::to_owned)
}

fn hash_of(secret: &str) -> String {
    use base64::Engine;
    use sha2::{Digest, Sha256};
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(Sha256::digest(secret.as_bytes()))
}

impl Mock {
    pub fn has_room(&self, id: &str) -> bool {
        self.0.rooms.lock().unwrap().contains_key(id)
    }

    pub fn room_hash(&self, id: &str) -> Option<String> {
        self.0.rooms.lock().unwrap().get(id).map(|r| r.hash.clone())
    }

    /// Create a room directly (with the hash of `secret`).
    pub fn create_room(&self, id: &str, secret: &str) {
        self.0.rooms.lock().unwrap().insert(
            id.to_owned(),
            Room { hash: hash_of(secret), ..Room::default() },
        );
    }

    /// Close every desktop connection of the room (a network drop).
    pub fn kick_desktop(&self, id: &str) {
        if let Some(r) = self.0.rooms.lock().unwrap().get(id) {
            for c in r.conns.iter().filter(|c| c.role == "desktop") {
                c.kick.notify_one();
            }
        }
    }

    pub fn desktop_present(&self, id: &str) -> bool {
        self.0
            .rooms
            .lock()
            .unwrap()
            .get(id)
            .is_some_and(|r| r.conns.iter().any(|c| c.role == "desktop"))
    }

    fn auth(&self, id: &str, h: &HeaderMap) -> Result<(), StatusCode> {
        let rooms = self.0.rooms.lock().unwrap();
        let room = rooms.get(id).ok_or(StatusCode::NOT_FOUND)?;
        match bearer(h) {
            Some(s) if hash_of(&s) == room.hash => Ok(()),
            _ => Err(StatusCode::UNAUTHORIZED),
        }
    }

    /// Deliver `msg` to connection `to` in the room.
    fn deliver(room: &mut Room, to: &str, msg: Value) {
        let Some(c) = room.conns.iter().find(|c| c.id == to) else { return };
        if let Some(tx) = &c.ws {
            let _ = tx.send(msg);
        } else if let Some(s) = c.session.as_ref().and_then(|s| room.sessions.get_mut(s)) {
            s.next += 1;
            let n = s.next;
            s.events.push((n, msg));
            s.notify.notify_one();
        }
    }

    /// Register a connection; returns its id.
    fn join(&self, room_id: &str, role: &str, ws: Option<Tx>, session: Option<String>, kick: Arc<Notify>) -> String {
        let id = format!("c{}", self.0.next_conn.fetch_add(1, Ordering::SeqCst) + 1);
        let mut rooms = self.0.rooms.lock().unwrap();
        let room = rooms.get_mut(room_id).unwrap();
        if let Some(s) = &session {
            room.sessions
                .entry(s.clone())
                .or_insert_with(|| PollSession { events: Vec::new(), next: 0, notify: Arc::new(Notify::new()) });
        }
        room.conns.push(Conn { id: id.clone(), role: role.to_owned(), ws, session, kick });
        if role == "desktop" {
            let phones: Vec<String> =
                room.conns.iter().filter(|c| c.role == "phone").map(|c| c.id.clone()).collect();
            for p in phones {
                Self::deliver(room, &id, json!({"type":"peer_joined","conn_id":p}));
            }
            let phone_ids: Vec<String> =
                room.conns.iter().filter(|c| c.role == "phone").map(|c| c.id.clone()).collect();
            for p in phone_ids {
                Self::deliver(room, &p, json!({"type":"desktop_present","present":true}));
            }
        } else {
            let desk = room.conns.iter().find(|c| c.role == "desktop").map(|c| c.id.clone());
            Self::deliver(room, &id, json!({"type":"desktop_present","present":desk.is_some()}));
            if let Some(d) = desk {
                Self::deliver(room, &d, json!({"type":"peer_joined","conn_id":id}));
            }
        }
        id
    }

    fn leave(&self, room_id: &str, conn_id: &str) {
        let mut rooms = self.0.rooms.lock().unwrap();
        let Some(room) = rooms.get_mut(room_id) else { return };
        let Some(pos) = room.conns.iter().position(|c| c.id == conn_id) else { return };
        let gone = room.conns.remove(pos);
        if let Some(s) = &gone.session {
            room.sessions.remove(s);
        }
        if gone.role == "phone" {
            if let Some(d) = room.conns.iter().find(|c| c.role == "desktop").map(|c| c.id.clone()) {
                Self::deliver(room, &d, json!({"type":"peer_left","conn_id":conn_id}));
            }
        } else {
            let phones: Vec<String> =
                room.conns.iter().filter(|c| c.role == "phone").map(|c| c.id.clone()).collect();
            for p in phones {
                Self::deliver(room, &p, json!({"type":"desktop_present","present":false}));
            }
        }
    }

    /// Route one client frame.
    fn route(&self, room_id: &str, from: &str, role: &str, data: &str, to: Option<&str>) {
        let mut rooms = self.0.rooms.lock().unwrap();
        let Some(room) = rooms.get_mut(room_id) else { return };
        let target = if role == "phone" {
            room.conns.iter().find(|c| c.role == "desktop").map(|c| c.id.clone())
        } else {
            to.map(str::to_owned)
        };
        if let Some(t) = target {
            Self::deliver(room, &t, json!({"type":"frame","from":from,"data":data}));
        }
    }
}

async fn put_room(
    State(m): State<Mock>,
    Path(id): Path<String>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Response {
    m.0.put_calls.fetch_add(1, Ordering::SeqCst);
    if headers.get("x-vq-owner").and_then(|v| v.to_str().ok()) != Some(OWNER) {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    let hash = body["secret_hash"].as_str().unwrap_or("").to_owned();
    let mut rooms = m.0.rooms.lock().unwrap();
    match rooms.get(&id) {
        Some(r) if r.hash == hash => StatusCode::OK.into_response(),
        Some(_) => StatusCode::CONFLICT.into_response(),
        None => {
            rooms.insert(id, Room { hash, ..Room::default() });
            StatusCode::CREATED.into_response()
        }
    }
}

async fn delete_room(State(m): State<Mock>, Path(id): Path<String>, headers: HeaderMap) -> Response {
    if headers.get("x-vq-owner").and_then(|v| v.to_str().ok()) != Some(OWNER) {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    if let Err(c) = m.auth(&id, &headers) {
        return c.into_response();
    }
    m.0.rooms.lock().unwrap().remove(&id);
    m.0.deleted.lock().unwrap().push(id);
    StatusCode::NO_CONTENT.into_response()
}

async fn ws_route(
    State(m): State<Mock>,
    Path(id): Path<String>,
    Query(q): Query<HashMap<String, String>>,
    headers: HeaderMap,
    upgrade: WebSocketUpgrade,
) -> Response {
    let role = q.get("role").cloned().unwrap_or_default();
    if role == "desktop" {
        m.0.ws_attempts.fetch_add(1, Ordering::SeqCst);
    }
    if m.0.ws_blocked.load(Ordering::SeqCst) {
        return StatusCode::FORBIDDEN.into_response();
    }
    if let Err(c) = m.auth(&id, &headers) {
        return c.into_response();
    }
    upgrade.on_upgrade(move |sock| ws_conn(m, id, role, sock))
}

async fn ws_conn(m: Mock, room: String, role: String, mut sock: WebSocket) {
    let (tx, mut rx) = mpsc::unbounded_channel::<Value>();
    let kick = Arc::new(Notify::new());
    let conn = m.join(&room, &role, Some(tx), None, kick.clone());
    let drop_now = role == "desktop" && m.0.ws_drop_immediately.load(Ordering::SeqCst);
    if drop_now {
        let _ = sock.send(Message::Close(None)).await;
    } else {
        loop {
            tokio::select! {
                out = rx.recv() => match out {
                    Some(v) => { if sock.send(Message::text(v.to_string())).await.is_err() { break } }
                    None => break,
                },
                inc = sock.recv() => match inc {
                    Some(Ok(Message::Text(t))) => handle_client_msg(&m, &room, &conn, &role, t.as_str()),
                    Some(Ok(Message::Binary(b))) => handle_client_msg(&m, &room, &conn, &role, &String::from_utf8_lossy(&b)),
                    Some(Ok(Message::Close(_))) | None | Some(Err(_)) => break,
                    Some(Ok(_)) => {}
                },
                _ = kick.notified() => { let _ = sock.send(Message::Close(None)).await; break }
            }
        }
    }
    m.leave(&room, &conn);
}

fn handle_client_msg(m: &Mock, room: &str, conn: &str, role: &str, text: &str) {
    let Ok(v) = serde_json::from_str::<Value>(text) else { return };
    if v["type"] == "frame" || v.get("data").is_some() {
        m.route(room, conn, role, v["data"].as_str().unwrap_or(""), v["to"].as_str());
    }
}

async fn send_route(
    State(m): State<Mock>,
    Path(id): Path<String>,
    Query(q): Query<HashMap<String, String>>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Response {
    if let Err(c) = m.auth(&id, &headers) {
        return c.into_response();
    }
    let (role, session) = (q["role"].clone(), q["session"].clone());
    let conn = poll_conn(&m, &id, &role, &session);
    let frames: Vec<Value> = match body.get("frames") {
        Some(Value::Array(a)) => a.clone(),
        _ => vec![body.clone()],
    };
    for f in &frames {
        m.route(&id, &conn, &role, f["data"].as_str().unwrap_or(""), f["to"].as_str());
    }
    Json(json!({"ok":true,"accepted":frames.len(),"conn_id":conn})).into_response()
}

/// The conn id of a long-poll session (created on first use).
fn poll_conn(m: &Mock, room: &str, role: &str, session: &str) -> String {
    let existing = {
        let rooms = m.0.rooms.lock().unwrap();
        rooms
            .get(room)
            .and_then(|r| r.conns.iter().find(|c| c.session.as_deref() == Some(session)).map(|c| c.id.clone()))
    };
    existing.unwrap_or_else(|| m.join(room, role, None, Some(session.to_owned()), Arc::new(Notify::new())))
}

async fn poll_route(
    State(m): State<Mock>,
    Path(id): Path<String>,
    Query(q): Query<HashMap<String, String>>,
    headers: HeaderMap,
) -> Response {
    if let Err(c) = m.auth(&id, &headers) {
        return c.into_response();
    }
    let (role, session) = (q["role"].clone(), q["session"].clone());
    let cursor: u64 = q.get("cursor").and_then(|c| c.parse().ok()).unwrap_or(0);
    let conn = poll_conn(&m, &id, &role, &session);
    let notify = {
        let mut rooms = m.0.rooms.lock().unwrap();
        let s = rooms.get_mut(&id).and_then(|r| r.sessions.get_mut(&session));
        let Some(s) = s else { return StatusCode::GONE.into_response() };
        s.events.retain(|(n, _)| *n > cursor);
        s.notify.clone()
    };
    let hold = Duration::from_millis(m.0.hold_ms.load(Ordering::SeqCst) as u64);
    let deadline = tokio::time::Instant::now() + hold;
    loop {
        {
            let rooms = m.0.rooms.lock().unwrap();
            let Some(s) = rooms.get(&id).and_then(|r| r.sessions.get(&session)) else {
                return StatusCode::GONE.into_response();
            };
            if !s.events.is_empty() {
                let events: Vec<Value> = s.events.iter().map(|(_, v)| v.clone()).collect();
                let last = s.events.last().map(|(n, _)| *n).unwrap_or(cursor);
                return Json(json!({"conn_id":conn,"cursor":last,"events":events})).into_response();
            }
        }
        if tokio::time::timeout_at(deadline, notify.notified()).await.is_err() {
            return Json(json!({"conn_id":conn,"cursor":cursor,"events":[]})).into_response();
        }
    }
}

// --------------------------------------------------------------- proxy

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum ProxyMode {
    Allow,
    Deny407,
    Deny403,
}

pub struct Proxy {
    pub addr: SocketAddr,
    /// Authorities seen in `CONNECT` requests.
    pub connects: Arc<Mutex<Vec<String>>>,
}

/// A CONNECT proxy: tunnels in `Allow` mode, answers 407/403 otherwise.
/// Any non-CONNECT request gets 502.
pub async fn start_proxy(mode: ProxyMode) -> Proxy {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let connects = Arc::new(Mutex::new(Vec::new()));
    let seen = connects.clone();
    tokio::spawn(async move {
        loop {
            let Ok((mut client, _)) = listener.accept().await else { return };
            let seen = seen.clone();
            tokio::spawn(async move {
                let mut head = Vec::new();
                let mut b = [0u8; 1];
                while !head.ends_with(b"\r\n\r\n") {
                    match client.read(&mut b).await {
                        Ok(1) => head.push(b[0]),
                        _ => return,
                    }
                }
                let text = String::from_utf8_lossy(&head).into_owned();
                let first = text.lines().next().unwrap_or("").to_owned();
                let mut parts = first.split_whitespace();
                if parts.next() != Some("CONNECT") {
                    let _ = client.write_all(b"HTTP/1.1 502 Bad Gateway\r\ncontent-length: 0\r\n\r\n").await;
                    return;
                }
                let authority = parts.next().unwrap_or("").to_owned();
                seen.lock().unwrap().push(authority.clone());
                match mode {
                    ProxyMode::Deny407 => {
                        let _ = client
                            .write_all(b"HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm=x\r\ncontent-length: 0\r\n\r\n")
                            .await;
                    }
                    ProxyMode::Deny403 => {
                        let _ = client.write_all(b"HTTP/1.1 403 Forbidden\r\ncontent-length: 0\r\n\r\n").await;
                    }
                    ProxyMode::Allow => {
                        let Ok(mut upstream) = TcpStream::connect(&authority).await else {
                            let _ = client.write_all(b"HTTP/1.1 502 Bad Gateway\r\ncontent-length: 0\r\n\r\n").await;
                            return;
                        };
                        let _ = client.write_all(b"HTTP/1.1 200 Connection established\r\n\r\n").await;
                        let _ = tokio::io::copy_bidirectional(&mut client, &mut upstream).await;
                    }
                }
            });
        }
    });
    Proxy { addr, connects }
}
