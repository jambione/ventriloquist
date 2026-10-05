//! vq-relay: the Ventriloquist relay server (SPEC_V3 section 4).
//!
//! Stores only room auth metadata (persisted to a JSON file); frames are
//! opaque end-to-end encrypted payloads and are never stored or logged.

#![allow(clippy::result_large_err)]

pub mod room;

use std::collections::{BTreeMap, HashMap, VecDeque};
use std::net::SocketAddr;
use std::path::{Path as FsPath, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use axum::body::{Body, Bytes};
use axum::extract::ws::{CloseFrame, Message, WebSocket, WebSocketUpgrade};
use axum::extract::{ConnectInfo, Path, Query, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post, put};
use axum::Router;
use base64::Engine;
use futures_util::{SinkExt, StreamExt};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use tokio::sync::mpsc;

use hyper::body::Incoming;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper_util::rt::{TokioIo, TokioTimer};
use tower::ServiceExt;

use room::*;

#[derive(Clone, Debug)]
pub struct Config {
    pub owner_token: String,
    pub data_dir: PathBuf,
    /// A connection or session idle for longer than this is closed (60 s).
    pub idle: Duration,
    /// How long a long-poll request is held (25 s).
    pub poll_hold: Duration,
    /// Server-initiated WebSocket ping interval (20 s).
    pub ping_interval: Duration,
    /// New rooms per IP per minute.
    pub create_limit: usize,
    /// Failed auth attempts per IP per minute.
    pub auth_fail_limit: usize,
}

impl Config {
    pub fn new(owner_token: String, data_dir: PathBuf) -> Config {
        Config {
            owner_token,
            data_dir,
            idle: Duration::from_secs(60),
            poll_hold: Duration::from_secs(25),
            ping_interval: Duration::from_secs(20),
            create_limit: 10,
            auth_fail_limit: 10,
        }
    }
}

const WINDOW: Duration = Duration::from_secs(60);
/// Time a client has to send its request headers.
const HEADER_READ_TIMEOUT: Duration = Duration::from_secs(10);
/// Time a client has to deliver a request body.
const BODY_READ_TIMEOUT: Duration = Duration::from_secs(10);
/// Largest `/send` request body.
const SEND_BODY_LIMIT: usize = 128 * 1024;
/// Largest `PUT /v1/rooms/{id}` request body.
const PUT_BODY_LIMIT: usize = 4 * 1024;
/// Base64url SHA-256 of the empty string: a room with an empty secret.
const EMPTY_SECRET_HASH: &str = "47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU";

#[derive(Serialize, Deserialize, Clone)]
struct Meta {
    secret_hash: String,
    /// Hash of the desktop secret (role=desktop). Absent on rooms created
    /// before it existed, which refuse role=desktop until the desktop re-PUTs.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    desktop_secret_hash: Option<String>,
    created_at: u64,
}

#[derive(Serialize, Deserialize, Default)]
struct StoreFile {
    rooms: BTreeMap<String, Meta>,
}

struct Store {
    path: PathBuf,
    rooms: BTreeMap<String, Meta>,
}

impl Store {
    fn load(dir: &FsPath) -> std::io::Result<Store> {
        std::fs::create_dir_all(dir)?;
        let path = dir.join("rooms.json");
        let rooms = match std::fs::read(&path) {
            Ok(b) => serde_json::from_slice::<StoreFile>(&b)
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?
                .rooms,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => BTreeMap::new(),
            Err(e) => return Err(e),
        };
        Ok(Store { path, rooms })
    }

    /// Atomic write: temp file in the same directory, fsync, rename.
    fn persist(&self) -> std::io::Result<()> {
        use std::io::Write;
        let tmp = self.path.with_extension("json.tmp");
        let body = serde_json::to_vec_pretty(&StoreFile { rooms: self.rooms.clone() })?;
        {
            let mut f = std::fs::File::create(&tmp)?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                f.set_permissions(std::fs::Permissions::from_mode(0o600))?;
            }
            f.write_all(&body)?;
            f.sync_all()?;
        }
        std::fs::rename(&tmp, &self.path)
    }
}

#[derive(Default)]
struct Limiter {
    fails: HashMap<String, VecDeque<Instant>>,
    creates: HashMap<String, VecDeque<Instant>>,
}

fn count(map: &mut HashMap<String, VecDeque<Instant>>, ip: &str) -> usize {
    let now = Instant::now();
    match map.get_mut(ip) {
        Some(q) => {
            while q.front().is_some_and(|t| now.duration_since(*t) > WINDOW) {
                q.pop_front();
            }
            if q.is_empty() {
                map.remove(ip);
                0
            } else {
                q.len()
            }
        }
        None => 0,
    }
}

fn record(map: &mut HashMap<String, VecDeque<Instant>>, ip: &str) {
    map.entry(ip.to_owned()).or_default().push_back(Instant::now());
}

type RoomCell = Mutex<Room>;

pub struct App {
    cfg: Config,
    owner_hash: [u8; 32],
    store: Mutex<Store>,
    rooms: Mutex<HashMap<String, Arc<RoomCell>>>,
    limiter: Mutex<Limiter>,
}

fn sha256(b: &[u8]) -> [u8; 32] {
    Sha256::digest(b).into()
}

fn b64url() -> base64::engine::GeneralPurpose {
    base64::engine::general_purpose::URL_SAFE_NO_PAD
}

/// Constant-time comparison of two secrets (compares their SHA-256 digests).
pub fn secrets_equal(a: &str, b: &str) -> bool {
    sha256(a.as_bytes()).ct_eq(&sha256(b.as_bytes())).into()
}

fn err(status: StatusCode, code: &str) -> Response {
    (status, axum::Json(json!({ "error": code }))).into_response()
}

fn valid_id(s: &str, min: usize, max: usize) -> bool {
    (min..=max).contains(&s.len()) && s.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'-' || c == b'_')
}

/// The client address used for rate limits. `CF-Connecting-IP` is trusted
/// only when the TCP peer is loopback (the local cloudflared); otherwise the
/// peer address is used.
fn client_ip(headers: &HeaderMap, peer: SocketAddr) -> String {
    if peer.ip().is_loopback() {
        if let Some(ip) = headers
            .get("cf-connecting-ip")
            .and_then(|v| v.to_str().ok())
            .map(str::trim)
            .filter(|s| !s.is_empty() && s.len() <= 64)
        {
            return ip.to_owned();
        }
    }
    peer.ip().to_string()
}

fn is_hash(h: &str) -> bool {
    h.len() == 43 && b64url().decode(h).map(|b| b.len()) == Ok(32) && h != EMPTY_SECRET_HASH
}

/// Read a request body, enforcing the size limit while streaming and a
/// deadline for the whole body.
async fn read_body(headers: &HeaderMap, body: Body, limit: usize) -> Result<Bytes, Response> {
    let declared = headers.get(header::CONTENT_LENGTH).and_then(|v| v.to_str().ok()).and_then(|v| v.parse::<u64>().ok());
    if declared.is_some_and(|n| n > limit as u64) {
        return Err(err(StatusCode::PAYLOAD_TOO_LARGE, "body_too_large"));
    }
    match tokio::time::timeout(BODY_READ_TIMEOUT, axum::body::to_bytes(body, limit)).await {
        Err(_) => Err(err(StatusCode::REQUEST_TIMEOUT, "body_timeout")),
        Ok(Err(_)) => Err(err(StatusCode::PAYLOAD_TOO_LARGE, "body_too_large")),
        Ok(Ok(b)) => Ok(b),
    }
}

fn bearer(headers: &HeaderMap) -> Option<String> {
    let v = headers.get(header::AUTHORIZATION)?.to_str().ok()?;
    let (scheme, rest) = v.split_once(' ')?;
    scheme.eq_ignore_ascii_case("bearer").then(|| rest.trim().to_owned())
}

/// The `vq.auth.<secret>` subprotocol offered by the client, if any.
fn subprotocol(headers: &HeaderMap) -> Option<String> {
    headers
        .get_all("sec-websocket-protocol")
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(','))
        .map(str::trim)
        .find(|p| p.starts_with("vq.auth."))
        .map(str::to_owned)
}

impl App {
    fn rate_blocked(&self, ip: &str) -> bool {
        count(&mut self.limiter.lock().unwrap().fails, ip) >= self.cfg.auth_fail_limit
    }

    fn fail(&self, ip: &str) {
        record(&mut self.limiter.lock().unwrap().fails, ip);
    }

    fn owner_ok(&self, headers: &HeaderMap) -> bool {
        let given = headers.get("x-vq-owner").and_then(|v| v.to_str().ok()).unwrap_or("");
        let eq: bool = sha256(given.as_bytes()).ct_eq(&self.owner_hash).into();
        eq && !self.cfg.owner_token.is_empty()
    }

    /// Check the secret for `role` (the desktop secret for role=desktop, the
    /// room secret for role=phone). Err is the response to return.
    fn authorize(&self, id: &str, role: Role, secret: Option<&str>, ip: &str) -> Result<Arc<RoomCell>, Response> {
        if self.rate_blocked(ip) {
            return Err(err(StatusCode::TOO_MANY_REQUESTS, "rate_limited"));
        }
        let meta = self.store.lock().unwrap().rooms.get(id).cloned();
        let Some(meta) = meta else { return Err(err(StatusCode::NOT_FOUND, "no_such_room")) };
        let stored_hash = match role {
            Role::Phone => Some(meta.secret_hash.as_str()),
            Role::Desktop => meta.desktop_secret_hash.as_deref(),
        };
        let stored = stored_hash.map(|h| b64url().decode(h).unwrap_or_default()).unwrap_or_default();
        let given = sha256(secret.unwrap_or("").as_bytes());
        let ok = stored.len() == 32
            && bool::from(given.as_slice().ct_eq(stored.as_slice()))
            && secret.is_some_and(|s| !s.is_empty());
        if !ok {
            self.fail(ip);
            return Err(err(StatusCode::UNAUTHORIZED, "unauthorized"));
        }
        Ok(self.rooms.lock().unwrap().entry(id.to_owned()).or_default().clone())
    }
}

type St = State<Arc<App>>;

async fn health() -> &'static str {
    "ok"
}

#[derive(Deserialize)]
struct PutBody {
    secret_hash: String,
    #[serde(default)]
    desktop_secret_hash: Option<String>,
}

async fn put_room(
    State(app): St,
    Path(id): Path<String>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    body: Body,
) -> Response {
    let ip = client_ip(&headers, peer);
    if app.rate_blocked(&ip) || count(&mut app.limiter.lock().unwrap().creates, &ip) >= app.cfg.create_limit {
        return err(StatusCode::TOO_MANY_REQUESTS, "rate_limited");
    }
    if !app.owner_ok(&headers) {
        app.fail(&ip);
        return err(StatusCode::UNAUTHORIZED, "unauthorized");
    }
    if !valid_id(&id, 16, 64) {
        return err(StatusCode::BAD_REQUEST, "bad_room_id");
    }
    let body = match read_body(&headers, body, PUT_BODY_LIMIT).await {
        Ok(b) => b,
        Err(r) => return r,
    };
    let Ok(PutBody { secret_hash, desktop_secret_hash }) = serde_json::from_slice(&body) else {
        return err(StatusCode::BAD_REQUEST, "bad_body");
    };
    if !is_hash(&secret_hash) {
        return err(StatusCode::BAD_REQUEST, "bad_secret_hash");
    }
    if desktop_secret_hash.as_deref().is_some_and(|h| !is_hash(h)) {
        return err(StatusCode::BAD_REQUEST, "bad_desktop_secret_hash");
    }
    let mut store = app.store.lock().unwrap();
    if let Some(m) = store.rooms.get_mut(&id) {
        let same: bool = m.secret_hash.as_bytes().ct_eq(secret_hash.as_bytes()).into();
        if !same {
            return err(StatusCode::CONFLICT, "hash_mismatch");
        }
        let Some(given) = desktop_secret_hash else { return StatusCode::OK.into_response() };
        return match m.desktop_secret_hash.clone() {
            Some(cur) => {
                let same: bool = cur.as_bytes().ct_eq(given.as_bytes()).into();
                if same {
                    StatusCode::OK.into_response()
                } else {
                    err(StatusCode::CONFLICT, "desktop_hash_mismatch")
                }
            }
            None => {
                // Migration: a room created before the desktop secret existed.
                m.desktop_secret_hash = Some(given);
                if let Err(e) = store.persist() {
                    if let Some(m) = store.rooms.get_mut(&id) {
                        m.desktop_secret_hash = None;
                    }
                    eprintln!("vq-relay: persist failed for room {}: {e}", &id[..6]);
                    return err(StatusCode::INTERNAL_SERVER_ERROR, "persist_failed");
                }
                StatusCode::OK.into_response()
            }
        };
    }
    let created_at = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    store.rooms.insert(id.clone(), Meta { secret_hash, desktop_secret_hash, created_at });
    if let Err(e) = store.persist() {
        store.rooms.remove(&id);
        eprintln!("vq-relay: persist failed for room {}: {e}", &id[..6]);
        return err(StatusCode::INTERNAL_SERVER_ERROR, "persist_failed");
    }
    drop(store);
    record(&mut app.limiter.lock().unwrap().creates, &ip);
    StatusCode::CREATED.into_response()
}

async fn delete_room(
    State(app): St,
    Path(id): Path<String>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
) -> Response {
    let ip = client_ip(&headers, peer);
    if app.rate_blocked(&ip) {
        return err(StatusCode::TOO_MANY_REQUESTS, "rate_limited");
    }
    if !app.owner_ok(&headers) {
        app.fail(&ip);
        return err(StatusCode::UNAUTHORIZED, "unauthorized");
    }
    let cell = match app.authorize(&id, Role::Phone, bearer(&headers).as_deref(), &ip) {
        Ok(c) => c,
        Err(r) => return r,
    };
    {
        let mut store = app.store.lock().unwrap();
        let Some(old) = store.rooms.remove(&id) else { return err(StatusCode::NOT_FOUND, "no_such_room") };
        if let Err(e) = store.persist() {
            store.rooms.insert(id.clone(), old);
            eprintln!("vq-relay: persist failed for room {}: {e}", &id[..6]);
            return err(StatusCode::INTERNAL_SERVER_ERROR, "persist_failed");
        }
    }
    app.rooms.lock().unwrap().remove(&id);
    cell.lock().unwrap().close_all(CLOSE_DELETED, "deleted");
    StatusCode::NO_CONTENT.into_response()
}

#[derive(Deserialize)]
struct RoleQ {
    role: Option<String>,
    session: Option<String>,
    cursor: Option<String>,
}

fn parse_role(q: &RoleQ) -> Result<Role, Response> {
    q.role.as_deref().and_then(Role::parse).ok_or_else(|| err(StatusCode::BAD_REQUEST, "bad_role"))
}

async fn ws_route(
    State(app): St,
    Path(id): Path<String>,
    Query(q): Query<RoleQ>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    ws: WebSocketUpgrade,
) -> Response {
    let ip = client_ip(&headers, peer);
    let role = match parse_role(&q) {
        Ok(r) => r,
        Err(r) => return r,
    };
    let sub = subprotocol(&headers);
    let secret = bearer(&headers).or_else(|| sub.as_ref().map(|s| s["vq.auth.".len()..].to_owned()));
    let cell = match app.authorize(&id, role, secret.as_deref(), &ip) {
        Ok(c) => c,
        Err(r) => return r,
    };
    let (tx, rx) = mpsc::channel(WS_QUEUE_MESSAGES + 1);
    let conn_id = match cell.lock().unwrap().join(role, Sink::Ws(tx.clone())) {
        Ok(c) => c,
        Err(JoinErr::Full) => return err(StatusCode::TOO_MANY_REQUESTS, "room_full"),
    };
    let ws = match &sub {
        Some(p) if bearer(&headers).is_none() => ws.protocols([p.clone()]),
        _ => ws,
    };
    let app2 = app.clone();
    let ws = ws.max_message_size(MAX_MESSAGE_BYTES).max_frame_size(MAX_MESSAGE_BYTES);
    ws.on_upgrade(move |socket| ws_task(app2, cell, conn_id, rx, socket))
}

fn handle_ws_message(cell: &RoomCell, id: &str, raw: &[u8]) -> Result<(), FrameErr> {
    if raw.len() > MAX_MESSAGE_BYTES {
        return Err(FrameErr::TooBig);
    }
    let v: Value = serde_json::from_slice(raw).map_err(|_| FrameErr::Bad)?;
    let f = parse_frame(&v)?;
    let mut room = cell.lock().unwrap();
    room.rate(id, 1)?;
    room.route(id, f)
}

async fn ws_task(
    app: Arc<App>,
    cell: Arc<RoomCell>,
    id: String,
    mut rx: mpsc::Receiver<Out>,
    socket: WebSocket,
) {
    let (mut sink, mut stream) = socket.split();
    let ping = app.cfg.ping_interval;
    let idle = app.cfg.idle;
    // A peer that stops reading is cut off after `idle` instead of holding the
    // writer (and its queue) forever.
    let write_timeout = idle;
    let mut writer = tokio::spawn(async move {
        let mut iv = tokio::time::interval(ping);
        iv.tick().await;
        loop {
            tokio::select! {
                m = rx.recv() => match m {
                    Some(Out::Text(t)) => {
                        if !matches!(tokio::time::timeout(write_timeout, sink.send(Message::Text(t.into()))).await, Ok(Ok(()))) {
                            break;
                        }
                    }
                    Some(Out::Close(code, reason)) => {
                        let close = Message::Close(Some(CloseFrame { code, reason: reason.into() }));
                        let _ = tokio::time::timeout(write_timeout, sink.send(close)).await;
                        break;
                    }
                    None => break,
                },
                _ = iv.tick() => {
                    if !matches!(tokio::time::timeout(write_timeout, sink.send(Message::Ping(Bytes::new()))).await, Ok(Ok(()))) {
                        break;
                    }
                }
            }
        }
    });
    let reader = async {
        loop {
            let next = tokio::time::timeout(idle, stream.next()).await;
            let msg = match next {
                Err(_) => {
                    cell.lock().unwrap().terminate(&id, CLOSE_IDLE, "idle");
                    return;
                }
                Ok(None) => return,
                Ok(Some(Err(e))) => {
                    // Over the size limit (tungstenite capacity error): 1009.
                    if e.to_string().to_ascii_lowercase().contains("too long") {
                        cell.lock().unwrap().terminate(&id, CLOSE_TOO_BIG, "frame too big");
                    }
                    return;
                }
                Ok(Some(Ok(m))) => m,
            };
            cell.lock().unwrap().touch(&id);
            let res = match msg {
                Message::Text(t) if t.as_str() == "ping" => {
                    cell.lock().unwrap().push_text(&id, "pong");
                    Ok(())
                }
                Message::Text(t) => handle_ws_message(&cell, &id, t.as_bytes()),
                Message::Binary(b) => handle_ws_message(&cell, &id, &b),
                Message::Close(_) => return,
                Message::Ping(_) | Message::Pong(_) => Ok(()),
            };
            if let Err(e) = res {
                let (code, reason) = e.close_code();
                cell.lock().unwrap().terminate(&id, code, reason);
                return;
            }
        }
    };
    let writer_done = tokio::select! {
        _ = reader => false,
        _ = &mut writer => true,
    };
    cell.lock().unwrap().terminate(&id, 1000, "");
    if !writer_done {
        let _ = tokio::time::timeout(Duration::from_secs(1), &mut writer).await;
    }
    writer.abort();
}

/// Resolve (or create) the long-poll session for a request.
fn session_for(
    cell: &RoomCell,
    role: Role,
    q: &RoleQ,
    creating_ok: bool,
) -> Result<String, Response> {
    let Some(session) = q.session.as_deref().filter(|s| valid_id(s, 8, 64)) else {
        return Err(err(StatusCode::BAD_REQUEST, "bad_session"));
    };
    let mut room = cell.lock().unwrap();
    if let Some(id) = room.session_conn(session) {
        if room.role_of(&id) != Some(role) {
            return Err(err(StatusCode::BAD_REQUEST, "role_mismatch"));
        }
        return Ok(id);
    }
    if !creating_ok {
        return Err(err(StatusCode::GONE, "session_expired"));
    }
    room.join_poll(role, session).map_err(|_| err(StatusCode::TOO_MANY_REQUESTS, "room_full"))
}

async fn send_route(
    State(app): St,
    Path(id): Path<String>,
    Query(q): Query<RoleQ>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    body: Body,
) -> Response {
    let ip = client_ip(&headers, peer);
    let role = match parse_role(&q) {
        Ok(r) => r,
        Err(r) => return r,
    };
    let cell = match app.authorize(&id, role, bearer(&headers).as_deref(), &ip) {
        Ok(c) => c,
        Err(r) => return r,
    };
    let body = match read_body(&headers, body, SEND_BODY_LIMIT).await {
        Ok(b) => b,
        Err(r) => return r,
    };
    let Ok(v) = serde_json::from_slice::<Value>(&body) else {
        return err(StatusCode::BAD_REQUEST, "bad_body");
    };
    let items: Vec<Value> = match v.get("frames") {
        Some(Value::Array(a)) => a.clone(),
        _ => vec![v],
    };
    let mut parsed = Vec::new();
    for item in &items {
        // Allow {"to","data"} without "type" in a frames array.
        let item = match item.as_object() {
            Some(o) if !o.contains_key("type") => {
                let mut o = o.clone();
                o.insert("type".into(), json!("frame"));
                Value::Object(o)
            }
            _ => item.clone(),
        };
        match parse_frame(&item) {
            Ok(f) => parsed.push(f),
            Err(FrameErr::TooBig) => return err(StatusCode::PAYLOAD_TOO_LARGE, "frame_too_big"),
            Err(_) => return err(StatusCode::BAD_REQUEST, "bad_frame"),
        }
    }
    if role == Role::Desktop && parsed.iter().any(|f| f.to.is_none()) {
        return err(StatusCode::BAD_REQUEST, "missing_to");
    }
    let conn_id = match session_for(&cell, role, &q, true) {
        Ok(c) => c,
        Err(r) => return r,
    };
    let mut room = cell.lock().unwrap();
    if room.poll_mut(&conn_id).is_some_and(|p| p.closed.is_some()) {
        return err(StatusCode::GONE, "session_closed");
    }
    room.touch(&conn_id);
    if room.rate(&conn_id, parsed.len()).is_err() {
        return err(StatusCode::TOO_MANY_REQUESTS, "rate_limited");
    }
    let n = parsed.len();
    for f in parsed {
        let _ = room.route(&conn_id, f);
    }
    axum::Json(json!({"ok": true, "accepted": n, "conn_id": conn_id})).into_response()
}

/// Decrements the held-poll counter even if the client disconnects.
struct ActiveGuard {
    cell: Arc<RoomCell>,
    id: String,
}

impl Drop for ActiveGuard {
    fn drop(&mut self) {
        if let Ok(mut room) = self.cell.lock() {
            if let Some(p) = room.poll_mut(&self.id) {
                p.active = p.active.saturating_sub(1);
            }
            room.touch(&self.id);
        }
    }
}

async fn poll_route(
    State(app): St,
    Path(id): Path<String>,
    Query(q): Query<RoleQ>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
) -> Response {
    let ip = client_ip(&headers, peer);
    let role = match parse_role(&q) {
        Ok(r) => r,
        Err(r) => return r,
    };
    let cursor: u64 = match q.cursor.as_deref() {
        None | Some("") => 0,
        Some(c) => match c.parse() {
            Ok(c) => c,
            Err(_) => return err(StatusCode::BAD_REQUEST, "bad_cursor"),
        },
    };
    let cell = match app.authorize(&id, role, bearer(&headers).as_deref(), &ip) {
        Ok(c) => c,
        Err(r) => return r,
    };
    // A session that no longer exists can only be re-created from cursor 0.
    let conn_id = match session_for(&cell, role, &q, cursor == 0) {
        Ok(c) => c,
        Err(r) => return r,
    };
    let notify = {
        let mut room = cell.lock().unwrap();
        room.touch(&conn_id);
        let Some(p) = room.poll_mut(&conn_id) else { return err(StatusCode::GONE, "session_expired") };
        if cursor > p.seq {
            return err(StatusCode::BAD_REQUEST, "bad_cursor");
        }
        while p.queue.front().is_some_and(|(s, _)| *s <= cursor) {
            p.queue.pop_front();
        }
        // A newer poll supersedes any older one still held.
        p.notify.notify_waiters();
        p.notify.clone()
    };
    let notified = notify.notified();
    tokio::pin!(notified);
    let ready = {
        let mut room = cell.lock().unwrap();
        let Some(p) = room.poll_mut(&conn_id) else { return err(StatusCode::GONE, "session_expired") };
        notified.as_mut().enable();
        p.active += 1;
        !p.queue.is_empty() || p.closed.is_some()
    };
    let guard = ActiveGuard { cell: cell.clone(), id: conn_id.clone() };
    if !ready {
        let _ = tokio::time::timeout(app.cfg.poll_hold, notified).await;
    }
    drop(guard);
    let mut room = cell.lock().unwrap();
    let Some(p) = room.poll_mut(&conn_id) else { return err(StatusCode::GONE, "session_expired") };
    let events: Vec<Value> = p.queue.iter().filter(|(s, _)| *s > cursor).map(|(_, v)| v.clone()).collect();
    let new_cursor = p.queue.back().map(|(s, _)| *s).unwrap_or(cursor).max(cursor);
    let closed = p.closed.clone();
    let mut resp = json!({"conn_id": conn_id, "cursor": new_cursor, "events": events});
    if let Some((code, reason)) = closed {
        resp["closed"] = json!({"code": code, "reason": reason});
        room.remove(&conn_id);
    }
    axum::Json(resp).into_response()
}

pub fn router(app: Arc<App>) -> Router {
    Router::new()
        .route("/v1/health", get(health))
        .route("/v1/rooms/{id}", put(put_room).delete(delete_room))
        .route("/v1/rooms/{id}/ws", get(ws_route))
        .route("/v1/rooms/{id}/send", post(send_route))
        .route("/v1/rooms/{id}/poll", get(poll_route))
        .with_state(app)
}

/// Build the shared application state (loads persisted rooms) and start the sweeper.
pub fn build_app(cfg: Config) -> std::io::Result<Arc<App>> {
    let store = Store::load(&cfg.data_dir)?;
    let app = Arc::new(App {
        owner_hash: sha256(cfg.owner_token.as_bytes()),
        cfg,
        store: Mutex::new(store),
        rooms: Mutex::new(HashMap::new()),
        limiter: Mutex::new(Limiter::default()),
    });
    let weak = Arc::downgrade(&app);
    let every = (app.cfg.idle / 4).clamp(Duration::from_millis(100), Duration::from_secs(5));
    tokio::spawn(async move {
        let mut iv = tokio::time::interval(every);
        loop {
            iv.tick().await;
            let Some(app) = weak.upgrade() else { return };
            let cells: Vec<Arc<RoomCell>> = app.rooms.lock().unwrap().values().cloned().collect();
            for c in cells {
                c.lock().unwrap().sweep(app.cfg.idle);
            }
            {
                let mut l = app.limiter.lock().unwrap();
                let ips: Vec<String> = l.fails.keys().cloned().collect();
                for ip in ips {
                    count(&mut l.fails, &ip);
                }
                let ips: Vec<String> = l.creates.keys().cloned().collect();
                for ip in ips {
                    count(&mut l.creates, &ip);
                }
            }
        }
    });
    Ok(app)
}

/// Serve on an existing listener until the future is dropped.
pub async fn serve(listener: tokio::net::TcpListener, cfg: Config) -> std::io::Result<()> {
    let app = build_app(cfg)?;
    let router = router(app);
    // One task per connection; dropping this future aborts them all.
    let mut conns = tokio::task::JoinSet::new();
    loop {
        let (stream, peer) = match listener.accept().await {
            Ok(x) => x,
            Err(_) => {
                tokio::time::sleep(Duration::from_millis(50)).await;
                continue;
            }
        };
        while conns.try_join_next().is_some() {}
        let router = router.clone().layer(axum::Extension(ConnectInfo(peer)));
        conns.spawn(async move {
            let svc = service_fn(move |req: hyper::Request<Incoming>| {
                let router = router.clone();
                async move { router.oneshot(req.map(Body::new)).await }
            });
            let mut http = http1::Builder::new();
            http.timer(TokioTimer::new()).header_read_timeout(HEADER_READ_TIMEOUT);
            let _ = http.serve_connection(TokioIo::new(stream), svc).with_upgrades().await;
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cf_connecting_ip_is_trusted_only_from_a_loopback_peer() {
        let mut h = HeaderMap::new();
        h.insert("cf-connecting-ip", "203.0.113.9".parse().unwrap());
        let lo: SocketAddr = "127.0.0.1:5000".parse().unwrap();
        let lo6: SocketAddr = "[::1]:5000".parse().unwrap();
        let far: SocketAddr = "198.51.100.7:5000".parse().unwrap();
        assert_eq!(client_ip(&h, lo), "203.0.113.9");
        assert_eq!(client_ip(&h, lo6), "203.0.113.9");
        assert_eq!(client_ip(&h, far), "198.51.100.7");
        assert_eq!(client_ip(&HeaderMap::new(), lo), "127.0.0.1");
    }
}
