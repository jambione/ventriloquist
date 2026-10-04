//! In-memory room state: connections (WebSocket or long-poll session),
//! role semantics, presence events and frame routing. All methods run under
//! the room's mutex and never block or await.

use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use std::time::Instant;

use base64::Engine;
use rand::RngCore;
use serde_json::{json, Value};
use tokio::sync::mpsc::UnboundedSender;
use tokio::sync::Notify;

pub const MAX_FRAME_BYTES: usize = 64 * 1024;
/// Largest accepted client message (a 64 KiB frame in base64 plus JSON overhead).
pub const MAX_MESSAGE_BYTES: usize = 96 * 1024;
pub const MAX_PHONES: usize = 8;
pub const FRAMES_PER_SEC: f64 = 50.0;
pub const MAX_QUEUE_EVENTS: usize = 1000;

pub const CLOSE_REPLACED: u16 = 4001;
pub const CLOSE_IDLE: u16 = 4002;
pub const CLOSE_DELETED: u16 = 4003;
pub const CLOSE_RATE: u16 = 4029;
pub const CLOSE_OVERFLOW: u16 = 4008;
pub const CLOSE_TOO_BIG: u16 = 1009;
pub const CLOSE_BAD: u16 = 1008;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Role {
    Desktop,
    Phone,
}

impl Role {
    pub fn parse(s: &str) -> Option<Role> {
        match s {
            "desktop" => Some(Role::Desktop),
            "phone" => Some(Role::Phone),
            _ => None,
        }
    }
}

/// What the WebSocket writer task is told to do.
pub enum Out {
    Text(String),
    Close(u16, String),
}

pub struct Poll {
    pub queue: VecDeque<(u64, Value)>,
    pub seq: u64,
    pub notify: Arc<Notify>,
    pub closed: Option<(u16, String)>,
    /// Number of poll requests currently held open.
    pub active: u32,
}

pub enum Sink {
    Ws(UnboundedSender<Out>),
    Poll(Poll),
}

pub struct Conn {
    pub role: Role,
    pub sink: Sink,
    pub last_seen: Instant,
    tokens: f64,
    refill: Instant,
}

impl Conn {
    fn new(role: Role, sink: Sink) -> Conn {
        let now = Instant::now();
        Conn { role, sink, last_seen: now, tokens: FRAMES_PER_SEC, refill: now }
    }
    fn live(&self) -> bool {
        match &self.sink {
            Sink::Ws(_) => true,
            Sink::Poll(p) => p.closed.is_none(),
        }
    }
    /// Token bucket: 50 frames/s with a burst of 50.
    fn take(&mut self, n: usize) -> bool {
        let now = Instant::now();
        let dt = now.duration_since(self.refill).as_secs_f64();
        self.refill = now;
        self.tokens = (self.tokens + dt * FRAMES_PER_SEC).min(FRAMES_PER_SEC);
        if self.tokens >= n as f64 {
            self.tokens -= n as f64;
            true
        } else {
            false
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum FrameErr {
    TooBig,
    Bad,
    Rate,
}

impl FrameErr {
    pub fn close_code(&self) -> (u16, &'static str) {
        match self {
            FrameErr::TooBig => (CLOSE_TOO_BIG, "frame too big"),
            FrameErr::Bad => (CLOSE_BAD, "bad message"),
            FrameErr::Rate => (CLOSE_RATE, "rate limit"),
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum JoinErr {
    Full,
}

#[derive(Default)]
pub struct Room {
    conns: HashMap<String, Conn>,
    desktop: Option<String>,
    /// long-poll session id -> conn_id
    sessions: HashMap<String, String>,
    kill: Vec<String>,
}

pub struct ParsedFrame {
    pub to: Option<String>,
    pub data: String,
}

fn b64() -> base64::engine::GeneralPurpose {
    base64::engine::GeneralPurpose::new(
        &base64::alphabet::STANDARD,
        base64::engine::GeneralPurposeConfig::new()
            .with_decode_padding_mode(base64::engine::DecodePaddingMode::Indifferent),
    )
}

/// Validate one client frame object `{type:"frame", to?, data}`.
pub fn parse_frame(v: &Value) -> Result<ParsedFrame, FrameErr> {
    let o = v.as_object().ok_or(FrameErr::Bad)?;
    if o.get("type").and_then(Value::as_str) != Some("frame") {
        return Err(FrameErr::Bad);
    }
    let data = o.get("data").and_then(Value::as_str).ok_or(FrameErr::Bad)?;
    if data.len() > MAX_FRAME_BYTES.div_ceil(3) * 4 + 4 {
        return Err(FrameErr::TooBig);
    }
    let decoded = b64().decode(data).map_err(|_| FrameErr::Bad)?;
    if decoded.len() > MAX_FRAME_BYTES {
        return Err(FrameErr::TooBig);
    }
    let to = o.get("to").and_then(Value::as_str).map(str::to_owned);
    Ok(ParsedFrame { to, data: data.to_owned() })
}

fn new_conn_id() -> String {
    let mut b = [0u8; 8];
    rand::thread_rng().fill_bytes(&mut b);
    b.iter().map(|x| format!("{x:02x}")).collect()
}

impl Room {
    pub fn is_empty(&self) -> bool {
        self.conns.is_empty()
    }

    fn live_phones(&self) -> usize {
        self.conns.values().filter(|c| c.role == Role::Phone && c.live()).count()
    }

    fn deliver(&mut self, id: &str, msg: Value) {
        let Some(c) = self.conns.get_mut(id) else { return };
        match &mut c.sink {
            Sink::Ws(tx) => {
                let _ = tx.send(Out::Text(msg.to_string()));
            }
            Sink::Poll(p) => {
                if p.closed.is_some() {
                    return;
                }
                p.seq += 1;
                p.queue.push_back((p.seq, msg));
                p.notify.notify_waiters();
                if p.queue.len() > MAX_QUEUE_EVENTS {
                    self.kill.push(id.to_owned());
                }
            }
        }
    }

    fn process_kills(&mut self) {
        while let Some(id) = self.kill.pop() {
            self.terminate(&id, CLOSE_OVERFLOW, "overflow");
        }
    }

    fn live_ids(&self, role: Role) -> Vec<String> {
        self.conns.iter().filter(|(_, c)| c.role == role && c.live()).map(|(k, _)| k.clone()).collect()
    }

    fn present(&self) -> bool {
        self.desktop.is_some()
    }

    fn announce_present(&mut self) {
        let p = self.present();
        for id in self.live_ids(Role::Phone) {
            self.deliver(&id, json!({"type":"desktop_present","present":p}));
        }
    }

    /// Register a connection. Returns its conn_id.
    pub fn join(&mut self, role: Role, sink: Sink) -> Result<String, JoinErr> {
        if role == Role::Phone && self.live_phones() >= MAX_PHONES {
            return Err(JoinErr::Full);
        }
        if role == Role::Desktop {
            if let Some(old) = self.desktop.clone() {
                self.terminate(&old, CLOSE_REPLACED, "replaced");
            }
        }
        let id = new_conn_id();
        self.conns.insert(id.clone(), Conn::new(role, sink));
        match role {
            Role::Desktop => {
                self.desktop = Some(id.clone());
                for p in self.live_ids(Role::Phone) {
                    self.deliver(&id, json!({"type":"peer_joined","conn_id":p}));
                }
                self.announce_present();
            }
            Role::Phone => {
                let p = self.present();
                self.deliver(&id, json!({"type":"desktop_present","present":p}));
                if let Some(d) = self.desktop.clone() {
                    self.deliver(&d, json!({"type":"peer_joined","conn_id":id}));
                }
            }
        }
        self.process_kills();
        Ok(id)
    }

    /// End a connection with a close code, announcing the departure.
    /// WebSocket connections are removed; long-poll sessions stay until the
    /// client collects the close notice (or the sweeper drops them).
    pub fn terminate(&mut self, id: &str, code: u16, reason: &str) {
        let Some(c) = self.conns.get_mut(id) else { return };
        let role = c.role;
        match &mut c.sink {
            Sink::Ws(tx) => {
                let _ = tx.send(Out::Close(code, reason.to_owned()));
                self.conns.remove(id);
            }
            Sink::Poll(p) => {
                if p.closed.is_some() {
                    return;
                }
                p.closed = Some((code, reason.to_owned()));
                p.notify.notify_waiters();
            }
        }
        match role {
            Role::Desktop => {
                if self.desktop.as_deref() == Some(id) {
                    self.desktop = None;
                    self.announce_present();
                }
            }
            Role::Phone => {
                if let Some(d) = self.desktop.clone() {
                    self.deliver(&d, json!({"type":"peer_left","conn_id":id}));
                }
            }
        }
        self.process_kills();
    }

    /// Forget a connection entirely (used after a poll session's close notice
    /// was delivered, and by the sweeper). Announces if it was still live.
    pub fn remove(&mut self, id: &str) {
        self.terminate(id, CLOSE_IDLE, "idle");
        self.conns.remove(id);
        self.sessions.retain(|_, v| v != id);
    }

    pub fn touch(&mut self, id: &str) {
        if let Some(c) = self.conns.get_mut(id) {
            c.last_seen = Instant::now();
        }
    }

    pub fn close_all(&mut self, code: u16, reason: &str) {
        let ids: Vec<String> = self.conns.keys().cloned().collect();
        for id in ids {
            self.terminate(&id, code, reason);
        }
        self.conns.clear();
        self.sessions.clear();
        self.desktop = None;
    }

    /// Consume rate-limit tokens for `n` frames from `id`.
    pub fn rate(&mut self, id: &str, n: usize) -> Result<(), FrameErr> {
        match self.conns.get_mut(id) {
            Some(c) => {
                if c.take(n) {
                    Ok(())
                } else {
                    Err(FrameErr::Rate)
                }
            }
            None => Err(FrameErr::Bad),
        }
    }

    /// Route one validated frame from `from`.
    pub fn route(&mut self, from: &str, f: ParsedFrame) -> Result<(), FrameErr> {
        let Some(role) = self.conns.get(from).map(|c| c.role) else { return Err(FrameErr::Bad) };
        let target = match role {
            Role::Phone => self.desktop.clone(),
            Role::Desktop => {
                let to = f.to.ok_or(FrameErr::Bad)?;
                match self.conns.get(&to) {
                    Some(c) if c.role == Role::Phone && c.live() => Some(to),
                    _ => None,
                }
            }
        };
        if let Some(t) = target {
            self.deliver(&t, json!({"type":"frame","from":from,"data":f.data}));
        }
        self.process_kills();
        Ok(())
    }

    // ---- long-poll sessions ----

    pub fn session_conn(&self, session: &str) -> Option<String> {
        self.sessions.get(session).cloned()
    }

    pub fn role_of(&self, id: &str) -> Option<Role> {
        self.conns.get(id).map(|c| c.role)
    }

    pub fn join_poll(&mut self, role: Role, session: &str) -> Result<String, JoinErr> {
        let id = self.join(
            role,
            Sink::Poll(Poll {
                queue: VecDeque::new(),
                seq: 0,
                notify: Arc::new(Notify::new()),
                closed: None,
                active: 0,
            }),
        )?;
        self.sessions.insert(session.to_owned(), id.clone());
        Ok(id)
    }

    pub fn poll_mut(&mut self, id: &str) -> Option<&mut Poll> {
        match self.conns.get_mut(id).map(|c| &mut c.sink) {
            Some(Sink::Poll(p)) => Some(p),
            _ => None,
        }
    }

    /// Drop expired connections: idle long-poll sessions with no held poll,
    /// and WebSocket connections whose task is gone.
    pub fn sweep(&mut self, idle: std::time::Duration) {
        let now = Instant::now();
        let dead: Vec<String> = self
            .conns
            .iter()
            .filter(|(_, c)| match &c.sink {
                Sink::Ws(tx) => tx.is_closed(),
                Sink::Poll(p) => p.active == 0 && now.duration_since(c.last_seen) > idle,
            })
            .map(|(k, _)| k.clone())
            .collect();
        for id in dead {
            self.remove(&id);
        }
    }
}
