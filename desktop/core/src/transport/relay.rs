//! Cloud relay transport (SPEC_V3 §4.3, §6; relay protocol in `relay/README.md`).
//!
//! The desktop makes **outbound** connections only:
//!
//! 1. **WebSocket first** (`GET /v1/rooms/{room}/ws?role=desktop`, header
//!    `Authorization: Bearer <desktop_secret>`; phones use the room secret,
//!    the desktop secret is never in the QR code). TLS comes from the **OS
//!    certificate store** (`native-tls`: Windows schannel, macOS
//!    Security.framework), so a TLS-inspecting corporate proxy whose root is
//!    installed in the OS works. The TCP connection goes through the proxy
//!    chosen by [`super::proxy`] (environment, then the OS settings including
//!    PAC/WPAD) with an HTTP `CONNECT` tunnel.
//! 2. **HTTPS long-poll fallback** (`POST …/send`, `GET …/poll`, `reqwest`
//!    with the same TLS and proxy choice) when the WebSocket cannot be
//!    established or keeps dropping within 10 s. The WebSocket is retried
//!    every 5 minutes.
//!
//! Reconnects back off 1, 2, 4, 8, then 30 s ([`backoff_factor`]).
//!
//! Mapping to the [`Transport`] trait (SPEC_V3 §4.3): every `peer_joined` is
//! a [`TransportEvent::Connected`] with peer id `relay:<conn_id>` and
//! `mtu = 8192`; `peer_left` and any link failure are
//! [`TransportEvent::Disconnected`]. The relay cannot drop a phone, so a
//! host `Disconnect` reports the peer gone and ignores its frames until it
//! leaves; the `reconnect_after` hold-off is not applicable (a reconnecting
//! phone is a new `conn_id`).
//!
//! The room is created with `PUT /v1/rooms/{room}` and the **owner token**
//! when one is configured and the room is not known to exist. The link state
//! is reported as [`TransportEvent::Relay`] ([`RelayStatus`]), with a
//! categorised reason when unreachable.
//!
//! Configuration at run time goes through [`RelayHandle`] (owner token, URL,
//! "Reset relay room", "Test connection").

use std::collections::{HashMap, HashSet};
use std::io;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine;
use futures_util::{SinkExt, StreamExt};
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::http::HeaderValue;
use tokio_tungstenite::tungstenite::protocol::Message as WsMessage;
use tokio_tungstenite::tungstenite::Error as WsError;
use tokio_tungstenite::WebSocketStream;
use url::Url;
use zeroize::Zeroizing;

use super::proxy::{self, OsProxyResolver, ProxyEntry};
use super::{Transport, TransportCommand, TransportEvent};
use crate::events::{PeerId, RelayLink, RelayReason, RelayStatus};
use crate::relay_room::{RelayRoomStore, RoomSettings};

/// Frame size limit (`mtu`) on the relay (SPEC_V3 §3): keeps long-poll
/// requests small.
pub const RELAY_MTU: usize = 8192;

/// Longest frame the relay accepts (64 KiB decoded); larger ones are dropped.
const MAX_FRAME_BYTES: usize = 64 * 1024;

/// Backoff factor (in units of 1 s) after `failures` consecutive failed or
/// short-lived connections: 0 → at once, then 1, 2, 4, 8 and 30.
pub fn backoff_factor(failures: u32) -> u32 {
    match failures {
        0 => 0,
        1 => 1,
        2 => 2,
        3 => 4,
        4 => 8,
        _ => 30,
    }
}

/// Timings of the transport. Tests shrink them.
#[derive(Debug, Clone)]
pub struct Timing {
    /// One backoff unit (1 s).
    pub backoff_unit: Duration,
    /// Timeout of one connection attempt (TCP, tunnel, TLS, upgrade).
    pub connect_timeout: Duration,
    /// Retry the WebSocket this long after falling back (5 min).
    pub ws_retry_every: Duration,
    /// A WebSocket that ends sooner than this counts as a short drop (10 s).
    pub short_drop: Duration,
    /// Short drops in a row that trigger the fallback.
    pub short_drops_for_fallback: u32,
    /// WebSocket ping interval (20 s).
    pub ping_every: Duration,
    /// Nothing received for this long ends the link (60 s).
    pub idle_timeout: Duration,
    /// Timeout of a long-poll request (the relay holds it 25 s).
    pub poll_timeout: Duration,
    /// Timeout of one write or send request.
    pub write_timeout: Duration,
}

impl Default for Timing {
    fn default() -> Self {
        Self {
            backoff_unit: Duration::from_secs(1),
            connect_timeout: Duration::from_secs(10),
            ws_retry_every: Duration::from_secs(300),
            short_drop: Duration::from_secs(10),
            short_drops_for_fallback: 2,
            ping_every: Duration::from_secs(20),
            idle_timeout: Duration::from_secs(60),
            poll_timeout: Duration::from_secs(35),
            write_timeout: Duration::from_secs(10),
        }
    }
}

/// When to use the WebSocket and when the long-poll fallback (pure).
#[derive(Debug, Clone)]
pub struct ModePolicy {
    timing: Timing,
    fallback_since: Option<Instant>,
    short_drops: u32,
    /// `VQ_RELAY_FORCE_LONGPOLL`: never try the WebSocket.
    force_longpoll: bool,
}

impl ModePolicy {
    /// A policy that starts with the WebSocket.
    pub fn new(timing: Timing) -> Self {
        Self { timing, fallback_since: None, short_drops: 0, force_longpoll: false }
    }

    /// A policy for a transport with `VQ_RELAY_FORCE_LONGPOLL` set to a
    /// non-empty value other than `0` in `env`: the WebSocket is never tried.
    pub fn from_env(timing: Timing, env: &dyn Fn(&str) -> Option<String>) -> Self {
        let force = env("VQ_RELAY_FORCE_LONGPOLL").is_some_and(|v| !v.is_empty() && v != "0");
        Self { force_longpoll: force, ..Self::new(timing) }
    }

    /// Whether the next attempt should use the WebSocket: always, until a
    /// fallback began; then again `ws_retry_every` after it began.
    pub fn should_try_websocket(&self, now: Instant) -> bool {
        !self.force_longpoll
            && self.fallback_since
            .is_none_or(|t| now.saturating_duration_since(t) >= self.timing.ws_retry_every)
    }

    /// Whether we are currently on the fallback.
    pub fn in_fallback(&self) -> bool {
        self.force_longpoll || self.fallback_since.is_some()
    }

    /// The WebSocket could not be established: use long-poll now.
    pub fn websocket_failed(&mut self, now: Instant) {
        self.fallback_since = Some(now);
    }

    /// A WebSocket connection that lasted `lasted` ended. Returns whether the
    /// fallback starts now (too many short drops in a row).
    pub fn websocket_ended(&mut self, now: Instant, lasted: Duration) -> bool {
        if lasted >= self.timing.short_drop {
            self.short_drops = 0;
            self.fallback_since = None;
            return false;
        }
        self.short_drops += 1;
        if self.short_drops >= self.timing.short_drops_for_fallback {
            self.fallback_since = Some(now);
            self.short_drops = 0;
            return true;
        }
        false
    }

    /// When a fallback session should hand over to a WebSocket retry.
    pub fn retry_deadline(&self, now: Instant) -> Instant {
        if self.force_longpoll {
            return now + Duration::from_secs(365 * 86_400);
        }
        self.fallback_since.map_or(now, |t| t + self.timing.ws_retry_every)
    }
}

/// Looks up an environment variable (injectable for tests).
pub type EnvLookup = Arc<dyn Fn(&str) -> Option<String> + Send + Sync>;

/// Everything the transport needs besides the room.
pub struct RelayOptions {
    /// Owner token (creates the room; stored by the app in the OS secret store).
    pub owner_token: Option<String>,
    /// OS proxy settings.
    pub os_proxy: Box<dyn OsProxyResolver>,
    /// Environment lookup (`HTTPS_PROXY`, `NO_PROXY`, …).
    pub env: EnvLookup,
    /// Timings.
    pub timing: Timing,
}

impl Default for RelayOptions {
    fn default() -> Self {
        Self {
            owner_token: None,
            os_proxy: proxy::system_resolver(),
            env: Arc::new(|k| std::env::var(k).ok()),
            timing: Timing::default(),
        }
    }
}

impl std::fmt::Debug for RelayOptions {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RelayOptions")
            .field("owner_token", &self.owner_token.as_ref().map(|_| "<set>"))
            .field("timing", &self.timing)
            .finish_non_exhaustive()
    }
}

// ----------------------------------------------------------- failures

/// Why a connection attempt failed (categorised for the UI).
#[derive(Debug, Clone)]
pub struct Failure {
    /// Category.
    pub reason: RelayReason,
    /// Technical description; never contains a secret.
    pub detail: String,
    /// The relay said the room does not exist (404).
    room_missing: bool,
}

impl Failure {
    fn new(reason: RelayReason, detail: impl Into<String>) -> Self {
        Self { reason, detail: detail.into(), room_missing: false }
    }

    /// As an `unreachable` status.
    pub fn status(&self) -> RelayStatus {
        RelayStatus::unreachable(self.reason, self.detail.clone())
    }
}

/// Categorise an error message from the TLS stack, the HTTP client or a
/// proxy (pure; the strings cover schannel, Security.framework, OpenSSL,
/// hyper and the OS resolver).
pub fn classify_error_text(text: &str) -> RelayReason {
    let t = text.to_ascii_lowercase();
    let has = |needles: &[&str]| needles.iter().any(|n| t.contains(n));
    if has(&[
        "certificate",
        "untrusted",
        "self signed",
        "self-signed",
        "unable to get local issuer",
        "unknown ca",
        "0x800b0109",
        "0x800b0101",
        "-9807",
        "-9808",
        "-9812",
        "-9813",
        "-9814",
        "-9841",
        "-9843",
        "-9845",
    ]) {
        RelayReason::TlsUntrusted
    } else if has(&[
        "dns error",
        "failed to lookup",
        "nodename nor servname",
        "name or service not known",
        "no such host",
        "name resolution",
        "no address associated",
        "host not found",
    ]) {
        RelayReason::Dns
    } else if has(&["407", "proxy authentication", "proxy authorization"]) {
        RelayReason::ProxyAuthRequired
    } else if has(&["proxy", "tunnel"]) {
        RelayReason::ProxyBlocked
    } else {
        RelayReason::Other
    }
}

/// Category of a proxy's answer to `CONNECT` (pure): 407 asks for
/// credentials, anything else that is not 2xx refuses the tunnel.
pub fn classify_connect_status(code: u16) -> Option<RelayReason> {
    classify_connect_response(code, &[])
}

/// Text of the status for a proxy that only offers integrated Windows sign-in.
pub const PROXY_AUTH_UNSUPPORTED_DETAIL: &str =
    "proxy requires Windows sign-in (NTLM/Kerberos) — not supported yet";

/// As [`classify_connect_status`], knowing the `Proxy-Authenticate`
/// challenges of a 407: when it offers only NTLM/Negotiate/Kerberos (no
/// `Basic`), the reason is [`RelayReason::ProxyAuthUnsupported`].
pub fn classify_connect_response(code: u16, proxy_authenticate: &[String]) -> Option<RelayReason> {
    if code == 407 && !proxy_authenticate.is_empty() {
        let scheme = |c: &String| c.split_whitespace().next().unwrap_or("").to_ascii_lowercase();
        let integrated = |s: &str| matches!(s, "ntlm" | "negotiate" | "kerberos");
        let schemes: Vec<String> = proxy_authenticate.iter().map(scheme).collect();
        if schemes.iter().all(|s| integrated(s)) {
            return Some(RelayReason::ProxyAuthUnsupported);
        }
    }
    classify_connect_status_plain(code)
}

fn classify_connect_status_plain(code: u16) -> Option<RelayReason> {
    match code {
        200..=299 => None,
        407 => Some(RelayReason::ProxyAuthRequired),
        _ => Some(RelayReason::ProxyBlocked),
    }
}

/// Category of an HTTP status from the relay itself (pure).
pub fn classify_relay_status(code: u16, has_owner_token: bool) -> Failure {
    match code {
        401 => Failure::new(RelayReason::RoomConflict, "the relay rejected the room secret (401)"),
        407 => Failure::new(RelayReason::ProxyAuthRequired, "the proxy wants credentials (407)"),
        // A proxy that blocks WebSocket upgrades answers 403; the relay itself uses 401.
        403 => Failure::new(RelayReason::Other, "the request was refused (403)"),
        404 => Failure {
            reason: if has_owner_token { RelayReason::Other } else { RelayReason::OwnerTokenRejected },
            detail: if has_owner_token {
                "the room does not exist on the relay (404)".into()
            } else {
                "the room does not exist on the relay and no owner token is set (404)".into()
            },
            room_missing: true,
        },
        409 => Failure::new(RelayReason::RoomConflict, "the room exists with a different secret (409)"),
        429 => Failure::new(RelayReason::Other, "the relay is rate limiting or the room is full (429)"),
        c => Failure::new(RelayReason::Other, format!("the relay answered HTTP {c}")),
    }
}

fn error_chain(e: &dyn std::error::Error) -> String {
    let mut s = e.to_string();
    let mut cur = e.source();
    while let Some(c) = cur {
        s.push_str(": ");
        s.push_str(&c.to_string());
        cur = c.source();
    }
    s
}

// ----------------------------------------------------------- wire types

#[derive(Debug, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum ServerMsg {
    Frame { from: String, data: String },
    PeerJoined { conn_id: String },
    PeerLeft { conn_id: String },
    #[serde(other)]
    Other,
}

#[derive(Debug, Serialize)]
struct ClientFrame<'a> {
    #[serde(rename = "type")]
    kind: &'static str,
    to: &'a str,
    data: String,
}

#[derive(Debug, Deserialize)]
struct PollResponse {
    #[serde(default)]
    cursor: u64,
    #[serde(default)]
    events: Vec<serde_json::Value>,
    #[serde(default)]
    closed: Option<Closed>,
}

#[derive(Debug, Deserialize)]
struct Closed {
    code: u16,
    #[serde(default)]
    reason: String,
}

fn peer_id(conn_id: &str) -> PeerId {
    format!("relay:{conn_id}")
}

fn conn_of(peer: &str) -> Option<&str> {
    peer.strip_prefix("relay:")
}

// -------------------------------------------------------------- control

enum Control {
    /// Owner token or URL changed: reconnect with a fresh state.
    Reconfigure,
    /// The room was reset: reconnect, and delete the old room if possible.
    ResetRoom(RoomSettings),
}

struct Shared {
    store: Arc<RelayRoomStore>,
    owner: Mutex<Option<Zeroizing<String>>>,
    net: Net,
    tx: mpsc::UnboundedSender<Control>,
}

/// Run-time configuration and diagnostics of a [`RelayTransport`].
#[derive(Clone)]
pub struct RelayHandle {
    shared: Arc<Shared>,
}

impl std::fmt::Debug for RelayHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("RelayHandle")
    }
}

/// Result of "Test connection".
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct TestReport {
    /// `websocket`: everything works; `fallback`: only HTTPS works (the
    /// WebSocket is blocked); `unreachable`: see `reason`.
    pub status: RelayStatus,
    /// What was checked, e.g. `["health", "room", "websocket"]`.
    pub checked: Vec<String>,
}

impl RelayHandle {
    /// The room store (URL, room id, secret).
    pub fn store(&self) -> &Arc<RelayRoomStore> {
        &self.shared.store
    }

    /// Whether an owner token is configured.
    pub fn has_owner_token(&self) -> bool {
        self.owner().is_some()
    }

    fn owner(&self) -> Option<Zeroizing<String>> {
        self.shared.owner.lock().unwrap_or_else(|p| p.into_inner()).clone()
    }

    /// Set (or clear, with `None`/empty) the owner token and reconnect.
    pub fn set_owner_token(&self, token: Option<String>) {
        let token = token.map(|t| t.trim().to_owned()).filter(|t| !t.is_empty()).map(Zeroizing::new);
        *self.shared.owner.lock().unwrap_or_else(|p| p.into_inner()) = token;
        let _ = self.shared.tx.send(Control::Reconfigure);
    }

    /// Change the relay URL and reconnect.
    pub fn set_url(&self, url: &str) -> io::Result<()> {
        self.shared.store.set_url(url)?;
        let _ = self.shared.tx.send(Control::Reconfigure);
        Ok(())
    }

    /// "Reset relay room": a new room id and secret (every phone is
    /// un-paired). The old room is deleted on the relay on a best-effort
    /// basis.
    pub fn reset_room(&self) -> io::Result<()> {
        let old = self.shared.store.reset_room()?;
        let _ = self.shared.tx.send(Control::ResetRoom(old));
        Ok(())
    }

    /// "Test connection": relay reachable (`/v1/health`), room creation when
    /// an owner token is set, and whether a WebSocket can be opened. Opening
    /// the WebSocket joins the room briefly as a phone.
    pub async fn test_connection(&self) -> TestReport {
        let net = &self.shared.net;
        let room = self.shared.store.get();
        let owner = self.owner();
        let mut checked = Vec::new();
        let entries = net.proxies_for(&room.url).await;
        checked.push("health".to_owned());
        if let Err(f) = net.health(&room.url, &entries).await {
            return TestReport { status: f.status(), checked };
        }
        if let Some(token) = owner.as_deref() {
            checked.push("room".to_owned());
            if let Err(f) = net.ensure_room(&room, token, &entries).await {
                return TestReport { status: f.status(), checked };
            }
        }
        checked.push("websocket".to_owned());
        match net.ws_connect(&room, "phone", &entries, owner.is_some()).await {
            Ok(mut ws) => {
                let _ = ws.close(None).await;
                TestReport { status: RelayStatus::of(RelayLink::Websocket), checked }
            }
            Err(f) if f.room_missing || f.reason == RelayReason::RoomConflict => {
                TestReport { status: f.status(), checked }
            }
            Err(f) => {
                let mut status = RelayStatus::of(RelayLink::Fallback);
                status.detail = Some(format!("WebSocket blocked ({}); long-poll will be used", f.detail));
                TestReport { status, checked }
            }
        }
    }
}

// ------------------------------------------------------------- network

type BoxIo = Box<dyn AsyncIo>;

trait AsyncIo: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> AsyncIo for T {}

struct Net {
    os: Arc<dyn OsProxyResolver>,
    env: EnvLookup,
    timing: Timing,
}

fn endpoint(base: &str, path: &str) -> String {
    format!("{}/v1{path}", base.trim_end_matches('/'))
}

fn ws_scheme_url(base: &str, room_id: &str, role: &str) -> String {
    let b = endpoint(base, &format!("/rooms/{room_id}/ws?role={role}"));
    if let Some(rest) = b.strip_prefix("https://") {
        format!("wss://{rest}")
    } else if let Some(rest) = b.strip_prefix("http://") {
        format!("ws://{rest}")
    } else {
        b
    }
}

impl Net {
    /// The proxies to try for the relay URL (blocking OS calls run off the
    /// async threads).
    async fn proxies_for(&self, base: &str) -> Vec<ProxyEntry> {
        let Ok(url) = Url::parse(base) else { return vec![ProxyEntry::Direct] };
        let os = self.os.clone();
        let env = self.env.clone();
        tokio::task::spawn_blocking(move || proxy::resolve_proxies(&*env, &*os, &url))
            .await
            .unwrap_or_else(|_| vec![ProxyEntry::Direct])
    }

    fn http_client(&self, entry: &ProxyEntry, timeout: Duration) -> Result<reqwest::Client, Failure> {
        let mut b = reqwest::Client::builder()
            .use_native_tls()
            .no_proxy()
            .connect_timeout(self.timing.connect_timeout)
            .timeout(timeout)
            .user_agent(concat!("Ventriloquist/", env!("CARGO_PKG_VERSION")));
        if let Some(u) = entry.to_url() {
            let p = reqwest::Proxy::all(u)
                .map_err(|e| Failure::new(RelayReason::ProxyBlocked, format!("bad proxy: {e}")))?;
            b = b.proxy(p);
        }
        b.build().map_err(|e| Failure::new(RelayReason::Other, format!("HTTP client: {}", error_chain(&e))))
    }

    /// Send one request, trying each proxy entry in order; the first entry
    /// that gets any HTTP answer wins. Returns the response and the client
    /// that worked.
    async fn http(
        &self,
        entries: &[ProxyEntry],
        timeout: Duration,
        build: impl Fn(&reqwest::Client) -> reqwest::RequestBuilder,
    ) -> Result<(reqwest::Response, reqwest::Client), Failure> {
        let mut last = Failure::new(RelayReason::Other, "no route to the relay");
        for entry in entries {
            let client = match self.http_client(entry, timeout) {
                Ok(c) => c,
                Err(f) => {
                    last = f;
                    continue;
                }
            };
            match build(&client).send().await {
                Ok(resp) => return Ok((resp, client)),
                Err(e) => {
                    let text = error_chain(&e);
                    let mut reason = classify_error_text(&text);
                    if matches!(entry, ProxyEntry::Direct) && reason == RelayReason::ProxyBlocked {
                        reason = RelayReason::Other;
                    }
                    last = Failure::new(reason, text);
                }
            }
        }
        Err(last)
    }

    async fn health(&self, base: &str, entries: &[ProxyEntry]) -> Result<reqwest::Client, Failure> {
        let url = endpoint(base, "/health");
        let (resp, client) = self.http(entries, self.timing.connect_timeout, |c| c.get(&url)).await?;
        if resp.status().is_success() {
            Ok(client)
        } else {
            Err(classify_relay_status(resp.status().as_u16(), true))
        }
    }

    /// `PUT /v1/rooms/{id}` with the owner token.
    async fn ensure_room(&self, room: &RoomSettings, owner: &str, entries: &[ProxyEntry]) -> Result<(), Failure> {
        let url = endpoint(&room.url, &format!("/rooms/{}", room.room_id));
        let body = serde_json::json!({
            "secret_hash": room.secret_hash(),
            "desktop_secret_hash": room.desktop_secret_hash(),
        });
        let (resp, _) = self
            .http(entries, self.timing.connect_timeout, |c| {
                c.put(&url).header("X-VQ-Owner", owner).json(&body)
            })
            .await?;
        match resp.status().as_u16() {
            200 | 201 => Ok(()),
            401 => Err(Failure::new(
                RelayReason::OwnerTokenRejected,
                "the relay rejected the owner token (401)",
            )),
            409 => Err(Failure::new(
                RelayReason::RoomConflict,
                "the room id exists on the relay with a different secret (409)",
            )),
            c => Err(classify_relay_status(c, true)),
        }
    }

    /// Best effort: delete a room that was replaced by "Reset relay room".
    async fn delete_room(&self, old: &RoomSettings, owner: Option<&str>) {
        let Some(owner) = owner else { return };
        let entries = self.proxies_for(&old.url).await;
        let url = endpoint(&old.url, &format!("/rooms/{}", old.room_id));
        let secret = old.room_secret.as_str();
        let r = self
            .http(&entries, self.timing.connect_timeout, |c| {
                c.delete(&url).header("X-VQ-Owner", owner).bearer_auth(secret)
            })
            .await;
        match r {
            Ok((resp, _)) => log::info!("relay: old room deleted (HTTP {})", resp.status().as_u16()),
            Err(f) => log::info!("relay: could not delete the old room: {}", f.detail),
        }
    }

    /// A TCP connection to `host:port`, directly or through `entry`, with
    /// the tunnel established when a proxy is used.
    async fn tunnel(&self, entry: &ProxyEntry, host: &str, port: u16) -> Result<TcpStream, Failure> {
        let (connect_host, connect_port) = match entry {
            ProxyEntry::Direct => (host, port),
            ProxyEntry::Http { host, port, .. } => (host.as_str(), *port),
        };
        let via_proxy = !matches!(entry, ProxyEntry::Direct);
        let addrs: Vec<_> = match tokio::time::timeout(
            self.timing.connect_timeout,
            tokio::net::lookup_host((connect_host, connect_port)),
        )
        .await
        {
            Ok(Ok(a)) => a.collect(),
            Ok(Err(e)) => {
                let what = if via_proxy { "the proxy" } else { "the relay" };
                return Err(Failure::new(
                    if via_proxy { RelayReason::ProxyBlocked } else { RelayReason::Dns },
                    format!("cannot resolve {what} host {connect_host}: {e}"),
                ));
            }
            Err(_) => {
                return Err(Failure::new(
                    if via_proxy { RelayReason::ProxyBlocked } else { RelayReason::Dns },
                    format!("resolving {connect_host} timed out"),
                ))
            }
        };
        let mut last = format!("no address for {connect_host}");
        let mut stream = None;
        for addr in addrs {
            match tokio::time::timeout(self.timing.connect_timeout, TcpStream::connect(addr)).await {
                Ok(Ok(s)) => {
                    stream = Some(s);
                    break;
                }
                Ok(Err(e)) => last = format!("connect {addr}: {e}"),
                Err(_) => last = format!("connect {addr}: timed out"),
            }
        }
        let Some(mut stream) = stream else {
            return Err(Failure::new(
                if via_proxy { RelayReason::ProxyBlocked } else { RelayReason::Other },
                last,
            ));
        };
        let _ = stream.set_nodelay(true);
        if let ProxyEntry::Http { auth, .. } = entry {
            tokio::time::timeout(self.timing.connect_timeout, http_connect(&mut stream, host, port, auth.as_ref()))
                .await
                .map_err(|_| Failure::new(RelayReason::ProxyBlocked, "the proxy did not answer CONNECT"))??;
        }
        Ok(stream)
    }

    /// Open the room's WebSocket as `role`.
    async fn ws_connect(
        &self,
        room: &RoomSettings,
        role: &str,
        entries: &[ProxyEntry],
        has_owner: bool,
    ) -> Result<WebSocketStream<BoxIo>, Failure> {
        let ws_url = ws_scheme_url(&room.url, &room.room_id, role);
        let url = Url::parse(&ws_url).map_err(|e| Failure::new(RelayReason::Other, format!("bad relay URL: {e}")))?;
        let tls = url.scheme() == "wss";
        let host = url.host_str().unwrap_or_default().to_owned();
        let port = url.port_or_known_default().unwrap_or(if tls { 443 } else { 80 });
        let target = WsTarget { url: ws_url, host, port, tls, has_owner, role: role.to_owned() };
        let mut last = Failure::new(RelayReason::Other, "no route to the relay");
        for entry in entries {
            match self.ws_connect_via(entry, &target, room).await {
                Ok(ws) => return Ok(ws),
                Err(f) => last = f,
            }
        }
        Err(last)
    }

    async fn ws_connect_via(
        &self,
        entry: &ProxyEntry,
        target: &WsTarget,
        room: &RoomSettings,
    ) -> Result<WebSocketStream<BoxIo>, Failure> {
        let WsTarget { url: ws_url, host, port, tls, has_owner, .. } = target;
        let (host, port, tls, has_owner) = (host.as_str(), *port, *tls, *has_owner);
        let tcp = self.tunnel(entry, host, port).await?;
        let io: BoxIo = if tls {
            let connector = native_tls::TlsConnector::builder()
                .min_protocol_version(Some(native_tls::Protocol::Tlsv12))
                .build()
                .map_err(|e| Failure::new(RelayReason::Other, format!("TLS setup: {e}")))?;
            let connector = tokio_native_tls::TlsConnector::from(connector);
            let stream = tokio::time::timeout(self.timing.connect_timeout, connector.connect(host, tcp))
                .await
                .map_err(|_| Failure::new(RelayReason::Other, "TLS handshake timed out"))?
                .map_err(|e| {
                    let text = error_chain(&e);
                    Failure::new(classify_error_text(&text), format!("TLS handshake: {text}"))
                })?;
            Box::new(stream)
        } else {
            Box::new(tcp)
        };
        let mut req = ws_url
            .as_str()
            .into_client_request()
            .map_err(|e| Failure::new(RelayReason::Other, format!("bad WebSocket request: {e}")))?;
        let secret = if target.role == "desktop" { &room.desktop_secret } else { &room.room_secret };
        let auth = HeaderValue::from_str(&format!("Bearer {}", secret.as_str()))
            .map_err(|_| Failure::new(RelayReason::Other, "the room secret is not a valid header value"))?;
        req.headers_mut().insert("Authorization", auth);
        let handshake = tokio::time::timeout(self.timing.connect_timeout, tokio_tungstenite::client_async(req, io))
            .await
            .map_err(|_| Failure::new(RelayReason::Other, "WebSocket handshake timed out"))?;
        match handshake {
            Ok((ws, _)) => Ok(ws),
            Err(WsError::Http(resp)) => {
                Err(classify_relay_status(resp.status().as_u16(), has_owner))
            }
            Err(e) => Err(Failure::new(
                classify_error_text(&error_chain(&e)),
                format!("WebSocket handshake: {e}"),
            )),
        }
    }
}

/// Where to open a WebSocket.
struct WsTarget {
    url: String,
    host: String,
    port: u16,
    tls: bool,
    has_owner: bool,
    role: String,
}

/// Send `CONNECT host:port` and read the answer headers.
async fn http_connect(
    stream: &mut TcpStream,
    host: &str,
    port: u16,
    auth: Option<&(String, String)>,
) -> Result<(), Failure> {
    let authority = if host.contains(':') { format!("[{host}]:{port}") } else { format!("{host}:{port}") };
    let mut req = format!("CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n");
    if let Some((u, p)) = auth {
        req.push_str(&format!(
            "Proxy-Authorization: Basic {}\r\n",
            STANDARD.encode(format!("{u}:{p}"))
        ));
    }
    req.push_str("Proxy-Connection: Keep-Alive\r\n\r\n");
    let io_err = |e: io::Error| Failure::new(RelayReason::ProxyBlocked, format!("proxy CONNECT: {e}"));
    stream.write_all(req.as_bytes()).await.map_err(io_err)?;
    // Read byte by byte: nothing after the headers may be consumed (the
    // TLS handshake follows on the same connection).
    let mut head = Vec::with_capacity(256);
    let mut byte = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        if head.len() > 16 * 1024 {
            return Err(Failure::new(RelayReason::ProxyBlocked, "the proxy's answer is too long"));
        }
        let n = stream.read(&mut byte).await.map_err(io_err)?;
        if n == 0 {
            return Err(Failure::new(RelayReason::ProxyBlocked, "the proxy closed the connection"));
        }
        head.push(byte[0]);
    }
    let text = String::from_utf8_lossy(&head);
    let status = text
        .lines()
        .next()
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|c| c.parse::<u16>().ok())
        .ok_or_else(|| Failure::new(RelayReason::ProxyBlocked, "the proxy's answer is not HTTP"))?;
    let challenges: Vec<String> = text
        .lines()
        .skip(1)
        .filter_map(|l| {
            let (k, v) = l.split_once(':')?;
            k.trim().eq_ignore_ascii_case("proxy-authenticate").then(|| v.trim().to_owned())
        })
        .collect();
    match classify_connect_response(status, &challenges) {
        None => Ok(()),
        Some(RelayReason::ProxyAuthUnsupported) => {
            Err(Failure::new(RelayReason::ProxyAuthUnsupported, PROXY_AUTH_UNSUPPORTED_DETAIL))
        }
        Some(reason) => Err(Failure::new(reason, format!("the proxy answered CONNECT with HTTP {status}"))),
    }
}

// ------------------------------------------------------------ transport

/// The relay transport. Create it with [`RelayTransport::new`], keep the
/// [`RelayHandle`] for configuration, and give the transport to
/// [`crate::spawn_host`].
pub struct RelayTransport {
    shared: Arc<Shared>,
    control: mpsc::UnboundedReceiver<Control>,
}

impl RelayTransport {
    /// A transport for the room in `store`.
    pub fn new(store: Arc<RelayRoomStore>, opts: RelayOptions) -> (Self, RelayHandle) {
        let (tx, control) = mpsc::unbounded_channel();
        let owner = opts
            .owner_token
            .map(|t| t.trim().to_owned())
            .filter(|t| !t.is_empty())
            .map(Zeroizing::new);
        let shared = Arc::new(Shared {
            store,
            owner: Mutex::new(owner),
            net: Net { os: Arc::from(opts.os_proxy), env: opts.env, timing: opts.timing },
            tx,
        });
        (Self { shared: shared.clone(), control }, RelayHandle { shared })
    }
}

impl Transport for RelayTransport {
    fn start(
        self: Box<Self>,
        commands: mpsc::UnboundedReceiver<TransportCommand>,
        events: mpsc::Sender<TransportEvent>,
    ) -> JoinHandle<()> {
        let RelayTransport { shared, control } = *self;
        tokio::spawn(run(shared, control, commands, events))
    }
}

/// Emits link status changes only.
struct StatusSink {
    events: mpsc::Sender<TransportEvent>,
    last: Option<RelayStatus>,
}

impl StatusSink {
    async fn set(&mut self, status: RelayStatus) -> bool {
        if self.last.as_ref() == Some(&status) {
            return true;
        }
        self.last = Some(status.clone());
        self.events.send(TransportEvent::Relay(status)).await.is_ok()
    }
}

/// Peers of one link session, and the translation to transport events.
struct Pump {
    events: mpsc::Sender<TransportEvent>,
    peers: HashMap<String, PeerId>,
    /// conn_ids the host disconnected: ignored until they leave.
    banned: HashSet<String>,
}

/// The host stopped listening.
struct HostGone;

impl Pump {
    fn new(events: mpsc::Sender<TransportEvent>) -> Self {
        Self { events, peers: HashMap::new(), banned: HashSet::new() }
    }

    async fn emit(&self, e: TransportEvent) -> Result<(), HostGone> {
        self.events.send(e).await.map_err(|_| HostGone)
    }

    /// One relay → desktop message (already parsed).
    async fn on_server(&mut self, msg: ServerMsg) -> Result<(), HostGone> {
        match msg {
            ServerMsg::PeerJoined { conn_id } => {
                if self.banned.contains(&conn_id) || self.peers.contains_key(&conn_id) {
                    return Ok(());
                }
                let peer = peer_id(&conn_id);
                self.peers.insert(conn_id, peer.clone());
                self.emit(TransportEvent::Connected { peer, mtu: RELAY_MTU }).await
            }
            ServerMsg::PeerLeft { conn_id } => {
                self.banned.remove(&conn_id);
                match self.peers.remove(&conn_id) {
                    Some(peer) => {
                        self.emit(TransportEvent::Disconnected { peer, reason: "peer left the room".into() }).await
                    }
                    None => Ok(()),
                }
            }
            ServerMsg::Frame { from, data } => {
                let Some(peer) = self.peers.get(&from).cloned() else {
                    log::debug!("relay: frame from an unknown connection ignored");
                    return Ok(());
                };
                let Ok(frame) = STANDARD.decode(data.trim_end_matches('=')).or_else(|_| STANDARD.decode(&data))
                else {
                    log::debug!("relay: frame with bad base64 ignored");
                    return Ok(());
                };
                if frame.len() > MAX_FRAME_BYTES {
                    return Ok(());
                }
                self.emit(TransportEvent::Frame { peer, frame }).await
            }
            ServerMsg::Other => Ok(()),
        }
    }

    /// A JSON text from the relay.
    async fn on_text(&mut self, text: &[u8]) -> Result<(), HostGone> {
        match serde_json::from_slice::<ServerMsg>(text) {
            Ok(m) => self.on_server(m).await,
            Err(e) => {
                log::debug!("relay: unparsable message ignored: {e}");
                Ok(())
            }
        }
    }

    /// Frames for one peer as the JSON messages to send.
    fn outbound(&self, peer: &str, frames: &[Vec<u8>]) -> Vec<String> {
        let Some(conn) = conn_of(peer) else { return Vec::new() };
        if !self.peers.contains_key(conn) {
            return Vec::new();
        }
        frames
            .iter()
            .filter_map(|f| {
                serde_json::to_string(&ClientFrame { kind: "frame", to: conn, data: STANDARD.encode(f) }).ok()
            })
            .collect()
    }

    /// The host disconnects `peer`: report it gone and ignore its frames.
    async fn host_disconnect(&mut self, peer: &str) -> Result<(), HostGone> {
        let Some(conn) = conn_of(peer).map(str::to_owned) else { return Ok(()) };
        if let Some(p) = self.peers.remove(&conn) {
            self.banned.insert(conn);
            self.emit(TransportEvent::Disconnected { peer: p, reason: "closed by host".into() }).await?;
        }
        Ok(())
    }

    async fn close_all(&mut self, reason: &str) {
        self.banned.clear();
        for (_, peer) in self.peers.drain() {
            let _ = self
                .events
                .send(TransportEvent::Disconnected { peer, reason: reason.to_owned() })
                .await;
        }
    }
}

enum SessionEnd {
    /// The host asked to stop (or went away).
    Shutdown,
    /// A [`Control`] arrived.
    Control(Control),
    /// The long-poll session found the WebSocket usable again (the probe
    /// succeeded); the caller continues on it.
    Upgrade(WebSocketStream<BoxIo>),
    /// The link ended.
    Ended { lasted: Duration, reason: String, failure: Option<Failure> },
}

/// Run one WebSocket link: report it, serve it, and update the mode policy.
/// `Err` when the host went away (the transport stops).
async fn run_ws(
    ws: WebSocketStream<BoxIo>,
    timing: &Timing,
    mode: &mut ModePolicy,
    status: &mut StatusSink,
    cmds: &mut mpsc::UnboundedReceiver<TransportCommand>,
    control: &mut mpsc::UnboundedReceiver<Control>,
    events: &mpsc::Sender<TransportEvent>,
) -> Result<SessionEnd, ()> {
    if !status.set(RelayStatus::of(RelayLink::Websocket)).await {
        return Err(());
    }
    let started = Instant::now();
    let end = ws_session(ws, timing, cmds, control, events, started).await;
    if let SessionEnd::Ended { lasted, .. } = &end {
        if mode.websocket_ended(Instant::now(), *lasted) {
            log::info!("relay: the WebSocket keeps dropping; using long-poll");
        }
    }
    Ok(end)
}

/// How informative a failure category is: the long-poll and WebSocket
/// failures are merged by keeping the more specific one.
fn specificity(r: RelayReason) -> u8 {
    match r {
        RelayReason::Other => 0,
        RelayReason::ProxyBlocked => 1,
        RelayReason::ProxyAuthUnsupported => 3,
        _ => 2,
    }
}

async fn run(
    shared: Arc<Shared>,
    mut control: mpsc::UnboundedReceiver<Control>,
    mut cmds: mpsc::UnboundedReceiver<TransportCommand>,
    events: mpsc::Sender<TransportEvent>,
) {
    let timing = shared.net.timing.clone();
    let mut status = StatusSink { events: events.clone(), last: None };
    if !status.set(RelayStatus::of(RelayLink::Connecting)).await {
        return;
    }
    let mut failures: u32 = 0;
    let mut mode = ModePolicy::from_env(timing.clone(), &*shared.net.env);
    let mut ensured: Option<(String, String)> = None;
    let mut wait = Duration::ZERO;
    loop {
        // Backoff, still honouring Shutdown and configuration changes.
        let sleep = tokio::time::sleep(wait);
        tokio::pin!(sleep);
        loop {
            tokio::select! {
                _ = &mut sleep => break,
                c = cmds.recv() => match c {
                    None | Some(TransportCommand::Shutdown) => return,
                    Some(_) => {} // nothing is connected: stale command
                },
                k = control.recv() => match k {
                    None => return,
                    Some(k) => {
                        handle_control(&shared, k, &mut failures, &mut ensured, &mut mode);
                        break;
                    }
                },
            }
        }

        let room = shared.store.get();
        let owner = shared.owner.lock().unwrap_or_else(|p| p.into_inner()).clone();
        let entries = shared.net.proxies_for(&room.url).await;
        log::info!("relay: connecting to {} via {:?}", room.url, entries);

        // Create the room when we can and have not yet.
        let key = (room.url.clone(), room.room_id.clone());
        if let (Some(token), true) = (owner.as_deref(), ensured.as_ref() != Some(&key)) {
            match shared.net.ensure_room(&room, token, &entries).await {
                Ok(()) => ensured = Some(key.clone()),
                Err(f) => {
                    log::info!("relay: room creation failed: {}", f.detail);
                    if !status.set(f.status()).await {
                        return;
                    }
                    failures = failures.saturating_add(1);
                    wait = timing.backoff_unit * backoff_factor(failures);
                    continue;
                }
            }
        }

        let mut ws_failure: Option<Failure> = None;
        let mut result: Option<SessionEnd> = None;
        if mode.should_try_websocket(Instant::now()) {
            match shared.net.ws_connect(&room, "desktop", &entries, owner.is_some()).await {
                Ok(ws) => {
                    let Ok(end) =
                        run_ws(ws, &timing, &mut mode, &mut status, &mut cmds, &mut control, &events).await
                    else {
                        return;
                    };
                    result = Some(end);
                }
                Err(f) => {
                    log::info!("relay: WebSocket failed ({}); trying long-poll", f.detail);
                    if f.room_missing {
                        ensured = None;
                    }
                    mode.websocket_failed(Instant::now());
                    ws_failure = Some(f);
                }
            }
        }
        let end = match result {
            Some(e) => e,
            None => {
                let deadline = mode.retry_deadline(Instant::now());
                let e = poll_session(&shared.net, &room, &entries, &mut cmds, &mut control, &events, &mut status, deadline, owner.is_some())
                    .await;
                match e {
                    SessionEnd::Upgrade(ws) => {
                        let Ok(end) =
                            run_ws(ws, &timing, &mut mode, &mut status, &mut cmds, &mut control, &events).await
                        else {
                            return;
                        };
                        end
                    }
                    SessionEnd::Ended { lasted, reason, failure: Some(f) } if lasted.is_zero() => {
                        // Never connected: the more specific failure wins.
                        let f = match ws_failure {
                            Some(w) if specificity(w.reason) > specificity(f.reason) => w,
                            _ => f,
                        };
                        SessionEnd::Ended { lasted, reason, failure: Some(f) }
                    }
                    e => e,
                }
            }
        };
        match end {
            SessionEnd::Shutdown => return,
            // Handled where the long-poll session ends; cannot reach here.
            SessionEnd::Upgrade(_) => wait = Duration::ZERO,
            SessionEnd::Control(k) => {
                handle_control(&shared, k, &mut failures, &mut ensured, &mut mode);
                wait = Duration::ZERO;
                if !status.set(RelayStatus::of(RelayLink::Connecting)).await {
                    return;
                }
            }
            SessionEnd::Ended { lasted, reason, failure } => {
                log::info!("relay: link ended after {:?}: {reason}", lasted);
                if lasted >= timing.short_drop {
                    failures = 0;
                }
                failures = failures.saturating_add(1);
                if let Some(f) = &failure {
                    if f.room_missing {
                        ensured = None;
                    }
                }
                let next = match failure {
                    Some(f) => f.status(),
                    None => RelayStatus::of(RelayLink::Connecting),
                };
                if !status.set(next).await {
                    return;
                }
                wait = timing.backoff_unit * backoff_factor(failures);
            }
        }
    }
}

fn handle_control(
    shared: &Arc<Shared>,
    k: Control,
    failures: &mut u32,
    ensured: &mut Option<(String, String)>,
    mode: &mut ModePolicy,
) {
    *failures = 0;
    *ensured = None;
    *mode = ModePolicy::from_env(shared.net.timing.clone(), &*shared.net.env);
    if let Control::ResetRoom(old) = k {
        let shared = shared.clone();
        tokio::spawn(async move {
            let owner = shared.owner.lock().unwrap_or_else(|p| p.into_inner()).clone();
            shared.net.delete_room(&old, owner.as_deref().map(String::as_str)).await;
        });
    }
}

// ------------------------------------------------------- WebSocket link

async fn ws_write(ws: &mut WebSocketStream<BoxIo>, t: &Timing, m: WsMessage) -> Result<(), String> {
    match tokio::time::timeout(t.write_timeout, ws.send(m)).await {
        Ok(Ok(())) => Ok(()),
        Ok(Err(e)) => Err(format!("write failed: {e}")),
        Err(_) => Err("write timed out".to_owned()),
    }
}

async fn ws_session(
    mut ws: WebSocketStream<BoxIo>,
    t: &Timing,
    cmds: &mut mpsc::UnboundedReceiver<TransportCommand>,
    control: &mut mpsc::UnboundedReceiver<Control>,
    events: &mpsc::Sender<TransportEvent>,
    started: Instant,
) -> SessionEnd {
    let mut pump = Pump::new(events.clone());
    let mut ping = tokio::time::interval(t.ping_every);
    ping.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    ping.tick().await; // the first tick is immediate
    let mut last_rx = Instant::now();

    let (reason, failure) = loop {
        tokio::select! {
            m = ws.next() => {
                let Some(m) = m else { break ("closed by the relay".to_owned(), None) };
                last_rx = Instant::now();
                match m {
                    Err(e) => break (format!("read failed: {e}"), None),
                    Ok(WsMessage::Text(text)) => {
                        if pump.on_text(text.as_bytes()).await.is_err() {
                            return SessionEnd::Shutdown;
                        }
                    }
                    Ok(WsMessage::Binary(b)) => {
                        if pump.on_text(&b).await.is_err() {
                            return SessionEnd::Shutdown;
                        }
                    }
                    Ok(WsMessage::Close(frame)) => {
                        let code = frame.as_ref().map(|f| u16::from(f.code));
                        let failure = match code {
                            Some(4001) => Some(Failure::new(
                                RelayReason::Other,
                                "another desktop took over this room (4001)",
                            )),
                            Some(4003) => Some(Failure::new(RelayReason::RoomConflict, "the room was deleted (4003)")),
                            _ => None,
                        };
                        break (format!("closed by the relay ({code:?})"), failure);
                    }
                    Ok(_) => {} // ping/pong (answered by tungstenite)
                }
            }
            c = cmds.recv() => match c {
                None | Some(TransportCommand::Shutdown) => {
                    let _ = tokio::time::timeout(Duration::from_secs(1), ws.close(None)).await;
                    pump.close_all("shutdown").await;
                    return SessionEnd::Shutdown;
                }
                Some(TransportCommand::Send { peer, frames }) => {
                    let mut write_error = None;
                    for text in pump.outbound(&peer, &frames) {
                        if let Err(e) = ws_write(&mut ws, t, WsMessage::text(text)).await {
                            write_error = Some(e);
                            break;
                        }
                    }
                    if let Some(e) = write_error {
                        break (e, None);
                    }
                }
                Some(TransportCommand::Disconnect { peer, .. }) => {
                    if pump.host_disconnect(&peer).await.is_err() {
                        return SessionEnd::Shutdown;
                    }
                }
            },
            k = control.recv() => {
                let _ = tokio::time::timeout(Duration::from_secs(1), ws.close(None)).await;
                pump.close_all("reconfigured").await;
                return match k {
                    Some(k) => SessionEnd::Control(k),
                    None => SessionEnd::Shutdown,
                };
            }
            _ = ping.tick() => {
                if last_rx.elapsed() >= t.idle_timeout {
                    break ("idle: nothing received".to_owned(), None);
                }
                if let Err(e) = ws_write(&mut ws, t, WsMessage::Ping(Vec::new().into())).await {
                    break (e, None);
                }
            }
        }
    };
    pump.close_all(&reason).await;
    SessionEnd::Ended { lasted: started.elapsed(), reason, failure }
}

// ------------------------------------------------------ long-poll link

/// Messages from the poller task.
type WsProbe<'a> =
    std::pin::Pin<Box<dyn std::future::Future<Output = Result<WebSocketStream<BoxIo>, Failure>> + Send + 'a>>;

enum Polled {
    /// First answer: the session exists.
    Up,
    Events(Vec<serde_json::Value>),
    Closed(Closed),
    Failed(Failure),
}

fn random_session_id() -> String {
    let mut b = [0u8; 16];
    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut b);
    URL_SAFE_NO_PAD.encode(b)
}

#[allow(clippy::too_many_arguments)]
async fn poll_session(
    net: &Net,
    room: &RoomSettings,
    entries: &[ProxyEntry],
    cmds: &mut mpsc::UnboundedReceiver<TransportCommand>,
    control: &mut mpsc::UnboundedReceiver<Control>,
    events: &mpsc::Sender<TransportEvent>,
    status: &mut StatusSink,
    deadline: Instant,
    has_owner: bool,
) -> SessionEnd {
    let t = &net.timing;
    // Pick the proxy entry that reaches the relay, and keep its client.
    let client = match probe_client(net, &room.url, entries).await {
        Ok(c) => c,
        Err(f) => return SessionEnd::Ended { lasted: Duration::ZERO, reason: f.detail.clone(), failure: Some(f) },
    };
    let session = random_session_id();
    let base = endpoint(&room.url, &format!("/rooms/{}", room.room_id));
    let secret = room.desktop_secret.clone();
    let (ptx, mut prx) = mpsc::channel::<Polled>(16);
    let poller: JoinHandle<()> = {
        let (client, base, session, secret) = (client.clone(), base.clone(), session.clone(), secret.clone());
        let timeout = t.poll_timeout;
        tokio::spawn(async move {
            let mut cursor: u64 = 0;
            let mut up = false;
            loop {
                let url = format!("{base}/poll?role=desktop&session={session}&cursor={cursor}");
                let resp = client.get(&url).bearer_auth(secret.as_str()).timeout(timeout).send().await;
                let msg = match resp {
                    Err(e) => Polled::Failed(Failure::new(classify_error_text(&error_chain(&e)), error_chain(&e))),
                    Ok(r) if r.status().is_success() => match r.json::<PollResponse>().await {
                        Ok(p) => {
                            if !up {
                                up = true;
                                if ptx.send(Polled::Up).await.is_err() {
                                    return;
                                }
                            }
                            cursor = p.cursor.max(cursor);
                            if !p.events.is_empty() && ptx.send(Polled::Events(p.events)).await.is_err() {
                                return;
                            }
                            match p.closed {
                                Some(c) => Polled::Closed(c),
                                None => continue,
                            }
                        }
                        Err(e) => Polled::Failed(Failure::new(RelayReason::Other, format!("bad poll answer: {e}"))),
                    },
                    Ok(r) if r.status().as_u16() == 410 => {
                        Polled::Failed(Failure::new(RelayReason::Other, "the long-poll session expired (410)"))
                    }
                    Ok(r) => Polled::Failed(classify_relay_status(r.status().as_u16(), has_owner)),
                };
                let _ = ptx.send(msg).await;
                return;
            }
        })
    };

    let mut pump = Pump::new(events.clone());
    let mut connected_at: Option<Instant> = None;
    let retry = tokio::time::sleep_until(deadline.into());
    tokio::pin!(retry);
    let mut probe: Option<WsProbe<'_>> = None;
    let send_url = format!("{base}/send?role=desktop&session={session}");

    let post = |bodies: Vec<String>| {
        let (client, url, secret, timeout) = (client.clone(), send_url.clone(), secret.clone(), t.write_timeout);
        async move {
            // `{"frames":[…]}` (the `type` field is optional inside).
            let frames: Vec<serde_json::Value> =
                bodies.iter().filter_map(|b| serde_json::from_str(b).ok()).collect();
            let r = client
                .post(&url)
                .bearer_auth(secret.as_str())
                .timeout(timeout)
                .json(&serde_json::json!({ "frames": frames }))
                .send()
                .await;
            match r {
                Ok(r) if r.status().is_success() => Ok(()),
                Ok(r) if r.status().as_u16() == 410 => Err("the long-poll session expired (410)".to_owned()),
                Ok(r) => Err(format!("send answered HTTP {}", r.status().as_u16())),
                Err(e) => Err(error_chain(&e)),
            }
        }
    };

    let (reason, failure) = loop {
        tokio::select! {
            p = prx.recv() => match p {
                None => break ("poller stopped".to_owned(), None),
                Some(Polled::Up) => {
                    connected_at = Some(Instant::now());
                    if !status.set(RelayStatus::of(RelayLink::Fallback)).await {
                        poller.abort();
                        return SessionEnd::Shutdown;
                    }
                }
                Some(Polled::Events(list)) => {
                    for v in list {
                        if let Ok(m) = serde_json::from_value::<ServerMsg>(v) {
                            if pump.on_server(m).await.is_err() {
                                poller.abort();
                                return SessionEnd::Shutdown;
                            }
                        }
                    }
                }
                Some(Polled::Closed(c)) => {
                    let failure = match c.code {
                        4001 => Some(Failure::new(RelayReason::Other, "another desktop took over this room (4001)")),
                        4003 => Some(Failure::new(RelayReason::RoomConflict, "the room was deleted (4003)")),
                        _ => None,
                    };
                    break (format!("closed by the relay ({} {})", c.code, c.reason), failure);
                }
                Some(Polled::Failed(f)) => {
                    let reason = f.detail.clone();
                    break (reason, connected_at.is_none().then_some(f));
                }
            },
            c = cmds.recv() => match c {
                None | Some(TransportCommand::Shutdown) => {
                    poller.abort();
                    pump.close_all("shutdown").await;
                    return SessionEnd::Shutdown;
                }
                Some(TransportCommand::Send { peer, frames }) => {
                    let bodies = pump.outbound(&peer, &frames);
                    if !bodies.is_empty() {
                        if let Err(e) = post(bodies).await {
                            break (format!("send failed: {e}"), None);
                        }
                    }
                }
                Some(TransportCommand::Disconnect { peer, .. }) => {
                    if pump.host_disconnect(&peer).await.is_err() {
                        poller.abort();
                        return SessionEnd::Shutdown;
                    }
                }
            },
            k = control.recv() => {
                poller.abort();
                pump.close_all("reconfigured").await;
                return match k {
                    Some(k) => SessionEnd::Control(k),
                    None => SessionEnd::Shutdown,
                };
            }
            _ = &mut retry, if probe.is_none() => {
                // Time to retry the WebSocket: probe it while this session
                // (and its phones) stays up; switch only if it connects.
                probe = Some(Box::pin(net.ws_connect(room, "desktop", entries, has_owner)));
            }
            r = async { probe.as_mut().expect("guarded").await }, if probe.is_some() => {
                probe = None;
                match r {
                    Ok(ws) => {
                        poller.abort();
                        pump.close_all("switching to the WebSocket").await;
                        return SessionEnd::Upgrade(ws);
                    }
                    Err(f) => {
                        log::info!("relay: the WebSocket is still unusable ({}); staying on long-poll", f.detail);
                        retry.as_mut().reset((Instant::now() + t.ws_retry_every).into());
                    }
                }
            }
        }
    };
    poller.abort();
    pump.close_all(&reason).await;
    // `lasted` is zero when the fallback never came up, so the caller can
    // tell a failed attempt (report the failure) from a dropped link.
    SessionEnd::Ended { lasted: connected_at.map_or(Duration::ZERO, |c| c.elapsed()), reason, failure }
}

/// `GET /v1/health` through each proxy entry; the first that answers gives
/// the client (built with the long-poll timeout) for the session.
async fn probe_client(net: &Net, base: &str, entries: &[ProxyEntry]) -> Result<reqwest::Client, Failure> {
    let mut last = Failure::new(RelayReason::Other, "no route to the relay");
    let url = endpoint(base, "/health");
    for entry in entries {
        let client = match net.http_client(entry, net.timing.poll_timeout) {
            Ok(c) => c,
            Err(f) => {
                last = f;
                continue;
            }
        };
        match client.get(&url).timeout(net.timing.connect_timeout).send().await {
            Ok(r) if r.status().is_success() => return Ok(client),
            Ok(r) => last = classify_relay_status(r.status().as_u16(), true),
            Err(e) => {
                let text = error_chain(&e);
                let mut reason = classify_error_text(&text);
                if matches!(entry, ProxyEntry::Direct) && reason == RelayReason::ProxyBlocked {
                    reason = RelayReason::Other;
                }
                last = Failure::new(reason, text);
            }
        }
    }
    Err(last)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn t(ms: u64) -> Duration {
        Duration::from_millis(ms)
    }

    #[test]
    fn backoff_is_1_2_4_8_then_30() {
        let v: Vec<u32> = (0..8).map(backoff_factor).collect();
        assert_eq!(v, [0, 1, 2, 4, 8, 30, 30, 30]);
        assert_eq!(backoff_factor(u32::MAX), 30);
    }

    #[test]
    fn websocket_failure_falls_back_and_retries_every_five_minutes() {
        let timing = Timing { ws_retry_every: Duration::from_secs(300), ..Timing::default() };
        let mut m = ModePolicy::new(timing);
        let t0 = Instant::now();
        assert!(m.should_try_websocket(t0));
        m.websocket_failed(t0);
        assert!(m.in_fallback());
        assert!(!m.should_try_websocket(t0 + Duration::from_secs(299)));
        assert!(m.should_try_websocket(t0 + Duration::from_secs(300)));
        // The retry fails again: another 5 minutes of fallback.
        let t1 = t0 + Duration::from_secs(301);
        m.websocket_failed(t1);
        assert!(!m.should_try_websocket(t1 + Duration::from_secs(10)));
        assert_eq!(m.retry_deadline(t1), t1 + Duration::from_secs(300));
    }

    #[test]
    fn force_longpoll_env_never_tries_the_websocket() {
        let on = |k: &str| (k == "VQ_RELAY_FORCE_LONGPOLL").then(|| "1".to_owned());
        let m = ModePolicy::from_env(Timing::default(), &on);
        let now = Instant::now();
        assert!(!m.should_try_websocket(now));
        assert!(!m.should_try_websocket(now + Duration::from_secs(10_000)));
        assert!(m.in_fallback());
        assert!(m.retry_deadline(now) > now + Duration::from_secs(86_400));
        let off = |k: &str| (k == "VQ_RELAY_FORCE_LONGPOLL").then(|| "0".to_owned());
        assert!(ModePolicy::from_env(Timing::default(), &off).should_try_websocket(now));
        assert!(ModePolicy::from_env(Timing::default(), &|_| None).should_try_websocket(now));
    }

    #[test]
    fn two_short_drops_in_a_row_fall_back_but_a_long_one_resets() {
        let mut m = ModePolicy::new(Timing::default());
        let now = Instant::now();
        assert!(!m.websocket_ended(now, t(3000)));
        assert!(m.should_try_websocket(now));
        assert!(m.websocket_ended(now, t(1000)));
        assert!(m.in_fallback());
        // A long-lived connection (after a retry) clears everything.
        let later = now + Duration::from_secs(301);
        assert!(m.should_try_websocket(later));
        assert!(!m.websocket_ended(later, Duration::from_secs(60)));
        assert!(!m.in_fallback());
        assert!(!m.websocket_ended(later, t(1000)));
    }

    #[test]
    fn error_classification() {
        use RelayReason::*;
        let cases = [
            ("error trying to connect: dns error: failed to lookup address information", Dns),
            ("nodename nor servname provided, or not known", Dns),
            ("TLS handshake: The certificate chain was issued by an authority that is not trusted", TlsUntrusted),
            ("SecureTransport error: -9807 (errSSLXCertChainInvalid)", TlsUntrusted),
            ("A certificate chain processed, but terminated in a root certificate which is not trusted: 0x800B0109", TlsUntrusted),
            ("unable to get local issuer certificate", TlsUntrusted),
            ("proxy authentication required", ProxyAuthRequired),
            ("the proxy answered CONNECT with HTTP 407", ProxyAuthRequired),
            ("unsuccessful tunnel", ProxyBlocked),
            ("connection reset by peer", Other),
        ];
        for (text, want) in cases {
            assert_eq!(classify_error_text(text), want, "{text}");
        }
    }

    #[test]
    fn connect_and_relay_statuses() {
        assert_eq!(classify_connect_status(200), None);
        assert_eq!(classify_connect_status(407), Some(RelayReason::ProxyAuthRequired));
        assert_eq!(classify_connect_status(403), Some(RelayReason::ProxyBlocked));
        assert_eq!(classify_connect_status(502), Some(RelayReason::ProxyBlocked));
        assert_eq!(classify_relay_status(401, true).reason, RelayReason::RoomConflict);
        assert_eq!(classify_relay_status(409, true).reason, RelayReason::RoomConflict);
        let missing_no_token = classify_relay_status(404, false);
        assert_eq!(missing_no_token.reason, RelayReason::OwnerTokenRejected);
        assert!(missing_no_token.room_missing);
        assert_eq!(classify_relay_status(500, true).reason, RelayReason::Other);
    }

    #[test]
    fn urls() {
        assert_eq!(
            ws_scheme_url("https://relay.example.com", "R", "desktop"),
            "wss://relay.example.com/v1/rooms/R/ws?role=desktop"
        );
        assert_eq!(
            ws_scheme_url("http://127.0.0.1:8787/", "R", "phone"),
            "ws://127.0.0.1:8787/v1/rooms/R/ws?role=phone"
        );
        assert_eq!(endpoint("https://r.example/", "/health"), "https://r.example/v1/health");
    }

    #[test]
    fn peer_ids() {
        assert_eq!(peer_id("abc"), "relay:abc");
        assert_eq!(conn_of("relay:abc"), Some("abc"));
        assert_eq!(conn_of("tcp:1"), None);
    }

    #[test]
    fn server_messages_parse() {
        let m: ServerMsg = serde_json::from_str(r#"{"type":"peer_joined","conn_id":"x"}"#).unwrap();
        assert!(matches!(m, ServerMsg::PeerJoined { conn_id } if conn_id == "x"));
        let m: ServerMsg = serde_json::from_str(r#"{"type":"desktop_present","present":true}"#).unwrap();
        assert!(matches!(m, ServerMsg::Other));
        let m: ServerMsg = serde_json::from_str(r#"{"type":"frame","from":"a","data":"AAE="}"#).unwrap();
        assert!(matches!(m, ServerMsg::Frame { .. }));
    }
}
