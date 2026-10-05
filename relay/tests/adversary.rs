//! Adversarial tests for vq-relay (SPEC_V3 §4, §9; relay/README.md).
//!
//! Every test runs against a locally started relay on an ephemeral loopback
//! port. Failing tests are findings; tests named `info_*` document behaviour
//! that is by design but worth knowing.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use base64::Engine;
use futures_util::{SinkExt, StreamExt};
use rand::RngCore;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::{sleep, timeout};
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::http::HeaderValue;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::{MaybeTlsStream, WebSocketStream};
use vq_relay::Config;

const OWNER: &str = "test-owner-token";

fn rnd(n: usize) -> String {
    let mut b = vec![0u8; n];
    rand::thread_rng().fill_bytes(&mut b);
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b)
}
fn hash_of(secret: &str) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(Sha256::digest(secret.as_bytes()))
}
/// The test desktop secret for a room secret (the relay never sees either).
fn dsec(room_secret: &str) -> String {
    format!("desk-{room_secret}")
}
/// PUT body for a room with both hashes (SPEC_V3 X1).
fn put_body(room_secret: &str) -> Value {
    json!({"secret_hash": hash_of(room_secret), "desktop_secret_hash": hash_of(&dsec(room_secret))})
}
fn b64(b: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(b)
}

struct Srv {
    addr: SocketAddr,
    task: tokio::task::JoinHandle<()>,
    http: reqwest::Client,
    _dir: Option<tempfile::TempDir>,
}

impl Drop for Srv {
    fn drop(&mut self) {
        self.task.abort();
    }
}

#[derive(Clone)]
struct Room {
    id: String,
    secret: String,
}

fn lenient(c: &mut Config) {
    c.auth_fail_limit = 1_000_000;
    c.create_limit = 1_000_000;
}

impl Srv {
    async fn start() -> Srv {
        Srv::start_with(|_| {}).await
    }
    async fn start_with(f: impl FnOnce(&mut Config)) -> Srv {
        let dir = tempfile::tempdir().unwrap();
        let mut s = Srv::start_at(dir.path(), f).await;
        s._dir = Some(dir);
        s
    }
    async fn start_at(dir: &Path, f: impl FnOnce(&mut Config)) -> Srv {
        let mut cfg = Config::new(OWNER.into(), dir.to_owned());
        f(&mut cfg);
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap();
        let task = tokio::spawn(async move {
            let _ = vq_relay::serve(l, cfg).await;
        });
        Srv { addr, task, http: reqwest::Client::new(), _dir: None }
    }
    fn url(&self, p: &str) -> String {
        format!("http://{}{}", self.addr, p)
    }
    async fn put(&self, id: &str, hash: &str, owner: Option<&str>, ip: Option<&str>) -> u16 {
        let mut r = self.http.put(self.url(&format!("/v1/rooms/{id}"))).json(&json!({"secret_hash": hash}));
        if let Some(o) = owner {
            r = r.header("X-VQ-Owner", o);
        }
        if let Some(ip) = ip {
            r = r.header("CF-Connecting-IP", ip);
        }
        r.send().await.unwrap().status().as_u16()
    }
    async fn room(&self) -> Room {
        let r = Room { id: rnd(16), secret: rnd(32) };
        let ip = format!("198.51.100.{}", rand::random::<u8>());
        let resp = self
            .http
            .put(self.url(&format!("/v1/rooms/{}", r.id)))
            .header("X-VQ-Owner", OWNER)
            .header("CF-Connecting-IP", ip)
            .json(&put_body(&r.secret))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status().as_u16(), 201);
        r
    }
    /// WebSocket upgrade with arbitrary path/query and raw header bytes.
    async fn ws_raw(&self, path_q: &str, headers: &[(&str, &[u8])]) -> Result<Ws, u16> {
        let mut req = format!("ws://{}{}", self.addr, path_q).into_client_request().unwrap();
        for (k, v) in headers {
            req.headers_mut().append(
                tokio_tungstenite::tungstenite::http::HeaderName::from_bytes(k.as_bytes()).unwrap(),
                HeaderValue::from_bytes(v).unwrap(),
            );
        }
        match timeout(Duration::from_secs(10), tokio_tungstenite::connect_async(req)).await.expect("ws connect hang") {
            Ok((ws, resp)) => Ok(Ws {
                ws,
                proto: resp.headers().get("Sec-WebSocket-Protocol").map(|v| v.to_str().unwrap().to_owned()),
            }),
            Err(tokio_tungstenite::tungstenite::Error::Http(resp)) => Err(resp.status().as_u16()),
            Err(e) => panic!("ws connect: {e}"),
        }
    }
    async fn ws(&self, r: &Room, role: &str) -> Ws {
        let secret = if role == "desktop" { dsec(&r.secret) } else { r.secret.clone() };
        let auth = format!("Bearer {secret}");
        self.ws_raw(&format!("/v1/rooms/{}/ws?role={role}", r.id), &[("Authorization", auth.as_bytes())])
            .await
            .unwrap()
    }
    async fn send_raw(&self, r: &Room, role: &str, session: &str, auth: Option<&str>, body: Vec<u8>) -> (u16, Value) {
        let mut q = self
            .http
            .post(self.url(&format!("/v1/rooms/{}/send?role={role}&session={session}", r.id)))
            .header("Content-Type", "application/json")
            .body(body);
        if let Some(a) = auth {
            q = q.header("Authorization", a);
        }
        let resp = q.send().await.unwrap();
        let s = resp.status().as_u16();
        (s, resp.json().await.unwrap_or(Value::Null))
    }
    async fn send(&self, r: &Room, role: &str, session: &str, body: Value) -> (u16, Value) {
        let secret = if role == "desktop" { dsec(&r.secret) } else { r.secret.clone() };
        let a = format!("Bearer {secret}");
        self.send_raw(r, role, session, Some(&a), body.to_string().into_bytes()).await
    }
    async fn poll_q(&self, r: &Room, query: &str) -> (u16, Value) {
        let resp = self
            .http
            .get(self.url(&format!("/v1/rooms/{}/poll?{query}", r.id)))
            .header("Authorization", format!("Bearer {}", if query.contains("role=desktop") { dsec(&r.secret) } else { r.secret.clone() }))
            .send()
            .await
            .unwrap();
        let s = resp.status().as_u16();
        (s, resp.json().await.unwrap_or(Value::Null))
    }
}

struct Ws {
    ws: WebSocketStream<MaybeTlsStream<TcpStream>>,
    proto: Option<String>,
}

impl Ws {
    async fn recv(&mut self) -> Value {
        loop {
            match timeout(Duration::from_secs(5), self.ws.next()).await.expect("recv timeout") {
                Some(Ok(Message::Text(t))) => return serde_json::from_str(t.as_str()).unwrap_or(json!(t.as_str())),
                Some(Ok(Message::Ping(_) | Message::Pong(_))) => {}
                other => panic!("expected text, got {other:?}"),
            }
        }
    }
    /// Close code, 1005 for a close without a code, 0 for an abrupt end.
    async fn recv_close(&mut self) -> u16 {
        loop {
            match timeout(Duration::from_secs(15), self.ws.next()).await.expect("close timeout") {
                Some(Ok(Message::Close(Some(f)))) => return f.code.into(),
                Some(Ok(Message::Close(None))) => return 1005,
                Some(Ok(_)) => {}
                Some(Err(_)) | None => return 0,
            }
        }
    }
    async fn expect_silence(&mut self, ms: u64) {
        let end = Instant::now() + Duration::from_millis(ms);
        while let Ok(m) = timeout(end.saturating_duration_since(Instant::now()), self.ws.next()).await {
            match m {
                Some(Ok(Message::Ping(_) | Message::Pong(_))) => {}
                other => panic!("expected silence, got {other:?}"),
            }
        }
    }
    async fn send_json(&mut self, v: Value) {
        self.ws.send(Message::text(v.to_string())).await.unwrap();
    }
}

/// Write raw bytes to the relay, then read whatever comes back within `wait`.
async fn raw_http(addr: SocketAddr, req: &[u8], wait: Duration) -> String {
    let mut s = TcpStream::connect(addr).await.unwrap();
    s.write_all(req).await.unwrap();
    let mut out = Vec::new();
    let mut buf = [0u8; 4096];
    let end = Instant::now() + wait;
    while let Ok(Ok(n)) = timeout(end.saturating_duration_since(Instant::now()), s.read(&mut buf)).await {
        if n == 0 {
            break;
        }
        out.extend_from_slice(&buf[..n]);
        if out.windows(4).any(|w| w == b"\r\n\r\n") {
            break;
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn list_dir(p: &Path) -> Vec<String> {
    let mut v: Vec<String> =
        std::fs::read_dir(p).unwrap().map(|e| e.unwrap().file_name().to_string_lossy().into_owned()).collect();
    v.sort();
    v
}

// ======================================================================
// Auth
// ======================================================================

#[tokio::test]
async fn auth_owner_token_variants_are_rejected() {
    let s = Srv::start_with(lenient).await;
    let id = rnd(16);
    let h = hash_of("s");
    for bad in ["", "wrong", "TEST-OWNER-TOKEN", "test-owner-toke", "test-owner-tokenX", "test-owner-token\tX"] {
        assert_eq!(s.put(&id, &h, Some(bad), None).await, 401, "owner token {bad:?}");
    }
    assert_eq!(s.put(&id, &h, None, None).await, 401);
    // Non-UTF-8 / unicode owner header over raw TCP.
    let body = json!({"secret_hash": h}).to_string();
    let req = format!(
        "PUT /v1/rooms/{id} HTTP/1.1\r\nHost: x\r\nX-VQ-Owner: t\u{e9}st-owner-token\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    let resp = raw_http(s.addr, req.as_bytes(), Duration::from_secs(5)).await;
    assert!(resp.starts_with("HTTP/1.1 401"), "unicode owner: {resp}");
    // Two owner headers, one right: must not create (or if it does, consistently).
    let req2 = format!(
        "PUT /v1/rooms/{id} HTTP/1.1\r\nHost: x\r\nX-VQ-Owner: wrong\r\nX-VQ-Owner: {OWNER}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    let resp = raw_http(s.addr, req2.as_bytes(), Duration::from_secs(5)).await;
    assert!(!resp.starts_with("HTTP/1.1 5"), "duplicate owner header crashed: {resp}");
    // Nothing was created by the rejected attempts.
    assert_eq!(s.put(&id, &hash_of("other"), Some(OWNER), None).await, if resp.starts_with("HTTP/1.1 201") { 409 } else { 201 });
}

#[tokio::test]
async fn auth_claim_with_different_hash_is_409_and_keeps_original_secret() {
    let s = Srv::start_with(lenient).await;
    let r = s.room().await;
    let attacker = rnd(32);
    assert_eq!(s.put(&r.id, &hash_of(&attacker), Some(OWNER), None).await, 409);
    // Lowercased / re-padded variants of the hash are different strings: still 409 or 400.
    let up = hash_of(&r.secret).to_uppercase();
    let st = s.put(&r.id, &up, Some(OWNER), None).await;
    assert!(st == 409 || st == 400, "case-mangled hash: {st}");
    let padded = format!("{}=", hash_of(&r.secret));
    assert_eq!(s.put(&r.id, &padded, Some(OWNER), None).await, 400);
    // Original secret still works; attacker's does not.
    let mut d = s.ws(&r, "desktop").await;
    let a = format!("Bearer {attacker}");
    assert_eq!(
        s.ws_raw(&format!("/v1/rooms/{}/ws?role=phone", r.id), &[("Authorization", a.as_bytes())]).await.err(),
        Some(401)
    );
    d.expect_silence(200).await;
}

#[tokio::test]
async fn auth_bad_secret_variants_rejected_on_ws_send_and_poll() {
    let s = Srv::start_with(lenient).await;
    let r = s.room().await;
    let long = "A".repeat(8000);
    let prefix = r.secret[..20].to_owned();
    let unicode = format!("Bearer {}\u{e9}", r.secret);
    let variants: Vec<Vec<u8>> = vec![
        b"Bearer ".to_vec(),
        b"Bearer".to_vec(),
        format!("Bearer {}x", r.secret).into_bytes(),
        format!("Bearer {prefix}").into_bytes(),
        format!("Bearer {long}").into_bytes(),
        format!("Basic {}", r.secret).into_bytes(),
        format!("Bearer{}", r.secret).into_bytes(),
        format!("Bearer {}", hash_of(&r.secret)).into_bytes(), // the stored hash is not the secret
        unicode.into_bytes(),
        vec![b'B', b'e', b'a', b'r', b'e', b'r', b' ', 0xff, 0xfe],
    ];
    for v in &variants {
        let st = s.ws_raw(&format!("/v1/rooms/{}/ws?role=phone", r.id), &[("Authorization", v)]).await.err();
        assert_eq!(st, Some(401), "ws auth {:?}", String::from_utf8_lossy(v));
        let resp = s
            .http
            .post(s.url(&format!("/v1/rooms/{}/send?role=phone&session=sess-aaaa", r.id)))
            .header("Authorization", HeaderValue::from_bytes(v).unwrap())
            .body(r#"{"type":"frame","data":"AA=="}"#)
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status().as_u16(), 401, "send auth {:?}", String::from_utf8_lossy(v));
    }
    // The secret in the query string must NOT authenticate (it would leak into logs).
    for q in ["secret", "room_secret", "token", "auth", "access_token"] {
        let path = format!("/v1/rooms/{}/ws?role=phone&{q}={}", r.id, r.secret);
        assert_eq!(s.ws_raw(&path, &[]).await.err(), Some(401), "query {q}");
        let resp = s
            .http
            .get(s.url(&format!("/v1/rooms/{}/poll?role=phone&session=sess-bbbb&cursor=0&{q}={}", r.id, r.secret)))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status().as_u16(), 401, "poll query {q}");
    }
}

#[tokio::test]
async fn auth_subprotocol_edge_cases() {
    let s = Srv::start_with(lenient).await;
    let r = s.room().await;
    let path = format!("/v1/rooms/{}/ws?role=phone", r.id);
    let p = |x: String| x.into_bytes();
    for bad in [
        p("vq.auth.".into()),
        p(format!("VQ.AUTH.{}", r.secret)),
        p(format!("vq.auth{}", r.secret)),
        p(format!("vq.auth.{}x", r.secret)),
        p(format!("x-vq.auth.{}", r.secret)),
    ] {
        assert_eq!(
            s.ws_raw(&path, &[("Sec-WebSocket-Protocol", &bad)]).await.err(),
            Some(401),
            "subprotocol {:?}",
            String::from_utf8_lossy(&bad)
        );
    }
    // Offered among other protocols: accepted and only the vq.auth one echoed.
    let list = format!("chat, vq.auth.{}", r.secret);
    let ws = s.ws_raw(&path, &[("Sec-WebSocket-Protocol", list.as_bytes())]).await.unwrap();
    assert_eq!(ws.proto.as_deref(), Some(format!("vq.auth.{}", r.secret).as_str()));
    drop(ws);
    // A wrong bearer header must not be rescued by a right subprotocol (or vice versa crash).
    let wrong = b"Bearer wrong".to_vec();
    let right = format!("vq.auth.{}", r.secret).into_bytes();
    let st = s.ws_raw(&path, &[("Authorization", &wrong), ("Sec-WebSocket-Protocol", &right)]).await.err();
    assert_eq!(st, Some(401));
}

/// README: "Bad or missing secret: 401". A room whose secret_hash is
/// SHA-256("") must not let a client with NO credentials in.
#[tokio::test]
async fn auth_missing_secret_rejected_even_if_room_hash_is_of_empty_string() {
    let s = Srv::start_with(lenient).await;
    let id = rnd(16);
    let st = s.put(&id, &hash_of(""), Some(OWNER), None).await;
    if st == 400 {
        return; // relay refuses such a room: fine
    }
    assert_eq!(st, 201);
    let res = s.ws_raw(&format!("/v1/rooms/{id}/ws?role=desktop"), &[]).await;
    assert_eq!(res.err(), Some(401), "a request with no Authorization header joined the room");
}

/// Constant-time heuristic: a wrong secret sharing a long prefix with the
/// real one must not be measurably slower/faster than a totally wrong one.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn auth_timing_heuristic_prefix_vs_random() {
    let s = Srv::start_with(lenient).await;
    let r = s.room().await;
    let mut near = r.secret.clone();
    near.pop();
    near.push(if r.secret.ends_with('A') { 'B' } else { 'A' });
    let far = "z".repeat(r.secret.len());
    let path = format!("/v1/rooms/{}/send?role=phone&session=sess-tttt", r.id);
    let mut tn = Vec::new();
    let mut tf = Vec::new();
    for i in 0..600 {
        let sec = if i % 2 == 0 { &near } else { &far };
        let t0 = Instant::now();
        let st = s
            .http
            .post(s.url(&path))
            .header("Authorization", format!("Bearer {sec}"))
            .body("{}")
            .send()
            .await
            .unwrap()
            .status();
        let dt = t0.elapsed().as_nanos() as f64;
        assert_eq!(st.as_u16(), 401);
        if i >= 100 {
            if i % 2 == 0 { tn.push(dt) } else { tf.push(dt) }
        }
    }
    tn.sort_by(|a, b| a.partial_cmp(b).unwrap());
    tf.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let (mn, mf) = (tn[tn.len() / 2], tf[tf.len() / 2]);
    let ratio = mn / mf;
    assert!((0.75..1.33).contains(&ratio), "median near {mn} ns vs far {mf} ns (ratio {ratio})");
}

#[tokio::test]
async fn auth_room_id_traversal_and_odd_encodings_never_touch_fs() {
    let outer = tempfile::tempdir().unwrap();
    let data = outer.path().join("data");
    let s = Srv::start_at(&data, lenient).await;
    let h = hash_of("x");
    let ids = [
        "..%2F..%2F..%2F..%2Ftmp%2Fpwned-room",
        "%2e%2e%2f%2e%2e%2faaaaaaaaaaaaaaaa",
        "%2E%2E",
        "aaaaaaaaaaaaaaaa%2F..%2F..%2Frooms",
        "aaaaaaaaaaaaaaaa.json",
        "aaaaaaaaaaaaaaa=",
        "aaaaaaaaaaaaaaa", // 15
        &"a".repeat(65),
        &"a".repeat(10_000),
        "%00aaaaaaaaaaaaaaaaa",
        "aaaaaaaaaaaaaaaa%00",
        "%D0%B0%D0%B0%D0%B0%D0%B0%D0%B0%D0%B0%D0%B0%D0%B0%D0%B0%D0%B0%D0%B0%D0%B0%D0%B0%D0%B0%D0%B0%D0%B0",
        "%EF%BC%A1%EF%BC%A1%EF%BC%A1%EF%BC%A1%EF%BC%A1%EF%BC%A1%EF%BC%A1%EF%BC%A1",
        "%ZZaaaaaaaaaaaaaaaa",
        "aaaa%20aaaaaaaaaaaaa",
        "aaaaaaaaaaaaaaaa+",
    ];
    for id in ids {
        let st = s.put(id, &h, Some(OWNER), None).await;
        assert!(st == 400 || st == 404, "PUT id {id:?} -> {st}");
        let resp = s
            .http
            .get(s.url(&format!("/v1/rooms/{id}/poll?role=phone&session=sess-cccc&cursor=0")))
            .header("Authorization", "Bearer x")
            .send()
            .await
            .unwrap();
        let st = resp.status().as_u16();
        assert!(st == 400 || st == 404, "poll id {id:?} -> {st}");
    }
    // Raw, un-normalised traversal over TCP.
    for p in ["/v1/rooms/../../../../tmp/x", "/v1/rooms/./aaaaaaaaaaaaaaaa", "/v1/rooms//aaaaaaaaaaaaaaaa"] {
        let body = json!({"secret_hash": h}).to_string();
        let req = format!(
            "PUT {p} HTTP/1.1\r\nHost: x\r\nX-VQ-Owner: {OWNER}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        );
        let resp = raw_http(s.addr, req.as_bytes(), Duration::from_secs(5)).await;
        assert!(!resp.starts_with("HTTP/1.1 2"), "raw path {p}: {resp}");
    }
    // One valid room so the store is written; nothing else may appear.
    assert_eq!(s.put(&"b".repeat(16), &h, Some(OWNER), None).await, 201);
    assert_eq!(list_dir(outer.path()), vec!["data".to_string()]);
    assert_eq!(list_dir(&data), vec!["rooms.json".to_string()]);
}

/// Per-IP failed-auth limit works for the peer address; the CF-Connecting-IP
/// header is trusted from any peer (documented: only acceptable on loopback).
#[tokio::test]
async fn info_cf_connecting_ip_is_trusted_from_loopback_peer() {
    let s = Srv::start().await;
    let r = s.room().await;
    for _ in 0..10 {
        let resp = s
            .http
            .get(s.url(&format!("/v1/rooms/{}/poll?role=phone&session=sess-dddd&cursor=0", r.id)))
            .header("Authorization", "Bearer wrong")
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status().as_u16(), 401);
    }
    let right = format!("Bearer {}", r.secret);
    let blocked = s.ws_raw(&format!("/v1/rooms/{}/ws?role=phone", r.id), &[("Authorization", right.as_bytes())]).await;
    assert_eq!(blocked.err(), Some(429), "peer IP is blocked after 10 failures");
    // Spoofing a fresh CF-Connecting-IP from the same loopback peer evades it.
    let evade = s
        .ws_raw(
            &format!("/v1/rooms/{}/ws?role=phone", r.id),
            &[("Authorization", right.as_bytes()), ("CF-Connecting-IP", b"203.0.113.9")],
        )
        .await;
    assert!(evade.is_ok(), "documented: header trusted from loopback");
}

// ======================================================================
// Isolation
// ======================================================================

#[tokio::test]
async fn isolation_cross_room_and_phone_to_phone() {
    let s = Srv::start_with(lenient).await;
    let a = s.room().await;
    let b = s.room().await;
    // A's secret does not open B.
    let wrong = Room { id: b.id.clone(), secret: a.secret.clone() };
    let aa = format!("Bearer {}", wrong.secret);
    assert_eq!(s.ws_raw(&format!("/v1/rooms/{}/ws?role=phone", b.id), &[("Authorization", aa.as_bytes())]).await.err(), Some(401));
    assert_eq!(s.send(&wrong, "phone", "sess-eeee", json!({"type":"frame","data":"AA=="})).await.0, 401);

    let mut da = s.ws(&a, "desktop").await;
    let mut db = s.ws(&b, "desktop").await;
    let mut pa = s.ws(&a, "phone").await;
    assert_eq!(pa.recv().await["present"], true);
    let pa_id = da.recv().await["conn_id"].as_str().unwrap().to_owned();
    let mut pa2 = s.ws(&a, "phone").await;
    assert_eq!(pa2.recv().await["present"], true);
    let pa2_id = da.recv().await["conn_id"].as_str().unwrap().to_owned();
    let mut pb = s.ws(&b, "phone").await;
    assert_eq!(pb.recv().await["present"], true);
    let pb_id = db.recv().await["conn_id"].as_str().unwrap().to_owned();

    // Desktop A addresses B's phone: dropped.
    da.send_json(json!({"type":"frame","to":pb_id,"data":b64(b"x-room")})).await;
    // Phone A addresses its sibling phone and B's phone, and forges `from`.
    pa.send_json(json!({"type":"frame","to":pa2_id,"from":pb_id,"data":b64(b"p2p")})).await;
    let got = da.recv().await;
    assert_eq!(got["type"], "frame");
    assert_eq!(got["from"], pa_id.as_str(), "relay must stamp the real sender");
    assert_eq!(got["data"], b64(b"p2p"));
    // Desktop A addresses itself: dropped.
    let me = "0000000000000000";
    da.send_json(json!({"type":"frame","to":me,"data":"AA=="})).await;
    // Long-poll session ids are per room.
    assert_eq!(s.send(&b, "phone", "shared-session", json!({"data":"AA=="})).await.0, 200);
    let pbs_id = db.recv().await["conn_id"].as_str().unwrap().to_owned();
    assert_eq!(db.recv().await["data"], "AA=="); // B's own poll phone frame, to B's desktop
    let (st, v) = s.send(&a, "phone", "shared-session", json!({"data":b64(b"from-a")})).await;
    assert_eq!(st, 200);
    assert_ne!(v["conn_id"].as_str().unwrap(), pbs_id);
    let _ = da.recv().await; // peer_joined for A's poll phone
    assert_eq!(da.recv().await["data"], b64(b"from-a"));

    pb.expect_silence(400).await;
    pa2.expect_silence(100).await;
    db.expect_silence(100).await;
}

#[tokio::test]
async fn isolation_second_desktop_without_secret_cannot_take_over() {
    let s = Srv::start_with(lenient).await;
    let r = s.room().await;
    let mut d = s.ws(&r, "desktop").await;
    let wrong = b"Bearer not-the-secret".to_vec();
    let path = format!("/v1/rooms/{}/ws?role=desktop", r.id);
    assert_eq!(s.ws_raw(&path, &[("Authorization", &wrong)]).await.err(), Some(401));
    assert_eq!(s.ws_raw(&path, &[("Sec-WebSocket-Protocol", b"vq.auth.nope")]).await.err(), Some(401));
    assert_eq!(s.ws_raw(&path, &[]).await.err(), Some(401));
    let bad = Room { id: r.id.clone(), secret: "nope".into() };
    assert_eq!(s.send(&bad, "desktop", "sess-ffff", json!({"frames":[]})).await.0, 401);
    // Role names are exact.
    for role in ["Desktop", "DESKTOP", "desktop%00", "desktop,phone", ""] {
        let st = s.ws_raw(&format!("/v1/rooms/{}/ws?role={role}", r.id), &[("Authorization", format!("Bearer {}", r.secret).as_bytes())]).await.err();
        assert_eq!(st, Some(400), "role {role:?}");
    }
    // Duplicate role params: either rejected or one of them, but never a crash.
    let st = s
        .ws_raw(&format!("/v1/rooms/{}/ws?role=phone&role=desktop", r.id), &[("Authorization", format!("Bearer {}", r.secret).as_bytes())])
        .await;
    if let Err(code) = st {
        assert!(code < 500, "duplicate role -> {code}");
    }
    sleep(Duration::from_millis(200)).await;
    // The original desktop was never replaced by the failed attempts. (A successful
    // duplicate-role desktop would legitimately replace it, so only check when refused.)
    if st.is_err() {
        d.expect_silence(300).await;
    }
}

// ======================================================================
// Resource exhaustion
// ======================================================================

#[tokio::test]
async fn resource_frame_size_boundaries() {
    let s = Srv::start_with(lenient).await;
    let r = s.room().await;
    let mut d = s.ws(&r, "desktop").await;
    let mut p = s.ws(&r, "phone").await;
    let _ = p.recv().await;
    let _ = d.recv().await;
    // Exactly 64 KiB, unpadded base64: delivered.
    let exact = vec![1u8; 65536];
    let unpadded = b64(&exact).trim_end_matches('=').to_owned();
    p.send_json(json!({"type":"frame","data":unpadded})).await;
    assert_eq!(d.recv().await["type"], "frame");
    // 64 KiB + 1: 1009.
    p.send_json(json!({"type":"frame","data":b64(&vec![1u8; 65537])})).await;
    assert_eq!(p.recv_close().await, 1009);
    // A tiny frame padded with 100 KiB of JSON whitespace: message too large, 1009.
    let mut p2 = s.ws(&r, "phone").await;
    let _ = p2.recv().await;
    let m = format!("{{\"type\":\"frame\",\"data\":\"AA==\"{}}}", " ".repeat(100 * 1024));
    p2.ws.send(Message::text(m)).await.unwrap();
    assert_eq!(p2.recv_close().await, 1009);
    // HTTP: 413 for a frame over 64 KiB.
    assert_eq!(s.send(&r, "phone", "sess-gggg", json!({"data": b64(&vec![0u8; 65537])})).await.0, 413);
}

/// README: "A message larger than 96 KiB ... closes the WebSocket with 1009".
/// Sent as one 20 MiB WebSocket frame (above tungstenite's 16 MiB default
/// frame cap), the relay must still answer 1009, not a generic close.
#[tokio::test]
async fn resource_ws_20mib_message_closes_1009() {
    let s = Srv::start_with(lenient).await;
    let r = s.room().await;
    let mut p = s.ws(&r, "phone").await;
    let _ = p.recv().await;
    let big = format!("{{\"type\":\"frame\",\"data\":\"{}\"}}", "A".repeat(20 << 20));
    let _ = timeout(Duration::from_secs(20), p.ws.send(Message::text(big))).await;
    let code = p.recv_close().await;
    assert_eq!(code, 1009, "20 MiB message closed with {code} (0 = abrupt, no close frame)");
}

#[tokio::test]
async fn resource_rate_limit_ws_and_http() {
    let s = Srv::start_with(lenient).await;
    let r = s.room().await;
    let mut p = s.ws(&r, "phone").await;
    let _ = p.recv().await;
    for _ in 0..60 {
        if p.ws.send(Message::text(r#"{"type":"frame","data":"AA=="}"#)).await.is_err() {
            break;
        }
    }
    assert_eq!(p.recv_close().await, 4029);
    // HTTP: a 51-frame batch is refused; nothing in it is delivered.
    let frames: Vec<Value> = (0..51).map(|_| json!({"data":"AA=="})).collect();
    assert_eq!(s.send(&r, "phone", "sess-hhhh", json!({"frames": frames})).await.0, 429);
    // Huge frames array (~4 MiB, 300k empty frames): fast refusal, server healthy.
    let mut body = String::from("{\"frames\":[");
    for i in 0..300_000 {
        if i > 0 {
            body.push(',');
        }
        body.push_str("{\"data\":\"\"}");
    }
    body.push_str("]}");
    let t0 = Instant::now();
    let a = format!("Bearer {}", r.secret);
    let (st, _) = s.send_raw(&r, "phone", "sess-iiii", Some(&a), body.into_bytes()).await;
    // X3 (orchestrator ruling): /send bodies are capped at 128 KiB while streaming, so
    // the ~4 MiB array is refused with 413 (it used to reach the 429 rate limit).
    assert_eq!(st, 413);
    assert!(t0.elapsed() < Duration::from_secs(5), "took {:?}", t0.elapsed());
    assert_eq!(s.http.get(s.url("/v1/health")).send().await.unwrap().status(), 200);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn resource_phone_cap_holds_under_concurrent_joins() {
    let s = std::sync::Arc::new(Srv::start_with(lenient).await);
    let r = s.room().await;
    let mut tasks = Vec::new();
    for i in 0..24 {
        let s = s.clone();
        let r = r.clone();
        tasks.push(tokio::spawn(async move {
            if i % 3 == 0 {
                let (st, _) = s.send(&r, "phone", &format!("sess-race-{i:04}"), json!({"data":"AA=="})).await;
                (st == 200, None)
            } else {
                let a = format!("Bearer {}", r.secret);
                match s.ws_raw(&format!("/v1/rooms/{}/ws?role=phone", r.id), &[("Authorization", a.as_bytes())]).await {
                    Ok(ws) => (true, Some(ws)),
                    Err(code) => {
                        assert_eq!(code, 429);
                        (false, None)
                    }
                }
            }
        }));
    }
    let mut ok = 0;
    let mut keep = Vec::new();
    for t in tasks {
        let (o, ws) = t.await.unwrap();
        ok += o as usize;
        keep.push(ws);
    }
    assert_eq!(ok, 8, "phones admitted concurrently");
}

/// README close-code table: 4008 "WebSocket peers only see this if their
/// queue is flooded". A desktop that stops reading while 8 phones send at the
/// allowed rate must eventually be cut off, not have ~100 MB buffered for it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn resource_ws_slow_consumer_queue_is_bounded() {
    let s = Srv::start_with(lenient).await;
    let r = s.room().await;
    let mut d = s.ws(&r, "desktop").await;
    let mut phones = Vec::new();
    for _ in 0..8 {
        let mut p = s.ws(&r, "phone").await;
        let _ = p.recv().await;
        phones.push(p);
    }
    let msg = json!({"type":"frame","data":b64(&vec![7u8; 60 * 1024])}).to_string();
    let per_phone = 200usize; // 1600 frames, ~130 MB of relay-to-desktop text
    let mut hs = Vec::new();
    for mut p in phones {
        let msg = msg.clone();
        hs.push(tokio::spawn(async move {
            for i in 0..per_phone {
                if i >= 40 {
                    sleep(Duration::from_millis(22)).await;
                }
                if p.ws.send(Message::text(msg.clone())).await.is_err() {
                    break;
                }
            }
            p
        }));
    }
    let mut keep = Vec::new();
    for h in hs {
        keep.push(timeout(Duration::from_secs(30), h).await.expect("phones hung").unwrap());
    }
    // Now drain the desktop.
    let total = 8 * per_phone;
    let mut frames = 0usize;
    let mut close = None;
    loop {
        match timeout(Duration::from_secs(5), d.ws.next()).await {
            Ok(Some(Ok(Message::Text(t)))) => {
                if t.as_str().contains("\"frame\"") {
                    frames += 1;
                }
            }
            Ok(Some(Ok(Message::Close(f)))) => {
                close = Some(f.map(|f| u16::from(f.code)).unwrap_or(1005));
                break;
            }
            Ok(Some(Ok(_))) => {}
            _ => break,
        }
    }
    assert!(
        close == Some(4008) || frames < total,
        "slow desktop received all {frames}/{total} frames (~{} MB queued in relay memory), close={close:?}",
        frames * 80 / 1000
    );
}

#[tokio::test]
async fn resource_never_polled_sessions_expire_and_free_slots() {
    let s = Srv::start_with(|c| {
        lenient(c);
        c.idle = Duration::from_millis(800);
    })
    .await;
    let r = s.room().await;
    let mut d = s.ws(&r, "desktop").await;
    for i in 0..8 {
        assert_eq!(s.send(&r, "phone", &format!("ghost-{i:04}"), json!({"data":"AA=="})).await.0, 200);
    }
    assert_eq!(s.send(&r, "phone", "ghost-0009", json!({"data":"AA=="})).await.0, 429);
    let mut left = 0;
    let end = Instant::now() + Duration::from_secs(6);
    while left < 8 && Instant::now() < end {
        // keep the desktop alive
        d.ws.send(Message::text("ping")).await.unwrap();
        if let Ok(Some(Ok(Message::Text(t)))) = timeout(Duration::from_millis(300), d.ws.next()).await {
            if t.as_str().contains("peer_left") {
                left += 1;
            }
        }
    }
    assert_eq!(left, 8, "ghost sessions were not swept");
    assert_eq!(s.send(&r, "phone", "ghost-0009", json!({"data":"AA=="})).await.0, 200);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn resource_unpolled_desktop_session_overflows_with_4008() {
    let s = Srv::start_with(lenient).await;
    let r = s.room().await;
    assert_eq!(s.send(&r, "desktop", "desk-sess-1", json!({"frames":[]})).await.0, 200);
    let mut phones = Vec::new();
    for _ in 0..8 {
        let mut p = s.ws(&r, "phone").await;
        assert_eq!(p.recv().await["present"], true);
        phones.push(p);
    }
    let mut hs = Vec::new();
    for mut p in phones {
        hs.push(tokio::spawn(async move {
            for i in 0..130 {
                if i >= 40 {
                    sleep(Duration::from_millis(22)).await;
                }
                let _ = p.ws.send(Message::text(r#"{"type":"frame","data":"AA=="}"#)).await;
            }
            p
        }));
    }
    let mut keep = Vec::new();
    for h in hs {
        keep.push(timeout(Duration::from_secs(20), h).await.unwrap().unwrap());
    }
    let (st, v) = s.poll_q(&r, "role=desktop&session=desk-sess-1&cursor=0").await;
    assert_eq!(st, 200);
    assert!(v["events"].as_array().unwrap().len() <= 1001, "queue exceeded bound: {}", v["events"].as_array().unwrap().len());
    assert_eq!(v["closed"]["code"], 4008, "{:?}", v.get("closed"));
    // Phones saw the desktop leave.
    let p0 = &mut keep[0];
    let mut saw = false;
    for _ in 0..5 {
        let m = p0.recv().await;
        if m["type"] == "desktop_present" && m["present"] == false {
            saw = true;
            break;
        }
    }
    assert!(saw);
}

#[tokio::test]
async fn resource_cursor_and_session_manipulation() {
    let s = Srv::start_with(|c| {
        lenient(c);
        c.poll_hold = Duration::from_millis(200);
    })
    .await;
    let r = s.room().await;
    let (st, v) = s.poll_q(&r, "role=phone&session=sess-jjjj&cursor=0").await;
    assert_eq!(st, 200);
    let cur = v["cursor"].as_u64().unwrap();
    for c in ["-1", "abc", "1e3", "18446744073709551616", "99999999999999999999999", " 1", "0x1", &(cur + 1).to_string()] {
        let (st, _) = s.poll_q(&r, &format!("role=phone&session=sess-jjjj&cursor={c}")).await;
        assert_eq!(st, 400, "cursor {c:?}");
    }
    assert_eq!(s.poll_q(&r, "role=phone&session=never-seen&cursor=5").await.0, 410);
    assert_eq!(s.poll_q(&r, "role=phone&session=never-seen&cursor=18446744073709551615").await.0, 410);
    for sess in ["short", &"s".repeat(65), "sess%2F..%2Fx", "sess%00aaaa", "s%C3%A9ssssss", ""] {
        assert_eq!(s.poll_q(&r, &format!("role=phone&session={sess}&cursor=0")).await.0, 400, "session {sess:?}");
    }
    assert_eq!(s.poll_q(&r, "role=phone&cursor=0").await.0, 400);
    // Same session id under the other role.
    assert_eq!(s.poll_q(&r, "role=desktop&session=sess-jjjj&cursor=0").await.0, 400);
    assert_eq!(s.send(&r, "desktop", "sess-jjjj", json!({"frames":[]})).await.0, 400);
}

/// An unauthenticated client must not be able to make the relay buffer a
/// multi-megabyte body: a request without credentials should be answered
/// 401 from its headers alone (axum's Bytes extractor reads the whole body,
/// up to 96 KiB * 60 = 5.76 MB, before the handler checks auth).
#[tokio::test]
async fn resource_unauthenticated_large_body_rejected_before_buffering() {
    let s = Srv::start_with(lenient).await;
    let r = s.room().await;
    let send = format!(
        "POST /v1/rooms/{}/send?role=phone&session=sess-kkkk HTTP/1.1\r\nHost: x\r\nContent-Type: application/json\r\nContent-Length: 5000000\r\n\r\n{{\"frames\":[",
        r.id
    );
    let resp = raw_http(s.addr, send.as_bytes(), Duration::from_secs(3)).await;
    assert!(resp.starts_with("HTTP/1.1 401"), "unauthenticated /send with 5 MB declared body: got {resp:?} within 3 s");
    let put = format!(
        "PUT /v1/rooms/{} HTTP/1.1\r\nHost: x\r\nContent-Type: application/json\r\nContent-Length: 5000000\r\n\r\n{{\"secret_hash\":\"",
        rnd(16)
    );
    let resp = raw_http(s.addr, put.as_bytes(), Duration::from_secs(3)).await;
    assert!(resp.starts_with("HTTP/1.1 401"), "PUT without owner token, 5 MB declared body: got {resp:?} within 3 s");
}

#[tokio::test]
async fn resource_oversized_body_is_413() {
    let s = Srv::start_with(lenient).await;
    let r = s.room().await;
    let a = format!("Bearer {}", r.secret);
    let body = vec![b' '; 7 * 1024 * 1024];
    let (st, _) = s.send_raw(&r, "phone", "sess-llll", Some(&a), body).await;
    assert_eq!(st, 413);
}

/// Slowloris: a connection that sends a partial request line and headers and
/// then stalls must be closed eventually (hyper's 30 s header-read timeout
/// only applies when a timer is configured; axum::serve sets none).
#[tokio::test]
async fn resource_slowloris_partial_headers_are_timed_out() {
    let s = Srv::start().await;
    let mut c = TcpStream::connect(s.addr).await.unwrap();
    c.write_all(b"GET /v1/health HTTP/1.1\r\nHost: x\r\nX-Slow: a").await.unwrap();
    sleep(Duration::from_secs(40)).await;
    let mut buf = [0u8; 256];
    let r = timeout(Duration::from_secs(2), c.read(&mut buf)).await;
    let closed = matches!(r, Ok(Ok(0)) | Ok(Err(_))) || matches!(r, Ok(Ok(n)) if buf[..n].starts_with(b"HTTP/1.1 408"));
    assert!(closed, "half-open request still held open after 40 s ({r:?})");
}

#[tokio::test]
async fn info_no_global_room_cap_owner_can_create_many_rooms_via_spoofed_ip() {
    let s = Srv::start().await;
    let t0 = Instant::now();
    let mut created = 0;
    for i in 0..300 {
        let ip = format!("10.9.{}.1", i / 10); // 10 rooms per spoofed IP
        if s.put(&rnd(16), &hash_of("x"), Some(OWNER), Some(&ip)).await == 201 {
            created += 1;
        }
    }
    eprintln!("created {created} rooms in {:?}", t0.elapsed());
    assert_eq!(created, 300, "per-IP create limit is keyed on the spoofable header");
}

// ======================================================================
// Protocol confusion
// ======================================================================

#[tokio::test]
async fn protocol_malformed_messages_close_1008_without_crash() {
    let s = Srv::start_with(lenient).await;
    let r = s.room().await;
    let nested = format!("{}{}", "[".repeat(40_000), "]".repeat(40_000));
    let cases: Vec<(&str, Message)> = vec![
        ("not json", Message::text("not json")),
        ("empty", Message::text("")),
        ("array", Message::text("[]")),
        ("null", Message::text("null")),
        ("hello", Message::text(r#"{"type":"hello"}"#)),
        ("no data", Message::text(r#"{"type":"frame","to":"x"}"#)),
        ("data int", Message::text(r#"{"type":"frame","to":"x","data":5}"#)),
        ("bad b64", Message::text(r#"{"type":"frame","to":"x","data":"!!!"}"#)),
        ("urlsafe b64", Message::text(r#"{"type":"frame","to":"x","data":"-_-_"}"#)),
        ("b64 whitespace", Message::text(r#"{"type":"frame","to":"x","data":"AA AA"}"#)),
        ("no to", Message::text(r#"{"type":"frame","data":"AA=="}"#)),
        ("to int", Message::text(r#"{"type":"frame","to":7,"data":"AA=="}"#)),
        ("to null", Message::text(r#"{"type":"frame","to":null,"data":"AA=="}"#)),
        ("binary ping", Message::binary(b"ping".to_vec())),
        ("PING", Message::text("PING")),
        ("invalid utf8 binary", Message::binary(vec![0xff, 0xfe, 0x7b, 0x7d])),
        ("deep nesting", Message::text(nested)),
        ("type case", Message::text(r#"{"type":"FRAME","to":"x","data":"AA=="}"#)),
    ];
    for (name, m) in cases {
        let mut d = s.ws(&r, "desktop").await;
        d.ws.send(m).await.unwrap();
        let code = d.recv_close().await;
        assert_eq!(code, 1008, "case {name}");
    }
    // Binary JSON frame and text ping are fine.
    let mut d = s.ws(&r, "desktop").await;
    d.ws.send(Message::text("ping")).await.unwrap();
    assert_eq!(d.recv().await, json!("pong"));
    d.ws.send(Message::binary(br#"{"type":"frame","to":"nobody","data":"AA=="}"#.to_vec())).await.unwrap();
    d.expect_silence(300).await;
    assert_eq!(s.http.get(s.url("/v1/health")).send().await.unwrap().status(), 200);
}

#[tokio::test]
async fn protocol_client_close_codes_and_ping_flood() {
    let s = Srv::start_with(lenient).await;
    let r = s.room().await;
    let mut d = s.ws(&r, "desktop").await;
    for code in [4001u16, 4003, 1000, 1009, 3999] {
        let mut p = s.ws(&r, "phone").await;
        let _ = p.recv().await;
        let id = d.recv().await["conn_id"].as_str().unwrap().to_owned();
        let _ = p
            .ws
            .send(Message::Close(Some(tokio_tungstenite::tungstenite::protocol::CloseFrame {
                code: code.into(),
                reason: "bye".into(),
            })))
            .await;
        let m = d.recv().await;
        assert_eq!(m["type"], "peer_left", "close {code}");
        assert_eq!(m["conn_id"], id.as_str());
    }
    // WebSocket control-frame ping flood: no crash, connection still works.
    let mut p = s.ws(&r, "phone").await;
    let _ = p.recv().await;
    let _ = d.recv().await;
    for _ in 0..5000 {
        p.ws.send(Message::Ping(vec![1u8; 125].into())).await.unwrap();
    }
    p.ws.send(Message::text(r#"{"type":"frame","data":"AA=="}"#)).await.unwrap();
    assert_eq!(d.recv().await["data"], "AA==");
}

static WS_TASK_PANICS: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

fn install_panic_counter() {
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| {
        let prev = std::panic::take_hook();
        std::panic::set_hook(Box::new(move |info| {
            let msg = info
                .payload()
                .downcast_ref::<&str>()
                .map(|s| s.to_string())
                .or_else(|| info.payload().downcast_ref::<String>().cloned())
                .unwrap_or_default();
            if msg.contains("JoinHandle polled after completion") {
                WS_TASK_PANICS.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            }
            prev(info);
        }));
    });
}

/// The relay's per-connection task must not panic when a connection is ended
/// from the room side (desktop replaced -> 4001, room deleted -> 4003): the
/// writer task finishes first and `ws_task` then polls its finished JoinHandle
/// again (`timeout(.., &mut writer)` after `select!` already completed it).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn protocol_server_side_close_does_not_panic_connection_task() {
    install_panic_counter();
    let s = Srv::start_with(lenient).await;
    let r = s.room().await;
    let mut olds = Vec::new();
    for _ in 0..20 {
        olds.push(s.ws(&r, "desktop").await); // each replaces the previous (4001)
    }
    let mut p = s.ws(&r, "phone").await;
    let _ = p.recv().await;
    let st = s
        .http
        .delete(s.url(&format!("/v1/rooms/{}", r.id)))
        .header("X-VQ-Owner", OWNER)
        .header("Authorization", format!("Bearer {}", r.secret))
        .send()
        .await
        .unwrap()
        .status();
    assert_eq!(st.as_u16(), 204);
    assert_eq!(p.recv_close().await, 4003);
    sleep(Duration::from_millis(1500)).await;
    let n = WS_TASK_PANICS.load(std::sync::atomic::Ordering::SeqCst);
    assert_eq!(n, 0, "{n} relay connection tasks panicked with 'JoinHandle polled after completion'");
}

// ======================================================================
// Persistence
// ======================================================================

#[tokio::test]
async fn persistence_corrupt_store_fails_closed_and_is_not_overwritten() {
    let cases: [&[u8]; 6] = [
        b"",
        b"{",
        b"{\"rooms\":{\"aaaaaaaaaaaaaaaa\":{\"secret_hash\":\"",
        b"\0\0\0\0",
        b"null",
        b"{\"rooms\":[]}",
    ];
    for c in cases {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("rooms.json");
        std::fs::write(&p, c).unwrap();
        let res = vq_relay::build_app(Config::new(OWNER.into(), dir.path().to_owned()));
        assert!(res.is_err(), "corrupt store {:?} was accepted", String::from_utf8_lossy(c));
        assert_eq!(std::fs::read(&p).unwrap(), c, "corrupt store was modified");
    }
}

#[tokio::test]
async fn persistence_bad_hash_entries_never_authenticate() {
    let dir = tempfile::tempdir().unwrap();
    let store = json!({"rooms": {
        "emptyhashroom000": {"secret_hash": "", "created_at": 0},
        "garbagehashroom0": {"secret_hash": "!!!not-base64!!!", "created_at": 0},
        "shorthashroom000": {"secret_hash": "AAAA", "created_at": 0},
    }});
    std::fs::write(dir.path().join("rooms.json"), store.to_string()).unwrap();
    // Leftover temp file from a crashed write is ignored.
    std::fs::write(dir.path().join("rooms.json.tmp"), b"{garbage").unwrap();
    let s = Srv::start_at(dir.path(), lenient).await;
    for id in ["emptyhashroom000", "garbagehashroom0", "shorthashroom000"] {
        for auth in [None, Some("Bearer "), Some("Bearer x"), Some("Bearer AAAA")] {
            let mut h: Vec<(&str, &[u8])> = Vec::new();
            if let Some(a) = auth {
                h.push(("Authorization", a.as_bytes()));
            }
            assert_eq!(s.ws_raw(&format!("/v1/rooms/{id}/ws?role=desktop"), &h).await.err(), Some(401), "{id} {auth:?}");
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn persistence_concurrent_creates_all_survive_restart() {
    let dir = tempfile::tempdir().unwrap();
    let s = std::sync::Arc::new(Srv::start_at(dir.path(), lenient).await);
    let ids: Vec<String> = (0..60).map(|_| rnd(16)).collect();
    let mut hs = Vec::new();
    for id in ids.clone() {
        let s = s.clone();
        hs.push(tokio::spawn(async move { s.put(&id, &hash_of(&id), Some(OWNER), None).await }));
    }
    // And a contested id with different hashes.
    let contested = rnd(16);
    let mut cs = Vec::new();
    for i in 0..20 {
        let s = s.clone();
        let c = contested.clone();
        cs.push(tokio::spawn(async move { (i, s.put(&c, &hash_of(&format!("h{i}")), Some(OWNER), None).await) }));
    }
    for h in hs {
        assert_eq!(h.await.unwrap(), 201);
    }
    let mut winners = Vec::new();
    for c in cs {
        let (i, st) = c.await.unwrap();
        assert!(st == 201 || st == 409, "contested -> {st}");
        if st == 201 {
            winners.push(i);
        }
    }
    assert_eq!(winners.len(), 1);
    drop(s);
    sleep(Duration::from_millis(100)).await;
    let s2 = Srv::start_at(dir.path(), lenient).await;
    for id in &ids {
        assert_eq!(s2.put(id, &hash_of(id), Some(OWNER), None).await, 200, "room lost after restart");
    }
    assert_eq!(s2.put(&contested, &hash_of(&format!("h{}", winners[0])), Some(OWNER), None).await, 200);
}

/// DELETE must not report success (204) for a deletion that was not
/// persisted: otherwise the deleted room (and its secret) comes back after a
/// restart.
#[cfg(unix)]
#[tokio::test]
async fn persistence_delete_that_fails_to_persist_must_not_resurrect() {
    use std::os::unix::fs::PermissionsExt;
    let outer = tempfile::tempdir().unwrap();
    let data: PathBuf = outer.path().join("data");
    let s = Srv::start_at(&data, lenient).await;
    let r = s.room().await;
    std::fs::set_permissions(&data, std::fs::Permissions::from_mode(0o500)).unwrap();
    let st = s
        .http
        .delete(s.url(&format!("/v1/rooms/{}", r.id)))
        .header("X-VQ-Owner", OWNER)
        .header("Authorization", format!("Bearer {}", r.secret))
        .send()
        .await
        .unwrap()
        .status()
        .as_u16();
    std::fs::set_permissions(&data, std::fs::Permissions::from_mode(0o700)).unwrap();
    drop(s);
    sleep(Duration::from_millis(100)).await;
    let s2 = Srv::start_at(&data, lenient).await;
    let a = format!("Bearer {}", r.secret);
    let back = s2.ws_raw(&format!("/v1/rooms/{}/ws?role=phone", r.id), &[("Authorization", a.as_bytes())]).await;
    if st == 204 {
        assert_eq!(back.err(), Some(404), "DELETE answered 204 but the room (and old secret) works after restart");
    } else {
        assert!(st >= 500, "unexpected status {st}");
    }
}
