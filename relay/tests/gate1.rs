//! SPEC_V3 gate 1: the relay protocol, end to end over real sockets.

use std::net::SocketAddr;
use std::time::{Duration, Instant};

use base64::Engine;
use futures_util::{SinkExt, StreamExt};
use rand::RngCore;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use tokio::net::TcpStream;
use tokio::time::timeout;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
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
    dir: tempfile::TempDir,
    task: tokio::task::JoinHandle<()>,
    http: reqwest::Client,
}

impl Drop for Srv {
    fn drop(&mut self) {
        self.task.abort();
    }
}

struct Room {
    id: String,
    secret: String,
}

impl Srv {
    async fn start() -> Srv {
        Srv::start_with(|_| {}).await
    }
    async fn start_with(f: impl FnOnce(&mut Config)) -> Srv {
        let dir = tempfile::tempdir().unwrap();
        Srv::start_in(dir, f).await
    }
    async fn start_in(dir: tempfile::TempDir, f: impl FnOnce(&mut Config)) -> Srv {
        let mut cfg = Config::new(OWNER.into(), dir.path().to_owned());
        f(&mut cfg);
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap();
        let task = tokio::spawn(async move {
            let _ = vq_relay::serve(l, cfg).await;
        });
        Srv { addr, dir, task, http: reqwest::Client::new() }
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
        let resp = self
            .http
            .put(self.url(&format!("/v1/rooms/{}", r.id)))
            .header("X-VQ-Owner", OWNER)
            .json(&put_body(&r.secret))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status().as_u16(), 201);
        r
    }
    async fn ws_try(&self, r: &Room, role: &str, how: Auth<'_>) -> Result<Ws, u16> {
        let mut req = format!("ws://{}/v1/rooms/{}/ws?role={role}", self.addr, r.id).into_client_request().unwrap();
        match how {
            Auth::Bearer(s) => {
                req.headers_mut().insert("Authorization", format!("Bearer {s}").parse().unwrap());
            }
            Auth::Sub(s) => {
                req.headers_mut().insert("Sec-WebSocket-Protocol", format!("vq.auth.{s}").parse().unwrap());
            }
            Auth::None => {}
        }
        match tokio_tungstenite::connect_async(req).await {
            Ok((ws, resp)) => Ok(Ws { ws, proto: resp.headers().get("Sec-WebSocket-Protocol").map(|v| v.to_str().unwrap().to_owned()) }),
            Err(tokio_tungstenite::tungstenite::Error::Http(resp)) => Err(resp.status().as_u16()),
            Err(e) => panic!("ws connect: {e}"),
        }
    }
    async fn ws(&self, r: &Room, role: &str) -> Ws {
        let secret = if role == "desktop" { dsec(&r.secret) } else { r.secret.clone() };
        self.ws_try(r, role, Auth::Bearer(&secret)).await.unwrap()
    }
    async fn send(&self, r: &Room, role: &str, session: &str, body: Value) -> (u16, Value) {
        let resp = self
            .http
            .post(self.url(&format!("/v1/rooms/{}/send?role={role}&session={session}", r.id)))
            .header("Authorization", format!("Bearer {}", if role == "desktop" { dsec(&r.secret) } else { r.secret.clone() }))
            .json(&body)
            .send()
            .await
            .unwrap();
        let s = resp.status().as_u16();
        (s, resp.json().await.unwrap_or(Value::Null))
    }
    async fn poll(&self, r: &Room, role: &str, session: &str, cursor: u64) -> (u16, Value) {
        let resp = self
            .http
            .get(self.url(&format!("/v1/rooms/{}/poll?role={role}&session={session}&cursor={cursor}", r.id)))
            .header("Authorization", format!("Bearer {}", if role == "desktop" { dsec(&r.secret) } else { r.secret.clone() }))
            .send()
            .await
            .unwrap();
        let s = resp.status().as_u16();
        (s, resp.json().await.unwrap_or(Value::Null))
    }
}

enum Auth<'a> {
    Bearer(&'a str),
    Sub(&'a str),
    None,
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
    async fn recv_close(&mut self) -> u16 {
        loop {
            match timeout(Duration::from_secs(8), self.ws.next()).await.expect("close timeout") {
                Some(Ok(Message::Close(Some(f)))) => return f.code.into(),
                Some(Ok(Message::Text(_) | Message::Ping(_) | Message::Pong(_))) => {}
                other => panic!("expected close, got {other:?}"),
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
    async fn frame(&mut self, to: Option<&str>, data: &[u8]) {
        let mut v = json!({"type":"frame","data":b64(data)});
        if let Some(t) = to {
            v["to"] = json!(t);
        }
        self.send_json(v).await;
    }
}

// ---------------------------------------------------------------- auth

#[tokio::test]
async fn health() {
    let s = Srv::start().await;
    let r = s.http.get(s.url("/v1/health")).send().await.unwrap();
    assert_eq!(r.status(), 200);
    assert_eq!(r.text().await.unwrap(), "ok");
}

#[tokio::test]
async fn owner_token_and_room_create_claim() {
    let s = Srv::start().await;
    let id = rnd(16);
    let h = hash_of("secret-one");
    assert_eq!(s.put(&id, &h, None, None).await, 401);
    assert_eq!(s.put(&id, &h, Some("wrong"), None).await, 401);
    assert_eq!(s.put(&id, &h, Some(OWNER), None).await, 201);
    assert_eq!(s.put(&id, &h, Some(OWNER), None).await, 200, "same hash claims");
    assert_eq!(s.put(&id, &hash_of("other"), Some(OWNER), None).await, 409, "different hash");
    assert_eq!(s.put(&id, &h, Some("wrong"), None).await, 401);
    assert_eq!(s.put(&rnd(16), "not-a-hash", Some(OWNER), None).await, 400);
}

#[tokio::test]
async fn ws_auth_header_subprotocol_and_failures() {
    let s = Srv::start().await;
    let r = s.room().await;
    assert_eq!(s.ws_try(&r, "phone", Auth::None).await.err(), Some(401));
    assert_eq!(s.ws_try(&r, "phone", Auth::Bearer("nope")).await.err(), Some(401));
    assert_eq!(s.ws_try(&r, "phone", Auth::Sub("nope")).await.err(), Some(401));
    let _a = s.ws_try(&r, "phone", Auth::Bearer(&r.secret)).await.unwrap();
    let b = s.ws_try(&r, "phone", Auth::Sub(&r.secret)).await.unwrap();
    assert_eq!(b.proto.as_deref(), Some(format!("vq.auth.{}", r.secret).as_str()));
    // unknown room, bad role
    let ghost = Room { id: rnd(16), secret: r.secret.clone() };
    assert_eq!(s.ws_try(&ghost, "phone", Auth::Bearer(&r.secret)).await.err(), Some(404));
    assert_eq!(s.ws_try(&r, "robot", Auth::Bearer(&r.secret)).await.err(), Some(400));
}

#[tokio::test]
async fn http_endpoints_require_room_secret() {
    let s = Srv::start().await;
    let r = s.room().await;
    let bad = Room { id: r.id.clone(), secret: "wrong".into() };
    assert_eq!(s.send(&bad, "phone", "session-0001", json!({"type":"frame","data":"AA=="})).await.0, 401);
    assert_eq!(s.poll(&bad, "phone", "session-0001", 0).await.0, 401);
}

#[tokio::test]
async fn delete_needs_owner_and_secret_and_closes_connections() {
    let s = Srv::start().await;
    let r = s.room().await;
    let mut d = s.ws(&r, "desktop").await;
    let url = s.url(&format!("/v1/rooms/{}", r.id));
    let st = |o: Option<&str>, sec: &str| {
        let mut q = s.http.delete(&url).header("Authorization", format!("Bearer {sec}"));
        if let Some(o) = o {
            q = q.header("X-VQ-Owner", o);
        }
        q.send()
    };
    assert_eq!(st(None, &r.secret).await.unwrap().status(), 401);
    assert_eq!(st(Some(OWNER), "wrong").await.unwrap().status(), 401);
    assert_eq!(st(Some(OWNER), &r.secret).await.unwrap().status(), 204);
    assert_eq!(d.recv_close().await, 4003);
    assert_eq!(s.ws_try(&r, "phone", Auth::Bearer(&r.secret)).await.err(), Some(404));
    // the id can be claimed afresh
    assert_eq!(s.put(&r.id, &hash_of("new"), Some(OWNER), None).await, 201);
}

#[tokio::test]
async fn rooms_persist_across_restart() {
    let s = Srv::start().await;
    let r = s.room().await;
    let dir = tempfile::tempdir_in(s.dir.path().parent().unwrap()).unwrap();
    std::fs::copy(s.dir.path().join("rooms.json"), dir.path().join("rooms.json")).unwrap();
    drop(s);
    let s2 = Srv::start_in(dir, |_| {}).await;
    assert_eq!(s2.put(&r.id, &hash_of(&r.secret), Some(OWNER), None).await, 200);
    assert_eq!(s2.put(&r.id, &hash_of("x"), Some(OWNER), None).await, 409);
    let _ws = s2.ws(&r, "phone").await;
    // metadata only: the file holds no secrets
    let body = std::fs::read_to_string(s2.dir.path().join("rooms.json")).unwrap();
    assert!(body.contains(&hash_of(&r.secret)) && !body.contains(&r.secret));
}

#[test]
fn secret_comparison() {
    assert!(vq_relay::secrets_equal("abc", "abc"));
    assert!(!vq_relay::secrets_equal("abc", "abd"));
    assert!(!vq_relay::secrets_equal("abc", "abcd"));
}

// ---------------------------------------------------------------- routing and presence

#[tokio::test]
async fn routing_presence_and_to() {
    let s = Srv::start().await;
    let r = s.room().await;
    let mut p1 = s.ws(&r, "phone").await;
    assert_eq!(p1.recv().await, json!({"type":"desktop_present","present":false}));
    let mut d = s.ws(&r, "desktop").await;
    // desktop learns about phones already in the room; phones learn the desktop is present
    let j = d.recv().await;
    assert_eq!(j["type"], "peer_joined");
    let c1 = j["conn_id"].as_str().unwrap().to_owned();
    assert_eq!(p1.recv().await, json!({"type":"desktop_present","present":true}));

    let mut p2 = s.ws(&r, "phone").await;
    assert_eq!(p2.recv().await, json!({"type":"desktop_present","present":true}));
    let j = d.recv().await;
    assert_eq!(j["type"], "peer_joined");
    let c2 = j["conn_id"].as_str().unwrap().to_owned();
    assert_ne!(c1, c2);

    // phone -> desktop, with from; the phone's `to` is ignored
    p1.frame(Some(&c2), b"hello from p1").await;
    let f = d.recv().await;
    assert_eq!(f["type"], "frame");
    assert_eq!(f["from"], c1);
    assert_eq!(f["data"], b64(b"hello from p1"));
    p2.expect_silence(200).await;

    // desktop -> specific phone only
    d.frame(Some(&c2), b"to p2").await;
    let f = p2.recv().await;
    assert_eq!(f["type"], "frame");
    assert_eq!(f["data"], b64(b"to p2"));
    assert!(f["from"].is_string());
    p1.expect_silence(200).await;

    // unknown `to` is dropped without disturbing anyone
    d.frame(Some("deadbeef"), b"x").await;
    d.expect_silence(200).await;

    // a desktop frame without `to` is a bad message
    d.frame(None, b"x").await;
    assert_eq!(d.recv_close().await, 1008);

}

#[tokio::test]
async fn peer_left_and_desktop_left_events() {
    let s = Srv::start().await;
    let r = s.room().await;
    let mut d = s.ws(&r, "desktop").await;
    let mut p = s.ws(&r, "phone").await;
    assert_eq!(p.recv().await["present"], true);
    let cid = d.recv().await["conn_id"].as_str().unwrap().to_owned();
    p.ws.close(None).await.unwrap();
    let j = d.recv().await;
    assert_eq!(j, json!({"type":"peer_left","conn_id":cid}));

    let mut p = s.ws(&r, "phone").await;
    assert_eq!(p.recv().await["present"], true);
    let _ = d.recv().await;
    d.ws.close(None).await.unwrap();
    assert_eq!(p.recv().await, json!({"type":"desktop_present","present":false}));
}

#[tokio::test]
async fn second_desktop_replaces_first() {
    let s = Srv::start().await;
    let r = s.room().await;
    let mut d1 = s.ws(&r, "desktop").await;
    let mut p = s.ws(&r, "phone").await;
    assert_eq!(p.recv().await["present"], true);
    let _ = d1.recv().await;
    let mut d2 = s.ws(&r, "desktop").await;
    assert_eq!(d1.recv_close().await, 4001);
    // phone is told the desktop went away and came back, so it can re-hello
    assert_eq!(p.recv().await["present"], false);
    assert_eq!(p.recv().await["present"], true);
    // new desktop learns about the phone
    let cid = d2.recv().await["conn_id"].as_str().unwrap().to_owned();
    p.frame(None, b"hi").await;
    assert_eq!(d2.recv().await["data"], b64(b"hi"));
    d2.frame(Some(&cid), b"back").await;
    assert_eq!(p.recv().await["data"], b64(b"back"));
}

// ---------------------------------------------------------------- limits

#[tokio::test]
async fn frame_size_limit() {
    let s = Srv::start().await;
    let r = s.room().await;
    let mut d = s.ws(&r, "desktop").await;
    let mut p = s.ws(&r, "phone").await;
    let _ = p.recv().await;
    let _ = d.recv().await;
    p.frame(None, &vec![7u8; 65536]).await;
    assert_eq!(d.recv().await["type"], "frame");
    p.frame(None, &vec![7u8; 65537]).await;
    assert_eq!(p.recv_close().await, 1009);
    // and over HTTP: 413
    let (st, _) = s.send(&r, "phone", "session-size1", json!({"type":"frame","data":b64(&vec![0u8; 65537])})).await;
    assert_eq!(st, 413);
    let (st, _) = s.send(&r, "phone", "session-size1", json!({"type":"frame","data":b64(&vec![0u8; 65536])})).await;
    assert_eq!(st, 200);
}

#[tokio::test]
async fn frame_rate_limit() {
    let s = Srv::start().await;
    let r = s.room().await;
    let mut p = s.ws(&r, "phone").await;
    let mut d = s.ws(&r, "desktop").await;
    let _ = p.recv().await;
    let _ = d.recv().await;
    for _ in 0..80 {
        let _ = p.frame(None, b"x").await;
    }
    assert_eq!(p.recv_close().await, 4029);
    // the desktop is unaffected
    let j = d.recv().await;
    assert!(j["type"] == "frame" || j["type"] == "peer_left");
}

#[tokio::test]
async fn at_most_eight_phones() {
    let s = Srv::start().await;
    let r = s.room().await;
    let mut keep = vec![];
    for _ in 0..7 {
        keep.push(s.ws(&r, "phone").await);
    }
    // the 8th is a long-poll session; the 9th is refused on either transport
    assert_eq!(s.poll(&r, "phone", "session-poll8", 0).await.0, 200);
    assert_eq!(s.ws_try(&r, "phone", Auth::Bearer(&r.secret)).await.err(), Some(429));
    assert_eq!(s.poll(&r, "phone", "session-poll9", 0).await.0, 429);
    drop(keep.pop());
    tokio::time::sleep(Duration::from_millis(200)).await;
    let _ok = s.ws(&r, "phone").await;
    // a desktop is never refused
    let _d = s.ws(&r, "desktop").await;
}

#[tokio::test]
async fn per_ip_failed_auth_limit() {
    let s = Srv::start().await;
    let r = s.room().await;
    let attempt = |ip: &'static str, secret: String| {
        let u = s.url(&format!("/v1/rooms/{}/poll?role=phone&session=session-ip01", r.id));
        let c = s.http.clone();
        async move {
            c.get(u).header("Authorization", format!("Bearer {secret}")).header("CF-Connecting-IP", ip).send().await.unwrap().status().as_u16()
        }
    };
    for _ in 0..10 {
        assert_eq!(attempt("9.9.9.9", "bad".into()).await, 401);
    }
    // blocked, even with the right secret
    assert_eq!(attempt("9.9.9.9", r.secret.clone()).await, 429);
    // other addresses are unaffected
    assert_eq!(attempt("8.8.8.8", "bad".into()).await, 401);
    // bad owner tokens count too
    for _ in 0..10 {
        assert_eq!(s.put(&rnd(16), &hash_of("a"), Some("bad"), Some("7.7.7.7")).await, 401);
    }
    assert_eq!(s.put(&rnd(16), &hash_of("a"), Some(OWNER), Some("7.7.7.7")).await, 429);
}

#[tokio::test]
async fn per_ip_room_creation_limit() {
    let s = Srv::start().await;
    for _ in 0..10 {
        assert_eq!(s.put(&rnd(16), &hash_of("a"), Some(OWNER), Some("5.5.5.5")).await, 201);
    }
    assert_eq!(s.put(&rnd(16), &hash_of("a"), Some(OWNER), Some("5.5.5.5")).await, 429);
    assert_eq!(s.put(&rnd(16), &hash_of("a"), Some(OWNER), Some("6.6.6.6")).await, 201);
}

// ---------------------------------------------------------------- long-poll

#[tokio::test]
async fn long_poll_send_poll_and_cursors() {
    let s = Srv::start_with(|c| c.poll_hold = Duration::from_millis(300)).await;
    let r = s.room().await;
    let mut d = s.ws(&r, "desktop").await;
    let sess = "session-cursor";
    let (st, j) = s.poll(&r, "phone", sess, 0).await;
    assert_eq!(st, 200);
    assert_eq!(j["events"], json!([{"type":"desktop_present","present":true}]));
    assert_eq!(j["cursor"], 1);
    let cid = j["conn_id"].as_str().unwrap().to_owned();
    assert_eq!(d.recv().await, json!({"type":"peer_joined","conn_id":cid}));

    // nothing pending: empty after the hold, cursor unchanged
    let (_, j) = s.poll(&r, "phone", sess, 1).await;
    assert_eq!(j["events"], json!([]));
    assert_eq!(j["cursor"], 1);

    // phone -> desktop via POST send, then desktop -> phone via WS
    let (st, j) = s.send(&r, "phone", sess, json!({"frames":[{"to":"ignored","data":b64(b"a")},{"data":b64(b"b")}]})).await;
    assert_eq!((st, &j["accepted"]), (200, &json!(2)));
    let f1 = d.recv().await;
    let f2 = d.recv().await;
    assert_eq!((f1["from"].as_str(), f1["data"].as_str()), (Some(cid.as_str()), Some(b64(b"a").as_str())));
    assert_eq!(f2["data"], b64(b"b"));
    d.frame(Some(&cid), b"one").await;
    d.frame(Some(&cid), b"two").await;
    tokio::time::sleep(Duration::from_millis(100)).await;
    let (_, j) = s.poll(&r, "phone", sess, 1).await;
    let ev = j["events"].as_array().unwrap();
    assert_eq!(ev.len(), 2);
    assert_eq!(ev[0]["data"], b64(b"one"));
    assert_eq!(ev[1]["data"], b64(b"two"));
    assert_eq!(j["cursor"], 3);
    // not acked yet: the same cursor redelivers (lost-response safety)
    let (_, j2) = s.poll(&r, "phone", sess, 1).await;
    assert_eq!(j2["events"], j["events"]);
    // acking part of it drops only those
    let (_, j3) = s.poll(&r, "phone", sess, 2).await;
    assert_eq!(j3["events"].as_array().unwrap().len(), 1);
    assert_eq!(j3["events"][0]["data"], b64(b"two"));
    let (_, j4) = s.poll(&r, "phone", sess, 3).await;
    assert_eq!(j4["events"], json!([]));
    // a cursor from the future is rejected
    assert_eq!(s.poll(&r, "phone", sess, 99).await.0, 400);
    // an unknown session with a nonzero cursor is gone (client must start over)
    assert_eq!(s.poll(&r, "phone", "session-unknown", 5).await.0, 410);
    // role mismatch on an existing session
    assert_eq!(s.poll(&r, "desktop", sess, 0).await.0, 400);
}

#[tokio::test]
async fn long_poll_holds_25_seconds_and_wakes_early() {
    let s = Srv::start().await; // default hold: 25 s
    let r = s.room().await;
    let _d = s.ws(&r, "desktop").await;
    let sess = "session-hold01";
    let (_, j) = s.poll(&r, "phone", sess, 0).await;
    let cid = j["conn_id"].as_str().unwrap().to_owned();

    // early wake: a frame arrives while the poll is held
    let (rr, ss, cc) = (Room { id: r.id.clone(), secret: r.secret.clone() }, s.addr, cid.clone());
    let http = s.http.clone();
    let _ = (ss, &cc, &http, &rr);
    let t0 = Instant::now();
    let poll = s.poll(&r, "phone", sess, 1);
    let waker = async {
        tokio::time::sleep(Duration::from_millis(500)).await;
        let mut d = s.ws(&r, "desktop").await; // replaces; phones see false/true
        let _ = d.recv().await;
        d.frame(Some(&cid), b"wake").await;
        tokio::time::sleep(Duration::from_secs(1)).await;
    };
    let ((_, j), _) = tokio::join!(poll, waker);
    assert!(t0.elapsed() < Duration::from_secs(10), "woken early");
    assert!(!j["events"].as_array().unwrap().is_empty());

    // full hold: nothing arrives, so the poll returns empty after about 25 s
    let cursor = j["cursor"].as_u64().unwrap();
    let (_, j) = s.poll(&r, "phone", sess, cursor).await;
    let cursor = j["cursor"].as_u64().unwrap();
    let t0 = Instant::now();
    let (st, j) = s.poll(&r, "phone", sess, cursor).await;
    let el = t0.elapsed();
    assert_eq!(st, 200);
    assert_eq!(j["events"], json!([]));
    assert!(el >= Duration::from_millis(24_500) && el < Duration::from_secs(29), "held {el:?}");
}

#[tokio::test]
async fn ws_and_long_poll_interoperate_both_ways() {
    let s = Srv::start_with(|c| c.poll_hold = Duration::from_millis(500)).await;
    let r = s.room().await;

    // WS phone <-> long-poll desktop
    let mut p = s.ws(&r, "phone").await;
    assert_eq!(p.recv().await["present"], false);
    let (_, j) = s.poll(&r, "desktop", "session-desk01", 0).await;
    assert_eq!(p.recv().await["present"], true);
    let ev = j["events"].as_array().unwrap();
    assert_eq!(ev.len(), 1);
    assert_eq!(ev[0]["type"], "peer_joined");
    let pid = ev[0]["conn_id"].as_str().unwrap().to_owned();
    let did = j["conn_id"].as_str().unwrap().to_owned();
    let (st, _) = s.send(&r, "desktop", "session-desk01", json!({"type":"frame","to":pid,"data":b64(b"d2p")})).await;
    assert_eq!(st, 200);
    let f = p.recv().await;
    assert_eq!((f["from"].as_str(), f["data"].as_str()), (Some(did.as_str()), Some(b64(b"d2p").as_str())));
    p.frame(None, b"p2d").await;
    let (_, j) = s.poll(&r, "desktop", "session-desk01", 1).await;
    assert_eq!(j["events"][0]["data"], b64(b"p2d"));
    assert_eq!(j["events"][0]["from"], pid);
    // phone leaves -> long-poll desktop gets peer_left
    drop(p);
    let (_, j) = s.poll(&r, "desktop", "session-desk01", 2).await;
    assert_eq!(j["events"][0], json!({"type":"peer_left","conn_id":pid}));

    // a WS desktop replaces the long-poll desktop: its poll reports close 4001
    let mut d = s.ws(&r, "desktop").await;
    let (st, j) = s.poll(&r, "desktop", "session-desk01", 3).await;
    assert_eq!(st, 200);
    assert_eq!(j["closed"], json!({"code":4001,"reason":"replaced"}));
    // the session is gone afterwards
    assert_eq!(s.poll(&r, "desktop", "session-desk01", 3).await.0, 410);
    // the long-poll phone and WS desktop talk
    let (_, j) = s.poll(&r, "phone", "session-phn001", 0).await;
    let cid = j["conn_id"].as_str().unwrap().to_owned();
    assert_eq!(d.recv().await["conn_id"], cid);
}

// ---------------------------------------------------------------- idle

#[tokio::test]
async fn idle_websocket_is_closed_and_ping_keeps_it_alive() {
    let s = Srv::start_with(|c| {
        c.idle = Duration::from_millis(1200);
        c.ping_interval = Duration::from_secs(100);
    })
    .await;
    let r = s.room().await;
    let mut d = s.ws(&r, "desktop").await;
    let mut lazy = s.ws(&r, "phone").await;
    let mut alive = s.ws(&r, "phone").await;
    let _ = lazy.recv().await;
    let _ = alive.recv().await;
    let _ = d.recv().await;
    let _ = d.recv().await;
    // `alive` pings every 400 ms for ~2.4 s; `lazy` stays silent and is closed
    for _ in 0..6 {
        alive.ws.send(Message::text("ping")).await.unwrap();
        d.ws.send(Message::text("ping")).await.unwrap();
        tokio::time::sleep(Duration::from_millis(400)).await;
    }
    assert_eq!(lazy.recv_close().await, 4002);
    let mut left = 0;
    while let Ok(j) = timeout(Duration::from_millis(300), d.recv_value()).await {
        if j.is_null() {
            break;
        }
        if j["type"] == "peer_left" {
            left += 1;
        }
    }
    assert_eq!(left, 1, "only the idle phone was dropped");
    assert_eq!(alive.recv().await, json!("pong"));
}

impl Ws {
    async fn recv_value(&mut self) -> Value {
        loop {
            match self.ws.next().await {
                Some(Ok(Message::Text(t))) => return serde_json::from_str(t.as_str()).unwrap_or(json!(t.as_str())),
                Some(Ok(_)) => {}
                _ => return Value::Null,
            }
        }
    }
}

#[tokio::test]
async fn idle_poll_session_expires() {
    let s = Srv::start_with(|c| {
        c.idle = Duration::from_millis(800);
        c.poll_hold = Duration::from_millis(100);
    })
    .await;
    let r = s.room().await;
    let mut d = s.ws(&r, "desktop").await;
    let (_, j) = s.poll(&r, "phone", "session-idle01", 0).await;
    let cid = j["conn_id"].as_str().unwrap().to_owned();
    assert_eq!(d.recv().await["conn_id"], cid);
    // stays alive while it keeps polling
    for _ in 0..4 {
        tokio::time::sleep(Duration::from_millis(300)).await;
        assert_eq!(s.poll(&r, "phone", "session-idle01", 1).await.0, 200);
        d.ws.send(Message::text("ping")).await.unwrap();
    }
    assert_eq!(d.recv().await, json!("pong"));
    // stop polling: the desktop sees it leave, and the session is gone
    for _ in 0..4 {
        d.ws.send(Message::text("ping")).await.unwrap();
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    assert_eq!(d.recv().await, json!("pong"));
    let mut left = false;
    while !left {
        left = d.recv().await == json!({"type":"peer_left","conn_id":cid});
    }
    assert_eq!(s.poll(&r, "phone", "session-idle01", 1).await.0, 410);
}

#[test]
fn spec_defaults() {
    let c = Config::new("t".into(), ".".into());
    assert_eq!(c.idle, Duration::from_secs(60));
    assert_eq!(c.poll_hold, Duration::from_secs(25));
    assert_eq!(c.ping_interval, Duration::from_secs(20));
}
