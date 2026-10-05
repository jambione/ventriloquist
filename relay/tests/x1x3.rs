//! SPEC_V3 R5 rulings X1 (separate desktop secret) and X3 (relay hardening).

use std::net::SocketAddr;
use std::time::Duration;

use base64::Engine;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use vq_relay::room::*;
use vq_relay::Config;

const OWNER: &str = "test-owner-token";

fn h(secret: &str) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(Sha256::digest(secret.as_bytes()))
}
fn rid(tag: &str) -> String {
    format!("room-{tag}-0123456789")
}

struct Srv {
    addr: SocketAddr,
    task: tokio::task::JoinHandle<()>,
    http: reqwest::Client,
}
impl Drop for Srv {
    fn drop(&mut self) {
        self.task.abort();
    }
}
impl Srv {
    async fn start(dir: &std::path::Path) -> Srv {
        let mut cfg = Config::new(OWNER.into(), dir.to_owned());
        cfg.create_limit = 1000;
        cfg.auth_fail_limit = 1000;
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap();
        let task = tokio::spawn(async move {
            let _ = vq_relay::serve(l, cfg).await;
        });
        Srv { addr, task, http: reqwest::Client::new() }
    }
    async fn put(&self, id: &str, body: Value) -> u16 {
        self.http
            .put(format!("http://{}/v1/rooms/{id}", self.addr))
            .header("X-VQ-Owner", OWNER)
            .json(&body)
            .send()
            .await
            .unwrap()
            .status()
            .as_u16()
    }
    async fn ws(&self, id: &str, role: &str, secret: &str) -> Result<(), u16> {
        let mut req = format!("ws://{}/v1/rooms/{id}/ws?role={role}", self.addr).into_client_request().unwrap();
        req.headers_mut().insert("Authorization", format!("Bearer {secret}").parse().unwrap());
        match tokio_tungstenite::connect_async(req).await {
            Ok(_) => Ok(()),
            Err(tokio_tungstenite::tungstenite::Error::Http(r)) => Err(r.status().as_u16()),
            Err(e) => panic!("{e}"),
        }
    }
    async fn poll(&self, id: &str, role: &str, secret: &str) -> u16 {
        self.http
            .get(format!("http://{}/v1/rooms/{id}/poll?role={role}&session=sess-x1x3-{role}&cursor=0", self.addr))
            .header("Authorization", format!("Bearer {secret}"))
            .timeout(Duration::from_secs(30))
            .send()
            .await
            .unwrap()
            .status()
            .as_u16()
    }
    async fn send(&self, id: &str, role: &str, secret: &str) -> u16 {
        self.http
            .post(format!("http://{}/v1/rooms/{id}/send?role={role}&session=sess-x1x3-{role}", self.addr))
            .header("Authorization", format!("Bearer {secret}"))
            .json(&json!({"frames": []}))
            .send()
            .await
            .unwrap()
            .status()
            .as_u16()
    }
}

#[tokio::test]
async fn x1_desktop_uses_desktop_secret_and_phone_secret_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let s = Srv::start(dir.path()).await;
    let id = rid("a");
    assert_eq!(s.put(&id, json!({"secret_hash": h("room"), "desktop_secret_hash": h("desk")})).await, 201);
    // desktop role: desktop secret works, room (phone) secret does not
    assert_eq!(s.ws(&id, "desktop", "desk").await, Ok(()));
    assert_eq!(s.ws(&id, "desktop", "room").await, Err(401));
    assert_eq!(s.poll(&id, "desktop", "room").await, 401);
    assert_eq!(s.send(&id, "desktop", "room").await, 401);
    assert_eq!(s.send(&id, "desktop", "desk").await, 200);
    // phone role: room secret works, desktop secret does not
    assert_eq!(s.ws(&id, "phone", "room").await, Ok(()));
    assert_eq!(s.ws(&id, "phone", "desk").await, Err(401));
    assert_eq!(s.send(&id, "phone", "desk").await, 401);
    assert_eq!(s.poll(&id, "phone", "desk").await, 401);
}

#[tokio::test]
async fn x1_mismatched_desktop_hash_is_409_and_same_is_200() {
    let dir = tempfile::tempdir().unwrap();
    let s = Srv::start(dir.path()).await;
    let id = rid("b");
    let body = json!({"secret_hash": h("room"), "desktop_secret_hash": h("desk")});
    assert_eq!(s.put(&id, body.clone()).await, 201);
    assert_eq!(s.put(&id, body).await, 200);
    assert_eq!(s.put(&id, json!({"secret_hash": h("room"), "desktop_secret_hash": h("other")})).await, 409);
    assert_eq!(s.put(&id, json!({"secret_hash": h("other"), "desktop_secret_hash": h("desk")})).await, 409);
    // the original desktop secret still works
    assert_eq!(s.ws(&id, "desktop", "desk").await, Ok(()));
    assert_eq!(s.ws(&id, "desktop", "other").await, Err(401));
    // malformed desktop hash
    assert_eq!(s.put(&rid("b2"), json!({"secret_hash": h("room"), "desktop_secret_hash": "nope"})).await, 400);
}

#[tokio::test]
async fn x1_room_without_desktop_hash_refuses_desktop_until_reput_then_persists() {
    let dir = tempfile::tempdir().unwrap();
    let id = rid("c");
    {
        let s = Srv::start(dir.path()).await;
        // an "old" room: only secret_hash
        assert_eq!(s.put(&id, json!({"secret_hash": h("room")})).await, 201);
        for secret in ["room", "desk", ""] {
            assert_eq!(s.ws(&id, "desktop", secret).await, Err(401), "{secret:?}");
        }
        assert_eq!(s.send(&id, "desktop", "room").await, 401);
        assert_eq!(s.ws(&id, "phone", "room").await, Ok(()));
        // migration needs the matching room hash
        assert_eq!(s.put(&id, json!({"secret_hash": h("x"), "desktop_secret_hash": h("desk")})).await, 409);
        assert_eq!(s.ws(&id, "desktop", "desk").await, Err(401));
        // matching hash adds the desktop hash
        assert_eq!(s.put(&id, json!({"secret_hash": h("room"), "desktop_secret_hash": h("desk")})).await, 200);
        assert_eq!(s.ws(&id, "desktop", "desk").await, Ok(()));
        assert_eq!(s.ws(&id, "desktop", "room").await, Err(401));
        // once set it is fixed
        assert_eq!(s.put(&id, json!({"secret_hash": h("room"), "desktop_secret_hash": h("new")})).await, 409);
    }
    // persisted, and a pre-X1 rooms.json (no field) still loads
    let stored = std::fs::read_to_string(dir.path().join("rooms.json")).unwrap();
    assert!(stored.contains(&h("desk")) && !stored.contains("\"desk\""));
    let legacy = format!(r#"{{"rooms":{{"{}":{{"secret_hash":"{}","created_at":1}}}}}}"#, rid("d"), h("room"));
    let dir2 = tempfile::tempdir().unwrap();
    std::fs::write(dir2.path().join("rooms.json"), legacy).unwrap();
    let s2 = Srv::start(dir2.path()).await;
    assert_eq!(s2.ws(&rid("d"), "phone", "room").await, Ok(()));
    assert_eq!(s2.ws(&rid("d"), "desktop", "room").await, Err(401));
    assert_eq!(s2.put(&rid("d"), json!({"secret_hash": h("room"), "desktop_secret_hash": h("desk")})).await, 200);
    assert_eq!(s2.ws(&rid("d"), "desktop", "desk").await, Ok(()));
}

#[tokio::test]
async fn x3_empty_secrets_are_refused() {
    let dir = tempfile::tempdir().unwrap();
    let s = Srv::start(dir.path()).await;
    let empty = h("");
    assert_eq!(s.put(&rid("e1"), json!({"secret_hash": empty})).await, 400);
    assert_eq!(s.put(&rid("e2"), json!({"secret_hash": h("room"), "desktop_secret_hash": empty})).await, 400);
    let id = rid("e3");
    assert_eq!(s.put(&id, json!({"secret_hash": h("room"), "desktop_secret_hash": h("desk")})).await, 201);
    // empty bearer -> 401
    assert_eq!(s.ws(&id, "phone", "").await, Err(401));
    assert_eq!(s.send(&id, "phone", "").await, 401);
    assert_eq!(s.poll(&id, "phone", "").await, 401);
}

#[test]
fn x3_pongs_count_toward_the_bounded_queue() {
    let mut room = Room::default();
    let (tx, mut rx) = tokio::sync::mpsc::channel::<Out>(WS_QUEUE_MESSAGES + 1);
    let id = room.join(Role::Phone, Sink::Ws(tx)).unwrap();
    for _ in 0..WS_QUEUE_MESSAGES * 2 {
        room.push_text(&id, "pong");
    }
    assert_eq!(room.role_of(&id), None, "connection must be terminated on overflow");
    let mut n = 0;
    let mut last = None;
    while let Ok(m) = rx.try_recv() {
        n += 1;
        last = Some(m);
    }
    assert!(n <= WS_QUEUE_MESSAGES + 1);
    assert!(matches!(last, Some(Out::Close(4008, _))), "the close message is delivered after the queue");
}

async fn raw(addr: SocketAddr, req: &[u8], wait: Duration) -> String {
    let mut s = TcpStream::connect(addr).await.unwrap();
    s.write_all(req).await.unwrap();
    let mut out = Vec::new();
    let _ = timeout(wait, async {
        let mut buf = [0u8; 1024];
        loop {
            match s.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    out.extend_from_slice(&buf[..n]);
                    if out.windows(4).any(|w| w == b"\r\n\r\n") {
                        break;
                    }
                }
            }
        }
    })
    .await;
    String::from_utf8_lossy(&out).into_owned()
}

#[tokio::test]
async fn x3_put_body_limit_is_4kib_and_enforced_while_streaming() {
    let dir = tempfile::tempdir().unwrap();
    let s = Srv::start(dir.path()).await;
    // authenticated, declared too large -> 413 without reading
    let req = format!(
        "PUT /v1/rooms/{} HTTP/1.1\r\nHost: x\r\nX-VQ-Owner: {OWNER}\r\nContent-Length: 5000\r\n\r\n",
        rid("f")
    );
    assert!(raw(s.addr, req.as_bytes(), Duration::from_secs(3)).await.starts_with("HTTP/1.1 413"));
    // chunked (no Content-Length) body past the limit -> 413
    let mut req = format!(
        "PUT /v1/rooms/{} HTTP/1.1\r\nHost: x\r\nX-VQ-Owner: {OWNER}\r\nTransfer-Encoding: chunked\r\n\r\n",
        rid("g")
    )
    .into_bytes();
    for _ in 0..3 {
        req.extend_from_slice(format!("{:x}\r\n", 2048).as_bytes());
        req.extend_from_slice(&[b' '; 2048]);
        req.extend_from_slice(b"\r\n");
    }
    assert!(raw(s.addr, &req, Duration::from_secs(3)).await.starts_with("HTTP/1.1 413"));
}

#[tokio::test]
async fn x3_body_read_times_out_after_10_seconds() {
    let dir = tempfile::tempdir().unwrap();
    let s = Srv::start(dir.path()).await;
    // owner token is valid; the body never arrives
    let req = format!(
        "PUT /v1/rooms/{} HTTP/1.1\r\nHost: x\r\nX-VQ-Owner: {OWNER}\r\nContent-Length: 100\r\n\r\n{{\"secret",
        rid("h")
    );
    let t0 = std::time::Instant::now();
    let resp = raw(s.addr, req.as_bytes(), Duration::from_secs(20)).await;
    assert!(resp.starts_with("HTTP/1.1 408"), "{resp:?}");
    assert!(t0.elapsed() < Duration::from_secs(15), "{:?}", t0.elapsed());
}
