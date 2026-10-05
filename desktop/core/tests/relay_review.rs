//! v3 review (relay transport, QR pairing): failing tests for defects found
//! by the R5 reviewer. Each test names the finding it covers in
//! the review findings file.

#![allow(dead_code)]

mod common;
#[cfg(feature = "relay")]
#[path = "relay_transport/mock.rs"]
mod mock;

use common::{FakePhone, Harness};
use vq_host_core::HostCommand;
use vq_host_core::HostEvent;
use vq_protocol::{Inbound, Message};

/// The `c` code of the latest `phone_pairing_qr` event.
fn qr_code(h: &Harness) -> String {
    let uri = h
        .events
        .iter()
        .rev()
        .find_map(|e| match e {
            HostEvent::PhonePairingQr { uri, .. } => Some(uri.clone()),
            _ => None,
        })
        .expect("a QR was shown");
    url::Url::parse(&uri)
        .unwrap()
        .query_pairs()
        .find(|(k, _)| k == "c")
        .map(|(_, v)| v.into_owned())
        .unwrap()
}

fn nth_wrong(code: &str, k: u32) -> String {
    let n: u32 = code.parse().unwrap();
    format!("{:06}", (n + k) % 1_000_000)
}

/// Finding 1 (MAJOR). README §7.3 / SPEC_V3 §5.5: a pairing code is
/// invalidated after 3 failed confirmations (and a global lockout starts).
/// The QR code is reused for every `pair_request` while it is active, but
/// failures are counted per attempt: an attacker holding the room secret
/// (any old QR, any forgotten phone) makes 2 wrong guesses per connection
/// with a fresh `device_id`, disconnects, and repeats. The QR code survives
/// an unlimited number of wrong guesses, and neither `qr_burned` nor the
/// global lockout ever triggers.
#[test]
fn qr_code_failures_accumulate_across_attempts_and_connections() {
    let mut h = Harness::new();
    h.command(HostCommand::StartPhonePairing);
    let code = qr_code(&h);
    let mut guess = 1;
    for i in 0..5 {
        let peer = format!("relay:attacker{i}");
        let mut phone = FakePhone::new("Attacker"); // fresh device_id each time
        h.handshake(&peer, &mut phone, None);
        let f = phone.pair_request();
        h.frames(&peer, f);
        let r = h.deliver_to_phone(&peer, &mut phone);
        if !matches!(r.as_slice(), [Inbound::Plaintext(Message::PairChallenge(_))]) {
            // Refused (rate limit / lockout): the defence worked.
            return;
        }
        for _ in 0..2 {
            let f = phone.pair_confirm(&nth_wrong(&code, guess));
            guess += 1;
            h.frames(&peer, f);
            let _ = h.deliver_to_phone(&peer, &mut phone);
        }
        h.disconnected(&peer);
    }
    // 10 wrong guesses against one 6-digit code.
    assert!(
        h.core.active_qr_code().map(|c| c.to_string()) != Some(code.clone()),
        "the QR code {code} is still accepted after {} wrong confirmations",
        guess - 1
    );
}

/// Finding 2 (MAJOR). On the real (https) relay, the long-poll path goes
/// through reqwest, whose CONNECT tunnel (hyper-util) reports a 407 as
/// "tunnel error: proxy authorization required". That text is classified as
/// `ProxyBlocked`, and in `run()` it overrides the WebSocket's correct
/// `ProxyAuthRequired` (only an `Other` long-poll failure yields to it), so
/// the UI says "proxy blocked" exactly when the proxy wants credentials.
#[cfg(feature = "relay")]
#[test]
fn reqwest_connect_407_is_classified_as_proxy_auth_required() {
    use vq_host_core::events::RelayReason;
    use vq_host_core::transport::relay::classify_error_text;
    let text = "error sending request for url (https://relay.example.com/v1/health): \
                client error (Connect): tunnel error: proxy authorization required";
    assert_eq!(classify_error_text(text), RelayReason::ProxyAuthRequired, "{text}");
}

/// Finding 9 (MINOR). The room secret travels as a bearer token. The
/// store's comment says `http://` is "only for local development" (and
/// vq-host's usage says "http:// allowed for loopback"), but any host is
/// accepted, so a typo'd `http://relay.example.com` sends the room secret
/// in clear text on every request, and the QR carries that URL to phones.
#[test]
fn plaintext_http_relay_url_is_refused_for_non_loopback_hosts() {
    use vq_host_core::relay_room::normalize_relay_url;
    assert!(normalize_relay_url("http://127.0.0.1:8787").is_some());
    assert!(normalize_relay_url("http://localhost:8787").is_some());
    assert!(
        normalize_relay_url("http://relay.jbrasfield.com").is_none(),
        "plaintext http to a public host must be refused"
    );
}

/// Finding 6 (MINOR). In fallback mode the desktop ends its long-poll
/// session every `ws_retry_every` (5 min) to retry the WebSocket, and
/// `close_all` reports every phone as disconnected even when the WebSocket is
/// still blocked. On a network where WebSockets never work (the corporate
/// proxy the spec targets) every phone session is torn down and re-handshaken
/// every 5 minutes. The retry should probe the WebSocket while the long-poll
/// session (and its peers) stays up, as the phone's `RelayClientState` does.
#[cfg(feature = "relay")]
#[tokio::test]
async fn ws_retry_in_fallback_does_not_drop_phones_while_ws_is_still_blocked() {
    use std::collections::HashMap;
    use std::sync::atomic::Ordering;
    use std::sync::Arc;
    use std::time::Duration;

    use tokio::sync::mpsc;
    use tokio_tungstenite::tungstenite::client::IntoClientRequest;
    use tokio_tungstenite::tungstenite::http::HeaderValue;
    use vq_host_core::events::RelayLink;
    use vq_host_core::relay_room::RelayRoomStore;
    use vq_host_core::transport::proxy::NoOsProxy;
    use vq_host_core::transport::relay::{RelayOptions, RelayTransport, Timing};
    use vq_host_core::transport::{Transport, TransportCommand, TransportEvent};

    let m = mock::start().await;
    m.mock.0.ws_blocked.store(true, Ordering::SeqCst);
    let dir = tempfile::tempdir().unwrap();
    let store = Arc::new(RelayRoomStore::load_or_create(dir.path()).unwrap());
    store.set_url(&m.url()).unwrap();
    let timing = Timing {
        backoff_unit: Duration::from_millis(20),
        connect_timeout: Duration::from_secs(2),
        ws_retry_every: Duration::from_millis(800),
        poll_timeout: Duration::from_secs(5),
        write_timeout: Duration::from_secs(2),
        ..Timing::default()
    };
    let env: HashMap<&'static str, String> = HashMap::new();
    let opts = RelayOptions {
        owner_token: Some(mock::OWNER.to_owned()),
        os_proxy: Box::new(NoOsProxy),
        env: Arc::new(move |k| env.get(k).cloned()),
        timing,
    };
    let (transport, _handle) = RelayTransport::new(store.clone(), opts);
    let (cmd, cmd_rx) = mpsc::unbounded_channel();
    let (ev_tx, mut ev) = mpsc::channel(256);
    let task = Box::new(transport).start(cmd_rx, ev_tx);

    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    // Wait for the fallback.
    loop {
        let e = tokio::time::timeout_at(deadline, ev.recv()).await.expect("fallback").expect("open");
        if matches!(e, TransportEvent::Relay(ref s) if s.link == RelayLink::Fallback) {
            break;
        }
    }
    // A phone joins over a WebSocket (unblocked just for it), then the
    // WebSocket is blocked again for every later upgrade.
    let r = store.get();
    let url = format!("ws://{}/v1/rooms/{}/ws?role=phone", m.addr, r.room_id);
    let mut req = url.into_client_request().unwrap();
    req.headers_mut()
        .insert("Authorization", HeaderValue::from_str(&format!("Bearer {}", *r.room_secret)).unwrap());
    m.mock.0.ws_blocked.store(false, Ordering::SeqCst);
    let (_phone, _) = tokio_tungstenite::connect_async(req).await.expect("phone connects");
    m.mock.0.ws_blocked.store(true, Ordering::SeqCst);
    let peer = loop {
        let e = tokio::time::timeout_at(deadline, ev.recv()).await.expect("peer").expect("open");
        if let TransportEvent::Connected { peer, .. } = e {
            break peer;
        }
    };
    // Spend 2 retry intervals with the WebSocket still blocked.
    let watch_until = tokio::time::Instant::now() + Duration::from_millis(2000);
    let mut dropped = false;
    while let Ok(Some(e)) = tokio::time::timeout_at(watch_until, ev.recv()).await {
        if matches!(&e, TransportEvent::Disconnected { peer: p, .. } if *p == peer) {
            dropped = true;
        }
    }
    let _ = cmd.send(TransportCommand::Shutdown);
    let _ = tokio::time::timeout(Duration::from_secs(5), task).await;
    assert!(!dropped, "the phone was disconnected by a WebSocket retry that could not succeed");
}
