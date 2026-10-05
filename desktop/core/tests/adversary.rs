//! Regression tests for the M3 critic (K*) and adversary (A*) findings.
//! Each test names the finding it covers.

mod common;

use std::sync::Arc;
use std::time::Duration;

use chrono::DateTime;
use common::{acks, wrong_code, FakePhone, Harness};
use uuid::Uuid;
use vq_host_core::events::{HostCommand, HostEvent, PeerState};
use vq_host_core::logger::{LogOutcome, Logger};
use vq_host_core::transcript::MAX_ENTRIES;
use vq_host_core::{Core, CoreOptions, ManualClock};
use vq_protocol::{Inbound, Message, Utt, UttState};

const P: &str = "peer-1";
const RATE_LIMITED: &str = "rate_limited";
const BUSY: &str = "busy";

fn secure_pair() -> (Harness, FakePhone) {
    let mut h = Harness::new();
    let mut phone = FakePhone::new("Jon's iPhone");
    h.pair(P, &mut phone);
    h.take_events();
    (h, phone)
}

fn error_codes(msgs: &[Inbound]) -> Vec<String> {
    msgs.iter()
        .filter_map(|m| match m {
            Inbound::Plaintext(Message::Error(e)) => Some(e.code.clone()),
            _ => None,
        })
        .collect()
}

fn codes_shown(h: &Harness) -> usize {
    h.events
        .iter()
        .filter(|e| matches!(e, HostEvent::PairingCodeShown { .. }))
        .count()
}

fn event_name(e: &HostEvent) -> String {
    serde_json::to_value(e).unwrap()["event"]
        .as_str()
        .unwrap()
        .to_owned()
}

fn has_challenge(msgs: &[Inbound]) -> bool {
    msgs.iter()
        .any(|m| matches!(m, Inbound::Plaintext(Message::PairChallenge(_))))
}

/// Send a pair_request on `peer`; returns what the desktop answered.
fn pair_request(h: &mut Harness, peer: &str, phone: &mut FakePhone) -> Vec<Inbound> {
    let f = phone.pair_request();
    h.frames(peer, f);
    h.deliver_to_phone(peer, phone)
}

/// Three wrong pair_confirms for the active code.
fn fail_three_times(h: &mut Harness, peer: &str, phone: &mut FakePhone) {
    let code = h.last_code().unwrap();
    for _ in 0..3 {
        let f = phone.pair_confirm(&wrong_code(&code));
        h.frames(peer, f);
        h.deliver_to_phone(peer, phone);
    }
}

// ------------------------------------------------------------------ A3

#[test]
fn a3_retried_final_after_eviction_is_not_reinserted() {
    let (mut h, mut phone) = secure_pair();
    let first = Uuid::new_v4();
    let f = phone.utt(first, 2, UttState::Final, "first");
    h.frames(P, f);
    for _ in 0..MAX_ENTRIES {
        let f = phone.utt(Uuid::new_v4(), 0, UttState::Final, "x");
        h.frames(P, f);
    }
    h.deliver_to_phone(P, &mut phone);
    assert!(h.core.transcript().get(&first).is_none(), "evicted");
    h.take_events();
    // The phone retries the same final (it missed the ack), and a late
    // lower revision arrives too: both are acked, neither comes back.
    let mut f = phone.utt(first, 2, UttState::Final, "first");
    f.extend(phone.utt(first, 1, UttState::Partial, "fir"));
    h.frames(P, f);
    assert_eq!(acks(&h.deliver_to_phone(P, &mut phone)), vec![(first, 2)]);
    assert!(h.upserts().is_empty(), "{:?}", h.upserts());
    assert!(h.core.transcript().get(&first).is_none());
    // A genuinely newer revision is still accepted.
    let f = phone.utt(first, 3, UttState::Edit, "first!");
    h.frames(P, f);
    assert_eq!(h.upserts().len(), 1);
}

// ------------------------------------------------------------------ A4

#[test]
fn a4_redelivery_after_midnight_and_restart_is_not_logged_again() {
    let mut h = Harness::new();
    h.clock
        .set_local(DateTime::parse_from_rfc3339("2026-10-03T23:59:50+02:00").unwrap());
    let mut phone = FakePhone::new("P");
    h.pair(P, &mut phone);
    let id = Uuid::new_v4();
    let f = phone.utt(id, 0, UttState::Final, "late night");
    h.frames(P, f);
    assert!(h.log_dir().join("2026-10-03.md").exists());
    h.disconnected(P);
    h.clock.advance(Duration::from_secs(20)); // 00:00:10 the next day
    h.restart();
    h.handshake("peer-2", &mut phone, None);
    assert!(phone.is_secure());
    let f = phone.utt(id, 0, UttState::Final, "late night");
    h.frames("peer-2", f);
    assert_eq!(
        acks(&h.deliver_to_phone("peer-2", &mut phone)),
        vec![(id, 0)]
    );
    assert!(
        !h.log_dir().join("2026-10-04.md").exists(),
        "re-delivered after midnight: logged twice"
    );
}

// --------------------------------------------------------------- A5 / K4

fn utt(id: Uuid, rev: u32) -> Utt {
    Utt {
        id,
        rev,
        state: UttState::Final,
        text: "x".into(),
        ts: 0,
    }
}

fn at(s: &str) -> chrono::DateTime<chrono::FixedOffset> {
    DateTime::parse_from_rfc3339(s).unwrap()
}

#[test]
fn a5_torn_index_line_does_not_corrupt_the_next_record() {
    let dir = tempfile::tempdir().unwrap();
    let idx_dir = dir.path().join(".vq-index");
    std::fs::create_dir_all(&idx_dir).unwrap();
    // A crash left half a line behind.
    std::fs::write(idx_dir.join("2026-10-03.idx"), b"1a2b3c4d-0000-40").unwrap();
    let t = at("2026-10-03T10:00:00+00:00");
    let b = Uuid::new_v4();
    Logger::new(dir.path().into()).log(&utt(b, 0), "P", t).unwrap();
    let mut l2 = Logger::new(dir.path().into());
    assert_eq!(l2.log(&utt(b, 0), "P", t).unwrap(), LogOutcome::Duplicate);
}

#[test]
fn k4_non_utf8_index_line_is_skipped_not_fatal() {
    let dir = tempfile::tempdir().unwrap();
    let idx_dir = dir.path().join(".vq-index");
    std::fs::create_dir_all(&idx_dir).unwrap();
    let a = Uuid::new_v4();
    let mut bytes = b"\xff\xfe garbage\nnot a line\n".to_vec();
    bytes.extend_from_slice(format!("{} 1\n", a.hyphenated()).as_bytes());
    std::fs::write(idx_dir.join("2026-10-03.idx"), bytes).unwrap();
    let mut l = Logger::new(dir.path().into());
    assert_eq!(
        l.log(&utt(a, 1), "P", at("2026-10-03T10:00:00+00:00"))
            .unwrap(),
        LogOutcome::Duplicate
    );
}

#[cfg(unix)]
#[test]
fn k4_unreadable_index_is_not_cached_as_empty() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().unwrap();
    let idx_dir = dir.path().join(".vq-index");
    std::fs::create_dir_all(&idx_dir).unwrap();
    let a = Uuid::new_v4();
    let idx = idx_dir.join("2026-10-03.idx");
    std::fs::write(&idx, format!("{} 1\n", a.hyphenated())).unwrap();
    std::fs::set_permissions(&idx, std::fs::Permissions::from_mode(0o000)).unwrap();
    if std::fs::read(&idx).is_ok() {
        return; // running as root: permissions are not enforced
    }
    let t = at("2026-10-03T10:00:00+00:00");
    let mut l = Logger::new(dir.path().into());
    // The index cannot be read; the entry is still logged (and the failure
    // reported), but the empty result is not cached for the day.
    let _ = l.log(&utt(Uuid::new_v4(), 0), "P", t);
    std::fs::set_permissions(&idx, std::fs::Permissions::from_mode(0o600)).unwrap();
    assert_eq!(l.log(&utt(a, 1), "P", t).unwrap(), LogOutcome::Duplicate);
}

// --------------------------------------------------------------- A6 / K1

#[test]
fn a6_second_pair_request_within_10s_is_rate_limited() {
    let mut h = Harness::new();
    let mut phone = FakePhone::new("P");
    h.handshake(P, &mut phone, None);
    assert!(has_challenge(&pair_request(&mut h, P, &mut phone)));
    let code = h.last_code().unwrap();
    h.advance(Duration::from_secs(5));
    let m = pair_request(&mut h, P, &mut phone);
    assert_eq!(error_codes(&m), vec![RATE_LIMITED]);
    assert!(!has_challenge(&m));
    assert_eq!(codes_shown(&h), 1, "the modal code is not replaced");
    assert!(h.disconnects.is_empty());
    // The first code still works (the phone kept its first challenge? no:
    // the phone regenerated its request, so pair with a fresh one later).
    let _ = code;
    h.advance(Duration::from_secs(6));
    assert!(has_challenge(&pair_request(&mut h, P, &mut phone)));
    assert_eq!(codes_shown(&h), 2);
}

#[test]
fn a6_six_pair_requests_in_10_minutes_disconnect_and_refuse_the_device() {
    let mut h = Harness::new();
    let mut phone = FakePhone::new("P");
    h.handshake(P, &mut phone, None);
    for _ in 0..5 {
        assert!(has_challenge(&pair_request(&mut h, P, &mut phone)));
        h.advance(Duration::from_secs(11));
    }
    let m = pair_request(&mut h, P, &mut phone);
    assert_eq!(error_codes(&m), vec![RATE_LIMITED]);
    assert_eq!(
        h.disconnects,
        vec![(P.to_owned(), Some(Duration::from_secs(600)))]
    );
    h.disconnected(P);
    // The device is refused on a new connection for 10 minutes.
    h.handshake("peer-2", &mut phone, None);
    let m = h.deliver_to_phone("peer-2", &mut phone);
    assert_eq!(error_codes(&m), vec![RATE_LIMITED]);
    assert_eq!(h.disconnects.len(), 2);
    h.disconnected("peer-2");
    h.advance(Duration::from_secs(600));
    h.handshake("peer-3", &mut phone, None);
    assert!(has_challenge(&pair_request(&mut h, "peer-3", &mut phone)));
}

#[test]
fn a6_pair_requests_do_not_extend_the_idle_timer() {
    let mut h = Harness::new();
    let mut phone = FakePhone::new("P");
    h.handshake(P, &mut phone, None);
    h.advance(Duration::from_secs(10));
    pair_request(&mut h, P, &mut phone); // the first one counts as activity
    for _ in 0..3 {
        h.advance(Duration::from_secs(70));
        pair_request(&mut h, P, &mut phone); // these do not
    }
    h.advance(Duration::from_secs(300 - 210 - 1));
    assert!(h.disconnects.is_empty());
    h.advance(Duration::from_secs(1));
    assert_eq!(h.disconnects.len(), 1, "idle drop 5 min after the first pair_request");
}

#[test]
fn a6_second_phone_gets_busy_while_a_code_is_shown() {
    let mut h = Harness::new();
    let mut a = FakePhone::new("A");
    let mut b = FakePhone::new("B");
    h.handshake(P, &mut a, None);
    h.handshake("peer-2", &mut b, None);
    assert!(has_challenge(&pair_request(&mut h, P, &mut a)));
    let code = h.last_code().unwrap();
    let m = pair_request(&mut h, "peer-2", &mut b);
    assert_eq!(error_codes(&m), vec![BUSY]);
    assert_eq!(codes_shown(&h), 1);
    assert!(h.disconnects.is_empty());
    // A can still finish pairing with the code on screen.
    let f = a.pair_confirm(&code);
    h.frames(P, f);
    let r = h.deliver_to_phone(P, &mut a);
    let [Inbound::Plaintext(Message::PairResult(r))] = r.as_slice() else {
        panic!("{r:?}")
    };
    assert!(a.on_pair_result(r));
}

#[test]
fn k1_global_lockout_after_code_invalidation_doubles_and_resets() {
    let mut h = Harness::new();
    let mut a = FakePhone::new("A");
    let mut b = FakePhone::new("B");
    h.handshake(P, &mut a, None);
    h.handshake("peer-2", &mut b, None);
    // t=0: first code, three wrong guesses -> 30 s lockout.
    assert!(has_challenge(&pair_request(&mut h, P, &mut a)));
    fail_three_times(&mut h, P, &mut a);
    h.advance(Duration::from_secs(11));
    assert_eq!(error_codes(&pair_request(&mut h, P, &mut a)), vec![RATE_LIMITED]);
    // The lockout is global: another phone is refused too.
    h.advance(Duration::from_secs(1));
    assert_eq!(
        error_codes(&pair_request(&mut h, "peer-2", &mut b)),
        vec![RATE_LIMITED]
    );
    // t=31: allowed again; three wrong guesses -> 60 s lockout.
    h.advance(Duration::from_secs(19));
    assert!(has_challenge(&pair_request(&mut h, P, &mut a)));
    fail_three_times(&mut h, P, &mut a);
    h.advance(Duration::from_secs(31));
    assert_eq!(error_codes(&pair_request(&mut h, P, &mut a)), vec![RATE_LIMITED]);
    h.advance(Duration::from_secs(30));
    // t=92: B pairs successfully, which resets the lockout.
    assert!(has_challenge(&pair_request(&mut h, "peer-2", &mut b)));
    let code = h.last_code().unwrap();
    let f = b.pair_confirm(&code);
    h.frames("peer-2", f);
    let r = h.deliver_to_phone("peer-2", &mut b);
    let [Inbound::Plaintext(Message::PairResult(r))] = r.as_slice() else {
        panic!("{r:?}")
    };
    assert!(b.on_pair_result(r));
    h.advance(Duration::from_secs(11));
    assert!(has_challenge(&pair_request(&mut h, P, &mut a)));
    assert!(h.disconnects.is_empty());
}

// ------------------------------------------------------------------ K13

#[test]
fn k13_phone_name_is_sanitized_and_capped() {
    let mut h = Harness::new();
    let evil = format!("\u{202E}Evil\u{1b}[31m\u{7}{}", "x".repeat(100));
    let mut phone = FakePhone::new(&evil);
    h.handshake(P, &mut phone, None);
    pair_request(&mut h, P, &mut phone);
    let names: Vec<String> = h
        .events
        .iter()
        .filter_map(|e| match e {
            HostEvent::ConnectionStatus { name: Some(n), .. } => Some(n.clone()),
            HostEvent::PairingCodeShown { phone_name, .. } => Some(phone_name.clone()),
            _ => None,
        })
        .collect();
    assert!(!names.is_empty());
    for n in names {
        assert!(n.chars().count() <= 64, "{n:?}");
        assert!(
            !n.chars()
                .any(|c| c.is_control() || matches!(c, '\u{202A}'..='\u{202E}')),
            "{n:?}"
        );
        assert!(n.starts_with("Evil[31m"), "{n:?}");
    }
}

// ------------------------------------------------------------------ K20

#[test]
fn k20_keepalive_starts_when_secure_not_at_connect() {
    let mut h = Harness::new();
    let mut phone = FakePhone::new("P");
    h.handshake(P, &mut phone, None);
    h.advance(Duration::from_secs(100)); // a slow user typing the code
    let f = phone.pair_request();
    h.frames(P, f);
    h.deliver_to_phone(P, &mut phone);
    let code = h.last_code().unwrap();
    let f = phone.pair_confirm(&code);
    h.frames(P, f);
    let r = h.deliver_to_phone(P, &mut phone);
    let [Inbound::Plaintext(Message::PairResult(r))] = r.as_slice() else {
        panic!("{r:?}")
    };
    assert!(phone.on_pair_result(r));
    h.advance(Duration::from_secs(1));
    assert!(
        h.deliver_to_phone(P, &mut phone).is_empty(),
        "no ping right after becoming Secure"
    );
    h.advance(Duration::from_secs(14));
    let m = h.deliver_to_phone(P, &mut phone);
    assert!(
        matches!(m.as_slice(), [Inbound::Encrypted(Message::Ping)]),
        "{m:?}"
    );
}

#[test]
fn k20_cap_of_500_through_core_evicts_oldest_after_upsert() {
    let (mut h, mut phone) = secure_pair();
    let ids: Vec<Uuid> = (0..MAX_ENTRIES + 1).map(|_| Uuid::new_v4()).collect();
    for id in &ids {
        let f = phone.utt(*id, 0, UttState::Final, "x");
        h.frames(P, f);
    }
    // `final_accepted` follows from the I/O worker; ignore it here.
    let events: Vec<&HostEvent> = h
        .events
        .iter()
        .filter(|e| !matches!(e, HostEvent::FinalAccepted { .. }))
        .collect();
    let tail: Vec<String> = events.iter().rev().take(2).map(|e| event_name(e)).collect();
    assert_eq!(tail, vec!["entry_evicted", "entry_upserted"]);
    assert!(matches!(events.last(), Some(HostEvent::EntryEvicted { id }) if *id == ids[0]));
    assert_eq!(h.core.transcript().len(), MAX_ENTRIES);
}

#[test]
fn k20_midnight_rollover_through_core_starts_a_new_file() {
    let mut h = Harness::new();
    h.clock
        .set_local(DateTime::parse_from_rfc3339("2026-10-03T23:59:59+02:00").unwrap());
    let mut phone = FakePhone::new("P");
    h.pair(P, &mut phone);
    let f = phone.utt(Uuid::new_v4(), 0, UttState::Final, "before");
    h.frames(P, f);
    h.advance(Duration::from_secs(2));
    let f = phone.utt(Uuid::new_v4(), 0, UttState::Final, "after");
    h.frames(P, f);
    let d1 = std::fs::read_to_string(h.log_dir().join("2026-10-03.md")).unwrap();
    let d2 = std::fs::read_to_string(h.log_dir().join("2026-10-04.md")).unwrap();
    assert!(d1.contains("  before\n") && !d1.contains("after"));
    assert!(d2.starts_with("# Ventriloquist — 2026-10-04\n\n- **00:00:01**"));
    assert!(d2.contains("  after\n"));
}

#[test]
fn k20_log_dir_change_mid_day_honours_that_dirs_index() {
    let (mut h, mut phone) = secure_pair();
    let other = h.dir.path().join("other");
    let id = Uuid::new_v4();
    std::fs::create_dir_all(other.join(".vq-index")).unwrap();
    std::fs::write(
        other.join(".vq-index/2026-10-03.idx"),
        format!("{} 0\n", id.hyphenated()),
    )
    .unwrap();
    h.command(HostCommand::SetLogDir {
        path: other.clone(),
    });
    let f = phone.utt(id, 0, UttState::Final, "already there");
    h.frames(P, f);
    assert_eq!(h.upserts().len(), 1);
    assert!(!other.join("2026-10-03.md").exists());
}

#[test]
fn k20_pairing_store_write_failure_is_not_counted_as_a_failure() {
    let mut h = Harness::new();
    let mut phone = FakePhone::new("P");
    h.handshake(P, &mut phone, None);
    pair_request(&mut h, P, &mut phone);
    let code = h.last_code().unwrap();
    // peers.json cannot be replaced: it is a non-empty directory.
    let blocker = h.config_dir().join("peers.json");
    std::fs::create_dir_all(blocker.join("x")).unwrap();
    let f = phone.pair_confirm(&code);
    h.frames(P, f);
    let r = h.deliver_to_phone(P, &mut phone);
    assert!(matches!(r.as_slice(), [Inbound::Plaintext(Message::PairResult(r))] if !r.ok));
    assert!(h
        .events
        .iter()
        .any(|e| matches!(e, HostEvent::PairingResult { ok: false, attempts_remaining: 3, .. })));
    assert!(h
        .events
        .iter()
        .any(|e| matches!(e, HostEvent::StorageWarning { .. })));
    assert!(h.core.pairing_store().peers().is_empty());
    std::fs::remove_dir_all(&blocker).unwrap();
    let f = phone.pair_confirm(&code);
    h.frames(P, f);
    let r = h.deliver_to_phone(P, &mut phone);
    let [Inbound::Plaintext(Message::PairResult(r))] = r.as_slice() else {
        panic!("{r:?}")
    };
    assert!(phone.on_pair_result(r));
    assert_eq!(h.core.sessions().peer_state(P), Some(PeerState::Secure));
}

fn open_with(dir: &std::path::Path) -> std::io::Result<Core> {
    Core::open(CoreOptions {
        config_dir: dir.join("config"),
        log_dir_override: Some(dir.join("logs")),
        name_override: None,
        clock: Arc::new(ManualClock::new(common::start_time())),
        relay: None,
    })
}

#[test]
fn k20_corrupt_peers_json_is_a_hard_error() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(dir.path().join("config")).unwrap();
    std::fs::write(dir.path().join("config/peers.json"), b"{nope").unwrap();
    assert!(open_with(dir.path()).is_err());
}

#[test]
fn k14_corrupt_config_json_falls_back_to_defaults() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(dir.path().join("config")).unwrap();
    std::fs::write(dir.path().join("config/config.json"), b"{nope").unwrap();
    let core = open_with(dir.path()).expect("a corrupt config.json does not block start-up");
    assert_eq!(core.log_dir(), dir.path().join("logs"));
}

// ------------------------------------------------------------------ K15

#[test]
fn k15_relative_or_empty_log_dir_is_refused() {
    let (mut h, _phone) = secure_pair();
    let before = h.core.log_dir();
    for p in ["", "relative/logs"] {
        h.command(HostCommand::SetLogDir { path: p.into() });
        assert_eq!(h.core.log_dir(), before, "{p:?} accepted");
        assert!(h
            .take_events()
            .iter()
            .any(|e| matches!(e, HostEvent::StorageWarning { .. })));
    }
}

// ------------------------------------------------------------------ K11

#[test]
fn k11_failed_log_append_is_retried_and_recovery_reported() {
    let (mut h, mut phone) = secure_pair();
    let blocker = h.dir.path().join("blocker");
    std::fs::write(&blocker, b"").unwrap();
    h.command(HostCommand::SetLogDir {
        path: blocker.join("logs"),
    });
    let id = Uuid::new_v4();
    let f = phone.utt(id, 0, UttState::Final, "keep me");
    h.frames(P, f);
    assert!(h
        .events
        .iter()
        .any(|e| matches!(e, HostEvent::LogWarning { .. })));
    std::fs::remove_file(&blocker).unwrap();
    h.advance(Duration::from_secs(1));
    let log = std::fs::read_to_string(blocker.join("logs/2026-10-03.md")).unwrap();
    assert!(log.contains("  keep me\n"), "{log}");
    assert!(h.events.iter().any(|e| event_name(e) == "log_recovered"));
}

// ------------------------------------------------------------------ K18

#[test]
fn k18_partial_of_a_closed_connection_is_settled_as_interrupted() {
    let (mut h, mut phone) = secure_pair();
    let id = Uuid::new_v4();
    let done = Uuid::new_v4();
    let mut f = phone.utt(id, 0, UttState::Partial, "half a sen");
    f.extend(phone.utt(done, 1, UttState::Final, "complete"));
    h.frames(P, f);
    h.take_events();
    h.disconnected(P);
    let settled: Vec<serde_json::Value> = h
        .events
        .iter()
        .filter(|e| matches!(e, HostEvent::EntryUpserted { .. }))
        .map(|e| serde_json::to_value(e).unwrap()["entry"].clone())
        .collect();
    assert_eq!(settled.len(), 1, "{settled:?}");
    assert_eq!(settled[0]["id"], id.to_string());
    assert_eq!(settled[0]["state"], "interrupted");
    assert_eq!(settled[0]["partial"], false);
    assert_eq!(settled[0]["text"], "half a sen");
}

// ------------------------------------------------------------------- K2

#[test]
fn k2_snapshot_restores_the_whole_ui_state() {
    let (mut h, mut a) = secure_pair();
    let id = Uuid::new_v4();
    let f = a.utt(id, 0, UttState::Final, "hello");
    h.frames(P, f);
    let o = h
        .core
        .handle_transport(vq_host_core::transport::TransportEvent::Relay(
            vq_host_core::events::RelayStatus::of(vq_host_core::events::RelayLink::Websocket),
        ));
    h.absorb(o);
    let mut b = FakePhone::new("B");
    h.handshake("peer-2", &mut b, None);
    pair_request(&mut h, "peer-2", &mut b);
    let code = h.last_code().unwrap();
    h.advance(Duration::from_secs(20));
    h.take_events();
    h.command(HostCommand::Snapshot);
    let [HostEvent::Snapshot {
        name,
        log_dir,
        paired_peers,
        relay,
        peers,
        entries,
        ..
    }] = h.events.as_slice()
    else {
        panic!("{:?}", h.events)
    };
    assert_eq!(name, "Test Desktop");
    assert_eq!(log_dir, &h.log_dir());
    assert_eq!(paired_peers.len(), 1);
    assert_eq!(relay.link, vq_host_core::events::RelayLink::Websocket);
    assert_eq!(peers.len(), 2);
    assert_eq!(peers[0].peer, P);
    assert_eq!(peers[0].state, PeerState::Secure);
    assert!(peers[0].paired && peers[0].pairing.is_none());
    let pairing = peers[1].pairing.as_ref().expect("modal state");
    assert_eq!(pairing.code, code);
    assert_eq!(pairing.phone_name, "B");
    assert_eq!(pairing.expires_in_secs, 100);
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].id, id);
    let v = serde_json::to_value(&h.events[0]).unwrap();
    assert_eq!(v["event"], "snapshot");
    assert_eq!(v["peers"][1]["pairing"]["code"], code);
}

// ------------------------------------------------------------- K14 / K15

#[test]
fn k14_corrupt_config_is_reported_at_startup() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(dir.path().join("config")).unwrap();
    std::fs::write(dir.path().join("config/config.json"), b"{nope").unwrap();
    let mut core = open_with(dir.path()).unwrap();
    let out = core.startup();
    assert!(out.iter().any(|o| matches!(
        o,
        vq_host_core::CoreOutput::Event(HostEvent::StorageWarning { message }) if message.contains("corrupt")
    )));
}

#[test]
fn k15_log_dir_is_created_at_startup_and_on_change_and_persisted_flag_is_reported() {
    let (mut h, _phone) = secure_pair();
    assert!(h.log_dir().is_dir(), "created at start-up");
    let new_dir = h.dir.path().join("new/logs");
    h.command(HostCommand::SetLogDir {
        path: new_dir.clone(),
    });
    assert!(new_dir.is_dir(), "created on change");
    assert!(h.events.iter().any(|e| matches!(
        e,
        HostEvent::ConfigChanged { persisted: true, log_dir, .. } if log_dir == &new_dir
    )));
    h.take_events();
    // config.json cannot be replaced: the change applies for this run only.
    std::fs::remove_file(h.config_dir().join("config.json")).unwrap();
    std::fs::create_dir_all(h.config_dir().join("config.json/x")).unwrap();
    h.command(HostCommand::SetName {
        name: "Unsaved".into(),
    });
    assert!(h
        .events
        .iter()
        .any(|e| matches!(e, HostEvent::StorageWarning { .. })));
    assert!(h.events.iter().any(|e| matches!(
        e,
        HostEvent::ConfigChanged { persisted: false, name, .. } if name == "Unsaved"
    )));
}

// ------------------------------------------------------------------ K19

#[cfg(unix)]
#[test]
fn k19_non_utf8_paths_serialize_lossily() {
    use std::os::unix::ffi::OsStrExt;
    let p = std::path::PathBuf::from(std::ffi::OsStr::from_bytes(b"/tmp/bad\xffdir"));
    let ev = HostEvent::Started {
        device_id: Uuid::nil(),
        name: "n".into(),
        log_dir: p,
        paired_peers: vec![],
    };
    let s = serde_json::to_string(&ev).expect("serializes");
    assert!(s.contains("/tmp/bad\u{FFFD}dir"), "{s}");
}

// ------------------------------------------------------- A1 / K3 (host)

#[cfg(feature = "dev-tcp")]
mod host_runtime {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};
    use tokio::sync::mpsc::Receiver;
    use tokio::time::timeout;
    use vq_host_core::io_worker::{IoExecutor, IoJob, IoResult, IoWorker};
    use vq_host_core::transport::tcp::{encode_frames, TcpTransport};
    use vq_host_core::{spawn_host_with_io, HostHandle, SystemClock};
    use vq_protocol::TCP_MTU;

    const T: Duration = Duration::from_secs(10);

    async fn send(s: &mut TcpStream, frames: Vec<Vec<u8>>) {
        s.write_all(&encode_frames(&frames)).await.unwrap();
    }

    /// Next `n` desktop messages that match `keep`, within `within`.
    async fn recv_matching(
        s: &mut TcpStream,
        phone: &mut FakePhone,
        within: Duration,
        mut keep: impl FnMut(&Inbound) -> bool,
    ) -> Inbound {
        timeout(within, async {
            loop {
                let len = s.read_u16().await.unwrap();
                let mut f = vec![0; usize::from(len)];
                s.read_exact(&mut f).await.unwrap();
                for m in phone.receive(&[f]) {
                    if keep(&m) {
                        return m;
                    }
                }
            }
        })
        .await
        .expect("timed out waiting for the desktop")
    }

    async fn wait_event(
        rx: &mut Receiver<HostEvent>,
        mut pred: impl FnMut(&HostEvent) -> bool,
    ) -> HostEvent {
        timeout(T, async {
            loop {
                let e = rx.recv().await.expect("host stopped");
                if pred(&e) {
                    return e;
                }
            }
        })
        .await
        .expect("timed out waiting for a host event")
    }

    struct Started {
        handle: HostHandle,
        events: Receiver<HostEvent>,
        task: tokio::task::JoinHandle<()>,
        stream: TcpStream,
        phone: FakePhone,
        log_dir: std::path::PathBuf,
        _dir: tempfile::TempDir,
    }

    async fn start(wrap: impl FnOnce(IoWorker) -> Box<dyn IoExecutor>) -> Started {
        let dir = tempfile::tempdir().unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap().to_string();
        let log_dir = dir.path().join("logs");
        let (handle, events, task) = spawn_host_with_io(
            CoreOptions {
                config_dir: dir.path().join("config"),
                log_dir_override: Some(log_dir.clone()),
                name_override: Some("Host".into()),
                clock: Arc::new(SystemClock::new()),
                relay: None,
            },
            Box::new(TcpTransport::new(addr)),
            wrap,
        )
        .unwrap();
        let (stream, _) = timeout(T, listener.accept()).await.unwrap().unwrap();
        let mut phone = FakePhone::new("Phone");
        phone.connect(TCP_MTU);
        Started {
            handle,
            events,
            task,
            stream,
            phone,
            log_dir,
            _dir: dir,
        }
    }

    async fn pair_over_tcp(st: &mut Started) {
        let s = &mut st.stream;
        let phone = &mut st.phone;
        recv_matching(s, phone, T, |m| matches!(m, Inbound::Plaintext(Message::Hello(_)))).await;
        let f = phone.hello(None);
        send(s, f).await;
        let f = phone.pair_request();
        send(s, f).await;
        recv_matching(s, phone, T, |m| {
            matches!(m, Inbound::Plaintext(Message::PairChallenge(_)))
        })
        .await;
        let HostEvent::PairingCodeShown { code, .. } = wait_event(&mut st.events, |e| {
            matches!(e, HostEvent::PairingCodeShown { .. })
        })
        .await
        else {
            unreachable!()
        };
        let f = phone.pair_confirm(&code);
        send(s, f).await;
        let Inbound::Plaintext(Message::PairResult(r)) = recv_matching(s, phone, T, |m| {
            matches!(m, Inbound::Plaintext(Message::PairResult(_)))
        })
        .await
        else {
            unreachable!()
        };
        assert!(phone.on_pair_result(&r));
    }

    /// An I/O executor whose log writes take `delay`.
    struct SlowDisk {
        inner: IoWorker,
        delay: Duration,
    }

    impl IoExecutor for SlowDisk {
        fn execute(&mut self, job: IoJob) -> Vec<IoResult> {
            if matches!(job, IoJob::Log(_)) {
                std::thread::sleep(self.delay);
            }
            self.inner.execute(job)
        }
        fn tick(&mut self) -> Vec<IoResult> {
            self.inner.tick()
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn k3_slow_disk_does_not_stall_acks_or_pongs() {
        let mut st = start(|w| {
            Box::new(SlowDisk {
                inner: w,
                delay: Duration::from_secs(3),
            })
        })
        .await;
        pair_over_tcp(&mut st).await;
        let (a, b) = (Uuid::new_v4(), Uuid::new_v4());
        let mut f = st.phone.utt(a, 0, UttState::Final, "first");
        f.extend(st.phone.utt(b, 0, UttState::Final, "second"));
        f.extend(st.phone.sealed(&Message::Ping));
        send(&mut st.stream, f).await;
        let fast = Duration::from_millis(1500);
        let s = &mut st.stream;
        let phone = &mut st.phone;
        recv_matching(s, phone, fast, |m| matches!(m, Inbound::Encrypted(Message::Pong))).await;
        // Both entries reach the UI while the disk is still busy.
        let mut seen = 0;
        timeout(fast, async {
            while seen < 2 {
                if let Some(HostEvent::EntryUpserted { .. }) = st.events.recv().await {
                    seen += 1;
                }
            }
        })
        .await
        .expect("entries are not held up by the disk");
        // The log is still written, in order.
        let file = st.log_dir.join(format!(
            "{}.md",
            chrono::Local::now().format("%Y-%m-%d")
        ));
        timeout(T, async {
            loop {
                let log = std::fs::read_to_string(&file).unwrap_or_default();
                if log.contains("  second\n") {
                    assert!(log.find("  first\n").unwrap() < log.find("  second\n").unwrap());
                    break;
                }
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        })
        .await
        .expect("log written eventually");
        st.handle.send(HostCommand::Shutdown);
        timeout(T, st.task).await.unwrap().unwrap();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a1_flooding_peer_with_a_ui_that_does_not_read() {
        let mut st = start(|w| Box::new(w)).await;
        let s = &mut st.stream;
        let phone = &mut st.phone;
        recv_matching(s, phone, T, |m| matches!(m, Inbound::Plaintext(Message::Hello(_)))).await;
        // 20,000 bad frames (one message_rejected each) while nobody reads
        // the event channel.
        let junk: Vec<Vec<u8>> = (0..20_000).map(|_| vec![0xFF, 0, 0]).collect();
        send(s, junk).await;
        // The host loop is not blocked by the full event channel.
        let f = phone.hello(None);
        send(s, f).await;
        let f = phone.pair_request();
        send(s, f).await;
        recv_matching(s, phone, T, |m| {
            matches!(m, Inbound::Plaintext(Message::PairChallenge(_)))
        })
        .await;
        // Only a bounded number of rejections was ever queued.
        let mut rejected = 0;
        wait_event(&mut st.events, |e| {
            if matches!(e, HostEvent::MessageRejected { .. }) {
                rejected += 1;
            }
            matches!(e, HostEvent::PairingCodeShown { .. })
        })
        .await;
        assert!(rejected > 0);
        assert!(rejected <= 300, "{rejected} rejection events queued");
        st.handle.send(HostCommand::Shutdown);
        timeout(T, st.task).await.unwrap().unwrap();
    }
}

// --------------------------------------------------------------- A2 / K10

#[cfg(feature = "dev-tcp")]
mod tcp_backpressure {
    use super::*;
    use tokio::net::TcpListener;
    use tokio::sync::mpsc;
    use tokio::time::timeout;
    use vq_host_core::transport::tcp::TcpTransport;
    use vq_host_core::transport::{Transport, TransportCommand, TransportEvent};

    async fn connected(
        ev: &mut mpsc::Receiver<TransportEvent>,
    ) -> String {
        loop {
            match timeout(Duration::from_secs(5), ev.recv()).await.unwrap() {
                Some(TransportEvent::Connected { peer, .. }) => return peer,
                Some(_) => {}
                None => panic!("transport stopped"),
            }
        }
    }

    async fn disconnected(ev: &mut mpsc::Receiver<TransportEvent>, within: Duration) -> String {
        timeout(within, async {
            loop {
                match ev.recv().await {
                    Some(TransportEvent::Disconnected { reason, .. }) => return reason,
                    Some(_) => {}
                    None => panic!("transport stopped"),
                }
            }
        })
        .await
        .expect("a stalled phone must not stall the transport")
    }

    fn big_send(peer: &str) -> TransportCommand {
        TransportCommand::Send {
            peer: peer.to_owned(),
            frames: vec![vec![0u8; 512]; 40_000], // ~20 MB, more than any socket buffer
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a2_phone_that_never_reads_cannot_block_disconnect() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap().to_string();
        let (cmd_tx, cmd_rx) = mpsc::unbounded_channel();
        let (ev_tx, mut ev_rx) = mpsc::channel(64);
        let task = Box::new(TcpTransport::new(addr)).start(cmd_rx, ev_tx);
        let (_stalled, _) = timeout(Duration::from_secs(5), listener.accept())
            .await
            .unwrap()
            .unwrap();
        let peer = connected(&mut ev_rx).await;
        cmd_tx.send(big_send(&peer)).unwrap();
        cmd_tx
            .send(TransportCommand::Disconnect {
                peer: peer.clone(),
                reconnect_after: Some(Duration::from_secs(60)),
            })
            .unwrap();
        disconnected(&mut ev_rx, Duration::from_secs(3)).await;
        cmd_tx.send(TransportCommand::Shutdown).unwrap();
        timeout(Duration::from_secs(3), task).await.unwrap().unwrap();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a2_send_queue_overflow_disconnects_the_peer() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap().to_string();
        let (cmd_tx, cmd_rx) = mpsc::unbounded_channel();
        let (ev_tx, mut ev_rx) = mpsc::channel(64);
        let task = Box::new(TcpTransport::new(addr)).start(cmd_rx, ev_tx);
        let (_stalled, _) = timeout(Duration::from_secs(5), listener.accept())
            .await
            .unwrap()
            .unwrap();
        let peer = connected(&mut ev_rx).await;
        for _ in 0..2_000 {
            cmd_tx
                .send(TransportCommand::Send {
                    peer: peer.clone(),
                    frames: vec![vec![0u8; 512]; 8],
                })
                .unwrap();
        }
        let reason = disconnected(&mut ev_rx, Duration::from_secs(5)).await;
        assert!(reason.contains("queue"), "{reason}");
        cmd_tx.send(TransportCommand::Shutdown).unwrap();
        timeout(Duration::from_secs(3), task).await.unwrap().unwrap();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn k10_write_timeout_disconnects_a_stalled_phone() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap().to_string();
        let (cmd_tx, cmd_rx) = mpsc::unbounded_channel();
        let (ev_tx, mut ev_rx) = mpsc::channel(64);
        let task = Box::new(TcpTransport::new(addr).with_write_timeout(Duration::from_millis(500)))
            .start(cmd_rx, ev_tx);
        let (_stalled, _) = timeout(Duration::from_secs(5), listener.accept())
            .await
            .unwrap()
            .unwrap();
        let peer = connected(&mut ev_rx).await;
        cmd_tx.send(big_send(&peer)).unwrap();
        let reason = disconnected(&mut ev_rx, Duration::from_secs(5)).await;
        assert!(reason.contains("timed out"), "{reason}");
        cmd_tx.send(TransportCommand::Shutdown).unwrap();
        timeout(Duration::from_secs(3), task).await.unwrap().unwrap();
    }
}
