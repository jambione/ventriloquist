//! SessionManager / Core behaviour against README §5.11 and §7 (SPEC §9 gate 2).

mod common;

use std::time::Duration;

use common::{acks, wrong_code, FakePhone, Harness};
use uuid::Uuid;
use vq_host_core::events::{CodeEndReason, HostCommand, HostEvent, PeerState};
use vq_host_core::transport::policy::{IDLE_RECONNECT_HOLDOFF, UNKNOWN_PEER_RECONNECT_HOLDOFF};
use vq_protocol::{ErrorMsg, Inbound, Message, PairResult, UttState};

const P: &str = "peer-1";

fn states(h: &Harness) -> Vec<PeerState> {
    h.events
        .iter()
        .filter_map(|e| match e {
            HostEvent::ConnectionStatus { state, .. } => Some(*state),
            _ => None,
        })
        .collect()
}

fn pair_results(h: &Harness) -> Vec<(bool, u32)> {
    h.events
        .iter()
        .filter_map(|e| match e {
            HostEvent::PairingResult {
                ok,
                attempts_remaining,
                ..
            } => Some((*ok, *attempts_remaining)),
            _ => None,
        })
        .collect()
}

fn code_ends(h: &Harness) -> Vec<CodeEndReason> {
    h.events
        .iter()
        .filter_map(|e| match e {
            HostEvent::PairingCodeEnded { reason, .. } => Some(*reason),
            _ => None,
        })
        .collect()
}

fn expect_pair_result(msgs: &[Inbound]) -> PairResult {
    match msgs {
        [Inbound::Plaintext(Message::PairResult(r))] => r.clone(),
        other => panic!("expected one plaintext pair_result, got {other:?}"),
    }
}

fn expect_error(msgs: &[Inbound], code: &str) {
    assert!(
        msgs.iter()
            .any(|m| matches!(m, Inbound::Plaintext(Message::Error(e)) if e.code == code)),
        "expected error{{{code}}}, got {msgs:?}"
    );
}

/// A paired phone on a fresh connection, Secure.
fn secure_pair() -> (Harness, FakePhone) {
    let mut h = Harness::new();
    let mut phone = FakePhone::new("Jon's iPhone");
    h.pair(P, &mut phone);
    assert_eq!(h.core.sessions().peer_state(P), Some(PeerState::Secure));
    h.take_events();
    (h, phone)
}

// ------------------------------------------------------------ pairing flow

#[test]
fn hello_is_sent_on_connect_with_paired_false_and_fresh_nonce() {
    let mut h = Harness::new();
    let mut phone = FakePhone::new("P");
    h.connect(P, 185);
    phone.connect(185);
    let m = h.deliver_to_phone(P, &mut phone);
    let Inbound::Plaintext(Message::Hello(hello)) = &m[0] else {
        panic!("{m:?}")
    };
    assert_eq!(hello.name, "Test Desktop");
    assert!(!hello.paired);
    assert_eq!(hello.v, 1);
    h.connect("peer-2", 185);
    let mut p2 = FakePhone::new("Q");
    p2.connect(185);
    let m2 = h.deliver_to_phone("peer-2", &mut p2);
    let Inbound::Plaintext(Message::Hello(hello2)) = &m2[0] else {
        panic!()
    };
    assert_ne!(hello.session_nonce, hello2.session_nonce);
    assert_eq!(states(&h), vec![PeerState::Connected, PeerState::Connected]);
}

#[test]
fn first_pairing_succeeds_and_is_persisted() {
    let mut h = Harness::new();
    let mut phone = FakePhone::new("Jon's iPhone");
    let code = h.pair(P, &mut phone);
    assert_eq!(code.len(), 6);
    assert!(code.bytes().all(|b| b.is_ascii_digit()));
    assert_eq!(
        states(&h),
        vec![
            PeerState::Connected,
            PeerState::HelloExchanged,
            PeerState::Pairing,
            PeerState::Secure
        ]
    );
    assert_eq!(pair_results(&h), vec![(true, 0)]);
    assert!(h
        .core
        .pairing_store()
        .knows(&phone.device_id, &phone.identity.public_bytes()));
    assert!(h
        .events
        .iter()
        .any(|e| matches!(e, HostEvent::PairedPeersChanged { peers } if peers.len() == 1)));
    let shown = h.events.iter().find_map(|e| match e {
        HostEvent::PairingCodeShown {
            phone_name,
            expires_in_secs,
            device_id,
            ..
        } => Some((phone_name.clone(), *expires_in_secs, *device_id)),
        _ => None,
    });
    assert_eq!(
        shown,
        Some(("Jon's iPhone".to_owned(), 120, phone.device_id))
    );
    // The pairing survives a restart.
    h.restart();
    assert!(h
        .core
        .pairing_store()
        .knows(&phone.device_id, &phone.identity.public_bytes()));
}

#[test]
fn wrong_code_three_times_invalidates_the_code() {
    let mut h = Harness::new();
    let mut phone = FakePhone::new("P");
    h.handshake(P, &mut phone, None);
    let f = phone.pair_request();
    h.frames(P, f);
    h.deliver_to_phone(P, &mut phone);
    let code = h.last_code().unwrap();
    let bad = wrong_code(&code);
    for _ in 0..3 {
        let f = phone.pair_confirm(&bad);
        h.frames(P, f);
        let r = expect_pair_result(&h.deliver_to_phone(P, &mut phone));
        assert!(!r.ok && r.mac.is_none());
    }
    assert_eq!(pair_results(&h), vec![(false, 2), (false, 1), (false, 0)]);
    assert_eq!(code_ends(&h), vec![CodeEndReason::TooManyFailures]);
    assert_eq!(
        h.core.sessions().peer_state(P),
        Some(PeerState::HelloExchanged)
    );
    // Even the right code is refused now — but still answered.
    let f = phone.pair_confirm(&code);
    h.frames(P, f);
    assert!(!expect_pair_result(&h.deliver_to_phone(P, &mut phone)).ok);
    assert!(h.core.pairing_store().peers().is_empty());
    // A new pair_request starts over, once the 30 s lockout after an
    // invalidated code has passed (D10).
    h.advance(Duration::from_secs(30));
    let f = phone.pair_request();
    h.frames(P, f);
    h.deliver_to_phone(P, &mut phone);
    let code2 = h.last_code().unwrap();
    let f = phone.pair_confirm(&code2);
    h.frames(P, f);
    let r = expect_pair_result(&h.deliver_to_phone(P, &mut phone));
    assert!(phone.on_pair_result(&r));
    assert_eq!(h.core.sessions().peer_state(P), Some(PeerState::Secure));
}

#[test]
fn code_expires_after_120_seconds() {
    let mut h = Harness::new();
    let mut phone = FakePhone::new("P");
    h.handshake(P, &mut phone, None);
    let f = phone.pair_request();
    h.frames(P, f);
    h.deliver_to_phone(P, &mut phone);
    let code = h.last_code().unwrap();
    h.advance(Duration::from_secs(119));
    assert!(code_ends(&h).is_empty());
    h.advance(Duration::from_secs(1));
    assert_eq!(code_ends(&h), vec![CodeEndReason::Expired]);
    let f = phone.pair_confirm(&code);
    h.frames(P, f);
    assert!(!expect_pair_result(&h.deliver_to_phone(P, &mut phone)).ok);
    assert!(h.core.pairing_store().peers().is_empty());
}

#[test]
fn code_expiry_is_checked_on_confirm_even_without_tick() {
    let mut h = Harness::new();
    let mut phone = FakePhone::new("P");
    h.handshake(P, &mut phone, None);
    let f = phone.pair_request();
    h.frames(P, f);
    h.deliver_to_phone(P, &mut phone);
    let code = h.last_code().unwrap();
    h.clock.advance(Duration::from_secs(120)); // no tick
    let f = phone.pair_confirm(&code);
    h.frames(P, f);
    assert!(!expect_pair_result(&h.deliver_to_phone(P, &mut phone)).ok);
    assert_eq!(code_ends(&h), vec![CodeEndReason::Expired]);
}

#[test]
fn right_code_just_before_expiry_succeeds() {
    let mut h = Harness::new();
    let mut phone = FakePhone::new("P");
    h.handshake(P, &mut phone, None);
    let f = phone.pair_request();
    h.frames(P, f);
    h.deliver_to_phone(P, &mut phone);
    let code = h.last_code().unwrap();
    h.advance(Duration::from_millis(119_999));
    let f = phone.pair_confirm(&code);
    h.frames(P, f);
    let r = expect_pair_result(&h.deliver_to_phone(P, &mut phone));
    assert!(phone.on_pair_result(&r));
}

#[test]
fn every_pair_confirm_is_answered_even_without_a_code() {
    let mut h = Harness::new();
    let mut phone = FakePhone::new("P");
    // Before hello.
    h.connect(P, 185);
    phone.connect(185);
    h.deliver_to_phone(P, &mut phone);
    let f = phone.plain(&Message::PairConfirm(vq_protocol::PairConfirm {
        mac: [1; 32],
    }));
    h.frames(P, f);
    assert!(!expect_pair_result(&h.deliver_to_phone(P, &mut phone)).ok);
    // After hello, no code ever generated.
    let f = phone.hello(None);
    h.frames(P, f);
    let f = phone.plain(&Message::PairConfirm(vq_protocol::PairConfirm {
        mac: [2; 32],
    }));
    h.frames(P, f);
    assert!(!expect_pair_result(&h.deliver_to_phone(P, &mut phone)).ok);
    assert_eq!(pair_results(&h), vec![(false, 0), (false, 0)]);
    assert!(h.disconnects.is_empty());
}

#[test]
fn new_pair_request_resets_code_and_failures() {
    let mut h = Harness::new();
    let mut phone = FakePhone::new("P");
    h.handshake(P, &mut phone, None);
    let f = phone.pair_request();
    h.frames(P, f);
    h.deliver_to_phone(P, &mut phone);
    let code1 = h.last_code().unwrap();
    for _ in 0..2 {
        let f = phone.pair_confirm(&wrong_code(&code1));
        h.frames(P, f);
        h.deliver_to_phone(P, &mut phone);
    }
    h.advance(Duration::from_secs(10)); // per-device pair_request interval (D10)
    let f = phone.pair_request();
    h.frames(P, f);
    h.deliver_to_phone(P, &mut phone);
    let code2 = h.last_code().unwrap();
    // The old code is invalid for the new challenge (unless equal by chance).
    if code1 != code2 {
        let f = phone.pair_confirm(&code1);
        h.frames(P, f);
        assert!(!expect_pair_result(&h.deliver_to_phone(P, &mut phone)).ok);
        // failures were reset: one failure on the new code leaves 2.
        assert_eq!(pair_results(&h).last(), Some(&(false, 2)));
    }
    let f = phone.pair_confirm(&code2);
    h.frames(P, f);
    let r = expect_pair_result(&h.deliver_to_phone(P, &mut phone));
    assert!(phone.on_pair_result(&r));
}

#[test]
fn cancel_pairing_invalidates_the_code() {
    let mut h = Harness::new();
    let mut phone = FakePhone::new("P");
    h.handshake(P, &mut phone, None);
    let f = phone.pair_request();
    h.frames(P, f);
    h.deliver_to_phone(P, &mut phone);
    let code = h.last_code().unwrap();
    h.command(HostCommand::CancelPairing { peer: P.into() });
    assert_eq!(code_ends(&h), vec![CodeEndReason::Cancelled]);
    let f = phone.pair_confirm(&code);
    h.frames(P, f);
    assert!(!expect_pair_result(&h.deliver_to_phone(P, &mut phone)).ok);
}

#[test]
fn wrong_direction_pairing_messages_are_ignored() {
    let mut h = Harness::new();
    let mut phone = FakePhone::new("P");
    h.handshake(P, &mut phone, None);
    let f = phone.plain(&Message::PairChallenge(vq_protocol::PairChallenge {
        nonce_d: [3; 32],
    }));
    h.frames(P, f);
    let f = phone.plain(&Message::PairResult(PairResult::failure()));
    h.frames(P, f);
    assert!(h.take(P).is_empty());
    assert!(h.disconnects.is_empty());
}

#[test]
fn disconnect_during_pairing_ends_the_code() {
    let mut h = Harness::new();
    let mut phone = FakePhone::new("P");
    h.handshake(P, &mut phone, None);
    let f = phone.pair_request();
    h.frames(P, f);
    h.disconnected(P);
    assert_eq!(code_ends(&h), vec![CodeEndReason::Disconnected]);
    assert_eq!(states(&h).last(), Some(&PeerState::Closed));
}

// ------------------------------------------------- README §7.2 table rows

#[test]
fn table_row_known_and_paired_true_is_secure_without_pairing() {
    let (mut h, mut phone) = secure_pair();
    h.disconnected(P);
    h.restart();
    h.handshake("peer-2", &mut phone, None);
    assert!(phone.is_secure());
    assert_eq!(
        h.core.sessions().peer_state("peer-2"),
        Some(PeerState::Secure)
    );
    assert!(h.last_code().is_none());
    // Encrypted traffic works both ways with counters from 0.
    let id = Uuid::new_v4();
    let f = phone.utt(id, 0, UttState::Final, "hi");
    h.frames("peer-2", f);
    assert_eq!(
        acks(&h.deliver_to_phone("peer-2", &mut phone)),
        vec![(id, 0)]
    );
}

#[test]
fn table_row_known_but_phone_says_unpaired_waits_for_pairing_and_repair_replaces() {
    let (mut h, mut phone) = secure_pair();
    h.disconnected(P);
    phone.desktop = None; // the user forgot the desktop on the phone
    h.handshake("peer-2", &mut phone, Some(false));
    assert_eq!(
        h.core.sessions().peer_state("peer-2"),
        Some(PeerState::HelloExchanged)
    );
    assert!(h.disconnects.is_empty());
    h.advance(Duration::from_secs(10)); // per-device pair_request interval (D10)
    let f = phone.pair_request();
    h.frames("peer-2", f);
    h.deliver_to_phone("peer-2", &mut phone);
    let code = h.last_code().unwrap();
    let f = phone.pair_confirm(&code);
    h.frames("peer-2", f);
    let r = expect_pair_result(&h.deliver_to_phone("peer-2", &mut phone));
    assert!(phone.on_pair_result(&r));
    assert_eq!(h.core.pairing_store().peers().len(), 1);
}

#[test]
fn table_row_unknown_and_paired_true_gets_unknown_peer() {
    let (mut h, mut phone) = secure_pair();
    h.disconnected(P);
    h.command(HostCommand::ForgetPeer {
        device_id: phone.device_id,
    });
    h.handshake("peer-2", &mut phone, None);
    let msgs = h.deliver_to_phone("peer-2", &mut phone);
    expect_error(&msgs, ErrorMsg::UNKNOWN_PEER);
    assert_eq!(
        h.disconnects,
        vec![("peer-2".to_owned(), Some(UNKNOWN_PEER_RECONNECT_HOLDOFF))]
    );
    assert!(h.core.pairing_store().peers().is_empty());
}

#[test]
fn table_row_unknown_and_paired_false_waits_for_pairing() {
    let mut h = Harness::new();
    let mut phone = FakePhone::new("P");
    h.handshake(P, &mut phone, Some(false));
    assert_eq!(
        h.core.sessions().peer_state(P),
        Some(PeerState::HelloExchanged)
    );
    assert!(h.take(P).is_empty());
    assert!(h.disconnects.is_empty());
}

#[test]
fn stored_device_id_with_different_key_is_not_known() {
    let (mut h, mut phone) = secure_pair();
    h.disconnected(P);
    phone.identity = vq_protocol::IdentityKeyPair::generate(); // reinstall, same id
    h.handshake("peer-2", &mut phone, Some(true));
    expect_error(
        &h.deliver_to_phone("peer-2", &mut phone),
        ErrorMsg::UNKNOWN_PEER,
    );
}

// --------------------------------------------------------- hello / version

#[test]
fn unsupported_version_gets_version_error() {
    let mut h = Harness::new();
    let mut phone = FakePhone::new("P");
    h.connect(P, 185);
    phone.connect(185);
    h.deliver_to_phone(P, &mut phone);
    let f = phone.raw_plain(br#"{"t":"hello","v":2,"name":"Future Phone"}"#);
    h.frames(P, f);
    expect_error(&h.deliver_to_phone(P, &mut phone), ErrorMsg::VERSION);
    assert!(h.events.iter().any(
        |e| matches!(e, HostEvent::VersionMismatch { device, .. } if device == "Future Phone")
    ));
    assert_eq!(h.disconnects.len(), 1);
}

#[test]
fn version_error_from_phone_names_this_desktop() {
    let mut h = Harness::new();
    let mut phone = FakePhone::new("P");
    h.connect(P, 185);
    phone.connect(185);
    h.deliver_to_phone(P, &mut phone);
    let f = phone.plain(&Message::Error(ErrorMsg::new(
        "version",
        "Update Ventriloquist",
    )));
    h.frames(P, f);
    assert!(h.events.iter().any(
        |e| matches!(e, HostEvent::VersionMismatch { device, .. } if device == "Test Desktop")
    ));
    assert_eq!(h.disconnects.len(), 1);
}

#[test]
fn second_hello_before_secure_is_a_protocol_error() {
    let mut h = Harness::new();
    let mut phone = FakePhone::new("P");
    h.handshake(P, &mut phone, Some(false));
    let f = phone.hello(Some(false));
    h.frames(P, f);
    expect_error(&h.deliver_to_phone(P, &mut phone), ErrorMsg::PROTOCOL);
    assert_eq!(h.disconnects.len(), 1);
}

#[test]
fn low_order_public_key_is_refused() {
    let mut h = Harness::new();
    let mut phone = FakePhone::new("P");
    h.connect(P, 185);
    phone.connect(185);
    h.deliver_to_phone(P, &mut phone);
    let json = format!(
        r#"{{"t":"hello","v":1,"device_id":"{}","name":"x","pub":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=","paired":false,"session_nonce":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="}}"#,
        Uuid::new_v4()
    );
    let f = phone.raw_plain(json.as_bytes());
    h.frames(P, f);
    expect_error(&h.deliver_to_phone(P, &mut phone), ErrorMsg::PROTOCOL);
    assert_eq!(h.disconnects.len(), 1);
}

// ------------------------------------------------- README §7.4 Secure state

#[test]
fn secure_second_hello_plaintext_or_encrypted_is_protocol_error() {
    for encrypted in [false, true] {
        let (mut h, mut phone) = secure_pair();
        let (hello, _) =
            vq_protocol::Hello::new(phone.device_id, "P", phone.identity.public_bytes(), true);
        let f = if encrypted {
            phone.sealed(&Message::Hello(hello))
        } else {
            phone.plain(&Message::Hello(hello))
        };
        h.frames(P, f);
        expect_error(&h.deliver_to_phone(P, &mut phone), ErrorMsg::PROTOCOL);
        assert_eq!(h.disconnects.len(), 1);
        assert_eq!(h.rejected_codes(), vec!["not_allowed_in_session"]);
    }
}

#[test]
fn secure_pairing_messages_are_dropped() {
    let (mut h, mut phone) = secure_pair();
    let f = phone.pair_request();
    h.frames(P, f);
    let f = phone.plain(&Message::PairConfirm(vq_protocol::PairConfirm {
        mac: [0; 32],
    }));
    h.frames(P, f);
    let f = phone.sealed(&Message::PairRequest(vq_protocol::PairRequest::generate()));
    h.frames(P, f);
    assert!(h.take(P).is_empty(), "no challenge or result while Secure");
    assert!(h.disconnects.is_empty());
    assert!(h.last_code().is_none());
    assert_eq!(h.rejected_codes(), vec!["not_allowed_in_session"; 3]);
    assert_eq!(h.core.sessions().peer_state(P), Some(PeerState::Secure));
}

#[test]
fn secure_plaintext_utt_is_rejected() {
    let (mut h, mut phone) = secure_pair();
    let json = format!(
        r#"{{"t":"utt","id":"{}","rev":0,"state":"final","text":"sneaky","ts":1}}"#,
        Uuid::new_v4()
    );
    let f = phone.raw_plain(json.as_bytes());
    h.frames(P, f);
    assert_eq!(h.rejected_codes(), vec!["plaintext_not_allowed"]);
    assert!(h.upserts().is_empty());
    assert!(h.take(P).is_empty(), "no ack");
    assert!(h.disconnects.is_empty());
    assert!(!h.log_dir().join("2026-10-03.md").exists());
}

#[test]
fn plaintext_utt_before_session_is_rejected() {
    let mut h = Harness::new();
    let mut phone = FakePhone::new("P");
    h.handshake(P, &mut phone, Some(false));
    let json = format!(
        r#"{{"t":"utt","id":"{}","rev":0,"state":"final","text":"x","ts":1}}"#,
        Uuid::new_v4()
    );
    let f = phone.raw_plain(json.as_bytes());
    h.frames(P, f);
    assert_eq!(h.rejected_codes(), vec!["plaintext_not_allowed"]);
    assert!(h.upserts().is_empty());
}

#[test]
fn secure_unauthenticated_error_disconnects_but_never_changes_pairing() {
    let (mut h, mut phone) = secure_pair();
    let before = h.core.pairing_store().peers().to_vec();
    let f = phone.plain(&Message::Error(ErrorMsg::new("unknown_peer", "forged")));
    h.frames(P, f);
    assert!(h.events.iter().any(|e| matches!(e, HostEvent::PeerError { authenticated: false, code, .. } if code == "unknown_peer")));
    assert_eq!(h.disconnects.len(), 1);
    assert_eq!(h.core.pairing_store().peers(), &before[..]);
    // Still known after a restart.
    h.restart();
    assert!(h
        .core
        .pairing_store()
        .knows(&phone.device_id, &phone.identity.public_bytes()));
}

#[test]
fn secure_encrypted_error_also_keeps_pairing() {
    let (mut h, mut phone) = secure_pair();
    let f = phone.sealed(&Message::Error(ErrorMsg::new("bad_mac", "")));
    h.frames(P, f);
    assert!(h.events.iter().any(|e| matches!(
        e,
        HostEvent::PeerError {
            authenticated: true,
            ..
        }
    )));
    assert_eq!(h.core.pairing_store().peers().len(), 1);
}

#[test]
fn secure_decrypt_failed_answers_and_disconnects() {
    let (mut h, mut phone) = secure_pair();
    let mut f = phone.utt(Uuid::new_v4(), 0, UttState::Final, "x");
    let last = f.last_mut().unwrap();
    *last.last_mut().unwrap() ^= 0x01; // corrupt the tag
    h.frames(P, f);
    expect_error(&h.deliver_to_phone(P, &mut phone), ErrorMsg::DECRYPT_FAILED);
    assert_eq!(h.rejected_codes(), vec!["decrypt_failed"]);
    assert_eq!(h.disconnects.len(), 1);
    assert!(h.upserts().is_empty());
}

#[test]
fn secure_replay_is_silently_dropped() {
    let (mut h, mut phone) = secure_pair();
    let id = Uuid::new_v4();
    let f = phone.utt(id, 0, UttState::Final, "once");
    h.frames(P, f.clone());
    assert_eq!(acks(&h.deliver_to_phone(P, &mut phone)), vec![(id, 0)]);
    h.take_events();
    h.frames(P, f);
    assert!(h.take(P).is_empty());
    assert!(h.events.is_empty(), "{:?}", h.events);
    assert!(h.disconnects.is_empty());
}

#[test]
fn secure_unknown_type_and_ack_are_dropped() {
    let (mut h, mut phone) = secure_pair();
    let f = phone.raw_sealed(br#"{"t":"future_thing","x":1}"#);
    h.frames(P, f);
    let f = phone.raw_plain(br#"{"t":"other_future_thing"}"#);
    h.frames(P, f);
    let f = phone.sealed(&Message::Ack(vq_protocol::Ack {
        id: Uuid::new_v4(),
        rev: 0,
    }));
    h.frames(P, f);
    assert!(h.take(P).is_empty());
    assert!(h.disconnects.is_empty());
    assert!(h.events.is_empty());
}

#[test]
fn encrypted_before_session_is_no_session() {
    let mut h = Harness::new();
    let mut phone = FakePhone::new("P");
    h.handshake(P, &mut phone, Some(false));
    let mut env = vec![1u8];
    env.extend_from_slice(&[0u8; 40]);
    let frames = vq_protocol::FrameSplitter::with_seq(9)
        .split(&env, 185)
        .unwrap();
    h.frames(P, frames);
    assert_eq!(h.rejected_codes(), vec!["no_session"]);
}

// ----------------------------------------------------------- size limits

#[test]
fn oversize_reassembly_is_rejected_and_session_continues() {
    let (mut h, mut phone) = secure_pair();
    // 65,537 bytes of envelope in max-size frames, never LAST until the end.
    let big = vec![0x01u8; 65_537];
    let mut frames = Vec::new();
    for (i, chunk) in big.chunks(509).enumerate() {
        let mut flags = 0u8;
        if i == 0 {
            flags |= 1;
        }
        if (i + 1) * 509 >= big.len() {
            flags |= 2;
        }
        let mut f = vec![flags, 0x12, 0x34];
        f.extend_from_slice(chunk);
        frames.push(f);
    }
    h.frames(P, frames);
    assert!(h.rejected_codes().contains(&"message_too_large".to_owned()));
    let id = Uuid::new_v4();
    let f = phone.utt(id, 0, UttState::Final, "after");
    h.frames(P, f);
    assert_eq!(acks(&h.deliver_to_phone(P, &mut phone)), vec![(id, 0)]);
}

#[test]
fn text_too_long_is_rejected_without_ack() {
    let (mut h, mut phone) = secure_pair();
    let id = Uuid::new_v4();
    let json = format!(
        r#"{{"t":"utt","id":"{id}","rev":0,"state":"final","text":"{}","ts":1}}"#,
        "a".repeat(32_001)
    );
    let f = phone.raw_sealed(json.as_bytes());
    h.frames(P, f);
    assert_eq!(h.rejected_codes(), vec!["text_too_long"]);
    assert!(h.take(P).is_empty());
    assert!(h.upserts().is_empty());
    // Exactly 32,000 bytes is fine.
    let f = phone.utt(id, 1, UttState::Final, &"b".repeat(32_000));
    h.frames(P, f);
    assert_eq!(acks(&h.deliver_to_phone(P, &mut phone)), vec![(id, 1)]);
    assert_eq!(h.upserts().len(), 1);
}

#[test]
fn malformed_frames_are_not_fatal() {
    let (mut h, mut phone) = secure_pair();
    h.frames(
        P,
        vec![vec![], vec![0x01], vec![0xFF, 0, 0], vec![0x00, 0, 0, 1]],
    );
    assert_eq!(
        h.rejected_codes(),
        vec![
            "frame_too_short",
            "frame_too_short",
            "reserved_flags",
            "orphan_frame"
        ]
    );
    assert!(h.disconnects.is_empty());
    let id = Uuid::new_v4();
    let f = phone.utt(id, 0, UttState::Final, "ok");
    h.frames(P, f);
    assert_eq!(acks(&h.deliver_to_phone(P, &mut phone)), vec![(id, 0)]);
}

// ------------------------------------------------------- delivery rules

#[test]
fn partial_final_edit_flow_with_acks_and_log() {
    let (mut h, mut phone) = secure_pair();
    let id = Uuid::new_v4();
    for (rev, text) in [(0, "kube"), (1, "kubectl get")] {
        let f = phone.utt(id, rev, UttState::Partial, text);
        h.frames(P, f);
    }
    assert!(
        acks(&h.deliver_to_phone(P, &mut phone)).is_empty(),
        "partials are never acked"
    );
    assert!(
        !h.log_dir().join("2026-10-03.md").exists(),
        "partials are never logged"
    );
    let f = phone.utt(id, 2, UttState::Final, "kubectl get pods");
    h.frames(P, f);
    assert_eq!(acks(&h.deliver_to_phone(P, &mut phone)), vec![(id, 2)]);
    h.clock.advance(Duration::from_secs(60));
    let f = phone.utt(id, 3, UttState::Edit, "kubectl get pods -A");
    h.frames(P, f);
    assert_eq!(acks(&h.deliver_to_phone(P, &mut phone)), vec![(id, 3)]);
    let ups = h.upserts();
    assert_eq!(ups.len(), 4);
    assert!(ups[0].partial && ups[1].partial);
    assert!(!ups[2].partial && !ups[2].edited);
    assert!(ups[3].edited);
    assert_eq!(ups[3].device_name, "Jon's iPhone");
    let short = &id.simple().to_string()[..8];
    assert_eq!(
        h.log_text(),
        format!(
            "# Ventriloquist — 2026-10-03\n\n\
             - **14:03:22** · Jon's iPhone · `id={short}`\n  kubectl get pods\n\
             - **14:04:22** · Jon's iPhone · `id={short}` · edited\n  kubectl get pods -A\n"
        )
    );
}

#[test]
fn duplicate_and_out_of_order_delivery_is_idempotent_but_acked() {
    let (mut h, mut phone) = secure_pair();
    let id = Uuid::new_v4();
    let f = phone.utt(id, 2, UttState::Final, "final text");
    h.frames(P, f);
    let f = phone.utt(id, 2, UttState::Final, "final text"); // retry (new counter)
    h.frames(P, f);
    let f = phone.utt(id, 1, UttState::Partial, "late partial");
    h.frames(P, f);
    let f = phone.utt(id, 1, UttState::Final, "older final");
    h.frames(P, f);
    // Every final is acked, duplicates and stale ones included; partials never.
    assert_eq!(
        acks(&h.deliver_to_phone(P, &mut phone)),
        vec![(id, 2), (id, 2), (id, 1)]
    );
    let ups = h.upserts();
    assert_eq!(ups.len(), 1);
    assert_eq!(h.core.transcript().get(&id).unwrap().text, "final text");
    assert_eq!(h.log_text().matches("- **").count(), 1);
}

#[test]
fn edit_before_final_creates_entry_and_late_final_is_ignored() {
    let (mut h, mut phone) = secure_pair();
    let id = Uuid::new_v4();
    let f = phone.utt(id, 5, UttState::Edit, "corrected");
    h.frames(P, f);
    let f = phone.utt(id, 3, UttState::Final, "corected");
    h.frames(P, f);
    assert_eq!(
        acks(&h.deliver_to_phone(P, &mut phone)),
        vec![(id, 5), (id, 3)]
    );
    let ups = h.upserts();
    assert_eq!(ups.len(), 1);
    assert!(ups[0].edited);
    let log = h.log_text();
    assert_eq!(log.matches("- **").count(), 1);
    assert!(log.contains("· edited\n  corrected\n"));
}

#[test]
fn reconnect_and_redelivery_after_restart_is_not_logged_twice() {
    let (mut h, mut phone) = secure_pair();
    let id = Uuid::new_v4();
    let f = phone.utt(id, 0, UttState::Final, "hello");
    h.frames(P, f);
    h.disconnected(P);
    h.restart();
    h.handshake("peer-2", &mut phone, None);
    assert!(phone.is_secure());
    let f = phone.utt(id, 0, UttState::Final, "hello");
    h.frames("peer-2", f);
    assert_eq!(
        acks(&h.deliver_to_phone("peer-2", &mut phone)),
        vec![(id, 0)]
    );
    // A fresh in-memory store shows it again, but the log has it once.
    assert_eq!(h.upserts().len(), 1);
    assert_eq!(h.log_text().matches("- **").count(), 1);
}

#[test]
fn disconnect_mid_message_then_reconnect() {
    let (mut h, mut phone) = secure_pair();
    let id = Uuid::new_v4();
    let mut f = phone.utt(id, 0, UttState::Final, &"x".repeat(1000));
    assert!(f.len() > 2);
    f.truncate(2);
    h.frames(P, f);
    h.disconnected(P);
    h.handshake("peer-2", &mut phone, None);
    let f = phone.utt(id, 0, UttState::Final, "complete");
    h.frames("peer-2", f);
    assert_eq!(
        acks(&h.deliver_to_phone("peer-2", &mut phone)),
        vec![(id, 0)]
    );
    assert_eq!(h.core.transcript().get(&id).unwrap().text, "complete");
}

#[test]
fn log_write_failure_is_a_warning_and_transcription_continues() {
    let (mut h, mut phone) = secure_pair();
    let blocker = h.dir.path().join("blocker");
    std::fs::write(&blocker, b"").unwrap();
    h.command(HostCommand::SetLogDir {
        path: blocker.join("logs"),
    });
    let id = Uuid::new_v4();
    let f = phone.utt(id, 0, UttState::Final, "still shown");
    h.frames(P, f);
    assert_eq!(acks(&h.deliver_to_phone(P, &mut phone)), vec![(id, 0)]);
    assert_eq!(h.upserts().len(), 1);
    assert!(h
        .events
        .iter()
        .any(|e| matches!(e, HostEvent::LogWarning { .. })));
    assert!(h.disconnects.is_empty());
}

#[test]
fn set_log_dir_and_name_take_effect() {
    let (mut h, mut phone) = secure_pair();
    let new_dir = h.dir.path().join("elsewhere");
    h.command(HostCommand::SetLogDir {
        path: new_dir.clone(),
    });
    h.command(HostCommand::SetName {
        name: "Renamed".into(),
    });
    assert!(h
        .events
        .iter()
        .any(|e| matches!(e, HostEvent::ConfigChanged { name, .. } if name == "Renamed")));
    let f = phone.utt(Uuid::new_v4(), 0, UttState::Final, "x");
    h.frames(P, f);
    assert!(new_dir.join("2026-10-03.md").exists());
    h.connect("peer-9", 185);
    let mut p2 = FakePhone::new("Q");
    p2.connect(185);
    let m = h.deliver_to_phone("peer-9", &mut p2);
    assert!(matches!(&m[0], Inbound::Plaintext(Message::Hello(hh)) if hh.name == "Renamed"));
}

#[test]
fn forget_peer_disconnects_and_removes() {
    let (mut h, phone) = secure_pair();
    h.command(HostCommand::ForgetPeer {
        device_id: phone.device_id,
    });
    assert_eq!(h.disconnects, vec![(P.to_owned(), None)]);
    assert!(h.core.pairing_store().peers().is_empty());
    assert!(h
        .events
        .iter()
        .any(|e| matches!(e, HostEvent::PairedPeersChanged { peers } if peers.is_empty())));
}

// ------------------------------------------------------ keepalive / idle

#[test]
fn ping_is_answered_with_pong() {
    let (mut h, mut phone) = secure_pair();
    let f = phone.sealed(&Message::Ping);
    h.frames(P, f);
    let m = h.deliver_to_phone(P, &mut phone);
    assert!(
        matches!(m.as_slice(), [Inbound::Encrypted(Message::Pong)]),
        "{m:?}"
    );
}

#[test]
fn keepalive_three_unanswered_pings_disconnect() {
    let (mut h, mut phone) = secure_pair();
    for _ in 0..3 {
        h.advance(Duration::from_secs(15));
        let m = h.deliver_to_phone(P, &mut phone);
        assert!(
            matches!(m.as_slice(), [Inbound::Encrypted(Message::Ping)]),
            "{m:?}"
        );
        assert!(h.disconnects.is_empty());
    }
    h.advance(Duration::from_secs(15));
    assert_eq!(h.disconnects, vec![(P.to_owned(), None)]);
    h.disconnected(P);
    assert!(h.events.iter().any(|e| matches!(e, HostEvent::ConnectionStatus { state: PeerState::Closed, reason: Some(r), .. } if r == "keepalive_timeout")));
}

#[test]
fn keepalive_pong_resets_the_count() {
    let (mut h, mut phone) = secure_pair();
    for _ in 0..10 {
        h.advance(Duration::from_secs(15));
        let m = h.deliver_to_phone(P, &mut phone);
        assert!(matches!(m.as_slice(), [Inbound::Encrypted(Message::Ping)]));
        let f = phone.sealed(&Message::Pong);
        h.frames(P, f);
    }
    assert!(h.disconnects.is_empty());
}

#[test]
fn unpaired_idle_phone_is_dropped_after_5_minutes() {
    let mut h = Harness::new();
    let mut phone = FakePhone::new("P");
    h.handshake(P, &mut phone, Some(false));
    h.advance(Duration::from_secs(200));
    // pairing activity restarts the 5-minute window
    let f = phone.pair_request();
    h.frames(P, f);
    h.advance(Duration::from_secs(299));
    assert!(h.disconnects.is_empty());
    h.advance(Duration::from_secs(1));
    assert_eq!(
        h.disconnects,
        vec![(P.to_owned(), Some(IDLE_RECONNECT_HOLDOFF))]
    );
}

#[test]
fn secure_phone_is_never_idle_dropped() {
    let (mut h, mut phone) = secure_pair();
    for _ in 0..40 {
        h.advance(Duration::from_secs(15));
        h.deliver_to_phone(P, &mut phone);
        let f = phone.sealed(&Message::Pong);
        h.frames(P, f);
    }
    assert!(h.disconnects.is_empty());
}

#[test]
fn phone_that_never_says_hello_is_dropped() {
    let mut h = Harness::new();
    h.connect(P, 185);
    h.advance(Duration::from_secs(300));
    assert_eq!(h.disconnects.len(), 1);
}

#[test]
fn small_mtu_is_respected() {
    let mut h = Harness::new();
    h.connect(P, 20);
    let frames = h.take(P);
    assert!(frames.len() > 1);
    assert!(frames.iter().all(|f| f.len() <= 20));
}
