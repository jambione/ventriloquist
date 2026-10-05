//! SPEC_V3 §5 at the session layer: the code in the QR is the v1 pairing
//! code, used by the next `pair_request` without showing a code modal.

mod common;

use std::time::Duration;

use common::{wrong_code, FakePhone, Harness};
use vq_host_core::events::PhonePairingEnd;
use vq_host_core::{HostCommand, HostEvent};
use vq_protocol::{Inbound, Message};

const P: &str = "relay:c1";

/// The QR code of the latest `phone_pairing_qr` event.
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

fn request_and_challenge(h: &mut Harness, phone: &mut FakePhone) {
    h.handshake(P, phone, None);
    let f = phone.pair_request();
    h.frames(P, f);
    let r = h.deliver_to_phone(P, phone);
    assert!(matches!(r.as_slice(), [Inbound::Plaintext(Message::PairChallenge(_))]), "{r:?}");
}

#[test]
fn the_qr_code_pairs_without_a_code_modal_and_closes_add_phone() {
    let mut h = Harness::new();
    h.command(HostCommand::StartPhonePairing);
    let code = qr_code(&h);
    let mut phone = FakePhone::new("Jon's iPhone");
    request_and_challenge(&mut h, &mut phone);
    assert!(
        !h.events.iter().any(|e| matches!(e, HostEvent::PairingCodeShown { .. })),
        "no modal for a QR pairing"
    );
    h.take_events();
    let f = phone.pair_confirm(&code);
    h.frames(P, f);
    let r = h.deliver_to_phone(P, &mut phone);
    match r.as_slice() {
        [Inbound::Plaintext(Message::PairResult(res))] => assert!(phone.on_pair_result(res)),
        other => panic!("{other:?}"),
    }
    assert_eq!(h.core.pairing_store().peers().len(), 1);
    assert!(h.events.iter().any(|e| matches!(
        e,
        HostEvent::PhonePairingEnded { reason: PhonePairingEnd::Paired }
    )));
    // The code is single-use.
    assert!(h.core.active_qr_code().is_none());
}

#[test]
fn a_wrong_code_does_not_pair_and_three_failures_burn_the_qr() {
    let mut h = Harness::new();
    h.command(HostCommand::StartPhonePairing);
    let code = qr_code(&h);
    let mut phone = FakePhone::new("Intruder");
    request_and_challenge(&mut h, &mut phone);
    for _ in 0..3 {
        let f = phone.pair_confirm(&wrong_code(&code));
        h.frames(P, f);
        let r = h.deliver_to_phone(P, &mut phone);
        assert!(matches!(r.as_slice(), [Inbound::Plaintext(Message::PairResult(res))] if !res.ok), "{r:?}");
    }
    assert!(h.core.pairing_store().peers().is_empty());
    // The used-up code is replaced at the next tick while "Add phone" is open.
    h.take_events();
    h.advance(Duration::from_secs(1));
    let new_code = qr_code(&h);
    assert_ne!(new_code, code);
    assert_eq!(h.core.active_qr_code().unwrap().to_string(), new_code);
}

#[test]
fn an_expired_qr_code_falls_back_to_the_normal_modal_flow() {
    let mut h = Harness::new();
    h.command(HostCommand::StartPhonePairing);
    let mut phone = FakePhone::new("Late phone");
    h.advance(Duration::from_secs(121)); // regenerates the QR
    h.take_events();
    // Close "Add phone": no QR code is active any more.
    h.command(HostCommand::StopPhonePairing);
    assert!(h.core.active_qr_code().is_none());
    h.handshake(P, &mut phone, None);
    let f = phone.pair_request();
    h.frames(P, f);
    assert!(h.last_code().is_some(), "the classic modal flow still works");
}

#[test]
fn closing_add_phone_cancels_a_qr_attempt_in_progress() {
    let mut h = Harness::new();
    h.command(HostCommand::StartPhonePairing);
    let code = qr_code(&h);
    let mut phone = FakePhone::new("Slow phone");
    request_and_challenge(&mut h, &mut phone);
    h.command(HostCommand::StopPhonePairing);
    let f = phone.pair_confirm(&code);
    h.frames(P, f);
    let r = h.deliver_to_phone(P, &mut phone);
    assert!(matches!(r.as_slice(), [Inbound::Plaintext(Message::PairResult(res))] if !res.ok), "{r:?}");
    assert!(h.core.pairing_store().peers().is_empty());
}
