//! `HostEvent::FinalAccepted`: exactly once per utterance id (SPEC_V2 §3, §6.2).

mod common;

use std::fs;
use std::time::Duration;

use common::{FakePhone, Harness};
use uuid::Uuid;
use vq_host_core::events::HostEvent;
use vq_host_core::outbox::{EventOutbox, MAX_QUEUED_EVENTS};
use vq_host_core::transcript::{Entry, EntryState};
use vq_protocol::UttState;

const P: &str = "peer-1";

fn paired() -> (Harness, FakePhone) {
    let mut h = Harness::new();
    let mut phone = FakePhone::new("Phone");
    h.pair(P, &mut phone);
    h.take_events();
    (h, phone)
}

fn send(h: &mut Harness, phone: &mut FakePhone, id: Uuid, rev: u32, st: UttState, text: &str) {
    let f = phone.utt(id, rev, st, text);
    h.frames(P, f);
}

fn accepted(h: &Harness) -> Vec<Entry> {
    h.events
        .iter()
        .filter_map(|e| match e {
            HostEvent::FinalAccepted { entry } => Some(entry.clone()),
            _ => None,
        })
        .collect()
}

#[test]
fn fires_once_for_the_first_final_and_carries_the_entry() {
    let (mut h, mut phone) = paired();
    let id = Uuid::new_v4();
    send(&mut h, &mut phone, id, 0, UttState::Partial, "he");
    send(&mut h, &mut phone, id, 1, UttState::Partial, "hello");
    assert!(accepted(&h).is_empty(), "partials never fire");
    send(&mut h, &mut phone, id, 2, UttState::Final, "hello world");
    let a = accepted(&h);
    assert_eq!(a.len(), 1);
    assert_eq!((a[0].id, a[0].rev, a[0].state), (id, 2, EntryState::Final));
    assert_eq!(a[0].text, "hello world");
    // follows the entry_upserted of the same final
    let up = h
        .events
        .iter()
        .position(|e| matches!(e, HostEvent::EntryUpserted { entry } if entry.rev == 2))
        .unwrap();
    let fa = h
        .events
        .iter()
        .position(|e| matches!(e, HostEvent::FinalAccepted { .. }))
        .unwrap();
    assert!(up < fa);
    let json = serde_json::to_string(&h.events[fa]).unwrap();
    assert!(json.starts_with(r#"{"event":"final_accepted","entry":{"#), "{json}");
}

#[test]
fn duplicate_and_lower_rev_finals_do_not_fire_again() {
    let (mut h, mut phone) = paired();
    let id = Uuid::new_v4();
    send(&mut h, &mut phone, id, 3, UttState::Final, "x");
    send(&mut h, &mut phone, id, 3, UttState::Final, "x");
    send(&mut h, &mut phone, id, 2, UttState::Final, "older");
    send(&mut h, &mut phone, id, 0, UttState::Final, "oldest");
    assert_eq!(accepted(&h).len(), 1);
}

#[test]
fn higher_rev_second_final_does_not_fire_again() {
    let (mut h, mut phone) = paired();
    let id = Uuid::new_v4();
    send(&mut h, &mut phone, id, 1, UttState::Final, "x");
    send(&mut h, &mut phone, id, 2, UttState::Final, "y");
    assert_eq!(accepted(&h).len(), 1);
}

#[test]
fn edit_before_final_never_fires_and_late_lower_final_is_stale() {
    let (mut h, mut phone) = paired();
    let id = Uuid::new_v4();
    send(&mut h, &mut phone, id, 5, UttState::Edit, "edited");
    send(&mut h, &mut phone, id, 2, UttState::Final, "late");
    assert!(accepted(&h).is_empty());
    // another id: edit alone
    send(&mut h, &mut phone, Uuid::new_v4(), 1, UttState::Edit, "e");
    assert!(accepted(&h).is_empty());
}

#[test]
fn final_then_edit_fires_only_for_the_final() {
    let (mut h, mut phone) = paired();
    let id = Uuid::new_v4();
    send(&mut h, &mut phone, id, 1, UttState::Final, "one");
    send(&mut h, &mut phone, id, 2, UttState::Edit, "two");
    let a = accepted(&h);
    assert_eq!(a.len(), 1);
    assert_eq!(a[0].rev, 1);
}

fn redelivery_after_restart(next_day: bool) {
    let (mut h, mut phone) = paired();
    let id = Uuid::new_v4();
    send(&mut h, &mut phone, id, 1, UttState::Final, "persisted");
    assert_eq!(accepted(&h).len(), 1);
    h.restart();
    if next_day {
        h.clock.advance(Duration::from_secs(24 * 3600));
    }
    h.handshake("peer-2", &mut phone, None);
    assert!(phone.is_secure());
    let f = phone.utt(id, 1, UttState::Final, "persisted");
    h.frames("peer-2", f);
    assert!(
        h.upserts().iter().any(|e| e.id == id),
        "the new run does accept it into its transcript"
    );
    assert!(accepted(&h).is_empty(), "but the log already holds it");
    // a new id still fires
    let f = phone.utt(Uuid::new_v4(), 1, UttState::Final, "fresh");
    h.frames("peer-2", f);
    assert_eq!(accepted(&h).len(), 1);
}

#[test]
fn restart_redelivery_same_day_does_not_fire() {
    redelivery_after_restart(false);
}

#[test]
fn restart_redelivery_next_day_does_not_fire() {
    redelivery_after_restart(true);
}

#[test]
fn evicted_id_tombstone_does_not_fire_again() {
    let (mut h, mut phone) = paired();
    let first = Uuid::new_v4();
    send(&mut h, &mut phone, first, 1, UttState::Final, "first");
    for i in 0..vq_host_core::transcript::MAX_ENTRIES {
        send(&mut h, &mut phone, Uuid::new_v4(), 1, UttState::Final, &format!("n{i}"));
    }
    assert!(h
        .events
        .iter()
        .any(|e| matches!(e, HostEvent::EntryEvicted { id } if *id == first)));
    let before = accepted(&h).len();
    assert_eq!(before, vq_host_core::transcript::MAX_ENTRIES + 1);
    send(&mut h, &mut phone, first, 1, UttState::Final, "first");
    send(&mut h, &mut phone, first, 0, UttState::Final, "first");
    assert_eq!(accepted(&h).len(), before);
}

#[test]
fn fires_once_at_acceptance_when_the_log_write_fails() {
    let (mut h, mut phone) = paired();
    // Replace the log directory with a file: every write fails.
    fs::remove_dir_all(h.log_dir()).unwrap();
    fs::write(h.log_dir(), b"blocker").unwrap();
    let id = Uuid::new_v4();
    send(&mut h, &mut phone, id, 1, UttState::Final, "unwritable");
    assert!(h
        .events
        .iter()
        .any(|e| matches!(e, HostEvent::LogWarning { .. })));
    assert_eq!(accepted(&h).len(), 1, "fires despite the failed write");
    // retries (ticks) and the duplicate final do not announce again
    send(&mut h, &mut phone, id, 1, UttState::Final, "unwritable");
    h.advance(Duration::from_secs(1));
    h.advance(Duration::from_secs(1));
    assert_eq!(accepted(&h).len(), 1);
    // recovery of the log does not announce either
    fs::remove_file(h.log_dir()).unwrap();
    h.advance(Duration::from_secs(1));
    assert!(h.events.iter().any(|e| matches!(e, HostEvent::LogRecovered)));
    assert_eq!(accepted(&h).len(), 1);
}

fn entry(id: Uuid, rev: u32, state: EntryState) -> Entry {
    Entry {
        id,
        rev,
        state,
        text: String::new(),
        ts: 0,
        device_id: Uuid::nil(),
        device_name: "P".into(),
        first_received_at: String::new(),
        received_at: String::new(),
        time: String::new(),
        partial: state == EntryState::Partial,
        edited: false,
    }
}

#[test]
fn outbox_flood_with_a_slow_ui_never_drops_or_coalesces_final_accepted() {
    let mut ob = EventOutbox::new();
    let mut wanted = Vec::new();
    // Far beyond the queue cap, with coalescible traffic interleaved.
    for i in 0..(MAX_QUEUED_EVENTS * 3) {
        let id = Uuid::new_v4();
        ob.push(HostEvent::EntryUpserted {
            entry: entry(id, 0, EntryState::Partial),
        });
        ob.push(HostEvent::MessageRejected {
            peer: format!("p{i}"),
            code: "c".into(),
        });
        if i % 2 == 0 {
            wanted.push(id);
            ob.push(HostEvent::FinalAccepted {
                entry: entry(id, 1, EntryState::Final),
            });
        }
        // a repeat for the same id too (distinct ids in real life; the
        // outbox must still never merge two of them)
        if i % 100 == 0 {
            ob.push(HostEvent::FinalAccepted {
                entry: entry(id, 1, EntryState::Final),
            });
            wanted.push(id);
        }
    }
    assert!(ob.dropped() > 0, "the flood did overflow");
    let mut got = Vec::new();
    while let Some(e) = ob.pop() {
        if let HostEvent::FinalAccepted { entry } = e {
            got.push(entry.id);
        }
    }
    assert_eq!(got, wanted, "all delivered, in order");
}
