//! [`EventOutbox`]: the queue between the host loop and a (possibly slow)
//! UI (docs/SPEC_QUESTIONS.md D11). The host loop pushes every event here
//! and never waits for the UI; the outbox hands events to the bounded
//! event channel as capacity frees up.
//!
//! Memory stays bounded however chatty a peer is, because events that
//! only describe the *latest* state are coalesced while queued:
//!
//! * `entry_upserted` for a **partial**: a newer partial of the same id
//!   replaces the queued one in place (latest wins). A final/edit is never
//!   replaced or dropped.
//! * `message_rejected`: one queued event per (peer, code); repeats are
//!   dropped while it waits.
//! * `pairing_code_shown`: the newest code per peer replaces the queued one.
//!
//! Beyond [`MAX_QUEUED_EVENTS`] live events, further coalescible events
//! (partials, `message_rejected`) are dropped; other events are always
//! queued.

use std::collections::{HashMap, VecDeque};

use uuid::Uuid;

use crate::events::HostEvent;
use crate::transcript::EntryState;

/// Queued events beyond which coalescible events are dropped.
pub const MAX_QUEUED_EVENTS: usize = 4096;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
enum Key {
    Partial(Uuid),
    Rejected(String, String),
    Code(String),
    Devices,
}

fn key_of(e: &HostEvent) -> Option<Key> {
    match e {
        HostEvent::EntryUpserted { entry } if entry.state == EntryState::Partial => {
            Some(Key::Partial(entry.id))
        }
        HostEvent::MessageRejected { peer, code } => {
            Some(Key::Rejected(peer.clone(), code.clone()))
        }
        HostEvent::PairingCodeShown { peer, .. } => Some(Key::Code(peer.clone())),
        HostEvent::DevicesSeen { .. } => Some(Key::Devices),
        _ => None,
    }
}

/// A coalescing FIFO of [`HostEvent`]s.
#[derive(Debug, Default)]
pub struct EventOutbox {
    slots: VecDeque<Option<HostEvent>>,
    /// Sequence number of `slots[0]`.
    head: u64,
    keyed: HashMap<Key, u64>,
    live: usize,
    dropped: u64,
}

impl EventOutbox {
    /// An empty outbox.
    pub fn new() -> Self {
        Self::default()
    }

    /// Queued events.
    pub fn len(&self) -> usize {
        self.live
    }

    /// Whether nothing is queued.
    pub fn is_empty(&self) -> bool {
        self.live == 0
    }

    /// Events dropped (not coalesced) because the queue was full.
    pub fn dropped(&self) -> u64 {
        self.dropped
    }

    /// Queue `e`, coalescing it with a queued event if possible.
    pub fn push(&mut self, e: HostEvent) {
        let key = key_of(&e);
        // A final/edit for an id ends the coalescing window of its partials.
        if let HostEvent::EntryUpserted { entry } = &e {
            if entry.state != EntryState::Partial {
                self.keyed.remove(&Key::Partial(entry.id));
            }
        }
        if let Some(k) = &key {
            if let Some(seq) = self.keyed.get(k).copied() {
                let idx = usize::try_from(seq - self.head).expect("index fits");
                match k {
                    // keep the first, drop the repeat
                    Key::Rejected(..) => {}
                    // latest wins, in place
                    Key::Partial(_) | Key::Code(_) | Key::Devices => self.slots[idx] = Some(e),
                }
                return;
            }
            if self.live >= MAX_QUEUED_EVENTS && !matches!(k, Key::Code(_)) {
                self.dropped += 1;
                return;
            }
        }
        let seq = self.head + self.slots.len() as u64;
        if let Some(k) = key {
            self.keyed.insert(k, seq);
        }
        self.slots.push_back(Some(e));
        self.live += 1;
    }

    /// Take the oldest queued event.
    pub fn pop(&mut self) -> Option<HostEvent> {
        while let Some(slot) = self.slots.pop_front() {
            let seq = self.head;
            self.head += 1;
            if let Some(e) = slot {
                self.live -= 1;
                if let Some(k) = key_of(&e) {
                    if self.keyed.get(&k) == Some(&seq) {
                        self.keyed.remove(&k);
                    }
                }
                return Some(e);
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transcript::Entry;

    fn entry(id: Uuid, rev: u32, state: EntryState) -> HostEvent {
        HostEvent::EntryUpserted {
            entry: Entry {
                id,
                rev,
                state,
                text: format!("rev {rev}"),
                ts: 0,
                device_id: Uuid::nil(),
                device_name: "P".into(),
                first_received_at: String::new(),
                received_at: String::new(),
                time: String::new(),
                partial: state == EntryState::Partial,
                edited: false,
            },
        }
    }

    fn rejected(code: &str) -> HostEvent {
        HostEvent::MessageRejected {
            peer: "p".into(),
            code: code.into(),
        }
    }

    fn revs(o: &mut EventOutbox) -> Vec<u32> {
        std::iter::from_fn(|| o.pop())
            .filter_map(|e| match e {
                HostEvent::EntryUpserted { entry } => Some(entry.rev),
                _ => None,
            })
            .collect()
    }

    #[test]
    fn partials_coalesce_in_place_finals_never() {
        let mut o = EventOutbox::new();
        let (a, b) = (Uuid::new_v4(), Uuid::new_v4());
        o.push(entry(a, 0, EntryState::Partial));
        o.push(entry(b, 0, EntryState::Final));
        o.push(entry(a, 1, EntryState::Partial));
        o.push(entry(a, 2, EntryState::Partial));
        assert_eq!(o.len(), 2);
        o.push(entry(a, 3, EntryState::Final));
        o.push(entry(a, 4, EntryState::Partial)); // after the final: new slot
        assert_eq!(revs(&mut o), vec![2, 0, 3, 4]);
        assert!(o.is_empty());
    }

    #[test]
    fn rejections_are_deduplicated_while_queued() {
        let mut o = EventOutbox::new();
        for _ in 0..10_000 {
            o.push(rejected("reserved_flags"));
            o.push(rejected("orphan_frame"));
        }
        assert_eq!(o.len(), 2);
        o.pop();
        o.push(rejected("orphan_frame")); // still queued: dropped
        o.push(rejected("reserved_flags")); // popped already: queued again
        assert_eq!(o.len(), 2);
    }

    #[test]
    fn bounded_for_coalescible_events_only() {
        let mut o = EventOutbox::new();
        for _ in 0..MAX_QUEUED_EVENTS {
            o.push(entry(Uuid::new_v4(), 0, EntryState::Final));
        }
        o.push(entry(Uuid::new_v4(), 0, EntryState::Partial));
        o.push(rejected("x"));
        assert_eq!(o.dropped(), 2);
        o.push(entry(Uuid::new_v4(), 0, EntryState::Final));
        o.push(HostEvent::LogRecovered);
        assert_eq!(o.len(), MAX_QUEUED_EVENTS + 2);
    }

    #[test]
    fn newest_code_per_peer_wins() {
        let mut o = EventOutbox::new();
        let code = |c: &str| HostEvent::PairingCodeShown {
            peer: "p".into(),
            device_id: Uuid::nil(),
            phone_name: "P".into(),
            code: c.into(),
            expires_in_secs: 120,
        };
        o.push(code("111111"));
        o.push(HostEvent::LogRecovered);
        o.push(code("222222"));
        assert_eq!(o.pop(), Some(code("222222")));
        assert_eq!(o.pop(), Some(HostEvent::LogRecovered));
        assert_eq!(o.pop(), None);
    }
}
