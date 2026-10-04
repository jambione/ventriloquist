//! In-memory transcript (SPEC §6.1, §7): entries keyed by utterance id,
//! highest revision wins, capped at 500 entries.
//!
//! * Evicted ids leave a tombstone (id → highest revision seen), bounded to
//!   [`MAX_TOMBSTONES`], so a retried `final` of an evicted entry is not
//!   inserted and announced again (README §5.11 idempotency).
//! * A partial whose connection closes is settled as
//!   [`EntryState::Interrupted`] so the UI stops showing "speaking…".

use std::collections::{HashMap, VecDeque};

use chrono::{DateTime, FixedOffset};
use serde::Serialize;
use uuid::Uuid;
use vq_protocol::{Utt, UttState};

use crate::events::PeerId;

/// Default in-memory cap (SPEC §6.1).
pub const MAX_ENTRIES: usize = 500;

/// Evicted ids remembered for idempotency.
pub const MAX_TOMBSTONES: usize = 10_000;

/// State of an entry's accepted revision.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EntryState {
    /// Live, volatile text.
    Partial,
    /// Final text.
    Final,
    /// User correction.
    Edit,
    /// A partial whose connection closed before its `final` arrived. A
    /// later revision (e.g. the `final` re-sent after reconnecting)
    /// replaces it.
    Interrupted,
}

impl From<UttState> for EntryState {
    fn from(s: UttState) -> Self {
        match s {
            UttState::Partial => Self::Partial,
            UttState::Final => Self::Final,
            UttState::Edit => Self::Edit,
        }
    }
}

/// One transcript entry as shown in the UI.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Entry {
    /// Utterance id.
    pub id: Uuid,
    /// Highest accepted revision.
    pub rev: u32,
    /// State of that revision: `partial`, `final`, `edit` or `interrupted`.
    pub state: EntryState,
    /// Full text of that revision (render inertly).
    pub text: String,
    /// Utterance start, ms since the Unix epoch (from the phone).
    pub ts: u64,
    /// Sending phone's `device_id`.
    pub device_id: Uuid,
    /// Sending phone's name.
    pub device_name: String,
    /// Local arrival time of the first revision (RFC 3339).
    pub first_received_at: String,
    /// Local arrival time of the accepted revision (RFC 3339).
    pub received_at: String,
    /// `HH:MM:SS` of `received_at`, for display.
    pub time: String,
    /// Live, volatile text (shown dimmed/italic, "speaking…").
    pub partial: bool,
    /// Replaced by an `edit` (shows an "edited" badge).
    pub edited: bool,
}

/// What [`TranscriptStore::upsert`] did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UpsertKind {
    /// A new id.
    Inserted,
    /// A higher revision of a known id.
    Updated,
    /// `rev` ≤ the highest seen for this id (also for evicted ids): ignored.
    Stale,
}

/// Result of an upsert.
#[derive(Debug, Clone)]
pub struct UpsertOutcome {
    /// What happened.
    pub kind: UpsertKind,
    /// The entry after the change (`None` when stale).
    pub entry: Option<Entry>,
    /// Ids evicted to respect the cap.
    pub evicted: Vec<Uuid>,
}

impl UpsertOutcome {
    /// Whether the revision was accepted (inserted or updated).
    pub fn accepted(&self) -> bool {
        self.kind != UpsertKind::Stale
    }

    fn stale() -> Self {
        Self {
            kind: UpsertKind::Stale,
            entry: None,
            evicted: Vec::new(),
        }
    }
}

/// The transcript store.
#[derive(Debug)]
pub struct TranscriptStore {
    cap: usize,
    entries: HashMap<Uuid, Entry>,
    /// Ids in first-seen order (oldest first).
    order: VecDeque<Uuid>,
    /// Evicted id → highest revision seen.
    tombstones: HashMap<Uuid, u32>,
    tombstone_order: VecDeque<Uuid>,
    /// Connection that delivered each entry whose current state is partial.
    partial_src: HashMap<Uuid, PeerId>,
}

impl Default for TranscriptStore {
    fn default() -> Self {
        Self::new(MAX_ENTRIES)
    }
}

impl TranscriptStore {
    /// Empty store holding at most `cap` entries (minimum 1).
    pub fn new(cap: usize) -> Self {
        Self {
            cap: cap.max(1),
            entries: HashMap::new(),
            order: VecDeque::new(),
            tombstones: HashMap::new(),
            tombstone_order: VecDeque::new(),
            partial_src: HashMap::new(),
        }
    }

    /// Apply one `utt` (README §5.11) received on connection `peer`: keep
    /// the highest `rev` per `id`; lower or equal revisions are ignored,
    /// also for ids already evicted; an `edit` (or `final`) for an unseen
    /// id creates the entry.
    pub fn upsert(
        &mut self,
        utt: &Utt,
        device_id: Uuid,
        device_name: &str,
        peer: &str,
        received_at: DateTime<FixedOffset>,
    ) -> UpsertOutcome {
        let at = received_at.to_rfc3339();
        let time = received_at.format("%H:%M:%S").to_string();
        let partial = utt.state == UttState::Partial;
        if let Some(e) = self.entries.get_mut(&utt.id) {
            if utt.rev <= e.rev {
                return UpsertOutcome::stale();
            }
            e.rev = utt.rev;
            e.state = utt.state.into();
            e.text.clone_from(&utt.text);
            e.ts = utt.ts;
            e.device_id = device_id;
            device_name.clone_into(&mut e.device_name);
            e.received_at = at;
            e.time = time;
            e.partial = partial;
            e.edited = utt.state == UttState::Edit;
            let entry = e.clone();
            self.track_partial(utt.id, partial, peer);
            return UpsertOutcome {
                kind: UpsertKind::Updated,
                entry: Some(entry),
                evicted: Vec::new(),
            };
        }
        if self.tombstones.get(&utt.id).is_some_and(|r| utt.rev <= *r) {
            return UpsertOutcome::stale();
        }
        if self.tombstones.remove(&utt.id).is_some() {
            self.tombstone_order.retain(|i| i != &utt.id);
        }
        let entry = Entry {
            id: utt.id,
            rev: utt.rev,
            state: utt.state.into(),
            text: utt.text.clone(),
            ts: utt.ts,
            device_id,
            device_name: device_name.to_owned(),
            first_received_at: at.clone(),
            received_at: at,
            time,
            partial,
            edited: utt.state == UttState::Edit,
        };
        self.entries.insert(utt.id, entry.clone());
        self.order.push_back(utt.id);
        self.track_partial(utt.id, partial, peer);
        let mut evicted = Vec::new();
        while self.order.len() > self.cap {
            if let Some(old) = self.order.pop_front() {
                if let Some(e) = self.entries.remove(&old) {
                    self.tombstone(old, e.rev);
                }
                self.partial_src.remove(&old);
                evicted.push(old);
            }
        }
        UpsertOutcome {
            kind: UpsertKind::Inserted,
            entry: Some(entry),
            evicted,
        }
    }

    fn track_partial(&mut self, id: Uuid, partial: bool, peer: &str) {
        if partial {
            self.partial_src.insert(id, peer.to_owned());
        } else {
            self.partial_src.remove(&id);
        }
    }

    fn tombstone(&mut self, id: Uuid, rev: u32) {
        self.tombstones.insert(id, rev);
        self.tombstone_order.push_back(id);
        while self.tombstone_order.len() > MAX_TOMBSTONES {
            if let Some(old) = self.tombstone_order.pop_front() {
                self.tombstones.remove(&old);
            }
        }
    }

    /// Connection `peer` closed: settle its live partials as
    /// [`EntryState::Interrupted`]. Returns the changed entries (oldest
    /// first).
    pub fn interrupt_partials_from(&mut self, peer: &str) -> Vec<Entry> {
        let ids: Vec<Uuid> = self
            .order
            .iter()
            .filter(|id| self.partial_src.get(*id).is_some_and(|p| p == peer))
            .copied()
            .collect();
        let mut out = Vec::with_capacity(ids.len());
        for id in ids {
            self.partial_src.remove(&id);
            if let Some(e) = self.entries.get_mut(&id) {
                e.state = EntryState::Interrupted;
                e.partial = false;
                out.push(e.clone());
            }
        }
        out
    }

    /// The entry for `id`.
    pub fn get(&self, id: &Uuid) -> Option<&Entry> {
        self.entries.get(id)
    }

    /// Number of entries.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the store is empty.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Entries in first-seen order (oldest first).
    pub fn entries(&self) -> impl Iterator<Item = &Entry> {
        self.order.iter().filter_map(|id| self.entries.get(id))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn t() -> DateTime<FixedOffset> {
        DateTime::parse_from_rfc3339("2026-10-03T14:03:22+02:00").unwrap()
    }

    fn utt(id: Uuid, rev: u32, state: UttState, text: &str) -> Utt {
        Utt {
            id,
            rev,
            state,
            text: text.into(),
            ts: 1,
        }
    }

    #[test]
    fn highest_rev_wins_and_out_of_order_is_ignored() {
        let mut s = TranscriptStore::default();
        let id = Uuid::new_v4();
        let d = Uuid::new_v4();
        assert_eq!(
            s.upsert(&utt(id, 0, UttState::Partial, "he"), d, "P", "c", t())
                .kind,
            UpsertKind::Inserted
        );
        assert!(s.get(&id).unwrap().partial);
        assert_eq!(
            s.upsert(&utt(id, 2, UttState::Final, "hello"), d, "P", "c", t())
                .kind,
            UpsertKind::Updated
        );
        // late partial rev 1 and duplicate final rev 2 are ignored
        assert_eq!(
            s.upsert(&utt(id, 1, UttState::Partial, "hel"), d, "P", "c", t())
                .kind,
            UpsertKind::Stale
        );
        assert_eq!(
            s.upsert(&utt(id, 2, UttState::Final, "hello"), d, "P", "c", t())
                .kind,
            UpsertKind::Stale
        );
        let e = s.get(&id).unwrap();
        assert_eq!(
            (e.rev, e.text.as_str(), e.partial, e.edited),
            (2, "hello", false, false)
        );
        assert_eq!(e.time, "14:03:22");
        assert_eq!(
            s.upsert(&utt(id, 3, UttState::Edit, "Hello!"), d, "P", "c", t())
                .kind,
            UpsertKind::Updated
        );
        let e = s.get(&id).unwrap();
        assert!(e.edited && !e.partial);
        assert_eq!(e.state, EntryState::Edit);
    }

    #[test]
    fn edit_for_unseen_id_creates_entry() {
        let mut s = TranscriptStore::default();
        let id = Uuid::new_v4();
        let o = s.upsert(
            &utt(id, 5, UttState::Edit, "fixed"),
            Uuid::new_v4(),
            "P",
            "c",
            t(),
        );
        assert_eq!(o.kind, UpsertKind::Inserted);
        assert!(o.entry.unwrap().edited);
        // the final that arrives afterwards with a lower rev is ignored
        assert!(!s
            .upsert(
                &utt(id, 3, UttState::Final, "fixd"),
                Uuid::new_v4(),
                "P",
                "c",
                t()
            )
            .accepted());
        assert_eq!(s.get(&id).unwrap().text, "fixed");
    }

    #[test]
    fn cap_evicts_oldest_first() {
        let mut s = TranscriptStore::default();
        let ids: Vec<Uuid> = (0..MAX_ENTRIES + 2).map(|_| Uuid::new_v4()).collect();
        let mut evicted = Vec::new();
        for id in &ids {
            evicted.extend(
                s.upsert(&utt(*id, 0, UttState::Final, "x"), Uuid::nil(), "P", "c", t())
                    .evicted,
            );
        }
        assert_eq!(s.len(), MAX_ENTRIES);
        assert_eq!(evicted, vec![ids[0], ids[1]]);
        assert!(s.get(&ids[0]).is_none());
        assert_eq!(s.entries().next().unwrap().id, ids[2]);
        // updating an existing entry does not evict
        assert!(s
            .upsert(&utt(ids[5], 1, UttState::Edit, "y"), Uuid::nil(), "P", "c", t())
            .evicted
            .is_empty());
    }

    #[test]
    fn evicted_ids_keep_a_tombstone() {
        let mut s = TranscriptStore::new(1);
        let (a, b) = (Uuid::new_v4(), Uuid::new_v4());
        s.upsert(&utt(a, 2, UttState::Final, "a"), Uuid::nil(), "P", "c", t());
        assert_eq!(
            s.upsert(&utt(b, 0, UttState::Final, "b"), Uuid::nil(), "P", "c", t())
                .evicted,
            vec![a]
        );
        for rev in [0, 2] {
            assert!(!s
                .upsert(&utt(a, rev, UttState::Final, "a"), Uuid::nil(), "P", "c", t())
                .accepted());
        }
        assert!(s
            .upsert(&utt(a, 3, UttState::Edit, "a!"), Uuid::nil(), "P", "c", t())
            .accepted());
    }

    #[test]
    fn tombstones_are_bounded() {
        let mut s = TranscriptStore::new(1);
        for _ in 0..(MAX_TOMBSTONES + 5) {
            s.upsert(
                &utt(Uuid::new_v4(), 0, UttState::Final, "x"),
                Uuid::nil(),
                "P",
                "c",
                t(),
            );
        }
        assert_eq!(s.tombstones.len(), MAX_TOMBSTONES);
        assert_eq!(s.tombstone_order.len(), MAX_TOMBSTONES);
    }

    #[test]
    fn partials_of_a_closed_connection_are_interrupted() {
        let mut s = TranscriptStore::default();
        let (a, b, c) = (Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4());
        s.upsert(&utt(a, 0, UttState::Partial, "a"), Uuid::nil(), "P", "c1", t());
        s.upsert(&utt(b, 0, UttState::Partial, "b"), Uuid::nil(), "P", "c2", t());
        s.upsert(&utt(c, 0, UttState::Partial, "c"), Uuid::nil(), "P", "c1", t());
        s.upsert(&utt(c, 1, UttState::Final, "c"), Uuid::nil(), "P", "c1", t());
        let settled = s.interrupt_partials_from("c1");
        assert_eq!(settled.len(), 1);
        assert_eq!(settled[0].id, a);
        assert_eq!(settled[0].state, EntryState::Interrupted);
        assert!(!settled[0].partial);
        assert!(s.interrupt_partials_from("c1").is_empty());
        assert!(s.get(&b).unwrap().partial);
        // the final re-sent later replaces the interrupted entry
        let o = s.upsert(&utt(a, 1, UttState::Final, "a."), Uuid::nil(), "P", "c3", t());
        assert_eq!(o.entry.unwrap().state, EntryState::Final);
    }
}
