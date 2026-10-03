//! In-memory transcript (SPEC §6.1, §7): entries keyed by utterance id,
//! highest revision wins, capped at 500 entries.

use std::collections::{HashMap, VecDeque};

use chrono::{DateTime, FixedOffset};
use serde::Serialize;
use uuid::Uuid;
use vq_protocol::{Utt, UttState};

/// Default in-memory cap (SPEC §6.1).
pub const MAX_ENTRIES: usize = 500;

/// One transcript entry as shown in the UI.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Entry {
    /// Utterance id.
    pub id: Uuid,
    /// Highest accepted revision.
    pub rev: u32,
    /// State of that revision: `partial`, `final` or `edit`.
    pub state: UttState,
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
    /// `rev` ≤ the highest seen for this id: ignored.
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
}

/// The transcript store.
#[derive(Debug)]
pub struct TranscriptStore {
    cap: usize,
    entries: HashMap<Uuid, Entry>,
    /// Ids in first-seen order (oldest first).
    order: VecDeque<Uuid>,
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
        }
    }

    /// Apply one `utt` (README §5.11): keep the highest `rev` per `id`;
    /// lower or equal revisions are ignored; an `edit` (or `final`) for an
    /// unseen id creates the entry.
    pub fn upsert(
        &mut self,
        utt: &Utt,
        device_id: Uuid,
        device_name: &str,
        received_at: DateTime<FixedOffset>,
    ) -> UpsertOutcome {
        let at = received_at.to_rfc3339();
        let time = received_at.format("%H:%M:%S").to_string();
        if let Some(e) = self.entries.get_mut(&utt.id) {
            if utt.rev <= e.rev {
                return UpsertOutcome {
                    kind: UpsertKind::Stale,
                    entry: None,
                    evicted: Vec::new(),
                };
            }
            e.rev = utt.rev;
            e.state = utt.state;
            e.text.clone_from(&utt.text);
            e.ts = utt.ts;
            e.device_id = device_id;
            device_name.clone_into(&mut e.device_name);
            e.received_at = at;
            e.time = time;
            e.partial = utt.state == UttState::Partial;
            e.edited = utt.state == UttState::Edit;
            return UpsertOutcome {
                kind: UpsertKind::Updated,
                entry: Some(e.clone()),
                evicted: Vec::new(),
            };
        }
        let entry = Entry {
            id: utt.id,
            rev: utt.rev,
            state: utt.state,
            text: utt.text.clone(),
            ts: utt.ts,
            device_id,
            device_name: device_name.to_owned(),
            first_received_at: at.clone(),
            received_at: at,
            time,
            partial: utt.state == UttState::Partial,
            edited: utt.state == UttState::Edit,
        };
        self.entries.insert(utt.id, entry.clone());
        self.order.push_back(utt.id);
        let mut evicted = Vec::new();
        while self.order.len() > self.cap {
            if let Some(old) = self.order.pop_front() {
                self.entries.remove(&old);
                evicted.push(old);
            }
        }
        UpsertOutcome {
            kind: UpsertKind::Inserted,
            entry: Some(entry),
            evicted,
        }
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
            s.upsert(&utt(id, 0, UttState::Partial, "he"), d, "P", t())
                .kind,
            UpsertKind::Inserted
        );
        assert!(s.get(&id).unwrap().partial);
        assert_eq!(
            s.upsert(&utt(id, 2, UttState::Final, "hello"), d, "P", t())
                .kind,
            UpsertKind::Updated
        );
        // late partial rev 1 and duplicate final rev 2 are ignored
        assert_eq!(
            s.upsert(&utt(id, 1, UttState::Partial, "hel"), d, "P", t())
                .kind,
            UpsertKind::Stale
        );
        assert_eq!(
            s.upsert(&utt(id, 2, UttState::Final, "hello"), d, "P", t())
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
            s.upsert(&utt(id, 3, UttState::Edit, "Hello!"), d, "P", t())
                .kind,
            UpsertKind::Updated
        );
        let e = s.get(&id).unwrap();
        assert!(e.edited && !e.partial);
        assert_eq!(e.state, UttState::Edit);
    }

    #[test]
    fn edit_for_unseen_id_creates_entry() {
        let mut s = TranscriptStore::default();
        let id = Uuid::new_v4();
        let o = s.upsert(
            &utt(id, 5, UttState::Edit, "fixed"),
            Uuid::new_v4(),
            "P",
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
                s.upsert(&utt(*id, 0, UttState::Final, "x"), Uuid::nil(), "P", t())
                    .evicted,
            );
        }
        assert_eq!(s.len(), MAX_ENTRIES);
        assert_eq!(evicted, vec![ids[0], ids[1]]);
        assert!(s.get(&ids[0]).is_none());
        assert_eq!(s.entries().next().unwrap().id, ids[2]);
        // updating an existing entry does not evict
        assert!(s
            .upsert(&utt(ids[5], 1, UttState::Edit, "y"), Uuid::nil(), "P", t())
            .evicted
            .is_empty());
    }
}
