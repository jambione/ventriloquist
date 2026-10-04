//! `bindings.json` persistence and the pure re-match logic (SPEC_V2 §4.6).

use std::collections::BTreeMap;
use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use serde::{Deserialize, Serialize};

use crate::model::{ActiveSlot, BindingTarget, SlotId, SlotSettings, WindowInfo};

pub const BINDINGS_FILE: &str = "bindings.json";
pub const BINDINGS_VERSION: u32 = 1;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SlotRecord {
    pub slot: SlotId,
    pub target: BindingTarget,
    #[serde(default)]
    pub settings: SlotSettings,
}

#[derive(Serialize, Deserialize)]
struct FileFormat {
    version: u32,
    /// 0 = Off, 1..=9 = slot.
    #[serde(default)]
    active: u8,
    #[serde(default)]
    slots: Vec<SlotRecord>,
}

/// Result of selecting a slot with the hotkey (§4.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SelectOutcome {
    /// The slot is now active ("selected" sound).
    Selected(SlotId),
    /// The slot is empty; the active slot is unchanged ("empty" sound).
    Empty(SlotId),
    /// Off ("off" sound).
    Off,
}

/// All slots plus the active slot.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct BindingsStore {
    slots: BTreeMap<SlotId, SlotRecord>,
    active: ActiveSlot,
}

impl BindingsStore {
    pub fn active(&self) -> ActiveSlot {
        self.active
    }

    pub fn get(&self, slot: SlotId) -> Option<&SlotRecord> {
        self.slots.get(&slot)
    }

    pub fn records(&self) -> impl Iterator<Item = &SlotRecord> {
        self.slots.values()
    }

    /// Bind `slot` (replacing whatever it held, settings reset to the app's defaults),
    /// make it active (O1).
    pub fn bind(&mut self, slot: SlotId, target: BindingTarget) {
        let settings = SlotSettings::for_app(&target.app_id);
        self.slots.insert(slot, SlotRecord { slot, target, settings });
        self.active = ActiveSlot::Slot(slot);
    }

    /// Unbind; if it was active the active slot becomes Off. Returns whether
    /// the slot held a binding.
    pub fn unbind(&mut self, slot: SlotId) -> bool {
        let had = self.slots.remove(&slot).is_some();
        if self.active == ActiveSlot::Slot(slot) {
            self.active = ActiveSlot::Off;
        }
        had
    }

    /// Hotkey selection: `digit` 0 = Off, 1..=9 = slot. `None` for other values.
    pub fn select(&mut self, digit: u8) -> Option<SelectOutcome> {
        match ActiveSlot::from_digit(digit)? {
            ActiveSlot::Off => {
                self.active = ActiveSlot::Off;
                Some(SelectOutcome::Off)
            }
            ActiveSlot::Slot(s) if self.slots.contains_key(&s) => {
                self.active = ActiveSlot::Slot(s);
                Some(SelectOutcome::Selected(s))
            }
            ActiveSlot::Slot(s) => Some(SelectOutcome::Empty(s)),
        }
    }

    pub fn set_auto_submit(&mut self, slot: SlotId, on: bool) -> bool {
        match self.slots.get_mut(&slot) {
            Some(r) => {
                r.settings.auto_submit = on;
                true
            }
            None => false,
        }
    }

    pub fn set_newline_mode(&mut self, slot: SlotId, mode: crate::model::NewlineMode) -> bool {
        match self.slots.get_mut(&slot) {
            Some(r) => {
                r.settings.newline_mode = mode;
                true
            }
            None => false,
        }
    }

    /// Record the window title after a single-window re-match.
    pub fn update_title(&mut self, slot: SlotId, title: &str) -> bool {
        match self.slots.get_mut(&slot) {
            Some(r) => {
                r.target.window_title = title.to_string();
                true
            }
            None => false,
        }
    }

    /// Load `bindings.json` from `dir`. Missing file: defaults, no warning.
    /// Unreadable, corrupt, or newer-version file: defaults plus a warning
    /// (a corrupt file is moved aside to `bindings.json.corrupt`, best effort).
    pub fn load(dir: &Path) -> (Self, Option<String>) {
        let path = dir.join(BINDINGS_FILE);
        let bytes = match fs::read(&path) {
            Ok(b) => b,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return (Self::default(), None),
            Err(e) => return (Self::default(), Some(format!("cannot read {BINDINGS_FILE}: {e}"))),
        };
        match Self::parse(&bytes) {
            Ok(s) => (s, None),
            Err(why) => {
                let mut aside = path.clone().into_os_string();
                aside.push(".corrupt");
                let _ = fs::rename(&path, PathBuf::from(aside));
                (Self::default(), Some(format!("{BINDINGS_FILE} ignored ({why}); starting with no bindings")))
            }
        }
    }

    fn parse(bytes: &[u8]) -> Result<Self, String> {
        let f: FileFormat = serde_json::from_slice(bytes).map_err(|e| format!("corrupt: {e}"))?;
        if f.version != BINDINGS_VERSION {
            return Err(format!("unsupported version {}", f.version));
        }
        let mut slots = BTreeMap::new();
        for r in f.slots {
            slots.insert(r.slot, r); // a later duplicate wins
        }
        let active = match ActiveSlot::from_digit(f.active) {
            Some(ActiveSlot::Slot(s)) if slots.contains_key(&s) => ActiveSlot::Slot(s),
            _ => ActiveSlot::Off,
        };
        Ok(BindingsStore { slots, active })
    }

    /// Atomic write (temp file + fsync + rename), private file mode.
    pub fn save(&self, dir: &Path) -> io::Result<()> {
        let f = FileFormat {
            version: BINDINGS_VERSION,
            active: self.active.digit(),
            slots: self.slots.values().cloned().collect(),
        };
        let bytes = serde_json::to_vec_pretty(&f).map_err(io::Error::other)?;
        atomic_write_private(&dir.join(BINDINGS_FILE), &bytes)
    }
}

static TMP_COUNTER: AtomicU64 = AtomicU64::new(0);

/// Same convention as `vq-host-core`'s `fsutil::atomic_write_private`.
fn atomic_write_private(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let dir = path
        .parent()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "path has no parent"))?;
    if !dir.is_dir() {
        fs::create_dir_all(dir)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = fs::set_permissions(dir, fs::Permissions::from_mode(0o700));
        }
    }
    let name = path.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let tmp = dir.join(format!(
        ".{name}.tmp-{}-{nanos:x}-{}",
        std::process::id(),
        TMP_COUNTER.fetch_add(1, Ordering::Relaxed)
    ));
    let result = (|| {
        let mut opts = fs::OpenOptions::new();
        opts.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        let mut f = opts.open(&tmp)?;
        f.write_all(bytes)?;
        f.sync_all()?;
        drop(f);
        fs::rename(&tmp, path)?;
        #[cfg(unix)]
        if let Ok(d) = fs::File::open(dir) {
            let _ = d.sync_all();
        }
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&tmp);
    }
    result
}

/// How a saved slot was matched to a live window.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MatchKind {
    /// A window with exactly the saved title.
    ExactTitle,
    /// The app's only standard window; the saved title must be updated.
    SingleWindow,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnboundReason {
    /// No window of that app id exists (not running, or no windows).
    NotRunning,
    /// Several windows carry the saved title.
    AmbiguousTitle,
    /// No exact title and not exactly one standard window.
    NoUniqueWindow,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RematchOutcome {
    Matched { window: WindowInfo, kind: MatchKind },
    Unbound(UnboundReason),
}

/// Pure re-match (§4.6). `running_windows` are the windows of running apps;
/// those of other app ids are ignored.
///
/// 1. windows of the app id (none: unbound);
/// 2. exactly one window with the saved title (several: unbound, never
///    guess; an empty saved title never matches by title);
/// 3. otherwise exactly one standard window;
/// 4. otherwise unbound.
pub fn rematch(saved: &BindingTarget, running_windows: &[WindowInfo]) -> RematchOutcome {
    let wins: Vec<&WindowInfo> = running_windows
        .iter()
        .filter(|w| w.app_id.eq_ignore_ascii_case(&saved.app_id))
        .collect();
    if wins.is_empty() {
        return RematchOutcome::Unbound(UnboundReason::NotRunning);
    }
    if !saved.window_title.is_empty() {
        let exact: Vec<&&WindowInfo> = wins.iter().filter(|w| w.title == saved.window_title).collect();
        match exact.len() {
            0 => {}
            1 => {
                return RematchOutcome::Matched { window: (**exact[0]).clone(), kind: MatchKind::ExactTitle }
            }
            _ => return RematchOutcome::Unbound(UnboundReason::AmbiguousTitle),
        }
    }
    let standard: Vec<&&WindowInfo> = wins.iter().filter(|w| w.standard).collect();
    if standard.len() == 1 {
        return RematchOutcome::Matched { window: (**standard[0]).clone(), kind: MatchKind::SingleWindow };
    }
    RematchOutcome::Unbound(UnboundReason::NoUniqueWindow)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn slot(n: u8) -> SlotId {
        SlotId::new(n).unwrap()
    }
    fn target(bundle: &str, title: &str) -> BindingTarget {
        BindingTarget {
            app_id: bundle.into(),
            app_name: "App".into(),
            window_title: title.into(),
            element_role: "AXTextArea".into(),
            element_subrole: String::new(),
            ax_insertable: true,
        }
    }
    fn win(bundle: &str, title: &str, standard: bool, id: u64) -> WindowInfo {
        WindowInfo { app_id: bundle.into(), pid: 100 + id as i32, title: title.into(), standard, id }
    }

    #[test]
    fn rematch_exact_title() {
        let ws = vec![win("a", "One", true, 1), win("a", "Two", true, 2)];
        match rematch(&target("a", "Two"), &ws) {
            RematchOutcome::Matched { window, kind } => {
                assert_eq!(window.id, 2);
                assert_eq!(kind, MatchKind::ExactTitle);
            }
            o => panic!("{o:?}"),
        }
    }

    #[test]
    fn rematch_exact_title_on_nonstandard_window() {
        let ws = vec![win("a", "Panel", false, 1), win("a", "Doc", true, 2)];
        assert!(matches!(
            rematch(&target("a", "Panel"), &ws),
            RematchOutcome::Matched { kind: MatchKind::ExactTitle, window } if window.id == 1
        ));
    }

    #[test]
    fn rematch_exact_title_wins_over_single_window() {
        let ws = vec![win("a", "Doc", true, 1)];
        assert!(matches!(
            rematch(&target("a", "Doc"), &ws),
            RematchOutcome::Matched { kind: MatchKind::ExactTitle, .. }
        ));
    }

    #[test]
    fn rematch_duplicate_exact_titles_are_ambiguous() {
        let ws = vec![win("a", "Same", true, 1), win("a", "Same", true, 2)];
        assert_eq!(rematch(&target("a", "Same"), &ws), RematchOutcome::Unbound(UnboundReason::AmbiguousTitle));
    }

    #[test]
    fn rematch_single_standard_window_updates_title() {
        let ws = vec![win("a", "Renamed", true, 7), win("a", "Find", false, 8)];
        match rematch(&target("a", "Old"), &ws) {
            RematchOutcome::Matched { window, kind } => {
                assert_eq!(kind, MatchKind::SingleWindow);
                assert_eq!(window.title, "Renamed");
                assert_eq!(window.id, 7);
            }
            o => panic!("{o:?}"),
        }
    }

    #[test]
    fn rematch_multiple_standard_windows_without_exact_is_unbound() {
        let ws = vec![win("a", "X", true, 1), win("a", "Y", true, 2)];
        assert_eq!(rematch(&target("a", "Z"), &ws), RematchOutcome::Unbound(UnboundReason::NoUniqueWindow));
    }

    #[test]
    fn rematch_no_standard_window_is_unbound() {
        let ws = vec![win("a", "Panel", false, 1)];
        assert_eq!(rematch(&target("a", "Z"), &ws), RematchOutcome::Unbound(UnboundReason::NoUniqueWindow));
    }

    #[test]
    fn rematch_not_running_or_other_bundles_only() {
        assert_eq!(rematch(&target("a", "Z"), &[]), RematchOutcome::Unbound(UnboundReason::NotRunning));
        let ws = vec![win("b", "Z", true, 1)];
        assert_eq!(rematch(&target("a", "Z"), &ws), RematchOutcome::Unbound(UnboundReason::NotRunning));
    }

    #[test]
    fn rematch_ignores_other_bundles_when_counting() {
        let ws = vec![win("a", "Doc", true, 1), win("b", "Other", true, 2)];
        assert!(matches!(
            rematch(&target("a", "Gone"), &ws),
            RematchOutcome::Matched { kind: MatchKind::SingleWindow, window } if window.id == 1
        ));
    }

    #[test]
    fn rematch_empty_saved_title_uses_single_window_rule() {
        let ws = vec![win("a", "", true, 1), win("a", "", true, 2)];
        assert_eq!(rematch(&target("a", ""), &ws), RematchOutcome::Unbound(UnboundReason::NoUniqueWindow));
        let ws = vec![win("a", "", true, 1)];
        assert!(matches!(rematch(&target("a", ""), &ws), RematchOutcome::Matched { kind: MatchKind::SingleWindow, .. }));
    }

    #[test]
    fn slot_id_range() {
        assert!(SlotId::new(0).is_none());
        assert!(SlotId::new(10).is_none());
        assert_eq!(SlotId::all().count(), 9);
        assert_eq!(ActiveSlot::from_digit(0), Some(ActiveSlot::Off));
        assert_eq!(ActiveSlot::from_digit(10), None);
        assert_eq!(ActiveSlot::Slot(slot(4)).digit(), 4);
    }

    #[test]
    fn bind_makes_active_and_replaces() {
        let mut s = BindingsStore::default();
        s.bind(slot(2), target("a", "W"));
        assert_eq!(s.active(), ActiveSlot::Slot(slot(2)));
        assert!(s.set_auto_submit(slot(2), true));
        s.bind(slot(2), target("b", "V"));
        let r = s.get(slot(2)).unwrap();
        assert_eq!(r.target.app_id, "b");
        assert!(!r.settings.auto_submit, "rebinding resets auto-submit");
    }

    #[test]
    fn select_logic() {
        let mut s = BindingsStore::default();
        s.bind(slot(1), target("a", "W"));
        s.bind(slot(3), target("b", "W"));
        assert_eq!(s.select(1), Some(SelectOutcome::Selected(slot(1))));
        assert_eq!(s.active(), ActiveSlot::Slot(slot(1)));
        assert_eq!(s.select(2), Some(SelectOutcome::Empty(slot(2))));
        assert_eq!(s.active(), ActiveSlot::Slot(slot(1)), "empty slot leaves active unchanged");
        assert_eq!(s.select(0), Some(SelectOutcome::Off));
        assert_eq!(s.active(), ActiveSlot::Off);
        assert_eq!(s.select(10), None);
        assert_eq!(s.select(3), Some(SelectOutcome::Selected(slot(3))));
    }

    #[test]
    fn unbind_active_goes_off() {
        let mut s = BindingsStore::default();
        s.bind(slot(1), target("a", "W"));
        s.bind(slot(2), target("b", "W"));
        assert!(s.unbind(slot(1)));
        assert_eq!(s.active(), ActiveSlot::Slot(slot(2)));
        assert!(s.unbind(slot(2)));
        assert_eq!(s.active(), ActiveSlot::Off);
        assert!(!s.unbind(slot(2)));
    }

    #[test]
    fn update_title_and_auto_submit_on_missing_slot() {
        let mut s = BindingsStore::default();
        assert!(!s.update_title(slot(1), "x"));
        assert!(!s.set_auto_submit(slot(1), true));
        s.bind(slot(1), target("a", "Old"));
        assert!(s.update_title(slot(1), "New"));
        assert_eq!(s.get(slot(1)).unwrap().target.window_title, "New");
    }

    #[test]
    fn save_load_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        let mut s = BindingsStore::default();
        s.bind(slot(2), target("a", "Teams"));
        s.bind(slot(5), target("b", "Term"));
        s.set_auto_submit(slot(5), true);
        s.select(2);
        s.save(dir.path()).unwrap();
        let (l, w) = BindingsStore::load(dir.path());
        assert_eq!(w, None);
        assert_eq!(l, s);
        assert_eq!(l.active(), ActiveSlot::Slot(slot(2)));
        assert!(l.get(slot(5)).unwrap().settings.auto_submit);
        let v: serde_json::Value = serde_json::from_slice(&fs::read(dir.path().join(BINDINGS_FILE)).unwrap()).unwrap();
        assert_eq!(v["version"], 1);
        // no stray temp files
        let n = fs::read_dir(dir.path()).unwrap().count();
        assert_eq!(n, 1);
    }

    #[cfg(unix)]
    #[test]
    fn saved_file_is_private() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        BindingsStore::default().save(dir.path()).unwrap();
        let m = fs::metadata(dir.path().join(BINDINGS_FILE)).unwrap().permissions().mode();
        assert_eq!(m & 0o777, 0o600);
    }

    #[test]
    fn save_creates_missing_dir() {
        let dir = tempfile::tempdir().unwrap();
        let sub = dir.path().join("a/b");
        BindingsStore::default().save(&sub).unwrap();
        assert!(sub.join(BINDINGS_FILE).exists());
    }

    #[test]
    fn missing_file_is_default_without_warning() {
        let dir = tempfile::tempdir().unwrap();
        let (s, w) = BindingsStore::load(dir.path());
        assert_eq!(s, BindingsStore::default());
        assert_eq!(w, None);
    }

    #[test]
    fn corrupt_file_gives_defaults_and_warning() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join(BINDINGS_FILE), b"{not json").unwrap();
        let (s, w) = BindingsStore::load(dir.path());
        assert_eq!(s, BindingsStore::default());
        assert!(w.unwrap().contains("corrupt"));
        assert!(dir.path().join("bindings.json.corrupt").exists());
        // next load is clean
        let (_, w) = BindingsStore::load(dir.path());
        assert_eq!(w, None);
    }

    #[test]
    fn wrong_version_and_bad_slot_numbers_give_defaults() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join(BINDINGS_FILE), br#"{"version":99,"active":0,"slots":[]}"#).unwrap();
        let (s, w) = BindingsStore::load(dir.path());
        assert_eq!(s, BindingsStore::default());
        assert!(w.unwrap().contains("version"));
        let bad = r#"{"version":1,"active":0,"slots":[{"slot":12,"target":{"app_id":"a","app_name":"A","window_title":"","element_role":"r","ax_insertable":true}}]}"#;
        fs::write(dir.path().join(BINDINGS_FILE), bad).unwrap();
        let (_, w) = BindingsStore::load(dir.path());
        assert!(w.is_some());
    }

    #[test]
    fn legacy_bundle_id_key_and_case_insensitive_app_id() {
        let dir = tempfile::tempdir().unwrap();
        let j = r#"{"version":1,"active":0,"slots":[{"slot":1,"target":{"bundle_id":"Ms-Teams.exe","app_name":"A","window_title":"w","element_role":"r","ax_insertable":false}}]}"#;
        fs::write(dir.path().join(BINDINGS_FILE), j).unwrap();
        let (s, w) = BindingsStore::load(dir.path());
        assert_eq!(w, None);
        let t = &s.get(slot(1)).unwrap().target;
        assert_eq!(t.app_id, "Ms-Teams.exe");
        assert!(matches!(rematch(t, &[win("ms-teams.exe", "w", true, 1)]), RematchOutcome::Matched { .. }));
    }

    #[test]
    fn active_pointing_at_empty_slot_becomes_off() {
        let dir = tempfile::tempdir().unwrap();
        let j = r#"{"version":1,"active":4,"slots":[{"slot":1,"target":{"app_id":"a","app_name":"A","window_title":"w","element_role":"r","ax_insertable":false}}]}"#;
        fs::write(dir.path().join(BINDINGS_FILE), j).unwrap();
        let (s, w) = BindingsStore::load(dir.path());
        assert_eq!(w, None);
        assert_eq!(s.active(), ActiveSlot::Off);
        let r = s.get(slot(1)).unwrap();
        assert_eq!(r.target.element_subrole, "");
        assert!(!r.settings.auto_submit, "auto-submit defaults off");
    }

    #[test]
    fn newline_mode_defaults_by_app_and_persists() {
        use crate::model::NewlineMode;
        let dir = tempfile::tempdir().unwrap();
        let mut s = BindingsStore::default();
        let mut t = target("WindowsTerminal.exe", "pwsh");
        t.app_id = "WindowsTerminal.exe".into();
        s.bind(slot(1), t);
        s.bind(slot(2), target("notepad.exe", "a.txt"));
        assert_eq!(s.get(slot(1)).unwrap().settings.newline_mode, NewlineMode::Spaces);
        assert_eq!(s.get(slot(2)).unwrap().settings.newline_mode, NewlineMode::ShiftEnter);
        assert!(s.set_newline_mode(slot(2), NewlineMode::Spaces));
        assert!(!s.set_newline_mode(slot(3), NewlineMode::Spaces));
        s.save(dir.path()).unwrap();
        let (l, w) = BindingsStore::load(dir.path());
        assert!(w.is_none());
        assert_eq!(l.get(slot(1)).unwrap().settings.newline_mode, NewlineMode::Spaces);
        assert_eq!(l.get(slot(2)).unwrap().settings.newline_mode, NewlineMode::Spaces);
        // A file without the key (older) reads as the default.
        let old = br#"{"version":1,"active":1,"slots":[{"slot":1,"target":{"app_id":"a","app_name":"A","window_title":"t","element_role":"r","ax_insertable":false},"settings":{"auto_submit":true}}]}"#;
        let st = BindingsStore::parse(old).unwrap();
        assert_eq!(st.get(slot(1)).unwrap().settings.newline_mode, NewlineMode::ShiftEnter);
        assert!(st.get(slot(1)).unwrap().settings.auto_submit);
    }
}
