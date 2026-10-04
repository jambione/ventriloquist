//! `bindings.json` persistence and the pure re-match logic (SPEC_V2 §4.6).

use std::collections::BTreeMap;
use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use serde::{Deserialize, Serialize};

use crate::model::{
    default_follow_title, ActiveSlot, BindingTarget, SlotId, SlotSettings, WindowDetail, WindowIdentity, WindowInfo,
};

pub const BINDINGS_FILE: &str = "bindings.json";
pub const BINDINGS_VERSION: u32 = 1;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SlotRecord {
    pub slot: SlotId,
    pub target: BindingTarget,
    #[serde(default)]
    pub settings: SlotSettings,
    /// Window class / AppUserModelID for the re-match fallback (R7).
    #[serde(default)]
    pub identity: WindowIdentity,
    /// R5: when false, text is only delivered while the live window title
    /// equals `target.window_title`. Default: true for terminals only; a file
    /// without the key gets that default on load.
    #[serde(default)]
    pub follow_title_changes: bool,
}

#[derive(Serialize)]
struct FileFormat {
    version: u32,
    /// 0 = Off, 1..=9 = slot.
    active: u8,
    slots: Vec<SlotRecord>,
}

#[derive(Deserialize)]
struct FileHead {
    version: u32,
}

#[derive(Deserialize)]
struct FileBody {
    /// 0 = Off, 1..=9 = slot.
    #[serde(default)]
    active: u8,
    /// Records are parsed one by one so one bad record cannot discard the rest.
    #[serde(default)]
    slots: Vec<serde_json::Value>,
}

#[derive(Debug)]
enum ParseFailure {
    Corrupt(String),
    /// A file from another version: kept untouched.
    OtherVersion(u32),
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
    /// Set when `bindings.json` was written by another version: the file is
    /// left alone and `save` refuses until the user binds a slot (which is an
    /// explicit decision to start over).
    foreign_version: Option<u32>,
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
        self.bind_with(slot, target, WindowIdentity::default());
    }

    /// [`BindingsStore::bind`] with the window identity (class, AUMID); the
    /// class also refines the per-app defaults.
    pub fn bind_with(&mut self, slot: SlotId, target: BindingTarget, identity: WindowIdentity) {
        let settings = SlotSettings::for_app_class(&target.app_id, &identity.class);
        let follow_title_changes = default_follow_title(&target.app_id, &identity.class);
        self.slots.insert(slot, SlotRecord { slot, target, settings, identity, follow_title_changes });
        self.active = ActiveSlot::Slot(slot);
        self.foreign_version = None;
    }

    pub fn set_follow_title_changes(&mut self, slot: SlotId, on: bool) -> bool {
        match self.slots.get_mut(&slot) {
            Some(r) => {
                r.follow_title_changes = on;
                true
            }
            None => false,
        }
    }

    /// Remember the window identity of a record that has none (old file).
    pub fn fill_identity(&mut self, slot: SlotId, identity: &WindowIdentity) -> bool {
        match self.slots.get_mut(&slot) {
            Some(r) if r.identity == WindowIdentity::default() && *identity != WindowIdentity::default() => {
                r.identity = identity.clone();
                true
            }
            _ => false,
        }
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
    /// Unreadable file: defaults plus a warning. Corrupt file: defaults plus a
    /// warning, the file moved aside to a fresh `bindings.json.corrupt[.N]`
    /// (best effort). A file of another version is left untouched (defaults
    /// plus a warning, and `save` refuses until the user binds a slot). Invalid
    /// slot records are skipped with a warning; the valid ones are kept.
    pub fn load(dir: &Path) -> (Self, Option<String>) {
        let path = dir.join(BINDINGS_FILE);
        let bytes = match fs::read(&path) {
            Ok(b) => b,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return (Self::default(), None),
            Err(e) => return (Self::default(), Some(format!("cannot read {BINDINGS_FILE}: {e}"))),
        };
        match Self::parse(&bytes) {
            Ok((s, warn)) => (s, warn),
            Err(ParseFailure::OtherVersion(v)) => (
                BindingsStore { foreign_version: Some(v), ..Self::default() },
                Some(format!(
                    "{BINDINGS_FILE} ignored (unsupported version {v}); starting with no bindings, the file is left as it is"
                )),
            ),
            Err(ParseFailure::Corrupt(why)) => {
                let _ = fs::rename(&path, unique_corrupt_name(&path));
                (Self::default(), Some(format!("{BINDINGS_FILE} ignored ({why}); starting with no bindings")))
            }
        }
    }

    fn parse(bytes: &[u8]) -> Result<(Self, Option<String>), ParseFailure> {
        let head: FileHead = serde_json::from_slice(bytes).map_err(|e| ParseFailure::Corrupt(format!("corrupt: {e}")))?;
        if head.version != BINDINGS_VERSION {
            return Err(ParseFailure::OtherVersion(head.version));
        }
        let f: FileBody = serde_json::from_slice(bytes).map_err(|e| ParseFailure::Corrupt(format!("corrupt: {e}")))?;
        let mut slots = BTreeMap::new();
        let mut bad = 0usize;
        for v in f.slots {
            match serde_json::from_value::<SlotRecord>(v.clone()) {
                Ok(mut r) => {
                    // Keys missing from an older file get the per-app defaults.
                    if v.pointer("/settings/newline_mode").is_none() {
                        r.settings.newline_mode =
                            SlotSettings::for_app_class(&r.target.app_id, &r.identity.class).newline_mode;
                    }
                    if v.get("follow_title_changes").is_none() {
                        r.follow_title_changes = default_follow_title(&r.target.app_id, &r.identity.class);
                    }
                    slots.insert(r.slot, r); // a later duplicate wins
                }
                Err(e) => {
                    bad += 1;
                    log::warn!("{BINDINGS_FILE}: skipping an invalid slot record: {e}");
                }
            }
        }
        let active = match ActiveSlot::from_digit(f.active) {
            Some(ActiveSlot::Slot(s)) if slots.contains_key(&s) => ActiveSlot::Slot(s),
            _ => ActiveSlot::Off,
        };
        let warn = (bad > 0).then(|| format!("{bad} invalid slot record(s) in {BINDINGS_FILE} ignored"));
        Ok((BindingsStore { slots, active, foreign_version: None }, warn))
    }

    /// Atomic write (temp file + fsync + rename), private file mode.
    pub fn save(&self, dir: &Path) -> io::Result<()> {
        if let Some(v) = self.foreign_version {
            return Err(io::Error::other(format!(
                "{BINDINGS_FILE} was written by another version ({v}) and is left unchanged until you bind a slot"
            )));
        }
        let f = FileFormat {
            version: BINDINGS_VERSION,
            active: self.active.digit(),
            slots: self.slots.values().cloned().collect(),
        };
        let bytes = serde_json::to_vec_pretty(&f).map_err(io::Error::other)?;
        atomic_write_private(&dir.join(BINDINGS_FILE), &bytes)
    }
}

/// `bindings.json.corrupt`, or `.corrupt.1`, `.corrupt.2`... when that exists,
/// so an earlier aside copy is never overwritten.
fn unique_corrupt_name(path: &Path) -> PathBuf {
    let mk = |suffix: String| {
        let mut p = path.to_path_buf().into_os_string();
        p.push(suffix);
        PathBuf::from(p)
    };
    let first = mk(".corrupt".into());
    if !first.exists() {
        return first;
    }
    (1..1000).map(|n| mk(format!(".corrupt.{n}"))).find(|p| !p.exists()).unwrap_or(first)
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

/// Exes shared by many unrelated apps or sites: the single-window fallback
/// would pick the wrong thing (R7).
const NO_SINGLE_WINDOW_FALLBACK: &[&str] =
    &["applicationframehost.exe", "javaw.exe", "java.exe", "python.exe", "pythonw.exe", "node.exe", "electron.exe", "dotnet.exe"];

/// May the "app's only standard window" fallback be used for this app id?
/// Never for browsers (a PWA's slot must not land in a normal tab) or generic
/// host/runtime exes: those match by exact title only (R7).
pub fn single_window_fallback_allowed(app_id: &str) -> bool {
    crate::planner::AppCategory::from_app_id(app_id) != crate::planner::AppCategory::Browser
        && !NO_SINGLE_WINDOW_FALLBACK.contains(&app_id.to_lowercase().as_str())
}

/// Pure re-match (§4.6) without extra identity: see [`rematch_detail`].
pub fn rematch(saved: &BindingTarget, running_windows: &[WindowInfo]) -> RematchOutcome {
    let details: Vec<WindowDetail> = running_windows.iter().cloned().map(WindowDetail::from).collect();
    rematch_detail(saved, &WindowIdentity::default(), &details)
}

/// Pure re-match (§4.6). `running_windows` are the windows of running apps;
/// those of other app ids are ignored.
///
/// 1. windows of the app id, case-insensitively (none: unbound);
/// 2. exactly one window with the saved title (several: unbound, never
///    guess; an empty saved title never matches by title). Windows on other
///    virtual desktops count here;
/// 3. otherwise, when the fallback is allowed for the app
///    ([`single_window_fallback_allowed`]), exactly one standard window whose
///    class / AppUserModelID equal the saved ones (when both are known) and
///    which is on this desktop; other-desktop windows count for uniqueness
///    but are never picked;
/// 4. otherwise unbound.
pub fn rematch_detail(saved: &BindingTarget, saved_identity: &WindowIdentity, running_windows: &[WindowDetail]) -> RematchOutcome {
    let app = saved.app_id.to_lowercase();
    let wins: Vec<&WindowDetail> =
        running_windows.iter().filter(|w| w.info.app_id.to_lowercase() == app).collect();
    if wins.is_empty() {
        return RematchOutcome::Unbound(UnboundReason::NotRunning);
    }
    if !saved.window_title.is_empty() {
        let exact: Vec<&&WindowDetail> = wins.iter().filter(|w| w.info.title == saved.window_title).collect();
        match exact.len() {
            0 => {}
            1 => {
                return RematchOutcome::Matched { window: exact[0].info.clone(), kind: MatchKind::ExactTitle }
            }
            _ => return RematchOutcome::Unbound(UnboundReason::AmbiguousTitle),
        }
    }
    if !single_window_fallback_allowed(&saved.app_id) {
        return RematchOutcome::Unbound(UnboundReason::NoUniqueWindow);
    }
    let same = |a: &str, b: &str| a.is_empty() || b.is_empty() || a == b;
    let standard: Vec<&&WindowDetail> = wins.iter().filter(|w| w.info.standard).collect();
    if let [w] = standard.as_slice() {
        if !w.other_desktop
            && same(&saved_identity.class, &w.identity.class)
            && same(&saved_identity.aumid, &w.identity.aumid)
        {
            return RematchOutcome::Matched { window: w.info.clone(), kind: MatchKind::SingleWindow };
        }
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
        assert_eq!(s.records().count(), 0);
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
        let st = BindingsStore::parse(old).unwrap().0;
        assert_eq!(st.get(slot(1)).unwrap().settings.newline_mode, NewlineMode::ShiftEnter);
        assert!(st.get(slot(1)).unwrap().settings.auto_submit);
    }

    // ---- N3 fixes

    fn detail(app: &str, title: &str, standard: bool, id: u64, class: &str, other: bool) -> WindowDetail {
        WindowDetail {
            info: win(app, title, standard, id),
            identity: WindowIdentity { class: class.into(), aumid: String::new() },
            other_desktop: other,
        }
    }

    #[test]
    fn fallback_never_for_browsers_and_generic_hosts() {
        for app in ["chrome.exe", "msedge.exe", "com.google.Chrome", "ApplicationFrameHost.exe", "javaw.exe", "python.exe"] {
            let ws = vec![win(app, "New title", true, 1)];
            assert_eq!(rematch(&target(app, "Old"), &ws), RematchOutcome::Unbound(UnboundReason::NoUniqueWindow), "{app}");
            // exact title still works
            assert!(matches!(rematch(&target(app, "New title"), &ws), RematchOutcome::Matched { kind: MatchKind::ExactTitle, .. }));
        }
        assert!(single_window_fallback_allowed("ms-teams.exe"));
    }

    #[test]
    fn fallback_requires_matching_window_class() {
        let saved_id = WindowIdentity { class: "TeamsWnd".into(), aumid: String::new() };
        let ws = vec![detail("a", "Renamed", true, 1, "OtherClass", false)];
        assert_eq!(
            rematch_detail(&target("a", "Old"), &saved_id, &ws),
            RematchOutcome::Unbound(UnboundReason::NoUniqueWindow)
        );
        let ws = vec![detail("a", "Renamed", true, 1, "TeamsWnd", false)];
        assert!(matches!(rematch_detail(&target("a", "Old"), &saved_id, &ws), RematchOutcome::Matched { .. }));
        // unknown class on either side: not a mismatch
        assert!(matches!(
            rematch_detail(&target("a", "Old"), &WindowIdentity::default(), &ws),
            RematchOutcome::Matched { .. }
        ));
    }

    #[test]
    fn other_desktop_windows_count_but_are_never_picked_by_fallback() {
        let id = WindowIdentity::default();
        // two same-titled windows, one on another desktop: ambiguous
        let ws = vec![detail("a", "Chat", true, 1, "", false), detail("a", "Chat", true, 2, "", true)];
        assert_eq!(rematch_detail(&target("a", "Chat"), &id, &ws), RematchOutcome::Unbound(UnboundReason::AmbiguousTitle));
        // the only other standard window is on another desktop: not picked
        let ws = vec![detail("a", "Renamed", true, 1, "", true)];
        assert_eq!(rematch_detail(&target("a", "Old"), &id, &ws), RematchOutcome::Unbound(UnboundReason::NoUniqueWindow));
        // one here, one there: not unique
        let ws = vec![detail("a", "X", true, 1, "", false), detail("a", "Y", true, 2, "", true)];
        assert_eq!(rematch_detail(&target("a", "Old"), &id, &ws), RematchOutcome::Unbound(UnboundReason::NoUniqueWindow));
    }

    #[test]
    fn follow_title_default_and_missing_key_migration() {
        let mut s = BindingsStore::default();
        s.bind(slot(1), target("WindowsTerminal.exe", "pwsh"));
        s.bind(slot(2), target("ms-teams.exe", "Chat"));
        assert!(s.get(slot(1)).unwrap().follow_title_changes);
        assert!(!s.get(slot(2)).unwrap().follow_title_changes);
        assert!(s.set_follow_title_changes(slot(2), true));
        assert!(!s.set_follow_title_changes(slot(3), true));
        let dir = tempfile::tempdir().unwrap();
        s.save(dir.path()).unwrap();
        let (l, _) = BindingsStore::load(dir.path());
        assert!(l.get(slot(2)).unwrap().follow_title_changes, "explicit value persists");
        // a file without the key: terminal true, others false
        let j = r#"{"version":1,"active":0,"slots":[
          {"slot":1,"target":{"app_id":"cmd.exe","app_name":"c","window_title":"w","element_role":"r","ax_insertable":false}},
          {"slot":2,"target":{"app_id":"x.exe","app_name":"c","window_title":"w","element_role":"r","ax_insertable":false}}]}"#;
        fs::write(dir.path().join(BINDINGS_FILE), j).unwrap();
        let (l, w) = BindingsStore::load(dir.path());
        assert!(w.is_none());
        assert!(l.get(slot(1)).unwrap().follow_title_changes);
        assert!(!l.get(slot(2)).unwrap().follow_title_changes);
    }

    #[test]
    fn newer_version_blocks_save_until_bind() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join(BINDINGS_FILE);
        let body = r#"{"version":2,"slots":"future format"}"#;
        fs::write(&p, body).unwrap();
        let (mut s, w) = BindingsStore::load(dir.path());
        assert!(w.unwrap().contains("version"));
        assert_eq!(fs::read_to_string(&p).unwrap(), body);
        assert!(s.save(dir.path()).is_err());
        assert_eq!(fs::read_to_string(&p).unwrap(), body, "not overwritten");
        s.bind(slot(1), target("a", "w"));
        s.save(dir.path()).unwrap();
    }

    #[test]
    fn corrupt_files_never_overwrite_an_earlier_aside_copy() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join(BINDINGS_FILE);
        fs::write(&p, b"{first").unwrap();
        BindingsStore::load(dir.path());
        fs::write(&p, b"{second").unwrap();
        BindingsStore::load(dir.path());
        assert_eq!(fs::read(dir.path().join("bindings.json.corrupt")).unwrap(), b"{first");
        assert_eq!(fs::read(dir.path().join("bindings.json.corrupt.1")).unwrap(), b"{second");
    }

    #[test]
    fn bad_slot_records_are_skipped_with_a_warning() {
        let dir = tempfile::tempdir().unwrap();
        let j = r#"{"version":1,"active":1,"slots":[
          {"slot":1,"target":{"app_id":"a","app_name":"A","window_title":"w","element_role":"r","ax_insertable":false}},
          {"slot":3},{"slot":10,"target":{"app_id":"a","app_name":"A","window_title":"w","element_role":"r","ax_insertable":false}}]}"#;
        fs::write(dir.path().join(BINDINGS_FILE), j).unwrap();
        let (s, w) = BindingsStore::load(dir.path());
        assert!(w.unwrap().contains("2 invalid"));
        assert_eq!(s.records().count(), 1);
        assert_eq!(s.active(), ActiveSlot::Slot(slot(1)));
        assert!(dir.path().join(BINDINGS_FILE).exists());
    }

    #[test]
    fn window_class_refines_defaults_and_identity_fill() {
        use crate::model::NewlineMode;
        let mut s = BindingsStore::default();
        let id = WindowIdentity { class: "ConsoleWindowClass".into(), aumid: String::new() };
        s.bind_with(slot(1), target("python.exe", "py"), id.clone());
        let r = s.get(slot(1)).unwrap();
        assert_eq!(r.settings.newline_mode, NewlineMode::Spaces);
        assert!(r.follow_title_changes);
        s.bind(slot(2), target("a", "w"));
        assert!(s.fill_identity(slot(2), &id));
        assert!(!s.fill_identity(slot(2), &WindowIdentity { class: "other".into(), aumid: String::new() }));
    }
}
