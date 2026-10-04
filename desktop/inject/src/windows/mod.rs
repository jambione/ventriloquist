//! Windows injector (SPEC_V2 §4.8): Win32 foreground/activation, UI
//! Automation for the focused element, `SendInput` typing and clipboard paste.
//! All FFI is in [`sys`]; this module is safe logic on top.
//!
//! Always the keystroke/paste path: `caps` reports `ax_insertable = false`.

mod sys;

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use crate::exec::{plan_sends_input, Os, Run, StepError};
use crate::injector::{CapturedBinding, InjectError, Injector, LiveHandle, ResolvedTarget, Result};
use crate::model::{BindingTarget, DeliveryResult, SlotId, Sound, WindowDetail, WindowIdentity, WindowInfo};
use crate::planner::{category_for, Plan, TargetCaps};
use crate::policy::{password_verdict_strict, wait_for_idle, FocusProbe, IDLE_MAX_WAIT_MS, IDLE_REQUIRED_MS};
use crate::store::{rematch_detail, MatchKind, RematchOutcome};
use sys::UiaElement;

// ------------------------------------------------------------ pure helpers

/// File name part of a Windows path (`C:\Windows\notepad.exe` -> `notepad.exe`).
fn file_name_of(path: &str) -> String {
    path.rsplit(['\\', '/']).next().unwrap_or(path).to_string()
}

/// `notepad.exe` -> `notepad`.
fn app_display_name(exe: &str) -> String {
    match exe.rsplit_once('.') {
        Some((stem, ext)) if ext.eq_ignore_ascii_case("exe") && !stem.is_empty() => stem.to_string(),
        _ => exe.to_string(),
    }
}

const CF_BITMAP: u32 = 2;
const CF_METAFILEPICT: u32 = 3;
const CF_DIB: u32 = 8;
const CF_PALETTE: u32 = 9;
const CF_ENHMETAFILE: u32 = 14;
const CF_DIBV5: u32 = 17;
const CF_OWNERDISPLAY: u32 = 0x80;
const CF_DSPBITMAP: u32 = 0x82;
const CF_DSPMETAFILEPICT: u32 = 0x83;
const CF_DSPENHMETAFILE: u32 = 0x8E;
const CF_GDIOBJ_RANGE: std::ops::RangeInclusive<u32> = 0x300..=0x3FF;
/// `CF_PRIVATEFIRST..=CF_PRIVATELAST`: owner-defined, not necessarily HGLOBAL.
const CF_PRIVATE_RANGE: std::ops::RangeInclusive<u32> = 0x200..=0x2FF;

fn has_dib(formats: &[u32]) -> bool {
    formats.iter().any(|f| *f == CF_DIB || *f == CF_DIBV5)
}

/// Windows synthesises `CF_BITMAP` and `CF_PALETTE` from a DIB, so they need
/// not be saved when a DIB is present.
fn is_synthesizable_from_dib(f: u32) -> bool {
    f == CF_BITMAP || f == CF_PALETTE
}

/// Can every format on the clipboard be copied as plain bytes (HGLOBAL)?
/// GDI-handle formats (bitmaps without a DIB, metafiles, palettes, owner
/// display, `CF_GDIOBJ*`) cannot, so we must not overwrite them (§4.8).
fn formats_restorable(formats: &[u32]) -> bool {
    let dib = has_dib(formats);
    formats.iter().all(|&f| match f {
        CF_BITMAP | CF_PALETTE => dib,
        CF_METAFILEPICT | CF_ENHMETAFILE | CF_OWNERDISPLAY | CF_DSPBITMAP | CF_DSPMETAFILEPICT
        | CF_DSPENHMETAFILE => false,
        f if CF_GDIOBJ_RANGE.contains(&f) || CF_PRIVATE_RANGE.contains(&f) => false,
        _ => true,
    })
}

/// UIA ControlType id -> name (used as `element_role`).
fn control_type_name(id: i32) -> &'static str {
    match id {
        50000 => "Button",
        50004 => "Edit",
        50007 => "ListItem",
        50003 => "ComboBox",
        50025 => "Custom",
        50026 => "Group",
        50030 => "Document",
        50032 => "Window",
        50033 => "Pane",
        50020 => "Text",
        50021 => "ToolBar",
        50018 => "Tab",
        50019 => "TabItem",
        _ => "Unknown",
    }
}

// ------------------------------------------------------------------ state

struct LiveRefs {
    hwnd: isize,
    element: Option<UiaElement>,
}

#[derive(Clone)]
struct SlotState {
    target: BindingTarget,
    identity: WindowIdentity,
    pid: u32,
    hwnd: Option<isize>,
    element: Option<UiaElement>,
}

#[derive(Default)]
pub struct WindowsInjector {
    slots: Mutex<HashMap<SlotId, SlotState>>,
}

impl WindowsInjector {
    pub fn new() -> Self {
        sys::ensure_com();
        Self::default()
    }

    fn state(&self, slot: SlotId) -> Option<SlotState> {
        self.slots.lock().ok()?.get(&slot).cloned()
    }

    /// Windows of `app_id` (case-insensitive), including those on other
    /// virtual desktops (flagged), with class and AppUserModelID.
    fn details_of(&self, app_id: &str) -> Vec<WindowDetail> {
        sys::ensure_com();
        let want = app_id.to_lowercase();
        let mut exe_cache: HashMap<u32, Option<String>> = HashMap::new();
        let mut aumid_cache: HashMap<u32, String> = HashMap::new();
        let mut out = Vec::new();
        for w in sys::enum_windows() {
            let exe = exe_cache.entry(w.pid).or_insert_with(|| sys::exe_name(w.pid));
            if exe.as_deref().is_some_and(|e| e.to_lowercase() == want) {
                let aumid = aumid_cache.entry(w.pid).or_insert_with(|| sys::aumid(w.pid)).clone();
                out.push(WindowDetail {
                    info: WindowInfo {
                        app_id: app_id.to_string(),
                        pid: w.pid as i32,
                        title: w.title,
                        standard: w.standard,
                        id: w.hwnd as u64,
                    },
                    identity: WindowIdentity { class: sys::class_name(w.hwnd), aumid },
                    other_desktop: w.other_desktop,
                });
            }
        }
        out
    }
}

/// The window still exists and belongs to the same process.
fn window_alive(hwnd: isize, pid: u32) -> bool {
    sys::is_window(hwnd) && sys::window_pid(hwnd) == Some(pid)
}

// -------------------------------------------------------------- execution

fn probe(f: Option<&sys::FocusedInfo>) -> FocusProbe {
    match f {
        None => FocusProbe::Unknown,
        Some(f) => FocusProbe::Element { is_password: f.is_password },
    }
}

fn epoch_ms() -> u64 {
    static START: std::sync::OnceLock<std::time::Instant> = std::sync::OnceLock::new();
    START.get_or_init(std::time::Instant::now).elapsed().as_millis() as u64
}

/// The Windows primitives for [`Run`].
struct WinOs {
    hwnd: isize,
    element: Option<UiaElement>,
    prev: Option<isize>,
    snapshot: Option<sys::ClipboardSnapshot>,
    set_seq: Option<u32>,
    focus_id: Option<Vec<i32>>,
    /// Keeps the low-level hooks alive for the whole delivery.
    watch: sys::InputWatch,
}

impl Os for WinOs {
    fn activate(&mut self) {
        let fg = sys::foreground();
        self.prev = fg.filter(|h| *h != self.hwnd);
        sys::activate(self.hwnd);
    }

    fn foreground_is_target(&mut self) -> bool {
        sys::foreground() == Some(self.hwnd)
    }

    fn wait_foreground(&mut self, timeout_ms: u64) -> bool {
        sys::wait_foreground(self.hwnd, Duration::from_millis(timeout_ms))
    }

    /// R1: whatever UIA says has focus (it may belong to another process: a
    /// WebView2, a UWP app host, conhost) must be known not to be a password
    /// field; if that cannot be determined the delivery is refused.
    fn focus_element(&mut self) -> std::result::Result<(), StepError> {
        if let Some(e) = &self.element {
            e.refocus();
        }
        let f = sys::uia_focused();
        password_verdict_strict(probe(f.as_ref())).map_err(StepError::Blocked)?;
        self.focus_id = f.map(|f| f.runtime_id).filter(|id| !id.is_empty());
        Ok(())
    }

    fn focus_unchanged(&mut self) -> bool {
        match &self.focus_id {
            None => true,
            Some(id) => sys::uia_focused().is_some_and(|f| &f.runtime_id == id),
        }
    }

    fn physical_input(&mut self) -> bool {
        self.watch.physical_seen()
    }

    fn modifiers_released(&mut self) -> bool {
        sys::wait_modifiers_released(Duration::from_millis(1000))
    }

    fn send_text(&mut self, s: &str) -> bool {
        sys::send_unicode(s)
    }
    fn send_shift_return(&mut self) -> bool {
        sys::send_shift_return()
    }
    fn send_return(&mut self) -> bool {
        sys::send_return()
    }
    fn send_paste(&mut self) -> bool {
        sys::send_ctrl_v()
    }

    fn clipboard_snapshot(&mut self) -> bool {
        self.snapshot = sys::clipboard_snapshot();
        self.snapshot.is_some()
    }

    fn clipboard_set(&mut self, text: &str) -> bool {
        self.set_seq = sys::clipboard_set_text(text);
        self.set_seq.is_some()
    }

    fn clipboard_unchanged(&mut self) -> bool {
        self.set_seq.is_some_and(|s| sys::clipboard_sequence() == s)
    }

    fn clipboard_restore_if_unchanged(&mut self) {
        let (Some(snap), Some(seq)) = (self.snapshot.take(), self.set_seq.take()) else { return };
        // Someone else wrote to the clipboard meanwhile: leave it alone.
        sys::clipboard_restore_if_unchanged(&snap, seq);
    }

    fn reactivate_previous(&mut self) {
        if let Some(p) = self.prev.take() {
            if sys::is_window(p) {
                sys::activate(p);
            }
        }
    }

    fn sleep_ms(&mut self, ms: u64) {
        std::thread::sleep(Duration::from_millis(ms));
    }

    fn now_ms(&mut self) -> u64 {
        epoch_ms()
    }
}

impl Injector for WindowsInjector {
    fn capture_focused(&self) -> Result<CapturedBinding> {
        sys::ensure_com();
        let hwnd = sys::foreground().ok_or_else(|| InjectError::Platform("no foreground window".into()))?;
        let pid = sys::window_pid(hwnd).ok_or_else(|| InjectError::Platform("foreground window not found".into()))?;
        if pid == sys::own_pid() {
            return Err(InjectError::SelfFrontmost);
        }
        if sys::target_is_elevated(pid) {
            return Err(InjectError::Platform("target is elevated".into()));
        }
        let exe = sys::exe_name(pid).ok_or_else(|| InjectError::Platform("cannot identify the foreground app".into()))?;
        // The focused element may belong to another process (WebView2, UWP
        // host, conhost): it is used regardless of its pid. If UIA reports
        // none, bind at window level; the password check at delivery time
        // then decides (fail closed).
        let focused = sys::uia_focused();
        if focused.as_ref().is_some_and(|f| f.is_password == Some(true)) {
            return Err(InjectError::SecureField);
        }
        let (role, subrole, element) = match focused {
            Some(f) => (control_type_name(f.control_type).to_string(), f.class_name, Some(f.element)),
            None => ("Window".to_string(), String::new(), None),
        };
        let identity = WindowIdentity { class: sys::class_name(hwnd), aumid: sys::aumid(pid) };
        let target = BindingTarget {
            app_name: app_display_name(&exe),
            app_id: exe,
            window_title: sys::window_title(hwnd),
            element_role: role,
            element_subrole: subrole,
            ax_insertable: false,
        };
        Ok(CapturedBinding {
            target,
            identity,
            pid: pid as i32,
            live: Some(LiveHandle(Arc::new(LiveRefs { hwnd, element }))),
        })
    }

    fn assign(&self, slot: SlotId, captured: CapturedBinding) {
        let (hwnd, element) = captured
            .live
            .as_ref()
            .and_then(|l| l.0.downcast_ref::<LiveRefs>())
            .map(|l| (Some(l.hwnd), l.element.clone()))
            .unwrap_or((None, None));
        if let Ok(mut m) = self.slots.lock() {
            m.insert(
                slot,
                SlotState { target: captured.target, identity: captured.identity, pid: captured.pid as u32, hwnd, element },
            );
        }
    }

    fn assign_saved(&self, slot: SlotId, target: &BindingTarget, identity: &WindowIdentity) {
        if let Ok(mut m) = self.slots.lock() {
            m.insert(
                slot,
                SlotState { target: target.clone(), identity: identity.clone(), pid: 0, hwnd: None, element: None },
            );
        }
    }

    fn release(&self, slot: SlotId) {
        if let Ok(mut m) = self.slots.lock() {
            m.remove(&slot);
        }
    }

    fn resolve(&self, slot: SlotId) -> Result<ResolvedTarget> {
        sys::ensure_com();
        let mut st = self.state(slot).ok_or(InjectError::Missing)?;
        // Valid while the window exists and its pid is unchanged (§4.8).
        if let Some(h) = st.hwnd {
            if window_alive(h, st.pid) {
                let live_title = sys::window_title(h);
                let title_changed = live_title != st.target.window_title;
                return Ok(ResolvedTarget {
                    slot,
                    pid: st.pid as i32,
                    target: st.target,
                    identity: st.identity,
                    live_title,
                    rematched: false,
                    title_changed,
                });
            }
        }
        // Re-match on (exe, exact title), then the exe's single window (§4.6).
        let wins = self.details_of(&st.target.app_id);
        match rematch_detail(&st.target, &st.identity, &wins) {
            RematchOutcome::Matched { window, kind } => {
                let live_title = window.title.clone();
                let title_changed = kind == MatchKind::SingleWindow && st.target.window_title != window.title;
                if let Some(d) = wins.iter().find(|d| d.info.id == window.id) {
                    if st.identity == WindowIdentity::default() {
                        st.identity = d.identity.clone();
                    }
                }
                st.pid = window.pid as u32;
                st.hwnd = Some(window.id as isize);
                st.element = None;
                if let Ok(mut m) = self.slots.lock() {
                    m.insert(slot, st.clone());
                }
                Ok(ResolvedTarget {
                    slot,
                    target: st.target,
                    identity: st.identity,
                    live_title,
                    pid: window.pid,
                    rematched: true,
                    title_changed,
                })
            }
            RematchOutcome::Unbound(_) => Err(InjectError::Missing),
        }
    }

    fn caps(&self, target: &ResolvedTarget) -> Result<TargetCaps> {
        sys::ensure_com();
        let st = self.state(target.slot).ok_or(InjectError::Missing)?;
        let secure_field = st.element.as_ref().and_then(|e| e.is_password()).unwrap_or(false);
        let class = st.hwnd.map(sys::class_name).unwrap_or_else(|| st.identity.class.clone());
        Ok(TargetCaps {
            category: category_for(&st.target.app_id, &class),
            ax_insertable: false,
            secure_field,
            secure_input: false,
            elevated: sys::target_is_elevated(target.pid as u32),
            clipboard_restorable: sys::clipboard_restorable(),
        })
    }

    fn execute(&self, plan: &Plan, target: &ResolvedTarget) -> DeliveryResult {
        sys::ensure_com();
        if let Some(r) = &plan.blocked {
            return DeliveryResult::blocked(r.clone());
        }
        if plan.is_noop() {
            return DeliveryResult::Sent { method: plan.method };
        }
        let Some(st) = self.state(target.slot) else { return DeliveryResult::Missing };
        let pid = target.pid as u32;
        let Some(hwnd) = st.hwnd.filter(|h| window_alive(*h, pid)) else { return DeliveryResult::Missing };
        if pid == sys::own_pid() {
            return DeliveryResult::blocked("target is Ventriloquist itself");
        }
        // Before activating anything (§4.8).
        if sys::target_is_elevated(pid) {
            return DeliveryResult::blocked("target is elevated");
        }
        // R4a: let the user finish typing before we take the focus.
        if plan_sends_input(plan) {
            wait_for_idle(sys::idle_ms, |ms| std::thread::sleep(Duration::from_millis(ms)), IDLE_REQUIRED_MS, IDLE_MAX_WAIT_MS);
        }
        let os = WinOs {
            hwnd,
            element: st.element.clone(),
            prev: None,
            snapshot: None,
            set_seq: None,
            focus_id: None,
            watch: sys::InputWatch::start(),
        };
        let result = Run::new(os).run(&plan.actions);
        match result {
            Ok(()) => DeliveryResult::Sent { method: plan.method },
            Err(StepError::Blocked(r)) => DeliveryResult::blocked(r),
            Err(StepError::Failed(r)) => DeliveryResult::failed(r),
            Err(StepError::AxUnconfirmed) => DeliveryResult::failed("direct insertion is not supported on Windows"),
        }
    }

    /// No permission prompt on Windows.
    fn is_trusted(&self, _prompt: bool) -> bool {
        true
    }

    /// No system-wide secure event input on Windows.
    fn secure_input_enabled(&self) -> bool {
        false
    }

    fn running_windows(&self, app_id: &str) -> Vec<WindowInfo> {
        self.details_of(app_id).into_iter().map(|d| d.info).collect()
    }

    fn window_details(&self, app_id: &str) -> Vec<WindowDetail> {
        self.details_of(app_id)
    }

    fn play_sound(&self, sound: Sound) {
        sys::play_alias(sound.windows_alias());
    }
}

/// Test support for `tests/win_it.rs`: text of the Edit/Document control
/// under `hwnd` via UIA. Not part of the stable API.
#[doc(hidden)]
pub fn window_text(hwnd: isize) -> Option<String> {
    sys::ensure_com();
    sys::window_text(hwnd)
}

/// Test support: bring `hwnd` forward and wait until it is the foreground window.
#[doc(hidden)]
pub fn test_activate(hwnd: isize) -> bool {
    sys::activate(hwnd);
    sys::wait_foreground(hwnd, Duration::from_millis(2000))
}

/// Test support: set / read the clipboard text.
#[doc(hidden)]
pub fn test_clipboard_set(text: &str) -> bool {
    sys::clipboard_set_text(text).is_some()
}

#[doc(hidden)]
pub fn test_clipboard_get() -> Option<String> {
    sys::clipboard_get_text()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::planner::FRONTMOST_TIMEOUT_MS;

    #[test]
    fn file_names() {
        assert_eq!(file_name_of(r"C:\Windows\System32\notepad.exe"), "notepad.exe");
        assert_eq!(file_name_of("notepad.exe"), "notepad.exe");
        assert_eq!(file_name_of(r"C:\a b\Code - Insiders.exe"), "Code - Insiders.exe");
        assert_eq!(app_display_name("notepad.exe"), "notepad");
        assert_eq!(app_display_name("ms-teams.EXE"), "ms-teams");
        assert_eq!(app_display_name("weird"), "weird");
    }

    #[test]
    fn clipboard_format_restorability() {
        const CF_TEXT: u32 = 1;
        const CF_UNICODETEXT: u32 = 13;
        const CF_HDROP: u32 = 15;
        assert!(formats_restorable(&[]));
        assert!(formats_restorable(&[CF_TEXT, CF_UNICODETEXT, 0xC001]));
        assert!(formats_restorable(&[CF_HDROP]));
        // Image with a DIB: the synthesised bitmap/palette are fine.
        assert!(formats_restorable(&[CF_DIB, CF_BITMAP, CF_PALETTE, CF_DIBV5]));
        // GDI handles without a DIB, metafiles, owner-display, GDI object range.
        assert!(!formats_restorable(&[CF_BITMAP]));
        assert!(!formats_restorable(&[CF_PALETTE, CF_UNICODETEXT]));
        assert!(!formats_restorable(&[CF_UNICODETEXT, CF_ENHMETAFILE]));
        assert!(!formats_restorable(&[CF_METAFILEPICT]));
        assert!(!formats_restorable(&[CF_OWNERDISPLAY]));
        assert!(!formats_restorable(&[CF_DSPBITMAP]));
        assert!(!formats_restorable(&[0x300]));
        assert!(!formats_restorable(&[CF_DIB, 0x3FF]));
        assert!(formats_restorable(&[0x400, 0xC001]));
        // Private formats are not necessarily HGLOBAL.
        assert!(!formats_restorable(&[0x200]));
        assert!(!formats_restorable(&[CF_UNICODETEXT, 0x2FF]));
    }

    #[test]
    fn control_types() {
        assert_eq!(control_type_name(50004), "Edit");
        assert_eq!(control_type_name(50030), "Document");
        assert_eq!(control_type_name(1), "Unknown");
    }

    #[test]
    fn sound_aliases() {
        assert_eq!(Sound::Selected.windows_alias(), "SystemAsterisk");
        assert_eq!(Sound::Empty.windows_alias(), "SystemHand");
        assert_eq!(Sound::Error.windows_alias(), "SystemHand");
        assert_eq!(Sound::Off.windows_alias(), "SystemExclamation");
    }

    #[test]
    fn frontmost_timeout_matches_spec() {
        assert_eq!(FRONTMOST_TIMEOUT_MS, 500);
    }
}
