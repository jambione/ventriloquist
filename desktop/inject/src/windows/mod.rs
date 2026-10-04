//! Windows injector (SPEC_V2 §4.8): Win32 foreground/activation, UI
//! Automation for the focused element, `SendInput` typing and clipboard paste.
//! All FFI is in [`sys`]; this module is safe logic on top.
//!
//! Always the keystroke/paste path: `caps` reports `ax_insertable = false`.

mod sys;

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use crate::injector::{CapturedBinding, InjectError, Injector, LiveHandle, ResolvedTarget, Result};
use crate::model::{BindingTarget, DeliveryResult, SlotId, Sound, WindowInfo};
use crate::planner::{Action, AppCategory, Plan, TargetCaps};
use crate::store::{rematch, MatchKind, RematchOutcome};
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
        f if CF_GDIOBJ_RANGE.contains(&f) => false,
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

    fn windows_of(&self, app_id: &str) -> Vec<WindowInfo> {
        sys::ensure_com();
        let mut exe_cache: HashMap<u32, Option<String>> = HashMap::new();
        let mut out = Vec::new();
        for w in sys::enum_windows() {
            let exe = exe_cache.entry(w.pid).or_insert_with(|| sys::exe_name(w.pid));
            if exe.as_deref().is_some_and(|e| e.eq_ignore_ascii_case(app_id)) {
                out.push(WindowInfo {
                    app_id: app_id.to_string(),
                    pid: w.pid as i32,
                    title: w.title,
                    standard: w.standard,
                    id: w.hwnd as u64,
                });
            }
        }
        out
    }
}

/// Read the title of a window for the binding (empty if it has none).
fn window_alive(hwnd: isize, pid: u32) -> bool {
    sys::is_window(hwnd) && sys::window_pid(hwnd) == Some(pid)
}

// -------------------------------------------------------------- execution

enum StepError {
    Failed(String),
    Blocked(String),
}

struct Run {
    hwnd: isize,
    pid: u32,
    element: Option<UiaElement>,
    prev: Option<isize>,
    snapshot: Option<sys::ClipboardSnapshot>,
    set_seq: Option<u32>,
}

impl Run {
    fn focus_check(&self) -> std::result::Result<(), StepError> {
        if sys::foreground() == Some(self.hwnd) {
            Ok(())
        } else {
            Err(StepError::Failed("focus changed".into()))
        }
    }

    fn input(&self, ok: bool) -> std::result::Result<(), StepError> {
        if ok {
            Ok(())
        } else {
            Err(StepError::Failed("cannot send keyboard input".into()))
        }
    }

    fn step(&mut self, a: &Action) -> std::result::Result<(), StepError> {
        let fail = |m: &str| StepError::Failed(m.to_string());
        match a {
            Action::AxInsertSelectedText(_) => Err(fail("direct insertion is not supported on Windows")),
            Action::Activate => {
                let fg = sys::foreground();
                self.prev = fg.filter(|h| *h != self.hwnd);
                sys::activate(self.hwnd);
                Ok(())
            }
            Action::WaitFrontmost { timeout_ms } => {
                if sys::wait_foreground(self.hwnd, Duration::from_millis(*timeout_ms)) {
                    Ok(())
                } else {
                    Err(fail("could not focus target"))
                }
            }
            Action::FocusElement => {
                if let Some(e) = &self.element {
                    e.refocus();
                }
                // Whatever has focus now must not be a password field.
                if let Some(f) = sys::uia_focused() {
                    if f.pid == self.pid && f.is_password {
                        return Err(StepError::Blocked("secure text field".into()));
                    }
                }
                Ok(())
            }
            Action::TypeUnicode(s) => {
                self.focus_check()?;
                self.input(sys::send_unicode(s))
            }
            Action::ShiftReturn => {
                self.focus_check()?;
                self.input(sys::send_shift_return())
            }
            Action::Return => {
                self.focus_check()?;
                self.input(sys::send_return())
            }
            Action::SnapshotClipboard => {
                // The planner only pastes when `caps` said the clipboard is
                // restorable; if that changed since, refuse rather than lose it.
                self.snapshot = Some(sys::clipboard_snapshot().ok_or_else(|| fail("clipboard cannot be restored"))?);
                Ok(())
            }
            Action::SetClipboard(s) => {
                self.set_seq = Some(sys::clipboard_set_text(s).ok_or_else(|| fail("cannot set clipboard"))?);
                Ok(())
            }
            // Ctrl+V on Windows.
            Action::CmdV => {
                self.focus_check()?;
                self.input(sys::send_ctrl_v())?;
                // Let the target consume the paste before the clipboard changes again.
                std::thread::sleep(Duration::from_millis(60));
                Ok(())
            }
            Action::RestoreClipboardIfUnchanged { delay_ms } => {
                self.restore_clipboard(*delay_ms);
                Ok(())
            }
            Action::ReactivatePrevious => {
                if let Some(p) = self.prev.take() {
                    if sys::is_window(p) {
                        sys::activate(p);
                    }
                }
                Ok(())
            }
        }
    }

    fn restore_clipboard(&mut self, delay_ms: u64) {
        let (Some(snap), Some(seq)) = (self.snapshot.take(), self.set_seq.take()) else { return };
        std::thread::sleep(Duration::from_millis(delay_ms));
        // Someone else wrote to the clipboard meanwhile: leave it alone.
        sys::clipboard_restore_if_unchanged(&snap, seq);
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
        let focused = sys::uia_focused().ok_or(InjectError::NoFocusedElement)?;
        if focused.pid != pid {
            return Err(InjectError::NoFocusedElement);
        }
        if focused.is_password {
            return Err(InjectError::SecureField);
        }
        let target = BindingTarget {
            app_name: app_display_name(&exe),
            app_id: exe,
            window_title: sys::window_title(hwnd),
            element_role: control_type_name(focused.control_type).to_string(),
            element_subrole: focused.class_name,
            ax_insertable: false,
        };
        Ok(CapturedBinding {
            target,
            pid: pid as i32,
            live: Some(LiveHandle(Arc::new(LiveRefs { hwnd, element: Some(focused.element) }))),
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
            m.insert(slot, SlotState { target: captured.target, pid: captured.pid as u32, hwnd, element });
        }
    }

    fn assign_saved(&self, slot: SlotId, target: &BindingTarget) {
        if let Ok(mut m) = self.slots.lock() {
            m.insert(slot, SlotState { target: target.clone(), pid: 0, hwnd: None, element: None });
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
                return Ok(ResolvedTarget {
                    slot,
                    pid: st.pid as i32,
                    target: st.target,
                    rematched: false,
                    title_changed: false,
                });
            }
        }
        // Re-match on (exe, exact title), then the exe's single window (§4.6).
        let wins = self.windows_of(&st.target.app_id);
        match rematch(&st.target, &wins) {
            RematchOutcome::Matched { window, kind } => {
                let title_changed = kind == MatchKind::SingleWindow && st.target.window_title != window.title;
                if title_changed {
                    st.target.window_title = window.title.clone();
                }
                st.pid = window.pid as u32;
                st.hwnd = Some(window.id as isize);
                st.element = None;
                if let Ok(mut m) = self.slots.lock() {
                    m.insert(slot, st.clone());
                }
                Ok(ResolvedTarget { slot, target: st.target, pid: window.pid, rematched: true, title_changed })
            }
            RematchOutcome::Unbound(_) => Err(InjectError::Missing),
        }
    }

    fn caps(&self, target: &ResolvedTarget) -> Result<TargetCaps> {
        sys::ensure_com();
        let st = self.state(target.slot).ok_or(InjectError::Missing)?;
        let secure_field = st.element.as_ref().and_then(|e| e.is_password()).unwrap_or(false);
        Ok(TargetCaps {
            category: AppCategory::from_app_id(&st.target.app_id),
            ax_insertable: false,
            secure_field,
            secure_input: false,
            elevated: sys::target_is_elevated(target.pid as u32),
            clipboard_restorable: sys::clipboard_formats().is_some_and(|f| formats_restorable(&f)),
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
        let mut run = Run { hwnd, pid, element: st.element.clone(), prev: None, snapshot: None, set_seq: None };
        let mut result = Ok(());
        for a in &plan.actions {
            if let Err(e) = run.step(a) {
                result = Err(e);
                break;
            }
        }
        // Never leave our text on the clipboard or the user's app buried.
        run.restore_clipboard(crate::planner::CLIPBOARD_RESTORE_DELAY_MS);
        if result.is_err() {
            let _ = run.step(&Action::ReactivatePrevious);
        }
        match result {
            Ok(()) => DeliveryResult::Sent { method: plan.method },
            Err(StepError::Blocked(r)) => DeliveryResult::blocked(r),
            Err(StepError::Failed(r)) => DeliveryResult::failed(r),
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
        self.windows_of(app_id)
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
        assert!(formats_restorable(&[0x2FF, 0x400]));
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
