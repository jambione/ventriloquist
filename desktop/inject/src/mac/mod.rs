//! macOS injector: Accessibility + CGEvent + NSPasteboard + NSWorkspace.
//! All FFI is in [`sys`]; this module is safe logic on top.

mod sys;

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use crate::injector::{CapturedBinding, InjectError, Injector, LiveHandle, ResolvedTarget, Result};
use crate::model::{BindingTarget, DeliveryResult, SlotId, Sound, WindowInfo};
use crate::planner::{AppCategory, Action, Plan, TargetCaps};
use crate::store::{rematch, MatchKind, RematchOutcome};
use sys::AxElement;

const TEXT_ROLES: &[&str] = &["AXTextField", "AXTextArea", "AXComboBox"];
const SECURE_SUBROLE: &str = "AXSecureTextField";
const STANDARD_WINDOW: &str = "AXStandardWindow";

/// Live AX references of one capture.
struct LiveRefs {
    window: Option<AxElement>,
    element: Option<AxElement>,
}

#[derive(Clone)]
struct SlotState {
    target: BindingTarget,
    pid: i32,
    window: Option<AxElement>,
    element: Option<AxElement>,
}

#[derive(Default)]
pub struct MacInjector {
    slots: Mutex<HashMap<SlotId, SlotState>>,
}

impl MacInjector {
    pub fn new() -> Self {
        Self::default()
    }

    fn state(&self, slot: SlotId) -> Option<SlotState> {
        self.slots.lock().ok()?.get(&slot).cloned()
    }

    fn windows_with_refs(&self, app_id: &str) -> Vec<(WindowInfo, AxElement)> {
        let mut out = Vec::new();
        let mut id = 0u64;
        for pid in sys::pids_for_bundle(app_id) {
            let Some(app) = AxElement::application(pid) else { continue };
            for w in app.attr_elements("AXWindows") {
                let title = w.attr_string("AXTitle").unwrap_or_default();
                let standard = w.attr_string("AXSubrole").as_deref() == Some(STANDARD_WINDOW);
                out.push((WindowInfo { app_id: app_id.to_string(), pid, title, standard, id }, w));
                id += 1;
            }
        }
        out
    }
}

fn window_alive(w: &AxElement) -> bool {
    match w.pid() {
        Some(pid) if sys::app_for_pid(pid).is_some() => w.attr_string("AXRole").is_some(),
        _ => false,
    }
}

fn is_secure(el: &AxElement) -> bool {
    el.attr_string("AXSubrole").as_deref() == Some(SECURE_SUBROLE)
}

fn ax_insertable(el: &AxElement) -> bool {
    let role = el.attr_string("AXRole").unwrap_or_default();
    TEXT_ROLES.contains(&role.as_str()) && !is_secure(el) && el.is_settable("AXSelectedText")
}

/// The element to deliver to: the live bound element if still valid, else the
/// window's focused element when its role matches the saved role (§4.6).
fn current_element(st: &SlotState) -> Option<AxElement> {
    if let Some(e) = &st.element {
        if e.attr_string("AXRole").is_some() {
            return Some(e.clone());
        }
    }
    let w = st.window.as_ref()?;
    let app = AxElement::application(st.pid)?;
    let focused = app.attr_element("AXFocusedUIElement").or_else(|| w.attr_element("AXFocusedUIElement"))?;
    (focused.attr_string("AXRole").as_deref() == Some(st.target.element_role.as_str())).then_some(focused)
}

enum StepError {
    /// AX insertion failed or could not be confirmed: use the fallback.
    AxUnconfirmed,
    Failed(String),
}

struct Run {
    pid: i32,
    st: SlotState,
    prev_pid: Option<i32>,
    snapshot: Option<sys::PasteboardSnapshot>,
    set_count: Option<isize>,
}

impl Run {
    fn focus_check(&self) -> std::result::Result<(), StepError> {
        if sys::frontmost_pid() == Some(self.pid) {
            Ok(())
        } else {
            Err(StepError::Failed("focus changed".into()))
        }
    }

    fn step(&mut self, a: &Action) -> std::result::Result<(), StepError> {
        let fail = |m: &str| StepError::Failed(m.to_string());
        match a {
            Action::AxInsertSelectedText(text) => {
                let el = current_element(&self.st).ok_or(StepError::AxUnconfirmed)?;
                if is_secure(&el) {
                    return Err(fail("secure text field"));
                }
                let before = el.attr_string("AXValue");
                if !el.set_string("AXSelectedText", text) {
                    return Err(StepError::AxUnconfirmed);
                }
                let after = el.attr_string("AXValue");
                match (before, after) {
                    (Some(b), Some(a)) if a != b => Ok(()),
                    _ => Err(StepError::AxUnconfirmed),
                }
            }
            Action::Activate => {
                let front = sys::frontmost_pid();
                self.prev_pid = front.filter(|p| *p != self.pid);
                sys::activate_pid(self.pid);
                if let Some(w) = &self.st.window {
                    w.perform("AXRaise");
                }
                Ok(())
            }
            Action::WaitFrontmost { timeout_ms } => {
                let end = Instant::now() + Duration::from_millis(*timeout_ms);
                loop {
                    if sys::frontmost_pid() == Some(self.pid) {
                        return Ok(());
                    }
                    if Instant::now() >= end {
                        return Err(fail("target did not become frontmost"));
                    }
                    std::thread::sleep(Duration::from_millis(25));
                }
            }
            Action::FocusElement => {
                if let Some(e) = &self.st.element {
                    if e.attr_string("AXRole").is_some() {
                        e.set_bool("AXFocused", true);
                    }
                }
                Ok(())
            }
            Action::TypeUnicode(s) => {
                self.focus_check()?;
                sys::post_unicode(s).then_some(()).ok_or_else(|| fail("cannot post keyboard event"))
            }
            Action::ShiftReturn => {
                self.focus_check()?;
                sys::post_key(sys::KEY_RETURN, sys::Mods::Shift).then_some(()).ok_or_else(|| fail("cannot post keyboard event"))
            }
            Action::Return => {
                self.focus_check()?;
                sys::post_key(sys::KEY_RETURN, sys::Mods::None).then_some(()).ok_or_else(|| fail("cannot post keyboard event"))
            }
            Action::SnapshotClipboard => {
                self.snapshot = Some(sys::pasteboard_snapshot());
                Ok(())
            }
            Action::SetClipboard(s) => {
                self.set_count = Some(sys::pasteboard_set_text(s).ok_or_else(|| fail("cannot set clipboard"))?);
                Ok(())
            }
            Action::CmdV => {
                self.focus_check()?;
                if !sys::post_key(sys::KEY_V, sys::Mods::Cmd) {
                    return Err(fail("cannot post keyboard event"));
                }
                // Let the target consume the paste before the clipboard changes again.
                std::thread::sleep(Duration::from_millis(60));
                Ok(())
            }
            Action::RestoreClipboardIfUnchanged { delay_ms } => {
                self.restore_clipboard(*delay_ms);
                Ok(())
            }
            Action::ReactivatePrevious => {
                if let Some(p) = self.prev_pid.take() {
                    if sys::app_for_pid(p).is_some() {
                        sys::activate_pid(p);
                    }
                }
                Ok(())
            }
        }
    }

    fn restore_clipboard(&mut self, delay_ms: u64) {
        let (Some(snap), Some(count)) = (self.snapshot.take(), self.set_count.take()) else { return };
        std::thread::sleep(Duration::from_millis(delay_ms));
        // Someone else wrote to the clipboard meanwhile: leave it alone.
        if sys::pasteboard_change_count() == count {
            sys::pasteboard_restore(&snap);
        }
    }
}

impl MacInjector {
    fn run_plan(&self, plan: &Plan, st: &SlotState) -> DeliveryResult {
        let mut run = Run { pid: st.pid, st: st.clone(), prev_pid: None, snapshot: None, set_count: None };
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
            Err(StepError::AxUnconfirmed) => match &plan.fallback {
                Some(fb) => self.run_plan(fb, st),
                None => DeliveryResult::failed("accessibility insertion failed"),
            },
            Err(StepError::Failed(r)) => DeliveryResult::failed(r),
        }
    }
}

impl Injector for MacInjector {
    fn capture_focused(&self) -> Result<CapturedBinding> {
        if !sys::is_trusted(false) {
            return Err(InjectError::NotTrusted);
        }
        let pid = sys::frontmost_pid().ok_or_else(|| InjectError::Platform("no frontmost app".into()))?;
        if pid as u32 == std::process::id() {
            return Err(InjectError::SelfFrontmost);
        }
        let info = sys::app_for_pid(pid).ok_or_else(|| InjectError::Platform("frontmost app not found".into()))?;
        let app = AxElement::application(pid).ok_or_else(|| InjectError::Platform("cannot inspect app".into()))?;
        let window = app.attr_element("AXFocusedWindow");
        let element = app.attr_element("AXFocusedUIElement").ok_or(InjectError::NoFocusedElement)?;
        if is_secure(&element) {
            return Err(InjectError::SecureField);
        }
        let target = BindingTarget {
            app_id: info.bundle_id,
            app_name: info.name,
            window_title: window.as_ref().and_then(|w| w.attr_string("AXTitle")).unwrap_or_default(),
            element_role: element.attr_string("AXRole").unwrap_or_default(),
            element_subrole: element.attr_string("AXSubrole").unwrap_or_default(),
            ax_insertable: ax_insertable(&element),
        };
        Ok(CapturedBinding {
            target,
            pid,
            live: Some(LiveHandle(Arc::new(LiveRefs { window, element: Some(element) }))),
        })
    }

    fn assign(&self, slot: SlotId, captured: CapturedBinding) {
        let (window, element) = captured
            .live
            .as_ref()
            .and_then(|l| l.0.downcast_ref::<LiveRefs>())
            .map(|l| (l.window.clone(), l.element.clone()))
            .unwrap_or((None, None));
        if let Ok(mut m) = self.slots.lock() {
            m.insert(slot, SlotState { target: captured.target, pid: captured.pid, window, element });
        }
    }

    fn assign_saved(&self, slot: SlotId, target: &BindingTarget) {
        if let Ok(mut m) = self.slots.lock() {
            m.insert(slot, SlotState { target: target.clone(), pid: 0, window: None, element: None });
        }
    }

    fn release(&self, slot: SlotId) {
        if let Ok(mut m) = self.slots.lock() {
            m.remove(&slot);
        }
    }

    fn resolve(&self, slot: SlotId) -> Result<ResolvedTarget> {
        if !sys::is_trusted(false) {
            return Err(InjectError::NotTrusted);
        }
        let mut st = self.state(slot).ok_or(InjectError::Missing)?;
        if let Some(w) = &st.window {
            if window_alive(w) {
                return Ok(ResolvedTarget {
                    slot,
                    pid: w.pid().unwrap_or(st.pid),
                    target: st.target,
                    rematched: false,
                    title_changed: false,
                });
            }
        }
        // Live reference invalid: re-match (§4.6). Never fall back further.
        let wins = self.windows_with_refs(&st.target.app_id);
        let infos: Vec<WindowInfo> = wins.iter().map(|(i, _)| i.clone()).collect();
        match rematch(&st.target, &infos) {
            RematchOutcome::Matched { window, kind } => {
                let el = wins.into_iter().find(|(i, _)| i.id == window.id).map(|(_, e)| e);
                let title_changed = kind == MatchKind::SingleWindow && st.target.window_title != window.title;
                if title_changed {
                    st.target.window_title = window.title.clone();
                }
                st.pid = window.pid;
                st.window = el;
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
        let st = self.state(target.slot).ok_or(InjectError::Missing)?;
        let el = current_element(&st);
        Ok(TargetCaps {
            category: AppCategory::from_app_id(&st.target.app_id),
            ax_insertable: el.as_ref().map(ax_insertable).unwrap_or(false),
            secure_field: el.as_ref().map(is_secure).unwrap_or(false),
            secure_input: sys::secure_input_enabled(),
            elevated: false,
        })
    }

    fn execute(&self, plan: &Plan, target: &ResolvedTarget) -> DeliveryResult {
        if let Some(r) = &plan.blocked {
            return DeliveryResult::blocked(r.clone());
        }
        if plan.is_noop() {
            return DeliveryResult::Sent { method: plan.method };
        }
        if !sys::is_trusted(false) {
            return DeliveryResult::failed("Accessibility permission needed");
        }
        if sys::secure_input_enabled() {
            return DeliveryResult::blocked("secure input enabled");
        }
        let Some(mut st) = self.state(target.slot) else { return DeliveryResult::Missing };
        st.pid = target.pid;
        if let Some(el) = current_element(&st) {
            if is_secure(&el) {
                return DeliveryResult::blocked("secure text field");
            }
        }
        self.run_plan(plan, &st)
    }

    fn is_trusted(&self, prompt: bool) -> bool {
        sys::is_trusted(prompt)
    }

    fn secure_input_enabled(&self) -> bool {
        sys::secure_input_enabled()
    }

    fn running_windows(&self, app_id: &str) -> Vec<WindowInfo> {
        self.windows_with_refs(app_id).into_iter().map(|(i, _)| i).collect()
    }

    fn play_sound(&self, sound: Sound) {
        sys::play_named_sound(sound.mac_name());
    }
}
