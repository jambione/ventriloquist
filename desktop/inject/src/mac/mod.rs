//! macOS injector: Accessibility + CGEvent + NSPasteboard + NSWorkspace.
//! All FFI is in [`sys`]; this module is safe logic on top.

mod sys;

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use crate::exec::{plan_sends_input, Os, Run, StepError};
use crate::injector::{CapturedBinding, InjectError, Injector, LiveHandle, ResolvedTarget, Result};
use crate::model::{BindingTarget, DeliveryResult, SlotId, Sound, WindowDetail, WindowIdentity, WindowInfo};
use crate::planner::{AppCategory, Plan, TargetCaps};
use crate::policy::{
    password_verdict_mac, physical_input_since, wait_for_idle, FocusProbe, IDLE_MAX_WAIT_MS, IDLE_REQUIRED_MS,
};
use crate::store::{rematch_detail, MatchKind, RematchOutcome};
use sys::AxElement;

const TEXT_ROLES: &[&str] = &["AXTextField", "AXTextArea", "AXComboBox"];
const SECURE_SUBROLE: &str = "AXSecureTextField";
const STANDARD_WINDOW: &str = "AXStandardWindow";
/// Role recorded for a window-level binding (the element could not be inspected).
const WINDOW_LEVEL_ROLE: &str = "";
/// How long to retry reading an Electron/Chromium app's AX tree after asking
/// it to expose it (R14).
const AX_EXPOSE_WAIT: Duration = Duration::from_millis(500);

/// Live AX references of one capture.
struct LiveRefs {
    window: Option<AxElement>,
    element: Option<AxElement>,
}

#[derive(Clone)]
struct SlotState {
    target: BindingTarget,
    identity: WindowIdentity,
    pid: i32,
    window: Option<AxElement>,
    element: Option<AxElement>,
}

#[derive(Default)]
pub struct MacInjector {
    slots: Mutex<HashMap<SlotId, SlotState>>,
}

/// Electron and Chromium do not build their accessibility tree until an
/// assistive client asks: set `AXManualAccessibility` (errors ignored).
fn expose_ax_tree(app: &AxElement) {
    app.set_bool("AXManualAccessibility", true);
}

/// Poll `f` until it gives `Some` or `AX_EXPOSE_WAIT` has passed.
fn retry_for<T>(mut f: impl FnMut() -> Option<T>) -> Option<T> {
    let end = Instant::now() + AX_EXPOSE_WAIT;
    loop {
        if let Some(v) = f() {
            return Some(v);
        }
        if Instant::now() >= end {
            return None;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
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
        let tree_may_be_hidden = AppCategory::from_app_id(app_id).keystroke_preferred();
        for pid in sys::pids_for_bundle(app_id) {
            let Some(app) = AxElement::application(pid) else { continue };
            let mut windows = app.attr_elements("AXWindows");
            if windows.is_empty() && tree_may_be_hidden {
                expose_ax_tree(&app);
                windows = retry_for(|| Some(app.attr_elements("AXWindows")).filter(|w| !w.is_empty())).unwrap_or_default();
            }
            for w in windows {
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

/// The element belongs to `window` (its `AXWindow` is the bound window).
fn in_window(el: &AxElement, window: &AxElement) -> bool {
    el.attr_element("AXWindow").is_some_and(|w| w.same(window))
}

/// The element to deliver to: the live bound element if still valid, else
/// the app's focused element when its role matches the saved role AND it
/// lives in the bound window (§4.6, R8). `None` otherwise: the keystroke path
/// then activates and raises the bound window.
fn current_element(st: &SlotState) -> Option<AxElement> {
    let w = st.window.as_ref()?;
    if let Some(e) = &st.element {
        if e.attr_string("AXRole").is_some() && in_window(e, w) {
            return Some(e.clone());
        }
    }
    if st.target.element_role == WINDOW_LEVEL_ROLE {
        return None;
    }
    let app = AxElement::application(st.pid)?;
    let focused = app.attr_element("AXFocusedUIElement")?;
    (focused.attr_string("AXRole").as_deref() == Some(st.target.element_role.as_str()) && in_window(&focused, w))
        .then_some(focused)
}

/// What is focused in the target app right now (any window), for the secure
/// re-check and the exact focus check.
fn app_focused_element(pid: i32) -> Option<AxElement> {
    AxElement::application(pid)?.attr_element("AXFocusedUIElement")
}

/// The Mac primitives for [`Run`].
struct MacOs {
    pid: i32,
    st: SlotState,
    prev_pid: Option<i32>,
    snapshot: Option<sys::PasteboardSnapshot>,
    set_count: Option<isize>,
    focus_el: Option<AxElement>,
    /// When we last posted an event (or began): input newer than this, and
    /// not ours, is the user's (R4b).
    last_post: Instant,
}

impl MacOs {
    fn post(&mut self, ok: bool) -> bool {
        self.last_post = Instant::now();
        ok
    }
}

impl Os for MacOs {
    fn ax_insert(&mut self, text: &str) -> std::result::Result<(), StepError> {
        let el = current_element(&self.st).ok_or(StepError::AxUnconfirmed)?;
        if is_secure(&el) {
            return Err(StepError::Failed("secure text field".into()));
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

    fn activate(&mut self) {
        let front = sys::frontmost_pid();
        self.prev_pid = front.filter(|p| *p != self.pid);
        sys::activate_pid(self.pid);
        if let Some(w) = &self.st.window {
            w.perform("AXRaise");
        }
        self.last_post = Instant::now();
    }

    /// The target app is frontmost and its focused window is the bound window
    /// (when readable): a different window of the same app is not the target
    /// (#28).
    fn foreground_is_target(&mut self) -> bool {
        if sys::frontmost_pid() != Some(self.pid) {
            return false;
        }
        let (Some(w), Some(app)) = (&self.st.window, AxElement::application(self.pid)) else { return true };
        match app.attr_element("AXFocusedWindow") {
            Some(f) => f.same(w),
            None => true,
        }
    }

    fn wait_foreground(&mut self, timeout_ms: u64) -> bool {
        let end = Instant::now() + Duration::from_millis(timeout_ms);
        loop {
            if self.foreground_is_target() {
                return true;
            }
            if Instant::now() >= end {
                return false;
            }
            std::thread::sleep(Duration::from_millis(25));
        }
    }

    /// R9/R14: after activation, re-check what has focus. A secure text field
    /// or secure event input refuses; an element that cannot be inspected
    /// (Electron) is allowed while secure input is off.
    fn focus_element(&mut self) -> std::result::Result<(), StepError> {
        if let Some(app) = AxElement::application(self.pid) {
            if AppCategory::from_app_id(&self.st.target.app_id).keystroke_preferred() {
                expose_ax_tree(&app);
            }
        }
        if let Some(e) = &self.st.element {
            if e.attr_string("AXRole").is_some() {
                e.set_bool("AXFocused", true);
            }
        }
        let focused = app_focused_element(self.pid);
        let probe = match &focused {
            Some(el) => FocusProbe::Element { is_password: Some(is_secure(el)) },
            None => FocusProbe::Unknown,
        };
        password_verdict_mac(probe, sys::secure_input_enabled()).map_err(StepError::Blocked)?;
        self.focus_el = focused;
        Ok(())
    }

    fn focus_unchanged(&mut self) -> bool {
        match (&self.focus_el, app_focused_element(self.pid)) {
            (Some(rec), Some(now)) => rec.same(&now),
            // Not inspectable (then or now): nothing to compare.
            _ => true,
        }
    }

    fn secure_input_now(&mut self) -> bool {
        sys::secure_input_enabled()
    }

    fn physical_input(&mut self) -> bool {
        physical_input_since(sys::hw_idle_secs(), self.last_post.elapsed().as_secs_f64())
    }

    fn send_text(&mut self, s: &str) -> bool {
        let ok = sys::post_unicode(s);
        self.post(ok)
    }
    fn send_shift_return(&mut self) -> bool {
        let ok = sys::post_key(sys::KEY_RETURN, sys::Mods::Shift);
        self.post(ok)
    }
    fn send_return(&mut self) -> bool {
        let ok = sys::post_key(sys::KEY_RETURN, sys::Mods::None);
        self.post(ok)
    }
    fn send_paste(&mut self) -> bool {
        let ok = sys::post_key(sys::KEY_V, sys::Mods::Cmd);
        self.post(ok)
    }

    fn clipboard_snapshot(&mut self) -> bool {
        self.snapshot = sys::pasteboard_snapshot();
        self.snapshot.is_some()
    }

    fn clipboard_set(&mut self, text: &str) -> bool {
        self.set_count = sys::pasteboard_set_text(text);
        self.set_count.is_some()
    }

    fn clipboard_unchanged(&mut self) -> bool {
        self.set_count.is_some_and(|c| sys::pasteboard_change_count() == c)
    }

    fn clipboard_restore_if_unchanged(&mut self) {
        let (Some(snap), Some(count)) = (self.snapshot.take(), self.set_count.take()) else { return };
        // Someone else wrote to the clipboard meanwhile: leave it alone.
        if sys::pasteboard_change_count() == count {
            sys::pasteboard_restore(&snap);
        }
    }

    fn reactivate_previous(&mut self) {
        if let Some(p) = self.prev_pid.take() {
            if sys::app_for_pid(p).is_some() {
                sys::activate_pid(p);
            }
        }
    }

    fn sleep_ms(&mut self, ms: u64) {
        std::thread::sleep(Duration::from_millis(ms));
    }

    fn now_ms(&mut self) -> u64 {
        static START: std::sync::OnceLock<Instant> = std::sync::OnceLock::new();
        START.get_or_init(Instant::now).elapsed().as_millis() as u64
    }
}

impl MacInjector {
    fn run_plan(&self, plan: &Plan, st: &SlotState) -> DeliveryResult {
        // R4a: let the user finish typing before we take the focus.
        if plan_sends_input(plan) {
            wait_for_idle(
                || Some((sys::hw_idle_secs() * 1000.0).min(1e9) as u64),
                |ms| std::thread::sleep(Duration::from_millis(ms)),
                IDLE_REQUIRED_MS,
                IDLE_MAX_WAIT_MS,
            );
        }
        let os = MacOs {
            pid: st.pid,
            st: st.clone(),
            prev_pid: None,
            snapshot: None,
            set_count: None,
            focus_el: None,
            last_post: Instant::now(),
        };
        match Run::new(os).run(&plan.actions) {
            Ok(()) => DeliveryResult::Sent { method: plan.method },
            Err(StepError::AxUnconfirmed) => match &plan.fallback {
                Some(fb) => self.run_plan(fb, st),
                None => DeliveryResult::failed("accessibility insertion failed"),
            },
            Err(StepError::Failed(r)) => DeliveryResult::failed(r),
            Err(StepError::Blocked(r)) => DeliveryResult::blocked(r),
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
        let mut window = app.attr_element("AXFocusedWindow");
        let mut element = app.attr_element("AXFocusedUIElement");
        if element.is_none() || window.is_none() {
            // R14: Electron/Chromium expose their tree only after an assistive
            // client asks; ask, then retry for up to ~500 ms.
            expose_ax_tree(&app);
            let end = Instant::now() + AX_EXPOSE_WAIT;
            while (element.is_none() || window.is_none()) && Instant::now() < end {
                std::thread::sleep(Duration::from_millis(50));
                window = window.or_else(|| app.attr_element("AXFocusedWindow"));
                element = element.or_else(|| app.attr_element("AXFocusedUIElement"));
            }
        }
        if element.as_ref().is_some_and(is_secure) {
            return Err(InjectError::SecureField);
        }
        let mut title = window.as_ref().and_then(|w| w.attr_string("AXTitle"));
        if element.is_none() {
            // Window-level binding: the window is known (AX, or the window
            // server's list) but no element can be inspected. The keystroke
            // path is used; the secure re-check after activation guards it.
            if window.is_none() {
                match sys::frontmost_window_title(pid) {
                    Some(t) => title = title.or(Some(t)),
                    None => return Err(InjectError::NoFocusedElement),
                }
            }
            log::info!("binding {} at window level (no focused element could be read)", info.bundle_id);
        }
        let (role, subrole, insertable) = match &element {
            Some(e) => (e.attr_string("AXRole").unwrap_or_default(), e.attr_string("AXSubrole").unwrap_or_default(), ax_insertable(e)),
            None => (WINDOW_LEVEL_ROLE.to_string(), String::new(), false),
        };
        let target = BindingTarget {
            app_id: info.bundle_id,
            app_name: info.name,
            window_title: title.unwrap_or_default(),
            element_role: role,
            element_subrole: subrole,
            ax_insertable: insertable,
        };
        Ok(CapturedBinding {
            target,
            identity: WindowIdentity::default(),
            pid,
            live: Some(LiveHandle(Arc::new(LiveRefs { window, element }))),
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
            m.insert(
                slot,
                SlotState { target: captured.target, identity: captured.identity, pid: captured.pid, window, element },
            );
        }
    }

    fn assign_saved(&self, slot: SlotId, target: &BindingTarget, identity: &WindowIdentity) {
        if let Ok(mut m) = self.slots.lock() {
            m.insert(
                slot,
                SlotState { target: target.clone(), identity: identity.clone(), pid: 0, window: None, element: None },
            );
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
                let live_title = w.attr_string("AXTitle").unwrap_or_default();
                let title_changed = live_title != st.target.window_title;
                return Ok(ResolvedTarget {
                    slot,
                    pid: w.pid().unwrap_or(st.pid),
                    target: st.target,
                    identity: st.identity,
                    live_title,
                    rematched: false,
                    title_changed,
                });
            }
        }
        // Live reference invalid: re-match (§4.6). Never fall back further.
        let wins = self.windows_with_refs(&st.target.app_id);
        let details: Vec<WindowDetail> = wins.iter().map(|(i, _)| WindowDetail::from(i.clone())).collect();
        match rematch_detail(&st.target, &st.identity, &details) {
            RematchOutcome::Matched { window, kind } => {
                let el = wins.into_iter().find(|(i, _)| i.id == window.id).map(|(_, e)| e);
                let live_title = window.title.clone();
                let title_changed = kind == MatchKind::SingleWindow && st.target.window_title != window.title;
                st.pid = window.pid;
                st.window = el;
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
        let st = self.state(target.slot).ok_or(InjectError::Missing)?;
        let el = current_element(&st);
        Ok(TargetCaps {
            category: AppCategory::from_app_id(&st.target.app_id),
            ax_insertable: el.as_ref().map(ax_insertable).unwrap_or(false),
            secure_field: el.as_ref().map(is_secure).unwrap_or(false),
            secure_input: sys::secure_input_enabled(),
            elevated: false,
            // A type that yields no data (file promises, lazy data) makes the
            // restore lossy: then long text is typed (#30).
            clipboard_restorable: sys::pasteboard_snapshot().is_some(),
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
