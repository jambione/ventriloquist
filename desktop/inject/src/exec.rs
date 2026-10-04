//! The platform-independent plan interpreter (SPEC_V2 §4.3, §4.8). Each
//! platform implements the small [`Os`] primitive set; the ordering rules
//! that make a delivery safe live here once and are tested with a fake `Os`:
//!
//! - every keystroke is preceded by checks for physical user input, held
//!   modifiers, secure input and "target still focused" (R4, R9, #28);
//! - after input, the target gets [`SETTLE_MS`] to consume it before Return,
//!   before the next pasted line and before the previous app is re-activated
//!   (R3, R10); auto-submit Return is skipped (and the delivery fails) if the
//!   focus changed meanwhile;
//! - the clipboard is restored no earlier than
//!   [`CLIPBOARD_RESTORE_DELAY_MS`](crate::planner::CLIPBOARD_RESTORE_DELAY_MS)
//!   after the last paste, and always (also on panic) through [`Run`]'s `Drop`.

use crate::planner::{Action, Plan};
use crate::policy::{typing_text, SETTLE_MS};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StepError {
    /// AX insertion failed or could not be confirmed: use the fallback plan.
    AxUnconfirmed,
    Failed(String),
    Blocked(String),
}

fn failed(m: &str) -> StepError {
    StepError::Failed(m.to_string())
}

/// Platform primitives. Methods take `&mut self` so implementations can keep
/// state (previous app, clipboard snapshot, last post time).
pub trait Os {
    /// Direct text insertion (macOS Accessibility). Default: unsupported.
    fn ax_insert(&mut self, _text: &str) -> Result<(), StepError> {
        Err(failed("direct insertion is not supported"))
    }
    /// Remember the frontmost app (if not the target), bring the target forward.
    fn activate(&mut self);
    /// The target window is the foreground window (exactly).
    fn foreground_is_target(&mut self) -> bool;
    fn wait_foreground(&mut self, timeout_ms: u64) -> bool;
    /// Re-focus the bound element, then inspect what has focus: refuse a
    /// password field (platform policy), record the focus for
    /// [`Os::focus_unchanged`].
    fn focus_element(&mut self) -> Result<(), StepError>;
    /// The focused element is still the one recorded by `focus_element`.
    fn focus_unchanged(&mut self) -> bool {
        true
    }
    /// System-wide secure input is on right now (macOS).
    fn secure_input_now(&mut self) -> bool {
        false
    }
    /// The user pressed/clicked something since the delivery began (R4b).
    fn physical_input(&mut self) -> bool;
    /// No modifier key is physically held (waits briefly for release).
    fn modifiers_released(&mut self) -> bool {
        true
    }
    fn send_text(&mut self, s: &str) -> bool;
    fn send_shift_return(&mut self) -> bool;
    fn send_return(&mut self) -> bool;
    fn send_paste(&mut self) -> bool;
    /// `false`: the clipboard cannot be restored losslessly.
    fn clipboard_snapshot(&mut self) -> bool;
    fn clipboard_set(&mut self, text: &str) -> bool;
    /// Nobody wrote to the clipboard since `clipboard_set`.
    fn clipboard_unchanged(&mut self) -> bool;
    /// Restore the snapshot if still unchanged; no-op without a snapshot.
    fn clipboard_restore_if_unchanged(&mut self);
    fn reactivate_previous(&mut self);
    fn sleep_ms(&mut self, ms: u64);
    /// Monotonic milliseconds.
    fn now_ms(&mut self) -> u64;
}

/// Does the plan send input to another app (so it needs the idle wait and the
/// physical-input watch)? Pure AX plans without activation do not.
pub fn plan_sends_input(plan: &Plan) -> bool {
    plan.actions.iter().any(|a| matches!(a, Action::Activate))
}

pub struct Run<O: Os> {
    pub os: O,
    /// Input was sent since the last settle.
    dirty: bool,
    last_paste_ms: Option<u64>,
    activated: bool,
    cleaned: bool,
}

impl<O: Os> Run<O> {
    pub fn new(os: O) -> Self {
        Run { os, dirty: false, last_paste_ms: None, activated: false, cleaned: false }
    }

    fn settle(&mut self) {
        self.os.sleep_ms(SETTLE_MS);
        self.dirty = false;
    }

    fn settle_if_dirty(&mut self) {
        if self.dirty {
            self.settle();
        }
    }

    /// Checks before any keystroke.
    fn guard(&mut self) -> Result<(), StepError> {
        if self.os.physical_input() {
            return Err(failed("interrupted by user input"));
        }
        if self.os.secure_input_now() {
            return Err(StepError::Blocked("secure input enabled".into()));
        }
        if !self.os.modifiers_released() {
            return Err(failed("modifier keys are held"));
        }
        if !self.os.foreground_is_target() || !self.os.focus_unchanged() {
            return Err(failed("focus changed"));
        }
        Ok(())
    }

    fn sent(&mut self, ok: bool) -> Result<(), StepError> {
        self.dirty = true;
        if ok {
            Ok(())
        } else {
            Err(failed("cannot send keyboard input"))
        }
    }

    pub fn step(&mut self, a: &Action) -> Result<(), StepError> {
        match a {
            Action::AxInsertSelectedText(t) => self.os.ax_insert(t),
            Action::Activate => {
                self.activated = true;
                self.os.activate();
                Ok(())
            }
            Action::WaitFrontmost { timeout_ms } => {
                if self.os.wait_foreground(*timeout_ms) {
                    Ok(())
                } else {
                    Err(failed("could not focus target"))
                }
            }
            Action::FocusElement => self.os.focus_element(),
            Action::TypeUnicode(s) => {
                self.guard()?;
                let ok = self.os.send_text(&typing_text(s));
                self.sent(ok)
            }
            Action::ShiftReturn => {
                self.guard()?;
                let ok = self.os.send_shift_return();
                self.sent(ok)
            }
            Action::Return => {
                // Auto-submit only once the text has been consumed and the
                // target is verifiably still the focused window.
                self.settle_if_dirty();
                if self.os.physical_input() {
                    return Err(failed("interrupted by user input"));
                }
                if self.os.secure_input_now() {
                    return Err(StepError::Blocked("secure input enabled".into()));
                }
                if !self.os.foreground_is_target() || !self.os.focus_unchanged() {
                    return Err(failed("focus changed before submit"));
                }
                if !self.os.modifiers_released() {
                    return Err(failed("modifier keys are held"));
                }
                let ok = self.os.send_return();
                self.sent(ok)
            }
            Action::SnapshotClipboard => {
                // The planner only pastes when `caps` said the clipboard is
                // restorable; if that changed since, refuse rather than lose it.
                if self.os.clipboard_snapshot() {
                    Ok(())
                } else {
                    Err(failed("clipboard cannot be restored"))
                }
            }
            Action::SetClipboard(s) => {
                if self.os.clipboard_set(s) {
                    Ok(())
                } else {
                    Err(failed("cannot set clipboard"))
                }
            }
            Action::CmdV => {
                self.guard()?;
                let ok = self.os.send_paste();
                self.sent(ok)?;
                self.last_paste_ms = Some(self.os.now_ms());
                // Let the target read the clipboard before it changes again.
                self.settle();
                if self.os.clipboard_unchanged() {
                    Ok(())
                } else {
                    Err(failed("clipboard changed during paste"))
                }
            }
            Action::RestoreClipboardIfUnchanged { delay_ms } => {
                self.restore_clipboard(*delay_ms);
                Ok(())
            }
            Action::ReactivatePrevious => {
                self.settle_if_dirty();
                self.os.reactivate_previous();
                self.activated = false;
                Ok(())
            }
        }
    }

    /// Wait until `delay_ms` after the last paste key, then restore.
    fn restore_clipboard(&mut self, delay_ms: u64) {
        if let Some(t) = self.last_paste_ms.take() {
            let now = self.os.now_ms();
            let due = t.saturating_add(delay_ms);
            if now < due {
                self.os.sleep_ms(due - now);
            }
        }
        self.os.clipboard_restore_if_unchanged();
    }

    /// Never leave our text on the clipboard or the user's app buried.
    /// Idempotent; also runs on drop (panic safety).
    pub fn finish(&mut self) {
        if self.cleaned {
            return;
        }
        self.cleaned = true;
        self.restore_clipboard(crate::planner::CLIPBOARD_RESTORE_DELAY_MS);
        if self.activated {
            self.settle_if_dirty();
            self.os.reactivate_previous();
            self.activated = false;
        }
    }

    /// Run `actions` in order, then clean up (also after an error).
    pub fn run(&mut self, actions: &[Action]) -> Result<(), StepError> {
        let mut result = Ok(());
        for a in actions {
            if let Err(e) = self.step(a) {
                result = Err(e);
                break;
            }
        }
        self.finish();
        result
    }
}

impl<O: Os> Drop for Run<O> {
    fn drop(&mut self) {
        self.finish();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{NewlineMode, SlotSettings};
    use crate::planner::{plan_delivery, AppCategory, TargetCaps};

    #[derive(Default)]
    struct Fake {
        log: Vec<String>,
        now: u64,
        /// Physical input appears once this many sends have happened.
        physical_after_sends: Option<usize>,
        sends: usize,
        /// Foreground leaves the target after this many sends.
        lose_focus_after_sends: Option<usize>,
        clipboard_changed: bool,
        snapshot_ok: bool,
        panic_on_paste: bool,
    }

    impl Fake {
        fn new() -> Self {
            Fake { snapshot_ok: true, ..Default::default() }
        }
        fn count(&self, s: &str) -> usize {
            self.log.iter().filter(|l| l.starts_with(s)).count()
        }
    }

    impl Os for &mut Fake {
        fn activate(&mut self) {
            self.log.push("activate".into());
        }
        fn foreground_is_target(&mut self) -> bool {
            self.lose_focus_after_sends.is_none_or(|n| self.sends < n)
        }
        fn wait_foreground(&mut self, _t: u64) -> bool {
            true
        }
        fn focus_element(&mut self) -> Result<(), StepError> {
            Ok(())
        }
        fn physical_input(&mut self) -> bool {
            self.physical_after_sends.is_some_and(|n| self.sends >= n)
        }
        fn send_text(&mut self, s: &str) -> bool {
            self.sends += 1;
            self.log.push(format!("text:{s}"));
            true
        }
        fn send_shift_return(&mut self) -> bool {
            self.sends += 1;
            self.log.push("shift_return".into());
            true
        }
        fn send_return(&mut self) -> bool {
            self.sends += 1;
            self.log.push("return".into());
            true
        }
        fn send_paste(&mut self) -> bool {
            if self.panic_on_paste {
                panic!("boom");
            }
            self.sends += 1;
            self.log.push(format!("paste@{}", self.now));
            true
        }
        fn clipboard_snapshot(&mut self) -> bool {
            self.log.push("snapshot".into());
            self.snapshot_ok
        }
        fn clipboard_set(&mut self, t: &str) -> bool {
            self.log.push(format!("set:{}", t.len()));
            true
        }
        fn clipboard_unchanged(&mut self) -> bool {
            !self.clipboard_changed
        }
        fn clipboard_restore_if_unchanged(&mut self) {
            self.log.push(format!("restore@{}", self.now));
        }
        fn reactivate_previous(&mut self) {
            self.log.push(format!("reactivate@{}", self.now));
        }
        fn sleep_ms(&mut self, ms: u64) {
            self.now += ms;
            self.log.push(format!("sleep:{ms}"));
        }
        fn now_ms(&mut self) -> u64 {
            self.now
        }
    }

    fn caps(cat: AppCategory) -> TargetCaps {
        TargetCaps {
            category: cat,
            ax_insertable: false,
            secure_field: false,
            secure_input: false,
            elevated: false,
            clipboard_restorable: true,
        }
    }
    fn settings(auto: bool) -> SlotSettings {
        SlotSettings { auto_submit: auto, newline_mode: NewlineMode::ShiftEnter }
    }

    fn run(f: &mut Fake, text: &str, auto: bool) -> Result<(), StepError> {
        let plan = plan_delivery(&caps(AppCategory::Electron), text, &settings(auto));
        Run::new(f).run(&plan.actions)
    }

    #[test]
    fn return_waits_for_settle_and_reactivate_waits_after_return() {
        let mut f = Fake::new();
        run(&mut f, "hello", true).unwrap();
        let i_text = f.log.iter().position(|l| l.starts_with("text:")).unwrap();
        let i_ret = f.log.iter().position(|l| l == "return").unwrap();
        let i_re = f.log.iter().position(|l| l.starts_with("reactivate")).unwrap();
        assert_eq!(f.log[i_ret - 1], "sleep:150", "settle before Return");
        assert!(i_text < i_ret);
        assert_eq!(f.log[i_re - 1], "sleep:150", "settle before re-activating the previous app");
    }

    #[test]
    fn return_is_skipped_when_focus_changed_before_submit() {
        let mut f = Fake::new();
        f.lose_focus_after_sends = Some(1); // after the text chunk
        let e = run(&mut f, "hello", true).unwrap_err();
        assert_eq!(e, StepError::Failed("focus changed before submit".into()));
        assert_eq!(f.count("return"), 0);
        assert_eq!(f.count("reactivate"), 1, "cleanup still re-activates");
    }

    #[test]
    fn physical_input_stops_typing_and_never_submits() {
        let mut f = Fake::new();
        f.physical_after_sends = Some(2);
        let text = "x".repeat(100); // five 20-unit chunks
        let e = run(&mut f, &text, true).unwrap_err();
        assert_eq!(e, StepError::Failed("interrupted by user input".into()));
        assert_eq!(f.count("text:"), 2, "stopped between chunks");
        assert_eq!(f.count("return"), 0);
    }

    #[test]
    fn physical_input_right_before_return_skips_it() {
        let mut f = Fake::new();
        f.physical_after_sends = Some(1);
        let e = run(&mut f, "hi", true).unwrap_err();
        assert_eq!(e, StepError::Failed("interrupted by user input".into()));
        assert_eq!(f.count("return"), 0);
    }

    #[test]
    fn typed_tab_never_reaches_the_keyboard() {
        let mut f = Fake::new();
        let actions = vec![Action::Activate, Action::TypeUnicode("a\tb".into())];
        Run::new(&mut f).run(&actions).unwrap();
        assert!(f.log.contains(&"text:a b".to_string()), "{:?}", f.log);
    }

    #[test]
    fn paste_lines_are_paced_and_restore_waits_400ms_after_last_paste() {
        let mut f = Fake::new();
        let long = format!("{}\n{}", "a".repeat(600), "b".repeat(600)); // > 1000: paste
        run(&mut f, &long, false).unwrap();
        assert_eq!(f.count("paste@"), 2);
        let pastes: Vec<usize> =
            f.log.iter().enumerate().filter(|(_, l)| l.starts_with("paste@")).map(|(i, _)| i).collect();
        assert_eq!(f.log[pastes[0] + 1], "sleep:150", "settle after every pasted line");
        let paste_t: u64 = f.log[pastes[1]].trim_start_matches("paste@").parse().unwrap();
        let restore_t: u64 = f
            .log
            .iter()
            .find(|l| l.starts_with("restore@"))
            .unwrap()
            .trim_start_matches("restore@")
            .parse()
            .unwrap();
        assert!(restore_t >= paste_t + 400, "restored at {restore_t}, last paste at {paste_t}");
    }

    #[test]
    fn clipboard_overwritten_during_paste_fails_the_delivery() {
        let mut f = Fake::new();
        f.clipboard_changed = true;
        let e = run(&mut f, &"p".repeat(300), false).unwrap_err();
        assert_eq!(e, StepError::Failed("clipboard changed during paste".into()));
    }

    #[test]
    fn unrestorable_clipboard_refuses_the_paste() {
        let mut f = Fake::new();
        f.snapshot_ok = false;
        let e = run(&mut f, &"p".repeat(300), false).unwrap_err();
        assert_eq!(e, StepError::Failed("clipboard cannot be restored".into()));
        assert_eq!(f.count("paste@"), 0);
    }

    #[test]
    fn drop_after_panic_restores_clipboard_and_reactivates() {
        let mut f = Fake::new();
        f.panic_on_paste = true;
        let plan = plan_delivery(&caps(AppCategory::Electron), &"p".repeat(300), &settings(false));
        let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let mut run = Run::new(&mut f);
            let _ = run.run(&plan.actions);
        }));
        assert!(r.is_err());
        assert_eq!(f.count("restore@"), 1);
        assert_eq!(f.count("reactivate"), 1);
    }

    #[test]
    fn modifiers_held_block_typing() {
        struct Held(Fake);
        impl Os for &mut Held {
            fn activate(&mut self) {}
            fn foreground_is_target(&mut self) -> bool {
                true
            }
            fn wait_foreground(&mut self, _t: u64) -> bool {
                true
            }
            fn focus_element(&mut self) -> Result<(), StepError> {
                Ok(())
            }
            fn physical_input(&mut self) -> bool {
                false
            }
            fn modifiers_released(&mut self) -> bool {
                false
            }
            fn send_text(&mut self, _: &str) -> bool {
                self.0.sends += 1;
                true
            }
            fn send_shift_return(&mut self) -> bool {
                true
            }
            fn send_return(&mut self) -> bool {
                true
            }
            fn send_paste(&mut self) -> bool {
                true
            }
            fn clipboard_snapshot(&mut self) -> bool {
                true
            }
            fn clipboard_set(&mut self, _: &str) -> bool {
                true
            }
            fn clipboard_unchanged(&mut self) -> bool {
                true
            }
            fn clipboard_restore_if_unchanged(&mut self) {}
            fn reactivate_previous(&mut self) {}
            fn sleep_ms(&mut self, _: u64) {}
            fn now_ms(&mut self) -> u64 {
                0
            }
        }
        let mut h = Held(Fake::new());
        let e = Run::new(&mut h).run(&[Action::TypeUnicode("a".into())]).unwrap_err();
        assert_eq!(e, StepError::Failed("modifier keys are held".into()));
        assert_eq!(h.0.sends, 0);
    }

    #[test]
    fn ax_only_plan_needs_no_input_watch() {
        let mut c = caps(AppCategory::Native);
        c.ax_insertable = true;
        let p = plan_delivery(&c, "hi", &settings(false));
        assert!(!plan_sends_input(&p));
        let p = plan_delivery(&c, "hi", &settings(true));
        assert!(plan_sends_input(&p));
        assert!(plan_sends_input(p.fallback.as_ref().unwrap()));
    }
}
