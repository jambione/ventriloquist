//! The `Injector` trait and the non-macOS `UnsupportedInjector`.

use std::any::Any;
use std::sync::Arc;

use crate::model::{BindingTarget, DeliveryResult, SlotId, Sound, WindowInfo};
use crate::planner::{Plan, TargetCaps};

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum InjectError {
    #[error("bindings are not supported on this platform")]
    Unsupported,
    #[error("Accessibility permission needed")]
    NotTrusted,
    #[error("the frontmost app is Ventriloquist itself")]
    SelfFrontmost,
    #[error("the focused element is a secure text field")]
    SecureField,
    #[error("no focused text element")]
    NoFocusedElement,
    /// The slot is empty, or its target window was not found (never falls
    /// back to another window).
    #[error("target not found")]
    Missing,
    #[error("{0}")]
    Platform(String),
}

pub type Result<T> = std::result::Result<T, InjectError>;

/// Opaque platform references (live AX window/element) of a fresh capture.
#[derive(Clone)]
pub struct LiveHandle(pub Arc<dyn Any + Send + Sync>);

impl std::fmt::Debug for LiveHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("LiveHandle(..)")
    }
}

/// Result of `capture_focused` (§4.1 step 1).
#[derive(Debug, Clone)]
pub struct CapturedBinding {
    pub target: BindingTarget,
    pub pid: i32,
    pub live: Option<LiveHandle>,
}

/// A slot's target, resolved for one delivery (§4.3 step 1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedTarget {
    pub slot: SlotId,
    /// The target as it is now (the window title may have changed after a
    /// single-window re-match; persist it when `title_changed`).
    pub target: BindingTarget,
    pub pid: i32,
    /// The live reference was invalid and the window was found by re-match.
    pub rematched: bool,
    pub title_changed: bool,
}

/// Platform executor. Blocking; call from the delivery thread.
///
/// Typical flow: `is_trusted` → `capture_focused` → store.bind + `assign`;
/// at start-up `assign_saved` for every stored slot; per delivery `resolve`
/// (Missing → `DeliveryResult::Missing`), `caps`, `secure_refusal` +
/// `plan_delivery`, `execute`.
pub trait Injector: Send + Sync {
    /// Read the frontmost app and its focused window/element. Refuses for
    /// Ventriloquist itself, secure fields and missing permission.
    fn capture_focused(&self) -> Result<CapturedBinding>;
    /// Remember the live references for `slot` (after `capture_focused`).
    fn assign(&self, slot: SlotId, captured: CapturedBinding);
    /// Register a slot restored from `bindings.json` (no live references;
    /// the first `resolve` re-matches).
    fn assign_saved(&self, slot: SlotId, target: &BindingTarget);
    fn release(&self, slot: SlotId);
    /// Use the live window if still valid, else re-match (§4.6). Never falls
    /// back to another window: `Err(Missing)` when nothing matches.
    fn resolve(&self, slot: SlotId) -> Result<ResolvedTarget>;
    fn caps(&self, target: &ResolvedTarget) -> Result<TargetCaps>;
    fn execute(&self, plan: &Plan, target: &ResolvedTarget) -> DeliveryResult;
    /// Accessibility permission; `prompt` shows the system prompt.
    fn is_trusted(&self, prompt: bool) -> bool;
    fn secure_input_enabled(&self) -> bool;
    fn running_windows(&self, app_id: &str) -> Vec<WindowInfo>;
    fn play_sound(&self, sound: Sound);
}

/// Injector for platforms without an implementation (everything but macOS and Windows).
#[derive(Debug, Default, Clone, Copy)]
pub struct UnsupportedInjector;

impl Injector for UnsupportedInjector {
    fn capture_focused(&self) -> Result<CapturedBinding> {
        Err(InjectError::Unsupported)
    }
    fn assign(&self, _slot: SlotId, _captured: CapturedBinding) {}
    fn assign_saved(&self, _slot: SlotId, _target: &BindingTarget) {}
    fn release(&self, _slot: SlotId) {}
    fn resolve(&self, _slot: SlotId) -> Result<ResolvedTarget> {
        Err(InjectError::Unsupported)
    }
    fn caps(&self, _target: &ResolvedTarget) -> Result<TargetCaps> {
        Err(InjectError::Unsupported)
    }
    fn execute(&self, _plan: &Plan, _target: &ResolvedTarget) -> DeliveryResult {
        DeliveryResult::failed("bindings are not supported on this platform")
    }
    fn is_trusted(&self, _prompt: bool) -> bool {
        false
    }
    fn secure_input_enabled(&self) -> bool {
        false
    }
    fn running_windows(&self, _app_id: &str) -> Vec<WindowInfo> {
        Vec::new()
    }
    fn play_sound(&self, _sound: Sound) {}
}

/// The injector for this platform.
pub fn default_injector() -> Box<dyn Injector> {
    #[cfg(target_os = "macos")]
    {
        Box::new(crate::mac::MacInjector::new())
    }
    #[cfg(target_os = "windows")]
    {
        Box::new(crate::windows::WindowsInjector::new())
    }
    #[cfg(not(any(target_os = "macos", target_os = "windows")))]
    {
        Box::new(UnsupportedInjector)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::planner::{plan_delivery, AppCategory};

    #[test]
    fn unsupported_injector_returns_unsupported() {
        let i = UnsupportedInjector;
        let slot = SlotId::new(1).unwrap();
        assert_eq!(i.capture_focused().unwrap_err(), InjectError::Unsupported);
        assert_eq!(i.resolve(slot).unwrap_err(), InjectError::Unsupported);
        assert!(!i.is_trusted(true));
        assert!(!i.secure_input_enabled());
        assert!(i.running_windows("x").is_empty());
        let rt = ResolvedTarget {
            slot,
            target: BindingTarget {
                app_id: "a".into(),
                app_name: "A".into(),
                window_title: "".into(),
                element_role: "".into(),
                element_subrole: "".into(),
                ax_insertable: false,
            },
            pid: 1,
            rematched: false,
            title_changed: false,
        };
        assert_eq!(i.caps(&rt).unwrap_err(), InjectError::Unsupported);
        let caps = TargetCaps { category: AppCategory::Native, ax_insertable: false, secure_field: false, secure_input: false, elevated: false, clipboard_restorable: true };
        let plan = plan_delivery(&caps, "hi", &Default::default());
        assert!(matches!(i.execute(&plan, &rt), DeliveryResult::Failed { .. }));
        i.play_sound(Sound::Selected);
    }
}
