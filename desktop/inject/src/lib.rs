//! `vq-inject`: bindings to text boxes in other apps (SPEC_V2).
//!
//! - [`model`], [`store`], [`planner`] are pure and OS-independent.
//! - [`Injector`] is the executor trait; `MacInjector` (macOS), `WindowsInjector` (Windows) and
//!   `UnsupportedInjector` (everything else) implement it.
//! - All `unsafe` lives in `mac/sys.rs` and `windows/sys.rs`.
#![deny(unsafe_code)]

pub mod exec;
pub mod injector;
pub mod model;
pub mod planner;
pub mod policy;
pub mod store;

#[cfg(target_os = "macos")]
pub mod mac;
#[cfg(target_os = "windows")]
pub mod windows;

pub use injector::{
    default_injector, CapturedBinding, InjectError, Injector, LiveHandle, ResolvedTarget, Result,
    UnsupportedInjector,
};
pub use model::{
    default_follow_title, ActiveSlot, BindingTarget, DeliveryMethod, DeliveryResult, NewlineMode, SlotId,
    SlotSettings, Sound, WindowDetail, WindowIdentity, WindowInfo,
};
pub use planner::{plan_delivery, secure_refusal, Action, AppCategory, Plan, TargetCaps};
pub use store::{rematch, rematch_detail, single_window_fallback_allowed, BindingsStore, RematchOutcome, SelectOutcome, SlotRecord};
