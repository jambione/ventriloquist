//! `vq-inject`: bindings to text boxes in other apps (SPEC_V2).
//!
//! - [`model`], [`store`], [`planner`] are pure and OS-independent.
//! - [`Injector`] is the executor trait; `MacInjector` (macOS) and
//!   `UnsupportedInjector` (everything else) implement it.
//! - All `unsafe` lives in `mac/sys.rs`.
#![deny(unsafe_code)]

pub mod injector;
pub mod model;
pub mod planner;
pub mod store;

#[cfg(target_os = "macos")]
pub mod mac;

pub use injector::{
    default_injector, CapturedBinding, InjectError, Injector, LiveHandle, ResolvedTarget, Result,
    UnsupportedInjector,
};
pub use model::{
    ActiveSlot, BindingTarget, DeliveryMethod, DeliveryResult, SlotId, SlotSettings, Sound,
    WindowInfo,
};
pub use planner::{plan_delivery, secure_refusal, Action, AppCategory, Plan, TargetCaps};
pub use store::{rematch, BindingsStore, RematchOutcome, SelectOutcome, SlotRecord};
