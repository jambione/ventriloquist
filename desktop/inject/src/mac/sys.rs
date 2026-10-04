//! The only module with `unsafe`: raw Accessibility / Carbon FFI plus thin
//! wrappers over AppKit and CGEvent. Everything it exports is a safe API.
//!
//! Safety notes shared by the FFI wrappers:
//! - AX functions take and return CF objects. Returned objects follow the CF
//!   "Create/Copy" rule and are immediately wrapped in `CFType`, which
//!   releases them on drop. Inputs are borrowed for the call only.
//! - `AXUIElementRef`s are immutable, thread-safe CF objects; AX calls may be
//!   made from any thread, so `AxElement` is `Send + Sync`.
//! - Output pointers are valid, initialised locals.
#![allow(unsafe_code)]
#![allow(non_snake_case)]

use std::ffi::c_void;
use std::time::Duration;

use core_foundation::array::CFArray;
use core_foundation::base::{CFGetTypeID, CFType, TCFType};
use core_foundation::boolean::CFBoolean;
use core_foundation::dictionary::CFDictionary;
use core_foundation::string::{CFString, CFStringRef};
use core_graphics::event::{CGEvent, CGEventFlags, CGEventTapLocation};
use core_graphics::event_source::{CGEventSource, CGEventSourceStateID};
use objc2::rc::Retained;
use objc2::runtime::ProtocolObject;
use objc2_app_kit::{
    NSApplicationActivationOptions, NSPasteboard, NSPasteboardItem, NSPasteboardTypeString,
    NSPasteboardWriting, NSRunningApplication, NSSound, NSWorkspace,
};
use objc2_foundation::{NSArray, NSData, NSString};

type CFTypeRef = *const c_void;
type AXError = i32;
const AX_OK: AXError = 0;

#[link(name = "ApplicationServices", kind = "framework")]
extern "C" {
    fn AXIsProcessTrustedWithOptions(options: *const c_void) -> u8;
    fn AXUIElementCreateApplication(pid: i32) -> CFTypeRef;
    fn AXUIElementCreateSystemWide() -> CFTypeRef;
    fn AXUIElementCopyAttributeValue(el: CFTypeRef, attr: CFStringRef, value: *mut CFTypeRef) -> AXError;
    fn AXUIElementSetAttributeValue(el: CFTypeRef, attr: CFStringRef, value: CFTypeRef) -> AXError;
    fn AXUIElementIsAttributeSettable(el: CFTypeRef, attr: CFStringRef, settable: *mut u8) -> AXError;
    fn AXUIElementPerformAction(el: CFTypeRef, action: CFStringRef) -> AXError;
    fn AXUIElementGetPid(el: CFTypeRef, pid: *mut i32) -> AXError;
    fn AXUIElementSetMessagingTimeout(el: CFTypeRef, seconds: f32) -> AXError;
}

#[link(name = "Carbon", kind = "framework")]
extern "C" {
    fn IsSecureEventInputEnabled() -> u8;
}

/// `AXIsProcessTrustedWithOptions`; with `prompt` the system dialog is shown.
pub fn is_trusted(prompt: bool) -> bool {
    let key = CFString::from_static_string("AXTrustedCheckOptionPrompt");
    let val = if prompt { CFBoolean::true_value() } else { CFBoolean::false_value() };
    let dict = CFDictionary::from_CFType_pairs(&[(key.as_CFType(), val.as_CFType())]);
    // SAFETY: the dictionary is a valid CFDictionary for the call.
    unsafe { AXIsProcessTrustedWithOptions(dict.as_concrete_TypeRef() as *const c_void) != 0 }
}

pub fn secure_input_enabled() -> bool {
    // SAFETY: no arguments, no side effects.
    unsafe { IsSecureEventInputEnabled() != 0 }
}

/// A retained AXUIElement.
#[derive(Clone)]
pub struct AxElement(CFType);

// SAFETY: see module notes; AXUIElementRef is an immutable CF object.
unsafe impl Send for AxElement {}
unsafe impl Sync for AxElement {}

impl AxElement {
    fn from_create(ptr: CFTypeRef) -> Option<AxElement> {
        if ptr.is_null() {
            None
        } else {
            // SAFETY: `ptr` is a +1 retained CF object from a Create/Copy call.
            Some(AxElement(unsafe { CFType::wrap_under_create_rule(ptr) }))
        }
    }

    pub fn system_wide() -> Option<AxElement> {
        // SAFETY: no preconditions.
        Self::from_create(unsafe { AXUIElementCreateSystemWide() })
    }

    pub fn application(pid: i32) -> Option<AxElement> {
        // SAFETY: no preconditions.
        let e = Self::from_create(unsafe { AXUIElementCreateApplication(pid) })?;
        // Don't hang on unresponsive apps.
        // SAFETY: `e` is a valid element.
        unsafe { AXUIElementSetMessagingTimeout(e.0.as_CFTypeRef(), 1.0) };
        Some(e)
    }

    fn raw(&self) -> CFTypeRef {
        self.0.as_CFTypeRef()
    }

    pub fn attr(&self, name: &str) -> Option<CFType> {
        let key = CFString::new(name);
        let mut out: CFTypeRef = std::ptr::null();
        // SAFETY: valid element/key; `out` is a valid out-pointer.
        let err = unsafe { AXUIElementCopyAttributeValue(self.raw(), key.as_concrete_TypeRef(), &mut out) };
        if err != AX_OK || out.is_null() {
            return None;
        }
        // SAFETY: Copy rule, +1.
        Some(unsafe { CFType::wrap_under_create_rule(out) })
    }

    pub fn attr_string(&self, name: &str) -> Option<String> {
        self.attr(name)?.downcast::<CFString>().map(|s| s.to_string())
    }

    /// An attribute whose value is itself an element.
    pub fn attr_element(&self, name: &str) -> Option<AxElement> {
        let v = self.attr(name)?;
        // AXUIElement type id check: compare with the type of a fresh system-wide element.
        let sw = AxElement::system_wide()?;
        // SAFETY: both are valid CF objects.
        if unsafe { CFGetTypeID(v.as_CFTypeRef()) } != unsafe { CFGetTypeID(sw.raw()) } {
            return None;
        }
        Some(AxElement(v))
    }

    pub fn attr_elements(&self, name: &str) -> Vec<AxElement> {
        let Some(v) = self.attr(name) else { return vec![] };
        if v.type_of() != CFArray::<CFType>::type_id() {
            return vec![];
        }
        // SAFETY: type id checked; the CFArray is retained by `v`, and
        // wrap_under_get_rule retains it again.
        let arr: CFArray<CFType> = unsafe { CFArray::wrap_under_get_rule(v.as_CFTypeRef() as _) };
        (0..arr.len())
            .filter_map(|i| arr.get(i).map(|x| AxElement(x.clone())))
            .collect()
    }

    pub fn is_settable(&self, name: &str) -> bool {
        let key = CFString::new(name);
        let mut s: u8 = 0;
        // SAFETY: valid element/key/out-pointer.
        let err = unsafe { AXUIElementIsAttributeSettable(self.raw(), key.as_concrete_TypeRef(), &mut s) };
        err == AX_OK && s != 0
    }

    pub fn set_string(&self, name: &str, value: &str) -> bool {
        let key = CFString::new(name);
        let v = CFString::new(value);
        // SAFETY: valid element/key/value for the call.
        unsafe { AXUIElementSetAttributeValue(self.raw(), key.as_concrete_TypeRef(), v.as_CFTypeRef()) == AX_OK }
    }

    pub fn set_bool(&self, name: &str, value: bool) -> bool {
        let key = CFString::new(name);
        let v = if value { CFBoolean::true_value() } else { CFBoolean::false_value() };
        // SAFETY: as above.
        unsafe { AXUIElementSetAttributeValue(self.raw(), key.as_concrete_TypeRef(), v.as_CFTypeRef()) == AX_OK }
    }

    pub fn perform(&self, action: &str) -> bool {
        let a = CFString::new(action);
        // SAFETY: valid element/action.
        unsafe { AXUIElementPerformAction(self.raw(), a.as_concrete_TypeRef()) == AX_OK }
    }

    pub fn pid(&self) -> Option<i32> {
        let mut pid: i32 = 0;
        // SAFETY: valid element/out-pointer.
        let err = unsafe { AXUIElementGetPid(self.raw(), &mut pid) };
        (err == AX_OK).then_some(pid)
    }
}

// ---- AppKit wrappers ----

pub struct AppInfo {
    pub bundle_id: String,
    pub name: String,
}

fn app_info(app: &NSRunningApplication) -> AppInfo {
    AppInfo {
        bundle_id: app.bundleIdentifier().map(|s| s.to_string()).unwrap_or_default(),
        name: app.localizedName().map(|s| s.to_string()).unwrap_or_default(),
    }
}

pub fn app_for_pid(pid: i32) -> Option<AppInfo> {
    let a = NSRunningApplication::runningApplicationWithProcessIdentifier(pid)?;
    if a.isTerminated() {
        return None;
    }
    Some(app_info(&a))
}

pub fn pids_for_bundle(bundle_id: &str) -> Vec<i32> {
    let apps = NSRunningApplication::runningApplicationsWithBundleIdentifier(&NSString::from_str(bundle_id));
    apps.iter().filter(|a| !a.isTerminated()).map(|a| a.processIdentifier()).collect()
}

/// Frontmost app pid: Accessibility first (reliable without a run loop),
/// `NSWorkspace` as a fallback.
pub fn frontmost_pid() -> Option<i32> {
    if let Some(sw) = AxElement::system_wide() {
        if let Some(pid) = sw.attr_element("AXFocusedApplication").and_then(|a| a.pid()) {
            return Some(pid);
        }
    }
    NSWorkspace::sharedWorkspace().frontmostApplication().map(|a| a.processIdentifier())
}

pub fn activate_pid(pid: i32) {
    if let Some(app) = NSRunningApplication::runningApplicationWithProcessIdentifier(pid) {
        #[allow(deprecated)]
        app.activateWithOptions(NSApplicationActivationOptions::ActivateIgnoringOtherApps);
    }
    // Also ask through AX; this works when `activate` is restricted.
    if let Some(el) = AxElement::application(pid) {
        el.set_bool("AXFrontmost", true);
    }
}

pub fn play_named_sound(name: &str) {
    if let Some(s) = NSSound::soundNamed(&NSString::from_str(name)) {
        s.play();
    }
}

// ---- Pasteboard ----

/// Every item of the general pasteboard with all its types.
pub struct PasteboardSnapshot(Vec<Vec<(Retained<NSString>, Retained<NSData>)>>);

pub fn pasteboard_change_count() -> isize {
    NSPasteboard::generalPasteboard().changeCount()
}

pub fn pasteboard_snapshot() -> PasteboardSnapshot {
    let pb = NSPasteboard::generalPasteboard();
    let mut items = Vec::new();
    if let Some(list) = pb.pasteboardItems() {
        for item in list.iter() {
            let mut entries = Vec::new();
            for t in item.types().iter() {
                if let Some(d) = item.dataForType(&t) {
                    entries.push((t.clone(), d));
                }
            }
            items.push(entries);
        }
    }
    PasteboardSnapshot(items)
}

/// Replace the pasteboard with `text`, marked transient so clipboard
/// managers ignore it. Returns the new change count.
pub fn pasteboard_set_text(text: &str) -> Option<isize> {
    let pb = NSPasteboard::generalPasteboard();
    pb.clearContents();
    let item = NSPasteboardItem::new();
    // SAFETY: NSPasteboardTypeString is a valid static NSString.
    let ty = unsafe { NSPasteboardTypeString };
    let ok = item.setString_forType(&NSString::from_str(text), ty);
    let transient = NSString::from_str("org.nspasteboard.TransientType");
    item.setData_forType(&NSData::new(), &transient);
    let arr = NSArray::from_retained_slice(&[ProtocolObject::<dyn NSPasteboardWriting>::from_retained(item)]);
    let wrote = pb.writeObjects(&arr);
    (ok && wrote).then(|| pb.changeCount())
}

pub fn pasteboard_restore(snap: &PasteboardSnapshot) {
    let pb = NSPasteboard::generalPasteboard();
    pb.clearContents();
    let mut objs = Vec::new();
    for entries in &snap.0 {
        let item = NSPasteboardItem::new();
        for (t, d) in entries {
            item.setData_forType(d, t);
        }
        objs.push(ProtocolObject::<dyn NSPasteboardWriting>::from_retained(item));
    }
    if !objs.is_empty() {
        pb.writeObjects(&NSArray::from_retained_slice(&objs));
    }
}

// ---- Keyboard events ----

pub const KEY_RETURN: u16 = 0x24;
pub const KEY_V: u16 = 0x09;

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Mods {
    None,
    Shift,
    Cmd,
}

fn flags(m: Mods) -> CGEventFlags {
    match m {
        Mods::None => CGEventFlags::CGEventFlagNull,
        Mods::Shift => CGEventFlags::CGEventFlagShift,
        Mods::Cmd => CGEventFlags::CGEventFlagCommand,
    }
}

fn source() -> Option<CGEventSource> {
    // Private state: physically held modifiers (e.g. the hotkey's) are not inherited.
    CGEventSource::new(CGEventSourceStateID::Private).ok()
}

/// Post a key press (down + up) with exactly the modifiers `m`.
pub fn post_key(code: u16, m: Mods) -> bool {
    let Some(src) = source() else { return false };
    for down in [true, false] {
        let Ok(ev) = CGEvent::new_keyboard_event(src.clone(), code, down) else { return false };
        ev.set_flags(flags(m));
        ev.post(CGEventTapLocation::HID);
        std::thread::sleep(Duration::from_millis(4));
    }
    true
}

/// Type `text` (at most ~20 UTF-16 units) as Unicode keyboard events.
pub fn post_unicode(text: &str) -> bool {
    let Some(src) = source() else { return false };
    for down in [true, false] {
        let Ok(ev) = CGEvent::new_keyboard_event(src.clone(), 0, down) else { return false };
        ev.set_flags(CGEventFlags::CGEventFlagNull);
        ev.set_string(text);
        ev.post(CGEventTapLocation::HID);
        std::thread::sleep(Duration::from_millis(4));
    }
    true
}
