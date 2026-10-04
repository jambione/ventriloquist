//! Pure decision helpers shared by the executors (SPEC_V2 §4.3-§4.8). No OS
//! calls, so every rule here is unit-tested on any host.

use std::borrow::Cow;

/// After the last input of a batch, wait this long for the target to consume
/// it before the next step that depends on it (Return, re-activation, the next
/// pasted line) (R3, R10).
pub const SETTLE_MS: u64 = 150;
/// The user must have been idle this long before a delivery starts (R4a).
pub const IDLE_REQUIRED_MS: u64 = 300;
/// ... but we wait at most this long, then proceed (R4a).
pub const IDLE_MAX_WAIT_MS: u64 = 3000;
/// Tolerance when comparing input ages (event-time granularity).
pub const INPUT_AGE_TOLERANCE_SECS: f64 = 0.03;

// ------------------------------------------------------------------ title

/// R5: a slot with `follow_title_changes == false` only receives text while
/// the live window title equals the bound title exactly.
pub fn title_check(follow_title_changes: bool, bound: &str, live: &str) -> Result<(), String> {
    if follow_title_changes || bound == live {
        Ok(())
    } else {
        Err(format!("window changed: was '{bound}', now '{live}'"))
    }
}

// ------------------------------------------------- password / focus probe

/// What UI Automation / Accessibility told us about the element that will
/// receive the keystrokes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FocusProbe {
    /// No focused element could be read.
    Unknown,
    /// An element was read; `is_password` is `None` when that property could
    /// not be read.
    Element { is_password: Option<bool> },
}

/// Windows (R1): fail closed. Anything but a readable, non-password element
/// refuses the delivery.
pub fn password_verdict_strict(p: FocusProbe) -> Result<(), String> {
    match p {
        FocusProbe::Element { is_password: Some(false) } => Ok(()),
        FocusProbe::Element { is_password: Some(true) } => Err("secure text field".into()),
        _ => Err("cannot verify field is not a password".into()),
    }
}

/// macOS (R9 as amended by R14): a secure field is refused. An element that
/// cannot be inspected (Electron before its tree is exposed) is allowed while
/// secure event input is off, because secure input is how macOS marks a
/// password field being edited; with secure input on it is refused (fail
/// closed).
pub fn password_verdict_mac(p: FocusProbe, secure_input: bool) -> Result<(), String> {
    if secure_input {
        return Err("secure input enabled".into());
    }
    match p {
        FocusProbe::Element { is_password: Some(true) } => Err("secure text field".into()),
        _ => Ok(()),
    }
}

// -------------------------------------------------------- physical input

pub const LLKHF_INJECTED: u32 = 0x10;
pub const LLKHF_LOWER_IL_INJECTED: u32 = 0x02;
pub const LLMHF_INJECTED: u32 = 0x01;
pub const LLMHF_LOWER_IL_INJECTED: u32 = 0x02;

pub const WM_KEYDOWN: u32 = 0x0100;
pub const WM_SYSKEYDOWN: u32 = 0x0104;
pub const WM_LBUTTONDOWN: u32 = 0x0201;
pub const WM_RBUTTONDOWN: u32 = 0x0204;
pub const WM_MBUTTONDOWN: u32 = 0x0207;
pub const WM_MOUSEWHEEL: u32 = 0x020A;
pub const WM_XBUTTONDOWN: u32 = 0x020B;

/// Is this a low-level hook event produced by the user (R4b)? `message` is the
/// hook's `wParam`, `flags` the structure's flags (`KBDLLHOOKSTRUCT.flags` or
/// `MSLLHOOKSTRUCT.flags`). Only presses count (a key release or mouse
/// movement alone cannot change what we type into).
pub fn is_physical_input(is_keyboard: bool, message: u32, flags: u32) -> bool {
    if is_keyboard {
        matches!(message, WM_KEYDOWN | WM_SYSKEYDOWN) && flags & (LLKHF_INJECTED | LLKHF_LOWER_IL_INJECTED) == 0
    } else {
        matches!(message, WM_LBUTTONDOWN | WM_RBUTTONDOWN | WM_MBUTTONDOWN | WM_XBUTTONDOWN | WM_MOUSEWHEEL)
            && flags & (LLMHF_INJECTED | LLMHF_LOWER_IL_INJECTED) == 0
    }
}

/// macOS (R4b): physical input happened since our last posted event when the
/// hardware idle time is shorter than the time since we last posted (our own
/// events either do not count, or count and then make the two equal).
pub fn physical_input_since(hw_idle_secs: f64, since_last_post_secs: f64) -> bool {
    hw_idle_secs + INPUT_AGE_TOLERANCE_SECS < since_last_post_secs
}

/// Wait until the user has been idle `required_ms` (R4a). `idle_ms` reads the
/// current idle time (`None`: unknown, treated as idle). Returns whether idle
/// was reached (false: gave up after `max_wait_ms`).
pub fn wait_for_idle(
    mut idle_ms: impl FnMut() -> Option<u64>,
    mut sleep_ms: impl FnMut(u64),
    required_ms: u64,
    max_wait_ms: u64,
) -> bool {
    let mut waited = 0u64;
    loop {
        match idle_ms() {
            None => return true,
            Some(i) if i >= required_ms => return true,
            Some(i) => {
                if waited >= max_wait_ms {
                    return false;
                }
                let step = (required_ms - i).clamp(10, 100).min(max_wait_ms - waited).max(1);
                sleep_ms(step);
                waited += step;
            }
        }
    }
}

// --------------------------------------------------------------- typing

/// Text as typed through keyboard events: a Tab would move keyboard focus (or
/// complete in a shell), so `\t` becomes a space (R2).
pub fn typing_text(s: &str) -> Cow<'_, str> {
    if s.contains('\t') {
        Cow::Owned(s.replace('\t', " "))
    } else {
        Cow::Borrowed(s)
    }
}

/// `SendInput` inserted only part of a batch: the modifier keys that are still
/// logically down afterwards. `batch` is `(virtual key, is_key_up)` in send
/// order, `inserted` how many events went in. Returns the keys to release.
pub fn compensating_keyups(batch: &[(u16, bool)], inserted: usize) -> Vec<u16> {
    const MODS: [u16; 4] = [0x10 /*SHIFT*/, 0x11 /*CONTROL*/, 0x12 /*MENU*/, 0x5B /*LWIN*/];
    let mut down: Vec<u16> = Vec::new();
    for &(vk, up) in batch.iter().take(inserted) {
        if !MODS.contains(&vk) {
            continue;
        }
        if up {
            down.retain(|d| *d != vk);
        } else if !down.contains(&vk) {
            down.push(vk);
        }
    }
    down
}

// ----------------------------------------------------------------- cloak

/// What `DWMWA_CLOAKED` says about a window (R6).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Cloak {
    /// Not cloaked.
    Visible,
    /// Cloaked by the shell: the window lives on another virtual desktop.
    OtherDesktop,
    /// Cloaked by its app (a hidden UWP frame): not a window the user can see.
    Hidden,
}

pub fn classify_cloak(v: u32) -> Cloak {
    const APP: u32 = 1;
    const SHELL: u32 = 2;
    if v == 0 {
        Cloak::Visible
    } else if v & SHELL != 0 {
        Cloak::OtherDesktop
    } else if v & APP != 0 {
        Cloak::Hidden
    } else {
        // DWM_CLOAKED_INHERITED only: follows its owner.
        Cloak::OtherDesktop
    }
}

// ------------------------------------------------------------- clipboard

/// Clipboard owners whose formats are rendered on demand (reading them forces
/// the owner to render, which can block on a slow or hung process and breaks
/// its live-copy state): treat the clipboard as not restorable (§4.8).
pub fn owner_renders_lazily(exe: &str) -> bool {
    const LAZY: &[&str] = &["excel.exe", "mstsc.exe", "rdpclip.exe", "powerpnt.exe", "winword.exe", "onenote.exe", "msaccess.exe"];
    let e = exe.to_lowercase();
    LAZY.contains(&e.as_str())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn title_policy() {
        assert!(title_check(false, "Chat | Alice", "Chat | Alice").is_ok());
        assert_eq!(
            title_check(false, "Chat | Alice", "Chat | Bob").unwrap_err(),
            "window changed: was 'Chat | Alice', now 'Chat | Bob'"
        );
        assert!(title_check(true, "a", "b").is_ok());
        assert!(title_check(false, "", "x").is_err());
    }

    #[test]
    fn windows_password_check_fails_closed() {
        use FocusProbe::*;
        assert!(password_verdict_strict(Element { is_password: Some(false) }).is_ok());
        assert_eq!(password_verdict_strict(Element { is_password: Some(true) }).unwrap_err(), "secure text field");
        assert_eq!(
            password_verdict_strict(Element { is_password: None }).unwrap_err(),
            "cannot verify field is not a password"
        );
        assert_eq!(password_verdict_strict(Unknown).unwrap_err(), "cannot verify field is not a password");
    }

    #[test]
    fn mac_password_check_allows_uninspectable_element_unless_secure_input() {
        use FocusProbe::*;
        assert!(password_verdict_mac(Unknown, false).is_ok());
        assert!(password_verdict_mac(Element { is_password: None }, false).is_ok());
        assert!(password_verdict_mac(Element { is_password: Some(false) }, false).is_ok());
        assert!(password_verdict_mac(Element { is_password: Some(true) }, false).is_err());
        assert!(password_verdict_mac(Unknown, true).is_err());
        assert!(password_verdict_mac(Element { is_password: Some(false) }, true).is_err());
    }

    #[test]
    fn physical_input_decision() {
        // keyboard: only non-injected presses
        assert!(is_physical_input(true, WM_KEYDOWN, 0));
        assert!(is_physical_input(true, WM_SYSKEYDOWN, 0x20));
        assert!(!is_physical_input(true, WM_KEYDOWN, LLKHF_INJECTED));
        assert!(!is_physical_input(true, WM_KEYDOWN, LLKHF_LOWER_IL_INJECTED));
        assert!(!is_physical_input(true, 0x0101 /*WM_KEYUP*/, 0));
        // mouse: clicks and wheel, not movement, not injected
        assert!(is_physical_input(false, WM_LBUTTONDOWN, 0));
        assert!(is_physical_input(false, WM_MOUSEWHEEL, 0));
        assert!(!is_physical_input(false, 0x0200 /*WM_MOUSEMOVE*/, 0));
        assert!(!is_physical_input(false, WM_LBUTTONDOWN, LLMHF_INJECTED));
    }

    #[test]
    fn mac_physical_input_sampling() {
        // our last post 0.2 s ago; hardware idle 5 s: user did nothing
        assert!(!physical_input_since(5.0, 0.2));
        // our events counted in the hw state: idle == time since our post
        assert!(!physical_input_since(0.2, 0.2));
        assert!(!physical_input_since(0.19, 0.2));
        // a key press 50 ms ago, after our post 200 ms ago
        assert!(physical_input_since(0.05, 0.2));
    }

    #[test]
    fn idle_wait_bounded() {
        // already idle
        assert!(wait_for_idle(|| Some(500), |_| panic!("no sleep"), 300, 3000));
        // unknown idle counts as idle
        assert!(wait_for_idle(|| None, |_| panic!("no sleep"), 300, 3000));
        // becomes idle after some sleeping
        let idle = std::cell::Cell::new(0u64);
        let slept = std::cell::Cell::new(0u64);
        let ok = wait_for_idle(
            || Some(idle.get()),
            |ms| {
                idle.set(idle.get() + ms);
                slept.set(slept.get() + ms);
            },
            300,
            3000,
        );
        assert!(ok);
        assert!((250..=450).contains(&slept.get()), "{}", slept.get());
        // never idle: gives up at the cap
        let mut slept = 0u64;
        let ok = wait_for_idle(|| Some(0), |ms| slept += ms, 300, 3000);
        assert!(!ok);
        assert_eq!(slept, 3000);
    }

    #[test]
    fn tabs_are_never_typed() {
        assert_eq!(typing_text("a\tb"), "a b");
        assert!(matches!(typing_text("ab"), Cow::Borrowed(_)));
    }

    #[test]
    fn partial_sendinput_releases_modifiers() {
        let shift_return = [(0x10, false), (0x0D, false), (0x0D, true), (0x10, true)];
        assert_eq!(compensating_keyups(&shift_return, 1), vec![0x10]);
        assert_eq!(compensating_keyups(&shift_return, 2), vec![0x10]);
        assert!(compensating_keyups(&shift_return, 4).is_empty());
        assert!(compensating_keyups(&shift_return, 0).is_empty());
        let ctrl_v = [(0x11, false), (0x56, false), (0x56, true), (0x11, true)];
        assert_eq!(compensating_keyups(&ctrl_v, 3), vec![0x11]);
    }

    #[test]
    fn cloak_classes() {
        assert_eq!(classify_cloak(0), Cloak::Visible);
        assert_eq!(classify_cloak(2), Cloak::OtherDesktop);
        assert_eq!(classify_cloak(2 | 4), Cloak::OtherDesktop);
        assert_eq!(classify_cloak(1), Cloak::Hidden);
        assert_eq!(classify_cloak(4), Cloak::OtherDesktop);
    }

    #[test]
    fn lazy_clipboard_owners() {
        assert!(owner_renders_lazily("EXCEL.EXE"));
        assert!(owner_renders_lazily("rdpclip.exe"));
        assert!(!owner_renders_lazily("notepad.exe"));
    }
}
