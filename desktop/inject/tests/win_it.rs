//! Windows integration test (SPEC_V2 §6 item 6w): drives Notepad through the
//! real `WindowsInjector`. Needs an interactive desktop session, so it is
//! `#[ignore]` and feature-gated:
//! `cargo test -p vq-inject --features win-it -- --ignored --nocapture --test-threads=1`
//!
//! Works with classic and Windows 11 Notepad: the document is a unique temp
//! file, so the window is found by its title either way. If no Notepad window
//! appears (headless session), the test skips with a message.
#![cfg(all(target_os = "windows", feature = "win-it"))]

use std::process::Command;
use std::time::{Duration, Instant};
use vq_inject::windows::{test_activate, test_clipboard_get, test_clipboard_set, window_text};
use vq_inject::*;

const NOTEPAD: &str = "notepad.exe";

fn wait_for<T>(timeout: Duration, mut f: impl FnMut() -> Option<T>) -> Option<T> {
    let end = Instant::now() + timeout;
    loop {
        if let Some(v) = f() {
            return Some(v);
        }
        if Instant::now() >= end {
            return None;
        }
        std::thread::sleep(Duration::from_millis(200));
    }
}

/// Poll the document text until `pred` holds (paste/typing are asynchronous).
fn text_eventually(hwnd: isize, pred: impl Fn(&str) -> bool) -> Option<String> {
    wait_for(Duration::from_secs(5), || window_text(hwnd).filter(|t| pred(t)))
}

#[test]
#[ignore = "needs an interactive desktop and drives Notepad"]
fn notepad_type_and_paste() {
    let inj = default_injector();
    assert!(inj.is_trusted(false));

    let file = std::env::temp_dir().join(format!("vq-win-it-{}.txt", std::process::id()));
    std::fs::write(&file, "").unwrap();
    let stem = file.file_stem().unwrap().to_string_lossy().to_string();
    // Win11 Notepad hands off to another process and exits; it is cleaned up by pid below.
    #[allow(clippy::zombie_processes)]
    let _child = Command::new(NOTEPAD).arg(&file).spawn().expect("launch notepad.exe");

    let Some(win) = wait_for(Duration::from_secs(20), || {
        inj.running_windows(NOTEPAD).into_iter().find(|w| w.title.contains(&stem))
    }) else {
        eprintln!("SKIP: no Notepad window appeared (no interactive desktop?)");
        let _ = std::fs::remove_file(&file);
        return;
    };
    let hwnd = win.id as isize;
    let notepad_pid = win.pid;
    let cleanup = || {
        let _ = Command::new("taskkill").args(["/F", "/T", "/PID", &notepad_pid.to_string()]).output();
        std::thread::sleep(Duration::from_millis(500));
        let _ = std::fs::remove_file(&file);
    };

    // Capture the binding with Notepad focused.
    assert!(test_activate(hwnd), "could not bring Notepad forward");
    std::thread::sleep(Duration::from_millis(500));
    let cap = match inj.capture_focused() {
        Ok(c) => c,
        Err(e) => {
            cleanup();
            panic!("capture_focused: {e}");
        }
    };
    assert!(cap.target.app_id.eq_ignore_ascii_case(NOTEPAD), "{:?}", cap.target);
    assert!(cap.target.window_title.contains(&stem));
    assert!(!cap.target.ax_insertable);
    eprintln!("captured: {:?}", cap.target);
    let slot = SlotId::new(1).unwrap();
    inj.assign(slot, cap);

    let rt = inj.resolve(slot).expect("resolve");
    assert!(!rt.rematched);
    let sentinel = "VQ-CLIPBOARD-SENTINEL";
    assert!(test_clipboard_set(sentinel));
    let caps = inj.caps(&rt).expect("caps");
    assert!(secure_refusal(&caps).is_none(), "{caps:?}");
    assert!(caps.clipboard_restorable);
    assert!(!caps.ax_insertable);

    // Short text: typed.
    let short = "typed \u{e9}\u{1f600} text";
    let plan = plan_delivery(&caps, short, &SlotSettings::default());
    assert_eq!(plan.method, DeliveryMethod::Type);
    let r = inj.execute(&plan, &rt);
    assert!(r.is_sent(), "{r:?}");
    let got = text_eventually(hwnd, |t| t.contains("typed")).unwrap_or_default();
    assert!(got.contains("typed \u{e9}\u{1f600} text"), "typed text not found: {got:?}");
    assert_eq!(test_clipboard_get().as_deref(), Some(sentinel), "typing must not touch the clipboard");

    // Long text: pasted, clipboard restored.
    let long = format!("{}END", "p".repeat(250));
    let plan = plan_delivery(&caps, &long, &SlotSettings::default());
    assert_eq!(plan.method, DeliveryMethod::Paste);
    let r = inj.execute(&plan, &rt);
    assert!(r.is_sent(), "{r:?}");
    let got = text_eventually(hwnd, |t| t.contains(&long)).unwrap_or_default();
    assert!(got.contains(&long), "pasted text not found (len {})", got.len());
    assert_eq!(test_clipboard_get().as_deref(), Some(sentinel), "clipboard must be restored");

    // Notepad no longer there: missing, never another window.
    cleanup();
    assert!(matches!(inj.resolve(slot), Err(InjectError::Missing)));
}
