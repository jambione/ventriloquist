//! Local macOS integration test (SPEC_V2 §6 item 6). Needs Accessibility
//! permission for the test runner, so it is `#[ignore]` and feature-gated:
//! `cargo test -p vq-inject --features mac-it -- --ignored --test-threads=1`
#![cfg(all(target_os = "macos", feature = "mac-it"))]

use std::process::Command;
use std::time::Duration;
use vq_inject::*;

const TEXTEDIT: &str = "com.apple.TextEdit";

fn osa(script: &str) -> String {
    let o = Command::new("osascript").args(["-e", script]).output().expect("osascript");
    String::from_utf8_lossy(&o.stdout).trim().to_string()
}

fn doc_text() -> String {
    osa("tell application \"TextEdit\" to get text of document 1")
}

fn fresh_textedit() {
    osa("tell application \"TextEdit\" to activate");
    osa("tell application \"TextEdit\" to make new document");
    std::thread::sleep(Duration::from_millis(800));
}

#[test]
#[ignore = "needs Accessibility permission and drives TextEdit"]
fn textedit_ax_and_keystroke_paths() {
    let inj = default_injector();
    assert!(inj.is_trusted(false), "grant Accessibility to the test runner");
    fresh_textedit();
    let cap = inj.capture_focused().expect("capture TextEdit's focused element");
    assert_eq!(cap.target.app_id, TEXTEDIT);
    assert!(cap.target.ax_insertable, "TextEdit's text area should accept AXSelectedText");
    let slot = SlotId::new(1).unwrap();
    inj.assign(slot, cap);

    // AX path.
    let rt = inj.resolve(slot).unwrap();
    let caps = inj.caps(&rt).unwrap();
    assert!(caps.ax_insertable && !secure_refusal(&caps).is_some());
    let plan = plan_delivery(&caps, "ax line one\nline two", &SlotSettings::default());
    assert_eq!(plan.method, DeliveryMethod::AxInsert);
    assert!(inj.execute(&plan, &rt).is_sent());
    assert!(doc_text().contains("ax line one"));

    // Keystroke path (forced by clearing ax_insertable): type, then paste.
    let mut caps = caps;
    caps.ax_insertable = false;
    let plan = plan_delivery(&caps, "typed \u{e9}\u{1f600}\nsecond", &SlotSettings::default());
    assert_eq!(plan.method, DeliveryMethod::Type);
    assert!(inj.execute(&plan, &rt).is_sent());
    assert!(doc_text().contains("typed"));

    let long = "p".repeat(300);
    let plan = plan_delivery(&caps, &long, &SlotSettings::default());
    assert_eq!(plan.method, DeliveryMethod::Paste);
    assert!(inj.execute(&plan, &rt).is_sent());
    assert!(doc_text().contains(&long));

    osa("tell application \"TextEdit\" to close every document saving no");
}
