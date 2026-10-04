//! Adversarial review tests for vq-inject (v2 N1/N1w). Tests named `defect_*`
//! are expected to FAIL until the defect in the review is fixed; tests named
//! `guard_*` are invariants that currently hold and must keep holding.
//! Findings: scratchpad/v2/inject-review.md.

use std::fs;

use vq_inject::planner::{plan_delivery, sanitize, Action, AppCategory, TargetCaps};
use vq_inject::{
    rematch, BindingTarget, BindingsStore, NewlineMode, RematchOutcome, SlotId, SlotSettings,
    WindowInfo,
};

fn caps(cat: AppCategory, ax: bool) -> TargetCaps {
    TargetCaps {
        category: cat,
        ax_insertable: ax,
        secure_field: false,
        secure_input: false,
        elevated: false,
        clipboard_restorable: true,
    }
}

fn settings(auto_submit: bool, mode: NewlineMode) -> SlotSettings {
    SlotSettings { auto_submit, newline_mode: mode }
}

fn typed_text(actions: &[Action]) -> String {
    actions
        .iter()
        .map(|a| match a {
            Action::TypeUnicode(s) | Action::SetClipboard(s) | Action::AxInsertSelectedText(s) => s.clone(),
            Action::ShiftReturn => "\n".into(),
            _ => String::new(),
        })
        .collect()
}

fn target(app: &str, title: &str) -> BindingTarget {
    BindingTarget {
        app_id: app.into(),
        app_name: "App".into(),
        window_title: title.into(),
        element_role: "Edit".into(),
        element_subrole: String::new(),
        ax_insertable: false,
    }
}

fn win(app: &str, title: &str, standard: bool, id: u64) -> WindowInfo {
    WindowInfo { app_id: app.into(), pid: 1000 + id as i32, title: title.into(), standard, id }
}

// ------------------------------------------------------------------ planner

/// F-tab: the Windows executor sends `\t` as a real VK_TAB (sys.rs
/// send_unicode). In a terminal slot (default `Spaces`) that triggers shell
/// completion; elsewhere it moves keyboard focus. In `Spaces` mode a tab must
/// be flattened like a line break.
#[test]
fn defect_spaces_mode_still_types_tab() {
    let p = plan_delivery(&caps(AppCategory::Terminal, false), "git status\tand more", &settings(false, NewlineMode::Spaces));
    let t = typed_text(&p.actions);
    assert!(!t.contains('\t'), "terminal Spaces plan types a Tab: {t:?}");
}

/// F-cr: a lone `\r` (old-Mac / some ASR and clipboard sources) is dropped,
/// gluing the words on either side together ("one\rtwo" -> "onetwo").
#[test]
fn defect_lone_cr_glues_words() {
    let (clean, _) = sanitize("one\rtwo");
    assert_ne!(clean, "onetwo", "lone CR silently joins words");
}

/// F-ls: U+2028/U+2029 survive sanitising and are not flattened in `Spaces`
/// mode; several apps (Electron/Chromium contenteditable, Word) treat them as
/// a line/paragraph break, so a terminal-default slot can still get a break.
#[test]
fn defect_unicode_line_separators_not_flattened_in_spaces_mode() {
    for sep in ['\u{2028}', '\u{2029}'] {
        let text = format!("a{sep}b");
        let p = plan_delivery(&caps(AppCategory::Terminal, false), &text, &settings(true, NewlineMode::Spaces));
        let t = typed_text(&p.actions);
        assert!(!t.contains(sep), "{sep:?} typed raw in Spaces mode: {t:?}");
    }
}

/// F-nl-default: a bindings.json slot without `newline_mode` (written before
/// N1w, or with `settings` omitted) loads as ShiftEnter even for a terminal,
/// where Shift+Enter arrives as Enter and submits every embedded line.
#[test]
fn defect_missing_newline_mode_for_terminal_loads_as_shift_enter() {
    let dir = tempfile::tempdir().unwrap();
    let json = r#"{"version":1,"active":1,"slots":[{"slot":1,"target":{
        "app_id":"WindowsTerminal.exe","app_name":"WindowsTerminal","window_title":"pwsh",
        "element_role":"Custom","ax_insertable":false},"settings":{"auto_submit":false}}]}"#;
    fs::write(dir.path().join("bindings.json"), json).unwrap();
    let (store, warn) = BindingsStore::load(dir.path());
    assert!(warn.is_none(), "{warn:?}");
    let r = store.get(SlotId::new(1).unwrap()).unwrap();
    assert_eq!(r.settings.newline_mode, NewlineMode::Spaces, "terminal slot migrated to ShiftEnter");
}

/// F-term-list: common Windows terminals are missing from the list, so they
/// default to ShiftEnter (Shift+Enter = Enter in mintty/Hyper/Tabby/Warp).
#[test]
fn defect_windows_terminals_missing_from_list() {
    for exe in ["mintty.exe", "Hyper.exe", "Tabby.exe", "warp.exe"] {
        assert_eq!(AppCategory::from_app_id(exe), AppCategory::Terminal, "{exe}");
        assert_eq!(SlotSettings::for_app(exe).newline_mode, NewlineMode::Spaces, "{exe}");
    }
}

// -------------------------------------------------------------------- store

/// F-case: Windows file names are case-insensitive beyond ASCII; an exe whose
/// name has a non-ASCII letter re-matches only with identical case.
#[test]
fn defect_rematch_app_id_case_non_ascii() {
    let ws = vec![win("ÄPP.EXE", "Doc", true, 1)];
    assert!(
        matches!(rematch(&target("äpp.exe", "Doc"), &ws), RematchOutcome::Matched { .. }),
        "non-ASCII exe name case difference treated as a different app"
    );
}

/// F-one-bad-slot: one out-of-range slot (or any invalid record) discards
/// every binding and moves the whole file aside.
#[test]
fn defect_one_bad_slot_discards_all_bindings() {
    let dir = tempfile::tempdir().unwrap();
    let json = r#"{"version":1,"active":1,"slots":[
        {"slot":1,"target":{"app_id":"notepad.exe","app_name":"notepad","window_title":"a","element_role":"Edit","ax_insertable":false}},
        {"slot":10,"target":{"app_id":"x.exe","app_name":"x","window_title":"b","element_role":"Edit","ax_insertable":false}}]}"#;
    fs::write(dir.path().join("bindings.json"), json).unwrap();
    let (store, _warn) = BindingsStore::load(dir.path());
    assert!(store.get(SlotId::new(1).unwrap()).is_some(), "valid slot 1 lost because slot 10 is invalid");
}

/// F-newer-version: the doc says a newer-version file gives defaults plus a
/// warning, but it is also renamed to `.corrupt`; after a downgrade the next
/// save replaces it and a later upgrade finds no bindings.
#[test]
fn defect_newer_version_file_is_moved_aside() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("bindings.json");
    fs::write(&path, r#"{"version":2,"active":0,"slots":[]}"#).unwrap();
    let (_s, warn) = BindingsStore::load(dir.path());
    assert!(warn.is_some());
    assert!(path.exists(), "newer-version bindings.json was renamed to .corrupt");
}

/// F-alias: a record carrying both `app_id` and the legacy `bundle_id` key
/// (hand edit, or a file merged across versions) is a serde duplicate-field
/// error, which discards every binding.
#[test]
fn defect_app_id_and_bundle_id_both_present() {
    let dir = tempfile::tempdir().unwrap();
    let json = r#"{"version":1,"active":1,"slots":[{"slot":1,"target":{
        "app_id":"com.apple.TextEdit","bundle_id":"com.apple.TextEdit","app_name":"TextEdit",
        "window_title":"a","element_role":"AXTextArea","ax_insertable":true}}]}"#;
    fs::write(dir.path().join("bindings.json"), json).unwrap();
    let (store, warn) = BindingsStore::load(dir.path());
    assert!(warn.is_none(), "{warn:?}");
    assert!(store.get(SlotId::new(1).unwrap()).is_some());
}

// ------------------------------------------------------------------- guards

/// Return is emitted only as the auto-submit step (at most once, after all
/// text) in every path and mode, never for embedded line breaks; typed chunks
/// are <= 20 UTF-16 units and never split a surrogate pair.
#[test]
fn guard_return_only_at_end_and_chunks_well_formed() {
    let long = "x".repeat(250);
    let samples = [
        "a\nb\r\nc\rd\u{0}\u{1b}[31m\t😀😀😀😀😀😀😀😀😀😀😀".to_string(),
        format!("{long}\n{long}\r\n\n"),
        "\n\n".into(),
        "😀".repeat(30),
    ];
    let all_caps = [
        caps(AppCategory::Native, true),
        caps(AppCategory::Native, false),
        caps(AppCategory::Terminal, false),
        TargetCaps { clipboard_restorable: false, ..caps(AppCategory::Electron, false) },
    ];
    for text in &samples {
        for c in &all_caps {
            for auto in [false, true] {
                for mode in [NewlineMode::ShiftEnter, NewlineMode::Spaces] {
                    let p = plan_delivery(c, text, &settings(auto, mode));
                    for plan in std::iter::once(&p).chain(p.fallback.as_deref()) {
                        let returns: Vec<usize> = plan
                            .actions
                            .iter()
                            .enumerate()
                            .filter(|(_, a)| **a == Action::Return)
                            .map(|(i, _)| i)
                            .collect();
                        assert!(returns.len() <= usize::from(auto), "{text:?} {c:?} {mode:?}");
                        if let Some(&i) = returns.first() {
                            assert!(
                                !plan.actions[i..].iter().any(|a| matches!(
                                    a,
                                    Action::TypeUnicode(_) | Action::CmdV | Action::ShiftReturn | Action::AxInsertSelectedText(_)
                                )),
                                "text after Return: {text:?}"
                            );
                        }
                        if mode == NewlineMode::Spaces {
                            assert!(!plan.actions.contains(&Action::ShiftReturn));
                        }
                        for a in &plan.actions {
                            if let Action::TypeUnicode(s) = a {
                                assert!(s.encode_utf16().count() <= 20);
                                assert!(!s.contains('\n') && !s.contains('\r') && !s.contains('\u{1b}'));
                            }
                        }
                    }
                }
            }
        }
    }
}

/// An ambiguous exact title is never guessed, even when one of the two
/// windows is the only standard one.
#[test]
fn guard_rematch_ambiguous_title_is_unbound() {
    let ws = vec![win("ms-teams.exe", "Chat | Microsoft Teams", true, 1), win("MS-Teams.exe", "Chat | Microsoft Teams", false, 2)];
    assert!(matches!(rematch(&target("ms-teams.exe", "Chat | Microsoft Teams"), &ws), RematchOutcome::Unbound(_)));
}
