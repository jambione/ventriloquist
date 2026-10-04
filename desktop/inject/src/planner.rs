//! Pure delivery planner (SPEC_V2 §4.3). No OS calls: the executor
//! (`Injector::execute`) interprets the [`Action`]s.

use crate::model::{DeliveryMethod, NewlineMode, SlotSettings};

/// Single-line text of at most this many characters (Unicode scalar values,
/// after sanitising) is typed; longer text is pasted.
pub const MAX_TYPED_CHARS: usize = 200;
/// Multi-line text up to this many characters is typed too: pasting line by
/// line races the target (SPEC_V2 §4.3, R10).
pub const MAX_TYPED_CHARS_MULTILINE: usize = 1000;
/// Maximum UTF-16 code units per typed keyboard event.
pub const TYPE_CHUNK_UTF16: usize = 20;
/// How long to wait for the target to become frontmost.
pub const FRONTMOST_TIMEOUT_MS: u64 = 500;
/// The clipboard snapshot is restored no earlier than this long after the
/// last paste key (the target reads the clipboard asynchronously, R10).
pub const CLIPBOARD_RESTORE_DELAY_MS: u64 = 400;

/// Bundle ids (compared case-insensitively) of apps where Accessibility text
/// insertion is unreliable or silently ignored, so the keystroke path is used
/// even if `AXSelectedText` looks settable: browsers, Electron apps and
/// terminals (SPEC_V2 §4.3).
pub const KEYSTROKE_PREFERRED_BUNDLE_IDS: &[(&str, AppCategory)] = &[
    // Browsers
    ("com.apple.Safari", AppCategory::Browser),
    ("com.apple.SafariTechnologyPreview", AppCategory::Browser),
    ("com.google.Chrome", AppCategory::Browser),
    ("com.google.Chrome.beta", AppCategory::Browser),
    ("com.google.Chrome.dev", AppCategory::Browser),
    ("com.google.Chrome.canary", AppCategory::Browser),
    ("org.chromium.Chromium", AppCategory::Browser),
    ("com.microsoft.edgemac", AppCategory::Browser),
    ("com.microsoft.edgemac.Beta", AppCategory::Browser),
    ("com.microsoft.edgemac.Dev", AppCategory::Browser),
    ("com.microsoft.edgemac.Canary", AppCategory::Browser),
    ("company.thebrowser.Browser", AppCategory::Browser), // Arc
    ("company.thebrowser.dia", AppCategory::Browser),
    ("org.mozilla.firefox", AppCategory::Browser),
    ("org.mozilla.firefoxdeveloperedition", AppCategory::Browser),
    ("org.mozilla.nightly", AppCategory::Browser),
    ("com.brave.Browser", AppCategory::Browser),
    ("com.brave.Browser.beta", AppCategory::Browser),
    ("com.brave.Browser.nightly", AppCategory::Browser),
    ("com.operasoftware.Opera", AppCategory::Browser),
    ("com.vivaldi.Vivaldi", AppCategory::Browser),
    ("app.zen-browser.zen", AppCategory::Browser),
    // Electron apps
    ("com.microsoft.teams2", AppCategory::Electron),
    ("com.microsoft.teams", AppCategory::Electron),
    ("com.microsoft.VSCode", AppCategory::Electron),
    ("com.microsoft.VSCodeInsiders", AppCategory::Electron),
    ("com.visualstudio.code.oss", AppCategory::Electron),
    ("com.todesktop.230313mzl4w4u92", AppCategory::Electron), // Cursor
    ("com.tinyspeck.slackmacgap", AppCategory::Electron),
    ("com.hnc.Discord", AppCategory::Electron),
    ("com.anthropic.claudefordesktop", AppCategory::Electron),
    ("com.exafunction.windsurf", AppCategory::Electron),
    ("com.postmanlabs.mac", AppCategory::Electron),
    ("com.linear", AppCategory::Electron),
    ("com.electron.dockerdesktop", AppCategory::Electron),
    ("com.termius.mac", AppCategory::Electron),
    ("com.openai.chat", AppCategory::Electron),
    ("notion.id", AppCategory::Electron),
    ("md.obsidian", AppCategory::Electron),
    ("com.figma.Desktop", AppCategory::Electron),
    ("org.whispersystems.signal-desktop", AppCategory::Electron),
    ("com.github.GitHubClient", AppCategory::Electron),
    // Windows executables (browsers, Electron apps, terminals)
    ("msedge.exe", AppCategory::Browser),
    ("chrome.exe", AppCategory::Browser),
    ("firefox.exe", AppCategory::Browser),
    ("brave.exe", AppCategory::Browser),
    ("opera.exe", AppCategory::Browser),
    ("vivaldi.exe", AppCategory::Browser),
    ("arc.exe", AppCategory::Browser),
    ("ms-teams.exe", AppCategory::Electron),
    ("Teams.exe", AppCategory::Electron),
    ("Code.exe", AppCategory::Electron),
    ("Code - Insiders.exe", AppCategory::Electron),
    ("Cursor.exe", AppCategory::Electron),
    ("slack.exe", AppCategory::Electron),
    ("Discord.exe", AppCategory::Electron),
    ("Claude.exe", AppCategory::Electron),
    ("ChatGPT.exe", AppCategory::Electron),
    ("Windsurf.exe", AppCategory::Electron),
    ("Notion.exe", AppCategory::Electron),
    ("Obsidian.exe", AppCategory::Electron),
    ("Signal.exe", AppCategory::Electron),
    ("Figma.exe", AppCategory::Electron),
    ("WhatsApp.exe", AppCategory::Electron),
    ("Postman.exe", AppCategory::Electron),
    ("Linear.exe", AppCategory::Electron),
    ("GitHubDesktop.exe", AppCategory::Electron),
    ("Termius.exe", AppCategory::Electron),
    ("WindowsTerminal.exe", AppCategory::Terminal),
    ("mintty.exe", AppCategory::Terminal),
    ("Hyper.exe", AppCategory::Terminal),
    ("Tabby.exe", AppCategory::Terminal),
    ("warp.exe", AppCategory::Terminal),
    ("ConEmu.exe", AppCategory::Terminal),
    ("ConEmu64.exe", AppCategory::Terminal),
    ("putty.exe", AppCategory::Terminal),
    ("bash.exe", AppCategory::Terminal),
    ("wsl.exe", AppCategory::Terminal),
    ("kitty.exe", AppCategory::Terminal),
    ("wt.exe", AppCategory::Terminal),
    ("OpenConsole.exe", AppCategory::Terminal),
    ("conhost.exe", AppCategory::Terminal),
    ("powershell.exe", AppCategory::Terminal),
    ("pwsh.exe", AppCategory::Terminal),
    ("cmd.exe", AppCategory::Terminal),
    ("wezterm-gui.exe", AppCategory::Terminal),
    ("alacritty.exe", AppCategory::Terminal),
    // Terminals
    ("com.apple.Terminal", AppCategory::Terminal),
    ("com.googlecode.iterm2", AppCategory::Terminal),
    ("dev.warp.Warp-Stable", AppCategory::Terminal),
    ("dev.warp.Warp", AppCategory::Terminal),
    ("com.mitchellh.ghostty", AppCategory::Terminal),
    ("com.github.wez.wezterm", AppCategory::Terminal),
    ("org.alacritty", AppCategory::Terminal),
    ("net.kovidgoyal.kitty", AppCategory::Terminal),
    ("co.zeit.hyper", AppCategory::Terminal),
    ("com.raphaelamorim.rio", AppCategory::Terminal),
];

/// Bundle-id prefixes treated like the list above (apps that ship variants).
pub const KEYSTROKE_PREFERRED_PREFIXES: &[(&str, AppCategory)] = &[
    ("org.mozilla.", AppCategory::Browser),
    ("dev.warp.", AppCategory::Terminal),
    ("com.electron.", AppCategory::Electron),
];

/// Coarse app category that decides the insertion path.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AppCategory {
    /// Native (AppKit/SwiftUI) app: AX insertion allowed.
    Native,
    Browser,
    Electron,
    Terminal,
}

impl AppCategory {
    pub fn from_app_id(app_id: &str) -> AppCategory {
        let b = app_id.to_lowercase();
        for (id, cat) in KEYSTROKE_PREFERRED_BUNDLE_IDS {
            if id.to_lowercase() == b {
                return *cat;
            }
        }
        for (p, cat) in KEYSTROKE_PREFERRED_PREFIXES {
            if b.starts_with(&p.to_lowercase()) {
                return *cat;
            }
        }
        AppCategory::Native
    }

    /// Category implied by a Windows window class (a console window of an
    /// exe we do not list, e.g. `python.exe` or `node.exe` in conhost).
    pub fn from_window_class(class: &str) -> Option<AppCategory> {
        const TERMINAL_CLASSES: &[&str] = &[
            "ConsoleWindowClass",
            "CASCADIA_HOSTING_WINDOW_CLASS",
            "PseudoConsoleWindow",
            "mintty",
            "VirtualConsoleClass",
            "PuTTY",
        ];
        TERMINAL_CLASSES
            .iter()
            .any(|c| c.eq_ignore_ascii_case(class))
            .then_some(AppCategory::Terminal)
    }

    pub fn keystroke_preferred(self) -> bool {
        self != AppCategory::Native
    }
}

/// Category of an app: by id first, then (when the id is unknown) by window class.
pub fn category_for(app_id: &str, window_class: &str) -> AppCategory {
    match AppCategory::from_app_id(app_id) {
        AppCategory::Native => AppCategory::from_window_class(window_class).unwrap_or(AppCategory::Native),
        c => c,
    }
}

/// What the planner needs to know about the target.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TargetCaps {
    pub category: AppCategory,
    /// The bound element is a native text field/area whose `AXSelectedText`
    /// is settable.
    pub ax_insertable: bool,
    /// The bound element is a secure text field (`AXSecureTextField`).
    pub secure_field: bool,
    /// `IsSecureEventInputEnabled()` is true system-wide.
    pub secure_input: bool,
    /// The target process is elevated and we are not (Windows UIPI).
    pub elevated: bool,
    /// The current clipboard can be snapshotted and restored losslessly. When
    /// false, long text is typed instead of pasted so the user's clipboard is
    /// never lost (SPEC_V2 §4.8). Always true on macOS.
    pub clipboard_restorable: bool,
}

impl TargetCaps {
    pub fn from_app(app_id: &str, ax_insertable: bool) -> Self {
        TargetCaps {
            category: AppCategory::from_app_id(app_id),
            ax_insertable,
            secure_field: false,
            secure_input: false,
            elevated: false,
            clipboard_restorable: true,
        }
    }
}

/// `Some(reason)` when the delivery must be refused (`blocked`, §4.3 step 2).
pub fn secure_refusal(caps: &TargetCaps) -> Option<String> {
    if caps.secure_field {
        Some("secure text field".to_string())
    } else if caps.secure_input {
        Some("secure input enabled".to_string())
    } else if caps.elevated {
        Some("target is elevated".to_string())
    } else {
        None
    }
}

/// One step of a delivery. Executed in order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Action {
    /// Set `AXSelectedText` on the bound element and read the value back.
    AxInsertSelectedText(String),
    /// Remember the frontmost app, then activate the target app and raise the
    /// bound window.
    Activate,
    /// Poll until the target is frontmost; otherwise the delivery fails.
    WaitFrontmost { timeout_ms: u64 },
    /// Set `AXFocused` on the bound element (if still valid).
    FocusElement,
    /// Type up to 20 UTF-16 units as Unicode keyboard events.
    TypeUnicode(String),
    ShiftReturn,
    /// Snapshot every pasteboard item and type.
    SnapshotClipboard,
    SetClipboard(String),
    CmdV,
    /// After `delay_ms`, restore the snapshot unless the pasteboard's
    /// `changeCount` differs from the one we set.
    RestoreClipboardIfUnchanged { delay_ms: u64 },
    Return,
    /// Re-activate the app that was frontmost at `Activate` (no-op if it was
    /// the target or there was none).
    ReactivatePrevious,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Plan {
    pub method: DeliveryMethod,
    pub actions: Vec<Action>,
    /// AX plans carry the keystroke plan to run if the AX insertion fails or
    /// cannot be confirmed by the read-back.
    pub fallback: Option<Box<Plan>>,
    /// Number of control characters dropped from the text (to be logged).
    pub dropped_controls: usize,
    /// Set when [`secure_refusal`] applies; `actions` is then empty.
    pub blocked: Option<String>,
}

impl Plan {
    /// Nothing to do (empty text after sanitising, or blocked).
    pub fn is_noop(&self) -> bool {
        self.actions.is_empty()
    }
}

/// Normalise and clean text: `\r\n`, a lone `\r`, U+2028, U+2029 and U+0085
/// all become one `\n`; other control characters except `\t` are dropped.
/// Returns the text and the number of dropped characters.
pub fn sanitize(text: &str) -> (String, usize) {
    let mut out = String::with_capacity(text.len());
    let mut dropped = 0;
    let mut it = text.chars().peekable();
    while let Some(c) = it.next() {
        match c {
            '\r' if it.peek() == Some(&'\n') => {} // part of CRLF, the \n follows
            '\r' | '\u{2028}' | '\u{2029}' | '\u{85}' => out.push('\n'),
            '\n' | '\t' => out.push(c),
            c if c.is_control() => dropped += 1,
            c => out.push(c),
        }
    }
    (out, dropped)
}

/// Bidirectional controls that can make a command line display differently
/// from what runs; stripped for terminals.
fn is_bidi_control(c: char) -> bool {
    matches!(c, '\u{202A}'..='\u{202E}' | '\u{2066}'..='\u{2069}' | '\u{200E}' | '\u{200F}' | '\u{061C}')
}

/// Split into chunks of at most `TYPE_CHUNK_UTF16` UTF-16 units, never
/// splitting a surrogate pair.
fn chunks(line: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut units = 0;
    for c in line.chars() {
        let n = c.len_utf16();
        if units + n > TYPE_CHUNK_UTF16 {
            out.push(std::mem::take(&mut cur));
            units = 0;
        }
        cur.push(c);
        units += n;
    }
    if !cur.is_empty() {
        out.push(cur);
    }
    out
}

fn keystroke_plan(clean: &str, auto_submit: bool, can_paste: bool, dropped: usize) -> Plan {
    let mut actions = vec![
        Action::Activate,
        Action::WaitFrontmost { timeout_ms: FRONTMOST_TIMEOUT_MS },
        Action::FocusElement,
    ];
    let method;
    let limit = if clean.contains('\n') { MAX_TYPED_CHARS_MULTILINE } else { MAX_TYPED_CHARS };
    if !can_paste || clean.chars().count() <= limit {
        method = DeliveryMethod::Type;
        for (i, line) in clean.split('\n').enumerate() {
            if i > 0 {
                actions.push(Action::ShiftReturn);
            }
            // A typed Tab would move keyboard focus (or complete in a shell):
            // type a space instead. Pasted text keeps its tabs (R2).
            let line = line.replace('\t', " ");
            actions.extend(chunks(&line).into_iter().map(Action::TypeUnicode));
        }
    } else {
        method = DeliveryMethod::Paste;
        let mut body = Vec::new();
        let mut pasted = false;
        for (i, line) in clean.split('\n').enumerate() {
            if i > 0 {
                body.push(Action::ShiftReturn);
            }
            if !line.is_empty() {
                body.push(Action::SetClipboard(line.to_string()));
                body.push(Action::CmdV);
                pasted = true;
            }
        }
        if pasted {
            actions.push(Action::SnapshotClipboard);
        }
        actions.extend(body);
        if pasted {
            actions.push(Action::RestoreClipboardIfUnchanged {
                delay_ms: CLIPBOARD_RESTORE_DELAY_MS,
            });
        }
    }
    if auto_submit {
        actions.push(Action::Return);
    }
    actions.push(Action::ReactivatePrevious);
    Plan { method, actions, fallback: None, dropped_controls: dropped, blocked: None }
}

/// Plan the delivery of `text` (the entry's final text, exactly) to a target.
///
/// - Refused targets give an empty plan with `blocked` set.
/// - Empty text (after sanitising) gives an empty plan (nothing is sent, not
///   even auto-submit).
/// - AX path: native app, `ax_insertable`, not keystroke-preferred. One
///   `AxInsertSelectedText` with `\n` for breaks, with the keystroke plan as
///   `fallback`. With auto-submit the target must also be activated and
///   focused to receive Return (AX insertion needs no activation, but a
///   keystroke does).
/// - Keystroke path otherwise: type (<= 200 chars) or paste (> 200); text is
///   always typed when `caps.clipboard_restorable` is false.
/// - `NewlineMode::Spaces` turns each line break into a space first.
pub fn plan_delivery(caps: &TargetCaps, text: &str, settings: &SlotSettings) -> Plan {
    let (mut clean, mut dropped) = sanitize(text);
    if caps.category == AppCategory::Terminal {
        let before = clean.chars().count();
        clean.retain(|c| !is_bidi_control(c));
        dropped += before - clean.chars().count();
    }
    if settings.newline_mode == NewlineMode::Spaces {
        // Flatten: every line break (already normalised to `\n`) and every
        // tab becomes one space.
        clean = clean.replace(['\n', '\t'], " ");
    }
    let mut plan = if let Some(reason) = secure_refusal(caps) {
        Plan {
            method: DeliveryMethod::Type,
            actions: vec![],
            fallback: None,
            dropped_controls: dropped,
            blocked: Some(reason),
        }
    } else if clean.is_empty() {
        Plan {
            method: DeliveryMethod::Type,
            actions: vec![],
            fallback: None,
            dropped_controls: dropped,
            blocked: None,
        }
    } else if caps.ax_insertable && !caps.category.keystroke_preferred() {
        let mut actions = vec![Action::AxInsertSelectedText(clean.clone())];
        if settings.auto_submit {
            actions.extend([
                Action::Activate,
                Action::WaitFrontmost { timeout_ms: FRONTMOST_TIMEOUT_MS },
                Action::FocusElement,
                Action::Return,
                Action::ReactivatePrevious,
            ]);
        }
        Plan {
            method: DeliveryMethod::AxInsert,
            actions,
            fallback: Some(Box::new(keystroke_plan(&clean, settings.auto_submit, caps.clipboard_restorable, dropped))),
            dropped_controls: dropped,
            blocked: None,
        }
    } else {
        keystroke_plan(&clean, settings.auto_submit, caps.clipboard_restorable, dropped)
    };
    plan.dropped_controls = dropped;
    plan
}

#[cfg(test)]
mod tests {
    use super::*;

    fn native(ax: bool) -> TargetCaps {
        TargetCaps { category: AppCategory::Native, ax_insertable: ax, secure_field: false, secure_input: false, elevated: false, clipboard_restorable: true }
    }
    fn cat(c: AppCategory, ax: bool) -> TargetCaps {
        TargetCaps { category: c, ..native(ax) }
    }
    fn off() -> SlotSettings {
        SlotSettings { auto_submit: false, newline_mode: NewlineMode::ShiftEnter }
    }
    fn on() -> SlotSettings {
        SlotSettings { auto_submit: true, newline_mode: NewlineMode::ShiftEnter }
    }
    fn typed(a: &[Action]) -> String {
        a.iter()
            .map(|x| match x {
                Action::TypeUnicode(s) => s.clone(),
                Action::ShiftReturn => "\n".into(),
                _ => String::new(),
            })
            .collect()
    }
    fn head() -> Vec<Action> {
        vec![
            Action::Activate,
            Action::WaitFrontmost { timeout_ms: 500 },
            Action::FocusElement,
        ]
    }

    #[test]
    fn categories() {
        for id in ["com.apple.Safari", "com.google.Chrome", "com.microsoft.edgemac", "company.thebrowser.Browser", "org.mozilla.firefox", "com.brave.Browser"] {
            assert_eq!(AppCategory::from_app_id(id), AppCategory::Browser, "{id}");
        }
        for id in ["com.microsoft.teams2", "com.microsoft.teams", "com.microsoft.VSCode", "com.tinyspeck.slackmacgap", "com.hnc.Discord"] {
            assert_eq!(AppCategory::from_app_id(id), AppCategory::Electron, "{id}");
        }
        for id in ["com.apple.Terminal", "com.googlecode.iterm2", "dev.warp.Warp-Stable", "com.mitchellh.ghostty", "com.github.wez.wezterm", "org.alacritty", "net.kovidgoyal.kitty"] {
            assert_eq!(AppCategory::from_app_id(id), AppCategory::Terminal, "{id}");
        }
        for id in ["com.apple.TextEdit", "com.apple.Notes", "", "com.example.unknown"] {
            assert_eq!(AppCategory::from_app_id(id), AppCategory::Native, "{id}");
        }
        // case-insensitive, prefix variants
        for id in ["ms-teams.exe", "Teams.exe", "MSEDGE.EXE", "chrome.exe", "firefox.exe", "Code.exe", "slack.exe"] {
            assert!(AppCategory::from_app_id(id).keystroke_preferred(), "{id}");
        }
        for id in ["WindowsTerminal.exe", "OpenConsole.exe", "conhost.exe", "powershell.exe", "pwsh.exe", "cmd.exe", "wt.exe"] {
            assert_eq!(AppCategory::from_app_id(id), AppCategory::Terminal, "{id}");
        }
        assert_eq!(AppCategory::from_app_id("notepad.exe"), AppCategory::Native);
        assert_eq!(AppCategory::from_app_id("COM.GOOGLE.CHROME"), AppCategory::Browser);
        assert_eq!(AppCategory::from_app_id("org.mozilla.firefoxfoo"), AppCategory::Browser);
        assert_eq!(AppCategory::from_app_id("com.electron.foo"), AppCategory::Electron);
        assert!(AppCategory::Terminal.keystroke_preferred());
        assert!(!AppCategory::Native.keystroke_preferred());
    }

    #[test]
    fn list_has_no_duplicates() {
        let mut ids: Vec<String> = KEYSTROKE_PREFERRED_BUNDLE_IDS.iter().map(|(i, _)| i.to_ascii_lowercase()).collect();
        let n = ids.len();
        ids.sort();
        ids.dedup();
        assert_eq!(ids.len(), n);
    }

    #[test]
    fn secure_refusals() {
        assert_eq!(secure_refusal(&native(true)), None);
        let mut c = native(true);
        c.secure_field = true;
        assert_eq!(secure_refusal(&c).as_deref(), Some("secure text field"));
        let mut c = native(true);
        c.secure_input = true;
        assert_eq!(secure_refusal(&c).as_deref(), Some("secure input enabled"));
        c.secure_field = true;
        assert_eq!(secure_refusal(&c).as_deref(), Some("secure text field"));
        let c = TargetCaps { elevated: true, ..native(true) };
        assert_eq!(secure_refusal(&c).as_deref(), Some("target is elevated"));
        let p = plan_delivery(&c, "hi", &on());
        assert!(p.is_noop());
        assert_eq!(p.blocked.as_deref(), Some("target is elevated"));
    }

    #[test]
    fn blocked_plan_has_no_actions() {
        for c in [
            TargetCaps { secure_field: true, ..native(true) },
            TargetCaps { secure_input: true, ..native(false) },
        ] {
            let p = plan_delivery(&c, "hello", &on());
            assert!(p.is_noop());
            assert!(p.blocked.is_some());
            assert!(p.fallback.is_none());
        }
    }

    #[test]
    fn ax_path_native_insertable() {
        let p = plan_delivery(&native(true), "hello world", &off());
        assert_eq!(p.method, DeliveryMethod::AxInsert);
        assert_eq!(p.actions, vec![Action::AxInsertSelectedText("hello world".into())]);
        assert_eq!(p.blocked, None);
        let fb = p.fallback.expect("fallback");
        assert_eq!(fb.method, DeliveryMethod::Type);
        assert_eq!(typed(&fb.actions), "hello world");
        assert!(fb.fallback.is_none());
    }

    #[test]
    fn ax_path_keeps_newlines_as_lf() {
        let p = plan_delivery(&native(true), "a\r\nb\nc", &off());
        assert_eq!(p.actions, vec![Action::AxInsertSelectedText("a\nb\nc".into())]);
    }

    #[test]
    fn ax_path_long_text_is_not_pasted() {
        let text = "x".repeat(1000);
        let p = plan_delivery(&native(true), &text, &off());
        assert_eq!(p.method, DeliveryMethod::AxInsert);
        assert_eq!(p.actions, vec![Action::AxInsertSelectedText(text.clone())]);
        assert_eq!(p.fallback.unwrap().method, DeliveryMethod::Paste);
    }

    #[test]
    fn ax_path_auto_submit_activates_then_returns() {
        let p = plan_delivery(&native(true), "hi", &on());
        assert_eq!(
            p.actions,
            vec![
                Action::AxInsertSelectedText("hi".into()),
                Action::Activate,
                Action::WaitFrontmost { timeout_ms: 500 },
                Action::FocusElement,
                Action::Return,
                Action::ReactivatePrevious,
            ]
        );
        let fb = p.fallback.unwrap();
        assert_eq!(fb.actions.iter().filter(|a| **a == Action::Return).count(), 1);
    }

    #[test]
    fn not_insertable_uses_keystrokes() {
        let p = plan_delivery(&native(false), "hi", &off());
        assert_eq!(p.method, DeliveryMethod::Type);
        assert!(p.fallback.is_none());
        assert_eq!(
            p.actions,
            [head(), vec![Action::TypeUnicode("hi".into())], vec![Action::ReactivatePrevious]].concat()
        );
    }

    #[test]
    fn keystroke_preferred_categories_skip_ax_even_if_insertable() {
        for c in [AppCategory::Browser, AppCategory::Electron, AppCategory::Terminal] {
            let p = plan_delivery(&cat(c, true), "hi", &off());
            assert_eq!(p.method, DeliveryMethod::Type, "{c:?}");
            assert!(p.fallback.is_none());
            assert!(!p.actions.iter().any(|a| matches!(a, Action::AxInsertSelectedText(_))));
        }
    }

    #[test]
    fn typing_chunks_at_20_utf16_units() {
        let text = "a".repeat(45);
        let p = plan_delivery(&native(false), &text, &off());
        let chunks: Vec<&String> = p.actions.iter().filter_map(|a| if let Action::TypeUnicode(s) = a { Some(s) } else { None }).collect();
        assert_eq!(chunks.iter().map(|c| c.len()).collect::<Vec<_>>(), vec![20, 20, 5]);
        assert_eq!(typed(&p.actions), text);
    }

    #[test]
    fn chunks_never_split_surrogate_pairs() {
        // 19 ASCII + one astral char (2 units) must start a new chunk.
        let text = format!("{}😀tail", "a".repeat(19));
        let p = plan_delivery(&native(false), &text, &off());
        let cs: Vec<&String> = p.actions.iter().filter_map(|a| if let Action::TypeUnicode(s) = a { Some(s) } else { None }).collect();
        assert_eq!(cs[0], &"a".repeat(19));
        assert!(cs[1].starts_with('😀'));
        for c in &cs {
            assert!(c.encode_utf16().count() <= 20);
        }
        assert_eq!(typed(&p.actions), text);
        // All-astral text: 10 per chunk.
        let text = "😀".repeat(25);
        let p = plan_delivery(&native(false), &text, &off());
        for a in &p.actions {
            if let Action::TypeUnicode(s) = a {
                assert!(s.encode_utf16().count() <= 20);
            }
        }
        assert_eq!(typed(&p.actions), text);
    }

    #[test]
    fn line_breaks_are_shift_return() {
        let p = plan_delivery(&native(false), "one\ntwo\n\nthree\n", &off());
        assert_eq!(
            p.actions,
            [
                head(),
                vec![
                    Action::TypeUnicode("one".into()),
                    Action::ShiftReturn,
                    Action::TypeUnicode("two".into()),
                    Action::ShiftReturn,
                    Action::ShiftReturn,
                    Action::TypeUnicode("three".into()),
                    Action::ShiftReturn,
                    Action::ReactivatePrevious,
                ]
            ]
            .concat()
        );
        assert!(!p.actions.contains(&Action::Return));
    }

    #[test]
    fn crlf_is_one_break() {
        let p = plan_delivery(&native(false), "a\r\nb", &off());
        assert_eq!(p.actions.iter().filter(|a| **a == Action::ShiftReturn).count(), 1);
        assert_eq!(typed(&p.actions), "a\nb");
        // \r\n\r\n is two breaks
        let p = plan_delivery(&native(false), "a\r\n\r\nb", &off());
        assert_eq!(p.actions.iter().filter(|a| **a == Action::ShiftReturn).count(), 2);
    }

    #[test]
    fn lone_cr_and_unicode_separators_are_line_breaks() {
        let p = plan_delivery(&native(false), "a\rb", &off());
        assert_eq!(typed(&p.actions), "a\nb");
        assert_eq!(p.dropped_controls, 0);
        let (c, d) = sanitize("a\u{2028}b\u{2029}c\u{85}d");
        assert_eq!((c.as_str(), d), ("a\nb\nc\nd", 0));
    }

    #[test]
    fn typed_tabs_become_spaces_pasted_tabs_stay() {
        let p = plan_delivery(&native(false), "a\tb", &off());
        assert_eq!(typed(&p.actions), "a b");
        let long = format!("{}\tz", "x".repeat(300));
        let p = plan_delivery(&native(false), &long, &off());
        assert_eq!(p.method, DeliveryMethod::Paste);
        assert!(p.actions.iter().any(|a| matches!(a, Action::SetClipboard(t) if t.contains('\t'))));
    }

    #[test]
    fn terminals_lose_bidi_controls() {
        let p = plan_delivery(&cat(AppCategory::Terminal, false), "ls \u{202E}gpj.txt\u{2066}", &off());
        assert_eq!(typed(&p.actions), "ls gpj.txt");
        assert_eq!(p.dropped_controls, 2);
        let p = plan_delivery(&native(false), "a\u{202E}b", &off());
        assert_eq!(typed(&p.actions), "a\u{202E}b");
    }

    #[test]
    fn window_class_identifies_consoles() {
        assert_eq!(category_for("python.exe", "ConsoleWindowClass"), AppCategory::Terminal);
        assert_eq!(category_for("python.exe", "TkTopLevel"), AppCategory::Native);
        assert_eq!(category_for("Code.exe", "ConsoleWindowClass"), AppCategory::Electron);
        for id in ["Claude.exe", "com.anthropic.claudefordesktop"] {
            assert_eq!(AppCategory::from_app_id(id), AppCategory::Electron);
        }
    }

    #[test]
    fn control_characters_dropped_except_newline_and_tab() {
        // U+0085 (NEL) is a line break now, not a dropped control.
        let text = "a\u{0}b\u{7}c\u{1b}d\u{7f}e\u{85}f\tg\nh";
        let (clean, dropped) = sanitize(text);
        assert_eq!(clean, "abcde\nf\tg\nh");
        assert_eq!(dropped, 4);
        // Typed: the tab becomes a space (R2).
        let p = plan_delivery(&native(false), text, &off());
        assert_eq!(typed(&p.actions), "abcde\nf g\nh");
        assert_eq!(p.dropped_controls, 4);
        // AX path keeps it.
        let p = plan_delivery(&native(true), text, &off());
        assert_eq!(p.actions, vec![Action::AxInsertSelectedText("abcde\nf\tg\nh".into())]);
        assert_eq!(p.dropped_controls, 4);
    }

    #[test]
    fn text_is_not_trimmed_or_decorated() {
        let p = plan_delivery(&native(false), "  hi  ", &off());
        assert_eq!(typed(&p.actions), "  hi  ");
        let p = plan_delivery(&native(true), " \n x \n", &off());
        assert_eq!(p.actions, vec![Action::AxInsertSelectedText(" \n x \n".into())]);
    }

    #[test]
    fn empty_or_all_control_text_is_noop_even_with_auto_submit() {
        for t in ["", "\u{0}\u{1}"] {
            for caps in [native(true), native(false)] {
                let p = plan_delivery(&caps, t, &on());
                assert!(p.is_noop(), "{t:?}");
                assert!(p.blocked.is_none());
            }
        }
    }

    #[test]
    fn threshold_200_types_201_pastes() {
        let t200 = "a".repeat(200);
        let p = plan_delivery(&native(false), &t200, &off());
        assert_eq!(p.method, DeliveryMethod::Type);
        let t201 = "a".repeat(201);
        let p = plan_delivery(&native(false), &t201, &off());
        assert_eq!(p.method, DeliveryMethod::Paste);
    }

    #[test]
    fn threshold_counts_chars_not_bytes_or_utf16() {
        let t = "é".repeat(200); // 400 bytes
        assert_eq!(plan_delivery(&native(false), &t, &off()).method, DeliveryMethod::Type);
        let t = "😀".repeat(200); // 400 UTF-16 units
        assert_eq!(plan_delivery(&native(false), &t, &off()).method, DeliveryMethod::Type);
        let t = "😀".repeat(201);
        assert_eq!(plan_delivery(&native(false), &t, &off()).method, DeliveryMethod::Paste);
    }

    #[test]
    fn threshold_counts_line_breaks_and_sanitised_text() {
        // 199 chars + \n = 200: typed. One more: pasted.
        let t = format!("{}\nb", "a".repeat(198));
        assert_eq!(t.chars().count(), 200);
        assert_eq!(plan_delivery(&native(false), &t, &off()).method, DeliveryMethod::Type);
        // Multi-line text is typed up to 1,000 chars (R10), pasted beyond.
        let t = format!("{}\nbc", "a".repeat(198));
        assert_eq!(plan_delivery(&native(false), &t, &off()).method, DeliveryMethod::Type);
        let t = format!("{}\n{}", "a".repeat(499), "b".repeat(500));
        assert_eq!(t.chars().count(), 1000);
        assert_eq!(plan_delivery(&native(false), &t, &off()).method, DeliveryMethod::Type);
        let t = format!("{}\n{}", "a".repeat(499), "b".repeat(501));
        assert_eq!(plan_delivery(&native(false), &t, &off()).method, DeliveryMethod::Paste);
        let t = "a".repeat(201);
        assert_eq!(plan_delivery(&native(false), &t, &off()).method, DeliveryMethod::Paste);
        // CRLF counts once, dropped controls don't count.
        let t = format!("{}\r\nb{}", "a".repeat(198), "\u{0}".repeat(50));
        assert_eq!(plan_delivery(&native(false), &t, &off()).method, DeliveryMethod::Type);
    }

    #[test]
    fn paste_plan_structure() {
        let long = "x".repeat(1001);
        let text = format!("{long}\nsecond line\n\nlast");
        let p = plan_delivery(&native(false), &text, &off());
        assert_eq!(p.method, DeliveryMethod::Paste);
        assert_eq!(
            p.actions,
            [
                head(),
                vec![
                    Action::SnapshotClipboard,
                    Action::SetClipboard(long),
                    Action::CmdV,
                    Action::ShiftReturn,
                    Action::SetClipboard("second line".into()),
                    Action::CmdV,
                    Action::ShiftReturn,
                    Action::ShiftReturn,
                    Action::SetClipboard("last".into()),
                    Action::CmdV,
                    Action::RestoreClipboardIfUnchanged { delay_ms: 400 },
                    Action::ReactivatePrevious,
                ]
            ]
            .concat()
        );
    }

    #[test]
    fn paste_plan_restores_before_return() {
        let p = plan_delivery(&native(false), &"x".repeat(300), &on());
        let n = p.actions.len();
        assert_eq!(p.actions[n - 3], Action::RestoreClipboardIfUnchanged { delay_ms: 400 });
        assert_eq!(p.actions[n - 2], Action::Return);
        assert_eq!(p.actions[n - 1], Action::ReactivatePrevious);
        assert_eq!(p.actions.iter().filter(|a| **a == Action::SnapshotClipboard).count(), 1);
    }

    #[test]
    fn paste_of_only_newlines_touches_no_clipboard() {
        let p = plan_delivery(&native(false), &"\n".repeat(1001), &off());
        assert_eq!(p.method, DeliveryMethod::Paste);
        assert!(!p.actions.contains(&Action::SnapshotClipboard));
        assert!(!p.actions.iter().any(|a| matches!(a, Action::SetClipboard(_) | Action::CmdV | Action::RestoreClipboardIfUnchanged { .. })));
        assert_eq!(p.actions.iter().filter(|a| **a == Action::ShiftReturn).count(), 1001);
    }

    #[test]
    fn auto_submit_off_never_returns() {
        for t in ["hi", "a\nb", &"x".repeat(300)] {
            for caps in [native(true), native(false), cat(AppCategory::Terminal, true)] {
                let p = plan_delivery(&caps, t, &off());
                assert!(!p.actions.contains(&Action::Return), "{t:?}");
                if let Some(fb) = p.fallback {
                    assert!(!fb.actions.contains(&Action::Return));
                }
            }
        }
    }

    #[test]
    fn auto_submit_on_returns_once_at_the_end_before_reactivate() {
        for caps in [native(false), cat(AppCategory::Terminal, true), cat(AppCategory::Electron, false)] {
            let p = plan_delivery(&caps, "hi\nthere", &on());
            let n = p.actions.len();
            assert_eq!(p.actions[n - 2], Action::Return);
            assert_eq!(p.actions[n - 1], Action::ReactivatePrevious);
            assert_eq!(p.actions.iter().filter(|a| **a == Action::Return).count(), 1);
        }
    }

    #[test]
    fn keystroke_plans_activate_and_wait_before_any_key() {
        let p = plan_delivery(&cat(AppCategory::Terminal, false), "a\nb", &on());
        assert_eq!(&p.actions[..3], &head()[..]);
        let first_key = p
            .actions
            .iter()
            .position(|a| matches!(a, Action::TypeUnicode(_) | Action::ShiftReturn | Action::CmdV | Action::Return))
            .unwrap();
        assert!(first_key >= 3);
        assert_eq!(*p.actions.last().unwrap(), Action::ReactivatePrevious);
    }

    #[test]
    fn dropped_controls_zero_for_clean_text() {
        assert_eq!(plan_delivery(&native(false), "clean\n\ttext", &off()).dropped_controls, 0);
    }

    #[test]
    fn unicode_text_is_preserved() {
        let t = "héllo 日本語 😀 العربية";
        let p = plan_delivery(&native(false), t, &off());
        assert_eq!(typed(&p.actions), t);
    }

    #[test]
    fn unrestorable_clipboard_types_long_text() {
        let text = "y".repeat(500);
        let caps = TargetCaps { clipboard_restorable: false, ..native(false) };
        let p = plan_delivery(&caps, &text, &off());
        assert_eq!(p.method, DeliveryMethod::Type);
        assert_eq!(typed(&p.actions), text);
        assert!(!p.actions.iter().any(|a| matches!(a, Action::SetClipboard(_) | Action::CmdV | Action::SnapshotClipboard)));
        // Multi-line long text keeps its Shift+Enter breaks.
        let multi = format!("{}\n{}", "a".repeat(150), "b".repeat(150));
        let p = plan_delivery(&caps, &multi, &off());
        assert_eq!(p.method, DeliveryMethod::Type);
        assert_eq!(typed(&p.actions), multi);
        // The AX fallback also types.
        let caps = TargetCaps { clipboard_restorable: false, ..native(true) };
        let p = plan_delivery(&caps, &text, &off());
        assert_eq!(p.fallback.unwrap().method, DeliveryMethod::Type);
        // Restorable clipboard still pastes.
        let p = plan_delivery(&native(false), &text, &off());
        assert_eq!(p.method, DeliveryMethod::Paste);
    }

    #[test]
    fn newline_mode_spaces_flattens() {
        let sp = SlotSettings { auto_submit: false, newline_mode: NewlineMode::Spaces };
        let p = plan_delivery(&native(false), "a\r\nb\nc", &sp);
        assert_eq!(typed(&p.actions), "a b c");
        assert!(!p.actions.contains(&Action::ShiftReturn));
        let p = plan_delivery(&native(true), "a\nb", &sp);
        assert_eq!(p.actions, vec![Action::AxInsertSelectedText("a b".into())]);
        // Flattened text is what counts toward the 200 threshold, and paste has no breaks.
        let long = format!("{}\n{}", "a".repeat(150), "b".repeat(150));
        let p = plan_delivery(&native(false), &long, &sp);
        assert_eq!(p.method, DeliveryMethod::Paste);
        assert!(!p.actions.contains(&Action::ShiftReturn));
        // Shift+Enter mode keeps breaks.
        let p = plan_delivery(&native(false), "a\nb", &off());
        assert!(p.actions.contains(&Action::ShiftReturn));
    }

    #[test]
    fn newline_mode_default_by_category() {
        assert_eq!(SlotSettings::for_app("WindowsTerminal.exe").newline_mode, NewlineMode::Spaces);
        assert_eq!(SlotSettings::for_app("com.apple.Terminal").newline_mode, NewlineMode::Spaces);
        assert_eq!(SlotSettings::for_app("ms-teams.exe").newline_mode, NewlineMode::ShiftEnter);
        assert_eq!(SlotSettings::for_app("notepad.exe").newline_mode, NewlineMode::ShiftEnter);
        assert_eq!(SlotSettings::default().newline_mode, NewlineMode::ShiftEnter);
    }
}
