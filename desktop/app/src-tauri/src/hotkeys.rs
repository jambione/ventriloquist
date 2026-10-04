//! Global hotkeys (SPEC_V2 §2, §4.2, §4.8). Registered from Rust only: the
//! web view has no `global-shortcut:*` permission and can only choose the
//! modifier sets through `set_hotkey_modifiers`, which validates them.
//!
//! select: <select modifiers>+0…9 (0 = Off); bind: <bind modifiers>+1…9.

use std::path::Path;

use serde::{Deserialize, Serialize};
use tauri::{AppHandle, Manager};
use tauri_plugin_global_shortcut::{Code, GlobalShortcutExt, Modifiers, Shortcut, ShortcutState};

use crate::delivery::DeliveryManager;

const FILE: &str = "hotkeys.json";

/// Canonical order and wire names of the modifiers.
const ORDER: [&str; 4] = ["ctrl", "alt", "shift", "super"];

/// What the UI shows: the modifier sets and the digits that could not be
/// registered ("taken by another app").
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize)]
pub struct HotkeyView {
    pub select: Vec<String>,
    pub bind: Vec<String>,
    pub select_taken: Vec<u8>,
    pub bind_taken: Vec<u8>,
}

/// The persisted choice.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HotkeyConfig {
    pub select: Vec<String>,
    pub bind: Vec<String>,
}

fn strs(v: &[&str]) -> Vec<String> {
    v.iter().map(|s| s.to_string()).collect()
}

impl Default for HotkeyConfig {
    /// Select Ctrl+Shift; bind Ctrl+Option+Shift (macOS) = Ctrl+Shift+Alt
    /// (Windows).
    fn default() -> Self {
        HotkeyConfig { select: strs(&["ctrl", "shift"]), bind: strs(&["ctrl", "alt", "shift"]) }
    }
}

/// Normalise names (`option`→`alt`, `cmd`/`win`→`super`), dedupe, order.
/// Needs at least one of ctrl/alt/super (Shift alone would swallow typing).
pub fn normalize_modifiers(input: &[String]) -> Result<Vec<String>, String> {
    if input.len() > 8 {
        return Err("too many modifiers".into());
    }
    let mut has = [false; 4];
    for m in input {
        let i = match m.to_ascii_lowercase().as_str() {
            "ctrl" | "control" => 0,
            "alt" | "option" => 1,
            "shift" => 2,
            "super" | "cmd" | "command" | "win" | "meta" => 3,
            other => return Err(format!("unknown modifier {other:?}")),
        };
        has[i] = true;
    }
    if !(has[0] || has[1] || has[3]) {
        return Err("use Ctrl, Alt/Option or Cmd/Win, alone or with Shift".into());
    }
    Ok(ORDER.iter().zip(has).filter(|(_, h)| *h).map(|(n, _)| n.to_string()).collect())
}

impl HotkeyConfig {
    /// Replace one set; the two sets must differ (same keys would collide).
    pub fn with(&self, kind: &str, mods: &[String]) -> Result<HotkeyConfig, String> {
        let m = normalize_modifiers(mods)?;
        let mut c = self.clone();
        match kind {
            "select" => c.select = m,
            "bind" => c.bind = m,
            _ => return Err("kind must be select or bind".into()),
        }
        if c.select == c.bind {
            return Err("the select and bind modifiers must differ".into());
        }
        Ok(c)
    }

    pub fn load(dir: &Path) -> HotkeyConfig {
        let Ok(bytes) = std::fs::read(dir.join(FILE)) else { return Self::default() };
        let Ok(c) = serde_json::from_slice::<HotkeyConfig>(&bytes) else {
            log::warn!("{FILE} is corrupt; using the default hotkeys");
            return Self::default();
        };
        match Self::default().with("select", &c.select).and_then(|d| d.with("bind", &c.bind)) {
            Ok(v) => v,
            Err(e) => {
                log::warn!("{FILE} ignored: {e}");
                Self::default()
            }
        }
    }

    pub fn save(&self, dir: &Path) -> std::io::Result<()> {
        std::fs::create_dir_all(dir)?;
        let tmp = dir.join(format!(".{FILE}.tmp-{}", std::process::id()));
        std::fs::write(&tmp, serde_json::to_vec_pretty(self).map_err(std::io::Error::other)?)?;
        std::fs::rename(&tmp, dir.join(FILE))
    }
}

fn to_tauri(mods: &[String]) -> Modifiers {
    let mut m = Modifiers::empty();
    for s in mods {
        m |= match s.as_str() {
            "ctrl" => Modifiers::CONTROL,
            "alt" => Modifiers::ALT,
            "shift" => Modifiers::SHIFT,
            _ => Modifiers::SUPER,
        };
    }
    m
}

fn digit_code(d: u8) -> Code {
    match d {
        0 => Code::Digit0,
        1 => Code::Digit1,
        2 => Code::Digit2,
        3 => Code::Digit3,
        4 => Code::Digit4,
        5 => Code::Digit5,
        6 => Code::Digit6,
        7 => Code::Digit7,
        8 => Code::Digit8,
        _ => Code::Digit9,
    }
}

/// (Re)register every hotkey; digits the OS refuses are reported as taken.
pub fn register_all(app: &AppHandle, cfg: &HotkeyConfig) -> HotkeyView {
    let gs = app.global_shortcut();
    let _ = gs.unregister_all();
    let mut view = HotkeyView {
        select: cfg.select.clone(),
        bind: cfg.bind.clone(),
        ..HotkeyView::default()
    };
    for d in 0..=9u8 {
        let sc = Shortcut::new(Some(to_tauri(&cfg.select)), digit_code(d));
        let r = gs.on_shortcut(sc, move |app, _, ev| {
            if ev.state() == ShortcutState::Pressed {
                let _ = app.state::<DeliveryManager>().select(d);
            }
        });
        if let Err(e) = r {
            log::warn!("select hotkey {d} not registered: {e}");
            view.select_taken.push(d);
        }
    }
    for d in 1..=9u8 {
        let sc = Shortcut::new(Some(to_tauri(&cfg.bind)), digit_code(d));
        let r = gs.on_shortcut(sc, move |app, _, ev| {
            if ev.state() == ShortcutState::Pressed {
                let _ = app.state::<DeliveryManager>().bind(d);
            }
        });
        if let Err(e) = r {
            log::warn!("bind hotkey {d} not registered: {e}");
            view.bind_taken.push(d);
        }
    }
    view
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v(a: &[&str]) -> Vec<String> {
        strs(a)
    }

    #[test]
    fn normalizes_names_order_and_duplicates() {
        assert_eq!(normalize_modifiers(&v(&["shift", "Option", "control", "ctrl"])).unwrap(), v(&["ctrl", "alt", "shift"]));
        assert_eq!(normalize_modifiers(&v(&["cmd", "shift"])).unwrap(), v(&["shift", "super"]));
    }

    #[test]
    fn rejects_unsafe_or_unknown_sets() {
        assert!(normalize_modifiers(&[]).is_err());
        assert!(normalize_modifiers(&v(&["shift"])).is_err());
        assert!(normalize_modifiers(&v(&["hyper"])).is_err());
    }

    #[test]
    fn select_and_bind_must_differ() {
        let c = HotkeyConfig::default();
        assert!(c.with("bind", &v(&["shift", "ctrl"])).is_err());
        let ok = c.with("select", &v(&["ctrl", "alt"])).unwrap();
        assert_eq!(ok.select, v(&["ctrl", "alt"]));
        assert!(c.with("other", &v(&["ctrl"])).is_err());
    }

    #[test]
    fn persists_and_ignores_garbage() {
        let d = std::env::temp_dir().join(format!("vq-hotkeys-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        assert_eq!(HotkeyConfig::load(&d), HotkeyConfig::default());
        let c = HotkeyConfig::default().with("select", &v(&["ctrl", "alt"])).unwrap();
        c.save(&d).unwrap();
        assert_eq!(HotkeyConfig::load(&d), c);
        std::fs::write(d.join(FILE), b"{\"select\":[\"shift\"],\"bind\":[\"ctrl\"]}").unwrap();
        assert_eq!(HotkeyConfig::load(&d), HotkeyConfig::default());
        let _ = std::fs::remove_dir_all(&d);
    }
}
