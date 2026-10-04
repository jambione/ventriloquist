//! Desktop configuration: log directory and display name (SPEC §6.1),
//! persisted as `config.json` in the config directory.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::fsutil::atomic_write_private;

/// Config directory name under the OS local config dir; equals the Tauri
/// identifier of the app (M5).
pub const APP_DIR_NAME: &str = "com.ventriloquist.desktop";

/// Config directory name used by the `vq-host` dev binary by default, so
/// dev runs never touch the real app's identity and pairings.
pub const DEV_APP_DIR_NAME: &str = "com.ventriloquist.desktop.dev";

/// File name of the config file inside the config directory.
pub const CONFIG_FILE: &str = "config.json";

/// Maximum display-name length in characters (longer names are truncated).
pub const MAX_NAME_CHARS: usize = 64;

/// The default config directory: `<OS local config dir>/com.ventriloquist.desktop`
/// (macOS `~/Library/Application Support/…`, Windows `%LOCALAPPDATA%\…`,
/// Linux `~/.config/…`). The *local* (non-roaming) directory is used so the
/// identity key never roams to other Windows machines.
pub fn default_config_dir() -> PathBuf {
    local_config_base().join(APP_DIR_NAME)
}

/// The default config directory of the `vq-host` dev binary
/// (`…/com.ventriloquist.desktop.dev`).
pub fn default_dev_config_dir() -> PathBuf {
    local_config_base().join(DEV_APP_DIR_NAME)
}

fn local_config_base() -> PathBuf {
    dirs::config_local_dir()
        .or_else(dirs::config_dir)
        .unwrap_or_else(|| PathBuf::from("."))
}

/// The default log directory: `~/Documents/Ventriloquist/`.
pub fn default_log_dir() -> PathBuf {
    dirs::document_dir()
        .or_else(|| dirs::home_dir().map(|h| h.join("Documents")))
        .unwrap_or_else(|| PathBuf::from("."))
        .join("Ventriloquist")
}

/// The default display name: the host name without a trailing `.local`.
pub fn default_name() -> String {
    let raw = gethostname::gethostname().to_string_lossy().into_owned();
    let trimmed = raw.trim();
    let trimmed = trimmed.strip_suffix(".local").unwrap_or(trimmed);
    let name = normalize_name(trimmed);
    if name.is_empty() {
        "Ventriloquist desktop".to_owned()
    } else {
        name
    }
}

/// Characters never kept in a displayed name: control characters (C0,
/// DEL, C1), Unicode bidi controls and the line/paragraph separators.
pub fn is_unsafe_name_char(c: char) -> bool {
    c.is_control()
        || matches!(
            c,
            '\u{061C}'
                | '\u{200E}'
                | '\u{200F}'
                | '\u{202A}'..='\u{202E}'
                | '\u{2066}'..='\u{2069}'
                | '\u{2028}'
                | '\u{2029}'
        )
}

/// Trim whitespace, remove control and bidi characters and cap the length
/// at [`MAX_NAME_CHARS`].
pub fn normalize_name(name: &str) -> String {
    name.chars()
        .filter(|c| !is_unsafe_name_char(*c))
        .collect::<String>()
        .trim()
        .chars()
        .take(MAX_NAME_CHARS)
        .collect::<String>()
        .trim()
        .to_owned()
}

/// A phone's `hello.name` as stored, displayed and logged: normalised like
/// [`normalize_name`], and `"Unnamed phone"` if nothing is left.
pub fn sanitize_peer_name(name: &str) -> String {
    let n = normalize_name(name);
    if n.is_empty() {
        "Unnamed phone".to_owned()
    } else {
        n
    }
}

/// What `config.json` holds. Absent fields mean "use the default".
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConfigFile {
    /// Log directory chosen by the user.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub log_dir: Option<PathBuf>,
    /// Display name chosen by the user.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
}

/// The persisted configuration.
#[derive(Debug)]
pub struct ConfigStore {
    path: PathBuf,
    file: ConfigFile,
}

impl ConfigStore {
    /// Load `config.json` from `config_dir`. A missing file is the default.
    /// An unreadable or corrupt file also falls back to the defaults (it is
    /// only preferences); the second value then describes the problem, for
    /// a `storage_warning`. The file is not touched until a setting changes.
    pub fn load(config_dir: &Path) -> (Self, Option<String>) {
        let path = config_dir.join(CONFIG_FILE);
        let (file, warning) = match fs::read(&path) {
            Ok(bytes) => match serde_json::from_slice(&bytes) {
                Ok(f) => (f, None),
                Err(e) => (
                    ConfigFile::default(),
                    Some(format!(
                        "{} is corrupt ({e}); using the default settings",
                        path.display()
                    )),
                ),
            },
            Err(e) if e.kind() == io::ErrorKind::NotFound => (ConfigFile::default(), None),
            Err(e) => (
                ConfigFile::default(),
                Some(format!(
                    "cannot read {} ({e}); using the default settings",
                    path.display()
                )),
            ),
        };
        (Self { path, file }, warning)
    }

    /// Path of `config.json`.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// The current contents.
    pub fn file(&self) -> &ConfigFile {
        &self.file
    }

    /// The effective log directory.
    pub fn log_dir(&self) -> PathBuf {
        self.file
            .log_dir
            .clone()
            .filter(|p| p.is_absolute())
            .unwrap_or_else(default_log_dir)
    }

    /// The effective display name.
    pub fn name(&self) -> String {
        self.file
            .name
            .as_deref()
            .map(normalize_name)
            .filter(|n| !n.is_empty())
            .unwrap_or_else(default_name)
    }

    /// Set the log directory in memory; returns the contents to persist
    /// (with [`save_config`]).
    pub fn set_log_dir(&mut self, dir: PathBuf) -> ConfigFile {
        self.file.log_dir = Some(dir);
        self.file.clone()
    }

    /// Set the display name in memory (an empty name, after normalisation,
    /// resets it to the default); returns the contents to persist.
    pub fn set_name(&mut self, name: &str) -> ConfigFile {
        let n = normalize_name(name);
        self.file.name = if n.is_empty() { None } else { Some(n) };
        self.file.clone()
    }
}

/// Atomically write `file` to `path`.
pub fn save_config(path: &Path, file: &ConfigFile) -> io::Result<()> {
    let bytes = serde_json::to_vec_pretty(file)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    atomic_write_private(path, &bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_and_persistence() {
        let dir = tempfile::tempdir().unwrap();
        let (mut c, w) = ConfigStore::load(dir.path());
        assert!(w.is_none());
        assert!(c.log_dir().ends_with("Ventriloquist"));
        assert!(!c.name().is_empty());
        c.set_name("  Jon's\u{7}Mac  ");
        let f = c.set_log_dir(dir.path().join("logs"));
        save_config(c.path(), &f).unwrap();
        let (c2, _) = ConfigStore::load(dir.path());
        assert_eq!(c2.name(), "Jon'sMac");
        assert_eq!(c2.log_dir(), dir.path().join("logs"));
        let mut c3 = c2;
        c3.set_name("   ");
        assert_eq!(c3.name(), default_name());
    }

    #[test]
    fn name_is_capped() {
        assert_eq!(
            normalize_name(&"x".repeat(100)).chars().count(),
            MAX_NAME_CHARS
        );
    }

    #[test]
    fn corrupt_config_falls_back_with_a_warning() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join(CONFIG_FILE), b"{nope").unwrap();
        let (c, w) = ConfigStore::load(dir.path());
        assert!(w.unwrap().contains("corrupt"));
        assert_eq!(c.file(), &ConfigFile::default());
        // untouched until a setting changes
        assert_eq!(fs::read(dir.path().join(CONFIG_FILE)).unwrap(), b"{nope");
    }

    #[test]
    fn dev_and_app_config_dirs_differ() {
        assert_ne!(default_config_dir(), default_dev_config_dir());
        assert!(default_dev_config_dir().ends_with(DEV_APP_DIR_NAME));
    }

    #[test]
    fn peer_names_are_sanitized() {
        assert_eq!(
            sanitize_peer_name("  \u{202E}Jon\u{1b}[31m\u{2066}'s\u{7}  "),
            "Jon[31m's"
        );
        assert_eq!(sanitize_peer_name("\u{200F}\n\t"), "Unnamed phone");
        assert_eq!(sanitize_peer_name(&"é".repeat(80)).chars().count(), MAX_NAME_CHARS);
    }
}
