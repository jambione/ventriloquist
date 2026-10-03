//! Desktop configuration: log directory and display name (SPEC §6.1),
//! persisted as `config.json` in the config directory.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::fsutil::atomic_write_private;

/// Config directory name under the OS config dir; equals the Tauri
/// identifier so the app (M5) and `vq-host` share it.
pub const APP_DIR_NAME: &str = "com.ventriloquist.desktop";

/// File name of the config file inside the config directory.
pub const CONFIG_FILE: &str = "config.json";

/// Maximum display-name length in characters (longer names are truncated).
pub const MAX_NAME_CHARS: usize = 64;

/// The default config directory: `<OS config dir>/com.ventriloquist.desktop`
/// (macOS `~/Library/Application Support/…`, Windows `%APPDATA%\…`).
pub fn default_config_dir() -> PathBuf {
    dirs::config_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join(APP_DIR_NAME)
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

/// Trim whitespace, remove control characters and cap the length.
pub fn normalize_name(name: &str) -> String {
    name.trim()
        .chars()
        .filter(|c| !c.is_control())
        .take(MAX_NAME_CHARS)
        .collect::<String>()
        .trim()
        .to_owned()
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
    /// Load `config.json` from `config_dir`; a missing file is the default.
    pub fn load(config_dir: &Path) -> io::Result<Self> {
        let path = config_dir.join(CONFIG_FILE);
        let file = match fs::read(&path) {
            Ok(bytes) => serde_json::from_slice(&bytes)
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?,
            Err(e) if e.kind() == io::ErrorKind::NotFound => ConfigFile::default(),
            Err(e) => return Err(e),
        };
        Ok(Self { path, file })
    }

    /// The effective log directory.
    pub fn log_dir(&self) -> PathBuf {
        self.file.log_dir.clone().unwrap_or_else(default_log_dir)
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

    /// Set and persist the log directory.
    pub fn set_log_dir(&mut self, dir: PathBuf) -> io::Result<()> {
        self.file.log_dir = Some(dir);
        self.save()
    }

    /// Set and persist the display name. An empty name (after
    /// normalisation) resets it to the default.
    pub fn set_name(&mut self, name: &str) -> io::Result<()> {
        let n = normalize_name(name);
        self.file.name = if n.is_empty() { None } else { Some(n) };
        self.save()
    }

    fn save(&self) -> io::Result<()> {
        let bytes = serde_json::to_vec_pretty(&self.file)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        atomic_write_private(&self.path, &bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_and_persistence() {
        let dir = tempfile::tempdir().unwrap();
        let mut c = ConfigStore::load(dir.path()).unwrap();
        assert!(c.log_dir().ends_with("Ventriloquist"));
        assert!(!c.name().is_empty());
        c.set_name("  Jon's\u{7}Mac  ").unwrap();
        c.set_log_dir(dir.path().join("logs")).unwrap();
        let c2 = ConfigStore::load(dir.path()).unwrap();
        assert_eq!(c2.name(), "Jon'sMac");
        assert_eq!(c2.log_dir(), dir.path().join("logs"));
        let mut c3 = c2;
        c3.set_name("   ").unwrap();
        assert_eq!(c3.name(), default_name());
    }

    #[test]
    fn name_is_capped() {
        assert_eq!(
            normalize_name(&"x".repeat(100)).chars().count(),
            MAX_NAME_CHARS
        );
    }
}
