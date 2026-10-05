//! Relay settings of the app (SPEC_V3 §6): the owner token store, QR
//! rendering and the owner-token generator. The commands that use them are
//! in `lib.rs`.
//!
//! **Owner token storage.** The token is a secret that only creates rooms
//! on the relay. It is stored in the OS secret store through the `keyring`
//! crate (macOS Keychain, Windows Credential Manager; service
//! `com.ventriloquist.desktop`, user `relay-owner-token`). When that store is
//! unavailable (or refuses), it falls back to a file `owner_token` with mode
//! 0600 in the per-user config directory (on Windows the non-roaming
//! `%LOCALAPPDATA%`, protected by its ACL). The UI says which one holds it.
//! The token is never sent to the web view.

use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use rand::RngCore;
use serde::Serialize;

const SERVICE: &str = "com.ventriloquist.desktop";
const USER: &str = "relay-owner-token";
const TOKEN_FILE: &str = "owner_token";
/// Longest owner token accepted from the UI.
pub const MAX_TOKEN_BYTES: usize = 512;

/// Where the owner token lives.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TokenStore {
    /// The OS secret store.
    Keychain,
    /// The 0600 file in the config directory.
    File,
}

/// The owner token store.
#[derive(Debug, Clone)]
pub struct OwnerTokenStore {
    dir: PathBuf,
    use_keyring: bool,
}

impl OwnerTokenStore {
    /// Keychain first, file fallback.
    pub fn new(config_dir: &Path) -> Self {
        Self { dir: config_dir.to_path_buf(), use_keyring: true }
    }

    /// File only (tests).
    #[cfg(test)]
    pub fn file_only(config_dir: &Path) -> Self {
        Self { dir: config_dir.to_path_buf(), use_keyring: false }
    }

    fn file(&self) -> PathBuf {
        self.dir.join(TOKEN_FILE)
    }

    fn entry(&self) -> Option<keyring::Entry> {
        self.use_keyring.then(|| keyring::Entry::new(SERVICE, USER).ok()).flatten()
    }

    /// The stored token and where it is.
    pub fn load(&self) -> Option<(String, TokenStore)> {
        if let Some(Ok(t)) = self.entry().map(|e| e.get_password()) {
            if !t.trim().is_empty() {
                return Some((t, TokenStore::Keychain));
            }
        }
        let t = fs::read_to_string(self.file()).ok()?;
        let t = t.trim().to_owned();
        (!t.is_empty()).then_some((t, TokenStore::File))
    }

    /// Store `token`; returns where it went.
    pub fn save(&self, token: &str) -> io::Result<TokenStore> {
        let token = token.trim();
        if token.is_empty() || token.len() > MAX_TOKEN_BYTES || token.chars().any(char::is_control) {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "that is not a valid owner token"));
        }
        if let Some(e) = self.entry() {
            match e.set_password(token) {
                Ok(()) => {
                    let _ = fs::remove_file(self.file());
                    return Ok(TokenStore::Keychain);
                }
                Err(err) => log::warn!("owner token: the OS secret store refused ({err}); using a file"),
            }
        }
        write_private(&self.file(), token.as_bytes())?;
        Ok(TokenStore::File)
    }

    /// Remove the token from both stores.
    pub fn clear(&self) {
        if let Some(e) = self.entry() {
            let _ = e.delete_credential();
        }
        let _ = fs::remove_file(self.file());
    }
}

fn write_private(path: &Path, bytes: &[u8]) -> io::Result<()> {
    if let Some(dir) = path.parent() {
        fs::create_dir_all(dir)?;
    }
    let tmp = path.with_extension("tmp");
    {
        let mut opts = fs::OpenOptions::new();
        opts.write(true).create(true).truncate(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        let mut f = opts.open(&tmp)?;
        f.write_all(bytes)?;
        f.sync_all()?;
    }
    fs::rename(&tmp, path)
}

/// A new owner token: 256 random bits, standard base64 (like
/// `openssl rand -base64 32`).
pub fn generate_owner_token() -> String {
    let mut b = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut b);
    STANDARD.encode(b)
}

/// Longest string `qr_svg` accepts.
const MAX_QR_BYTES: usize = 1500;

/// The pairing QR as an SVG `data:` URL (no network, no external
/// resources). Only `vq://pair?…` URIs are rendered.
pub fn qr_data_url(uri: &str) -> Result<String, String> {
    if !uri.starts_with("vq://pair?") || uri.len() > MAX_QR_BYTES {
        return Err("not a pairing URI".into());
    }
    let code = qrcode::QrCode::with_error_correction_level(uri.as_bytes(), qrcode::EcLevel::M)
        .map_err(|e| format!("cannot encode the QR code: {e}"))?;
    let svg = code
        .render::<qrcode::render::svg::Color<'_>>()
        .min_dimensions(320, 320)
        .quiet_zone(true)
        .dark_color(qrcode::render::svg::Color("#000000"))
        .light_color(qrcode::render::svg::Color("#ffffff"))
        .build();
    Ok(format!("data:image/svg+xml;base64,{}", STANDARD.encode(svg)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn token_file_round_trip_is_private_and_clearable() {
        let dir = tempfile::tempdir().unwrap();
        let s = OwnerTokenStore::file_only(dir.path());
        assert!(s.load().is_none());
        assert_eq!(s.save("  abc123  ").unwrap(), TokenStore::File);
        assert_eq!(s.load(), Some(("abc123".to_owned(), TokenStore::File)));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = fs::metadata(dir.path().join(TOKEN_FILE)).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600);
        }
        s.clear();
        assert!(s.load().is_none());
    }

    #[test]
    fn invalid_tokens_are_refused() {
        let dir = tempfile::tempdir().unwrap();
        let s = OwnerTokenStore::file_only(dir.path());
        for bad in ["", "   ", "a\nb", &"x".repeat(MAX_TOKEN_BYTES + 1)] {
            assert!(s.save(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn generated_tokens_are_random_base64_of_32_bytes() {
        let a = generate_owner_token();
        let b = generate_owner_token();
        assert_ne!(a, b);
        assert_eq!(STANDARD.decode(&a).unwrap().len(), 32);
    }

    #[test]
    fn qr_is_an_svg_data_url_for_pairing_uris_only() {
        let url = qr_data_url("vq://pair?v=3&r=https%3A%2F%2Frelay.example&room=x&s=y&c=123456").unwrap();
        let b64 = url.strip_prefix("data:image/svg+xml;base64,").unwrap();
        let svg = String::from_utf8(STANDARD.decode(b64).unwrap()).unwrap();
        assert!(svg.starts_with("<?xml") || svg.starts_with("<svg"), "{svg:.40}");
        assert!(svg.contains("<svg"));
        assert!(qr_data_url("https://evil.example").is_err());
        assert!(qr_data_url(&format!("vq://pair?{}", "a".repeat(MAX_QR_BYTES))).is_err());
    }
}
