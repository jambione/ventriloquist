//! The relay room this desktop owns (SPEC_V3 §3, §5): `room_id` (128 random
//! bits) and `room_secret` (256 random bits), both base64url, plus the relay
//! URL. They are generated once and persisted in the config directory:
//!
//! * `relay.json`: `{ "url": …, "room_id": … }`;
//! * `relay_secret`: the room secret, mode 0600 (on Windows it lives in the
//!   per-user, non-roaming `%LOCALAPPDATA%` directory and inherits its ACL);
//! * `relay_desktop_secret`: the desktop secret (same protections). Only the
//!   desktop uses it, for `role=desktop`; it is never put in the QR code, so
//!   a phone (or a leaked QR) cannot impersonate the desktop (X1).
//!
//! The owner token is **not** stored here: the app keeps it in the OS secret
//! store (it is only needed to create rooms).
//!
//! [`RelayRoomStore`] is shared (`Arc`) between the [`crate::Core`] (QR
//! pairing needs room id, secret and URL) and the relay transport. "Reset
//! relay room" ([`RelayRoomStore::reset_room`]) replaces both id and secret.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use rand::rngs::OsRng;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::fsutil::{atomic_write_private, ensure_private_file};

/// The default relay (SPEC_V3 §2).
pub const DEFAULT_RELAY_URL: &str = "https://relay.jbrasfield.com";

const ROOM_FILE: &str = "relay.json";
const SECRET_FILE: &str = "relay_secret";
const DESKTOP_SECRET_FILE: &str = "relay_desktop_secret";

/// One room's credentials and where to find it.
#[derive(Clone, PartialEq, Eq)]
pub struct RoomSettings {
    /// Relay base URL (`https://…`; `http://` only for local development).
    pub url: String,
    /// 128 random bits, base64url.
    pub room_id: String,
    /// 256 random bits, base64url. Never logged.
    pub room_secret: Zeroizing<String>,
    /// 256 random bits, base64url: authenticates `role=desktop`. Never
    /// logged and never in the QR code.
    pub desktop_secret: Zeroizing<String>,
}

impl std::fmt::Debug for RoomSettings {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RoomSettings")
            .field("url", &self.url)
            .field("room_id", &self.room_id)
            .field("room_secret", &"<hidden>")
            .field("desktop_secret", &"<hidden>")
            .finish()
    }
}

impl RoomSettings {
    /// `base64url(SHA-256(room_secret))`: what the relay stores (SPEC_V3 §3).
    pub fn secret_hash(&self) -> String {
        secret_hash(&self.room_secret)
    }

    /// `base64url(SHA-256(desktop_secret))`: sent as `desktop_secret_hash`.
    pub fn desktop_secret_hash(&self) -> String {
        secret_hash(&self.desktop_secret)
    }
}

/// `base64url(SHA-256(secret))` of the secret's ASCII text.
pub fn secret_hash(secret: &str) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(secret.as_bytes()))
}

fn random_b64(bytes: usize) -> String {
    let mut buf = Zeroizing::new(vec![0u8; bytes]);
    OsRng.fill_bytes(&mut buf);
    URL_SAFE_NO_PAD.encode(&*buf)
}

/// A fresh room id (128 bits), room secret and desktop secret (256 bits each).
pub fn generate_room() -> (String, Zeroizing<String>, Zeroizing<String>) {
    (random_b64(16), Zeroizing::new(random_b64(32)), Zeroizing::new(random_b64(32)))
}

/// Whether `host` (as `url::Url::host_str` returns it) is a loopback host.
pub fn is_loopback_host(host: &str) -> bool {
    let h = host.trim_start_matches('[').trim_end_matches(']');
    if h.eq_ignore_ascii_case("localhost") {
        return true;
    }
    h.parse::<std::net::IpAddr>().is_ok_and(|ip| ip.is_loopback())
}

/// Normalise a relay URL typed by the user: trimmed, no trailing slash, no
/// `/v1` suffix. Only `https://` (and `http://` for loopback hosts, for local
/// development) are accepted; anything else (including credentials in the
/// URL) is `None`.
pub fn normalize_relay_url(raw: &str) -> Option<String> {
    let t = raw.trim().trim_end_matches('/');
    let t = t.strip_suffix("/v1").unwrap_or(t).trim_end_matches('/');
    let u = url::Url::parse(t).ok()?;
    let host = u.host_str()?;
    match u.scheme() {
        "https" => {}
        "http" if is_loopback_host(host) => {}
        _ => return None,
    }
    if !u.username().is_empty() || u.password().is_some() || u.query().is_some() || u.fragment().is_some() {
        return None;
    }
    Some(t.to_owned())
}

#[derive(Serialize, Deserialize)]
struct RoomFile {
    url: String,
    room_id: String,
}

/// Persisted, shared room settings.
#[derive(Debug)]
pub struct RelayRoomStore {
    dir: PathBuf,
    settings: Mutex<RoomSettings>,
}

impl RelayRoomStore {
    /// Load the room from `dir`, creating (and saving) a new one when there
    /// is none, or when either file is unreadable or invalid.
    pub fn load_or_create(dir: &Path) -> io::Result<Self> {
        let loaded = Self::try_load(dir);
        let settings = match loaded {
            Some(s) => s,
            None => {
                let (room_id, room_secret, desktop_secret) = generate_room();
                let s = RoomSettings {
                    url: DEFAULT_RELAY_URL.to_owned(),
                    room_id,
                    room_secret,
                    desktop_secret,
                };
                Self::write(dir, &s)?;
                s
            }
        };
        Ok(Self {
            dir: dir.to_path_buf(),
            settings: Mutex::new(settings),
        })
    }

    fn try_load(dir: &Path) -> Option<RoomSettings> {
        let file: RoomFile = serde_json::from_slice(&fs::read(dir.join(ROOM_FILE)).ok()?).ok()?;
        let secret = Zeroizing::new(fs::read_to_string(dir.join(SECRET_FILE)).ok()?.trim().to_owned());
        let _ = ensure_private_file(&dir.join(SECRET_FILE));
        let valid = |s: &str, n: usize| URL_SAFE_NO_PAD.decode(s).is_ok_and(|b| b.len() == n);
        if !valid(&file.room_id, 16) || !valid(&secret, 32) {
            return None;
        }
        // A room from before X1 has no desktop secret: add one (the room
        // itself stays; the next PUT teaches the relay its hash).
        let desktop_secret = fs::read_to_string(dir.join(DESKTOP_SECRET_FILE))
            .ok()
            .map(|t| Zeroizing::new(t.trim().to_owned()))
            .filter(|t| valid(t, 32));
        let desktop_secret = match desktop_secret {
            Some(d) => {
                let _ = ensure_private_file(&dir.join(DESKTOP_SECRET_FILE));
                d
            }
            None => {
                let d = Zeroizing::new(random_b64(32));
                atomic_write_private(&dir.join(DESKTOP_SECRET_FILE), d.as_bytes()).ok()?;
                d
            }
        };
        Some(RoomSettings {
            url: normalize_relay_url(&file.url).unwrap_or_else(|| DEFAULT_RELAY_URL.to_owned()),
            room_id: file.room_id,
            room_secret: secret,
            desktop_secret,
        })
    }

    fn write(dir: &Path, s: &RoomSettings) -> io::Result<()> {
        // The secrets first: a room file without its secrets is regenerated.
        atomic_write_private(&dir.join(DESKTOP_SECRET_FILE), s.desktop_secret.as_bytes())?;
        atomic_write_private(&dir.join(SECRET_FILE), s.room_secret.as_bytes())?;
        let json = serde_json::to_vec_pretty(&RoomFile {
            url: s.url.clone(),
            room_id: s.room_id.clone(),
        })
        .map_err(io::Error::other)?;
        atomic_write_private(&dir.join(ROOM_FILE), &json)
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, RoomSettings> {
        self.settings.lock().unwrap_or_else(|p| p.into_inner())
    }

    /// The current settings.
    pub fn get(&self) -> RoomSettings {
        self.lock().clone()
    }

    /// Change the relay URL (normalised; invalid URLs are refused).
    pub fn set_url(&self, url: &str) -> io::Result<()> {
        let url = normalize_relay_url(url).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "the relay URL must be an https:// address (http:// is accepted only for localhost)",
            )
        })?;
        let mut g = self.lock();
        let mut next = g.clone();
        next.url = url;
        Self::write(&self.dir, &next)?;
        *g = next;
        Ok(())
    }

    /// "Reset relay room": a new room id and both secrets, which un-pairs every
    /// phone. Returns the previous settings (for deleting the old room).
    pub fn reset_room(&self) -> io::Result<RoomSettings> {
        let mut g = self.lock();
        let (room_id, room_secret, desktop_secret) = generate_room();
        let next = RoomSettings {
            url: g.url.clone(),
            room_id,
            room_secret,
            desktop_secret,
        };
        Self::write(&self.dir, &next)?;
        Ok(std::mem::replace(&mut *g, next))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn room_is_generated_once_and_persisted() {
        let dir = tempfile::tempdir().unwrap();
        let a = RelayRoomStore::load_or_create(dir.path()).unwrap().get();
        assert_eq!(URL_SAFE_NO_PAD.decode(&a.room_id).unwrap().len(), 16);
        assert_eq!(URL_SAFE_NO_PAD.decode(&*a.room_secret).unwrap().len(), 32);
        assert_eq!(URL_SAFE_NO_PAD.decode(&*a.desktop_secret).unwrap().len(), 32);
        assert_ne!(*a.room_secret, *a.desktop_secret);
        assert_eq!(a.url, DEFAULT_RELAY_URL);
        let b = RelayRoomStore::load_or_create(dir.path()).unwrap().get();
        assert_eq!(a, b);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            for f in [SECRET_FILE, DESKTOP_SECRET_FILE] {
                let mode = fs::metadata(dir.path().join(f)).unwrap().permissions().mode();
                assert_eq!(mode & 0o777, 0o600);
            }
        }
    }

    #[test]
    fn reset_rotates_id_and_secret_and_keeps_the_url() {
        let dir = tempfile::tempdir().unwrap();
        let s = RelayRoomStore::load_or_create(dir.path()).unwrap();
        s.set_url("http://127.0.0.1:8787/").unwrap();
        let old = s.reset_room().unwrap();
        let new = s.get();
        assert_ne!(old.room_id, new.room_id);
        assert_ne!(*old.room_secret, *new.room_secret);
        assert_ne!(*old.desktop_secret, *new.desktop_secret);
        assert_eq!(new.url, "http://127.0.0.1:8787");
        let again = RelayRoomStore::load_or_create(dir.path()).unwrap().get();
        assert_eq!(again, new);
    }

    #[test]
    fn a_room_from_before_the_desktop_secret_gets_one_and_keeps_its_id() {
        let dir = tempfile::tempdir().unwrap();
        let a = RelayRoomStore::load_or_create(dir.path()).unwrap().get();
        fs::remove_file(dir.path().join(DESKTOP_SECRET_FILE)).unwrap();
        let b = RelayRoomStore::load_or_create(dir.path()).unwrap().get();
        assert_eq!((&a.room_id, &*a.room_secret), (&b.room_id, &*b.room_secret));
        assert_ne!(*a.desktop_secret, *b.desktop_secret);
        let c = RelayRoomStore::load_or_create(dir.path()).unwrap().get();
        assert_eq!(*b.desktop_secret, *c.desktop_secret);
    }

    #[test]
    fn corrupt_files_are_replaced_by_a_new_room() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join(ROOM_FILE), b"{nope").unwrap();
        let s = RelayRoomStore::load_or_create(dir.path()).unwrap().get();
        assert_eq!(URL_SAFE_NO_PAD.decode(&s.room_id).unwrap().len(), 16);
    }

    #[test]
    fn url_normalisation() {
        assert_eq!(normalize_relay_url(" https://relay.example.com/ ").unwrap(), "https://relay.example.com");
        assert_eq!(normalize_relay_url("https://relay.example.com/v1").unwrap(), "https://relay.example.com");
        assert_eq!(normalize_relay_url("http://localhost:8787").unwrap(), "http://localhost:8787");
        assert!(normalize_relay_url("http://127.0.0.1:8787").is_some());
        assert!(normalize_relay_url("http://[::1]:8787").is_some());
        assert!(normalize_relay_url("http://127.5.5.5").is_some());
        assert!(normalize_relay_url("http://relay.example.com").is_none());
        assert!(normalize_relay_url("http://localhost.evil.com").is_none());
        assert!(normalize_relay_url("ftp://x").is_none());
        assert!(normalize_relay_url("relay.example.com").is_none());
        assert!(normalize_relay_url("https://user:pw@relay.example.com").is_none());
        assert!(normalize_relay_url("https://relay.example.com/?a=b").is_none());
    }

    #[test]
    fn secret_hash_is_unpadded_base64url_sha256() {
        // sha256("abc")
        assert_eq!(secret_hash("abc"), "ungWv48Bz-pBQUDeXa4iI7ADYaOWF3qctBD_YfIAFa0");
    }
}
