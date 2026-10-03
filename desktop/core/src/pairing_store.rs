//! Persistent identity and pairing records (SPEC §4.4, §7).
//!
//! * `identity.json` — this desktop's `device_id` and X25519 private key.
//!   On unix the file is mode 0600 (enforced on every load). On Windows it
//!   lives in the per-user `%APPDATA%` config dir, whose default ACL only
//!   grants the user (and SYSTEM/Administrators) access; no extra ACL is set.
//! * `peers.json` — the paired phones (`device_id`, name, public key).
//!
//! Both are written atomically (temp file + fsync + rename).

use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use uuid::Uuid;
use vq_protocol::{b64, IdentityKeyPair};
use zeroize::Zeroizing;

use crate::fsutil::{atomic_write_private, create_private_dir_all, ensure_private_file};

/// Identity file name.
pub const IDENTITY_FILE: &str = "identity.json";
/// Pairing store file name.
pub const PEERS_FILE: &str = "peers.json";

fn invalid(msg: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, msg.into())
}

/// This desktop's long-term identity.
#[derive(Debug)]
pub struct Identity {
    /// Random install id (UUID v4).
    pub device_id: Uuid,
    /// Long-term X25519 key pair.
    pub keypair: IdentityKeyPair,
}

#[derive(Serialize, Deserialize)]
struct IdentityFile {
    version: u32,
    device_id: String,
    secret_key: String,
}

impl Identity {
    /// Load `identity.json` from `config_dir`, creating a new identity if
    /// the file does not exist. A file that exists but cannot be parsed is
    /// an error: silently regenerating would break every pairing.
    pub fn load_or_create(config_dir: &Path) -> io::Result<Self> {
        create_private_dir_all(config_dir)?;
        let path = config_dir.join(IDENTITY_FILE);
        match fs::read(&path) {
            Ok(bytes) => {
                let bytes = Zeroizing::new(bytes);
                ensure_private_file(&path)?;
                let f: IdentityFile = serde_json::from_slice(&bytes)
                    .map_err(|e| invalid(format!("{}: {e}", path.display())))?;
                if f.version != 1 {
                    return Err(invalid(format!("{}: unsupported version", path.display())));
                }
                let device_id = b64::parse_uuid(&f.device_id).map_err(invalid)?;
                let secret = Zeroizing::new(f.secret_key);
                let key = Zeroizing::new(b64::decode_fixed::<32>(&secret).map_err(invalid)?);
                Ok(Self {
                    device_id,
                    keypair: IdentityKeyPair::from_secret_bytes(key),
                })
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                let id = Self {
                    device_id: vq_protocol::crypto::new_device_id(),
                    keypair: IdentityKeyPair::generate(),
                };
                let f = IdentityFile {
                    version: 1,
                    device_id: b64::format_uuid(&id.device_id),
                    secret_key: b64::encode(id.keypair.secret_bytes().as_ref()),
                };
                let json = Zeroizing::new(
                    serde_json::to_vec_pretty(&f).map_err(|e| invalid(e.to_string()))?,
                );
                let _wipe = Zeroizing::new(f.secret_key);
                atomic_write_private(&path, &json)?;
                Ok(id)
            }
            Err(e) => Err(e),
        }
    }
}

/// One paired phone.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PairedPeer {
    /// The phone's `device_id`.
    pub device_id: Uuid,
    /// The phone's name at pairing time.
    pub name: String,
    /// The phone's X25519 public key.
    #[serde(serialize_with = "ser_b64")]
    pub public_key: [u8; 32],
    /// When the pairing completed, ms since the Unix epoch.
    pub paired_at_ms: u64,
}

fn ser_b64<S: serde::Serializer>(k: &[u8; 32], s: S) -> Result<S::Ok, S::Error> {
    s.serialize_str(&b64::encode(k))
}

#[derive(Serialize, Deserialize)]
struct PeerRecord {
    device_id: String,
    name: String,
    public_key: String,
    paired_at_ms: u64,
}

#[derive(Serialize, Deserialize)]
struct PeersFile {
    version: u32,
    peers: Vec<PeerRecord>,
}

/// The persisted set of paired phones.
#[derive(Debug)]
pub struct PairingStore {
    path: PathBuf,
    peers: Vec<PairedPeer>,
}

impl PairingStore {
    /// Load `peers.json` from `config_dir` (missing = empty).
    pub fn load(config_dir: &Path) -> io::Result<Self> {
        let path = config_dir.join(PEERS_FILE);
        let peers = match fs::read(&path) {
            Ok(bytes) => {
                let f: PeersFile = serde_json::from_slice(&bytes)
                    .map_err(|e| invalid(format!("{}: {e}", path.display())))?;
                if f.version != 1 {
                    return Err(invalid(format!("{}: unsupported version", path.display())));
                }
                f.peers
                    .into_iter()
                    .map(|r| {
                        Ok(PairedPeer {
                            device_id: b64::parse_uuid(&r.device_id).map_err(invalid)?,
                            name: r.name,
                            public_key: b64::decode_fixed::<32>(&r.public_key).map_err(invalid)?,
                            paired_at_ms: r.paired_at_ms,
                        })
                    })
                    .collect::<io::Result<Vec<_>>>()?
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => Vec::new(),
            Err(e) => return Err(e),
        };
        Ok(Self { path, peers })
    }

    /// All paired phones.
    pub fn peers(&self) -> &[PairedPeer] {
        &self.peers
    }

    /// The record for `device_id`, if any.
    pub fn get(&self, device_id: &Uuid) -> Option<&PairedPeer> {
        self.peers.iter().find(|p| &p.device_id == device_id)
    }

    /// README §7.1 "known peer": a record whose `device_id` **and** public
    /// key both match.
    pub fn knows(&self, device_id: &Uuid, public_key: &[u8; 32]) -> bool {
        self.get(device_id)
            .is_some_and(|p| &p.public_key == public_key)
    }

    /// Insert or replace (by `device_id`) and persist. On a write error the
    /// in-memory store is left unchanged.
    pub fn upsert(&mut self, peer: PairedPeer) -> io::Result<()> {
        let mut next = self.peers.clone();
        match next.iter_mut().find(|p| p.device_id == peer.device_id) {
            Some(p) => *p = peer,
            None => next.push(peer),
        }
        self.persist(&next)?;
        self.peers = next;
        Ok(())
    }

    /// Remove `device_id` and persist. Returns whether a record existed.
    pub fn remove(&mut self, device_id: &Uuid) -> io::Result<bool> {
        if self.get(device_id).is_none() {
            return Ok(false);
        }
        let next: Vec<_> = self
            .peers
            .iter()
            .filter(|p| &p.device_id != device_id)
            .cloned()
            .collect();
        self.persist(&next)?;
        self.peers = next;
        Ok(true)
    }

    fn persist(&self, peers: &[PairedPeer]) -> io::Result<()> {
        let f = PeersFile {
            version: 1,
            peers: peers
                .iter()
                .map(|p| PeerRecord {
                    device_id: b64::format_uuid(&p.device_id),
                    name: p.name.clone(),
                    public_key: b64::encode(&p.public_key),
                    paired_at_ms: p.paired_at_ms,
                })
                .collect(),
        };
        let bytes = serde_json::to_vec_pretty(&f).map_err(|e| invalid(e.to_string()))?;
        atomic_write_private(&self.path, &bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identity_is_created_once_and_private() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = dir.path().join("cfg");
        let a = Identity::load_or_create(&cfg).unwrap();
        let b = Identity::load_or_create(&cfg).unwrap();
        assert_eq!(a.device_id, b.device_id);
        assert_eq!(a.keypair.public_bytes(), b.keypair.public_bytes());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let p = cfg.join(IDENTITY_FILE);
            assert_eq!(
                fs::metadata(&p).unwrap().permissions().mode() & 0o777,
                0o600
            );
            fs::set_permissions(&p, fs::Permissions::from_mode(0o644)).unwrap();
            Identity::load_or_create(&cfg).unwrap();
            assert_eq!(
                fs::metadata(&p).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
    }

    #[test]
    fn corrupt_identity_is_an_error_not_a_new_key() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join(IDENTITY_FILE), b"{nope").unwrap();
        assert!(Identity::load_or_create(dir.path()).is_err());
    }

    #[test]
    fn peers_round_trip_and_known_requires_matching_key() {
        let dir = tempfile::tempdir().unwrap();
        let mut s = PairingStore::load(dir.path()).unwrap();
        let id = Uuid::new_v4();
        s.upsert(PairedPeer {
            device_id: id,
            name: "Phone".into(),
            public_key: [7; 32],
            paired_at_ms: 1,
        })
        .unwrap();
        let mut s2 = PairingStore::load(dir.path()).unwrap();
        assert!(s2.knows(&id, &[7; 32]));
        assert!(!s2.knows(&id, &[8; 32]));
        assert!(!s2.knows(&Uuid::new_v4(), &[7; 32]));
        s2.upsert(PairedPeer {
            device_id: id,
            name: "Phone 2".into(),
            public_key: [8; 32],
            paired_at_ms: 2,
        })
        .unwrap();
        assert_eq!(s2.peers().len(), 1);
        assert!(s2.knows(&id, &[8; 32]));
        assert!(s2.remove(&id).unwrap());
        assert!(!s2.remove(&id).unwrap());
        assert!(PairingStore::load(dir.path()).unwrap().peers().is_empty());
    }
}
