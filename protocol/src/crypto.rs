//! Identity keys, pairing and session key derivation (SPEC §4.4, §4.5).
//!
//! ```text
//! ss     = X25519(own_priv, peer_pub)                       (32 bytes; all-zero rejected)
//! K_pair = HKDF-SHA256(ikm = ss, salt = nonce_p ‖ nonce_d,
//!                      info = "vq/pair/v1" ‖ C)            (L = 32; C = 6 ASCII digits)
//! mac_p  = HMAC-SHA256(K_pair, "phone"   ‖ pub_p ‖ pub_d)
//! mac_d  = HMAC-SHA256(K_pair, "desktop" ‖ pub_d ‖ pub_p)
//! K_sess = HKDF-SHA256(ikm = ss, salt = nonce_phone ‖ nonce_desktop,
//!                      info = "vq/session/v1")              (L = 32)
//! ```

use std::fmt;
use std::str::FromStr;

use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use rand::rngs::OsRng;
use rand::{CryptoRng, Rng, RngCore};
use sha2::Sha256;
use uuid::Uuid;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroizing;

use crate::error::{Error, Result};

/// HKDF info prefix for the pairing key; the 6 code digits are appended.
pub const PAIR_INFO_PREFIX: &[u8] = b"vq/pair/v1";
/// HKDF info for the session key.
pub const SESSION_INFO: &[u8] = b"vq/session/v1";
/// MAC label for the phone's `pair_confirm`.
pub const PHONE_MAC_LABEL: &[u8] = b"phone";
/// MAC label for the desktop's `pair_result`.
pub const DESKTOP_MAC_LABEL: &[u8] = b"desktop";

type HmacSha256 = Hmac<Sha256>;

/// A long-term X25519 identity key pair.
#[derive(Clone)]
pub struct IdentityKeyPair {
    secret: StaticSecret,
    public: PublicKey,
}

impl IdentityKeyPair {
    /// Generate with the OS CSPRNG.
    pub fn generate() -> Self {
        Self::generate_with(&mut OsRng)
    }

    /// Generate with a caller-supplied CSPRNG.
    pub fn generate_with<R: RngCore + CryptoRng>(rng: &mut R) -> Self {
        let mut bytes = Zeroizing::new([0u8; 32]);
        rng.fill_bytes(bytes.as_mut());
        Self::from_secret_bytes(*bytes)
    }

    /// Restore from the 32-byte private key (RFC 7748 scalar; clamped on use).
    pub fn from_secret_bytes(secret: [u8; 32]) -> Self {
        let secret = StaticSecret::from(secret);
        let public = PublicKey::from(&secret);
        Self { secret, public }
    }

    /// The 32-byte private key, for persistent storage.
    pub fn secret_bytes(&self) -> Zeroizing<[u8; 32]> {
        Zeroizing::new(self.secret.to_bytes())
    }

    /// The 32-byte public key (`pub` in `hello`).
    pub fn public_bytes(&self) -> [u8; 32] {
        self.public.to_bytes()
    }

    /// `ss = X25519(own_priv, peer_pub)`. Rejects an all-zero result.
    pub fn shared_secret(&self, peer_public: &[u8; 32]) -> Result<SharedSecret> {
        let ss = self.secret.diffie_hellman(&PublicKey::from(*peer_public));
        if !ss.was_contributory() {
            return Err(Error::NonContributory);
        }
        Ok(SharedSecret(Zeroizing::new(ss.to_bytes())))
    }
}

impl fmt::Debug for IdentityKeyPair {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("IdentityKeyPair")
            .field("public", &self.public.as_bytes())
            .finish_non_exhaustive()
    }
}

/// The X25519 shared secret between two identities.
#[derive(Clone)]
pub struct SharedSecret(Zeroizing<[u8; 32]>);

impl SharedSecret {
    /// Wrap raw bytes (tests / vectors).
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(Zeroizing::new(bytes))
    }
    /// Raw bytes.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Debug for SharedSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SharedSecret(..)")
    }
}

/// New random 128-bit install identifier (UUID v4).
pub fn new_device_id() -> Uuid {
    Uuid::new_v4()
}

/// 32 random bytes from the OS CSPRNG (for `nonce_p`, `nonce_d`, `session_nonce`).
pub fn random_nonce() -> [u8; 32] {
    let mut n = [0u8; 32];
    OsRng.fill_bytes(&mut n);
    n
}

/// A 6-digit pairing code, 000000–999999.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct PairingCode(u32);

impl PairingCode {
    /// Uniformly random code from the OS CSPRNG.
    pub fn generate() -> Self {
        Self::generate_with(&mut OsRng)
    }

    /// Uniformly random code (unbiased rejection sampling via `gen_range`).
    pub fn generate_with<R: RngCore + CryptoRng>(rng: &mut R) -> Self {
        Self(rng.gen_range(0..1_000_000))
    }

    /// From a number; `None` if ≥ 1,000,000.
    pub fn from_u32(n: u32) -> Option<Self> {
        (n < 1_000_000).then_some(Self(n))
    }

    /// Numeric value.
    pub fn value(&self) -> u32 {
        self.0
    }

    /// The 6 ASCII digits, zero-padded (e.g. `b"004217"`).
    pub fn ascii(&self) -> [u8; 6] {
        let mut out = [b'0'; 6];
        let mut n = self.0;
        for d in out.iter_mut().rev() {
            *d = b'0' + (n % 10) as u8;
            n /= 10;
        }
        out
    }
}

impl FromStr for PairingCode {
    type Err = Error;
    /// Exactly 6 ASCII digits; nothing else (no spaces, signs or Unicode digits).
    fn from_str(s: &str) -> Result<Self> {
        let b = s.as_bytes();
        if b.len() != 6 || !b.iter().all(u8::is_ascii_digit) {
            return Err(Error::InvalidCode);
        }
        Ok(Self(
            b.iter().fold(0u32, |acc, d| acc * 10 + u32::from(d - b'0')),
        ))
    }
}

impl fmt::Display for PairingCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:06}", self.0)
    }
}

impl fmt::Debug for PairingCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PairingCode(******)")
    }
}

/// HKDF info for `K_pair`: `"vq/pair/v1" ‖ code digits` (16 bytes).
pub fn pair_info(code: &PairingCode) -> Vec<u8> {
    let mut info = PAIR_INFO_PREFIX.to_vec();
    info.extend_from_slice(&code.ascii());
    info
}

fn hkdf32(ikm: &[u8; 32], salt_a: &[u8; 32], salt_b: &[u8; 32], info: &[u8]) -> [u8; 32] {
    let mut salt = [0u8; 64];
    salt[..32].copy_from_slice(salt_a);
    salt[32..].copy_from_slice(salt_b);
    let hk = Hkdf::<Sha256>::new(Some(&salt), ikm);
    let mut okm = [0u8; 32];
    hk.expand(info, &mut okm)
        .expect("32 bytes is a valid HKDF-SHA256 output length");
    okm
}

/// `K_pair = HKDF-SHA256(ss, salt = nonce_p ‖ nonce_d, info = "vq/pair/v1" ‖ C)`, 32 bytes.
pub fn derive_pair_key(
    ss: &SharedSecret,
    nonce_p: &[u8; 32],
    nonce_d: &[u8; 32],
    code: &PairingCode,
) -> [u8; 32] {
    hkdf32(ss.as_bytes(), nonce_p, nonce_d, &pair_info(code))
}

/// `K_sess = HKDF-SHA256(ss, salt = nonce_phone ‖ nonce_desktop, info = "vq/session/v1")`, 32 bytes.
pub fn derive_session_key(
    ss: &SharedSecret,
    nonce_phone: &[u8; 32],
    nonce_desktop: &[u8; 32],
) -> [u8; 32] {
    hkdf32(ss.as_bytes(), nonce_phone, nonce_desktop, SESSION_INFO)
}

fn mac_over(k: &[u8; 32], label: &[u8], a: &[u8; 32], b: &[u8; 32]) -> HmacSha256 {
    let mut m = <HmacSha256 as Mac>::new_from_slice(k).expect("HMAC accepts any key length");
    m.update(label);
    m.update(a);
    m.update(b);
    m
}

/// `pair_confirm.mac = HMAC-SHA256(K_pair, "phone" ‖ pub_p ‖ pub_d)`.
pub fn phone_confirm_mac(
    k_pair: &[u8; 32],
    pub_phone: &[u8; 32],
    pub_desktop: &[u8; 32],
) -> [u8; 32] {
    mac_over(k_pair, PHONE_MAC_LABEL, pub_phone, pub_desktop)
        .finalize()
        .into_bytes()
        .into()
}

/// `pair_result.mac = HMAC-SHA256(K_pair, "desktop" ‖ pub_d ‖ pub_p)`.
///
/// Note the argument order is (phone, desktop) for both MAC helpers; the
/// concatenation order differs internally as the spec requires.
pub fn desktop_result_mac(
    k_pair: &[u8; 32],
    pub_phone: &[u8; 32],
    pub_desktop: &[u8; 32],
) -> [u8; 32] {
    mac_over(k_pair, DESKTOP_MAC_LABEL, pub_desktop, pub_phone)
        .finalize()
        .into_bytes()
        .into()
}

/// Constant-time verification of the phone's `pair_confirm` MAC.
pub fn verify_phone_confirm_mac(
    k_pair: &[u8; 32],
    pub_phone: &[u8; 32],
    pub_desktop: &[u8; 32],
    mac: &[u8; 32],
) -> Result<()> {
    mac_over(k_pair, PHONE_MAC_LABEL, pub_phone, pub_desktop)
        .verify_slice(mac)
        .map_err(|_| Error::BadMac)
}

/// Constant-time verification of the desktop's `pair_result` MAC.
pub fn verify_desktop_result_mac(
    k_pair: &[u8; 32],
    pub_phone: &[u8; 32],
    pub_desktop: &[u8; 32],
    mac: &[u8; 32],
) -> Result<()> {
    mac_over(k_pair, DESKTOP_MAC_LABEL, pub_desktop, pub_phone)
        .verify_slice(mac)
        .map_err(|_| Error::BadMac)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn h32(s: &str) -> [u8; 32] {
        hex::decode(s).unwrap().try_into().unwrap()
    }

    /// RFC 7748 §6.1 Diffie-Hellman test vector.
    #[test]
    fn rfc7748_x25519() {
        let a = IdentityKeyPair::from_secret_bytes(h32(
            "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a",
        ));
        let b = IdentityKeyPair::from_secret_bytes(h32(
            "5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb",
        ));
        assert_eq!(
            a.public_bytes(),
            h32("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a")
        );
        assert_eq!(
            b.public_bytes(),
            h32("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f")
        );
        let expect = h32("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742");
        assert_eq!(
            a.shared_secret(&b.public_bytes()).unwrap().as_bytes(),
            &expect
        );
        assert_eq!(
            b.shared_secret(&a.public_bytes()).unwrap().as_bytes(),
            &expect
        );
    }

    #[test]
    fn low_order_point_rejected() {
        let a = IdentityKeyPair::generate();
        assert_eq!(
            a.shared_secret(&[0u8; 32]).unwrap_err(),
            Error::NonContributory
        );
        let mut one = [0u8; 32];
        one[0] = 1;
        assert_eq!(a.shared_secret(&one).unwrap_err(), Error::NonContributory);
    }

    #[test]
    fn secret_roundtrip() {
        let a = IdentityKeyPair::generate();
        let b = IdentityKeyPair::from_secret_bytes(*a.secret_bytes());
        assert_eq!(a.public_bytes(), b.public_bytes());
        assert!(!format!("{a:?}").contains("secret:"));
    }

    /// RFC 5869 A.1 checks that our HKDF wiring is standard HKDF-SHA256.
    #[test]
    fn rfc5869_case1_wiring() {
        let ikm = [0x0bu8; 22];
        let salt = hex::decode("000102030405060708090a0b0c").unwrap();
        let info = hex::decode("f0f1f2f3f4f5f6f7f8f9").unwrap();
        let hk = Hkdf::<Sha256>::new(Some(&salt), &ikm);
        let mut okm = [0u8; 42];
        hk.expand(&info, &mut okm).unwrap();
        assert_eq!(
            hex::encode(okm),
            "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"
        );
    }

    #[test]
    fn code_format_and_parse() {
        assert_eq!(PairingCode::from_u32(7).unwrap().to_string(), "000007");
        assert_eq!(&PairingCode::from_u32(42).unwrap().ascii(), b"000042");
        assert_eq!(
            PairingCode::from_u32(999_999).unwrap().to_string(),
            "999999"
        );
        assert!(PairingCode::from_u32(1_000_000).is_none());
        assert_eq!("000000".parse::<PairingCode>().unwrap().value(), 0);
        assert_eq!("123456".parse::<PairingCode>().unwrap().value(), 123_456);
        for bad in [
            "12345",
            "1234567",
            "12a456",
            " 12345",
            "123 456",
            "+12345",
            "-12345",
            "",
            "١٢٣٤٥٦",
        ] {
            assert_eq!(
                bad.parse::<PairingCode>().unwrap_err(),
                Error::InvalidCode,
                "{bad:?}"
            );
        }
        assert_eq!(
            pair_info(&PairingCode::from_u32(1234).unwrap()),
            b"vq/pair/v1001234"
        );
        assert_eq!(
            format!("{:?}", PairingCode::from_u32(1).unwrap()),
            "PairingCode(******)"
        );
    }

    #[test]
    fn code_generation_is_roughly_uniform() {
        use rand::SeedableRng;
        let mut rng = rand::rngs::StdRng::seed_from_u64(1);
        let mut buckets = [0u32; 10];
        let n = 200_000;
        for _ in 0..n {
            let c = PairingCode::generate_with(&mut rng);
            assert!(c.value() < 1_000_000);
            buckets[(c.value() / 100_000) as usize] += 1;
        }
        for b in buckets {
            let expected = n / 10;
            assert!(b.abs_diff(expected) < expected / 20, "{buckets:?}");
        }
        // OS RNG path works and stays in range.
        for _ in 0..1000 {
            assert!(PairingCode::generate().value() < 1_000_000);
        }
    }

    #[test]
    fn pairing_flow_and_wrong_code() {
        let phone = IdentityKeyPair::generate();
        let desk = IdentityKeyPair::generate();
        let (np, nd) = (random_nonce(), random_nonce());
        let code = PairingCode::generate();
        let ss_p = phone.shared_secret(&desk.public_bytes()).unwrap();
        let ss_d = desk.shared_secret(&phone.public_bytes()).unwrap();
        let kp = derive_pair_key(&ss_p, &np, &nd, &code);
        let kd = derive_pair_key(&ss_d, &np, &nd, &code);
        assert_eq!(kp, kd);
        let (pp, pd) = (phone.public_bytes(), desk.public_bytes());
        let mac_p = phone_confirm_mac(&kp, &pp, &pd);
        verify_phone_confirm_mac(&kd, &pp, &pd, &mac_p).unwrap();
        let mac_d = desktop_result_mac(&kd, &pp, &pd);
        verify_desktop_result_mac(&kp, &pp, &pd, &mac_d).unwrap();
        assert_ne!(mac_p, mac_d);
        // role confusion fails
        assert_eq!(
            verify_desktop_result_mac(&kp, &pp, &pd, &mac_p),
            Err(Error::BadMac)
        );
        // wrong code fails
        let wrong = PairingCode::from_u32((code.value() + 1) % 1_000_000).unwrap();
        let kw = derive_pair_key(&ss_d, &np, &nd, &wrong);
        assert_eq!(
            verify_phone_confirm_mac(&kw, &pp, &pd, &mac_p),
            Err(Error::BadMac)
        );
        // swapped nonces give a different key
        assert_ne!(derive_pair_key(&ss_p, &nd, &np, &code), kp);
        // session keys agree and differ from the pair key
        let (sp, sd) = (random_nonce(), random_nonce());
        let s1 = derive_session_key(&ss_p, &sp, &sd);
        assert_eq!(s1, derive_session_key(&ss_d, &sp, &sd));
        assert_ne!(s1, derive_session_key(&ss_d, &sd, &sp));
        assert_ne!(s1, kp);
    }
}
