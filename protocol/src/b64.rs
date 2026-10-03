//! Field encodings used inside JSON messages.
//!
//! * Binary fields: RFC 4648 §4 **standard** base64 alphabet (`+`, `/`) **with
//!   `=` padding**. Decoding is strict: no whitespace, no missing or extra
//!   padding, no non-zero trailing bits, and the decoded length must match the
//!   field's fixed length exactly.
//! * UUID fields: the 36-character hyphenated form (8-4-4-4-12). Parsing is
//!   case-insensitive; encoding is always lowercase.

use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use uuid::Uuid;

/// Encode bytes as standard, padded base64.
pub fn encode(bytes: &[u8]) -> String {
    STANDARD.encode(bytes)
}

/// Strictly decode standard, padded base64 into exactly `N` bytes.
pub fn decode_fixed<const N: usize>(s: &str) -> Result<[u8; N], String> {
    let v = STANDARD
        .decode(s.as_bytes())
        .map_err(|e| format!("invalid base64: {e}"))?;
    <[u8; N]>::try_from(v.as_slice())
        .map_err(|_| format!("expected {N} bytes after base64 decoding, got {}", v.len()))
}

/// Strictly parse a hyphenated UUID string (case-insensitive).
pub fn parse_uuid(s: &str) -> Result<Uuid, String> {
    let b = s.as_bytes();
    let hyphenated = b.len() == 36
        && b.iter().enumerate().all(|(i, c)| match i {
            8 | 13 | 18 | 23 => *c == b'-',
            _ => c.is_ascii_hexdigit(),
        });
    if !hyphenated {
        return Err(format!("expected a hyphenated UUID, got {s:?}"));
    }
    Uuid::try_parse(s).map_err(|e| format!("invalid UUID: {e}"))
}

/// Format a UUID in lowercase hyphenated form.
pub fn format_uuid(u: &Uuid) -> String {
    u.hyphenated().to_string()
}

/// `#[serde(with = "b64::bytes32")]` for `[u8; 32]` fields.
pub mod bytes32 {
    use serde::{de::Error as _, Deserialize, Deserializer, Serializer};

    /// Serialize as base64.
    pub fn serialize<S: Serializer>(v: &[u8; 32], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&super::encode(v))
    }

    /// Deserialize from base64, requiring exactly 32 bytes.
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; 32], D::Error> {
        let s = String::deserialize(d)?;
        super::decode_fixed::<32>(&s).map_err(D::Error::custom)
    }
}

/// `#[serde(with = "b64::opt_bytes32")]` for `Option<[u8; 32]>` fields
/// (absent and `null` both mean `None`; use with `#[serde(default)]`).
pub mod opt_bytes32 {
    use serde::{de::Error as _, Deserialize, Deserializer, Serializer};

    /// Serialize `Some` as base64 (callers skip `None`).
    pub fn serialize<S: Serializer>(v: &Option<[u8; 32]>, s: S) -> Result<S::Ok, S::Error> {
        match v {
            Some(b) => s.serialize_str(&super::encode(b)),
            None => s.serialize_none(),
        }
    }

    /// Deserialize optional base64 of exactly 32 bytes.
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Option<[u8; 32]>, D::Error> {
        match Option::<String>::deserialize(d)? {
            None => Ok(None),
            Some(s) => super::decode_fixed::<32>(&s)
                .map(Some)
                .map_err(D::Error::custom),
        }
    }
}

/// `#[serde(with = "b64::uuid_str")]` for strict hyphenated, lowercase-emitted UUIDs.
pub mod uuid_str {
    use serde::{de::Error as _, Deserialize, Deserializer, Serializer};
    use uuid::Uuid;

    /// Serialize lowercase hyphenated.
    pub fn serialize<S: Serializer>(v: &Uuid, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&super::format_uuid(v))
    }

    /// Deserialize hyphenated, case-insensitive.
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Uuid, D::Error> {
        let s = String::deserialize(d)?;
        super::parse_uuid(&s).map_err(D::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base64_roundtrip_and_strictness() {
        let k = [0xABu8; 32];
        let s = encode(&k);
        assert_eq!(s.len(), 44);
        assert!(s.ends_with('='));
        assert_eq!(decode_fixed::<32>(&s).unwrap(), k);
        // missing padding
        assert!(decode_fixed::<32>(s.trim_end_matches('=')).is_err());
        // wrong length
        assert!(decode_fixed::<32>(&encode(&[0u8; 31])).is_err());
        assert!(decode_fixed::<32>(&encode(&[0u8; 33])).is_err());
        // url-safe alphabet rejected
        let urlsafe = encode(&[0xFBu8; 32]).replace('+', "-").replace('/', "_");
        assert!(decode_fixed::<32>(&urlsafe).is_err());
        // whitespace rejected
        assert!(decode_fixed::<32>(&format!(" {s}")).is_err());
        // non-canonical trailing bits rejected: for 32 bytes the char before '='
        // carries 2 unused low bits, which must be zero ('A' ok, 'B' not).
        let zeros = encode(&[0u8; 32]);
        assert_eq!(&zeros[42..], "A=");
        let bad = format!("{}B=", &zeros[..42]);
        assert!(decode_fixed::<32>(&bad).is_err());
    }

    #[test]
    fn uuid_parsing() {
        let u = parse_uuid("1A2B3C4D-0000-4000-8000-00000000000F").unwrap();
        assert_eq!(format_uuid(&u), "1a2b3c4d-0000-4000-8000-00000000000f");
        assert!(parse_uuid("1a2b3c4d000040008000000000000000").is_err());
        assert!(parse_uuid("{1a2b3c4d-0000-4000-8000-00000000000f}").is_err());
        assert!(parse_uuid("urn:uuid:1a2b3c4d-0000-4000-8000-00000000000f").is_err());
        assert!(parse_uuid("1a2b3c4d-0000-4000-8000-00000000000g").is_err());
        assert!(parse_uuid("").is_err());
    }
}
