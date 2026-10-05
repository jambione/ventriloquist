//! The QR payload of SPEC_V3 §5:
//!
//! `vq://pair?v=3&r=<relay url>&room=<room_id>&s=<room_secret>&d=<desktop device_id>&k=<desktop X25519 pub, b64url>&c=<6-digit code>&n=<desktop name>`
//!
//! Values are percent-encoded (RFC 3986 unreserved characters stay as they
//! are; a space is `%20`, never `+`, so every URL parser agrees).

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use percent_encoding::{utf8_percent_encode, AsciiSet, NON_ALPHANUMERIC};
use uuid::Uuid;

/// Version of the QR payload.
pub const PAIRING_URI_VERSION: u32 = 3;

const ENCODE: &AsciiSet = &NON_ALPHANUMERIC.remove(b'-').remove(b'_').remove(b'.').remove(b'~');

/// Everything the QR carries.
#[derive(Debug, Clone)]
pub struct PairingUri<'a> {
    /// Relay base URL.
    pub relay_url: &'a str,
    /// Room id.
    pub room_id: &'a str,
    /// Room secret (base64url).
    pub room_secret: &'a str,
    /// This desktop's `device_id`.
    pub device_id: Uuid,
    /// This desktop's X25519 public key.
    pub public_key: [u8; 32],
    /// The active 6-digit pairing code.
    pub code: &'a str,
    /// This desktop's display name.
    pub name: &'a str,
}

impl PairingUri<'_> {
    /// The `vq://pair?…` string.
    pub fn to_uri(&self) -> String {
        let enc = |s: &str| utf8_percent_encode(s, ENCODE).to_string();
        format!(
            "vq://pair?v={}&r={}&room={}&s={}&d={}&k={}&c={}&n={}",
            PAIRING_URI_VERSION,
            enc(self.relay_url),
            enc(self.room_id),
            enc(self.room_secret),
            self.device_id.hyphenated(),
            URL_SAFE_NO_PAD.encode(self.public_key),
            enc(self.code),
            enc(self.name),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Parse like a phone would (the `url` crate decodes percent escapes).
    pub(crate) fn parse(uri: &str) -> std::collections::HashMap<String, String> {
        let u = url::Url::parse(uri).unwrap();
        assert_eq!(u.scheme(), "vq");
        assert_eq!(u.host_str(), Some("pair"));
        u.query_pairs().map(|(k, v)| (k.into_owned(), v.into_owned())).collect()
    }

    #[test]
    fn fields_round_trip_and_special_characters_are_escaped() {
        let id = Uuid::new_v4();
        let uri = PairingUri {
            relay_url: "https://relay.example.com",
            room_id: "AAAA-_bb",
            room_secret: "sec-ret_9",
            device_id: id,
            public_key: [7u8; 32],
            code: "004217",
            name: "Jon's PC & Mac=1 é",
        }
        .to_uri();
        assert!(!uri.contains(' ') && !uri.contains('+'), "{uri}");
        let q = parse(&uri);
        assert_eq!(q["v"], "3");
        assert_eq!(q["r"], "https://relay.example.com");
        assert_eq!(q["room"], "AAAA-_bb");
        assert_eq!(q["s"], "sec-ret_9");
        assert_eq!(q["d"], id.to_string());
        assert_eq!(URL_SAFE_NO_PAD.decode(&q["k"]).unwrap(), vec![7u8; 32]);
        assert_eq!(q["c"], "004217");
        assert_eq!(q["n"], "Jon's PC & Mac=1 é");
        assert_eq!(q.len(), 8);
    }
}
