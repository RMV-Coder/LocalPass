//! Device-identity export/import and fingerprints (sync-protocol.md §6) — the
//! **pairing groundwork** half of Part D.
//!
//! A device advertises its trust anchor as a compact, self-describing string:
//!
//! ```text
//! LPDEV1-<hex(device_id(16) || ed25519_pub(32) || x25519_pub(32) || crc(4))>
//! ```
//!
//! The trailing CRC-32 catches typos on manual re-entry. The **fingerprint** is
//! a short BLAKE3 digest of the two public keys, rendered as
//! `xxxx-xxxx-xxxx-xxxx` hex groups — the value a user compares out-of-band
//! before trusting (`localpass device trust <id> --fingerprint <fp>`).
//!
//! Full live SAS pairing (mDNS discovery + a 6-word transcript phrase) is a
//! **later wave** (sync-protocol.md §6 / §7.4); this module provides only the
//! offline string exchange + fingerprint confirmation the MVP CLI needs.

use lp_crypto::blake3_256;
use lp_vault::DeviceIdentityInfo;
use lp_vault::ids::{DeviceId, Id};

use crate::error::{Error, Result};

/// The identity-string version prefix.
const PREFIX: &str = "LPDEV1-";

/// Bytes of the identity payload before the CRC: `device_id || ed || x`.
const PAYLOAD_LEN: usize = 16 + 32 + 32;

/// A parsed device identity (the trust anchor a peer pins; sync-protocol.md §6).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DeviceIdentity {
    /// The device id (16 bytes).
    pub device_id: DeviceId,
    /// Ed25519 signing public key (op-author verification anchor).
    pub ed25519_pub: [u8; 32],
    /// X25519 sealing public key (key-share recipient).
    pub x25519_pub: [u8; 32],
}

impl From<DeviceIdentityInfo> for DeviceIdentity {
    fn from(i: DeviceIdentityInfo) -> Self {
        Self {
            device_id: i.device_id,
            ed25519_pub: i.ed25519_pub,
            x25519_pub: i.x25519_pub,
        }
    }
}

impl DeviceIdentity {
    /// Render the compact, CRC-checked identity string (`LPDEV1-…`).
    #[must_use]
    pub fn to_export_string(&self) -> String {
        let mut payload = Vec::with_capacity(PAYLOAD_LEN + 4);
        payload.extend_from_slice(self.device_id.as_bytes());
        payload.extend_from_slice(&self.ed25519_pub);
        payload.extend_from_slice(&self.x25519_pub);
        let crc = crc32(&payload);
        payload.extend_from_slice(&crc.to_be_bytes());
        format!("{PREFIX}{}", to_hex(&payload))
    }

    /// Parse an identity string produced by [`to_export_string`](Self::to_export_string),
    /// verifying the version prefix and CRC.
    ///
    /// # Errors
    ///
    /// [`Error::Invalid`] on a wrong prefix, non-hex body, wrong length, or a
    /// failed CRC (a mistyped character).
    pub fn from_export_string(s: &str) -> Result<Self> {
        let s = s.trim();
        let body = s
            .strip_prefix(PREFIX)
            .ok_or(Error::Invalid("identity string missing LPDEV1 prefix"))?;
        let bytes = from_hex(body).ok_or(Error::Invalid("identity string is not valid hex"))?;
        if bytes.len() != PAYLOAD_LEN + 4 {
            return Err(Error::Invalid("identity string has the wrong length"));
        }
        let (payload, crc_bytes) = bytes.split_at(PAYLOAD_LEN);
        let crc = u32::from_be_bytes(crc_bytes.try_into().unwrap());
        if crc != crc32(payload) {
            return Err(Error::Invalid(
                "identity string checksum failed (mistyped?)",
            ));
        }
        let device_id = Id::from_bytes(payload[0..16].try_into().unwrap());
        let ed25519_pub: [u8; 32] = payload[16..48].try_into().unwrap();
        let x25519_pub: [u8; 32] = payload[48..80].try_into().unwrap();
        Ok(Self {
            device_id,
            ed25519_pub,
            x25519_pub,
        })
    }

    /// The out-of-band comparison fingerprint: a BLAKE3 digest of
    /// `"localpass/v1/device-fpr" || ed25519_pub || x25519_pub`, rendered as
    /// four dash-separated 4-hex-digit groups (`xxxx-xxxx-xxxx-xxxx`).
    ///
    /// Binding both public keys means an attacker cannot swap either key without
    /// changing the fingerprint the user reads aloud.
    #[must_use]
    pub fn fingerprint(&self) -> String {
        let mut input = Vec::with_capacity(24 + 64);
        input.extend_from_slice(b"localpass/v1/device-fpr");
        input.extend_from_slice(&self.ed25519_pub);
        input.extend_from_slice(&self.x25519_pub);
        let digest = blake3_256(&input);
        // First 8 bytes → four 16-bit groups of hex.
        let mut groups = Vec::with_capacity(4);
        for chunk in digest[..8].chunks(2) {
            groups.push(format!("{:02x}{:02x}", chunk[0], chunk[1]));
        }
        groups.join("-")
    }

    /// Whether `candidate` (case-insensitive, dashes optional) matches this
    /// identity's [`fingerprint`](Self::fingerprint) — the non-interactive
    /// confirmation for `device trust --fingerprint`.
    #[must_use]
    pub fn fingerprint_matches(&self, candidate: &str) -> bool {
        let norm = |s: &str| {
            s.chars()
                .filter(|c| c.is_ascii_hexdigit())
                .flat_map(char::to_lowercase)
                .collect::<String>()
        };
        norm(candidate) == norm(&self.fingerprint())
    }
}

/// Lowercase-hex encode.
fn to_hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push(char::from_digit(u32::from(b >> 4), 16).unwrap());
        s.push(char::from_digit(u32::from(b & 0x0f), 16).unwrap());
    }
    s
}

/// Decode lowercase/uppercase hex, ignoring dashes; `None` on any bad char or
/// an odd length.
fn from_hex(s: &str) -> Option<Vec<u8>> {
    let clean: Vec<char> = s.chars().filter(|c| *c != '-').collect();
    if !clean.len().is_multiple_of(2) {
        return None;
    }
    let mut out = Vec::with_capacity(clean.len() / 2);
    let mut iter = clean.chunks(2);
    for pair in &mut iter {
        let hi = pair[0].to_digit(16)?;
        let lo = pair[1].to_digit(16)?;
        out.push((hi * 16 + lo) as u8);
    }
    Some(out)
}

/// A small, dependency-free CRC-32 (IEEE 802.3 polynomial) for the identity
/// string's typo check. Not a security control — the trust decision rests on
/// the out-of-band fingerprint comparison.
fn crc32(data: &[u8]) -> u32 {
    let mut crc: u32 = 0xFFFF_FFFF;
    for &byte in data {
        crc ^= u32::from(byte);
        for _ in 0..8 {
            let mask = (crc & 1).wrapping_neg();
            crc = (crc >> 1) ^ (0xEDB8_8320 & mask);
        }
    }
    !crc
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> DeviceIdentity {
        DeviceIdentity {
            device_id: Id::from_bytes([0x11; 16]),
            ed25519_pub: [0x22; 32],
            x25519_pub: [0x33; 32],
        }
    }

    #[test]
    fn export_string_roundtrips() {
        let id = sample();
        let s = id.to_export_string();
        assert!(s.starts_with("LPDEV1-"));
        let back = DeviceIdentity::from_export_string(&s).unwrap();
        assert_eq!(back, id);
    }

    #[test]
    fn checksum_rejects_a_typo() {
        let id = sample();
        let mut s = id.to_export_string();
        // Flip one hex nibble in the body.
        let last = s.pop().unwrap();
        let flipped = if last == 'a' { 'b' } else { 'a' };
        s.push(flipped);
        assert!(DeviceIdentity::from_export_string(&s).is_err());
    }

    #[test]
    fn fingerprint_is_stable_and_grouped() {
        let id = sample();
        let fp = id.fingerprint();
        assert_eq!(fp, id.fingerprint());
        assert_eq!(fp.matches('-').count(), 3);
        assert!(id.fingerprint_matches(&fp));
        assert!(id.fingerprint_matches(&fp.replace('-', "")));
        assert!(id.fingerprint_matches(&fp.to_uppercase()));
        assert!(!id.fingerprint_matches("0000-0000-0000-0000"));
    }

    #[test]
    fn different_keys_change_fingerprint() {
        let a = sample();
        let mut b = a;
        b.ed25519_pub[0] ^= 0xFF;
        assert_ne!(a.fingerprint(), b.fingerprint());
    }

    #[test]
    fn rejects_wrong_prefix() {
        assert!(DeviceIdentity::from_export_string("NOPE-abcd").is_err());
    }
}
