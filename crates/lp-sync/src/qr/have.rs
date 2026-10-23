//! The "what I have" code (`qr-transport.md` §4): one still QR code the
//! receiver shows the sender, carrying per-vault, per-device seq heads.
//!
//! ```text
//! "LPQH" (4) || version (1) || device_id (16) || INVENTORY body || crc32 LE (4)
//! ```
//!
//! The body is the nearby link's `INVENTORY` encoding, read by the same
//! bounded decoder. The code is **unauthenticated**: it may only change which
//! ops a sender selects (§4.3), so nothing here is trusted beyond its shape.

use lp_vault::Session;
use lp_vault::ids::{DeviceId, Id, VaultId};

use super::{MAX_HAVE_BYTES, PROTOCOL_VERSION};
use crate::engine;
use crate::error::{Error, Result};
use crate::identity::crc32;
use crate::nearby::message;

const HAVE_MAGIC: &[u8; 4] = b"LPQH";
/// The text form's prefix (`qr-transport.md` §4.1).
pub const HAVE_TEXT_PREFIX: &str = "LPHAVE1-";
/// Bytes around the `INVENTORY` body.
const HAVE_OVERHEAD: usize = 4 + 1 + 16 + 4;

/// Per vault id, per author device id, the highest seq held — the nearby
/// link's `INVENTORY` (`lan-transport.md` §6.2).
pub type Heads = std::collections::BTreeMap<[u8; 16], std::collections::BTreeMap<[u8; 16], u64>>;

/// What a receiver holds: its device id and, per vault, per author device,
/// the highest seq.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HaveCode {
    /// The receiver (as it claims).
    pub device_id: DeviceId,
    /// Per vault id, per author device id, the highest seq held.
    pub heads: Heads,
}

impl HaveCode {
    /// This device's code for `vaults` (empty = every vault it holds).
    ///
    /// # Errors
    ///
    /// [`Error::Vault`] on a read failure or an unknown vault.
    pub fn build(session: &Session, vaults: &[VaultId]) -> Result<Self> {
        let mut heads = Heads::new();
        let held: Vec<VaultId> = session.list_vaults()?.into_iter().map(|(v, _)| v).collect();
        for vault_id in held {
            if !vaults.is_empty() && !vaults.contains(&vault_id) {
                continue;
            }
            let vault = session.open_vault(vault_id)?;
            heads.insert(*vault_id.as_bytes(), engine::vault_heads(&vault)?);
        }
        for v in vaults {
            if !heads.contains_key(v.as_bytes()) {
                return Err(Error::Invalid("no such vault on this device"));
            }
        }
        Ok(Self {
            device_id: session.device_id(),
            heads,
        })
    }

    /// The code's bytes.
    ///
    /// # Errors
    ///
    /// [`Error::Qr`] if it would not fit one QR code ([`MAX_HAVE_BYTES`]) —
    /// list fewer vaults, or receive everything instead.
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        let body = message::encode_inventory(&self.heads)?;
        let mut out = Vec::with_capacity(HAVE_OVERHEAD + body.len());
        out.extend_from_slice(HAVE_MAGIC);
        out.push(PROTOCOL_VERSION);
        out.extend_from_slice(self.device_id.as_bytes());
        out.extend_from_slice(&body);
        let crc = crc32(&out);
        out.extend_from_slice(&crc.to_le_bytes());
        if out.len() > MAX_HAVE_BYTES {
            return Err(Error::Qr(
                "this device holds too many vaults for one code; pick fewer vaults or receive everything",
            ));
        }
        Ok(out)
    }

    /// Parse a scanned code. Every check runs before anything is allocated
    /// from a declared count.
    ///
    /// # Errors
    ///
    /// [`Error::Qr`] for anything that is not a well-formed code.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() > MAX_HAVE_BYTES || bytes.len() < HAVE_OVERHEAD + 2 {
            return Err(Error::Qr(
                "not a LocalPass \"what I have\" code (wrong size)",
            ));
        }
        if &bytes[..4] != HAVE_MAGIC {
            return Err(Error::Qr("not a LocalPass \"what I have\" code"));
        }
        if bytes[4] != PROTOCOL_VERSION {
            return Err(Error::Qr(
                "the code was made by a different LocalPass version",
            ));
        }
        let (body, crc) = bytes.split_at(bytes.len() - 4);
        if crc32(body).to_le_bytes() != crc {
            return Err(Error::Qr("the code failed its checksum (scan it again)"));
        }
        let device_id = Id::from_bytes(body[5..21].try_into().expect("16 bytes"));
        let heads = message::decode_inventory(&body[21..])
            .map_err(|_| Error::Qr("the code's vault list is malformed"))?;
        Ok(Self { device_id, heads })
    }

    /// The text form: `LPHAVE1-` + lowercase hex.
    ///
    /// # Errors
    ///
    /// As [`to_bytes`](Self::to_bytes).
    pub fn to_text(&self) -> Result<String> {
        let bytes = self.to_bytes()?;
        let mut s = String::with_capacity(HAVE_TEXT_PREFIX.len() + bytes.len() * 2);
        s.push_str(HAVE_TEXT_PREFIX);
        for b in &bytes {
            s.push(char::from_digit(u32::from(b >> 4), 16).expect("nibble"));
            s.push(char::from_digit(u32::from(b & 0x0f), 16).expect("nibble"));
        }
        Ok(s)
    }

    /// Parse the text form (surrounding whitespace ignored).
    ///
    /// # Errors
    ///
    /// [`Error::Qr`] for anything that is not a well-formed code.
    pub fn from_text(text: &str) -> Result<Self> {
        let hex = text
            .trim()
            .strip_prefix(HAVE_TEXT_PREFIX)
            .ok_or(Error::Qr("not a LocalPass \"what I have\" code"))?;
        if hex.len() % 2 != 0 || hex.len() > MAX_HAVE_BYTES * 2 {
            return Err(Error::Qr(
                "not a LocalPass \"what I have\" code (wrong size)",
            ));
        }
        let bytes = hex
            .as_bytes()
            .chunks(2)
            .map(|p| {
                let hi = char::from(p[0]).to_digit(16)?;
                let lo = char::from(p[1]).to_digit(16)?;
                Some((hi * 16 + lo) as u8)
            })
            .collect::<Option<Vec<u8>>>()
            .ok_or(Error::Qr("not a LocalPass \"what I have\" code"))?;
        Self::from_bytes(&bytes)
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::*;

    fn code(vaults: usize, devices: usize) -> HaveCode {
        let mut heads = Heads::new();
        for v in 0..vaults {
            let mut h = BTreeMap::new();
            for d in 0..devices {
                h.insert([d as u8 + 1; 16], (v * 10 + d) as u64);
            }
            heads.insert([v as u8 + 1; 16], h);
        }
        HaveCode {
            device_id: Id::from_bytes([0xEE; 16]),
            heads,
        }
    }

    #[test]
    fn round_trips_as_bytes_and_text() {
        let c = code(3, 3);
        assert_eq!(HaveCode::from_bytes(&c.to_bytes().unwrap()).unwrap(), c);
        let t = c.to_text().unwrap();
        assert!(t.starts_with("LPHAVE1-"));
        assert_eq!(HaveCode::from_text(&format!("  {t}\n")).unwrap(), c);
    }

    #[test]
    fn a_vault_with_three_devices_costs_90_bytes() {
        let one = code(1, 3).to_bytes().unwrap().len();
        let two = code(2, 3).to_bytes().unwrap().len();
        assert_eq!(two - one, 16 + 2 + 3 * 24);
    }

    #[test]
    fn a_code_that_does_not_fit_one_qr_is_refused() {
        // 40 vaults × 3 devices = 3 600 bytes > 2 953.
        assert!(code(40, 3).to_bytes().is_err());
    }

    #[test]
    fn damaged_or_hostile_codes_are_refused() {
        let good = code(2, 2).to_bytes().unwrap();
        // Any flipped bit fails the CRC.
        for i in 0..good.len() {
            let mut bad = good.clone();
            bad[i] ^= 1;
            assert!(HaveCode::from_bytes(&bad).is_err(), "byte {i}");
        }
        // Oversize input is refused before parsing.
        assert!(HaveCode::from_bytes(&vec![0u8; MAX_HAVE_BYTES + 1]).is_err());
        // A correctly-checksummed code whose body claims 65 535 vaults.
        let mut forged = b"LPQH\x01".to_vec();
        forged.extend_from_slice(&[0u8; 16]);
        forged.extend_from_slice(&u16::MAX.to_le_bytes());
        let crc = crc32(&forged);
        forged.extend_from_slice(&crc.to_le_bytes());
        assert!(HaveCode::from_bytes(&forged).is_err());
        // Text that is not hex.
        assert!(HaveCode::from_text("LPHAVE1-zz").is_err());
        assert!(HaveCode::from_text("LPDEV1-00").is_err());
    }
}
