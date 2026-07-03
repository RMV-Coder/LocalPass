//! Argon2id parameters: [`KdfParams`].
//!
//! These are the tunable cost parameters for the password KDF (PRD §5.2). They
//! are **not secret** — they live in the account-store header so the MUK can be
//! re-derived on any device — but they are integrity-relevant: a change to the
//! salt or cost parameters changes the derived key, so they must round-trip
//! deterministically.
//!
//! # Serialization
//!
//! [`KdfParams::to_bytes`] emits a compact, fixed-layout, **versioned** binary
//! encoding:
//!
//! ```text
//! ┌─────────┬──────────┬────────┬────────┬───────────┐
//! │ version │ m_cost   │ t_cost │ p_cost │ salt      │
//! │ 0x01    │ u32 (KiB)│ u32    │ u32    │ 16 bytes  │
//! │ 1 byte  │ 4 (LE)   │ 4 (LE) │ 4 (LE) │ 16        │
//! └─────────┴──────────┴────────┴────────┴───────────┘  = 29 bytes
//! ```
//!
//! Fixed little-endian layout (rather than JSON) keeps the header compact and
//! byte-exact across platforms, which matters because these bytes feed into a
//! deterministic key derivation. [`KdfParams::from_bytes`] is the inverse and
//! rejects a wrong version or length.

use rand_core::{OsRng, RngCore};

use crate::error::{Error, Result};

/// Serialization version for [`KdfParams`].
const PARAMS_VERSION: u8 = 0x01;

/// Length of the Argon2id salt, in bytes (PRD contract: 16-byte salt).
pub const SALT_LEN: usize = 16;

/// Serialized length of [`KdfParams`]: `1 + 4 + 4 + 4 + 16`.
pub const PARAMS_SERIALIZED_LEN: usize = 1 + 4 + 4 + 4 + SALT_LEN;

/// Argon2id cost parameters plus the per-derivation salt.
///
/// Construct via [`KdfParams::recommended`] (fresh random salt at PRD default
/// costs), [`KdfParams::new`] (explicit costs, fresh salt), or
/// [`KdfParams::from_bytes`] (rehydrate a stored header).
///
/// Not a secret; freely `Clone`/`Copy`/`Debug` (the salt is public header
/// data, not key material).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct KdfParams {
    /// Memory cost in kibibytes (KiB). PRD recommended: 65 536 (= 64 MiB).
    m_cost_kib: u32,
    /// Time cost (number of passes). PRD recommended: 3.
    t_cost: u32,
    /// Degree of parallelism (lanes). PRD recommended: 4.
    p_cost: u32,
    /// 16-byte salt.
    salt: [u8; SALT_LEN],
}

impl KdfParams {
    /// PRD §5.2 recommended defaults: **m = 64 MiB, t = 3, p = 4**, with a
    /// freshly generated random 16-byte salt.
    #[must_use]
    pub fn recommended() -> Self {
        Self::new(64 * 1024, 3, 4)
    }

    /// Construct with explicit cost parameters and a **fresh random salt**.
    ///
    /// - `m_cost_kib` — memory in KiB.
    /// - `t_cost` — passes.
    /// - `p_cost` — lanes.
    ///
    /// Intended for tests (cheap params) and device auto-calibration. The salt
    /// is always generated from the OS CSPRNG so two calls never collide.
    #[must_use]
    pub fn new(m_cost_kib: u32, t_cost: u32, p_cost: u32) -> Self {
        let mut salt = [0u8; SALT_LEN];
        OsRng.fill_bytes(&mut salt);
        Self {
            m_cost_kib,
            t_cost,
            p_cost,
            salt,
        }
    }

    /// Reconstruct from all fields, including a caller-supplied salt.
    ///
    /// Used by [`from_bytes`](Self::from_bytes) and by tests that need a fixed,
    /// reproducible salt for deterministic vectors.
    #[must_use]
    pub fn with_salt(m_cost_kib: u32, t_cost: u32, p_cost: u32, salt: [u8; SALT_LEN]) -> Self {
        Self {
            m_cost_kib,
            t_cost,
            p_cost,
            salt,
        }
    }

    /// Memory cost in KiB.
    #[must_use]
    pub fn m_cost_kib(&self) -> u32 {
        self.m_cost_kib
    }

    /// Time cost (passes).
    #[must_use]
    pub fn t_cost(&self) -> u32 {
        self.t_cost
    }

    /// Parallelism (lanes).
    #[must_use]
    pub fn p_cost(&self) -> u32 {
        self.p_cost
    }

    /// The 16-byte salt.
    #[must_use]
    pub fn salt(&self) -> &[u8; SALT_LEN] {
        &self.salt
    }

    /// Serialize to the fixed 29-byte versioned layout (see [module docs](self)).
    #[must_use]
    pub fn to_bytes(&self) -> [u8; PARAMS_SERIALIZED_LEN] {
        let mut out = [0u8; PARAMS_SERIALIZED_LEN];
        out[0] = PARAMS_VERSION;
        out[1..5].copy_from_slice(&self.m_cost_kib.to_le_bytes());
        out[5..9].copy_from_slice(&self.t_cost.to_le_bytes());
        out[9..13].copy_from_slice(&self.p_cost.to_le_bytes());
        out[13..].copy_from_slice(&self.salt);
        out
    }

    /// Parse the fixed layout produced by [`to_bytes`](Self::to_bytes).
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidKdfParams`] for a wrong length, an unknown
    /// version byte, or a zero cost parameter (Argon2 requires each of
    /// m/t/p ≥ 1; a zero would fail at derivation time, so we reject early).
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != PARAMS_SERIALIZED_LEN {
            return Err(Error::InvalidKdfParams("wrong serialized length"));
        }
        if bytes[0] != PARAMS_VERSION {
            return Err(Error::InvalidKdfParams("unsupported params version"));
        }
        let m_cost_kib = u32::from_le_bytes(bytes[1..5].try_into().unwrap());
        let t_cost = u32::from_le_bytes(bytes[5..9].try_into().unwrap());
        let p_cost = u32::from_le_bytes(bytes[9..13].try_into().unwrap());
        if m_cost_kib == 0 || t_cost == 0 || p_cost == 0 {
            return Err(Error::InvalidKdfParams("cost parameters must be non-zero"));
        }
        let mut salt = [0u8; SALT_LEN];
        salt.copy_from_slice(&bytes[13..]);
        Ok(Self {
            m_cost_kib,
            t_cost,
            p_cost,
            salt,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recommended_values() {
        let p = KdfParams::recommended();
        assert_eq!(p.m_cost_kib(), 65_536);
        assert_eq!(p.t_cost(), 3);
        assert_eq!(p.p_cost(), 4);
    }

    #[test]
    fn serialize_roundtrip() {
        let p = KdfParams::with_salt(65_536, 3, 4, *b"saltsaltsaltsalt");
        let bytes = p.to_bytes();
        assert_eq!(bytes.len(), PARAMS_SERIALIZED_LEN);
        let p2 = KdfParams::from_bytes(&bytes).unwrap();
        assert_eq!(p, p2);
    }

    #[test]
    fn from_bytes_rejects_wrong_length() {
        assert!(KdfParams::from_bytes(&[0u8; PARAMS_SERIALIZED_LEN - 1]).is_err());
        assert!(KdfParams::from_bytes(&[]).is_err());
    }

    #[test]
    fn from_bytes_rejects_wrong_version() {
        let mut bytes = KdfParams::recommended().to_bytes();
        bytes[0] = 0xFF;
        assert!(KdfParams::from_bytes(&bytes).is_err());
    }

    #[test]
    fn from_bytes_rejects_zero_cost() {
        let mut bytes = KdfParams::with_salt(0, 1, 1, [0u8; SALT_LEN]).to_bytes();
        // m_cost is bytes[1..5]; the constructor stored 0 already.
        assert!(KdfParams::from_bytes(&bytes).is_err());
        // t_cost zero.
        bytes = KdfParams::with_salt(64, 0, 1, [0u8; SALT_LEN]).to_bytes();
        assert!(KdfParams::from_bytes(&bytes).is_err());
    }
}
