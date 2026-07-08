//! Identifiers: a 16-byte [`Id`] newtype (UUIDv7 in practice) and typed aliases.
//!
//! Every id in LocalPass — vault, item, folder, op, device — is a 16-byte
//! UUIDv7 stored as a `BLOB` primary key (vault-format.md §2/§3) and rendered as
//! 32-char lowercase hex in AAD (`crate::aad`). UUIDv7's time-ordered prefix
//! leaks only *creation ordering* (accepted, vault-format.md §12 T1); it is
//! otherwise a random identifier and reveals no content.
//!
//! We keep one concrete `Id` type and expose readable aliases ([`VaultId`],
//! [`ItemId`], …) for signatures. They are the same type, so ids can be used as
//! join keys freely; the aliases are documentation, not enforcement.

use uuid::Uuid;

/// A 16-byte identifier (UUIDv7), stored as a SQLite `BLOB`.
///
/// `Copy` because it is 16 non-secret bytes; comparing and hashing are value
/// operations. Rendered for AAD via [`crate::aad::id_hex`].
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct Id([u8; 16]);

impl Id {
    /// Generate a fresh time-ordered UUIDv7.
    #[must_use]
    pub fn new() -> Self {
        Self(*Uuid::now_v7().as_bytes())
    }

    /// Construct from raw 16 bytes (e.g. read back from a `BLOB` column).
    #[must_use]
    pub fn from_bytes(bytes: [u8; 16]) -> Self {
        Self(bytes)
    }

    /// Construct from a byte slice, validating the length.
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error::Invalid`] if `bytes` is not exactly 16 bytes long
    /// (a corrupt or wrong-width `BLOB`).
    pub fn from_slice(bytes: &[u8]) -> crate::Result<Self> {
        let arr: [u8; 16] = bytes
            .try_into()
            .map_err(|_| crate::Error::Invalid("id blob was not 16 bytes"))?;
        Ok(Self(arr))
    }

    /// Borrow the raw 16 bytes (for storage and hashing).
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }

    /// Owned copy of the raw 16 bytes (convenient for `params!`).
    #[must_use]
    pub fn to_vec(&self) -> Vec<u8> {
        self.0.to_vec()
    }

    /// The lowercase-hyphenated UUID string, used for the `<vault_id>.vault`
    /// file name (vault-format.md §1). Distinct from the AAD hex (no hyphens).
    #[must_use]
    pub fn to_hyphenated(&self) -> String {
        Uuid::from_bytes(self.0).hyphenated().to_string()
    }
}

impl Default for Id {
    fn default() -> Self {
        Self::new()
    }
}

impl core::fmt::Debug for Id {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // Ids are non-secret; print the hyphenated UUID for readability.
        write!(f, "Id({})", self.to_hyphenated())
    }
}

/// A vault identifier.
pub type VaultId = Id;
/// An item identifier.
pub type ItemId = Id;
/// A folder identifier.
pub type FolderId = Id;
/// An op identifier.
pub type OpId = Id;
/// A device identifier.
pub type DeviceId = Id;
/// An attachment identifier.
pub type AttachmentId = Id;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn v7_ids_are_unique_and_time_ordered() {
        let a = Id::new();
        let b = Id::new();
        assert_ne!(a, b);
        // v7 high bytes are a millisecond timestamp; b was created at or after a.
        assert!(b.as_bytes()[..6] >= a.as_bytes()[..6]);
    }

    #[test]
    fn roundtrip_bytes() {
        let id = Id::new();
        let back = Id::from_slice(&id.to_vec()).unwrap();
        assert_eq!(id, back);
    }

    #[test]
    fn from_slice_rejects_wrong_length() {
        assert!(Id::from_slice(&[0u8; 15]).is_err());
        assert!(Id::from_slice(&[0u8; 17]).is_err());
    }

    #[test]
    fn hyphenated_has_hyphens_hex_does_not() {
        let id = Id::from_bytes([0xABu8; 16]);
        assert!(id.to_hyphenated().contains('-'));
        assert_eq!(crate::aad::id_hex(&id).len(), 32);
    }
}
