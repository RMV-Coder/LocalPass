//! Symmetric key material: the 256-bit core, its role-typed newtypes, and the
//! 128-bit [`SecretKey`] second KDF factor.
//!
//! # The one core, four roles
//!
//! LocalPass's key hierarchy (PRD §4.3) is:
//!
//! ```text
//! master password ─┐
//!                  ├─ Argon2id ─┐
//! SecretKey ───────┘            ├─ HKDF ─▶ MasterUnlockKey (MUK)
//!                               │            │ unwraps
//!                               ▼            ▼
//!                            (per §4.3)   AccountKey
//!                                            │ unwraps
//!                                            ▼
//!                                         VaultKey
//!                                            │ unwraps
//!                                            ▼
//!                                         ItemKey
//! ```
//!
//! Every one of MUK / AccountKey / VaultKey / ItemKey is *the same* 256-bit
//! symmetric primitive ([`SymmetricKey`]) — but each is a **distinct newtype**
//! so the type system forbids using an `ItemKey` where a `VaultKey` is
//! expected. This kills a whole class of key-confusion bugs at compile time.
//! `IndexKey` is not a distinct type here: it is derived by callers from a
//! `VaultKey` via `derive_subkey("localpass/v1/index")` (fixed contract).
//!
//! All secret types here:
//! - are [`Zeroize`] + [`ZeroizeOnDrop`] — key bytes are wiped on drop;
//! - have redacting [`Debug`] impls (never print key material);
//! - do **not** implement `Clone` or `Serialize` (a key should be moved /
//!   derived, never casually copied or serialized in the clear);
//! - compare in constant time via [`subtle`] where equality is meaningful.

use rand_core::{OsRng, RngCore};
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::envelope::Envelope;
use crate::error::Result;
use crate::kdf::hkdf_sha256_32;
use crate::symmetric;

/// Length of a core symmetric key, in bytes (256-bit).
pub const SYMMETRIC_KEY_LEN: usize = 32;

/// Length of the [`SecretKey`] second KDF factor, in bytes (128-bit, PRD §4.3).
pub const SECRET_KEY_LEN: usize = 16;

/// A raw 256-bit symmetric key: the primitive underneath every role key.
///
/// This is the untyped core. Prefer the role newtypes ([`MasterUnlockKey`],
/// [`AccountKey`], [`VaultKey`], [`ItemKey`]) in application code so the
/// compiler prevents cross-role misuse; reach for the bare `SymmetricKey` only
/// inside `lp-crypto` or when a role genuinely does not yet apply.
///
/// # Hygiene
///
/// Zeroized on drop; redacting `Debug`; constant-time equality; intentionally
/// neither `Clone` nor `Serialize`.
#[derive(ZeroizeOnDrop)]
pub struct SymmetricKey {
    bytes: [u8; SYMMETRIC_KEY_LEN],
}

impl SymmetricKey {
    /// Wrap raw key bytes. Internal: callers outside the crate must go through
    /// `generate`, a KDF, or `derive_subkey` so keys always have a defined
    /// provenance.
    pub(crate) fn from_bytes(bytes: [u8; SYMMETRIC_KEY_LEN]) -> Self {
        Self { bytes }
    }

    /// Borrow the raw key bytes. Internal only — raw key access never leaves
    /// the crate.
    pub(crate) fn as_bytes(&self) -> &[u8; SYMMETRIC_KEY_LEN] {
        &self.bytes
    }

    /// Generate a fresh random 256-bit key from the OS CSPRNG.
    ///
    /// The only randomness source is `getrandom`/`OsRng` (PRD §5.2 — no
    /// userspace RNG state).
    #[must_use]
    pub fn generate() -> Self {
        let mut bytes = [0u8; SYMMETRIC_KEY_LEN];
        OsRng.fill_bytes(&mut bytes);
        Self { bytes }
    }

    /// Derive a labelled subkey via HKDF-SHA256.
    ///
    /// The receiver's bytes are the HKDF input keying material; `label` is the
    /// HKDF `info` (domain separation) and **must** be in the `localpass/v1/`
    /// namespace. Distinct labels yield independent keys; the same label
    /// always yields the same key (deterministic).
    ///
    /// This is how callers obtain, for example, the vault `IndexKey`:
    /// `vault_key.derive_subkey("localpass/v1/index")`.
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error::InvalidLabel`] if `label` is outside the
    /// namespace.
    pub fn derive_subkey(&self, label: &str) -> Result<SymmetricKey> {
        // Empty salt: the IKM (this key) already has full entropy, so HKDF's
        // extract step needs no additional salt; separation comes from `label`.
        let okm = hkdf_sha256_32(&[], &self.bytes, label)?;
        Ok(SymmetricKey::from_bytes(okm))
    }

    /// Authenticated-encrypt `plaintext` under this key, binding `aad`.
    ///
    /// A fresh random 24-byte nonce is drawn from the OS CSPRNG for every call
    /// (XChaCha's 192-bit nonce makes random nonces safe at scale, PRD §5.2).
    /// The returned [`Envelope`] carries the nonce and ciphertext+tag; `aad` is
    /// **not** stored and must be supplied again at [`open`](Self::open).
    ///
    /// # Errors
    ///
    /// Practically infallible for in-memory data; returns
    /// [`crate::Error::DecryptionFailed`] only if the AEAD backend reports an
    /// internal encrypt error (e.g. a length overflow).
    pub fn seal(&self, plaintext: &[u8], aad: &[u8]) -> Result<Envelope> {
        symmetric::seal(&self.bytes, plaintext, aad)
    }

    /// Verify and decrypt an [`Envelope`] under this key with the given `aad`.
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error::DecryptionFailed`] for *any* authentication
    /// failure — wrong key, tampered bytes, or wrong `aad` — with no
    /// distinction between them (oracle-resistance, see [`crate::error`]).
    pub fn open(&self, envelope: &Envelope, aad: &[u8]) -> Result<Vec<u8>> {
        symmetric::open(&self.bytes, envelope, aad)
    }
}

impl core::fmt::Debug for SymmetricKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("SymmetricKey(<redacted 32 bytes>)")
    }
}

/// Constant-time equality over the raw key bytes.
///
/// Provided because higher layers legitimately need to compare derived keys
/// (e.g. confirm a re-derivation matches) without leaking timing information.
impl ConstantTimeEq for SymmetricKey {
    fn ct_eq(&self, other: &Self) -> subtle::Choice {
        self.bytes.ct_eq(&other.bytes)
    }
}

impl PartialEq for SymmetricKey {
    fn eq(&self, other: &Self) -> bool {
        self.ct_eq(other).into()
    }
}
impl Eq for SymmetricKey {}

/// Declares a distinct role newtype over [`SymmetricKey`].
///
/// Each role gets its own type so the compiler forbids substituting one role
/// key for another. The macro forwards the safe operations (`generate`,
/// `derive_subkey`, `seal`, `open`, constant-time equality) and a redacting
/// `Debug`, while keeping raw-byte access crate-internal.
macro_rules! role_key {
    ($(#[$meta:meta])* $name:ident, $dbg:literal) => {
        $(#[$meta])*
        #[derive(ZeroizeOnDrop)]
        pub struct $name(SymmetricKey);

        impl $name {
            /// Generate a fresh random key for this role from the OS CSPRNG.
            #[must_use]
            pub fn generate() -> Self {
                Self(SymmetricKey::generate())
            }

            /// Derive a labelled subkey (HKDF-SHA256); `label` must be
            /// namespaced. See [`SymmetricKey::derive_subkey`].
            ///
            /// # Errors
            /// [`crate::Error::InvalidLabel`] if `label` is outside the namespace.
            pub fn derive_subkey(&self, label: &str) -> Result<SymmetricKey> {
                self.0.derive_subkey(label)
            }

            /// Authenticated-encrypt under this role key. See [`SymmetricKey::seal`].
            ///
            /// # Errors
            /// See [`SymmetricKey::seal`].
            pub fn seal(&self, plaintext: &[u8], aad: &[u8]) -> Result<Envelope> {
                self.0.seal(plaintext, aad)
            }

            /// Verify-and-decrypt under this role key. See [`SymmetricKey::open`].
            ///
            /// # Errors
            /// [`crate::Error::DecryptionFailed`] on any authentication failure.
            pub fn open(&self, envelope: &Envelope, aad: &[u8]) -> Result<Vec<u8>> {
                self.0.open(envelope, aad)
            }

            /// Borrow the underlying untyped [`SymmetricKey`].
            ///
            /// This is the bridge the storage layer (`lp-vault`) uses to feed a
            /// role key into [`wrap_key`](crate::wrap_key) /
            /// [`unwrap_key`](crate::unwrap_key), which operate on the untyped
            /// core. It exposes only the `SymmetricKey` wrapper (still no raw
            /// bytes), so the type-level role protection is intact everywhere
            /// except the single wrap/unwrap seam.
            #[must_use]
            pub fn inner(&self) -> &SymmetricKey {
                &self.0
            }

            /// Re-tag an untyped [`SymmetricKey`] as this role.
            ///
            /// Used after [`unwrap_key`](crate::unwrap_key) yields the untyped
            /// core, to restore the role newtype. The caller asserts the role
            /// by choosing which constructor to call; the purpose binding on
            /// the wrap (see [`wrap`](crate::wrap)) is what actually guards
            /// against a cross-role mistake.
            #[must_use]
            pub fn from_inner(inner: SymmetricKey) -> Self {
                Self(inner)
            }
        }

        impl ConstantTimeEq for $name {
            fn ct_eq(&self, other: &Self) -> subtle::Choice {
                self.0.ct_eq(&other.0)
            }
        }
        impl PartialEq for $name {
            fn eq(&self, other: &Self) -> bool {
                self.ct_eq(other).into()
            }
        }
        impl Eq for $name {}

        impl core::fmt::Debug for $name {
            fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                f.write_str($dbg)
            }
        }
    };
}

role_key!(
    /// **Master Unlock Key** — the top of the hierarchy, derived from the
    /// master password and [`SecretKey`] (see
    /// [`derive_master_unlock_key`](crate::derive_master_unlock_key)). Unwraps
    /// the [`AccountKey`]. Never generated randomly.
    MasterUnlockKey,
    "MasterUnlockKey(<redacted>)"
);
role_key!(
    /// **Account Key** — a random 256-bit key generated once at setup; wrapped
    /// under the MUK. Password rotation only re-wraps it, so it is stable
    /// across password changes (PRD §4.3). Unwraps [`VaultKey`]s.
    AccountKey,
    "AccountKey(<redacted>)"
);
role_key!(
    /// **Vault Key** — per-vault; wrapped under the [`AccountKey`]. Unwraps
    /// [`ItemKey`]s and derives the vault `IndexKey`
    /// (`derive_subkey("localpass/v1/index")`).
    VaultKey,
    "VaultKey(<redacted>)"
);
role_key!(
    /// **Item Key** — per-item (and per-version); wrapped under the
    /// [`VaultKey`]. Encrypts the item payload. Sharing an item re-wraps this
    /// key for the recipient rather than re-encrypting the vault (PRD §4.3).
    ItemKey,
    "ItemKey(<redacted>)"
);

/// A 128-bit locally-generated **Secret Key** (à la 1Password), mixed into the
/// KDF as a second factor (PRD §4.3 / T1, T12).
///
/// An attacker who steals only the vault file must brute-force this 128-bit
/// value *in addition* to the master password — so even a weak password is not
/// offline-crackable from the vault alone. It is stored on-device (OS keychain
/// where available) and printed in the Emergency Kit (PRD §4.11).
///
/// # Human-readable form
///
/// [`to_display_string`](Self::to_display_string) renders a versioned,
/// checksummed, dash-grouped Crockford-base32 string (prefix `LP1-`) suitable
/// for printing and re-typing. [`from_display_string`](Self::from_display_string)
/// round-trips it and rejects any single-character corruption via the
/// checksum. The encoding is a 20-byte payload (`key || crc32(key)`) rendered
/// as 32 Crockford base32 symbols; see the crate source for full details.
///
/// # Hygiene
///
/// Zeroized on drop; redacting `Debug`; constant-time equality; not `Clone`,
/// not `Serialize`.
#[derive(ZeroizeOnDrop)]
pub struct SecretKey {
    bytes: [u8; SECRET_KEY_LEN],
}

impl SecretKey {
    /// Generate a fresh random 128-bit Secret Key from the OS CSPRNG.
    #[must_use]
    pub fn generate() -> Self {
        let mut bytes = [0u8; SECRET_KEY_LEN];
        OsRng.fill_bytes(&mut bytes);
        Self { bytes }
    }

    /// Construct from raw 16 bytes. Crate-internal: public construction is via
    /// `generate` or `from_display_string` so provenance is always defined.
    pub(crate) fn from_bytes(bytes: [u8; SECRET_KEY_LEN]) -> Self {
        Self { bytes }
    }

    /// Borrow the raw 16 key bytes. Crate-internal (consumed by the KDF and the
    /// display encoder only).
    pub(crate) fn as_bytes(&self) -> &[u8; SECRET_KEY_LEN] {
        &self.bytes
    }

    /// Render the versioned, checksummed, human-typable display string
    /// (`LP1-XXXXX-...`). Round-trips with
    /// [`from_display_string`](Self::from_display_string).
    #[must_use]
    pub fn to_display_string(&self) -> String {
        crate::secretkey::encode(&self.bytes)
    }

    /// Parse a display string produced by
    /// [`to_display_string`](Self::to_display_string).
    ///
    /// Dashes and case are ignored; the checksum is verified, so any
    /// single-character substitution is rejected.
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error::InvalidSecretKeyEncoding`] for a wrong prefix,
    /// an out-of-alphabet character, a wrong decoded length, or a failed
    /// checksum.
    pub fn from_display_string(s: &str) -> Result<Self> {
        let bytes = crate::secretkey::decode(s)?;
        Ok(Self::from_bytes(bytes))
    }
}

impl core::fmt::Debug for SecretKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("SecretKey(<redacted 16 bytes>)")
    }
}

impl ConstantTimeEq for SecretKey {
    fn ct_eq(&self, other: &Self) -> subtle::Choice {
        self.bytes.ct_eq(&other.bytes)
    }
}
impl PartialEq for SecretKey {
    fn eq(&self, other: &Self) -> bool {
        self.ct_eq(other).into()
    }
}
impl Eq for SecretKey {}

// The derive macro needs `Zeroize` in scope; the struct fields are all arrays
// of `u8`, which implement it. Explicitly assert the manual-zeroize contract in
// case a field type ever changes to something without `Zeroize`.
const _: fn() = || {
    fn assert_zeroize<T: Zeroize>() {}
    assert_zeroize::<[u8; SYMMETRIC_KEY_LEN]>();
    assert_zeroize::<[u8; SECRET_KEY_LEN]>();
};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_redacts_all_secret_types() {
        // No Debug impl may ever print raw key bytes.
        let sym = SymmetricKey::generate();
        let muk = MasterUnlockKey::generate();
        let account = AccountKey::generate();
        let vault = VaultKey::generate();
        let item = ItemKey::generate();
        let secret = SecretKey::generate();

        assert_eq!(format!("{sym:?}"), "SymmetricKey(<redacted 32 bytes>)");
        assert_eq!(format!("{muk:?}"), "MasterUnlockKey(<redacted>)");
        assert_eq!(format!("{account:?}"), "AccountKey(<redacted>)");
        assert_eq!(format!("{vault:?}"), "VaultKey(<redacted>)");
        assert_eq!(format!("{item:?}"), "ItemKey(<redacted>)");
        assert_eq!(format!("{secret:?}"), "SecretKey(<redacted 16 bytes>)");
    }

    #[test]
    fn constant_time_equality_matches_value_equality() {
        let a = SymmetricKey::from_bytes([1u8; SYMMETRIC_KEY_LEN]);
        let b = SymmetricKey::from_bytes([1u8; SYMMETRIC_KEY_LEN]);
        let c = SymmetricKey::from_bytes([2u8; SYMMETRIC_KEY_LEN]);
        assert_eq!(a, b);
        assert_ne!(a, c);
    }

    #[test]
    fn roles_are_distinct_types_but_share_the_core() {
        // A subkey derived from a VaultKey equals the same derivation done
        // through its inner SymmetricKey — confirming the newtype is a thin,
        // faithful wrapper (and exercising `inner`).
        let vault = VaultKey::generate();
        let via_role = vault.derive_subkey("localpass/v1/index").unwrap();
        let via_core = vault.inner().derive_subkey("localpass/v1/index").unwrap();
        assert_eq!(via_role, via_core);
    }

    #[test]
    fn generate_produces_distinct_keys() {
        // Overwhelmingly likely to differ; a 1-in-2^256 collision is negligible.
        assert_ne!(SymmetricKey::generate(), SymmetricKey::generate());
    }
}
