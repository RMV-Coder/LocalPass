//! Key wrapping: encrypt one symmetric key under another, bound to a purpose.
//!
//! Wrapping is how the hierarchy is stored (PRD §4.3): the AccountKey is
//! wrapped under the MUK, each VaultKey under the AccountKey, each ItemKey
//! under its VaultKey. Sharing re-wraps an ItemKey for a recipient rather than
//! re-encrypting the vault.
//!
//! # Purpose binding (mandatory)
//!
//! Every wrap carries a **namespaced `purpose` label** that is bound into the
//! AEAD as Additional Authenticated Data. Unwrapping *must* present the same
//! purpose or authentication fails. This prevents key-confusion: a blob that
//! wraps a VaultKey (purpose `localpass/v1/wrap/vault-key`) will **not** unwrap
//! if a caller asks for it as an ItemKey (purpose
//! `localpass/v1/wrap/item-key`) — the AAD mismatch collapses to
//! [`DecryptionFailed`](crate::Error::DecryptionFailed).
//!
//! Because the purpose is bound out-of-band as AAD (never serialized into the
//! [`Envelope`]), it costs nothing on the wire and cannot be silently rewritten
//! by an attacker who only has the ciphertext.
//!
//! The wrapped output is exactly an [`Envelope`] over the 32 raw key bytes; its
//! `to_bytes()` / `from_bytes()` give the storable form.

use crate::envelope::Envelope;
use crate::error::Result;
use crate::kdf::check_label;
use crate::keys::{SYMMETRIC_KEY_LEN, SymmetricKey};

/// Suggested purpose label for wrapping an AccountKey under the MUK.
pub const PURPOSE_ACCOUNT_KEY: &str = "localpass/v1/wrap/account-key";
/// Suggested purpose label for wrapping a VaultKey under an AccountKey.
pub const PURPOSE_VAULT_KEY: &str = "localpass/v1/wrap/vault-key";
/// Suggested purpose label for wrapping an ItemKey under a VaultKey.
pub const PURPOSE_ITEM_KEY: &str = "localpass/v1/wrap/item-key";

/// Wrap `target` under `wrapping_key`, binding `purpose` as AAD.
///
/// Returns an [`Envelope`] whose plaintext is the 32 raw bytes of `target`.
/// Serialize it with [`Envelope::to_bytes`] to store on disk.
///
/// # Errors
///
/// Returns [`crate::Error::InvalidLabel`] if `purpose` is outside the
/// `localpass/v1/` namespace. AEAD encryption is otherwise infallible for
/// in-memory data.
pub fn wrap_key(
    wrapping_key: &SymmetricKey,
    target: &SymmetricKey,
    purpose: &str,
) -> Result<Envelope> {
    let purpose = check_label(purpose)?;
    wrapping_key.seal(target.as_bytes(), purpose.as_bytes())
}

/// Unwrap an [`Envelope`] produced by [`wrap_key`], requiring the same `purpose`.
///
/// # Errors
///
/// - [`crate::Error::InvalidLabel`] if `purpose` is outside the namespace.
/// - [`crate::Error::DecryptionFailed`] if the wrapping key is wrong, the bytes
///   were tampered, **or the purpose does not match** the one used to wrap.
/// - [`crate::Error::MalformedEnvelope`] if the unwrapped plaintext is not
///   exactly [`SYMMETRIC_KEY_LEN`] bytes (a well-formed key wrap always is).
pub fn unwrap_key(
    wrapping_key: &SymmetricKey,
    envelope: &Envelope,
    purpose: &str,
) -> Result<SymmetricKey> {
    let purpose = check_label(purpose)?;
    let mut plaintext = wrapping_key.open(envelope, purpose.as_bytes())?;

    let bytes: [u8; SYMMETRIC_KEY_LEN] = plaintext
        .as_slice()
        .try_into()
        .map_err(|_| crate::Error::MalformedEnvelope("unwrapped key had unexpected length"))?;
    // Wipe the heap copy of the key bytes; `bytes` (the array) becomes the key.
    use zeroize::Zeroize;
    plaintext.zeroize();
    Ok(SymmetricKey::from_bytes(bytes))
}
