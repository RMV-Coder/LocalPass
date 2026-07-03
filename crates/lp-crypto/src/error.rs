//! The crate's single error type.
//!
//! # Oracle-resistance
//!
//! Every failure that could otherwise reveal *why* a decryption failed —
//! wrong key, tampered ciphertext, bad tag, wrong AAD, wrong recipient,
//! wrong wrap purpose — collapses into one opaque [`Error::DecryptionFailed`]
//! variant. Callers (and, more importantly, attackers observing error
//! behaviour) cannot distinguish these cases. This denies padding-oracle /
//! authentication-oracle style side channels: an attacker probing with
//! mutated ciphertexts learns nothing beyond "did not authenticate".
//!
//! Failures that occur *before* any secret-dependent processing — a malformed
//! outer byte layout, an unknown version byte, a truncated buffer — are safe
//! to distinguish and surface as [`Error::MalformedEnvelope`], because they
//! depend only on attacker-supplied structure, not on secret key material.
//!
//! Label-namespace violations are a *programming* error (a caller passed a
//! label outside the `localpass/v1/` namespace) and get their own
//! [`Error::InvalidLabel`] variant so the mistake is loud during development.

use core::fmt;

/// Errors returned by `lp-crypto`.
///
/// This is deliberately small. See the [module docs](self) for the
/// oracle-resistance rationale behind collapsing all authentication failures
/// into a single variant.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// Authenticated decryption failed.
    ///
    /// This single variant covers *all* secret-dependent failure modes: wrong
    /// key, tampered ciphertext or tag, wrong AAD, wrong X25519 recipient,
    /// wrong key-wrap purpose. It carries no detail by design — see the
    /// [module docs](self).
    #[error("decryption failed")]
    DecryptionFailed,

    /// The outer byte layout could not be parsed.
    ///
    /// Raised only for structural problems visible without any secret: an
    /// unknown or unsupported version byte, a buffer too short to contain the
    /// mandatory fields, or an otherwise malformed wire encoding. Safe to
    /// distinguish from [`Error::DecryptionFailed`] because it depends only on
    /// attacker-supplied structure.
    #[error("malformed envelope: {0}")]
    MalformedEnvelope(&'static str),

    /// A derivation or purpose label fell outside the `localpass/v1/`
    /// namespace, or was otherwise unusable.
    ///
    /// This is a caller/programming error, kept distinct so it surfaces
    /// loudly during development rather than hiding inside a generic failure.
    #[error("invalid label: {0}")]
    InvalidLabel(&'static str),

    /// A supplied [`crate::KdfParams`] value was out of range or
    /// self-inconsistent (e.g. zero lanes, or an unparseable serialization).
    #[error("invalid KDF parameters: {0}")]
    InvalidKdfParams(&'static str),

    /// A human-readable [`crate::SecretKey`] display string failed to decode:
    /// wrong prefix, bad alphabet, wrong length, or a failed checksum
    /// (including any single-character corruption).
    #[error("invalid secret-key encoding: {0}")]
    InvalidSecretKeyEncoding(&'static str),

    /// A supplied public key was cryptographically unusable — e.g. an X25519
    /// point in the low-order subgroup, which would force a non-contributory
    /// (attacker-known) shared secret.
    ///
    /// Raised only on the *sealing* side, where the key is caller-supplied
    /// input; on the opening side the same condition collapses into
    /// [`Error::DecryptionFailed`] like every other authentication failure.
    #[error("invalid public key: {0}")]
    InvalidPublicKey(&'static str),
}

/// Convenience alias for `Result<T, `[`Error`]`>`.
pub type Result<T> = core::result::Result<T, Error>;

impl Error {
    /// Internal helper: map *any* underlying AEAD/authentication failure onto
    /// the single opaque [`Error::DecryptionFailed`] variant.
    ///
    /// Centralising this guarantees no call site accidentally leaks a more
    /// specific error kind from a primitive crate.
    #[inline]
    pub(crate) fn from_aead<E: fmt::Debug>(_e: E) -> Self {
        Error::DecryptionFailed
    }
}
