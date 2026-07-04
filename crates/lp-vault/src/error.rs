//! The crate's single error type.
//!
//! # No secret leakage
//!
//! No variant carries decrypted plaintext, key material, passwords, or the
//! Secret Key. Cryptographic failures (wrong password, wrong Secret Key,
//! tampered ciphertext, AAD mismatch) all arrive from `lp-crypto` as
//! [`lp_crypto::Error::DecryptionFailed`] and are surfaced here as
//! [`Error::DecryptionFailed`] — the same opaque, oracle-resistant collapse the
//! crypto layer performs (`lp-crypto` `error` module). Structural crypto errors
//! (malformed envelope, invalid label) are preserved as [`Error::Crypto`] but
//! still carry no secret payload, because `lp-crypto`'s own error type never
//! does.

/// Errors returned by `lp-vault`.
///
/// Constructed so that a `Display`/`Debug` render never reveals a secret: item
/// payloads, key bytes, passwords, and the Secret Key are absent from every
/// variant. See the [module docs](self) for the oracle-resistance rationale.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// Authenticated decryption or key-unwrap failed.
    ///
    /// This is the single opaque variant that all secret-dependent failures
    /// collapse to: a wrong master password or Secret Key at unlock, a tampered
    /// or relocated ciphertext blob (AAD mismatch), or a corrupted wrapped key.
    /// It carries no detail by design — mirroring `lp-crypto`'s oracle-resistant
    /// [`DecryptionFailed`](lp_crypto::Error::DecryptionFailed).
    #[error("decryption failed")]
    DecryptionFailed,

    /// A structural cryptographic error from `lp-crypto` that is *not* a
    /// secret-dependent authentication failure (e.g. a malformed envelope or an
    /// out-of-namespace label). Never carries plaintext or key material.
    #[error("crypto error: {0}")]
    Crypto(#[from] lp_crypto::Error),

    /// An underlying SQLite / `rusqlite` error.
    ///
    /// Row-level SQL error text can name columns and constraints but never a
    /// decrypted value (all secret columns store ciphertext blobs only).
    #[error("storage error: {0}")]
    Sqlite(#[from] rusqlite::Error),

    /// A filesystem error while creating or permissioning a store/vault file.
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    /// The requested account store, vault, item, version, or folder does not
    /// exist. The message names only the kind of missing entity, never its
    /// decrypted contents.
    #[error("not found: {0}")]
    NotFound(&'static str),

    /// A logical/usage error: e.g. an item is already deleted, a version number
    /// is out of range, or a store already exists where `create` was asked to
    /// make a fresh one. Carries a static, secret-free description.
    #[error("invalid operation: {0}")]
    Invalid(&'static str),

    /// The on-disk format version is newer than this build supports; the file
    /// must not be opened (vault-format.md §9 downgrade resistance).
    #[error("unsupported format version {found} (this build supports {supported})")]
    UnsupportedFormat {
        /// The `format_version` read from the file.
        found: i64,
        /// The highest `format_version` this build understands.
        supported: i64,
    },

    /// Op-log hash-chain, sequence, or signature verification failed
    /// (sync-protocol.md §5). Raised by
    /// [`Vault::verify_local_chain`](crate::Vault::verify_local_chain).
    #[error("op-chain verification failed: {0}")]
    ChainVerification(&'static str),

    /// A stored JSON payload or wire structure failed to (de)serialize. Carries
    /// only the serde message shape, which for our ciphertext-at-rest model is
    /// reached only on a decrypted-but-corrupt payload — no plaintext secret is
    /// embedded (the serde error names JSON structure, not field values we
    /// deliberately format in).
    #[error("serialization error: {0}")]
    Serialization(String),
}

impl From<serde_json::Error> for Error {
    fn from(e: serde_json::Error) -> Self {
        // serde_json error Display includes a line/column and a category, not the
        // offending value bytes; safe to surface without leaking a secret.
        Error::Serialization(e.to_string())
    }
}

impl Error {
    /// Map an `lp-crypto` error, collapsing its opaque authentication failure to
    /// our [`Error::DecryptionFailed`] and preserving structural errors as
    /// [`Error::Crypto`].
    #[must_use]
    pub(crate) fn from_crypto(e: lp_crypto::Error) -> Self {
        match e {
            lp_crypto::Error::DecryptionFailed => Error::DecryptionFailed,
            other => Error::Crypto(other),
        }
    }
}

/// Convenience alias for `Result<T, `[`Error`]`>`.
pub type Result<T> = core::result::Result<T, Error>;
