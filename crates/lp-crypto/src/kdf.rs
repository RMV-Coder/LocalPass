//! HKDF-SHA256 helpers with mandatory label namespacing.
//!
//! Every key-derivation and every purpose binding in LocalPass is
//! *domain-separated* by a label. The [fixed contract](crate) requires that
//! **every** label start with the namespace prefix `localpass/v1/`. This is
//! enforced at runtime here ([`check_label`]); a label outside the namespace
//! is a programming error and yields [`Error::InvalidLabel`].
//!
//! Why namespacing matters: HKDF's `info` parameter is the only thing that
//! separates one derived key from another when the input keying material is
//! shared. Forcing a versioned, collision-resistant prefix guarantees that
//! (a) two different purposes can never accidentally derive the same key, and
//! (b) a future format version can rotate the whole namespace at once
//! (`localpass/v2/...`) without silent overlap — crypto agility via versioned
//! labels, not runtime negotiation (PRD §5.1).

use hkdf::Hkdf;
use sha2::Sha256;

use crate::error::{Error, Result};

/// The mandatory namespace prefix for every derivation / purpose label.
///
/// See the [module docs](self) and the crate-level fixed-contract notes.
pub const LABEL_NAMESPACE: &str = "localpass/v1/";

/// Validate that `label` is inside the `localpass/v1/` namespace.
///
/// Returns the label unchanged on success so it can be used inline:
///
/// ```
/// # use lp_crypto::kdf::check_label;
/// let l = check_label("localpass/v1/muk").unwrap();
/// assert_eq!(l, "localpass/v1/muk");
/// assert!(check_label("muk").is_err());
/// assert!(check_label("localpass/v1/").is_err()); // prefix only, no purpose
/// ```
///
/// # Errors
///
/// Returns [`Error::InvalidLabel`] if the label does not start with
/// [`LABEL_NAMESPACE`], or if it is exactly the bare prefix with no purpose
/// suffix (an empty purpose is never meaningful).
pub fn check_label(label: &str) -> Result<&str> {
    match label.strip_prefix(LABEL_NAMESPACE) {
        Some("") => Err(Error::InvalidLabel(
            "label must include a purpose after the `localpass/v1/` prefix",
        )),
        Some(_) => Ok(label),
        None => Err(Error::InvalidLabel(
            "label must start with the `localpass/v1/` namespace",
        )),
    }
}

/// HKDF-SHA256 Extract-then-Expand into a fixed 32-byte output.
///
/// - `salt`  → HKDF *salt* (the "extract" salt; may be empty).
/// - `ikm`   → input keying material (the secret being stretched/mixed).
/// - `label` → HKDF *info* (domain separation); **must** be namespaced.
///
/// This is the single choke point for all 32-byte key derivations in the
/// crate, so the namespace check cannot be bypassed.
///
/// # Errors
///
/// Returns [`Error::InvalidLabel`] if `label` is outside the namespace.
pub(crate) fn hkdf_sha256_32(salt: &[u8], ikm: &[u8], label: &str) -> Result<[u8; 32]> {
    hkdf_sha256_32_transcript(salt, ikm, label, &[])
}

/// Like [`hkdf_sha256_32`], but appends fixed-width `transcript` bytes to the
/// HKDF `info` after the validated namespaced `label`.
///
/// The full info is `label_bytes || transcript`. The `label` is still required
/// to be namespaced (the namespace guarantee holds because the label is a
/// *prefix* of the info), while `transcript` carries raw, non-UTF-8 material
/// such as X25519 public keys. Used by the asymmetric [`seal`](crate::seal)
/// construction to bind both public keys into the derived key.
///
/// # Errors
///
/// Returns [`Error::InvalidLabel`] if `label` is outside the namespace.
pub(crate) fn hkdf_sha256_32_transcript(
    salt: &[u8],
    ikm: &[u8],
    label: &str,
    transcript: &[u8],
) -> Result<[u8; 32]> {
    let label = check_label(label)?;
    let hk = Hkdf::<Sha256>::new(Some(salt), ikm);

    let mut info = Vec::with_capacity(label.len() + transcript.len());
    info.extend_from_slice(label.as_bytes());
    info.extend_from_slice(transcript);

    let mut okm = [0u8; 32];
    // `expand` only fails when the requested length exceeds 255*HashLen; 32 is
    // far below that bound for SHA-256, so this cannot fail in practice.
    hk.expand(&info, &mut okm)
        .expect("HKDF-SHA256 expand of 32 bytes is always within bounds");
    Ok(okm)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_namespaced_labels() {
        assert!(check_label("localpass/v1/muk").is_ok());
        assert!(check_label("localpass/v1/index").is_ok());
        assert!(check_label("localpass/v1/wrap/vault-key").is_ok());
    }

    #[test]
    fn rejects_non_namespaced_labels() {
        assert!(matches!(check_label("muk"), Err(Error::InvalidLabel(_))));
        assert!(matches!(check_label(""), Err(Error::InvalidLabel(_))));
        assert!(matches!(
            check_label("localpass/v2/muk"),
            Err(Error::InvalidLabel(_))
        ));
        // Bare prefix with no purpose is rejected.
        assert!(matches!(
            check_label("localpass/v1/"),
            Err(Error::InvalidLabel(_))
        ));
    }

    #[test]
    fn distinct_labels_yield_distinct_keys() {
        let ikm = [42u8; 32];
        let a = hkdf_sha256_32(&[], &ikm, "localpass/v1/a").unwrap();
        let b = hkdf_sha256_32(&[], &ikm, "localpass/v1/b").unwrap();
        assert_ne!(a, b);
        // Deterministic for the same label.
        let a2 = hkdf_sha256_32(&[], &ikm, "localpass/v1/a").unwrap();
        assert_eq!(a, a2);
    }

    #[test]
    fn transcript_affects_output() {
        let ikm = [7u8; 32];
        let x = hkdf_sha256_32_transcript(&[], &ikm, "localpass/v1/seal", b"AAAA").unwrap();
        let y = hkdf_sha256_32_transcript(&[], &ikm, "localpass/v1/seal", b"BBBB").unwrap();
        assert_ne!(x, y);
    }
}
