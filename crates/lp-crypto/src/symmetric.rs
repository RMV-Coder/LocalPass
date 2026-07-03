//! The XChaCha20-Poly1305 primitive wrapper.
//!
//! This is the single implementation of authenticated encryption in the crate.
//! Everything else — [`SymmetricKey::seal`](crate::SymmetricKey::seal), key
//! wrapping, and asymmetric sealing — funnels through [`seal`] / [`open`] here,
//! so there is exactly one place that touches nonces and tags.
//!
//! See [`crate::envelope`] for the wire layout these functions produce and
//! consume.

use chacha20poly1305::aead::{Aead, Payload};
use chacha20poly1305::{KeyInit, XChaCha20Poly1305, XNonce};
use rand_core::{OsRng, RngCore};

use crate::envelope::{Envelope, NONCE_LEN};
use crate::error::{Error, Result};
use crate::keys::SYMMETRIC_KEY_LEN;

/// Encrypt `plaintext` under `key`, binding `aad`, with a fresh random nonce.
///
/// Returns an [`Envelope`] holding the drawn nonce and the ciphertext+tag. The
/// nonce comes from the OS CSPRNG on every call; XChaCha's 192-bit nonce makes
/// random selection collision-safe at scale (PRD §5.2).
///
/// # Errors
///
/// Returns [`Error::DecryptionFailed`] (used here as a generic AEAD-failure
/// signal) only if the backend reports an internal encrypt error; this does
/// not happen for well-formed in-memory inputs.
pub(crate) fn seal(
    key: &[u8; SYMMETRIC_KEY_LEN],
    plaintext: &[u8],
    aad: &[u8],
) -> Result<Envelope> {
    let cipher = XChaCha20Poly1305::new(key.into());

    let mut nonce_bytes = [0u8; NONCE_LEN];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = XNonce::from_slice(&nonce_bytes);

    let ciphertext = cipher
        .encrypt(
            nonce,
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(Error::from_aead)?;

    Ok(Envelope::from_parts(nonce_bytes, ciphertext))
}

/// Verify and decrypt `envelope` under `key` with the given `aad`.
///
/// # Errors
///
/// Returns [`Error::DecryptionFailed`] for any authentication failure — wrong
/// key, tampered ciphertext/tag, or mismatched `aad` — indistinguishably
/// (oracle-resistance, see [`crate::error`]).
pub(crate) fn open(
    key: &[u8; SYMMETRIC_KEY_LEN],
    envelope: &Envelope,
    aad: &[u8],
) -> Result<Vec<u8>> {
    let cipher = XChaCha20Poly1305::new(key.into());
    let nonce = XNonce::from_slice(envelope.nonce());

    cipher
        .decrypt(
            nonce,
            Payload {
                msg: envelope.ciphertext(),
                aad,
            },
        )
        .map_err(Error::from_aead)
}
