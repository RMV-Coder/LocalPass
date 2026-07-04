//! Digital signatures: Ed25519 with mandatory, length-prefixed context.
//!
//! Signatures authenticate sync-log operations, membership changes, and release
//! metadata (PRD §5.2). Ed25519 is chosen partly for SSH-key interop: a user's
//! existing Ed25519 SSH key can serve as a trust anchor.
//!
//! # Domain separation via a mandatory context
//!
//! Every [`sign`](SigningKeyPair::sign) / [`verify`](VerifyingKey::verify)
//! takes a **namespaced `context` string** (e.g. `localpass/v1/sign/sync-op`).
//! A signature made under one context will **not** verify under another. This
//! stops cross-protocol signature reuse: a signature over a sync-log op can
//! never be replayed as, say, a membership-change approval.
//!
//! # Unambiguous incorporation (length-prefixed framing)
//!
//! The context and message are combined into the signed payload as:
//!
//! ```text
//!   signed_payload = LE_u64(context.len()) || context || message
//! ```
//!
//! The 8-byte little-endian length prefix makes the framing **injective**:
//! there is exactly one `(context, message)` pair for any signed byte string,
//! so an attacker cannot shift bytes between the context and the message to
//! forge a different-but-colliding interpretation (the classic
//! concatenation-ambiguity attack). We prepend the length rather than using a
//! separator so no escaping is ever needed.
//!
//! Ed25519 signs the whole framed payload; the context is *not* transmitted
//! inside the signature and must be supplied identically at verify time.

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey as DalekVerifyingKey};

use crate::error::{Error, Result};
use crate::kdf::check_label;

/// Length of an Ed25519 signature, in bytes.
pub const SIGNATURE_LEN: usize = 64;
/// Length of an Ed25519 public (verifying) key, in bytes.
pub const VERIFYING_KEY_LEN: usize = 32;

/// Suggested signing context for a sync-log operation.
pub const CONTEXT_SYNC_OP: &str = "localpass/v1/sign/sync-op";
/// Suggested signing context for a membership-change operation.
pub const CONTEXT_MEMBERSHIP: &str = "localpass/v1/sign/membership";
/// Suggested signing context for release metadata.
pub const CONTEXT_RELEASE: &str = "localpass/v1/sign/release";

/// Frame `(context, message)` into the injective signed payload.
///
/// `LE_u64(context.len()) || context || message`. Requires `context` to be
/// namespaced.
fn framed_payload(context: &str, message: &[u8]) -> Result<Vec<u8>> {
    let context = check_label(context)?;
    let clen = context.len() as u64;
    let mut payload = Vec::with_capacity(8 + context.len() + message.len());
    payload.extend_from_slice(&clen.to_le_bytes());
    payload.extend_from_slice(context.as_bytes());
    payload.extend_from_slice(message);
    Ok(payload)
}

/// An Ed25519 signing keypair. The secret scalar is zeroized on drop.
///
/// `SigningKey` (from `ed25519-dalek`, built with the `zeroize` feature) wipes
/// its secret on drop. We do not implement `Clone` (private keys should not be
/// duplicated) or `Serialize`.
pub struct SigningKeyPair {
    signing_key: SigningKey,
}

impl SigningKeyPair {
    /// Generate a fresh signing keypair from the OS CSPRNG.
    #[must_use]
    pub fn generate() -> Self {
        let signing_key = SigningKey::generate(&mut rand_core::OsRng);
        Self { signing_key }
    }

    /// The public verifying key, for handing to verifiers.
    #[must_use]
    pub fn verifying_key(&self) -> VerifyingKey {
        VerifyingKey(self.signing_key.verifying_key())
    }

    /// Sign `message` under the namespaced domain-separation `context`.
    ///
    /// Returns the 64-byte Ed25519 signature over the framed payload (see
    /// [module docs](self)).
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidLabel`] if `context` is outside the namespace.
    pub fn sign(&self, context: &str, message: &[u8]) -> Result<[u8; SIGNATURE_LEN]> {
        let payload = framed_payload(context, message)?;
        let sig: Signature = self.signing_key.sign(&payload);
        Ok(sig.to_bytes())
    }

    /// Export the 32-byte secret seed — for **encrypted persistence only**.
    ///
    /// Exists solely so the storage layer can persist the device identity
    /// wrapped under the AccountKey (vault-format.md §2) and reconstruct it at
    /// unlock via [`SigningKeyPair::from_seed`]. The returned buffer zeroizes
    /// on drop; callers must encrypt it immediately and never write it to
    /// disk, logs, or any other sink in plaintext.
    #[must_use]
    pub fn secret_seed(&self) -> zeroize::Zeroizing<[u8; 32]> {
        zeroize::Zeroizing::new(self.signing_key.to_bytes())
    }

    /// Reconstruct a keypair from a previously exported 32-byte seed.
    ///
    /// Deterministic: the same seed always yields the same keypair (and thus
    /// the same [`VerifyingKey`]).
    #[must_use]
    pub fn from_seed(seed: &[u8; 32]) -> Self {
        Self {
            signing_key: SigningKey::from_bytes(seed),
        }
    }
}

impl core::fmt::Debug for SigningKeyPair {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("SigningKeyPair(<redacted>)")
    }
}

/// An Ed25519 public verifying key. Not secret.
#[derive(Clone)]
pub struct VerifyingKey(DalekVerifyingKey);

impl VerifyingKey {
    /// The 32 raw public-key bytes (safe to serialize / transmit).
    #[must_use]
    pub fn to_bytes(&self) -> [u8; VERIFYING_KEY_LEN] {
        self.0.to_bytes()
    }

    /// Reconstruct from 32 raw bytes.
    ///
    /// # Errors
    ///
    /// Returns [`Error::MalformedEnvelope`] if the bytes are not a valid
    /// Ed25519 point encoding.
    pub fn from_bytes(bytes: &[u8; VERIFYING_KEY_LEN]) -> Result<Self> {
        DalekVerifyingKey::from_bytes(bytes)
            .map(VerifyingKey)
            .map_err(|_| Error::MalformedEnvelope("invalid Ed25519 verifying key"))
    }

    /// Verify `signature` over `message` under the namespaced `context`.
    ///
    /// # Errors
    ///
    /// - [`Error::InvalidLabel`] if `context` is outside the namespace.
    /// - [`Error::DecryptionFailed`] if the signature is invalid for this key,
    ///   message, or context. (All verification failures collapse to the single
    ///   opaque variant; a signature valid under a *different* context is a
    ///   verification failure here.)
    pub fn verify(
        &self,
        context: &str,
        message: &[u8],
        signature: &[u8; SIGNATURE_LEN],
    ) -> Result<()> {
        let payload = framed_payload(context, message)?;
        let sig = Signature::from_bytes(signature);
        self.0
            .verify(&payload, &sig)
            .map_err(|_| Error::DecryptionFailed)
    }
}

impl core::fmt::Debug for VerifyingKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("VerifyingKey(..)")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seed_roundtrip_reconstructs_identity() {
        let original = SigningKeyPair::generate();
        let restored = SigningKeyPair::from_seed(&original.secret_seed());
        assert_eq!(
            original.verifying_key().to_bytes(),
            restored.verifying_key().to_bytes()
        );
        // Signatures from the restored pair verify under the original public key.
        let sig = restored.sign(CONTEXT_SYNC_OP, b"msg").unwrap();
        original
            .verifying_key()
            .verify(CONTEXT_SYNC_OP, b"msg", &sig)
            .unwrap();
    }
}
