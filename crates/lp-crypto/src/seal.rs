//! Asymmetric sealing: encrypt to an X25519 recipient public key (age-style).
//!
//! This is the "seal a secret for a recipient" primitive behind device pairing
//! and team sharing (PRD §5.2, the age recipient model). The sender needs only
//! the recipient's **public** key; only the holder of the matching private key
//! can open the result.
//!
//! # Construction (ephemeral-static ECDH)
//!
//! For each `seal_for` call the sender generates a fresh **ephemeral** X25519
//! keypair, performs ECDH against the recipient's **static** public key, and
//! derives a one-time symmetric key from the shared secret:
//!
//! ```text
//!   e            = ephemeral X25519 keypair          (fresh per message)
//!   shared       = X25519(e_secret, recipient_pk)
//!   sym          = HKDF-SHA256(
//!                      ikm  = shared,
//!                      salt = <empty>,
//!                      info = "localpass/v1/seal" || ephemeral_pk || recipient_pk,
//!                  )
//!   inner        = XChaCha20Poly1305(sym).seal(plaintext, aad)   // an Envelope
//!   output       = 0x01 || ephemeral_pk(32) || inner.to_bytes()
//! ```
//!
//! # Transcript binding
//!
//! Both public keys — ephemeral and recipient — are folded into the HKDF `info`
//! ("transcript"). This binds the derived key to the exact pair of parties, so
//! a captured `ephemeral_pk` cannot be spliced onto a ciphertext sealed for a
//! different recipient, and key-reuse across recipients cannot collide. HKDF's
//! `info` is namespaced (`localpass/v1/seal`) like every other derivation.
//!
//! The recipient recomputes the identical shared secret with
//! `X25519(recipient_secret, ephemeral_pk)` (ECDH symmetry) and the same
//! transcript, then opens the inner [`Envelope`]. A wrong recipient derives a
//! different `sym` and authentication fails — indistinguishably, as
//! [`DecryptionFailed`](crate::Error::DecryptionFailed).
//!
//! # Wire layout (v1)
//!
//! ```text
//! 0x01 || ephemeral_pk(32) || <Envelope bytes>
//! ```
//!
//! The `aad` is carried out of band exactly as for the symmetric envelope.

use x25519_dalek::{EphemeralSecret, PublicKey, StaticSecret};
use zeroize::Zeroize;

use crate::envelope::Envelope;
use crate::error::{Error, Result};
use crate::keys::{SYMMETRIC_KEY_LEN, SymmetricKey};
use crate::symmetric;

/// The HKDF domain-separation label for asymmetric sealing (fixed contract).
const SEAL_LABEL: &str = "localpass/v1/seal";

/// Version byte prefixing a sealed message.
const SEAL_VERSION: u8 = 0x01;

/// Length of an X25519 public key, in bytes.
pub const SEAL_PUBLIC_KEY_LEN: usize = 32;

/// The fixed prefix of a sealed message: version byte + ephemeral public key.
const SEAL_HEADER_LEN: usize = 1 + SEAL_PUBLIC_KEY_LEN;

/// A recipient's public sealing key (X25519). Freely shareable; not secret.
#[derive(Clone)]
pub struct PublicSealingKey(PublicKey);

impl PublicSealingKey {
    /// The 32 raw public-key bytes (safe to serialize / transmit).
    #[must_use]
    pub fn to_bytes(&self) -> [u8; SEAL_PUBLIC_KEY_LEN] {
        *self.0.as_bytes()
    }

    /// Reconstruct from 32 raw bytes.
    #[must_use]
    pub fn from_bytes(bytes: [u8; SEAL_PUBLIC_KEY_LEN]) -> Self {
        Self(PublicKey::from(bytes))
    }
}

impl core::fmt::Debug for PublicSealingKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // Public data, but keep Debug terse and consistent with secret types.
        f.write_str("PublicSealingKey(..)")
    }
}

/// An X25519 sealing keypair. The secret half is zeroized on drop.
///
/// The secret is an X25519 `StaticSecret`, which itself zeroizes on drop; we
/// hold it in a `ZeroizeOnDrop` wrapper and never expose the raw scalar. Not
/// `Clone` (a private key should not be duplicated) and not `Serialize`.
pub struct SealingKeyPair {
    secret: StaticSecret,
    public: PublicSealingKey,
}

impl SealingKeyPair {
    /// Generate a fresh recipient keypair from the OS CSPRNG.
    #[must_use]
    pub fn generate() -> Self {
        let secret = StaticSecret::random_from_rng(rand_core::OsRng);
        let public = PublicSealingKey(PublicKey::from(&secret));
        Self { secret, public }
    }

    /// This keypair's public key, for handing to senders.
    #[must_use]
    pub fn public_key(&self) -> PublicSealingKey {
        self.public.clone()
    }

    /// Open a key-transport blob produced by [`seal_key_for`], returning the
    /// key as a typed [`SymmetricKey`].
    ///
    /// This is the receiving half of cross-device key sharing (PRD §4.5): the
    /// raw key bytes never surface to the caller — the heap plaintext is
    /// zeroized after the typed key is constructed.
    ///
    /// # Errors
    ///
    /// - [`Error::MalformedEnvelope`] if the outer bytes are truncated or carry
    ///   a wrong version byte.
    /// - [`Error::DecryptionFailed`] if this keypair is not the recipient, the
    ///   bytes were tampered, the `aad` differs, or the sealed payload is not
    ///   exactly one key long (collapsed indistinguishably — no oracle).
    pub fn open_key(&self, sealed: &[u8], aad: &[u8]) -> Result<SymmetricKey> {
        let mut plain = self.open(sealed, aad)?;
        if plain.len() != SYMMETRIC_KEY_LEN {
            plain.zeroize();
            return Err(Error::DecryptionFailed);
        }
        let mut arr = [0u8; SYMMETRIC_KEY_LEN];
        arr.copy_from_slice(&plain);
        plain.zeroize();
        Ok(SymmetricKey::from_bytes(arr))
    }

    /// Export the 32-byte X25519 secret — for **encrypted persistence only**.
    ///
    /// Exists solely so the storage layer can persist the device identity
    /// wrapped under the AccountKey (vault-format.md §2) and reconstruct it at
    /// unlock via [`SealingKeyPair::from_secret_bytes`]. The returned buffer
    /// zeroizes on drop; callers must encrypt it immediately and never write
    /// it to disk, logs, or any other sink in plaintext.
    #[must_use]
    pub fn secret_bytes(&self) -> zeroize::Zeroizing<[u8; 32]> {
        zeroize::Zeroizing::new(self.secret.to_bytes())
    }

    /// Reconstruct a keypair from previously exported secret bytes.
    ///
    /// Deterministic: the same bytes always yield the same keypair (and thus
    /// the same [`PublicSealingKey`]).
    #[must_use]
    pub fn from_secret_bytes(bytes: &[u8; 32]) -> Self {
        let secret = StaticSecret::from(*bytes);
        let public = PublicSealingKey(PublicKey::from(&secret));
        Self { secret, public }
    }

    /// Open a message produced by [`seal_for`] addressed to this keypair.
    ///
    /// # Errors
    ///
    /// - [`Error::MalformedEnvelope`] if the outer bytes are truncated or carry
    ///   a wrong version byte.
    /// - [`Error::DecryptionFailed`] if this keypair is not the intended
    ///   recipient, the ciphertext/tag was tampered, or the `aad` differs.
    pub fn open(&self, sealed: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
        let (&version, rest) = sealed
            .split_first()
            .ok_or(Error::MalformedEnvelope("empty sealed message"))?;
        if version != SEAL_VERSION {
            return Err(Error::MalformedEnvelope(
                "unsupported sealed-message version",
            ));
        }
        if rest.len() < SEAL_PUBLIC_KEY_LEN {
            return Err(Error::MalformedEnvelope(
                "truncated: ephemeral key incomplete",
            ));
        }
        let (eph_bytes, envelope_bytes) = rest.split_at(SEAL_PUBLIC_KEY_LEN);
        let mut eph_arr = [0u8; SEAL_PUBLIC_KEY_LEN];
        eph_arr.copy_from_slice(eph_bytes);
        let ephemeral_pk = PublicKey::from(eph_arr);

        // Recompute the shared secret and the transcript-bound symmetric key.
        let shared = self.secret.diffie_hellman(&ephemeral_pk);
        // A low-order ephemeral point ⇒ non-contributory shared secret. On the
        // opening side this collapses into the opaque authentication failure
        // like every other secret-dependent rejection (no oracle).
        if !shared.was_contributory() {
            return Err(Error::DecryptionFailed);
        }
        let mut sym = derive_seal_key(&shared, &eph_arr, self.public.0.as_bytes())?;

        let envelope = Envelope::from_bytes(envelope_bytes)?;
        let result = symmetric::open(&sym, &envelope, aad);
        sym.zeroize();
        result
    }
}

// Note on zeroization: the secret half is an `x25519_dalek::StaticSecret` built
// with the `zeroize` feature, which wipes its scalar on drop. We therefore do
// not add a manual `Drop` — an empty one would be misleading, and a non-empty
// one would risk double-wiping. The public half is not secret.

impl core::fmt::Debug for SealingKeyPair {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("SealingKeyPair { secret: <redacted>, public: .. }")
    }
}

/// Seal `plaintext` for `recipient`, binding `aad`.
///
/// Produces `0x01 || ephemeral_pk(32) || Envelope-bytes` (see [module
/// docs](self)). A fresh ephemeral keypair is used per call, so sealing the
/// same plaintext twice yields unlinkable outputs.
///
/// # Errors
///
/// Effectively infallible for in-memory input; surfaces
/// [`Error::DecryptionFailed`] only on an internal AEAD error.
pub fn seal_for(recipient: &PublicSealingKey, plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
    let ephemeral_secret = EphemeralSecret::random_from_rng(rand_core::OsRng);
    let ephemeral_pk = PublicKey::from(&ephemeral_secret);
    let ephemeral_bytes = *ephemeral_pk.as_bytes();

    let shared = ephemeral_secret.diffie_hellman(&recipient.0);
    // Reject low-order recipient points: a non-contributory ECDH result is an
    // attacker-known all-zero shared secret (RFC 7748 §6.1 guidance).
    if !shared.was_contributory() {
        return Err(Error::InvalidPublicKey("low-order X25519 recipient key"));
    }
    let mut sym = derive_seal_key(&shared, &ephemeral_bytes, recipient.0.as_bytes())?;

    let envelope = symmetric::seal(&sym, plaintext, aad);
    sym.zeroize();
    let envelope = envelope?;

    let inner = envelope.to_bytes();
    let mut out = Vec::with_capacity(SEAL_HEADER_LEN + inner.len());
    out.push(SEAL_VERSION);
    out.extend_from_slice(&ephemeral_bytes);
    out.extend_from_slice(&inner);
    Ok(out)
}

/// Seal a symmetric key to a recipient — the key-transport primitive behind
/// cross-device VaultKey sharing (PRD §4.5).
///
/// This exists so higher layers can move a key between devices without raw
/// key bytes ever crossing the crate's public API: the bytes are read
/// internally and sealed immediately. The receiving side is
/// [`SealingKeyPair::open_key`], which likewise returns a typed key.
///
/// Callers must bind context via `aad` (vault id + recipient device id) so a
/// sealed key cannot be replayed for a different vault or recipient intent.
///
/// # Errors
///
/// [`Error::InvalidPublicKey`] for a low-order recipient point; otherwise
/// effectively infallible for in-memory input.
pub fn seal_key_for(
    recipient: &PublicSealingKey,
    key: &SymmetricKey,
    aad: &[u8],
) -> Result<Vec<u8>> {
    seal_for(recipient, key.as_bytes(), aad)
}

/// Derive the one-time symmetric key from an ECDH shared secret plus the
/// ephemeral/recipient public-key transcript.
///
/// `info = SEAL_LABEL || ephemeral_pk || recipient_pk`, via
/// [`hkdf_sha256_32_transcript`]: the namespaced label is validated as a prefix
/// and the two fixed-width 32-byte public keys follow as an unambiguous
/// transcript. IKM is the ECDH shared secret; the HKDF salt is empty.
fn derive_seal_key(
    shared: &x25519_dalek::SharedSecret,
    ephemeral_pk: &[u8; SEAL_PUBLIC_KEY_LEN],
    recipient_pk: &[u8; SEAL_PUBLIC_KEY_LEN],
) -> Result<[u8; 32]> {
    let mut transcript = [0u8; 2 * SEAL_PUBLIC_KEY_LEN];
    transcript[..SEAL_PUBLIC_KEY_LEN].copy_from_slice(ephemeral_pk);
    transcript[SEAL_PUBLIC_KEY_LEN..].copy_from_slice(recipient_pk);

    crate::kdf::hkdf_sha256_32_transcript(&[], shared.as_bytes(), SEAL_LABEL, &transcript)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The all-zero u-coordinate is a low-order X25519 point; ECDH against it
    /// yields the all-zero (non-contributory) shared secret.
    const LOW_ORDER_PK: [u8; SEAL_PUBLIC_KEY_LEN] = [0u8; SEAL_PUBLIC_KEY_LEN];

    #[test]
    fn sealing_to_low_order_recipient_is_rejected() {
        let recipient = PublicSealingKey::from_bytes(LOW_ORDER_PK);
        let err = seal_for(&recipient, b"secret", b"aad").unwrap_err();
        assert!(matches!(err, Error::InvalidPublicKey(_)));
    }

    #[test]
    fn key_transport_roundtrip_wrong_recipient_and_wrong_length() {
        let recipient = SealingKeyPair::generate();
        let key = SymmetricKey::generate();
        let sealed = seal_key_for(&recipient.public_key(), &key, b"aad").unwrap();

        // Round trip: the typed key comes back equal (constant-time eq).
        let opened = recipient.open_key(&sealed, b"aad").unwrap();
        assert!(opened == key);

        // Wrong recipient and wrong AAD both collapse to DecryptionFailed.
        let other = SealingKeyPair::generate();
        assert!(matches!(
            other.open_key(&sealed, b"aad"),
            Err(Error::DecryptionFailed)
        ));
        assert!(matches!(
            recipient.open_key(&sealed, b"other-aad"),
            Err(Error::DecryptionFailed)
        ));

        // A sealed blob that is not exactly one key long is rejected the same way.
        let not_a_key = seal_for(&recipient.public_key(), b"short", b"aad").unwrap();
        assert!(matches!(
            recipient.open_key(&not_a_key, b"aad"),
            Err(Error::DecryptionFailed)
        ));
    }

    #[test]
    fn secret_bytes_roundtrip_reconstructs_identity() {
        let original = SealingKeyPair::generate();
        let restored = SealingKeyPair::from_secret_bytes(&original.secret_bytes());
        assert_eq!(
            original.public_key().to_bytes(),
            restored.public_key().to_bytes()
        );
        // A message sealed to the original public key opens with the restored pair.
        let sealed = seal_for(&original.public_key(), b"secret", b"aad").unwrap();
        assert_eq!(restored.open(&sealed, b"aad").unwrap(), b"secret");
    }

    #[test]
    fn opening_with_low_order_ephemeral_fails_opaquely() {
        let keypair = SealingKeyPair::generate();
        let mut sealed = seal_for(&keypair.public_key(), b"secret", b"aad").unwrap();
        // Overwrite the ephemeral public key with a low-order point.
        sealed[1..1 + SEAL_PUBLIC_KEY_LEN].copy_from_slice(&LOW_ORDER_PK);
        let err = keypair.open(&sealed, b"aad").unwrap_err();
        assert!(matches!(err, Error::DecryptionFailed));
    }
}
