//! The versioned AEAD envelope: the on-the-wire ciphertext container.
//!
//! # Wire layout (v1 — a fixed cross-crate contract)
//!
//! ```text
//! ┌──────────┬───────────────────┬────────────────────────────┐
//! │ version  │  nonce            │  ciphertext || Poly1305 tag │
//! │ 0x01     │  24 bytes         │  (variable, ≥ 16 bytes)     │
//! │ 1 byte   │  XChaCha20 nonce  │  AEAD output                │
//! └──────────┴───────────────────┴────────────────────────────┘
//! ```
//!
//! Concretely: `0x01 || nonce(24) || ciphertext+tag`, using
//! **XChaCha20-Poly1305**. The 16-byte Poly1305 tag is appended to the
//! ciphertext by the AEAD, so the trailing field is always at least 16 bytes.
//!
//! # AAD is carried out of band
//!
//! The Additional Authenticated Data is **never** serialized into the
//! envelope. It is supplied by the caller at both [`seal`](crate::SymmetricKey::seal)
//! and [`open`](crate::SymmetricKey::open) time and bound into the Poly1305
//! tag. This lets higher layers bind context (item IDs, versions, wrap
//! purposes, transcript hashes) to a ciphertext without paying to store it,
//! and without letting an attacker rewrite that context — a tag computed over
//! one AAD will not verify under another.
//!
//! # Version byte
//!
//! The leading `0x01` is a *format* version, checked before anything else.
//! Crypto agility in LocalPass is by versioned headers, not runtime
//! negotiation (PRD §5.1), so an unknown version is a hard structural error,
//! not a downgrade opportunity.

use crate::error::{Error, Result};

/// Envelope format version byte. The only value accepted by [`Envelope::from_bytes`].
pub const ENVELOPE_VERSION: u8 = 0x01;

/// Length of the XChaCha20-Poly1305 nonce, in bytes (192-bit / XChaCha).
pub const NONCE_LEN: usize = 24;

/// Length of the Poly1305 authentication tag, in bytes.
pub const TAG_LEN: usize = 16;

/// The fixed-size prefix: one version byte plus the nonce.
const HEADER_LEN: usize = 1 + NONCE_LEN;

/// A parsed, self-describing AEAD envelope (v1).
///
/// Holds the random per-message `nonce` and the combined `ciphertext` (which
/// already includes the trailing Poly1305 tag). Construct one via
/// [`SymmetricKey::seal`](crate::SymmetricKey::seal); serialize with
/// [`Envelope::to_bytes`]; parse untrusted bytes with [`Envelope::from_bytes`].
///
/// This struct holds *ciphertext only* — no plaintext and no key — so it is
/// deliberately `Clone`-able and does not need zeroization.
#[derive(Clone)]
pub struct Envelope {
    nonce: [u8; NONCE_LEN],
    /// Ciphertext with the 16-byte Poly1305 tag appended.
    ciphertext: Vec<u8>,
}

impl Envelope {
    /// Assemble an envelope from a nonce and an AEAD ciphertext-with-tag.
    ///
    /// Internal: the ciphertext must already carry the appended tag (i.e. it
    /// is the direct output of the AEAD encrypt). Not exposed publicly because
    /// callers should only ever obtain envelopes from `seal` or `from_bytes`.
    pub(crate) fn from_parts(nonce: [u8; NONCE_LEN], ciphertext: Vec<u8>) -> Self {
        Self { nonce, ciphertext }
    }

    /// The 24-byte XChaCha20 nonce.
    #[must_use]
    pub fn nonce(&self) -> &[u8; NONCE_LEN] {
        &self.nonce
    }

    /// The ciphertext with its appended Poly1305 tag.
    #[must_use]
    pub fn ciphertext(&self) -> &[u8] {
        &self.ciphertext
    }

    /// Serialize to the exact v1 wire layout: `0x01 || nonce(24) || ct+tag`.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(HEADER_LEN + self.ciphertext.len());
        out.push(ENVELOPE_VERSION);
        out.extend_from_slice(&self.nonce);
        out.extend_from_slice(&self.ciphertext);
        out
    }

    /// Parse untrusted bytes into an [`Envelope`], validating structure only.
    ///
    /// This performs **no** cryptographic check — it just enforces the wire
    /// layout so that a later `open` has a well-formed nonce and ciphertext.
    /// All structural rejections are safe to distinguish from authentication
    /// failures (see [`crate::error`]).
    ///
    /// # Errors
    ///
    /// Returns [`Error::MalformedEnvelope`] if the input is empty, carries an
    /// unrecognised version byte, is too short to contain the header, or is
    /// too short to contain even an empty-plaintext ciphertext (which is still
    /// [`TAG_LEN`] bytes because of the appended tag).
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let (&version, rest) = bytes
            .split_first()
            .ok_or(Error::MalformedEnvelope("empty input"))?;
        if version != ENVELOPE_VERSION {
            return Err(Error::MalformedEnvelope("unsupported envelope version"));
        }
        if rest.len() < NONCE_LEN {
            return Err(Error::MalformedEnvelope("truncated: nonce incomplete"));
        }
        let (nonce_bytes, ciphertext) = rest.split_at(NONCE_LEN);
        if ciphertext.len() < TAG_LEN {
            return Err(Error::MalformedEnvelope(
                "truncated: ciphertext shorter than authentication tag",
            ));
        }
        let mut nonce = [0u8; NONCE_LEN];
        nonce.copy_from_slice(nonce_bytes);
        Ok(Self {
            nonce,
            ciphertext: ciphertext.to_vec(),
        })
    }
}

impl core::fmt::Debug for Envelope {
    /// Ciphertext and nonce are non-secret, but we keep the output terse and
    /// never dump raw bytes — only structural sizes.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Envelope")
            .field("version", &ENVELOPE_VERSION)
            .field("nonce_len", &NONCE_LEN)
            .field("ciphertext_len", &self.ciphertext.len())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> Envelope {
        Envelope::from_parts([9u8; NONCE_LEN], vec![0xAB; TAG_LEN + 3])
    }

    #[test]
    fn to_from_bytes_roundtrip() {
        let env = sample();
        let bytes = env.to_bytes();
        // Layout: version(1) + nonce(24) + ct(len).
        assert_eq!(bytes[0], ENVELOPE_VERSION);
        assert_eq!(&bytes[1..1 + NONCE_LEN], &[9u8; NONCE_LEN]);
        let parsed = Envelope::from_bytes(&bytes).unwrap();
        assert_eq!(parsed.nonce(), env.nonce());
        assert_eq!(parsed.ciphertext(), env.ciphertext());
    }

    #[test]
    fn rejects_empty() {
        assert!(matches!(
            Envelope::from_bytes(&[]),
            Err(crate::Error::MalformedEnvelope(_))
        ));
    }

    #[test]
    fn rejects_wrong_version() {
        let mut bytes = sample().to_bytes();
        bytes[0] = 0x02;
        assert!(Envelope::from_bytes(&bytes).is_err());
    }

    #[test]
    fn rejects_truncated_nonce() {
        assert!(Envelope::from_bytes(&[ENVELOPE_VERSION; 10]).is_err());
    }

    #[test]
    fn rejects_ciphertext_below_tag_len() {
        // version + full nonce + (TAG_LEN - 1) ciphertext bytes.
        let bytes = [ENVELOPE_VERSION; 1 + NONCE_LEN + (TAG_LEN - 1)];
        assert!(Envelope::from_bytes(&bytes).is_err());
    }

    #[test]
    fn debug_redacts_bytes() {
        let dbg = format!("{:?}", sample());
        assert!(!dbg.contains("ab"));
        assert!(dbg.contains("Envelope"));
    }
}
