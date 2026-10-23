//! Noise XX handshake and transport for the LAN sync link
//! (`docs/specs/lan-transport.md` §3–§5).
//!
//! This module is the crypto boundary for the live transport (PRD §6.2): it is
//! the only place in the workspace that touches the `snow` Noise
//! implementation. Callers get a handshake object that writes and reads
//! messages, exposes the transcript hash and the static keys, and turns into a
//! transport that encrypts and decrypts records. They never see a private key,
//! a cipher key, or a nonce.
//!
//! # Fixed parameters
//!
//! [`NOISE_PARAMS`] is `Noise_XX_25519_ChaChaPoly_SHA256`: the primitives
//! `lp-crypto` already uses (X25519 via `curve25519-dalek` 4, ChaCha20-Poly1305
//! via `chacha20poly1305` 0.10, SHA-256 via `sha2` 0.10). `snow` is built with
//! only those three plus the OS RNG, so no second AEAD, hash or curve enters the
//! tree. The pattern is not negotiable at runtime (PRD §5.1): a different
//! protocol needs a different prologue and a new spec version.
//!
//! # A fresh static key per handshake
//!
//! Every [`NoiseHandshake`] generates its own X25519 static keypair from the OS
//! CSPRNG. It is **not** the device's long-term X25519 sealing key: the spec
//! keeps that key for sealed vault-key shares only (key separation,
//! `lan-transport.md` §3.2). The static key's owner is proven by an Ed25519
//! signature from the device's identity key carried in the handshake payload
//! (§3.1) — that binding lives one layer up, in `lp-sync`, which only needs
//! [`NoiseHandshake::handshake_hash`] and the static public keys from here.
//!
//! # Errors
//!
//! Anything that depends on received bytes — a failed decrypt, a malformed
//! handshake message, a bad tag — collapses into the opaque
//! [`Error::DecryptionFailed`], like every other authentication failure in this
//! crate. Caller mistakes that depend on no secret (writing out of turn, a
//! payload too large for one Noise message) are [`Error::NoiseState`].

use zeroize::{Zeroize, Zeroizing};

use crate::error::{Error, Result};

/// The one Noise protocol LocalPass speaks (`lan-transport.md` §4.1).
pub const NOISE_PARAMS: &str = "Noise_XX_25519_ChaChaPoly_SHA256";

/// The largest Noise message, handshake or transport (Noise spec §3).
pub const MAX_NOISE_MESSAGE_LEN: usize = 65_535;

/// The ChaChaPoly authentication tag carried by every encrypted payload.
pub const NOISE_TAG_LEN: usize = 16;

/// The largest plaintext one transport message can carry.
pub const MAX_TRANSPORT_PLAINTEXT_LEN: usize = MAX_NOISE_MESSAGE_LEN - NOISE_TAG_LEN;

/// Length of an X25519 Noise static public key.
pub const NOISE_STATIC_KEY_LEN: usize = 32;

/// Length of the Noise handshake hash `h` for SHA-256.
pub const HANDSHAKE_HASH_LEN: usize = 32;

/// Parse the fixed protocol name. It is a compile-time constant, so a failure
/// here is a build defect, reported without detail.
fn params() -> Result<snow::params::NoiseParams> {
    NOISE_PARAMS
        .parse()
        .map_err(|_| Error::NoiseState("unsupported noise parameters"))
}

/// An in-progress Noise XX handshake, as initiator or responder.
///
/// Drive it by alternating [`write_message`](Self::write_message) and
/// [`read_message`](Self::read_message) in the XX order (initiator writes
/// first), then call [`into_transport`](Self::into_transport). Not `Clone`; the
/// static private key it generated is held only inside `snow` and is dropped
/// with this value.
pub struct NoiseHandshake {
    state: snow::HandshakeState,
    local_static: [u8; NOISE_STATIC_KEY_LEN],
}

impl NoiseHandshake {
    /// Start a handshake as the **initiator** (the side that connects).
    ///
    /// # Errors
    ///
    /// [`Error::NoiseState`] if the OS RNG or the Noise state cannot be set up.
    pub fn initiator(prologue: &[u8]) -> Result<Self> {
        Self::build(prologue, true)
    }

    /// Start a handshake as the **responder** (the side that listens).
    ///
    /// # Errors
    ///
    /// [`Error::NoiseState`] if the OS RNG or the Noise state cannot be set up.
    pub fn responder(prologue: &[u8]) -> Result<Self> {
        Self::build(prologue, false)
    }

    fn build(prologue: &[u8], initiator: bool) -> Result<Self> {
        let builder = snow::Builder::new(params()?);
        let keypair = builder
            .generate_keypair()
            .map_err(|_| Error::NoiseState("could not generate a noise static key"))?;
        // Hold the private half in a zeroizing buffer for the moment it is
        // copied into the handshake state.
        let private = Zeroizing::new(keypair.private);
        let local_static: [u8; NOISE_STATIC_KEY_LEN] = keypair
            .public
            .as_slice()
            .try_into()
            .map_err(|_| Error::NoiseState("unexpected noise static key length"))?;
        let builder = builder
            .prologue(prologue)
            .map_err(|_| Error::NoiseState("invalid noise prologue"))?
            .local_private_key(&private)
            .map_err(|_| Error::NoiseState("invalid noise static key"))?;
        let state = if initiator {
            builder.build_initiator()
        } else {
            builder.build_responder()
        }
        .map_err(|_| Error::NoiseState("could not start the noise handshake"))?;
        Ok(Self {
            state,
            local_static,
        })
    }

    /// Write the next handshake message carrying `payload`.
    ///
    /// # Errors
    ///
    /// [`Error::NoiseState`] if it is not this side's turn, the handshake is
    /// finished, or the message would exceed [`MAX_NOISE_MESSAGE_LEN`].
    pub fn write_message(&mut self, payload: &[u8]) -> Result<Vec<u8>> {
        let mut buf = vec![0u8; MAX_NOISE_MESSAGE_LEN];
        let n = self
            .state
            .write_message(payload, &mut buf)
            .map_err(|_| Error::NoiseState("could not write the handshake message"))?;
        buf.truncate(n);
        Ok(buf)
    }

    /// Read the peer's next handshake message and return its payload.
    ///
    /// # Errors
    ///
    /// [`Error::DecryptionFailed`] for any failure: a malformed or truncated
    /// message, a failed decrypt, or a message out of turn.
    pub fn read_message(&mut self, message: &[u8]) -> Result<Vec<u8>> {
        let mut buf = vec![0u8; MAX_NOISE_MESSAGE_LEN];
        let n = self
            .state
            .read_message(message, &mut buf)
            .map_err(|_| Error::DecryptionFailed)?;
        buf.truncate(n);
        Ok(buf)
    }

    /// The current handshake hash `h`. At a message boundary both sides hold
    /// the same value; `lp-sync` signs it into the identity proof
    /// (`lan-transport.md` §4.3).
    #[must_use]
    pub fn handshake_hash(&self) -> [u8; HANDSHAKE_HASH_LEN] {
        let mut out = [0u8; HANDSHAKE_HASH_LEN];
        let h = self.state.get_handshake_hash();
        let n = h.len().min(HANDSHAKE_HASH_LEN);
        out[..n].copy_from_slice(&h[..n]);
        out
    }

    /// This side's static public key for this connection.
    #[must_use]
    pub fn local_static_public(&self) -> [u8; NOISE_STATIC_KEY_LEN] {
        self.local_static
    }

    /// The peer's static public key, once its `s` token has been read.
    #[must_use]
    pub fn remote_static_public(&self) -> Option<[u8; NOISE_STATIC_KEY_LEN]> {
        self.state
            .get_remote_static()
            .and_then(|k| <[u8; NOISE_STATIC_KEY_LEN]>::try_from(k).ok())
    }

    /// Whether every handshake message has been written or read.
    #[must_use]
    pub fn is_finished(&self) -> bool {
        self.state.is_handshake_finished()
    }

    /// Finish the handshake and switch to transport mode.
    ///
    /// # Errors
    ///
    /// [`Error::NoiseState`] if the handshake is not finished.
    pub fn into_transport(self) -> Result<NoiseTransport> {
        let state = self
            .state
            .into_transport_mode()
            .map_err(|_| Error::NoiseState("the noise handshake is not finished"))?;
        Ok(NoiseTransport { state })
    }
}

impl core::fmt::Debug for NoiseHandshake {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("NoiseHandshake")
            .field("initiator", &self.state.is_initiator())
            .field("finished", &self.state.is_handshake_finished())
            .finish_non_exhaustive()
    }
}

/// An established Noise transport: one cipher state per direction, with
/// implicit nonces. A record that is reordered, dropped, duplicated or altered
/// fails to decrypt.
pub struct NoiseTransport {
    state: snow::TransportState,
}

impl NoiseTransport {
    /// Encrypt one record. `plaintext` must fit in one Noise message
    /// ([`MAX_TRANSPORT_PLAINTEXT_LEN`]).
    ///
    /// # Errors
    ///
    /// [`Error::NoiseState`] if `plaintext` is too long or the nonce space is
    /// exhausted.
    pub fn encrypt(&mut self, plaintext: &[u8]) -> Result<Vec<u8>> {
        if plaintext.len() > MAX_TRANSPORT_PLAINTEXT_LEN {
            return Err(Error::NoiseState("record too large for one noise message"));
        }
        let mut buf = vec![0u8; plaintext.len() + NOISE_TAG_LEN];
        let n = self
            .state
            .write_message(plaintext, &mut buf)
            .map_err(|_| Error::NoiseState("could not encrypt the record"))?;
        buf.truncate(n);
        Ok(buf)
    }

    /// Decrypt the next record from the peer.
    ///
    /// # Errors
    ///
    /// [`Error::DecryptionFailed`] for a record that does not authenticate (wrong
    /// key, altered, out of order, replayed, truncated).
    pub fn decrypt(&mut self, message: &[u8]) -> Result<Vec<u8>> {
        if message.len() > MAX_NOISE_MESSAGE_LEN || message.len() < NOISE_TAG_LEN {
            return Err(Error::DecryptionFailed);
        }
        let mut buf = vec![0u8; message.len()];
        match self.state.read_message(message, &mut buf) {
            Ok(n) => {
                buf.truncate(n);
                Ok(buf)
            }
            Err(_) => {
                buf.zeroize();
                Err(Error::DecryptionFailed)
            }
        }
    }
}

impl core::fmt::Debug for NoiseTransport {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("NoiseTransport").finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const PROLOGUE: &[u8] = b"localpass/v1/lan-sync/test";

    /// Run a full XX handshake and return both transports plus the identity
    /// facts each side saw.
    fn handshake() -> (NoiseTransport, NoiseTransport) {
        let mut i = NoiseHandshake::initiator(PROLOGUE).unwrap();
        let mut r = NoiseHandshake::responder(PROLOGUE).unwrap();
        let m1 = i.write_message(&[]).unwrap();
        assert!(r.read_message(&m1).unwrap().is_empty());
        let h1_r = r.handshake_hash();
        assert_eq!(h1_r, i.handshake_hash(), "h agrees after msg 1");
        let m2 = r.write_message(b"responder proof").unwrap();
        assert_eq!(i.read_message(&m2).unwrap(), b"responder proof");
        assert_eq!(i.remote_static_public(), Some(r.local_static_public()));
        assert_eq!(
            i.handshake_hash(),
            r.handshake_hash(),
            "h agrees after msg 2"
        );
        let m3 = i.write_message(b"initiator proof").unwrap();
        assert_eq!(r.read_message(&m3).unwrap(), b"initiator proof");
        assert_eq!(r.remote_static_public(), Some(i.local_static_public()));
        assert!(i.is_finished() && r.is_finished());
        (i.into_transport().unwrap(), r.into_transport().unwrap())
    }

    #[test]
    fn xx_handshake_and_transport_round_trip() {
        let (mut i, mut r) = handshake();
        let c = i.encrypt(b"hello").unwrap();
        assert_eq!(r.decrypt(&c).unwrap(), b"hello");
        let c = r.encrypt(b"world").unwrap();
        assert_eq!(i.decrypt(&c).unwrap(), b"world");
    }

    #[test]
    fn every_handshake_has_a_fresh_static_key() {
        let a = NoiseHandshake::initiator(PROLOGUE).unwrap();
        let b = NoiseHandshake::initiator(PROLOGUE).unwrap();
        assert_ne!(a.local_static_public(), b.local_static_public());
    }

    #[test]
    fn prologue_mismatch_fails_the_handshake() {
        let mut i = NoiseHandshake::initiator(b"localpass/v1/lan-sync/1").unwrap();
        let mut r = NoiseHandshake::responder(b"localpass/v1/lan-sync/2").unwrap();
        let m1 = i.write_message(&[]).unwrap();
        r.read_message(&m1).unwrap();
        let m2 = r.write_message(b"x").unwrap();
        assert!(matches!(i.read_message(&m2), Err(Error::DecryptionFailed)));
    }

    #[test]
    fn tampered_handshake_message_is_opaque_failure() {
        let mut i = NoiseHandshake::initiator(PROLOGUE).unwrap();
        let mut r = NoiseHandshake::responder(PROLOGUE).unwrap();
        let m1 = i.write_message(&[]).unwrap();
        r.read_message(&m1).unwrap();
        let mut m2 = r.write_message(b"proof").unwrap();
        let last = m2.len() - 1;
        m2[last] ^= 0x01;
        assert!(matches!(i.read_message(&m2), Err(Error::DecryptionFailed)));
    }

    #[test]
    fn tampered_reordered_and_replayed_records_fail() {
        let (mut i, mut r) = handshake();
        let mut c1 = i.encrypt(b"one").unwrap();
        c1[0] ^= 0x80;
        assert!(matches!(r.decrypt(&c1), Err(Error::DecryptionFailed)));

        let (mut i, mut r) = handshake();
        let c1 = i.encrypt(b"one").unwrap();
        let c2 = i.encrypt(b"two").unwrap();
        // Out of order: record 2 first.
        assert!(matches!(r.decrypt(&c2), Err(Error::DecryptionFailed)));

        let (mut i, mut r) = handshake();
        let c1b = i.encrypt(b"one").unwrap();
        assert_eq!(r.decrypt(&c1b).unwrap(), b"one");
        // Replay of the same record.
        assert!(matches!(r.decrypt(&c1b), Err(Error::DecryptionFailed)));
        let _ = c1;
    }

    #[test]
    fn oversize_record_is_refused() {
        let (mut i, _r) = handshake();
        let big = vec![0u8; MAX_TRANSPORT_PLAINTEXT_LEN + 1];
        assert!(matches!(i.encrypt(&big), Err(Error::NoiseState(_))));
        let max = vec![0u8; MAX_TRANSPORT_PLAINTEXT_LEN];
        assert_eq!(i.encrypt(&max).unwrap().len(), MAX_NOISE_MESSAGE_LEN);
    }

    #[test]
    fn out_of_turn_write_is_a_state_error() {
        let mut r = NoiseHandshake::responder(PROLOGUE).unwrap();
        assert!(matches!(r.write_message(&[]), Err(Error::NoiseState(_))));
    }

    #[test]
    fn debug_reveals_no_key_material() {
        let i = NoiseHandshake::initiator(PROLOGUE).unwrap();
        let s = format!("{i:?}");
        assert!(s.contains("NoiseHandshake"));
        assert!(!s.contains(&format!("{:?}", i.local_static_public())));
    }
}
