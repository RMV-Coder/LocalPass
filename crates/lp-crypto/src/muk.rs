//! Master Unlock Key derivation: password + Secret Key → MUK.
//!
//! This is the root of the entire key hierarchy (PRD §4.3). It combines two
//! independent factors so that an attacker who steals the on-disk vault must
//! break **both**:
//!
//! 1. the user's **master password** (low-entropy, human-chosen), and
//! 2. the 128-bit **[`SecretKey`]** (high-entropy, machine-generated, stored on
//!    device / in the Emergency Kit — never in the vault file).
//!
//! # Construction
//!
//! ```text
//!   argon_out = Argon2id(
//!                   password = master password bytes,
//!                   salt     = KdfParams.salt (16 bytes),
//!                   m, t, p  = KdfParams costs,
//!                   outlen   = 32,
//!               )
//!
//!   MUK       = HKDF-SHA256(
//!                   ikm  = argon_out,          // the expensive, password-bound secret
//!                   salt = SecretKey (16 bytes),// the high-entropy second factor
//!                   info = "localpass/v1/muk",  // domain separation
//!               )                               // → 32-byte MasterUnlockKey
//! ```
//!
//! # Why this assignment of IKM vs salt
//!
//! HKDF's security goal here is *combining* two secrets, and both orderings are
//! sound (HKDF-Extract is a PRF keyed by the salt, applied to the IKM). We put
//! the **Argon2 output as the IKM** and the **Secret Key as the HKDF salt** for
//! two concrete reasons:
//!
//! - **Semantic fit.** HKDF-Extract treats the IKM as "the keying material to
//!   be conditioned" and the salt as "an independent, ideally high-entropy
//!   value that keys the extractor". The Secret Key is exactly a fixed,
//!   uniformly-random high-entropy value — the textbook role of an HKDF salt —
//!   while the Argon2 output is the password-derived material we are
//!   conditioning. This makes the construction easy to reason about in audit.
//! - **No factor is skippable.** Because HKDF-Extract mixes salt and IKM
//!   through HMAC, changing *either* input changes the MUK. Neither the
//!   password path nor the Secret Key can be dropped without producing a
//!   different key — which is precisely the "must break both factors" property
//!   (PRD T1/T12).
//!
//! Argon2id itself already salts with `KdfParams.salt`, so its output is unique
//! per account even before the Secret Key is mixed in; the Secret Key then adds
//! 128 bits of entropy that never touches the vault file.
//!
//! # Determinism
//!
//! Same password + same [`SecretKey`] + same [`KdfParams`] ⇒ same MUK, on any
//! device. This is what lets a paired device re-derive the MUK from the stored
//! (public) params plus the user-supplied password and on-device Secret Key.

use argon2::{Algorithm, Argon2, Params, Version};

use crate::error::{Error, Result};
use crate::kdf::hkdf_sha256_32;
use crate::keys::{MasterUnlockKey, SecretKey, SymmetricKey};
use crate::params::KdfParams;

/// The HKDF domain-separation label for the MUK (fixed contract).
const MUK_LABEL: &str = "localpass/v1/muk";

/// Intermediate Argon2id output length, in bytes (feeds HKDF as IKM).
const ARGON_OUTPUT_LEN: usize = 32;

/// Derive the [`MasterUnlockKey`] from a password, [`SecretKey`], and
/// [`KdfParams`].
///
/// The construction is:
///
/// ```text
///   argon_out = Argon2id(password, salt = KdfParams.salt, m/t/p, outlen = 32)
///   MUK       = HKDF-SHA256(ikm = argon_out, salt = SecretKey, info = "localpass/v1/muk")
/// ```
///
/// The Argon2 output is the HKDF **IKM** (the expensive, password-bound secret)
/// and the Secret Key is the HKDF **salt** (the high-entropy second factor);
/// changing either input changes the MUK, so both factors must be broken to
/// reproduce it (PRD T1/T12). Deterministic in all three inputs.
///
/// # Errors
///
/// Returns [`Error::InvalidKdfParams`] if the parameters are rejected by
/// Argon2 (e.g. a memory/lane/time value outside the algorithm's valid range,
/// or a memory cost too small for the requested parallelism).
pub fn derive_master_unlock_key(
    password: &[u8],
    secret_key: &SecretKey,
    params: &KdfParams,
) -> Result<MasterUnlockKey> {
    // 1) Argon2id over the password, salted by the public per-account salt.
    let argon_params = Params::new(
        params.m_cost_kib(),
        params.t_cost(),
        params.p_cost(),
        Some(ARGON_OUTPUT_LEN),
    )
    .map_err(|_| Error::InvalidKdfParams("Argon2 rejected the cost parameters"))?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, argon_params);

    let mut argon_out = [0u8; ARGON_OUTPUT_LEN];
    argon
        .hash_password_into(password, params.salt(), &mut argon_out)
        .map_err(|_| Error::InvalidKdfParams("Argon2 derivation failed"))?;

    // 2) HKDF-SHA256 combine: IKM = argon_out, salt = SecretKey, info = MUK label.
    let okm = hkdf_sha256_32(secret_key.as_bytes(), &argon_out, MUK_LABEL);

    // Wipe the intermediate Argon2 output regardless of the HKDF outcome.
    use zeroize::Zeroize;
    argon_out.zeroize();

    let okm = okm?;
    Ok(MasterUnlockKey::from_inner(SymmetricKey::from_bytes(okm)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::SecretKey;
    use crate::params::KdfParams;
    use hex_literal::hex;

    /// Byte-exact fixed vector with cheap params, pinned so any change to the
    /// MUK construction (Argon2 config, HKDF label/salt/IKM assignment, or
    /// output handling) is caught immediately. Uses crate-internal raw access.
    ///
    /// Inputs:
    ///   password = b"correct horse battery staple"
    ///   secret_key = 0x101112131415161718191a1b1c1d1e1f
    ///   params = Argon2id(m = 64 KiB, t = 1, p = 1), salt = b"0123456789abcdef"
    #[test]
    fn muk_fixed_vector() {
        let sk = SecretKey::from_bytes(hex!("101112131415161718191a1b1c1d1e1f"));
        let params = KdfParams::with_salt(64, 1, 1, *b"0123456789abcdef");
        let muk = derive_master_unlock_key(b"correct horse battery staple", &sk, &params).unwrap();

        // Recorded reference output (regenerate with the ignored `print_vector`).
        let expected = hex!("8f4a0714ff9af1096b5e2e55aef8dc7e1ddd29069dc9556c22596e6944bd0b2a");
        assert_eq!(muk.inner().as_bytes(), &expected);
    }

    /// One-shot helper to (re)compute the vector above. Ignored in normal runs.
    #[test]
    #[ignore = "prints the fixed MUK vector for pinning"]
    fn print_vector() {
        let sk = SecretKey::from_bytes(hex!("101112131415161718191a1b1c1d1e1f"));
        let params = KdfParams::with_salt(64, 1, 1, *b"0123456789abcdef");
        let muk = derive_master_unlock_key(b"correct horse battery staple", &sk, &params).unwrap();
        let bytes = muk.inner().as_bytes();
        let hexs: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
        println!("MUK_VECTOR={hexs}");
    }
}
