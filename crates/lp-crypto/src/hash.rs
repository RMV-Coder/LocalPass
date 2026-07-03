//! BLAKE3 hashing — the op-chain link primitive.
//!
//! The sync protocol (`docs/specs/sync-protocol.md` §5) chains each device's
//! ops with `prev_hash = BLAKE3(canonical bytes of the previous op)`. This
//! module is the single place that primitive lives, per the crate boundary
//! rule (only `lp-crypto` may depend on cryptographic primitive crates).
//!
//! BLAKE3 is used for *integrity chaining only* — never for key derivation
//! (that is HKDF-SHA256, see [`crate::kdf`]) and never for password hashing
//! (Argon2id, see [`crate::params`]).

/// Length of a BLAKE3-256 digest, in bytes.
pub const HASH_LEN: usize = 32;

/// Hash `data` with BLAKE3, returning the 32-byte digest.
///
/// Callers composing multi-part inputs (e.g. the chain-genesis value
/// `"localpass/v1/chain-genesis" || vault_id || device_id`) must use
/// fixed-width or length-prefixed framing so the input is unambiguous.
#[must_use]
pub fn blake3_256(data: &[u8]) -> [u8; HASH_LEN] {
    *blake3::hash(data).as_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;
    use hex_literal::hex;

    /// Pinned official BLAKE3 test vector (empty input).
    #[test]
    fn blake3_empty_vector() {
        assert_eq!(
            blake3_256(b""),
            hex!("af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262")
        );
    }

    #[test]
    fn distinct_inputs_distinct_digests() {
        assert_ne!(blake3_256(b"a"), blake3_256(b"b"));
    }
}
