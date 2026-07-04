//! Op authoring — canonical wire bytes, Ed25519 signing, and the per-device
//! hash chain (sync-protocol.md §1–§5, local authoring side only).
//!
//! This crate authors ops for **this device**; cross-device ingest/merge is a
//! later crate. Every item mutation writes exactly one op row in the same
//! transaction as the state change (vault-format.md §7).
//!
//! # Canonical serialization (sync-protocol.md §1)
//!
//! An op is 11 fields in a fixed order. Integers are fixed-width little-endian;
//! `payload_env` is `u32`-length-prefixed:
//!
//! ```text
//!  1 op_id       16 bytes
//!  2 vault_id    16 bytes
//!  3 device_id   16 bytes
//!  4 seq         u64 LE
//!  5 prev_hash   32 bytes
//!  6 lamport     u64 LE
//!  7 op_kind     u8
//!  8 target_item 16 bytes (zero if vault-scope)
//!  9 target_ver  u32 LE
//! 10 payload_env u32 length prefix || Envelope v1 bytes
//! 11 signature   64 bytes  (Ed25519 over canonical bytes of fields 1..10)
//! ```
//!
//! - The **signed region** is fields 1..10; the signature (field 11) is made
//!   with `lp-crypto`'s Ed25519 [`sign`](lp_crypto::SigningKeyPair::sign) under
//!   the mandatory namespaced context [`OP_SIGN_CONTEXT`].
//! - **Sign-after-encrypt**: the signature covers the ciphertext `payload_env`,
//!   not plaintext (sync-protocol.md §1).
//!
//! # Hash chain (sync-protocol.md §5)
//!
//! `prev_hash(op) = blake3_256(canonical bytes fields 1..11 of this device's
//! previous op)`. The chain covers the *signature* too, so a peer cannot swap a
//! validly-signed but different prior op. The genesis (first op by a device) is
//! `blake3_256("localpass/v1/chain-genesis" || vault_id(16) || device_id(16))`,
//! **raw-byte framed** (LESSONS 2026-07-04) — not the `|`-joined AAD encoding.

use lp_crypto::{SigningKeyPair, VerifyingKey, blake3_256};

use crate::ids::{DeviceId, Id, OpId, VaultId};

/// Ed25519 signing context for ops (sync-protocol.md §1; the task fixes this
/// exact string). Namespaced per the `localpass/v1/` contract.
pub const OP_SIGN_CONTEXT: &str = "localpass/v1/op";

/// The raw-byte-framed genesis label for a device's first `prev_hash`
/// (sync-protocol.md §5, LESSONS raw-framing rule).
const CHAIN_GENESIS_LABEL: &[u8] = b"localpass/v1/chain-genesis";

/// Op kind codes (sync-protocol.md §2 / vault-format.md §3).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum OpKind {
    /// A new item (full payload + wrapped ItemKey).
    Create = 1,
    /// An edit to an existing item.
    Update = 2,
    /// A tombstone.
    Delete = 3,
    /// A restore of a prior version.
    Restore = 4,
    /// A key re-wrap (share/rotate). Reserved; not authored by MVP flows here.
    Rewrap = 5,
}

impl OpKind {
    /// The wire byte for this kind.
    #[must_use]
    pub fn code(self) -> u8 {
        self as u8
    }
}

/// The fixed-order fields of an op, before signing.
///
/// Field 5 (`prev_hash`) and field 11 (`signature`) are filled in during
/// authoring; this struct carries fields 1..10 plus `prev_hash`, and is signed
/// to produce the signature.
#[derive(Clone)]
pub struct OpFields {
    /// Field 1: the op's own id.
    pub op_id: OpId,
    /// Field 2: the vault this op belongs to.
    pub vault_id: VaultId,
    /// Field 3: the authoring device.
    pub device_id: DeviceId,
    /// Field 4: per-device gapless sequence (1-based).
    pub seq: u64,
    /// Field 5: hash-chain link to this device's previous op.
    pub prev_hash: [u8; 32],
    /// Field 6: Lamport clock.
    pub lamport: u64,
    /// Field 7: op kind.
    pub op_kind: OpKind,
    /// Field 8: target item (all-zero if vault-scope).
    pub target_item: ItemTarget,
    /// Field 9: target version (0 if n/a).
    pub target_version: u32,
    /// Field 10: the encrypted op payload (Envelope v1 wire bytes).
    pub payload_env: Vec<u8>,
}

/// Field 8: the op's target item, or the all-zero sentinel for vault-scope ops.
#[derive(Clone, Copy)]
pub struct ItemTarget([u8; 16]);

impl ItemTarget {
    /// A concrete item target.
    #[must_use]
    pub fn item(id: &Id) -> Self {
        Self(*id.as_bytes())
    }

    /// The all-zero vault-scope sentinel (sync-protocol.md §1: "zero if
    /// vault-scope").
    #[must_use]
    pub fn none() -> Self {
        Self([0u8; 16])
    }

    /// The raw 16 bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }
}

impl OpFields {
    /// Serialize the signed region (fields 1..10) to canonical wire bytes.
    ///
    /// This is exactly the byte string the Ed25519 signature is computed over.
    #[must_use]
    pub fn signed_region_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(16 * 4 + 8 * 2 + 1 + 4 + 4 + self.payload_env.len() + 32);
        out.extend_from_slice(self.op_id.as_bytes()); // 1
        out.extend_from_slice(self.vault_id.as_bytes()); // 2
        out.extend_from_slice(self.device_id.as_bytes()); // 3
        out.extend_from_slice(&self.seq.to_le_bytes()); // 4
        out.extend_from_slice(&self.prev_hash); // 5
        out.extend_from_slice(&self.lamport.to_le_bytes()); // 6
        out.push(self.op_kind.code()); // 7
        out.extend_from_slice(self.target_item.as_bytes()); // 8
        out.extend_from_slice(&self.target_version.to_le_bytes()); // 9
        // 10: u32 length prefix then the envelope bytes.
        let len = u32::try_from(self.payload_env.len()).expect("payload_env fits in u32");
        out.extend_from_slice(&len.to_le_bytes());
        out.extend_from_slice(&self.payload_env);
        out
    }

    /// Serialize the full canonical op (fields 1..11), appending the signature.
    ///
    /// This is the byte string the *next* op's `prev_hash` is the BLAKE3 of
    /// (sync-protocol.md §5, chain covers fields 1..11).
    #[must_use]
    pub fn full_bytes(&self, signature: &[u8; 64]) -> Vec<u8> {
        let mut out = self.signed_region_bytes();
        out.extend_from_slice(signature); // 11
        out
    }

    /// Sign the signed region under [`OP_SIGN_CONTEXT`].
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error`] if signing fails (only on an out-of-namespace
    /// context, which is a constant here — effectively infallible).
    pub fn sign(&self, signing: &SigningKeyPair) -> crate::Result<[u8; 64]> {
        let msg = self.signed_region_bytes();
        signing
            .sign(OP_SIGN_CONTEXT, &msg)
            .map_err(crate::Error::from_crypto)
    }

    /// Verify a signature over this op's signed region under `verifying`.
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error::DecryptionFailed`] if the signature is invalid
    /// (mirroring `lp-crypto`'s opaque verify failure).
    pub fn verify(&self, verifying: &VerifyingKey, signature: &[u8; 64]) -> crate::Result<()> {
        let msg = self.signed_region_bytes();
        verifying
            .verify(OP_SIGN_CONTEXT, &msg, signature)
            .map_err(crate::Error::from_crypto)
    }
}

/// The genesis `prev_hash` for a device's first op in a vault.
///
/// `blake3_256("localpass/v1/chain-genesis" || vault_id(16) || device_id(16))`,
/// raw-byte framed (LESSONS 2026-07-04). Fixed-width components make the input
/// unambiguous without length prefixes.
#[must_use]
pub fn genesis_hash(vault_id: &VaultId, device_id: &DeviceId) -> [u8; 32] {
    let mut input = Vec::with_capacity(CHAIN_GENESIS_LABEL.len() + 32);
    input.extend_from_slice(CHAIN_GENESIS_LABEL);
    input.extend_from_slice(vault_id.as_bytes());
    input.extend_from_slice(device_id.as_bytes());
    blake3_256(&input)
}

/// The chain hash of a full op (fields 1..11) — the next op's `prev_hash`.
#[must_use]
pub fn chain_hash(full_op_bytes: &[u8]) -> [u8; 32] {
    blake3_256(full_op_bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fields(seq: u64, lamport: u64, prev: [u8; 32]) -> OpFields {
        OpFields {
            op_id: Id::from_bytes([1u8; 16]),
            vault_id: Id::from_bytes([2u8; 16]),
            device_id: Id::from_bytes([3u8; 16]),
            seq,
            prev_hash: prev,
            lamport,
            op_kind: OpKind::Create,
            target_item: ItemTarget::item(&Id::from_bytes([4u8; 16])),
            target_version: 1,
            payload_env: vec![0xAB, 0xCD, 0xEF],
        }
    }

    #[test]
    fn signed_region_layout_is_fixed_width() {
        let f = fields(1, 1, [0u8; 32]);
        let bytes = f.signed_region_bytes();
        // 16*4 + 8 (seq) + 32 (prev) + 8 (lamport) + 1 (kind) + 4 (ver) + 4 (len) + 3 (payload)
        let expected = 64 + 8 + 32 + 8 + 1 + 4 + 4 + 3;
        assert_eq!(bytes.len(), expected);
        // seq is at offset 48 (after 3 ids), little-endian.
        assert_eq!(&bytes[48..56], &1u64.to_le_bytes());
    }

    #[test]
    fn sign_then_verify_roundtrips() {
        let kp = SigningKeyPair::generate();
        let f = fields(1, 1, [7u8; 32]);
        let sig = f.sign(&kp).unwrap();
        f.verify(&kp.verifying_key(), &sig).unwrap();
    }

    #[test]
    fn tampering_the_signed_region_breaks_verify() {
        let kp = SigningKeyPair::generate();
        let f = fields(1, 1, [7u8; 32]);
        let sig = f.sign(&kp).unwrap();
        let mut f2 = f.clone();
        f2.lamport = 999; // changed field 6
        assert!(f2.verify(&kp.verifying_key(), &sig).is_err());
    }

    #[test]
    fn genesis_is_deterministic_and_binds_ids() {
        let v = Id::from_bytes([1u8; 16]);
        let d = Id::from_bytes([2u8; 16]);
        assert_eq!(genesis_hash(&v, &d), genesis_hash(&v, &d));
        // Different device → different genesis.
        let d2 = Id::from_bytes([9u8; 16]);
        assert_ne!(genesis_hash(&v, &d), genesis_hash(&v, &d2));
    }

    #[test]
    fn chain_covers_signature() {
        let kp = SigningKeyPair::generate();
        let f = fields(1, 1, [0u8; 32]);
        let sig_a = f.sign(&kp).unwrap();
        let full_a = f.full_bytes(&sig_a);
        // A different signature would change the chain hash of the same fields.
        let mut sig_b = sig_a;
        sig_b[0] ^= 0xFF;
        let full_b = f.full_bytes(&sig_b);
        assert_ne!(chain_hash(&full_a), chain_hash(&full_b));
    }
}
