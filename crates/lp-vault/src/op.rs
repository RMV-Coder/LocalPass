//! Op authoring — canonical wire bytes, Ed25519 signing, and the per-device
//! hash chain (sync-protocol.md §1–§5, local authoring side only).
//!
//! This crate authors ops for **this device**; cross-device ingest/merge is a
//! later crate. Every item mutation writes exactly one op row in the same
//! transaction as the state change (vault-format.md §7).
//!
//! # Canonical serialization (sync-protocol.md §1, **wire version 2**)
//!
//! An op is a version byte plus 12 fields in a fixed order. Integers are
//! fixed-width little-endian; `payload_env` and `observed` are length-prefixed:
//!
//! ```text
//!  0 wire_ver    u8         = 2  (op-format version; §1)
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
//! 11 observed    u32 count prefix || count × (device_id 16 bytes || seq u64 LE),
//!                entries ascending by device_id  -- the causal summary (§3)
//! 12 signature   64 bytes  (Ed25519 over canonical bytes of fields 0..11)
//! ```
//!
//! - The **signed region** is the version byte + fields 1..11; the signature
//!   (field 12) is made with `lp-crypto`'s Ed25519
//!   [`sign`](lp_crypto::SigningKeyPair::sign) under the mandatory namespaced
//!   context [`OP_SIGN_CONTEXT`].
//! - **Sign-after-encrypt**: the signature covers the ciphertext `payload_env`,
//!   not plaintext (sync-protocol.md §1).
//! - **`observed` (the causal summary, sync-protocol.md §3):** the highest
//!   `seq` this device had applied from every device (itself included) at
//!   author time. It is authenticated metadata: covered by both the signature
//!   and the hash chain. The merge (sync-protocol.md §4.3) derives **true
//!   happens-before** from it (`A → B` iff `A.seq <= B.observed[A.device]`),
//!   replacing the old scalar-Lamport approximation. The Lamport clock stays
//!   only as the LWW total-order tiebreak (§4.1).
//!
//! # Hash chain (sync-protocol.md §5)
//!
//! `prev_hash(op) = blake3_256(canonical bytes fields 0..12 of this device's
//! previous op)`. The chain covers the *signature* and the *observed vector*
//! too, so a peer cannot swap a validly-signed but different prior op nor
//! rewrite its causal summary. The genesis (first op by a device) is
//! `blake3_256("localpass/v1/chain-genesis" || vault_id(16) || device_id(16))`,
//! **raw-byte framed** (LESSONS 2026-07-04) — not the `|`-joined AAD encoding.

use std::collections::BTreeMap;

use lp_crypto::{SigningKeyPair, VerifyingKey, blake3_256};

use crate::ids::{DeviceId, Id, OpId, VaultId};

/// The op canonical-wire format version (sync-protocol.md §1). Bumped from the
/// implicit v1 to **2** when the [`ObservedHeads`] causal summary (field 11)
/// was added; a decoder reads this leading byte to detect the layout. There are
/// no released v1 ops in the wild, so v2 is the only accepted version.
pub const OP_WIRE_VERSION: u8 = 2;

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
    /// A new attachment added to an item (metadata; the blob ships separately
    /// through the file channel — sync-protocol.md §2). Payload carries the
    /// attachment_id, item_id, version, content_hash, size_plain, and the
    /// already-ItemKey-sealed wrapped-key + filename envelopes.
    AttachAdd = 6,
    /// An attachment removed from an item (a tombstone by `attachment_id`;
    /// sync-protocol.md §2). Payload carries only the `attachment_id`.
    AttachDelete = 7,
}

impl OpKind {
    /// Parse a wire byte into an [`OpKind`], or `None` for an unknown value.
    #[must_use]
    pub fn from_code(code: u8) -> Option<Self> {
        match code {
            1 => Some(Self::Create),
            2 => Some(Self::Update),
            3 => Some(Self::Delete),
            4 => Some(Self::Restore),
            5 => Some(Self::Rewrap),
            6 => Some(Self::AttachAdd),
            7 => Some(Self::AttachDelete),
            _ => None,
        }
    }
}

impl OpKind {
    /// The wire byte for this kind.
    #[must_use]
    pub fn code(self) -> u8 {
        self as u8
    }
}

/// The per-op **observed-heads causal summary** (sync-protocol.md §3): for each
/// device this op's author had ever applied an op from (itself included), the
/// highest `seq` it had applied at author time.
///
/// This is the exact version vector that makes cross-device happens-before
/// precise. Given ops `A` (by device `d`, seq `s`) and `B`:
///
/// - if `A.device == B.device`, `A → B` iff `A.seq < B.seq` (same-device chain
///   order);
/// - otherwise `A → B` iff `B.observed[A.device] >= A.seq` (B had applied A, or
///   a later op from A's device, when it was authored).
///
/// Two ops are **concurrent** iff neither observes the other. Because `observed`
/// is authored deterministically from applied state and is signed + chained, the
/// relation is identical on every device and cannot be forged.
///
/// # Canonical bytes
///
/// `u32` entry count, then each entry as `device_id(16) || seq(u64 LE)`, with
/// entries in **ascending `device_id`** order. The `BTreeMap` guarantees that
/// order, so the encoding is reproducible byte-for-byte on any device.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ObservedHeads {
    /// device_id bytes → highest observed `seq`. A `BTreeMap` so iteration is
    /// deterministically ascending by device_id (canonical-bytes requirement).
    heads: BTreeMap<[u8; 16], u64>,
}

impl ObservedHeads {
    /// An empty summary (a device's very first op observes nothing).
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Build from an iterator of `(device_id_bytes, seq)` pairs; on a duplicate
    /// device the greater `seq` is kept (the "highest observed" invariant).
    pub fn from_pairs(pairs: impl IntoIterator<Item = ([u8; 16], u64)>) -> Self {
        let mut heads = BTreeMap::new();
        for (dev, seq) in pairs {
            let e = heads.entry(dev).or_insert(0);
            *e = (*e).max(seq);
        }
        Self { heads }
    }

    /// Record that `seq` (or higher) from `device` has been observed. Monotone:
    /// a lower `seq` never lowers a recorded head.
    pub fn observe(&mut self, device: &DeviceId, seq: u64) {
        let e = self.heads.entry(*device.as_bytes()).or_insert(0);
        *e = (*e).max(seq);
    }

    /// The highest observed `seq` from `device`, or `0` if none observed.
    #[must_use]
    pub fn get(&self, device: &DeviceId) -> u64 {
        self.heads.get(device.as_bytes()).copied().unwrap_or(0)
    }

    /// The number of devices in the summary.
    #[must_use]
    pub fn len(&self) -> usize {
        self.heads.len()
    }

    /// Whether the summary is empty (no device observed).
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.heads.is_empty()
    }

    /// Iterate `(device_id_bytes, seq)` in ascending device_id order.
    pub fn iter(&self) -> impl Iterator<Item = (&[u8; 16], &u64)> {
        self.heads.iter()
    }

    /// Serialize to canonical bytes: `u32` count then sorted
    /// `device_id(16) || seq(u64 LE)` entries. Appended to `out`.
    pub fn encode_bytes_into(&self, out: &mut Vec<u8>) {
        let count = u32::try_from(self.heads.len()).expect("device count fits in u32");
        out.extend_from_slice(&count.to_le_bytes());
        for (dev, seq) in &self.heads {
            out.extend_from_slice(dev);
            out.extend_from_slice(&seq.to_le_bytes());
        }
    }

    /// The canonical bytes of this summary (`u32` count + sorted entries).
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.encoded_len());
        self.encode_bytes_into(&mut out);
        out
    }

    /// The serialized byte length (count prefix + fixed-width entries).
    #[must_use]
    fn encoded_len(&self) -> usize {
        4 + self.heads.len() * (16 + 8)
    }

    /// Parse canonical bytes back into an [`ObservedHeads`] — the inverse of
    /// [`encode_bytes_into`](Self::encode_bytes_into). Accepts empty input as an
    /// empty summary (a device's first op, or an absent column).
    ///
    /// # Errors
    ///
    /// [`crate::Error::Invalid`] on truncation, a length that overruns the
    /// buffer, or trailing bytes (a corrupt / non-canonical encoding).
    pub fn decode(bytes: &[u8]) -> crate::Result<Self> {
        if bytes.is_empty() {
            return Ok(Self::new());
        }
        if bytes.len() < 4 {
            return Err(crate::Error::Invalid("observed-heads: truncated count"));
        }
        let count = u32::from_le_bytes(bytes[0..4].try_into().unwrap()) as usize;
        let entry_len = 16 + 8;
        let expected = 4 + count * entry_len;
        if bytes.len() != expected {
            return Err(crate::Error::Invalid("observed-heads: bad length"));
        }
        let mut heads = BTreeMap::new();
        let mut prev_dev: Option<[u8; 16]> = None;
        for i in 0..count {
            let base = 4 + i * entry_len;
            let dev: [u8; 16] = bytes[base..base + 16].try_into().unwrap();
            let seq = u64::from_le_bytes(bytes[base + 16..base + 24].try_into().unwrap());
            // Enforce the canonical ascending-device_id ordering (no dupes), so
            // a re-encode is byte-identical and a forged reordering is rejected.
            if let Some(p) = prev_dev
                && dev <= p
            {
                return Err(crate::Error::Invalid(
                    "observed-heads: entries not strictly ascending",
                ));
            }
            prev_dev = Some(dev);
            heads.insert(dev, seq);
        }
        Ok(Self { heads })
    }
}

/// The fixed-order fields of an op, before signing.
///
/// Field 5 (`prev_hash`) and field 12 (`signature`) are filled in during
/// authoring; this struct carries the version byte + fields 1..11 (including
/// `prev_hash` and the `observed` causal summary), and is signed to produce the
/// signature.
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
    /// Field 11: the observed-heads causal summary (sync-protocol.md §3), the
    /// version vector the merge derives true happens-before from.
    pub observed: ObservedHeads,
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
    /// Serialize the signed region (version byte + fields 1..11) to canonical
    /// wire bytes (sync-protocol.md §1 wire version 2).
    ///
    /// This is exactly the byte string the Ed25519 signature is computed over.
    #[must_use]
    pub fn signed_region_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(
            1 + 16 * 4
                + 8 * 2
                + 1
                + 4
                + 4
                + self.payload_env.len()
                + 32
                + self.observed.encoded_len(),
        );
        out.push(OP_WIRE_VERSION); // 0: wire-format version discriminator
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
        // 11: the observed-heads causal summary (u32 count + sorted entries).
        self.observed.encode_bytes_into(&mut out);
        out
    }

    /// Serialize the full canonical op (version byte + fields 1..12), appending
    /// the signature.
    ///
    /// This is the byte string the *next* op's `prev_hash` is the BLAKE3 of
    /// (sync-protocol.md §5, chain covers the whole canonical form).
    #[must_use]
    pub fn full_bytes(&self, signature: &[u8; 64]) -> Vec<u8> {
        let mut out = self.signed_region_bytes();
        out.extend_from_slice(signature); // 12
        out
    }

    /// The standalone canonical bytes of the observed-heads causal summary
    /// (field 11): `u32` count then sorted `device_id(16) || seq(u64 LE)`
    /// entries. This is what the `ops.observed` column stores, so the vector is
    /// reconstructable for chain verification and merge.
    #[must_use]
    pub fn observed_bytes(&self) -> Vec<u8> {
        self.observed.to_bytes()
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
            observed: ObservedHeads::new(),
        }
    }

    #[test]
    fn signed_region_layout_is_fixed_width() {
        let f = fields(1, 1, [0u8; 32]);
        let bytes = f.signed_region_bytes();
        // 1 (wire_ver) + 16*4 + 8 (seq) + 32 (prev) + 8 (lamport) + 1 (kind)
        // + 4 (ver) + 4 (payload len) + 3 (payload) + 4 (observed count, empty).
        let expected = 1 + 64 + 8 + 32 + 8 + 1 + 4 + 4 + 3 + 4;
        assert_eq!(bytes.len(), expected);
        // Version byte leads.
        assert_eq!(bytes[0], OP_WIRE_VERSION);
        // seq is at offset 1 + 48 = 49 (after the version byte and 3 ids), LE.
        assert_eq!(&bytes[49..57], &1u64.to_le_bytes());
    }

    #[test]
    fn observed_heads_canonical_bytes_are_sorted_and_stable() {
        // Insertion order must not affect canonical bytes (BTreeMap-sorted).
        let a = ObservedHeads::from_pairs([([9u8; 16], 3), ([1u8; 16], 7)]);
        let b = ObservedHeads::from_pairs([([1u8; 16], 7), ([9u8; 16], 3)]);
        let ba = a.to_bytes();
        let bb = b.to_bytes();
        assert_eq!(ba, bb, "observed-heads bytes are order-independent");
        // First entry is the smaller device_id ([1;16]), seq 7.
        assert_eq!(&ba[0..4], &2u32.to_le_bytes());
        assert_eq!(&ba[4..20], &[1u8; 16]);
        assert_eq!(&ba[20..28], &7u64.to_le_bytes());
    }

    #[test]
    fn observe_is_monotone() {
        let mut o = ObservedHeads::new();
        let d = Id::from_bytes([5u8; 16]);
        o.observe(&d, 4);
        o.observe(&d, 2); // lower seq must not lower the head
        assert_eq!(o.get(&d), 4);
        o.observe(&d, 9);
        assert_eq!(o.get(&d), 9);
    }

    #[test]
    fn changing_observed_breaks_signature() {
        let kp = SigningKeyPair::generate();
        let mut f = fields(1, 1, [7u8; 32]);
        f.observed.observe(&Id::from_bytes([2u8; 16]), 1);
        let sig = f.sign(&kp).unwrap();
        f.verify(&kp.verifying_key(), &sig).unwrap();
        // Mutating the causal summary invalidates the signature (it is signed).
        let mut f2 = f.clone();
        f2.observed.observe(&Id::from_bytes([3u8; 16]), 5);
        assert!(f2.verify(&kp.verifying_key(), &sig).is_err());
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
