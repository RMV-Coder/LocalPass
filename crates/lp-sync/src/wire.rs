//! Canonical op wire bytes (fields 1..11) and segment-file framing
//! (sync-protocol.md §1, §7.1).
//!
//! # Canonical op bytes (wire version 2)
//!
//! The single source of truth for the fixed-order, fixed-width op encoding is
//! `lp_vault::op::OpFields` (the version byte + fields 1..11 via
//! `signed_region_bytes`, plus the 64-byte signature = field 12 via
//! `full_bytes`). This module **reuses** that encoder for writing and provides
//! the exact-inverse decoder for reading, so the bytes an ingesting peer
//! verifies are byte-identical to the bytes the author signed and chained (no
//! divergent re-implementation).
//!
//! ```text
//!  0 wire_ver    u8         = 2
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
//! 11 observed    u32 count prefix || count × (device_id 16 || seq u64 LE)
//! 12 signature   64 bytes
//! ```
//!
//! # Segment body framing (§7.1)
//!
//! A `.oplog` segment body is a length-prefixed concatenation of these canonical
//! op byte strings: each op is `u32 LE length || <canonical op bytes 1..11>`.
//! The framing adds no security (ops are already E2EE + signed); it only lets a
//! reader split a multi-op file.

use lp_vault::StoredOp;
use lp_vault::ids::Id;
use lp_vault::op::{ItemTarget, OP_WIRE_VERSION, ObservedHeads, OpFields, OpKind};

use crate::error::{Error, Result};

/// The all-zero item target (vault-scope sentinel, sync-protocol.md §1).
const ZERO_ITEM: [u8; 16] = [0u8; 16];

/// Encode one [`StoredOp`] to its canonical wire bytes (fields 1..11).
///
/// Reuses `lp_vault::op::OpFields` so the bytes exactly match what the author
/// signed and hash-chained.
#[must_use]
pub fn encode_op(op: &StoredOp) -> Vec<u8> {
    let fields = to_op_fields(op);
    fields.full_bytes(&op.signature)
}

/// Build `OpFields` (fields 1..10 + prev_hash) from a [`StoredOp`].
fn to_op_fields(op: &StoredOp) -> OpFields {
    let target = match &op.target_item {
        Some(id) => ItemTarget::item(id),
        None => ItemTarget::none(),
    };
    OpFields {
        op_id: op.op_id,
        vault_id: op.vault_id,
        device_id: op.device_id,
        seq: op.seq,
        prev_hash: op.prev_hash,
        lamport: op.lamport,
        op_kind: op.op_kind,
        target_item: target,
        target_version: op.target_version,
        payload_env: op.payload_env.clone(),
        observed: op.observed.clone(),
    }
}

/// Decode canonical wire bytes (fields 1..11) back into a [`StoredOp`].
///
/// The inverse of [`encode_op`]. `created_at` is not on the wire (it is a local
/// insert-time field), so it is set to `0`; the applier stamps the real local
/// time. Validates every fixed-width field and the trailing signature length.
///
/// # Errors
///
/// [`Error::Malformed`] on any truncation, a bad `op_kind` byte, or a
/// `payload_env` length that overruns the buffer.
pub fn decode_op(bytes: &[u8]) -> Result<StoredOp> {
    let mut cur = Cursor::new(bytes);
    // Field 0: the wire-format version discriminator. Only v2 is accepted (no
    // released v1 ops exist; sync-protocol.md §1).
    let wire_ver = cur.take_u8()?;
    if wire_ver != OP_WIRE_VERSION {
        return Err(Error::Malformed("unsupported op wire version"));
    }
    let op_id = Id::from_bytes(cur.take_16()?);
    let vault_id = Id::from_bytes(cur.take_16()?);
    let device_id = Id::from_bytes(cur.take_16()?);
    let seq = cur.take_u64()?;
    let prev_hash = cur.take_32()?;
    let lamport = cur.take_u64()?;
    let op_kind = decode_kind(cur.take_u8()?)?;
    let target_bytes = cur.take_16()?;
    let target_item = if target_bytes == ZERO_ITEM {
        None
    } else {
        Some(Id::from_bytes(target_bytes))
    };
    let target_version = cur.take_u32()?;
    let payload_len = cur.take_u32()? as usize;
    let payload_env = cur.take_n(payload_len)?.to_vec();
    // Field 11: the observed-heads causal summary (u32 count + fixed-width
    // entries). Read the count, then the exact entry span, then decode.
    let observed_count = cur.take_u32()? as usize;
    let observed_body_len = observed_count
        .checked_mul(16 + 8)
        .ok_or(Error::Malformed("observed-heads length overflow"))?;
    let observed_body = cur.take_n(observed_body_len)?;
    let observed = decode_observed(observed_count, observed_body)?;
    let signature = cur.take_64()?;
    if !cur.is_empty() {
        return Err(Error::Malformed("trailing bytes after op"));
    }
    Ok(StoredOp {
        op_id,
        vault_id,
        device_id,
        seq,
        prev_hash,
        lamport,
        op_kind,
        target_item,
        target_version,
        payload_env,
        observed,
        signature,
        created_at: 0,
    })
}

/// Decode the observed-heads field from its `(count, body)` split, reusing
/// `lp_vault::op::ObservedHeads::decode` so the canonical-ordering check is the
/// single authoritative implementation.
fn decode_observed(count: usize, body: &[u8]) -> Result<ObservedHeads> {
    // Reassemble the full canonical encoding (count prefix + body) and hand it
    // to the authoritative decoder.
    let mut full = Vec::with_capacity(4 + body.len());
    full.extend_from_slice(&u32::try_from(count).unwrap_or(u32::MAX).to_le_bytes());
    full.extend_from_slice(body);
    ObservedHeads::decode(&full).map_err(|_| Error::Malformed("malformed observed-heads vector"))
}

/// Frame a run of ops into a segment-file body: `u32 LE len || op-bytes` each.
#[must_use]
pub fn encode_segment(ops: &[StoredOp]) -> Vec<u8> {
    let mut out = Vec::new();
    for op in ops {
        let bytes = encode_op(op);
        let len = u32::try_from(bytes.len()).expect("op bytes fit in u32");
        out.extend_from_slice(&len.to_le_bytes());
        out.extend_from_slice(&bytes);
    }
    out
}

/// Parse a segment-file body back into its ops (the inverse of
/// [`encode_segment`]).
///
/// # Errors
///
/// [`Error::Malformed`] on a truncated frame or a bad inner op encoding.
pub fn decode_segment(body: &[u8]) -> Result<Vec<StoredOp>> {
    let mut cur = Cursor::new(body);
    let mut ops = Vec::new();
    while !cur.is_empty() {
        let len = cur.take_u32()? as usize;
        let op_bytes = cur.take_n(len)?;
        ops.push(decode_op(op_bytes)?);
    }
    Ok(ops)
}

/// Map an op-kind wire byte to [`OpKind`] (covers kinds 1..7, sync-protocol.md
/// §2 — Create..Rewrap plus AttachAdd/AttachDelete).
fn decode_kind(b: u8) -> Result<OpKind> {
    OpKind::from_code(b).ok_or(Error::Malformed("unknown op_kind byte"))
}

/// A minimal forward-only byte cursor with length-checked takes.
struct Cursor<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    fn is_empty(&self) -> bool {
        self.pos >= self.buf.len()
    }

    fn take_n(&mut self, n: usize) -> Result<&'a [u8]> {
        let end = self
            .pos
            .checked_add(n)
            .ok_or(Error::Malformed("length overflow"))?;
        if end > self.buf.len() {
            return Err(Error::Malformed("truncated op bytes"));
        }
        let slice = &self.buf[self.pos..end];
        self.pos = end;
        Ok(slice)
    }

    fn take_u8(&mut self) -> Result<u8> {
        Ok(self.take_n(1)?[0])
    }

    fn take_u32(&mut self) -> Result<u32> {
        let b: [u8; 4] = self.take_n(4)?.try_into().unwrap();
        Ok(u32::from_le_bytes(b))
    }

    fn take_u64(&mut self) -> Result<u64> {
        let b: [u8; 8] = self.take_n(8)?.try_into().unwrap();
        Ok(u64::from_le_bytes(b))
    }

    fn take_16(&mut self) -> Result<[u8; 16]> {
        Ok(self.take_n(16)?.try_into().unwrap())
    }

    fn take_32(&mut self) -> Result<[u8; 32]> {
        Ok(self.take_n(32)?.try_into().unwrap())
    }

    fn take_64(&mut self) -> Result<[u8; 64]> {
        Ok(self.take_n(64)?.try_into().unwrap())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_op(seq: u64, lamport: u64) -> StoredOp {
        StoredOp {
            op_id: Id::from_bytes([1u8; 16]),
            vault_id: Id::from_bytes([2u8; 16]),
            device_id: Id::from_bytes([3u8; 16]),
            seq,
            prev_hash: [7u8; 32],
            lamport,
            op_kind: OpKind::Update,
            target_item: Some(Id::from_bytes([4u8; 16])),
            target_version: 5,
            payload_env: vec![0xAB, 0xCD, 0xEF],
            observed: ObservedHeads::from_pairs([
                ([3u8; 16], seq.saturating_sub(1)),
                ([8u8; 16], 2),
            ]),
            signature: [9u8; 64],
            created_at: 0,
        }
    }

    #[test]
    fn op_roundtrips_through_wire() {
        let op = sample_op(1, 1);
        let bytes = encode_op(&op);
        let back = decode_op(&bytes).unwrap();
        assert_eq!(back.op_id.as_bytes(), op.op_id.as_bytes());
        assert_eq!(back.seq, op.seq);
        assert_eq!(back.lamport, op.lamport);
        assert_eq!(back.target_version, op.target_version);
        assert_eq!(back.payload_env, op.payload_env);
        assert_eq!(back.signature, op.signature);
        assert_eq!(back.observed, op.observed);
        assert_eq!(
            back.target_item.unwrap().as_bytes(),
            op.target_item.unwrap().as_bytes()
        );
    }

    #[test]
    fn vault_scope_target_roundtrips_as_none() {
        let mut op = sample_op(1, 1);
        op.target_item = None;
        let back = decode_op(&encode_op(&op)).unwrap();
        assert!(back.target_item.is_none());
    }

    #[test]
    fn segment_roundtrips_multiple_ops() {
        let ops = vec![sample_op(1, 1), sample_op(2, 2), sample_op(3, 4)];
        let body = encode_segment(&ops);
        let back = decode_segment(&body).unwrap();
        assert_eq!(back.len(), 3);
        assert_eq!(back[1].seq, 2);
        assert_eq!(back[2].lamport, 4);
    }

    #[test]
    fn truncated_segment_is_malformed() {
        let ops = vec![sample_op(1, 1)];
        let mut body = encode_segment(&ops);
        body.truncate(body.len() - 4);
        assert!(matches!(decode_segment(&body), Err(Error::Malformed(_))));
    }

    #[test]
    fn decode_rejects_bad_kind() {
        let mut bytes = encode_op(&sample_op(1, 1));
        // op_kind byte is at offset 1(wire_ver) + 16*3 + 8(seq) + 32(prev)
        // + 8(lamport) = 97.
        bytes[97] = 99;
        assert!(matches!(decode_op(&bytes), Err(Error::Malformed(_))));
    }

    #[test]
    fn decode_rejects_bad_wire_version() {
        let mut bytes = encode_op(&sample_op(1, 1));
        bytes[0] = 1; // pretend it is the retired v1 layout
        assert!(matches!(decode_op(&bytes), Err(Error::Malformed(_))));
    }
}
