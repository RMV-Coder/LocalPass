//! Canonical op wire bytes (fields 1..11) and segment-file framing
//! (sync-protocol.md §1, §7.1).
//!
//! # Canonical op bytes
//!
//! The single source of truth for the fixed-order, fixed-width op encoding is
//! `lp_vault::op::OpFields` (fields 1..10 via `signed_region_bytes`, plus the
//! 64-byte signature = field 11 via `full_bytes`). This module **reuses** that
//! encoder for writing and provides the exact-inverse decoder for reading, so
//! the bytes an ingesting peer verifies are byte-identical to the bytes the
//! author signed and chained (no divergent re-implementation).
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
//! 11 signature   64 bytes
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
use lp_vault::op::{ItemTarget, OpFields, OpKind};

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
        signature,
        created_at: 0,
    })
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

/// Map an op-kind wire byte to [`OpKind`].
fn decode_kind(b: u8) -> Result<OpKind> {
    match b {
        1 => Ok(OpKind::Create),
        2 => Ok(OpKind::Update),
        3 => Ok(OpKind::Delete),
        4 => Ok(OpKind::Restore),
        5 => Ok(OpKind::Rewrap),
        _ => Err(Error::Malformed("unknown op_kind byte")),
    }
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
        // op_kind byte is at offset 16*3 + 8(seq) + 32(prev) + 8(lamport) = 96.
        bytes[96] = 99;
        assert!(matches!(decode_op(&bytes), Err(Error::Malformed(_))));
    }
}
