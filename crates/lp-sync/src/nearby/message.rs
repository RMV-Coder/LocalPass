//! Application message types, size caps and body codecs
//! (`lan-transport.md` §5.2, §6.2).
//!
//! Bodies are fixed-width little-endian integers and raw 16/32-byte ids. Every
//! decoder checks counts against the protocol limits before allocating, and
//! requires lists to be strictly ascending (no duplicates, one canonical
//! encoding). `OPS` bodies reuse the `.oplog` segment framing from
//! [`crate::wire`] byte for byte.

use std::collections::BTreeMap;

use lp_vault::StoredOp;
use lp_vault::ids::{Id, VaultId};

use super::{MAX_HEADS, MAX_SHARES, MAX_VAULTS, MAX_WANTED_BLOBS};
use crate::error::{Error, Result};
use crate::wire;

/// `type u8 || body_len u32 LE` at the start of a message's first record.
pub(super) const MESSAGE_HEADER_LEN: usize = 5;

/// Signed vault-key shares.
pub(super) const MSG_HELLO: u8 = 0x01;
/// Vaults held, with per-device seq heads.
pub(super) const MSG_INVENTORY: u8 = 0x02;
/// A batch of canonical op bytes for one vault.
pub(super) const MSG_OPS: u8 = 0x03;
/// End of this side's ops.
pub(super) const MSG_OPS_END: u8 = 0x04;
/// Attachment blobs this side still lacks.
pub(super) const MSG_BLOB_WANT: u8 = 0x05;
/// One attachment blob.
pub(super) const MSG_BLOB: u8 = 0x06;
/// End of this side's blobs.
pub(super) const MSG_BLOBS_END: u8 = 0x07;
/// The session finished.
pub(super) const MSG_DONE: u8 = 0x08;

/// Cap for the control messages.
const CONTROL_CAP: usize = 4 * 1024 * 1024;
/// Cap for one `OPS` message.
const OPS_CAP: usize = 16 * 1024 * 1024;
/// `vault_id (16) || hash (32)` ahead of a blob's bytes.
const BLOB_HEADER_LEN: usize = 16 + 32;

/// The largest body a message of `kind` may declare, or `None` for an unknown
/// type (§5.2).
pub(super) fn cap_for(kind: u8) -> Option<usize> {
    match kind {
        MSG_HELLO | MSG_INVENTORY | MSG_BLOB_WANT => Some(CONTROL_CAP),
        MSG_OPS => Some(OPS_CAP),
        MSG_BLOB => Some(lp_vault::MAX_ATTACHMENT_BYTES + BLOB_HEADER_LEN),
        MSG_OPS_END | MSG_BLOBS_END | MSG_DONE => Some(0),
        _ => None,
    }
}

/// Per vault id, per author device id, the highest seq held.
pub(super) type Inventory = BTreeMap<[u8; 16], BTreeMap<[u8; 16], u64>>;

/// Per vault id, the blob hashes wanted (ascending).
pub(super) type BlobWants = BTreeMap<[u8; 16], Vec<[u8; 32]>>;

// --- Encoders ----------------------------------------------------------------

fn put_u16(out: &mut Vec<u8>, n: usize) -> Result<()> {
    let n = u16::try_from(n).map_err(|_| Error::Protocol("list too long"))?;
    out.extend_from_slice(&n.to_le_bytes());
    Ok(())
}

fn put_u32(out: &mut Vec<u8>, n: usize) -> Result<()> {
    let n = u32::try_from(n).map_err(|_| Error::Protocol("length too long"))?;
    out.extend_from_slice(&n.to_le_bytes());
    Ok(())
}

/// `HELLO`: `u16 n || n × (vault_id || u32 len || share blob)`.
pub(super) fn encode_hello(shares: &[(VaultId, Vec<u8>)]) -> Result<Vec<u8>> {
    if shares.len() > MAX_SHARES {
        return Err(Error::Invalid("too many vaults to share in one session"));
    }
    let mut out = Vec::new();
    put_u16(&mut out, shares.len())?;
    for (vault_id, blob) in shares {
        out.extend_from_slice(vault_id.as_bytes());
        put_u32(&mut out, blob.len())?;
        out.extend_from_slice(blob);
    }
    Ok(out)
}

/// `INVENTORY`: `u16 n || n × (vault_id || u16 m || m × (device_id || u64 seq))`.
pub(super) fn encode_inventory(inv: &Inventory) -> Result<Vec<u8>> {
    if inv.len() > MAX_VAULTS {
        return Err(Error::Invalid("too many vaults for one nearby session"));
    }
    let mut out = Vec::new();
    put_u16(&mut out, inv.len())?;
    for (vault_id, heads) in inv {
        if heads.len() > MAX_HEADS {
            return Err(Error::Invalid("too many devices in one vault"));
        }
        out.extend_from_slice(vault_id);
        put_u16(&mut out, heads.len())?;
        for (device, seq) in heads {
            out.extend_from_slice(device);
            out.extend_from_slice(&seq.to_le_bytes());
        }
    }
    Ok(out)
}

/// `OPS`: `vault_id || segment body` (§7.1 framing).
pub(super) fn encode_ops(vault_id: &VaultId, ops: &[StoredOp]) -> Vec<u8> {
    let mut out = Vec::with_capacity(16);
    out.extend_from_slice(vault_id.as_bytes());
    out.extend_from_slice(&wire::encode_segment(ops));
    out
}

/// `BLOB_WANT`: `u16 n || n × (vault_id || u32 k || k × hash)`.
pub(super) fn encode_blob_want(wants: &BlobWants) -> Result<Vec<u8>> {
    let total: usize = wants.values().map(Vec::len).sum();
    if total > MAX_WANTED_BLOBS || wants.len() > MAX_VAULTS {
        return Err(Error::Invalid(
            "too many missing attachments for one session",
        ));
    }
    let mut out = Vec::new();
    put_u16(&mut out, wants.len())?;
    for (vault_id, hashes) in wants {
        out.extend_from_slice(vault_id);
        put_u32(&mut out, hashes.len())?;
        for h in hashes {
            out.extend_from_slice(h);
        }
    }
    Ok(out)
}

/// `BLOB`: `vault_id || hash || bytes`.
pub(super) fn encode_blob(vault_id: &VaultId, hash: &[u8; 32], bytes: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(BLOB_HEADER_LEN + bytes.len());
    out.extend_from_slice(vault_id.as_bytes());
    out.extend_from_slice(hash);
    out.extend_from_slice(bytes);
    out
}

// --- Decoders ----------------------------------------------------------------

/// A forward-only cursor whose every take is length-checked.
struct Cursor<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        let end = self
            .pos
            .checked_add(n)
            .filter(|e| *e <= self.buf.len())
            .ok_or(Error::Protocol("truncated message body"))?;
        let s = &self.buf[self.pos..end];
        self.pos = end;
        Ok(s)
    }

    fn u16(&mut self) -> Result<usize> {
        Ok(usize::from(u16::from_le_bytes(
            self.take(2)?.try_into().expect("2 bytes"),
        )))
    }

    fn u32(&mut self) -> Result<usize> {
        Ok(u32::from_le_bytes(self.take(4)?.try_into().expect("4 bytes")) as usize)
    }

    fn u64(&mut self) -> Result<u64> {
        Ok(u64::from_le_bytes(
            self.take(8)?.try_into().expect("8 bytes"),
        ))
    }

    fn id(&mut self) -> Result<[u8; 16]> {
        Ok(self.take(16)?.try_into().expect("16 bytes"))
    }

    fn hash(&mut self) -> Result<[u8; 32]> {
        Ok(self.take(32)?.try_into().expect("32 bytes"))
    }

    fn rest(&mut self) -> &'a [u8] {
        let s = &self.buf[self.pos..];
        self.pos = self.buf.len();
        s
    }

    fn finish(&self) -> Result<()> {
        if self.pos == self.buf.len() {
            Ok(())
        } else {
            Err(Error::Protocol("trailing bytes after a message body"))
        }
    }
}

/// Require `next` to sort strictly after `prev`.
fn ascending<T: Ord>(prev: Option<&T>, next: &T) -> Result<()> {
    if prev.is_some_and(|p| p >= next) {
        return Err(Error::Protocol("a list is not strictly ascending"));
    }
    Ok(())
}

/// Decode `HELLO`.
pub(super) fn decode_hello(body: &[u8]) -> Result<Vec<(VaultId, Vec<u8>)>> {
    let mut c = Cursor::new(body);
    let n = c.u16()?;
    if n > MAX_SHARES {
        return Err(Error::Protocol("too many shares"));
    }
    let mut out: Vec<(VaultId, Vec<u8>)> = Vec::with_capacity(n);
    for _ in 0..n {
        let vault = c.id()?;
        ascending(out.last().map(|(v, _)| v.as_bytes()), &vault)?;
        let len = c.u32()?;
        let blob = c.take(len)?.to_vec();
        out.push((Id::from_bytes(vault), blob));
    }
    c.finish()?;
    Ok(out)
}

/// Decode `INVENTORY`.
pub(super) fn decode_inventory(body: &[u8]) -> Result<Inventory> {
    let mut c = Cursor::new(body);
    let n = c.u16()?;
    if n > MAX_VAULTS {
        return Err(Error::Protocol("too many vaults"));
    }
    let mut out = Inventory::new();
    let mut prev_vault: Option<[u8; 16]> = None;
    for _ in 0..n {
        let vault = c.id()?;
        ascending(prev_vault.as_ref(), &vault)?;
        prev_vault = Some(vault);
        let m = c.u16()?;
        if m > MAX_HEADS {
            return Err(Error::Protocol("too many device heads"));
        }
        let mut heads = BTreeMap::new();
        let mut prev_dev: Option<[u8; 16]> = None;
        for _ in 0..m {
            let dev = c.id()?;
            ascending(prev_dev.as_ref(), &dev)?;
            prev_dev = Some(dev);
            heads.insert(dev, c.u64()?);
        }
        out.insert(vault, heads);
    }
    c.finish()?;
    Ok(out)
}

/// Decode `OPS`: the vault id and its ops, each of which must belong to it.
pub(super) fn decode_ops(body: &[u8]) -> Result<(VaultId, Vec<StoredOp>)> {
    let mut c = Cursor::new(body);
    let vault_id = Id::from_bytes(c.id()?);
    let ops = wire::decode_segment(c.rest())
        .map_err(|_| Error::Protocol("malformed op in an OPS message"))?;
    if ops.iter().any(|o| o.vault_id != vault_id) {
        return Err(Error::Protocol("an OPS message carried another vault's op"));
    }
    Ok((vault_id, ops))
}

/// Decode `BLOB_WANT`.
pub(super) fn decode_blob_want(body: &[u8]) -> Result<BlobWants> {
    let mut c = Cursor::new(body);
    let n = c.u16()?;
    if n > MAX_VAULTS {
        return Err(Error::Protocol("too many vaults"));
    }
    let mut out = BlobWants::new();
    let mut total = 0usize;
    let mut prev_vault: Option<[u8; 16]> = None;
    for _ in 0..n {
        let vault = c.id()?;
        ascending(prev_vault.as_ref(), &vault)?;
        prev_vault = Some(vault);
        let k = c.u32()?;
        total = total.saturating_add(k);
        if total > MAX_WANTED_BLOBS {
            return Err(Error::Protocol("too many wanted blobs"));
        }
        let mut hashes: Vec<[u8; 32]> = Vec::with_capacity(k);
        for _ in 0..k {
            let h = c.hash()?;
            ascending(hashes.last(), &h)?;
            hashes.push(h);
        }
        out.insert(vault, hashes);
    }
    c.finish()?;
    Ok(out)
}

/// Decode `BLOB`.
pub(super) fn decode_blob(body: &[u8]) -> Result<(VaultId, [u8; 32], &[u8])> {
    let mut c = Cursor::new(body);
    let vault = Id::from_bytes(c.id()?);
    let hash = c.hash()?;
    Ok((vault, hash, c.rest()))
}

/// Lowercase hex of a 32-byte hash (the form `lp-vault`'s attachment API
/// takes).
pub(super) fn hash_hex(hash: &[u8; 32]) -> String {
    use std::fmt::Write as _;
    let mut s = String::with_capacity(64);
    for b in hash {
        let _ = write!(s, "{b:02x}");
    }
    s
}

/// Parse a 64-char hex hash; `None` on anything else.
pub(super) fn hash_from_hex(s: &str) -> Option<[u8; 32]> {
    if s.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for (i, b) in out.iter_mut().enumerate() {
        *b = u8::from_str_radix(s.get(i * 2..i * 2 + 2)?, 16).ok()?;
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn vid(b: u8) -> VaultId {
        Id::from_bytes([b; 16])
    }

    #[test]
    fn inventory_round_trips() {
        let mut inv = Inventory::new();
        inv.insert(
            [1u8; 16],
            BTreeMap::from([([2u8; 16], 5u64), ([3u8; 16], 9u64)]),
        );
        inv.insert([4u8; 16], BTreeMap::new());
        let back = decode_inventory(&encode_inventory(&inv).unwrap()).unwrap();
        assert_eq!(back, inv);
    }

    #[test]
    fn hello_and_blob_want_round_trip() {
        let shares = vec![(vid(1), b"LPS2-a".to_vec()), (vid(2), b"LPS2-b".to_vec())];
        assert_eq!(
            decode_hello(&encode_hello(&shares).unwrap()).unwrap(),
            shares
        );
        let mut wants = BlobWants::new();
        wants.insert([1u8; 16], vec![[1u8; 32], [2u8; 32]]);
        assert_eq!(
            decode_blob_want(&encode_blob_want(&wants).unwrap()).unwrap(),
            wants
        );
    }

    #[test]
    fn unsorted_or_duplicate_lists_are_refused() {
        let shares = vec![(vid(2), vec![1]), (vid(1), vec![2])];
        assert!(decode_hello(&encode_hello(&shares).unwrap()).is_err());
        let dup = vec![(vid(1), vec![1]), (vid(1), vec![2])];
        assert!(decode_hello(&encode_hello(&dup).unwrap()).is_err());
    }

    #[test]
    fn counts_beyond_the_limits_are_refused_before_allocation() {
        // An INVENTORY claiming 65535 vaults in a 2-byte body.
        assert!(decode_inventory(&u16::MAX.to_le_bytes()).is_err());
        // A HELLO claiming one share of 4 GiB.
        let mut body = 1u16.to_le_bytes().to_vec();
        body.extend_from_slice(&[0u8; 16]);
        body.extend_from_slice(&u32::MAX.to_le_bytes());
        assert!(matches!(
            decode_hello(&body),
            Err(Error::Protocol("truncated message body"))
        ));
        // A BLOB_WANT claiming more hashes than the protocol allows.
        let mut body = 1u16.to_le_bytes().to_vec();
        body.extend_from_slice(&[0u8; 16]);
        body.extend_from_slice(&u32::try_from(MAX_WANTED_BLOBS + 1).unwrap().to_le_bytes());
        assert!(matches!(
            decode_blob_want(&body),
            Err(Error::Protocol("too many wanted blobs"))
        ));
    }

    #[test]
    fn trailing_bytes_are_refused() {
        let mut body = encode_inventory(&Inventory::new()).unwrap();
        body.push(0);
        assert!(decode_inventory(&body).is_err());
    }

    #[test]
    fn caps_cover_every_type_and_nothing_else() {
        for kind in 1..=8u8 {
            assert!(cap_for(kind).is_some(), "type {kind}");
        }
        assert!(cap_for(0).is_none());
        assert!(cap_for(9).is_none());
        assert_eq!(cap_for(MSG_DONE), Some(0));
    }

    #[test]
    fn hash_hex_round_trips() {
        let h = [0xabu8; 32];
        assert_eq!(hash_from_hex(&hash_hex(&h)), Some(h));
        assert_eq!(hash_from_hex("zz"), None);
    }
}
