//! File-based log shipping (sync-protocol.md §7) — Part C.
//!
//! The encrypted op log is written as immutable append-only segment files that
//! **any dumb file channel** (Syncthing, USB, a network share) can replicate.
//! Zero networking in the critical path; the channel is fully untrusted — §5
//! verification (in [`crate::verify`]) is what protects it.
//!
//! # Layout (§7.1)
//!
//! ```text
//! <sync-root>/<vault_id>/
//!   manifest.json                          -- plaintext, advisory, NOT trusted
//!   ops/<device_id>/<device_id>-<lo>-<hi>.oplog
//!   chain/<device_id>.head                 -- last seq + head hash published
//!   keys/<device_id>-<vault_id>.wrapped    -- sealed VaultKey for a peer (Part D)
//! ```
//!
//! Per-device subdirectories mean two devices writing concurrently never touch
//! the same file (append-only, no write conflicts on the dumb channel). A
//! segment is immutable once written; a device appends by writing a **new**
//! segment for the next `seq` range.
//!
//! # The manifest is advisory only (§7.2)
//!
//! `manifest.json` lists device ids and their highest published `seq` — a
//! discovery hint. It is plaintext and unauthenticated; readers treat it as a
//! hint and trust only §5 verification of the actual segments, so a forged
//! manifest can at worst point at segments that then fail chain checks — it can
//! never inject state.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use lp_vault::StoredOp;
use lp_vault::ids::{DeviceId, Id, VaultId};
use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};
use crate::wire;

/// The per-vault subdirectory names.
const OPS_DIR: &str = "ops";
const CHAIN_DIR: &str = "chain";
const KEYS_DIR: &str = "keys";
const ATTACH_DIR: &str = "attachments";
const MANIFEST_FILE: &str = "manifest.json";
const OPLOG_EXT: &str = "oplog";
const BLOB_EXT: &str = "blob";

/// The advisory, plaintext channel manifest (sync-protocol.md §7.2).
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct Manifest {
    /// The vault id (hyphenated UUID), for a human reading the file.
    pub vault_id: String,
    /// Per device (hyphenated UUID) → highest published `seq`. **Advisory.**
    pub devices: BTreeMap<String, u64>,
}

/// A discovered segment file: its author, inclusive `[seq_lo, seq_hi]`, path.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SegmentFile {
    /// The authoring device.
    pub device_id: DeviceId,
    /// Inclusive low seq of the range in this file.
    pub seq_lo: u64,
    /// Inclusive high seq of the range in this file.
    pub seq_hi: u64,
    /// The file path.
    pub path: PathBuf,
}

/// The on-disk sync directory for one vault (`<sync-root>/<vault_id>/`).
pub struct SyncDir {
    root: PathBuf,
    vault_id: VaultId,
}

impl SyncDir {
    /// Bind (and create) the per-vault sync directory under `sync_root`.
    ///
    /// # Errors
    ///
    /// [`Error::Io`] if the directories cannot be created.
    pub fn open(sync_root: &Path, vault_id: VaultId) -> Result<Self> {
        let root = sync_root.join(vault_id.to_hyphenated());
        fs::create_dir_all(root.join(OPS_DIR))?;
        fs::create_dir_all(root.join(CHAIN_DIR))?;
        fs::create_dir_all(root.join(KEYS_DIR))?;
        Ok(Self { root, vault_id })
    }

    /// The per-vault root path.
    #[must_use]
    pub fn root(&self) -> &Path {
        &self.root
    }

    // --- Writer (§7.1) ----------------------------------------------------

    /// Write a device's ops as one immutable segment file
    /// `ops/<device_id>/<device_id>-<lo>-<hi>.oplog`. `ops` must be a single
    /// device's contiguous `seq` run in ascending order.
    ///
    /// Skips writing (returns `Ok(None)`) if a segment covering exactly this
    /// range already exists (idempotent re-push) or `ops` is empty.
    ///
    /// # Errors
    ///
    /// [`Error::Invalid`] if `ops` spans multiple devices or is non-contiguous;
    /// [`Error::Io`] on a write failure.
    pub fn write_segment(&self, ops: &[StoredOp]) -> Result<Option<SegmentFile>> {
        let Some(first) = ops.first() else {
            return Ok(None);
        };
        let device_id = first.device_id;
        for (expect, op) in (first.seq..).zip(ops.iter()) {
            if op.device_id.as_bytes() != device_id.as_bytes() {
                return Err(Error::Invalid("segment spans multiple devices"));
            }
            if op.seq != expect {
                return Err(Error::Invalid("segment ops are not contiguous"));
            }
        }
        let seq_lo = first.seq;
        let seq_hi = ops.last().unwrap().seq;

        let dev_dir = self.root.join(OPS_DIR).join(device_id.to_hyphenated());
        fs::create_dir_all(&dev_dir)?;
        let name = format!(
            "{}-{seq_lo}-{seq_hi}.{OPLOG_EXT}",
            device_id.to_hyphenated()
        );
        let path = dev_dir.join(name);
        if path.exists() {
            return Ok(Some(SegmentFile {
                device_id,
                seq_lo,
                seq_hi,
                path,
            }));
        }
        let body = wire::encode_segment(ops);
        write_atomic(&path, &body)?;
        Ok(Some(SegmentFile {
            device_id,
            seq_lo,
            seq_hi,
            path,
        }))
    }

    /// Update `chain/<device_id>.head` with the last published seq + head hash
    /// (store-and-forward bookkeeping; sync-protocol.md §7.3 step 4).
    ///
    /// # Errors
    ///
    /// [`Error::Io`] on a write failure.
    pub fn write_head(&self, device_id: &DeviceId, seq: u64, head_hash: &[u8; 32]) -> Result<()> {
        let head = HeadFile {
            seq,
            head_hash_hex: hex(head_hash),
        };
        let path = self
            .root
            .join(CHAIN_DIR)
            .join(format!("{}.head", device_id.to_hyphenated()));
        write_atomic(&path, serde_json::to_vec_pretty(&head)?.as_slice())?;
        Ok(())
    }

    /// Write (or overwrite) the advisory manifest (§7.2).
    ///
    /// # Errors
    ///
    /// [`Error::Io`] on a write failure.
    pub fn write_manifest(&self, manifest: &Manifest) -> Result<()> {
        let path = self.root.join(MANIFEST_FILE);
        write_atomic(&path, serde_json::to_vec_pretty(manifest)?.as_slice())?;
        Ok(())
    }

    /// Ship a sealed VaultKey blob for a peer to `keys/<peer>-<vault>.wrapped`
    /// (Part D key sharing; the seal itself is done by the caller).
    ///
    /// # Errors
    ///
    /// [`Error::Io`] on a write failure.
    pub fn write_key_blob(&self, peer_device_id: &DeviceId, sealed: &[u8]) -> Result<()> {
        let name = format!(
            "{}-{}.wrapped",
            peer_device_id.to_hyphenated(),
            self.vault_id.to_hyphenated()
        );
        let path = self.root.join(KEYS_DIR).join(name);
        write_atomic(&path, sealed)?;
        Ok(())
    }

    /// Read the sealed VaultKey blob addressed to `me`, if present.
    ///
    /// # Errors
    ///
    /// [`Error::Io`] on a read failure other than not-found.
    pub fn read_key_blob(&self, me: &DeviceId) -> Result<Option<Vec<u8>>> {
        let name = format!(
            "{}-{}.wrapped",
            me.to_hyphenated(),
            self.vault_id.to_hyphenated()
        );
        let path = self.root.join(KEYS_DIR).join(name);
        match fs::read(&path) {
            Ok(bytes) => Ok(Some(bytes)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(Error::Io(e)),
        }
    }

    // --- Attachment blobs (§7 file channel, content-addressed) ------------

    /// Write a content-addressed attachment blob to
    /// `attachments/<content_hash_hex>.blob`. Immutable once written — a blob
    /// already present is a byte-identical rewrite (content-addressed), so this
    /// is idempotent. The caller ships already-encrypted bytes; the channel adds
    /// no security (the content hash is verified on read by the vault).
    ///
    /// # Errors
    ///
    /// [`Error::Io`] on a write failure.
    pub fn write_attachment_blob(&self, content_hash_hex: &str, bytes: &[u8]) -> Result<()> {
        let dir = self.root.join(ATTACH_DIR);
        fs::create_dir_all(&dir)?;
        let path = dir.join(format!("{content_hash_hex}.{BLOB_EXT}"));
        write_atomic(&path, bytes)?;
        Ok(())
    }

    /// Read a content-addressed attachment blob from the sync dir, or `None` if
    /// the peer has not shipped it yet (the referenced-but-pending state).
    ///
    /// # Errors
    ///
    /// [`Error::Io`] on a read failure other than not-found.
    pub fn read_attachment_blob(&self, content_hash_hex: &str) -> Result<Option<Vec<u8>>> {
        let path = self
            .root
            .join(ATTACH_DIR)
            .join(format!("{content_hash_hex}.{BLOB_EXT}"));
        match fs::read(&path) {
            Ok(bytes) => Ok(Some(bytes)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(Error::Io(e)),
        }
    }

    /// List the `content_hash` (hex) of every attachment blob present in the
    /// sync dir. Used to skip already-shipped blobs on push.
    ///
    /// # Errors
    ///
    /// [`Error::Io`] on a directory read failure other than not-found.
    pub fn list_attachment_blob_hashes(&self) -> Result<Vec<String>> {
        let dir = self.root.join(ATTACH_DIR);
        let mut out = Vec::new();
        let entries = match fs::read_dir(&dir) {
            Ok(e) => e,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(out),
            Err(e) => return Err(Error::Io(e)),
        };
        for entry in entries {
            let path = entry?.path();
            if path.extension().and_then(|e| e.to_str()) != Some(BLOB_EXT) {
                continue;
            }
            if let Some(stem) = path.file_stem().and_then(|s| s.to_str()) {
                out.push(stem.to_string());
            }
        }
        Ok(out)
    }

    /// Remove the sealed VaultKey blob addressed to `me` after a successful
    /// import (the blob is per-recipient, so removal affects no other device).
    /// Missing file is a no-op.
    ///
    /// # Errors
    ///
    /// [`Error::Io`] on a removal failure other than not-found.
    pub fn remove_key_blob(&self, me: &DeviceId) -> Result<()> {
        let name = format!(
            "{}-{}.wrapped",
            me.to_hyphenated(),
            self.vault_id.to_hyphenated()
        );
        let path = self.root.join(KEYS_DIR).join(name);
        match fs::remove_file(&path) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(Error::Io(e)),
        }
    }

    // --- Reader (§7.3) ----------------------------------------------------

    /// Discover every segment file under `ops/`, grouped and sorted per device
    /// by `seq_lo` (sync-protocol.md §7.3 step 1). Malformed file names are
    /// skipped (a dumb channel may drop unrelated files in).
    ///
    /// # Errors
    ///
    /// [`Error::Io`] on a directory read failure.
    pub fn list_segments(&self) -> Result<BTreeMap<[u8; 16], Vec<SegmentFile>>> {
        let mut by_device: BTreeMap<[u8; 16], Vec<SegmentFile>> = BTreeMap::new();
        let ops_root = self.root.join(OPS_DIR);
        let Ok(dev_dirs) = fs::read_dir(&ops_root) else {
            return Ok(by_device);
        };
        for dev_entry in dev_dirs {
            let dev_entry = dev_entry?;
            if !dev_entry.file_type()?.is_dir() {
                continue;
            }
            for seg in fs::read_dir(dev_entry.path())? {
                let seg = seg?;
                let path = seg.path();
                if path.extension().and_then(|e| e.to_str()) != Some(OPLOG_EXT) {
                    continue;
                }
                if let Some(sf) = parse_segment_name(&path) {
                    by_device
                        .entry(*sf.device_id.as_bytes())
                        .or_default()
                        .push(sf);
                }
            }
        }
        for segs in by_device.values_mut() {
            segs.sort_by_key(|s| s.seq_lo);
        }
        Ok(by_device)
    }

    /// Read + decode all ops from every segment, in per-device `seq_lo` order
    /// (sync-protocol.md §7.3 step 1–2). The returned ops are fed straight into
    /// the §5 verifier. Duplicate `seq`s across overlapping segments are kept
    /// (the verifier de-dups idempotently by `op_id`).
    ///
    /// # Errors
    ///
    /// [`Error::Io`] / [`Error::Malformed`] on a bad segment.
    pub fn read_all_ops(&self) -> Result<Vec<StoredOp>> {
        let segments = self.list_segments()?;
        let mut ops = Vec::new();
        for segs in segments.values() {
            for sf in segs {
                let body = fs::read(&sf.path)?;
                ops.extend(wire::decode_segment(&body)?);
            }
        }
        Ok(ops)
    }

    /// Read the advisory manifest, or an empty default if absent/unparseable
    /// (it is only a hint; a broken manifest never blocks a pull).
    #[must_use]
    pub fn read_manifest(&self) -> Manifest {
        let path = self.root.join(MANIFEST_FILE);
        fs::read(path)
            .ok()
            .and_then(|b| serde_json::from_slice(&b).ok())
            .unwrap_or_default()
    }
}

/// The `chain/<device>.head` file body (advisory publish bookkeeping).
#[derive(Clone, Debug, Serialize, Deserialize)]
struct HeadFile {
    seq: u64,
    head_hash_hex: String,
}

/// Parse `<device_id>-<lo>-<hi>.oplog` into a [`SegmentFile`]; `None` if the
/// name does not match (a foreign file the dumb channel dropped in).
fn parse_segment_name(path: &Path) -> Option<SegmentFile> {
    let stem = path.file_stem()?.to_str()?;
    // device_id is a 36-char hyphenated UUID; the range is `-<lo>-<hi>`.
    // Split off the last two `-`-separated numeric fields.
    let (rest, hi) = stem.rsplit_once('-')?;
    let (dev_str, lo) = rest.rsplit_once('-')?;
    let seq_lo: u64 = lo.parse().ok()?;
    let seq_hi: u64 = hi.parse().ok()?;
    let device_id = parse_uuid(dev_str)?;
    Some(SegmentFile {
        device_id,
        seq_lo,
        seq_hi,
        path: path.to_path_buf(),
    })
}

/// Parse a hyphenated UUID into a device id (no `uuid` string dep needed here —
/// but we use the `uuid` crate for correctness).
fn parse_uuid(s: &str) -> Option<DeviceId> {
    uuid::Uuid::parse_str(s)
        .ok()
        .map(|u| Id::from_bytes(*u.as_bytes()))
}

/// Lowercase-hex encode a hash for the head file.
fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push(char::from_digit(u32::from(b >> 4), 16).unwrap());
        s.push(char::from_digit(u32::from(b & 0x0f), 16).unwrap());
    }
    s
}

/// Write bytes durably-ish: to a temp sibling then rename into place, so a
/// reader never sees a half-written segment (segments are immutable once named).
fn write_atomic(path: &Path, bytes: &[u8]) -> Result<()> {
    let tmp = path.with_extension("tmp");
    fs::write(&tmp, bytes)?;
    fs::rename(&tmp, path)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use lp_vault::op::OpKind;

    fn op(dev: [u8; 16], seq: u64, lamport: u64) -> StoredOp {
        StoredOp {
            op_id: Id::from_bytes([(seq as u8).wrapping_add(1); 16]),
            vault_id: Id::from_bytes([2u8; 16]),
            device_id: Id::from_bytes(dev),
            seq,
            prev_hash: [0u8; 32],
            lamport,
            op_kind: OpKind::Create,
            target_item: Some(Id::from_bytes([4u8; 16])),
            target_version: 1,
            payload_env: vec![1, 2, 3],
            observed: lp_vault::op::ObservedHeads::new(),
            signature: [9u8; 64],
            created_at: 0,
        }
    }

    #[test]
    fn segment_write_read_roundtrip() {
        let tmp = tempfile::tempdir().unwrap();
        let vault = Id::from_bytes([2u8; 16]);
        let dir = SyncDir::open(tmp.path(), vault).unwrap();
        let ops = vec![op([3u8; 16], 1, 1), op([3u8; 16], 2, 2)];
        let seg = dir.write_segment(&ops).unwrap().unwrap();
        assert_eq!(seg.seq_lo, 1);
        assert_eq!(seg.seq_hi, 2);

        let back = dir.read_all_ops().unwrap();
        assert_eq!(back.len(), 2);
        assert_eq!(back[0].seq, 1);
        assert_eq!(back[1].seq, 2);
    }

    #[test]
    fn non_contiguous_segment_rejected() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = SyncDir::open(tmp.path(), Id::from_bytes([2u8; 16])).unwrap();
        let ops = vec![op([3u8; 16], 1, 1), op([3u8; 16], 3, 3)];
        assert!(matches!(dir.write_segment(&ops), Err(Error::Invalid(_))));
    }

    #[test]
    fn manifest_roundtrips() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = SyncDir::open(tmp.path(), Id::from_bytes([2u8; 16])).unwrap();
        let mut m = Manifest {
            vault_id: "v".into(),
            devices: BTreeMap::new(),
        };
        m.devices.insert("d".into(), 7);
        dir.write_manifest(&m).unwrap();
        assert_eq!(dir.read_manifest(), m);
    }

    #[test]
    fn forged_manifest_is_only_advisory() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = SyncDir::open(tmp.path(), Id::from_bytes([2u8; 16])).unwrap();
        // A manifest claiming a device+seq with NO backing segments.
        let mut m = Manifest::default();
        m.devices.insert("deadbeef".into(), 999);
        dir.write_manifest(&m).unwrap();
        // The reader finds no actual ops (state cannot be injected via manifest).
        assert!(dir.read_all_ops().unwrap().is_empty());
    }

    #[test]
    fn key_blob_roundtrips_for_recipient_only() {
        let tmp = tempfile::tempdir().unwrap();
        let vault = Id::from_bytes([2u8; 16]);
        let dir = SyncDir::open(tmp.path(), vault).unwrap();
        let me = Id::from_bytes([5u8; 16]);
        let other = Id::from_bytes([6u8; 16]);
        dir.write_key_blob(&me, b"sealed").unwrap();
        assert_eq!(
            dir.read_key_blob(&me).unwrap().as_deref(),
            Some(&b"sealed"[..])
        );
        assert!(dir.read_key_blob(&other).unwrap().is_none());
    }
}
