//! Foreign-op application — the minimal, additive lp-vault seam that lets the
//! sync engine (`lp-sync`) ingest and materialize ops authored by **other**
//! devices (sync-protocol.md §4/§5, vault-format.md §7).
//!
//! # Why this module exists (the one permitted lp-vault change class)
//!
//! Every existing [`Vault`] write path (`create_item`,
//! `update_item`, …) *authors a new local op*: it assigns **this** device's
//! `seq`/`lamport`/`prev_hash` and signs with **this** device's Ed25519 key.
//! That is exactly wrong for a foreign op, which already carries the *authoring*
//! device's identity, sequence, chain link, Lamport clock, and signature — all
//! of which must be preserved byte-for-byte so the per-device hash chain still
//! verifies on every peer (sync-protocol.md §5).
//!
//! So `lp-sync` cannot reuse the local authoring paths. Instead this module
//! exposes a small, **additive** API (no behaviour change to any existing path):
//!
//! - [`Vault::stored_ops`] / [`Vault::last_seq_for`] — read the local op log so
//!   the verifier can recompute chains and seq high-water marks.
//! - [`Vault::decrypt_op_payload`] — VaultKey-decrypt a foreign op's
//!   `payload_env` (single-user multi-device: every device shares the VaultKey,
//!   so a peer op's payload opens exactly like a local one).
//! - [`Vault::apply_foreign_ops`] — the crown jewel: given a batch of verified
//!   foreign ops **and** the fully-recomputed materialized state the merge
//!   (sync-protocol.md §4) determined, insert every op row verbatim *and* write
//!   the resulting item/version/tombstone state **and** update the encrypted
//!   search index — all in **one** SQLite transaction (vault-format.md §7:
//!   applying an op is atomic with recording it).
//!
//! `lp-sync` owns the *policy* (verification, total order, per-field LWW, loser
//! preservation, version-number assignment); this module owns the *mechanism*
//! (transactional persistence + index consistency). The split keeps the merge a
//! pure, testable function while the storage invariants stay in lp-vault where
//! the index seams live.
//!
//! # Determinism of persisted state
//!
//! The caller hands us a [`Materialization`] computed purely from the op set in
//! total order (sync-protocol.md §4.4). We persist it verbatim: version numbers,
//! payloads, tombstone facts, and `op_id` back-links are all decided by the
//! merge, not here. Each materialized version is re-sealed under a **fresh local
//! `ItemKey`** (per-version key hygiene, vault-format.md §5.3); the *ciphertext*
//! differs per device (fresh key + nonce) but the *decrypted* payload and the
//! structural rows are byte-identical across devices — which is the convergence
//! the property tests assert.

use rusqlite::{Connection, OptionalExtension, params};

use crate::aad;
use crate::error::{Error, Result};
use crate::ids::{AttachmentId, DeviceId, Id, ItemId, OpId, VaultId};
use crate::op::{ObservedHeads, OpKind};
use crate::payload::ItemPayload;
use crate::vault::Vault;

/// A raw op row as it lives in (or will live in) the `ops` table — every wire
/// field (sync-protocol.md §1) plus the local `created_at`.
///
/// This is the canonical carrier `lp-sync` uses to move ops between the log, the
/// verifier, and the shipping segments. All byte fields are the on-disk /
/// on-wire representation (ids as 16 bytes, `payload_env` as Envelope-v1 bytes,
/// `signature` as 64 bytes, `prev_hash` as 32 bytes).
#[derive(Clone, Debug)]
pub struct StoredOp {
    /// Field 1: the op's own id (16 bytes).
    pub op_id: OpId,
    /// Field 2: the vault this op belongs to.
    pub vault_id: VaultId,
    /// Field 3: the authoring device.
    pub device_id: DeviceId,
    /// Field 4: per-device gapless sequence (1-based).
    pub seq: u64,
    /// Field 5: hash-chain link to the author's previous op.
    pub prev_hash: [u8; 32],
    /// Field 6: Lamport clock.
    pub lamport: u64,
    /// Field 7: op kind.
    pub op_kind: OpKind,
    /// Field 8: target item (`None` for a vault-scope op).
    pub target_item: Option<ItemId>,
    /// Field 9: target version (0 if n/a).
    pub target_version: u32,
    /// Field 10: the encrypted op payload (Envelope-v1 wire bytes).
    pub payload_env: Vec<u8>,
    /// Field 11: the observed-heads causal summary (sync-protocol.md §3) — the
    /// version vector the merge derives true happens-before from. Authenticated
    /// metadata (covered by the signature and the hash chain).
    pub observed: ObservedHeads,
    /// Field 12: Ed25519 signature over the version byte + fields 1..11.
    pub signature: [u8; 64],
    /// Local wall-clock insert time (plaintext; not part of the signed region).
    pub created_at: i64,
}

impl StoredOp {
    /// The canonical bytes of this op's observed-heads causal summary (field
    /// 11), for the `ops.observed` column. Thin adapter over
    /// [`crate::op::OpFields::observed_bytes`].
    #[must_use]
    pub fn observed_bytes(&self) -> Vec<u8> {
        self.observed.to_bytes()
    }
}

/// One item's fully-resolved materialized state, as decided by the merge
/// (sync-protocol.md §4). Persisted verbatim by [`Vault::apply_foreign_ops`].
///
/// `versions` lists **every** version row to exist for this item after the
/// merge, in ascending `version` order (version numbers are assigned by the
/// merge in ascending total order — sync-protocol.md §4.4). The last entry whose
/// version equals `current_version` is the item head; earlier entries include
/// preserved conflict losers (never dropped — sync-protocol.md §4.2).
#[derive(Clone, Debug)]
pub struct ItemMaterialization {
    /// The item id.
    pub item_id: ItemId,
    /// The current (head) version number after the merge.
    pub current_version: i64,
    /// Item creation time (unix millis) — the earliest producing op's time.
    pub created_at: i64,
    /// Item last-update time (unix millis) — the head-producing op's time.
    pub updated_at: i64,
    /// Every version row for this item, ascending by `version`.
    pub versions: Vec<VersionMaterialization>,
    /// The tombstone, if the merge resolved this item as deleted
    /// (sync-protocol.md §4.3). `None` means live.
    pub tombstone: Option<TombstoneMaterialization>,
}

/// One immutable version row to persist (vault-format.md §3 `item_versions`).
#[derive(Clone, Debug)]
pub struct VersionMaterialization {
    /// 1-based version number (assigned by the merge in total order).
    pub version: i64,
    /// The decrypted canonical payload for this version.
    pub payload: ItemPayload,
    /// When this version was produced (unix millis; the op's `created_at`).
    pub created_at: i64,
    /// The authoring device of the op that produced this version.
    pub author_device_id: DeviceId,
    /// The op that produced this version.
    pub op_id: OpId,
}

/// A tombstone row to persist (vault-format.md §3 `tombstones`).
#[derive(Clone, Debug)]
pub struct TombstoneMaterialization {
    /// When the item was deleted (unix millis).
    pub deleted_at: i64,
    /// When it becomes eligible for permanent purge (unix millis).
    pub purge_after: i64,
    /// The device that authored the winning delete op.
    pub deleted_by_device: DeviceId,
    /// The delete op that is canonical for this tombstone.
    pub op_id: OpId,
}

/// One attachment row to insert (materialized from an `AttachAdd` op that has
/// no matching `AttachDelete` tombstone; sync-protocol.md §2). The two envelopes
/// are the **VaultKey-form** wrapped-key + filename carried in the op payload:
/// portable across devices (unlike the per-device ItemKey form). On apply the
/// vault unwraps them under the shared VaultKey and **re-wraps** them under its
/// own current-version ItemKey for the stored row (see
/// `Vault::materialize_attachment`). The **blob** is fetched separately (Part C)
/// — a materialized row may temporarily lack its local blob (the "pending"
/// state).
#[derive(Clone, Debug)]
pub struct AttachmentMaterialization {
    /// The attachment id.
    pub attachment_id: AttachmentId,
    /// The owning item id.
    pub item_id: ItemId,
    /// The item version the attachment was recorded against on the author (kept
    /// for reference; the local row rebinds to this device's current version).
    pub version: i64,
    /// BLAKE3 of the ciphertext blob (32 bytes, decoded from the op payload hex).
    pub content_hash: Vec<u8>,
    /// The plaintext size in bytes (structural).
    pub size_plain: i64,
    /// The **VaultKey-wrapped** per-attachment key (Envelope-v1 bytes, from the
    /// op payload). Re-wrapped under the local ItemKey on apply.
    pub wrapped_key_env: Vec<u8>,
    /// The **VaultKey-sealed** filename (Envelope-v1 bytes, from the op payload).
    /// Re-sealed under the local ItemKey on apply.
    pub filename_env: Vec<u8>,
    /// When the `AttachAdd` op was ingested (unix millis; plaintext structural).
    pub created_at: i64,
}

/// The complete result of a merge over a batch of foreign ops: the op rows to
/// record and the per-item materialized state to write, all applied atomically.
#[derive(Clone, Debug, Default)]
pub struct Materialization {
    /// Foreign op rows to insert verbatim (idempotent on `UNIQUE(device_id,
    /// seq)` / `op_id` primary key — an already-present op is skipped).
    pub ops: Vec<StoredOp>,
    /// The materialized state of every item touched by this batch. Items not
    /// listed here are left untouched.
    pub items: Vec<ItemMaterialization>,
    /// Attachments that **exist** after the merge (an `AttachAdd` with no
    /// `AttachDelete` for its id; sync-protocol.md §2). Inserted idempotently by
    /// `attachment_id`. The blob ships separately and is not present here.
    pub attachments: Vec<AttachmentMaterialization>,
    /// Attachment ids **tombstoned** by an `AttachDelete` — their rows are
    /// removed (and a reordered `AttachAdd` cannot resurrect them, because the
    /// merge re-derives the exists-iff-add-and-no-delete set every apply).
    pub attachment_tombstones: Vec<AttachmentId>,
}

impl Vault<'_> {
    /// Read this vault's entire op log as [`StoredOp`]s, ordered by
    /// `(lamport, device_id, seq)` — a stable, total, decryption-free order the
    /// sync engine folds and re-ships from.
    ///
    /// # Errors
    ///
    /// [`Error::Sqlite`] on a read failure; [`Error::Invalid`] on a corrupt row
    /// (wrong-width blob / out-of-range integer).
    pub fn stored_ops(&self) -> Result<Vec<StoredOp>> {
        let conn = self.connect_foreign()?;
        read_ops(&conn, None)
    }

    /// Read only the ops authored by `device_id`, ascending by `seq` (the
    /// per-device chain order — sync-protocol.md §5).
    ///
    /// # Errors
    ///
    /// [`Error::Sqlite`] / [`Error::Invalid`] as [`stored_ops`](Self::stored_ops).
    pub fn stored_ops_for(&self, device_id: &DeviceId) -> Result<Vec<StoredOp>> {
        let conn = self.connect_foreign()?;
        read_ops(&conn, Some(device_id))
    }

    /// The highest `seq` this vault has recorded for `device_id`, or `0` if none
    /// (the per-device high-water mark; sync-protocol.md §5 / §7 `status`).
    ///
    /// # Errors
    ///
    /// [`Error::Sqlite`] on a read failure.
    pub fn last_seq_for(&self, device_id: &DeviceId) -> Result<u64> {
        let conn = self.connect_foreign()?;
        let last: i64 = conn
            .query_row(
                "SELECT COALESCE(MAX(seq), 0) FROM ops WHERE device_id = ?1",
                params![device_id.to_vec()],
                |r| r.get(0),
            )
            .unwrap_or(0);
        Ok(u64::try_from(last).unwrap_or(0))
    }

    /// Whether an op with this `op_id` is already recorded (idempotent re-read
    /// short-circuit; sync-protocol.md §7.3).
    ///
    /// # Errors
    ///
    /// [`Error::Sqlite`] on a read failure.
    pub fn has_op(&self, op_id: &OpId) -> Result<bool> {
        let conn = self.connect_foreign()?;
        Ok(conn
            .query_row(
                "SELECT 1 FROM ops WHERE op_id = ?1",
                params![op_id.to_vec()],
                |_| Ok(true),
            )
            .optional()?
            .unwrap_or(false))
    }

    /// VaultKey-decrypt a foreign op's `payload_env` into its plaintext bytes
    /// (the canonical item JSON, or `{}` for a delete, etc.).
    ///
    /// Single-user multi-device: every paired device shares the VaultKey, so a
    /// peer op's payload opens exactly like a local one (the op AAD binds
    /// `vault_id | op_id`, so a relocated ciphertext fails — vault-format.md §3).
    ///
    /// # Errors
    ///
    /// [`Error::DecryptionFailed`] if the ciphertext/tag/AAD do not verify
    /// (tamper or wrong vault); [`Error::Crypto`] on a malformed envelope.
    pub fn decrypt_op_payload(&self, op_id: &OpId, payload_env: &[u8]) -> Result<Vec<u8>> {
        let envelope = lp_crypto::Envelope::from_bytes(payload_env).map_err(Error::from_crypto)?;
        self.vault_key_ref()
            .open(&envelope, &aad::op_payload(&self.vault_id(), op_id))
            .map_err(Error::from_crypto)
    }

    /// VaultKey-encrypt an op payload plaintext into its `payload_env` wire
    /// bytes, bound to the op AAD (`localpass/v1/op/payload | vault_id | op_id`).
    ///
    /// The exact inverse of [`decrypt_op_payload`](Self::decrypt_op_payload).
    /// This is the seam a shared-vault peer (or the sync engine simulating one)
    /// uses to author an op payload under the shared VaultKey before signing it
    /// — single-user multi-device, every device holds the same VaultKey, so a
    /// payload sealed here opens on any paired device.
    ///
    /// # Errors
    ///
    /// [`Error::Crypto`] on an AEAD encrypt failure (practically infallible).
    pub fn seal_op_payload(&self, op_id: &OpId, plaintext: &[u8]) -> Result<Vec<u8>> {
        let env = self
            .vault_key_ref()
            .seal(plaintext, &aad::op_payload(&self.vault_id(), op_id))
            .map_err(Error::from_crypto)?;
        Ok(env.to_bytes())
    }

    /// Apply a batch of verified foreign ops and their computed materialization
    /// (sync-protocol.md §4/§5, vault-format.md §7).
    ///
    /// In a single transaction, for the whole batch:
    ///
    /// 1. INSERT every [`StoredOp`] verbatim (skipping ops already present, so a
    ///    replayed segment is an idempotent no-op — sync-protocol.md §7.3).
    /// 2. For each touched item, rewrite its `item_versions` + `wrapped_keys` to
    ///    exactly the merge's [`ItemMaterialization`] (re-sealing each version
    ///    under a fresh local ItemKey), set `items.current_version`, and either
    ///    clear or write its `tombstones` row.
    /// 3. Update the encrypted search index for each item (live → upsert,
    ///    tombstoned → delete), riding the same transaction (vault-format.md §7 /
    ///    search-index.md §4) so the index generation and item state never
    ///    diverge.
    ///
    /// The whole thing commits or rolls back atomically; a torn foreign-op apply
    /// is impossible, and [`verify_local_chain`](Vault::verify_local_chain) plus
    /// every peer's chain check remain valid afterwards because op rows are
    /// stored byte-exact.
    ///
    /// # Errors
    ///
    /// [`Error::Sqlite`] / [`Error::Crypto`] / [`Error::DecryptionFailed`];
    /// nothing is committed on error.
    pub fn apply_foreign_ops(&self, mat: &Materialization) -> Result<()> {
        let mut conn = self.connect_foreign()?;
        let tx = conn.transaction()?;

        // 1) Insert op rows verbatim, idempotently.
        for op in &mat.ops {
            insert_stored_op(&tx, op)?;
        }

        // 2) Materialize each touched item's state.
        for item in &mat.items {
            self.materialize_item(&tx, item)?;
        }

        // 3) Materialize attachment rows (sync-protocol.md §2). The merge already
        //    enforces exists-iff-add-and-no-delete, but we defend in depth: a
        //    tombstoned id is removed AND never re-inserted, so an add + delete
        //    for the same id in one batch nets to "deleted" regardless of vector
        //    order (the tombstone wins). Concurrent adds have distinct ids.
        let tombstoned: std::collections::BTreeSet<[u8; 16]> = mat
            .attachment_tombstones
            .iter()
            .map(|id| *id.as_bytes())
            .collect();
        for attachment_id in &mat.attachment_tombstones {
            remove_attachment_row(&tx, attachment_id)?;
        }
        for att in &mat.attachments {
            if tombstoned.contains(att.attachment_id.as_bytes()) {
                continue;
            }
            self.materialize_attachment(&tx, att)?;
        }

        tx.commit()?;
        Ok(())
    }

    /// Rewrite one item's version/key/head/tombstone rows to the merge result
    /// and update the index — all inside the caller's transaction.
    fn materialize_item(&self, tx: &Connection, item: &ItemMaterialization) -> Result<()> {
        let item_bytes = item.item_id.to_vec();

        // Replace the item's versions + wrapped keys wholesale. The merge is a
        // pure function of the op set, so the desired version set is fully known;
        // rewriting (rather than diffing) keeps this deterministic and simple.
        // `item_versions`/`ops` immutability (vault-format.md §10) is honored at
        // the *op* level — the op log is append-only and never rewritten; the
        // materialized version rows are a projection of it and may be recomputed.
        tx.execute(
            "DELETE FROM item_versions WHERE item_id = ?1",
            params![item_bytes],
        )?;
        tx.execute(
            "DELETE FROM wrapped_keys WHERE item_id = ?1",
            params![item_bytes],
        )?;

        for ver in &item.versions {
            let plaintext = ver.payload.to_canonical()?;
            let (payload_env, wrapped_key_env) =
                self.seal_version_foreign(&item.item_id, ver.version, &plaintext)?;
            tx.execute(
                "INSERT INTO wrapped_keys (item_id, version, envelope) VALUES (?1, ?2, ?3)",
                params![item_bytes, ver.version, wrapped_key_env],
            )?;
            tx.execute(
                "INSERT INTO item_versions
                    (item_id, version, payload_env, created_at, author_device_id, op_id)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                params![
                    item_bytes,
                    ver.version,
                    payload_env,
                    ver.created_at,
                    ver.author_device_id.to_vec(),
                    ver.op_id.to_vec(),
                ],
            )?;
        }

        // Upsert the item head row (create on first sight, else update).
        tx.execute(
            "INSERT INTO items (item_id, current_version, created_at, updated_at)
             VALUES (?1, ?2, ?3, ?4)
             ON CONFLICT(item_id) DO UPDATE SET
                current_version = excluded.current_version,
                updated_at = excluded.updated_at",
            params![
                item_bytes,
                item.current_version,
                item.created_at,
                item.updated_at
            ],
        )?;

        // Tombstone: write it (delete-wins) or clear it (edit-wins / revived).
        tx.execute(
            "DELETE FROM tombstones WHERE item_id = ?1",
            params![item_bytes],
        )?;
        if let Some(tomb) = &item.tombstone {
            tx.execute(
                "INSERT INTO tombstones
                    (item_id, deleted_at, purge_after, deleted_by_device, op_id)
                 VALUES (?1, ?2, ?3, ?4, ?5)",
                params![
                    item_bytes,
                    tomb.deleted_at,
                    tomb.purge_after,
                    tomb.deleted_by_device.to_vec(),
                    tomb.op_id.to_vec(),
                ],
            )?;
        }

        // Index update in the same transaction (search-index.md §4/§5). A
        // tombstoned item is removed from the index; a live item is upserted
        // to its current fields. The reader decrypts the just-written head
        // version through the same per-item-key read path.
        self.index_apply_foreign(tx, &item.item_id, item.tombstone.is_some())?;
        Ok(())
    }
}

/// Remove a tombstoned attachment row (idempotent — a no-op if already gone).
/// The on-disk blob is left in place: it is content-addressed and may be shared
/// (dedup) by another row, and the local blob store's authority is the row set.
/// A future GC can sweep unreferenced blobs; leaving it is harmless and never
/// loses referenced data.
fn remove_attachment_row(tx: &Connection, attachment_id: &AttachmentId) -> Result<()> {
    tx.execute(
        "DELETE FROM attachments WHERE attachment_id = ?1",
        params![attachment_id.to_vec()],
    )?;
    Ok(())
}

/// INSERT a [`StoredOp`] verbatim, skipping it if already present (idempotent).
fn insert_stored_op(tx: &Connection, op: &StoredOp) -> Result<()> {
    let exists: bool = tx
        .query_row(
            "SELECT 1 FROM ops WHERE op_id = ?1",
            params![op.op_id.to_vec()],
            |_| Ok(true),
        )
        .optional()?
        .unwrap_or(false);
    if exists {
        return Ok(());
    }
    tx.execute(
        "INSERT INTO ops
            (op_id, vault_id, lamport, device_id, op_kind, target_item_id, target_version,
             payload_env, signature, seq, prev_hash, observed, created_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)",
        params![
            op.op_id.to_vec(),
            op.vault_id.to_vec(),
            i64::try_from(op.lamport).map_err(|_| Error::Invalid("lamport out of range"))?,
            op.device_id.to_vec(),
            i64::from(op.op_kind.code()),
            op.target_item.as_ref().map(Id::to_vec),
            i64::from(op.target_version),
            op.payload_env.as_slice(),
            op.signature.as_slice(),
            i64::try_from(op.seq).map_err(|_| Error::Invalid("seq out of range"))?,
            op.prev_hash.as_slice(),
            op.observed_bytes(),
            op.created_at,
        ],
    )?;
    Ok(())
}

/// Read `ops` rows into [`StoredOp`]s. With `device`, filters to one author in
/// `seq` order; without, returns all ops in `(lamport, device_id, seq)` order.
fn read_ops(conn: &Connection, device: Option<&DeviceId>) -> Result<Vec<StoredOp>> {
    let (sql, filter): (&str, Option<Vec<u8>>) = match device {
        Some(d) => (
            "SELECT op_id, vault_id, device_id, seq, prev_hash, lamport, op_kind,
                    target_item_id, target_version, payload_env, signature, observed, created_at
               FROM ops WHERE device_id = ?1 ORDER BY seq",
            Some(d.to_vec()),
        ),
        None => (
            "SELECT op_id, vault_id, device_id, seq, prev_hash, lamport, op_kind,
                    target_item_id, target_version, payload_env, signature, observed, created_at
               FROM ops ORDER BY lamport, device_id, seq",
            None,
        ),
    };
    let mut stmt = conn.prepare(sql)?;
    let map = |r: &rusqlite::Row<'_>| -> rusqlite::Result<RawOpRow> {
        Ok(RawOpRow {
            op_id: r.get(0)?,
            vault_id: r.get(1)?,
            device_id: r.get(2)?,
            seq: r.get(3)?,
            prev_hash: r.get(4)?,
            lamport: r.get(5)?,
            op_kind: r.get(6)?,
            target_item_id: r.get(7)?,
            target_version: r.get(8)?,
            payload_env: r.get(9)?,
            signature: r.get(10)?,
            observed: r.get(11)?,
            created_at: r.get(12)?,
        })
    };
    let rows: Vec<RawOpRow> = match filter {
        Some(bytes) => stmt
            .query_map(params![bytes], map)?
            .collect::<std::result::Result<_, _>>()?,
        None => stmt
            .query_map([], map)?
            .collect::<std::result::Result<_, _>>()?,
    };
    rows.into_iter().map(RawOpRow::into_stored).collect()
}

/// A raw `ops` row straight from SQLite, before typing/validation.
struct RawOpRow {
    op_id: Vec<u8>,
    vault_id: Vec<u8>,
    device_id: Vec<u8>,
    seq: i64,
    prev_hash: Vec<u8>,
    lamport: i64,
    op_kind: i64,
    target_item_id: Option<Vec<u8>>,
    target_version: i64,
    payload_env: Vec<u8>,
    signature: Vec<u8>,
    observed: Vec<u8>,
    created_at: i64,
}

impl RawOpRow {
    fn into_stored(self) -> Result<StoredOp> {
        let prev_hash: [u8; 32] = self
            .prev_hash
            .as_slice()
            .try_into()
            .map_err(|_| Error::Invalid("stored prev_hash not 32 bytes"))?;
        let signature: [u8; 64] = self
            .signature
            .as_slice()
            .try_into()
            .map_err(|_| Error::Invalid("stored signature not 64 bytes"))?;
        let op_kind = u8::try_from(self.op_kind)
            .ok()
            .and_then(OpKind::from_code)
            .ok_or(Error::Invalid("unknown op_kind"))?;
        Ok(StoredOp {
            op_id: Id::from_slice(&self.op_id)?,
            vault_id: Id::from_slice(&self.vault_id)?,
            device_id: Id::from_slice(&self.device_id)?,
            seq: u64::try_from(self.seq).map_err(|_| Error::Invalid("seq out of range"))?,
            prev_hash,
            lamport: u64::try_from(self.lamport)
                .map_err(|_| Error::Invalid("lamport out of range"))?,
            op_kind,
            target_item: match self.target_item_id {
                Some(bytes) => Some(Id::from_slice(&bytes)?),
                None => None,
            },
            target_version: u32::try_from(self.target_version)
                .map_err(|_| Error::Invalid("target_version out of range"))?,
            payload_env: self.payload_env,
            observed: ObservedHeads::decode(&self.observed)?,
            signature,
            created_at: self.created_at,
        })
    }
}
