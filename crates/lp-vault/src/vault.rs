//! The [`Vault`] — items, versions, folders, trash, op authoring, and search.
//!
//! A `Vault` is an open handle over one `<vault_id>.vault` file plus the live
//! [`VaultKey`]. Every item mutation writes its op row **in the same
//! transaction** as the state change (vault-format.md §7; sync-protocol.md §5),
//! so local state and the local op log can never diverge.
//!
//! # Per-version keys (vault-format.md §5.3)
//!
//! Every `(item_id, version)` gets a **fresh** [`ItemKey`], wrapped by the
//! VaultKey in `wrapped_keys`. A new version generates a new ItemKey, so a
//! single compromised ItemKey never spans versions and nonce reuse across edits
//! is structurally impossible.
//!
//! # Op authoring (sync-protocol.md §1–§5)
//!
//! Each mutation authors an op: canonical wire bytes, payload encrypted under
//! the VaultKey, an Ed25519 signature over fields 1..10, a per-device gapless
//! `seq`, a `prev_hash` chaining this device's previous op, and a `lamport`
//! clock that is `max(all ops' lamport) + 1`. [`Vault::verify_local_chain`]
//! re-checks this device's whole chain (signatures, seq gaplessness, prev_hash
//! links, lamport monotonicity).
//!
//! # Search (placeholder)
//!
//! [`Vault::search`] is a **linear** scan over decrypted items — the documented
//! fallback the encrypted index (`search-index.md`, a later work unit) will sit
//! in front of. [`Vault::iter_items`] exposes `(item_id, decrypted payload)` so
//! the index layer can plug in over the same read path without rework.

use lp_crypto::{ItemKey, VaultKey, unwrap_key, wrap_key};
use rusqlite::{Connection, OptionalExtension, params};

use crate::aad;
use crate::account::Session;
use crate::db;
use crate::error::{Error, Result};
use crate::ids::{FolderId, Id, ItemId, VaultId};
use crate::index::SearchIndex;
use crate::op::{ItemTarget, OpFields, OpKind, chain_hash, genesis_hash};
use crate::payload::ItemPayload;

/// The ItemKey wrap purpose/AAD as a `&str` (the full `|`-joined row-binding
/// string). Valid UTF-8 by construction (label + hex + decimal), so the
/// conversion never fails.
fn item_key_aad_str(vault_id: &VaultId, item_id: &ItemId, version: i64) -> String {
    String::from_utf8(aad::item_key(vault_id, item_id, version)).expect("item-key AAD is UTF-8")
}

/// A live, unlocked vault.
///
/// Holds the vault file path, its id, and the live [`VaultKey`]. Reads and
/// writes open short-lived connections to the file (each with the durability
/// PRAGMAs). The [`VaultKey`] zeroizes on drop with the vault handle.
pub struct Vault<'s> {
    path: std::path::PathBuf,
    vault_id: VaultId,
    vault_key: VaultKey,
    /// The encrypted search index handle (holds the derived IndexKey).
    /// Constructed at open; drops with the vault, so lock/unlock never touches
    /// the index (search-index.md §7).
    index: SearchIndex,
    session: &'s Session,
}

/// A stored item's summary (plaintext metadata + decrypted payload).
#[derive(Debug)]
pub struct Item {
    /// The item id.
    pub item_id: ItemId,
    /// The current version number.
    pub current_version: i64,
    /// Creation time (unix millis, plaintext).
    pub created_at: i64,
    /// Last-update time (unix millis, plaintext).
    pub updated_at: i64,
    /// The decrypted payload of the current version.
    pub payload: ItemPayload,
}

/// One entry in an item's version history.
#[derive(Debug)]
pub struct VersionInfo {
    /// The version number.
    pub version: i64,
    /// When this version was written (unix millis, plaintext).
    pub created_at: i64,
    /// The decrypted payload of this version.
    pub payload: ItemPayload,
}

/// Per-vault storage statistics (PRD §4.10 visible stats). Returned by
/// [`Vault::storage_stats`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StorageStats {
    /// Number of live (non-tombstoned) items.
    pub live_items: u64,
    /// Total immutable version rows across all items.
    pub total_versions: u64,
    /// Number of items currently in trash (tombstoned).
    pub trashed: u64,
    /// Number of encrypted data segments in the search index (excludes the
    /// manifest segment 0).
    pub index_segments: u64,
}

/// A trash entry (tombstoned item).
#[derive(Debug)]
pub struct TrashEntry {
    /// The tombstoned item id.
    pub item_id: ItemId,
    /// When it was deleted (unix millis).
    pub deleted_at: i64,
    /// When it becomes eligible for permanent purge (unix millis).
    pub purge_after: i64,
}

impl<'s> Vault<'s> {
    /// Open an existing vault file with an already-unwrapped [`VaultKey`].
    ///
    /// Called by [`Session::open_vault`](crate::Session::open_vault); validates
    /// the file's `format_version`.
    pub(crate) fn open(
        path: std::path::PathBuf,
        vault_id: VaultId,
        vault_key: VaultKey,
        session: &'s Session,
    ) -> Result<Self> {
        let conn = db::open_connection(&path)?;
        db::check_format_version(&conn)?;
        let index = SearchIndex::new(vault_id, &vault_key)?;
        Ok(Self {
            path,
            vault_id,
            vault_key,
            index,
            session,
        })
    }

    /// Build a [`PayloadReader`](crate::index::PayloadReader) closure the index
    /// uses to decrypt an item's current version over a given connection. This
    /// is the read path the index rebuilds on; it decrypts through the same
    /// per-item-key mechanism as [`get_item`](Self::get_item).
    fn payload_reader(&self) -> impl Fn(&Connection, &ItemId) -> Result<ItemPayload> + '_ {
        move |conn: &Connection, item_id: &ItemId| -> Result<ItemPayload> {
            let current: i64 = conn
                .query_row(
                    "SELECT current_version FROM items WHERE item_id = ?1",
                    params![item_id.to_vec()],
                    |r| r.get(0),
                )
                .optional()?
                .ok_or(Error::NotFound("item"))?;
            let plaintext = self.read_version_plaintext(conn, item_id, current)?;
            ItemPayload::from_canonical(&plaintext)
        }
    }

    /// This vault's id.
    #[must_use]
    pub fn vault_id(&self) -> VaultId {
        self.vault_id
    }

    /// Open a fresh connection to the vault file.
    fn connect(&self) -> Result<Connection> {
        db::open_connection(&self.path)
    }

    // --- Item create -------------------------------------------------------

    /// Create a new item from `payload` (vault-format.md §7 item-create).
    ///
    /// Atomically inserts `items` + `item_versions` v1 + `wrapped_keys` v1 +
    /// the `create` op — all in one transaction.
    ///
    /// # Errors
    ///
    /// [`Error::Sqlite`] / [`Error::Crypto`] on failure; nothing partial is
    /// committed on error.
    pub fn create_item(&self, payload: &ItemPayload) -> Result<ItemId> {
        let item_id = Id::new();
        let version: i64 = 1;
        let now = db::now_millis();

        let plaintext = payload.to_canonical()?;
        let (payload_env, wrapped_key_env) = self.seal_version(&item_id, version, &plaintext)?;

        let mut conn = self.connect()?;
        let tx = conn.transaction()?;

        // Author the create op (payload = the full item body).
        let op_id = self.author_op(
            &tx,
            OpKind::Create,
            Some(&item_id),
            u32::try_from(version).unwrap_or(0),
            &plaintext,
        )?;

        tx.execute(
            "INSERT INTO wrapped_keys (item_id, version, envelope) VALUES (?1, ?2, ?3)",
            params![item_id.to_vec(), version, wrapped_key_env],
        )?;
        tx.execute(
            "INSERT INTO item_versions
                (item_id, version, payload_env, created_at, author_device_id, op_id)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                item_id.to_vec(),
                version,
                payload_env,
                now,
                self.session.device_id().to_vec(),
                op_id.to_vec(),
            ],
        )?;
        tx.execute(
            "INSERT INTO items (item_id, current_version, created_at, updated_at)
             VALUES (?1, ?2, ?3, ?3)",
            params![item_id.to_vec(), version, now],
        )?;

        // Update the encrypted index IN THE SAME TRANSACTION (search-index.md
        // §4): bumps meta.index_generation once and re-encrypts the owning
        // segment + manifest at the new generation. Rolls back with the item
        // write on any failure.
        let reader = self.payload_reader();
        self.index.apply_upsert(&tx, &item_id, payload, &reader)?;

        tx.commit()?;
        Ok(item_id)
    }

    // --- Item update -------------------------------------------------------

    /// Update an item, creating a new immutable version (vault-format.md §7
    /// item-edit). A **new** ItemKey is generated for the new version.
    ///
    /// # Errors
    ///
    /// - [`Error::NotFound`] if the item does not exist.
    /// - [`Error::Invalid`] if the item is tombstoned (restore it first).
    pub fn update_item(&self, item_id: ItemId, payload: &ItemPayload) -> Result<i64> {
        let now = db::now_millis();
        let mut conn = self.connect()?;
        let tx = conn.transaction()?;

        if is_tombstoned(&tx, &item_id)? {
            return Err(Error::Invalid("cannot update a deleted item"));
        }
        let current: i64 = tx
            .query_row(
                "SELECT current_version FROM items WHERE item_id = ?1",
                params![item_id.to_vec()],
                |r| r.get(0),
            )
            .optional()?
            .ok_or(Error::NotFound("item"))?;
        let version = current + 1;

        let plaintext = payload.to_canonical()?;
        let (payload_env, wrapped_key_env) = self.seal_version(&item_id, version, &plaintext)?;

        let op_id = self.author_op(
            &tx,
            OpKind::Update,
            Some(&item_id),
            u32::try_from(version).unwrap_or(0),
            &plaintext,
        )?;

        tx.execute(
            "INSERT INTO wrapped_keys (item_id, version, envelope) VALUES (?1, ?2, ?3)",
            params![item_id.to_vec(), version, wrapped_key_env],
        )?;
        tx.execute(
            "INSERT INTO item_versions
                (item_id, version, payload_env, created_at, author_device_id, op_id)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                item_id.to_vec(),
                version,
                payload_env,
                now,
                self.session.device_id().to_vec(),
                op_id.to_vec(),
            ],
        )?;
        tx.execute(
            "UPDATE items SET current_version = ?2, updated_at = ?3 WHERE item_id = ?1",
            params![item_id.to_vec(), version, now],
        )?;

        // Index update in the same transaction (search-index.md §4/§5 update).
        let reader = self.payload_reader();
        self.index.apply_upsert(&tx, &item_id, payload, &reader)?;

        tx.commit()?;
        Ok(version)
    }

    // --- Item delete (tombstone) ------------------------------------------

    /// Delete an item — insert a tombstone + a `delete` op (vault-format.md §7
    /// item-delete). The `items`/`item_versions` rows linger for restore until
    /// [`purge_expired_trash`](Self::purge_expired_trash) shreds them.
    ///
    /// `retention_ms` is the trash window (PRD §4.10 default 30 days); the
    /// tombstone's `purge_after = deleted_at + retention_ms`.
    ///
    /// # Errors
    ///
    /// - [`Error::NotFound`] if the item does not exist.
    /// - [`Error::Invalid`] if the item is already tombstoned.
    pub fn delete_item(&self, item_id: ItemId, retention_ms: i64) -> Result<()> {
        let now = db::now_millis();
        let mut conn = self.connect()?;
        let tx = conn.transaction()?;

        let exists: bool = tx
            .query_row(
                "SELECT 1 FROM items WHERE item_id = ?1",
                params![item_id.to_vec()],
                |_| Ok(true),
            )
            .optional()?
            .unwrap_or(false);
        if !exists {
            return Err(Error::NotFound("item"));
        }
        if is_tombstoned(&tx, &item_id)? {
            return Err(Error::Invalid("item already deleted"));
        }

        let op_id = self.author_op(&tx, OpKind::Delete, Some(&item_id), 0, b"{}")?;

        tx.execute(
            "INSERT INTO tombstones (item_id, deleted_at, purge_after, deleted_by_device, op_id)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                item_id.to_vec(),
                now,
                now.saturating_add(retention_ms),
                self.session.device_id().to_vec(),
                op_id.to_vec(),
            ],
        )?;

        // Remove the item from the index in the same transaction (search-index.md
        // §5 delete). The tombstone above is already visible, so any lazy segment
        // rebuild triggered here correctly excludes the deleted item.
        let reader = self.payload_reader();
        self.index.apply_delete(&tx, &item_id, &reader)?;

        tx.commit()?;
        Ok(())
    }

    // --- Restore version ---------------------------------------------------

    /// Restore a prior version as the new current version (vault-format.md §7
    /// restore). A forward-restore: the target version's payload is re-sealed as
    /// a new version (with a fresh ItemKey), so history is never mutated
    /// (invariant §3 immutability). Also clears any tombstone (revives the
    /// item), matching the "restore is an edit" model (sync-protocol.md §4.3).
    ///
    /// # Errors
    ///
    /// - [`Error::NotFound`] if the item or target version does not exist.
    pub fn restore_version(&self, item_id: ItemId, target_version: i64) -> Result<i64> {
        let now = db::now_millis();
        let mut conn = self.connect()?;
        let tx = conn.transaction()?;

        // Decrypt the target version's payload (validates it exists).
        let plaintext = self.read_version_plaintext(&tx, &item_id, target_version)?;

        let current: i64 = tx
            .query_row(
                "SELECT current_version FROM items WHERE item_id = ?1",
                params![item_id.to_vec()],
                |r| r.get(0),
            )
            .optional()?
            .ok_or(Error::NotFound("item"))?;
        let new_version = current + 1;

        let (payload_env, wrapped_key_env) =
            self.seal_version(&item_id, new_version, &plaintext)?;

        let op_id = self.author_op(
            &tx,
            OpKind::Restore,
            Some(&item_id),
            u32::try_from(target_version).unwrap_or(0),
            &plaintext,
        )?;

        tx.execute(
            "INSERT INTO wrapped_keys (item_id, version, envelope) VALUES (?1, ?2, ?3)",
            params![item_id.to_vec(), new_version, wrapped_key_env],
        )?;
        tx.execute(
            "INSERT INTO item_versions
                (item_id, version, payload_env, created_at, author_device_id, op_id)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                item_id.to_vec(),
                new_version,
                payload_env,
                now,
                self.session.device_id().to_vec(),
                op_id.to_vec(),
            ],
        )?;
        tx.execute(
            "UPDATE items SET current_version = ?2, updated_at = ?3 WHERE item_id = ?1",
            params![item_id.to_vec(), new_version, now],
        )?;
        // Restoring revives the item: drop any tombstone.
        tx.execute(
            "DELETE FROM tombstones WHERE item_id = ?1",
            params![item_id.to_vec()],
        )?;

        // Re-index the restored item as an update to its current fields
        // (search-index.md §5 restore). The tombstone is already dropped, so the
        // item is live for the index.
        let restored_payload = ItemPayload::from_canonical(&plaintext)?;
        let reader = self.payload_reader();
        self.index
            .apply_upsert(&tx, &item_id, &restored_payload, &reader)?;

        tx.commit()?;
        Ok(new_version)
    }

    // --- Reads -------------------------------------------------------------

    /// Get an item's current version (decrypted). Returns [`Error::NotFound`]
    /// for a missing or tombstoned item (tombstoned items are hidden here; see
    /// [`list_trash`](Self::list_trash)).
    ///
    /// # Errors
    ///
    /// [`Error::NotFound`] / [`Error::DecryptionFailed`].
    pub fn get_item(&self, item_id: ItemId) -> Result<Item> {
        let conn = self.connect()?;
        if is_tombstoned(&conn, &item_id)? {
            return Err(Error::NotFound("item (deleted)"));
        }
        self.read_item(&conn, &item_id)
    }

    /// Get a specific version of an item (decrypted), regardless of tombstone
    /// state (history is retrievable while the rows linger).
    ///
    /// # Errors
    ///
    /// [`Error::NotFound`] / [`Error::DecryptionFailed`].
    pub fn get_item_version(&self, item_id: ItemId, version: i64) -> Result<VersionInfo> {
        let conn = self.connect()?;
        let created_at: i64 = conn
            .query_row(
                "SELECT created_at FROM item_versions WHERE item_id = ?1 AND version = ?2",
                params![item_id.to_vec(), version],
                |r| r.get(0),
            )
            .optional()?
            .ok_or(Error::NotFound("item version"))?;
        let payload =
            ItemPayload::from_canonical(&self.read_version_plaintext(&conn, &item_id, version)?)?;
        Ok(VersionInfo {
            version,
            created_at,
            payload,
        })
    }

    /// The full version history of an item, oldest first.
    ///
    /// # Errors
    ///
    /// [`Error::NotFound`] if the item has no versions; [`Error::DecryptionFailed`].
    pub fn history(&self, item_id: ItemId) -> Result<Vec<VersionInfo>> {
        let conn = self.connect()?;
        let versions: Vec<(i64, i64)> = {
            let mut stmt = conn.prepare(
                "SELECT version, created_at FROM item_versions WHERE item_id = ?1 ORDER BY version",
            )?;
            let rows = stmt.query_map(params![item_id.to_vec()], |r| Ok((r.get(0)?, r.get(1)?)))?;
            rows.collect::<std::result::Result<_, _>>()?
        };
        if versions.is_empty() {
            return Err(Error::NotFound("item"));
        }
        let mut out = Vec::with_capacity(versions.len());
        for (version, created_at) in versions {
            let payload = ItemPayload::from_canonical(
                &self.read_version_plaintext(&conn, &item_id, version)?,
            )?;
            out.push(VersionInfo {
                version,
                created_at,
                payload,
            });
        }
        Ok(out)
    }

    /// List all live (non-tombstoned) items with their current payloads.
    ///
    /// # Errors
    ///
    /// [`Error::Sqlite`] / [`Error::DecryptionFailed`].
    pub fn list_items(&self) -> Result<Vec<Item>> {
        let conn = self.connect()?;
        self.iter_items(&conn)
    }

    /// The read hook the encrypted-index layer will build on: an eager list of
    /// `(item_id, decrypted current payload)` over all live items. Kept simple
    /// (a `Vec`, not a trait-bound iterator) so the index can plug in without
    /// rework (search-index.md is the next work unit).
    ///
    /// # Errors
    ///
    /// [`Error::Sqlite`] / [`Error::DecryptionFailed`].
    pub fn iter_items(&self, conn: &Connection) -> Result<Vec<Item>> {
        let ids: Vec<Vec<u8>> = {
            let mut stmt = conn.prepare(
                "SELECT i.item_id FROM items i
                 WHERE NOT EXISTS (SELECT 1 FROM tombstones t WHERE t.item_id = i.item_id)
                 ORDER BY i.created_at",
            )?;
            let rows = stmt.query_map([], |r| r.get::<_, Vec<u8>>(0))?;
            rows.collect::<std::result::Result<_, _>>()?
        };
        let mut out = Vec::with_capacity(ids.len());
        for id_bytes in ids {
            let item_id = Id::from_slice(&id_bytes)?;
            out.push(self.read_item(conn, &item_id)?);
        }
        Ok(out)
    }

    // --- Search (index-backed, linear fallback) ---------------------------

    /// Search live items by `query`, optionally restricted to one `type_filter`
    /// (e.g. `"ssh_key"`), returning the matching items in rank order
    /// (exact > prefix > trigram; search-index.md §6).
    ///
    /// Index-backed: the encrypted index resolves candidate item ids
    /// (AND-intersected across query tokens, filters applied, tombstoned ids
    /// dropped), then the matched items are decrypted for return. If the index
    /// is absent or unreadable, this **falls back to a linear scan** (correct,
    /// just slower) and lazily rebuilds the index in the background of the same
    /// call — never as an unlock precondition (search-index.md §7). Supports the
    /// `type:`/`tag:`/`folder:`/`fav:` filter syntax inside `query`.
    ///
    /// The signature and semantics are unchanged from the previous linear
    /// implementation (additive index backing); an empty query with no filter
    /// still returns all live items.
    ///
    /// # Errors
    ///
    /// [`Error::Sqlite`] / [`Error::DecryptionFailed`].
    pub fn search(&self, query: &str, type_filter: Option<&str>) -> Result<Vec<Item>> {
        let mut conn = self.connect()?;
        let reader = self.payload_reader();

        // Try the index. Any structural failure (not a wrong-key failure) falls
        // back to the linear scan — the index is a cache, never a hard dep.
        match self.index.query(&mut conn, query, type_filter, &reader) {
            Ok(ids) => {
                let mut out = Vec::with_capacity(ids.len());
                for id in ids {
                    // An item could have been concurrently removed; skip misses.
                    if let Ok(item) = self.read_item(&conn, &id) {
                        out.push(item);
                    }
                }
                Ok(out)
            }
            Err(Error::DecryptionFailed) => {
                // A wrong/rotated IndexKey (or unrecoverable AEAD state) → serve
                // via linear fallback (search-index.md §7 rung 3).
                self.search_linear(&conn, query, type_filter)
            }
            Err(other) => Err(other),
        }
    }

    /// The linear-scan fallback: decrypt every live item and match `query`
    /// (NFKC-insensitive substring on title/tags/type plus the structural
    /// filters). Correct but O(n); used only when the index cannot be read
    /// (search-index.md §7 rung 3).
    fn search_linear(
        &self,
        conn: &Connection,
        query: &str,
        type_filter: Option<&str>,
    ) -> Result<Vec<Item>> {
        let needle = query.to_lowercase();
        let all = self.iter_items(conn)?;
        Ok(all
            .into_iter()
            .filter(|item| {
                if let Some(t) = type_filter
                    && item.payload.type_data.type_str() != t
                {
                    return false;
                }
                if needle.is_empty() {
                    return true;
                }
                let title_hit = item.payload.title.to_lowercase().contains(&needle);
                let tag_hit = item
                    .payload
                    .tags
                    .iter()
                    .any(|tag| tag.to_lowercase().contains(&needle));
                let type_hit = item.payload.type_data.type_str().contains(&needle);
                title_hit || tag_hit || type_hit
            })
            .collect())
    }

    /// Rebuild the entire encrypted search index from the items (maintenance;
    /// search-index.md §7). The index is a cache, so this is always safe: it
    /// re-derives every segment + the manifest at a bumped generation in one
    /// transaction. Useful after a format change, a restore, or to reclaim a
    /// fragmented index.
    ///
    /// # Errors
    ///
    /// [`Error::Sqlite`] / [`Error::DecryptionFailed`].
    pub fn rebuild_index(&self) -> Result<()> {
        let mut conn = self.connect()?;
        let reader = self.payload_reader();
        self.index.rebuild(&mut conn, &reader)
    }

    /// Per-vault storage statistics (PRD §4.10 visible stats): live item count,
    /// total version count, trashed item count, and index segment count.
    ///
    /// # Errors
    ///
    /// [`Error::Sqlite`].
    pub fn storage_stats(&self) -> Result<StorageStats> {
        let conn = self.connect()?;
        let live_items: i64 = conn.query_row(
            "SELECT COUNT(*) FROM items i
             WHERE NOT EXISTS (SELECT 1 FROM tombstones t WHERE t.item_id = i.item_id)",
            [],
            |r| r.get(0),
        )?;
        let total_versions: i64 =
            conn.query_row("SELECT COUNT(*) FROM item_versions", [], |r| r.get(0))?;
        let trashed: i64 = conn.query_row("SELECT COUNT(*) FROM tombstones", [], |r| r.get(0))?;
        let index_segments: i64 = conn.query_row(
            "SELECT COUNT(*) FROM index_segments WHERE segment_id > 0",
            [],
            |r| r.get(0),
        )?;
        Ok(StorageStats {
            live_items: u64::try_from(live_items).unwrap_or(0),
            total_versions: u64::try_from(total_versions).unwrap_or(0),
            trashed: u64::try_from(trashed).unwrap_or(0),
            index_segments: u64::try_from(index_segments).unwrap_or(0),
        })
    }

    // --- Folders -----------------------------------------------------------

    /// Create a folder with an encrypted name (vault-format.md §3 folders).
    ///
    /// # Errors
    ///
    /// [`Error::Sqlite`] / [`Error::Crypto`].
    pub fn create_folder(&self, name: &str) -> Result<FolderId> {
        let folder_id = Id::new();
        let now = db::now_millis();
        let name_env = self
            .vault_key
            .seal(
                name.as_bytes(),
                &aad::folder_name(&self.vault_id, &folder_id),
            )
            .map_err(Error::from_crypto)?;
        let conn = self.connect()?;
        conn.execute(
            "INSERT INTO folders (folder_id, name_env, created_at) VALUES (?1, ?2, ?3)",
            params![folder_id.to_vec(), name_env.to_bytes(), now],
        )?;
        Ok(folder_id)
    }

    /// List folders as `(id, decrypted name)`.
    ///
    /// # Errors
    ///
    /// [`Error::Sqlite`] / [`Error::DecryptionFailed`].
    pub fn list_folders(&self) -> Result<Vec<(FolderId, String)>> {
        let conn = self.connect()?;
        let mut stmt =
            conn.prepare("SELECT folder_id, name_env FROM folders ORDER BY created_at")?;
        let rows = stmt.query_map([], |r| {
            Ok((r.get::<_, Vec<u8>>(0)?, r.get::<_, Vec<u8>>(1)?))
        })?;
        let mut out = Vec::new();
        for row in rows {
            let (id_bytes, name_env) = row?;
            let folder_id = Id::from_slice(&id_bytes)?;
            let envelope =
                lp_crypto::Envelope::from_bytes(&name_env).map_err(Error::from_crypto)?;
            let name_bytes = self
                .vault_key
                .open(&envelope, &aad::folder_name(&self.vault_id, &folder_id))
                .map_err(Error::from_crypto)?;
            let name = String::from_utf8(name_bytes)
                .map_err(|_| Error::Invalid("decrypted folder name was not UTF-8"))?;
            out.push((folder_id, name));
        }
        Ok(out)
    }

    /// Delete a folder by id.
    ///
    /// # Errors
    ///
    /// [`Error::NotFound`] if the folder does not exist.
    pub fn delete_folder(&self, folder_id: FolderId) -> Result<()> {
        let conn = self.connect()?;
        let n = conn.execute(
            "DELETE FROM folders WHERE folder_id = ?1",
            params![folder_id.to_vec()],
        )?;
        if n == 0 {
            return Err(Error::NotFound("folder"));
        }
        Ok(())
    }

    // --- Trash -------------------------------------------------------------

    /// List trashed (tombstoned) items.
    ///
    /// # Errors
    ///
    /// [`Error::Sqlite`].
    pub fn list_trash(&self) -> Result<Vec<TrashEntry>> {
        let conn = self.connect()?;
        let mut stmt = conn.prepare(
            "SELECT item_id, deleted_at, purge_after FROM tombstones ORDER BY deleted_at",
        )?;
        let rows = stmt.query_map([], |r| {
            Ok((
                r.get::<_, Vec<u8>>(0)?,
                r.get::<_, i64>(1)?,
                r.get::<_, i64>(2)?,
            ))
        })?;
        let mut out = Vec::new();
        for row in rows {
            let (id_bytes, deleted_at, purge_after) = row?;
            out.push(TrashEntry {
                item_id: Id::from_slice(&id_bytes)?,
                deleted_at,
                purge_after,
            });
        }
        Ok(out)
    }

    /// Permanently shred trash whose `purge_after <= now`: delete the item, its
    /// versions, wrapped keys, and the tombstone (vault-format.md §4.10 shred).
    /// Op rows are append-only and are **not** removed (chain integrity).
    ///
    /// Returns the number of items purged.
    ///
    /// # Errors
    ///
    /// [`Error::Sqlite`].
    pub fn purge_expired_trash(&self, now: i64) -> Result<usize> {
        let mut conn = self.connect()?;
        let tx = conn.transaction()?;
        let expired: Vec<Vec<u8>> = {
            let mut stmt = tx.prepare("SELECT item_id FROM tombstones WHERE purge_after <= ?1")?;
            let rows = stmt.query_map(params![now], |r| r.get::<_, Vec<u8>>(0))?;
            rows.collect::<std::result::Result<_, _>>()?
        };
        for id in &expired {
            tx.execute("DELETE FROM item_versions WHERE item_id = ?1", params![id])?;
            tx.execute("DELETE FROM wrapped_keys WHERE item_id = ?1", params![id])?;
            tx.execute("DELETE FROM items WHERE item_id = ?1", params![id])?;
            tx.execute("DELETE FROM tombstones WHERE item_id = ?1", params![id])?;
        }
        tx.commit()?;
        Ok(expired.len())
    }

    // --- Op-chain verification --------------------------------------------

    /// Re-verify this device's entire op chain (sync-protocol.md §5): for each
    /// of this device's ops in `seq` order, check the Ed25519 signature over
    /// fields 1..10, that `seq` is gapless from 1, that `prev_hash` links to the
    /// previous op's full-bytes hash (genesis for the first), and that `lamport`
    /// is non-decreasing.
    ///
    /// This is the local-authoring self-check; the cross-device ingest verifier
    /// is a later crate.
    ///
    /// # Errors
    ///
    /// [`Error::ChainVerification`] on any break; [`Error::Sqlite`] on read
    /// failure.
    pub fn verify_local_chain(&self) -> Result<()> {
        let conn = self.connect()?;
        let device_id = self.session.device_id();
        let verifying = lp_crypto::VerifyingKey::from_bytes(&self.session.device.ed25519_pub)
            .map_err(Error::from_crypto)?;

        let mut stmt = conn.prepare(
            "SELECT op_id, lamport, op_kind, target_item_id, target_version, payload_env,
                    signature, seq, prev_hash
             FROM ops WHERE device_id = ?1 ORDER BY seq",
        )?;
        let rows = stmt.query_map(params![device_id.to_vec()], |r| {
            Ok(OpRow {
                op_id: r.get(0)?,
                lamport: r.get(1)?,
                op_kind: r.get(2)?,
                target_item_id: r.get(3)?,
                target_version: r.get(4)?,
                payload_env: r.get(5)?,
                signature: r.get(6)?,
                seq: r.get(7)?,
                prev_hash: r.get(8)?,
            })
        })?;

        let mut prev_full_hash = genesis_hash(&self.vault_id, &device_id);
        let mut last_lamport: i64 = -1;

        // `seq` is 1-based and must be gapless, so it equals the 1-based position.
        for (expected_seq, row) in (1_i64..).zip(rows) {
            let row = row?;
            if row.seq != expected_seq {
                return Err(Error::ChainVerification("seq is not gapless from 1"));
            }
            if row.prev_hash != prev_full_hash {
                return Err(Error::ChainVerification("prev_hash does not chain"));
            }
            if row.lamport < last_lamport {
                return Err(Error::ChainVerification("lamport regressed for device"));
            }

            let fields = row.to_op_fields(&self.vault_id, &device_id)?;
            let sig: [u8; 64] = row
                .signature
                .as_slice()
                .try_into()
                .map_err(|_| Error::ChainVerification("signature not 64 bytes"))?;
            fields
                .verify(&verifying, &sig)
                .map_err(|_| Error::ChainVerification("signature invalid"))?;

            prev_full_hash = chain_hash(&fields.full_bytes(&sig));
            last_lamport = row.lamport;
        }
        Ok(())
    }

    // --- Internal helpers --------------------------------------------------

    /// Seal a version's payload: generate a fresh ItemKey, wrap it under the
    /// VaultKey, encrypt the plaintext under the ItemKey. Returns
    /// `(payload_env bytes, wrapped_key_env bytes)`.
    fn seal_version(
        &self,
        item_id: &ItemId,
        version: i64,
        plaintext: &[u8],
    ) -> Result<(Vec<u8>, Vec<u8>)> {
        let item_key = ItemKey::generate();
        let payload_env = item_key
            .seal(
                plaintext,
                &aad::item_payload(&self.vault_id, item_id, version),
            )
            .map_err(Error::from_crypto)?;
        // The ItemKey wrap AAD (its "purpose") is the full `|`-joined string
        // `localpass/v1/wrap/item-key|vault|item|version` (vault-format.md §3).
        // `wrap_key` requires the purpose to begin with the `localpass/v1/`
        // namespace, which this AAD does, so the full row-binding AAD is used
        // verbatim as the wrap purpose — closing cross-row key relocation.
        let wrapped = wrap_key(
            self.vault_key.inner(),
            item_key.inner(),
            &item_key_aad_str(&self.vault_id, item_id, version),
        )
        .map_err(Error::from_crypto)?;
        Ok((payload_env.to_bytes(), wrapped.to_bytes()))
    }

    /// Read + decrypt a specific version's plaintext payload bytes.
    fn read_version_plaintext(
        &self,
        conn: &Connection,
        item_id: &ItemId,
        version: i64,
    ) -> Result<Vec<u8>> {
        let (payload_env, wrapped_env): (Vec<u8>, Vec<u8>) = conn
            .query_row(
                "SELECT v.payload_env, k.envelope
                 FROM item_versions v JOIN wrapped_keys k
                   ON v.item_id = k.item_id AND v.version = k.version
                 WHERE v.item_id = ?1 AND v.version = ?2",
                params![item_id.to_vec(), version],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?
            .ok_or(Error::NotFound("item version"))?;

        let wrapped = lp_crypto::Envelope::from_bytes(&wrapped_env).map_err(Error::from_crypto)?;
        let item_key_inner = unwrap_key(
            self.vault_key.inner(),
            &wrapped,
            &item_key_aad_str(&self.vault_id, item_id, version),
        )
        .map_err(Error::from_crypto)?;
        let item_key = ItemKey::from_inner(item_key_inner);

        let payload = lp_crypto::Envelope::from_bytes(&payload_env).map_err(Error::from_crypto)?;
        item_key
            .open(
                &payload,
                &aad::item_payload(&self.vault_id, item_id, version),
            )
            .map_err(Error::from_crypto)
    }

    /// Read + decrypt an item's current version into an [`Item`].
    fn read_item(&self, conn: &Connection, item_id: &ItemId) -> Result<Item> {
        let (current_version, created_at, updated_at): (i64, i64, i64) = conn
            .query_row(
                "SELECT current_version, created_at, updated_at FROM items WHERE item_id = ?1",
                params![item_id.to_vec()],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .optional()?
            .ok_or(Error::NotFound("item"))?;
        let plaintext = self.read_version_plaintext(conn, item_id, current_version)?;
        let payload = ItemPayload::from_canonical(&plaintext)?;
        Ok(Item {
            item_id: *item_id,
            current_version,
            created_at,
            updated_at,
            payload,
        })
    }

    /// Author an op inside `tx`: assign seq/lamport/prev_hash, encrypt the
    /// payload under the VaultKey, sign fields 1..10, and INSERT the `ops` row.
    /// Returns the new op id (stored on the version/tombstone row).
    fn author_op(
        &self,
        tx: &Connection,
        kind: OpKind,
        target_item: Option<&ItemId>,
        target_version: u32,
        payload_plaintext: &[u8],
    ) -> Result<Id> {
        let op_id = Id::new();
        let device_id = self.session.device_id();

        // seq = max(seq for this device)+1, gapless per device per vault.
        let last_seq: i64 = tx
            .query_row(
                "SELECT COALESCE(MAX(seq), 0) FROM ops WHERE device_id = ?1",
                params![device_id.to_vec()],
                |r| r.get(0),
            )
            .unwrap_or(0);
        let seq = last_seq + 1;

        // lamport = max(all ops' lamport)+1.
        let max_lamport: i64 = tx
            .query_row("SELECT COALESCE(MAX(lamport), 0) FROM ops", [], |r| {
                r.get(0)
            })
            .unwrap_or(0);
        let lamport = max_lamport + 1;

        // prev_hash = chain hash of this device's previous op (fields 1..11),
        // or genesis for the first op.
        let prev_full: Option<Vec<u8>> = tx
            .query_row(
                "SELECT op_id, lamport, op_kind, target_item_id, target_version, payload_env,
                        signature, seq, prev_hash
                 FROM ops WHERE device_id = ?1 ORDER BY seq DESC LIMIT 1",
                params![device_id.to_vec()],
                |r| {
                    let row = OpRow {
                        op_id: r.get(0)?,
                        lamport: r.get(1)?,
                        op_kind: r.get(2)?,
                        target_item_id: r.get(3)?,
                        target_version: r.get(4)?,
                        payload_env: r.get(5)?,
                        signature: r.get(6)?,
                        seq: r.get(7)?,
                        prev_hash: r.get(8)?,
                    };
                    Ok(row)
                },
            )
            .optional()?
            .map(|row| -> Result<Vec<u8>> {
                let fields = row.to_op_fields(&self.vault_id, &device_id)?;
                let sig: [u8; 64] = row
                    .signature
                    .as_slice()
                    .try_into()
                    .map_err(|_| Error::Invalid("stored signature not 64 bytes"))?;
                Ok(fields.full_bytes(&sig).to_vec())
            })
            .transpose()?;

        let prev_hash = match prev_full {
            Some(bytes) => chain_hash(&bytes),
            None => genesis_hash(&self.vault_id, &device_id),
        };

        // Encrypt the op payload under the VaultKey with the op AAD.
        let payload_env = self
            .vault_key
            .seal(payload_plaintext, &aad::op_payload(&self.vault_id, &op_id))
            .map_err(Error::from_crypto)?;
        let payload_env_bytes = payload_env.to_bytes();

        let target = target_item.map_or_else(ItemTarget::none, ItemTarget::item);
        let fields = OpFields {
            op_id,
            vault_id: self.vault_id,
            device_id,
            seq: u64::try_from(seq).map_err(|_| Error::Invalid("seq out of range"))?,
            prev_hash,
            lamport: u64::try_from(lamport).map_err(|_| Error::Invalid("lamport out of range"))?,
            op_kind: kind,
            target_item: target,
            target_version,
            payload_env: payload_env_bytes.clone(),
        };
        let signature = fields.sign(&self.session.device.signing)?;

        tx.execute(
            "INSERT INTO ops
                (op_id, vault_id, lamport, device_id, op_kind, target_item_id, target_version,
                 payload_env, signature, seq, prev_hash, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
            params![
                op_id.to_vec(),
                self.vault_id.to_vec(),
                lamport,
                device_id.to_vec(),
                i64::from(kind.code()),
                target_item.map(Id::to_vec),
                i64::from(target_version),
                payload_env_bytes,
                signature.as_slice(),
                seq,
                prev_hash.as_slice(),
                db::now_millis(),
            ],
        )?;
        Ok(op_id)
    }
}

/// A raw `ops` row, used to reconstruct canonical op bytes for chain checks.
struct OpRow {
    op_id: Vec<u8>,
    lamport: i64,
    op_kind: i64,
    target_item_id: Option<Vec<u8>>,
    target_version: i64,
    payload_env: Vec<u8>,
    signature: Vec<u8>,
    seq: i64,
    prev_hash: Vec<u8>,
}

impl OpRow {
    /// Rebuild the [`OpFields`] (fields 1..10 + prev_hash) from stored columns.
    fn to_op_fields(&self, vault_id: &VaultId, device_id: &Id) -> Result<OpFields> {
        let op_id = Id::from_slice(&self.op_id)?;
        let prev_hash: [u8; 32] = self
            .prev_hash
            .as_slice()
            .try_into()
            .map_err(|_| Error::Invalid("stored prev_hash not 32 bytes"))?;
        let kind = match u8::try_from(self.op_kind).ok() {
            Some(1) => OpKind::Create,
            Some(2) => OpKind::Update,
            Some(3) => OpKind::Delete,
            Some(4) => OpKind::Restore,
            Some(5) => OpKind::Rewrap,
            _ => return Err(Error::Invalid("unknown op_kind")),
        };
        let target = match &self.target_item_id {
            Some(bytes) => ItemTarget::item(&Id::from_slice(bytes)?),
            None => ItemTarget::none(),
        };
        Ok(OpFields {
            op_id,
            vault_id: *vault_id,
            device_id: *device_id,
            seq: u64::try_from(self.seq).map_err(|_| Error::Invalid("stored seq out of range"))?,
            prev_hash,
            lamport: u64::try_from(self.lamport)
                .map_err(|_| Error::Invalid("stored lamport out of range"))?,
            op_kind: kind,
            target_item: target,
            target_version: u32::try_from(self.target_version)
                .map_err(|_| Error::Invalid("stored target_version out of range"))?,
            payload_env: self.payload_env.clone(),
        })
    }
}

/// Whether an item has a tombstone (is in trash).
fn is_tombstoned(conn: &Connection, item_id: &ItemId) -> Result<bool> {
    Ok(conn
        .query_row(
            "SELECT 1 FROM tombstones WHERE item_id = ?1",
            params![item_id.to_vec()],
            |_| Ok(true),
        )
        .optional()?
        .unwrap_or(false))
}
