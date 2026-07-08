//! Encrypted file attachments — content-addressed blobs stored beside the vault
//! (vault-format.md §8).
//!
//! An attachment lets a user store an arbitrary file (a certificate, a
//! `service-account.json`, a binary secret) encrypted at rest and bound to an
//! item. This module is the storage foundation: [`Vault::add_attachment`],
//! [`Vault::list_attachments`], [`Vault::get_attachment`], and
//! [`Vault::delete_attachment`].
//!
//! # On-disk layout
//!
//! Blob **bytes never live in SQLite**. The ciphertext is written to
//! `<profile>/attachments/<vault_id_hyphenated>/<content_hash_hex>.blob`, where
//! `content_hash = BLAKE3(ciphertext)`. Content-addressing the *ciphertext*
//! gives dedup across identical stored blobs without any plaintext oracle, and
//! the per-vault subdir keeps a vault portable — the blobs travel with the
//! `.vault` file. The `attachments` table holds only references + wrapped keys
//! (vault-format.md §3).
//!
//! # Key wrapping + AAD binding
//!
//! Each attachment gets a **fresh** per-attachment [`SymmetricKey`]. The blob is
//! sealed under that key (AAD [`aad::attachment_blob`]); the key itself is
//! wrapped under the owning item's **current-version ItemKey** (AAD
//! [`aad::attachment_key`]); and the filename is sealed under the same ItemKey
//! (AAD [`aad::attachment_name`]). Because every AAD binds `vault_id +
//! attachment_id`, no wrapped key, filename, or blob can be relocated to a
//! different attachment, item, or vault — AEAD verification fails against the
//! reconstructed AAD (vault-format.md §3 anti-cut-and-paste). A wrong item key,
//! a tampered blob, or a copied row all fail closed as
//! [`Error::DecryptionFailed`].
//!
//! # Write ordering + durability
//!
//! On add, the ciphertext blob is written **first** (atomically: to a temp file,
//! then renamed), then the `attachments` row is committed in a transaction. If
//! the row commit fails, the freshly written blob is removed best-effort so a
//! crash never leaves a referenced-but-missing or orphaned blob. On delete, the
//! row is removed in a transaction and the blob file is unlinked **only** if no
//! other row references the same `content_hash` (dedup-safe).
//!
//! # Known limitation — attachments are local-only (no sync yet)
//!
//! Attachments are **not** part of the op log in this wave: adding, getting, or
//! deleting an attachment authors **no** op and ships nothing over the sync
//! channel. The blobs are local to this device; replicating them across devices
//! is a follow-up wave. This keeps the op chain and `verify_local_chain`
//! unaffected by attachment activity.

use lp_crypto::{ItemKey, SymmetricKey, blake3_256, unwrap_key, wrap_key};
use rusqlite::{Connection, OptionalExtension, params};
use zeroize::Zeroize;

use crate::aad;
use crate::db;
use crate::error::{Error, Result};
use crate::ids::{AttachmentId, Id, ItemId};
use crate::vault::Vault;

/// The maximum plaintext size of a single attachment, in bytes (50 MiB — the
/// PRD §4.1 default cap). Larger inputs are rejected before any blob is written.
pub const MAX_ATTACHMENT_BYTES: usize = 50 * 1024 * 1024;

/// The raw columns of a listing query row (before decrypting the filename):
/// `(attachment_id, version, size_plain, filename_env, created_at)`.
type ListRow = (Vec<u8>, i64, i64, Vec<u8>, i64);

/// A decrypted attachment listing entry ([`Vault::list_attachments`]).
#[derive(Clone, Debug)]
pub struct AttachmentInfo {
    /// The attachment id (UUIDv7).
    pub attachment_id: AttachmentId,
    /// The decrypted filename.
    pub filename: String,
    /// The plaintext size in bytes (structural; the `size_plain` column).
    pub size_plain: i64,
    /// The item version this attachment was recorded against.
    pub version: i64,
    /// When the attachment row was inserted (unix millis, plaintext).
    pub created_at: i64,
}

impl Vault<'_> {
    /// Store `data` as an encrypted attachment named `filename`, bound to
    /// `item_id` (vault-format.md §8). Returns the new [`AttachmentId`].
    ///
    /// A fresh per-attachment key seals the blob; that key is wrapped under the
    /// item's **current-version** ItemKey, and the filename is sealed under the
    /// same ItemKey. The ciphertext blob is written first (atomically) and the
    /// row is committed second; a row-commit failure removes the orphan blob.
    ///
    /// # Errors
    ///
    /// - [`Error::Invalid`] if `data` exceeds [`MAX_ATTACHMENT_BYTES`] (checked
    ///   before any blob is written) or the item is tombstoned.
    /// - [`Error::NotFound`] if the item does not exist.
    /// - [`Error::DecryptionFailed`] if the item's current ItemKey cannot be
    ///   unwrapped.
    /// - [`Error::Io`] / [`Error::Sqlite`] / [`Error::Crypto`] on failure.
    pub fn add_attachment(
        &self,
        item_id: ItemId,
        filename: &str,
        data: &[u8],
    ) -> Result<AttachmentId> {
        // Enforce the size cap BEFORE any crypto or filesystem work.
        if data.len() > self.max_attachment_bytes() {
            return Err(Error::Invalid("attachment exceeds the maximum size"));
        }

        let conn = self.connect_attachments()?;
        // The attachment binds to the item's CURRENT version's ItemKey.
        let version = current_version(&conn, &item_id)?;
        if is_item_tombstoned(&conn, &item_id)? {
            return Err(Error::Invalid("cannot attach to a deleted item"));
        }
        let item_key = self.load_item_key(&conn, &item_id, version)?;

        let attachment_id = Id::new();

        // Seal the blob under a fresh per-attachment key. The key is zeroized as
        // soon as it has been wrapped below.
        let att_key = SymmetricKey::generate();
        let blob = att_key
            .seal(
                data,
                &aad::attachment_blob(&self.vault_id(), &attachment_id),
            )
            .map_err(Error::from_crypto)?;
        let blob_bytes = blob.to_bytes();
        let content_hash = blake3_256(&blob_bytes);

        // Wrap the per-attachment key under the ItemKey and seal the filename.
        let wrapped_key = wrap_key(
            item_key.inner(),
            &att_key,
            attachment_key_aad_str(&self.vault_id(), &attachment_id).as_str(),
        )
        .map_err(Error::from_crypto)?;
        // The per-attachment key has served its purpose; wipe it.
        drop(att_key);

        let filename_env = item_key
            .seal(
                filename.as_bytes(),
                &aad::attachment_name(&self.vault_id(), &attachment_id),
            )
            .map_err(Error::from_crypto)?;

        // 1) Write the ciphertext blob FIRST (atomic write-then-rename), so a
        //    committed row is always backed by a readable blob.
        let blob_path = self.blob_path(&content_hash);
        self.write_blob_atomic(&blob_path, &blob_bytes)?;

        // 2) Commit the row in a transaction. On failure, remove the orphan blob
        //    (best-effort) UNLESS another row already references the same hash
        //    (dedup: an identical ciphertext could already be stored).
        let mut conn = conn;
        let now = db::now_millis();
        let insert = (|| -> Result<()> {
            let tx = conn.transaction()?;
            tx.execute(
                "INSERT INTO attachments
                    (attachment_id, item_id, version, content_hash, size_plain,
                     wrapped_key_env, filename_env, created_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                params![
                    attachment_id.to_vec(),
                    item_id.to_vec(),
                    version,
                    content_hash.as_slice(),
                    i64::try_from(data.len()).unwrap_or(i64::MAX),
                    wrapped_key.to_bytes(),
                    filename_env.to_bytes(),
                    now,
                ],
            )?;
            tx.commit()?;
            Ok(())
        })();

        if let Err(e) = insert {
            // Orphan cleanup: only remove the blob if no committed row references
            // this content_hash (a dedup sibling might already point at it).
            if !self.content_hash_referenced(&conn, &content_hash)? {
                let _ = std::fs::remove_file(&blob_path);
            }
            return Err(e);
        }

        Ok(attachment_id)
    }

    /// List the attachments of `item_id` with decrypted filenames + sizes
    /// (vault-format.md §8). Filenames are decrypted via the item's ItemKey for
    /// the version each attachment was recorded against.
    ///
    /// # Errors
    ///
    /// [`Error::Sqlite`] / [`Error::DecryptionFailed`] on failure.
    pub fn list_attachments(&self, item_id: ItemId) -> Result<Vec<AttachmentInfo>> {
        let conn = self.connect_attachments()?;
        let rows: Vec<ListRow> = {
            let mut stmt = conn.prepare(
                "SELECT attachment_id, version, size_plain, filename_env, created_at
                   FROM attachments WHERE item_id = ?1 ORDER BY created_at",
            )?;
            let rows = stmt.query_map(params![item_id.to_vec()], |r| {
                Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?))
            })?;
            rows.collect::<std::result::Result<_, _>>()?
        };

        let mut out = Vec::with_capacity(rows.len());
        for (id_bytes, version, size_plain, filename_env, created_at) in rows {
            let attachment_id = Id::from_slice(&id_bytes)?;
            let item_key = self.load_item_key(&conn, &item_id, version)?;
            let filename = self.open_filename(&item_key, &attachment_id, &filename_env)?;
            out.push(AttachmentInfo {
                attachment_id,
                filename,
                size_plain,
                version,
                created_at,
            });
        }
        Ok(out)
    }

    /// Read + decrypt an attachment by id (vault-format.md §8): read the blob,
    /// unwrap the per-attachment key under the item's ItemKey, open the
    /// envelope (which verifies the AAD binding), and return
    /// `(filename, plaintext)`.
    ///
    /// A tampered blob, a copied wrapped-key row, or a wrong item all fail closed
    /// as [`Error::DecryptionFailed`].
    ///
    /// # Errors
    ///
    /// - [`Error::NotFound`] if the attachment id is unknown or its blob is
    ///   missing on disk.
    /// - [`Error::DecryptionFailed`] on any authentication failure.
    /// - [`Error::Sqlite`] / [`Error::Io`] on failure.
    pub fn get_attachment(&self, attachment_id: AttachmentId) -> Result<(String, Vec<u8>)> {
        let conn = self.connect_attachments()?;
        let (item_id, version, content_hash, wrapped_key_env, filename_env) =
            self.read_attachment_row(&conn, &attachment_id)?;

        let item_key = self.load_item_key(&conn, &item_id, version)?;
        let filename = self.open_filename(&item_key, &attachment_id, &filename_env)?;

        // Unwrap the per-attachment key under the ItemKey (AAD-bound).
        let wrapped =
            lp_crypto::Envelope::from_bytes(&wrapped_key_env).map_err(Error::from_crypto)?;
        let att_key = unwrap_key(
            item_key.inner(),
            &wrapped,
            attachment_key_aad_str(&self.vault_id(), &attachment_id).as_str(),
        )
        .map_err(Error::from_crypto)?;

        // Read the blob and open it under the per-attachment key + blob AAD.
        let blob_path = self.blob_path(&content_hash_array(&content_hash)?);
        let blob_bytes = match std::fs::read(&blob_path) {
            Ok(b) => b,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return Err(Error::NotFound("attachment blob"));
            }
            Err(e) => return Err(Error::Io(e)),
        };
        let envelope = lp_crypto::Envelope::from_bytes(&blob_bytes).map_err(Error::from_crypto)?;
        let plaintext = att_key
            .open(
                &envelope,
                &aad::attachment_blob(&self.vault_id(), &attachment_id),
            )
            .map_err(Error::from_crypto)?;
        // The per-attachment key drops (and zeroizes) here.
        drop(att_key);

        Ok((filename, plaintext))
    }

    /// Delete an attachment by id (vault-format.md §8): remove the row, and unlink
    /// its blob file **only** if no other row references the same `content_hash`
    /// (dedup-safe). The row delete and the reference check run in one
    /// transaction so a concurrent add cannot race the reference count.
    ///
    /// # Errors
    ///
    /// - [`Error::NotFound`] if the attachment id is unknown.
    /// - [`Error::Sqlite`] / [`Error::Io`] on failure.
    pub fn delete_attachment(&self, attachment_id: AttachmentId) -> Result<()> {
        let mut conn = self.connect_attachments()?;

        // Read the content_hash first (also validates existence).
        let content_hash: Vec<u8> = conn
            .query_row(
                "SELECT content_hash FROM attachments WHERE attachment_id = ?1",
                params![attachment_id.to_vec()],
                |r| r.get(0),
            )
            .optional()?
            .ok_or(Error::NotFound("attachment"))?;

        let tx = conn.transaction()?;
        tx.execute(
            "DELETE FROM attachments WHERE attachment_id = ?1",
            params![attachment_id.to_vec()],
        )?;
        // Is the content still referenced by a sibling row (dedup)? Checked
        // inside the same transaction, after the delete, so the answer is
        // consistent with the row we just removed.
        let still_referenced: bool = tx
            .query_row(
                "SELECT 1 FROM attachments WHERE content_hash = ?1 LIMIT 1",
                params![content_hash],
                |_| Ok(true),
            )
            .optional()?
            .unwrap_or(false);
        tx.commit()?;

        // Unlink the blob only when nothing references it any more. Best-effort:
        // the row is authoritative, so a failed unlink leaves a harmless orphan
        // blob rather than failing the (committed) delete.
        if !still_referenced {
            let hash: [u8; 32] = content_hash_array(&content_hash)?;
            let _ = std::fs::remove_file(self.blob_path(&hash));
        }
        Ok(())
    }

    // --- internal helpers --------------------------------------------------

    /// The effective size cap. Always [`MAX_ATTACHMENT_BYTES`] (50 MiB) in
    /// release builds. In **debug builds only** (which is how the test suite
    /// runs), the `LP_MAX_ATTACHMENT_BYTES` env var may *lower* it so the
    /// reject-before-write path can be exercised without materializing 50 MiB.
    /// The override can only shrink the cap, never raise it, and is compiled out
    /// of release binaries entirely — so a production `localpass`/daemon always
    /// enforces the 50 MiB constant regardless of the environment.
    fn max_attachment_bytes(&self) -> usize {
        #[cfg(debug_assertions)]
        {
            if let Some(v) = std::env::var("LP_MAX_ATTACHMENT_BYTES")
                .ok()
                .and_then(|s| s.parse::<usize>().ok())
            {
                return v.min(MAX_ATTACHMENT_BYTES);
            }
        }
        MAX_ATTACHMENT_BYTES
    }

    /// Open a fresh connection to the vault file for attachment work.
    fn connect_attachments(&self) -> Result<Connection> {
        db::open_connection(self.vault_path_ref())
    }

    /// The path of a content-addressed blob under this vault's attachments dir.
    fn blob_path(&self, content_hash: &[u8; 32]) -> std::path::PathBuf {
        self.attachments_base_ref()
            .join(format!("{}.blob", hex_lower(content_hash)))
    }

    /// Atomically write `bytes` to `path`: write to a sibling temp file, fsync,
    /// then rename over the target, so a crash never leaves a half-written blob.
    /// Creates the parent directory (owner-only on Unix) if absent.
    fn write_blob_atomic(&self, path: &std::path::Path, bytes: &[u8]) -> Result<()> {
        use std::io::Write;

        let dir = self.attachments_base_ref();
        std::fs::create_dir_all(dir)?;

        // A unique temp name in the same dir (same filesystem → atomic rename).
        let tmp = dir.join(format!(".tmp-{}", Id::new().to_hyphenated()));
        {
            let mut f = std::fs::File::create(&tmp)?;
            f.write_all(bytes)?;
            f.sync_all()?;
        }
        // Owner-only permissions on the blob (mirrors db::restrict_permissions).
        db::restrict_permissions(&tmp)?;

        // Rename over the target. If a blob with this content_hash already exists
        // (dedup), the rename replaces it with byte-identical content — harmless.
        if let Err(e) = std::fs::rename(&tmp, path) {
            let _ = std::fs::remove_file(&tmp);
            return Err(Error::Io(e));
        }
        Ok(())
    }

    /// Load and re-tag the ItemKey for `(item_id, version)` from `wrapped_keys`,
    /// unwrapped under this vault's VaultKey (same mechanism as the item read
    /// path). Fails [`Error::NotFound`] if the version has no wrapped key.
    fn load_item_key(&self, conn: &Connection, item_id: &ItemId, version: i64) -> Result<ItemKey> {
        let wrapped_env: Vec<u8> = conn
            .query_row(
                "SELECT envelope FROM wrapped_keys WHERE item_id = ?1 AND version = ?2",
                params![item_id.to_vec(), version],
                |r| r.get(0),
            )
            .optional()?
            .ok_or(Error::NotFound("item version"))?;
        let wrapped = lp_crypto::Envelope::from_bytes(&wrapped_env).map_err(Error::from_crypto)?;
        let inner = unwrap_key(
            self.vault_key_ref().inner(),
            &wrapped,
            &item_key_aad_str(&self.vault_id(), item_id, version),
        )
        .map_err(Error::from_crypto)?;
        Ok(ItemKey::from_inner(inner))
    }

    /// Decrypt an attachment's filename under `item_key`, validating UTF-8.
    fn open_filename(
        &self,
        item_key: &ItemKey,
        attachment_id: &AttachmentId,
        filename_env: &[u8],
    ) -> Result<String> {
        let envelope = lp_crypto::Envelope::from_bytes(filename_env).map_err(Error::from_crypto)?;
        let mut bytes = item_key
            .open(
                &envelope,
                &aad::attachment_name(&self.vault_id(), attachment_id),
            )
            .map_err(Error::from_crypto)?;
        let name = String::from_utf8(bytes.clone())
            .map_err(|_| Error::Invalid("decrypted filename was not UTF-8"));
        bytes.zeroize();
        name
    }

    /// Read the stored columns of one attachment row (existence-checked).
    #[allow(clippy::type_complexity)]
    fn read_attachment_row(
        &self,
        conn: &Connection,
        attachment_id: &AttachmentId,
    ) -> Result<(ItemId, i64, Vec<u8>, Vec<u8>, Vec<u8>)> {
        let row = conn
            .query_row(
                "SELECT item_id, version, content_hash, wrapped_key_env, filename_env
                   FROM attachments WHERE attachment_id = ?1",
                params![attachment_id.to_vec()],
                |r| {
                    Ok((
                        r.get::<_, Vec<u8>>(0)?,
                        r.get::<_, i64>(1)?,
                        r.get::<_, Vec<u8>>(2)?,
                        r.get::<_, Vec<u8>>(3)?,
                        r.get::<_, Vec<u8>>(4)?,
                    ))
                },
            )
            .optional()?
            .ok_or(Error::NotFound("attachment"))?;
        let (item_bytes, version, content_hash, wrapped_key_env, filename_env) = row;
        Ok((
            Id::from_slice(&item_bytes)?,
            version,
            content_hash,
            wrapped_key_env,
            filename_env,
        ))
    }

    /// Whether any committed `attachments` row references `content_hash`.
    fn content_hash_referenced(&self, conn: &Connection, content_hash: &[u8; 32]) -> Result<bool> {
        Ok(conn
            .query_row(
                "SELECT 1 FROM attachments WHERE content_hash = ?1 LIMIT 1",
                params![content_hash.as_slice()],
                |_| Ok(true),
            )
            .optional()?
            .unwrap_or(false))
    }
}

/// The current version of `item_id`, or [`Error::NotFound`].
fn current_version(conn: &Connection, item_id: &ItemId) -> Result<i64> {
    conn.query_row(
        "SELECT current_version FROM items WHERE item_id = ?1",
        params![item_id.to_vec()],
        |r| r.get(0),
    )
    .optional()?
    .ok_or(Error::NotFound("item"))
}

/// Whether `item_id` has a tombstone (is in trash).
fn is_item_tombstoned(conn: &Connection, item_id: &ItemId) -> Result<bool> {
    Ok(conn
        .query_row(
            "SELECT 1 FROM tombstones WHERE item_id = ?1",
            params![item_id.to_vec()],
            |_| Ok(true),
        )
        .optional()?
        .unwrap_or(false))
}

/// Coerce a stored 32-byte content_hash blob into a fixed array.
fn content_hash_array(bytes: &[u8]) -> Result<[u8; 32]> {
    bytes
        .try_into()
        .map_err(|_| Error::Invalid("stored content_hash was not 32 bytes"))
}

/// Lowercase hex of a byte slice (blob file names are content-addressed hex).
fn hex_lower(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push(char::from_digit(u32::from(b >> 4), 16).unwrap());
        s.push(char::from_digit(u32::from(b & 0x0f), 16).unwrap());
    }
    s
}

/// The ItemKey wrap AAD as an owned `String` (the full `|`-joined row-binding
/// purpose). Valid UTF-8 by construction. Mirrors the vault module's helper so
/// the attachment path unwraps ItemKeys with the identical purpose.
fn item_key_aad_str(vault_id: &crate::ids::VaultId, item_id: &ItemId, version: i64) -> String {
    String::from_utf8(aad::item_key(vault_id, item_id, version)).expect("item-key AAD is UTF-8")
}

/// The attachment-key wrap AAD as an owned `String` (valid UTF-8 by
/// construction). `wrap_key`/`unwrap_key` take a `&str` purpose that must be in
/// the `localpass/v1/` namespace, which this AAD is.
fn attachment_key_aad_str(vault_id: &crate::ids::VaultId, attachment_id: &AttachmentId) -> String {
    String::from_utf8(aad::attachment_key(vault_id, attachment_id))
        .expect("attachment-key AAD is UTF-8")
}
