//! SQLite connection setup, DDL, and file permissions.
//!
//! # Durability PRAGMAs (vault-format.md §7, normative)
//!
//! Every connection to either file kind sets, in this order:
//!
//! - `journal_mode = WAL` — write-ahead logging;
//! - `synchronous = FULL` — fsync on every commit. NORMAL could lose the last
//!   committed write on power loss, unacceptable for a just-saved credential
//!   (LESSONS 2026-07-04 durability decision);
//! - `foreign_keys = ON` — enforce the FK constraints in the DDL.
//!
//! # File permissions
//!
//! On Unix the file is chmod'd to `0600` (owner read/write only) right after
//! creation (PRD §4.3). On Windows there is no POSIX mode; the file inherits the
//! user-profile directory ACLs, which are owner-scoped by default for
//! `%LOCALAPPDATA%`-style locations. This is noted rather than enforced here —
//! see the crate docs.

use rusqlite::Connection;
use std::path::Path;

use crate::error::Result;

/// The on-disk `format_version` this build writes and is willing to open.
pub const FORMAT_VERSION: i64 = 1;

/// The default cipher suite code (1 = XChaCha20-Poly1305, vault-format.md §2).
pub const CIPHER_SUITE_XCHACHA: i64 = 1;

/// `file_kind` string for the account store.
pub const FILE_KIND_ACCOUNT: &str = "account-store";
/// `file_kind` string for a vault file.
pub const FILE_KIND_VAULT: &str = "vault";

/// Open (creating if absent) a SQLite connection and apply the durability
/// PRAGMAs required by vault-format.md §7.
///
/// # Errors
///
/// Returns [`crate::Error::Sqlite`] if the file cannot be opened or a PRAGMA is
/// rejected.
pub fn open_connection(path: &Path) -> Result<Connection> {
    let conn = Connection::open(path)?;
    apply_pragmas(&conn)?;
    Ok(conn)
}

/// Apply the mandatory PRAGMAs to an open connection.
///
/// `journal_mode=WAL` returns the resulting mode as a row, so it is queried
/// rather than executed; the rest are plain sets.
fn apply_pragmas(conn: &Connection) -> Result<()> {
    // WAL is persistent (stored in the DB header) but re-asserting per
    // connection is cheap and guarantees it even on a freshly created file.
    let mode: String = conn.query_row("PRAGMA journal_mode = WAL", [], |r| r.get(0))?;
    debug_assert_eq!(mode.to_ascii_lowercase(), "wal");
    conn.pragma_update(None, "synchronous", "FULL")?;
    conn.pragma_update(None, "foreign_keys", "ON")?;
    Ok(())
}

/// Restrict a freshly created file to owner-only access.
///
/// On Unix: `chmod 0600`. On Windows: a no-op (the file inherits the
/// user-profile ACLs; see the crate docs). Safe to call more than once.
///
/// # Errors
///
/// Returns [`crate::Error::Io`] if the permission change fails on Unix.
#[allow(clippy::unnecessary_wraps)] // Result kept uniform across platforms.
pub fn restrict_permissions(path: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::Permissions::from_mode(0o600);
        std::fs::set_permissions(path, perms)?;
    }
    #[cfg(not(unix))]
    {
        // Windows: rely on default user-profile ACLs. No portable owner-only
        // chmod equivalent without pulling in a Win32 ACL crate, which is out of
        // scope for this work unit; documented in the crate root.
        let _ = path;
    }
    Ok(())
}

/// The DDL for the account store (`account.localpass`), verbatim from
/// vault-format.md §2.
pub const ACCOUNT_STORE_DDL: &str = r#"
CREATE TABLE meta (
    id                 INTEGER PRIMARY KEY CHECK (id = 1),
    format_version     INTEGER NOT NULL,
    file_kind          TEXT    NOT NULL,
    cipher_suite       INTEGER NOT NULL,
    created_at         INTEGER NOT NULL,
    schema_migrated_at INTEGER NOT NULL
);
CREATE TABLE kdf_params (
    id                INTEGER PRIMARY KEY CHECK (id = 1),
    kdf               INTEGER NOT NULL,
    argon2_m_kib      INTEGER NOT NULL,
    argon2_t          INTEGER NOT NULL,
    argon2_p          INTEGER NOT NULL,
    salt              BLOB    NOT NULL,
    secret_key_id     BLOB    NOT NULL
);
CREATE TABLE wrapped_account_key (
    id                INTEGER PRIMARY KEY CHECK (id = 1),
    envelope          BLOB    NOT NULL,
    wrapped_at        INTEGER NOT NULL
);
CREATE TABLE device_identity (
    device_id         BLOB    PRIMARY KEY,
    ed25519_pub       BLOB    NOT NULL,
    x25519_pub        BLOB    NOT NULL,
    ed25519_priv_env  BLOB    NOT NULL,
    x25519_priv_env   BLOB    NOT NULL,
    created_at        INTEGER NOT NULL,
    label             TEXT
);
CREATE TABLE peer_devices (
    device_id         BLOB    PRIMARY KEY,
    ed25519_pub       BLOB    NOT NULL,
    x25519_pub        BLOB    NOT NULL,
    verified_at       INTEGER NOT NULL,
    label             TEXT
);
CREATE TABLE vault_registry (
    vault_id          BLOB    PRIMARY KEY,
    name_env          BLOB    NOT NULL,
    wrapped_vault_key BLOB    NOT NULL,
    cipher_suite      INTEGER NOT NULL,
    created_at        INTEGER NOT NULL,
    deleted_at        INTEGER
);
CREATE TABLE settings (
    key               TEXT PRIMARY KEY,
    value             TEXT,
    value_env         BLOB
);
"#;

/// The DDL for the device-local audit log (`audit_log` table in the account
/// store), PRD §4.9. **Plaintext metadata only** — ids, kinds, timestamps; never
/// a secret value and never a vault/item name (see [`crate::audit`]). Integrity
/// comes from the per-device BLAKE3 hash chain (`prev_hash` links each record to
/// the previous one), not from confidentiality.
///
/// Created with `IF NOT EXISTS` so it is added idempotently both by
/// [`ACCOUNT_STORE_DDL`]'s companion [`ensure_audit_table`] on a fresh store and,
/// forward-only, on the first append against an account store created before this
/// build (a purely additive migration — no `format_version` bump, since a v1
/// reader that predates the table simply never queries it; vault-format.md §9).
///
/// `UNIQUE (device_id, seq)` mirrors the op log: per-device gapless sequencing.
pub const AUDIT_LOG_DDL: &str = r#"
CREATE TABLE IF NOT EXISTS audit_log (
    seq               INTEGER NOT NULL,
    device_id         BLOB    NOT NULL,
    prev_hash         BLOB    NOT NULL,
    timestamp         INTEGER NOT NULL,
    kind              INTEGER NOT NULL,
    item_id           BLOB,
    vault_id          BLOB,
    peer_device_id    BLOB,
    field             TEXT,
    format            TEXT,
    item_count        INTEGER NOT NULL DEFAULT 0,
    detail            TEXT,
    PRIMARY KEY (device_id, seq)
);
CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_log (timestamp);
"#;

/// Idempotently create the `audit_log` table + index if absent
/// ([`AUDIT_LOG_DDL`]). Safe to call on every unlock/append; a no-op once the
/// table exists. This is the forward-only migration that gives an account store
/// created before this build its audit table on first use (vault-format.md §9:
/// forward-only, idempotent, single transaction — `execute_batch` runs the DDL
/// as one implicit transaction).
///
/// # Errors
///
/// [`crate::Error::Sqlite`] if the DDL cannot be applied.
pub fn ensure_audit_table(conn: &Connection) -> Result<()> {
    conn.execute_batch(AUDIT_LOG_DDL)?;
    Ok(())
}

/// Idempotent, forward-only migration bringing a vault file's `attachments`
/// schema up to date (vault-format.md §9: additive, no `format_version` bump).
/// Two eras of vault predate today's schema: those created before attachments
/// existed at all (no `attachments` table), and those created after the table
/// but before the `created_at` column (added with attachment sync) — the latter
/// makes every attachment query fail with *"no such column: created_at"*. Safe to
/// call on every vault open; a no-op once the schema is current.
///
/// # Errors
///
/// [`crate::Error::Sqlite`] if the DDL/ALTER cannot be applied.
pub fn ensure_attachments_schema(conn: &Connection) -> Result<()> {
    // Vaults predating attachments entirely: create the table + its indexes.
    conn.execute_batch(
        r#"
CREATE TABLE IF NOT EXISTS attachments (
    attachment_id     BLOB    PRIMARY KEY,
    item_id           BLOB    NOT NULL,
    version           INTEGER NOT NULL,
    content_hash      BLOB    NOT NULL,
    size_plain        INTEGER NOT NULL,
    wrapped_key_env   BLOB    NOT NULL,
    filename_env      BLOB    NOT NULL,
    created_at        INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_attachments_item ON attachments (item_id);
CREATE INDEX IF NOT EXISTS idx_attachments_hash ON attachments (content_hash);
"#,
    )?;
    // Vaults that have the table but predate `created_at`: add the column.
    // SQLite has no `ADD COLUMN IF NOT EXISTS`, so gate on `PRAGMA table_info`.
    // `DEFAULT 0` backfills any existing rows to the epoch (sorts oldest),
    // matching the fresh-vault schema default in [`VAULT_DDL`].
    if !column_exists(conn, "attachments", "created_at")? {
        conn.execute_batch(
            "ALTER TABLE attachments ADD COLUMN created_at INTEGER NOT NULL DEFAULT 0",
        )?;
    }
    Ok(())
}

/// Whether `table` has a column named `column`, via `PRAGMA table_info`. `table`
/// is a trusted internal literal (never user input), so interpolating it into
/// the pragma — which cannot take a bound parameter for the table name — is safe.
fn column_exists(conn: &Connection, table: &str, column: &str) -> Result<bool> {
    let mut stmt = conn.prepare(&format!("PRAGMA table_info({table})"))?;
    let mut rows = stmt.query([])?;
    while let Some(row) = rows.next()? {
        // Column 1 of table_info is the column name.
        let name: String = row.get(1)?;
        if name == column {
            return Ok(true);
        }
    }
    Ok(false)
}

/// The DDL for a vault file (`<vault_id>.vault`), verbatim from
/// vault-format.md §3 (including indexes).
pub const VAULT_DDL: &str = r#"
CREATE TABLE meta (
    id                INTEGER PRIMARY KEY CHECK (id = 1),
    format_version    INTEGER NOT NULL,
    file_kind         TEXT    NOT NULL,
    vault_id          BLOB    NOT NULL,
    cipher_suite      INTEGER NOT NULL,
    created_at        INTEGER NOT NULL,
    index_generation  INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE wrapped_keys (
    item_id           BLOB    NOT NULL,
    version           INTEGER NOT NULL,
    envelope          BLOB    NOT NULL,
    PRIMARY KEY (item_id, version)
);
CREATE TABLE items (
    item_id           BLOB    PRIMARY KEY,
    current_version   INTEGER NOT NULL,
    created_at        INTEGER NOT NULL,
    updated_at        INTEGER NOT NULL
);
CREATE TABLE item_versions (
    item_id           BLOB    NOT NULL,
    version           INTEGER NOT NULL,
    payload_env       BLOB    NOT NULL,
    created_at        INTEGER NOT NULL,
    author_device_id  BLOB    NOT NULL,
    op_id             BLOB,
    PRIMARY KEY (item_id, version)
);
CREATE TABLE folders (
    folder_id         BLOB    PRIMARY KEY,
    name_env          BLOB    NOT NULL,
    created_at        INTEGER NOT NULL
);
CREATE TABLE tombstones (
    item_id           BLOB    PRIMARY KEY,
    deleted_at        INTEGER NOT NULL,
    purge_after       INTEGER NOT NULL,
    deleted_by_device BLOB    NOT NULL,
    op_id             BLOB
);
CREATE TABLE ops (
    op_id             BLOB    PRIMARY KEY,
    vault_id          BLOB    NOT NULL,
    lamport           INTEGER NOT NULL,
    device_id         BLOB    NOT NULL,
    op_kind           INTEGER NOT NULL,
    target_item_id    BLOB,
    target_version    INTEGER NOT NULL DEFAULT 0,
    payload_env       BLOB    NOT NULL,
    signature         BLOB    NOT NULL,
    seq               INTEGER NOT NULL,
    prev_hash         BLOB    NOT NULL,
    observed          BLOB    NOT NULL DEFAULT X'00000000',
    created_at        INTEGER NOT NULL,
    UNIQUE (device_id, seq)
);
CREATE TABLE index_segments (
    segment_id        INTEGER PRIMARY KEY,
    generation        INTEGER NOT NULL,
    payload_env       BLOB    NOT NULL
);
CREATE TABLE attachments (
    attachment_id     BLOB    PRIMARY KEY,
    item_id           BLOB    NOT NULL,
    version           INTEGER NOT NULL,
    content_hash      BLOB    NOT NULL,
    size_plain        INTEGER NOT NULL,
    wrapped_key_env   BLOB    NOT NULL,
    filename_env      BLOB    NOT NULL,
    created_at        INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX idx_versions_item ON item_versions (item_id, version);
CREATE INDEX idx_ops_lamport    ON ops (lamport, device_id);
CREATE INDEX idx_ops_device_seq ON ops (device_id, seq);
CREATE INDEX idx_attachments_item ON attachments (item_id);
CREATE INDEX idx_attachments_hash ON attachments (content_hash);
"#;

/// Read `meta.format_version` and reject a file newer than this build supports
/// (vault-format.md §9 downgrade resistance).
///
/// # Errors
///
/// - [`crate::Error::UnsupportedFormat`] if the file's `format_version` exceeds
///   [`FORMAT_VERSION`].
/// - [`crate::Error::Sqlite`] if the `meta` row cannot be read.
pub fn check_format_version(conn: &Connection) -> Result<()> {
    let found: i64 = conn.query_row("SELECT format_version FROM meta WHERE id = 1", [], |r| {
        r.get(0)
    })?;
    if found > FORMAT_VERSION {
        return Err(crate::Error::UnsupportedFormat {
            found,
            supported: FORMAT_VERSION,
        });
    }
    Ok(())
}

/// Current time in unix milliseconds (plaintext timestamp source).
///
/// Uses the system clock; timestamps are structural metadata (vault-format.md
/// §6), not secrets.
#[must_use]
pub fn now_millis() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    let dur = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    // Fits in i64 for any realistic date; saturating on the astronomically
    // unlikely overflow keeps this total.
    i64::try_from(dur.as_millis()).unwrap_or(i64::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A vault created after attachments but before the sync `created_at` column
    /// gets the column added, so the `ORDER BY created_at` query stops failing.
    #[test]
    fn migration_adds_created_at_to_pre_sync_attachments() {
        let conn = Connection::open_in_memory().unwrap();
        // The pre-sync attachments table: same columns minus `created_at`.
        conn.execute_batch(
            "CREATE TABLE attachments (
                attachment_id   BLOB PRIMARY KEY,
                item_id         BLOB NOT NULL,
                version         INTEGER NOT NULL,
                content_hash    BLOB NOT NULL,
                size_plain      INTEGER NOT NULL,
                wrapped_key_env BLOB NOT NULL,
                filename_env    BLOB NOT NULL
            );",
        )
        .unwrap();
        assert!(!column_exists(&conn, "attachments", "created_at").unwrap());

        ensure_attachments_schema(&conn).unwrap();
        assert!(column_exists(&conn, "attachments", "created_at").unwrap());

        // The exact query shape that was failing now resolves.
        conn.execute_batch(
            "SELECT attachment_id, version, size_plain, filename_env, created_at \
             FROM attachments ORDER BY created_at",
        )
        .unwrap();

        // Idempotent: a second run is a no-op (no duplicate-column error).
        ensure_attachments_schema(&conn).unwrap();
    }

    /// A vault predating attachments entirely gets the table created.
    #[test]
    fn migration_creates_attachments_table_when_absent() {
        let conn = Connection::open_in_memory().unwrap();
        ensure_attachments_schema(&conn).unwrap();
        assert!(column_exists(&conn, "attachments", "created_at").unwrap());
        // Idempotent on an already-current schema too.
        ensure_attachments_schema(&conn).unwrap();
    }
}
