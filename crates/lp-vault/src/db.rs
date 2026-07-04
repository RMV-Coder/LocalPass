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
    filename_env      BLOB    NOT NULL
);
CREATE INDEX idx_versions_item ON item_versions (item_id, version);
CREATE INDEX idx_ops_lamport    ON ops (lamport, device_id);
CREATE INDEX idx_ops_device_seq ON ops (device_id, seq);
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
