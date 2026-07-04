//! Consistent, E2EE-preserving backups of a profile (PRD §4.11).
//!
//! A backup is a **full snapshot** of a profile's account store plus all its
//! live vault files into `<dest_root>/<UTC-timestamp>/`, using SQLite's Online
//! Backup API (`rusqlite::backup::Backup`) so a snapshot is consistent even
//! while the DB is live in WAL mode — never a raw file copy of a live database.
//!
//! ```text
//! <dest_root>/
//!   20260704T112233Z/            -- one snapshot dir per backup (UTC timestamp)
//!     manifest.json              -- plaintext, non-secret (see below)
//!     account.localpass          -- online-backup snapshot of the account store
//!     vaults/
//!       <vault_id>.vault         -- one snapshot per live vault
//! ```
//!
//! # The backup is the same E2EE format
//!
//! Every snapshotted file is byte-for-byte the same envelope-encrypted SQLite
//! format as the live profile (vault-format.md). The Secret Key is **not** in
//! the backup (it lives only in the OS keychain / Emergency Kit), so a backup is
//! safe on untrusted storage exactly like the live files: an attacker with the
//! backup still faces Argon2id + the 128-bit Secret Key (PRD §4.11 / T1).
//!
//! # The manifest (plaintext, non-secret)
//!
//! `manifest.json` records only structural, non-secret facts: the backup
//! timestamp, the on-disk `format_version`, and, per file, its relative path, a
//! BLAKE3-256 hash of its bytes (via [`lp_crypto::blake3_256`]), and — for vault
//! files — a decrypt-free item/version count read from plaintext structural
//! columns. None of this reveals titles, secrets, or key material.
//!
//! # Consistency & rotation
//!
//! [`create`] snapshots the account store first, then each **live** (non
//! soft-deleted) vault from the registry, writing the manifest last. Rotation
//! ([`prune_old`]) runs only **after** a successful create, and only deletes
//! *complete, manifested* backup directories beyond the newest `keep` — a failed
//! create never deletes anything.
//!
//! # Restore atomicity
//!
//! [`restore`] never destroys live state: it moves the current live files to
//! `<profile>/backups/pre-restore-<ts>/`, stages the backup copies into a temp
//! dir on the **same filesystem** as the profile, then renames each file into
//! place. On any failure it rolls the pre-restore copies back. A half-restored
//! profile is therefore never left behind.

use std::fs;
use std::path::{Path, PathBuf};

use lp_crypto::SecretKey;
use rusqlite::Connection;
use rusqlite::backup::Backup;
use serde::{Deserialize, Serialize};

use crate::account::{ACCOUNT_FILE, AccountStore, VAULTS_DIR};
use crate::db;
use crate::error::{Error, Result};
use crate::ids::{Id, ItemId, VaultId};
use crate::payload::ItemPayload;
use crate::vault::Vault;

/// The subdirectory (within a profile) holding rotating backups
/// (vault-format.md §1 `backups/`).
pub const BACKUPS_DIR: &str = "backups";

/// The manifest file name written into each backup directory.
pub const MANIFEST_FILE: &str = "manifest.json";

/// The default number of backups to keep after a successful create (PRD §4.11
/// "keep 30"). Overridable per-call and via a profile setting at the CLI layer.
pub const DEFAULT_KEEP: usize = 30;

/// One file recorded in a [`BackupManifest`].
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ManifestFile {
    /// Path relative to the backup directory (forward-slash separated), e.g.
    /// `account.localpass` or `vaults/<id>.vault`.
    pub path: String,
    /// Lowercase-hex BLAKE3-256 of the file's bytes.
    pub blake3: String,
    /// Byte length of the file.
    pub size: u64,
    /// For a vault file: number of live (non-tombstoned) items. `None` for the
    /// account store. Read from plaintext structural columns — no decryption.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub item_count: Option<u64>,
    /// For a vault file: total `item_versions` rows. `None` for the account
    /// store.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version_count: Option<u64>,
}

/// The plaintext, non-secret manifest written to every backup directory.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct BackupManifest {
    /// The backup timestamp: the UTC directory name (`YYYYMMDDThhmmssZ`).
    pub timestamp: String,
    /// The on-disk `format_version` the account store carried at backup time.
    pub format_version: i64,
    /// Every file in the backup, with its hash and (for vaults) item counts.
    pub files: Vec<ManifestFile>,
}

impl BackupManifest {
    /// Total live items across all vault files in this backup.
    #[must_use]
    pub fn total_items(&self) -> u64 {
        self.files.iter().filter_map(|f| f.item_count).sum()
    }

    /// Total versions across all vault files in this backup.
    #[must_use]
    pub fn total_versions(&self) -> u64 {
        self.files.iter().filter_map(|f| f.version_count).sum()
    }

    /// Read + parse a manifest from a backup directory.
    ///
    /// # Errors
    ///
    /// [`Error::Io`] if the file is missing/unreadable; [`Error::Serialization`]
    /// if it does not parse.
    pub fn read(backup_dir: &Path) -> Result<Self> {
        let raw = fs::read(backup_dir.join(MANIFEST_FILE))?;
        let manifest: Self = serde_json::from_slice(&raw)?;
        Ok(manifest)
    }
}

/// A listed backup: its directory and parsed manifest (PRD §4.11 `backup list`).
#[derive(Clone, Debug)]
pub struct BackupInfo {
    /// The backup directory (named for its UTC timestamp).
    pub dir: PathBuf,
    /// Total on-disk size of the backup directory in bytes.
    pub total_size: u64,
    /// The parsed manifest.
    pub manifest: BackupManifest,
}

/// Per-check outcome of [`verify`] (PRD §4.11 `backup verify`).
///
/// Checks 1 and 2 need no credentials; check 3 needs the master password + the
/// Secret Key and proves the backup is *actually recoverable with the current
/// credentials*.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct VerifyReport {
    /// Check 1: every file's bytes hash to the manifest's recorded BLAKE3.
    pub hashes_ok: bool,
    /// Check 2: every SQLite file opens and passes `PRAGMA integrity_check`.
    pub integrity_ok: bool,
    /// Check 3: the wrapped AccountKey unwraps, each VaultKey unwraps, and one
    /// newest item per vault decrypts — i.e. the backup is recoverable with the
    /// supplied credentials. `None` when check 3 was not requested (no
    /// credentials supplied).
    pub decrypt_ok: Option<bool>,
    /// Human-readable per-check notes (never a secret value), in check order.
    pub notes: Vec<String>,
}

impl VerifyReport {
    /// Whether every *performed* check passed. Check 3 counts only if it ran.
    #[must_use]
    pub fn all_ok(&self) -> bool {
        self.hashes_ok && self.integrity_ok && self.decrypt_ok.unwrap_or(true)
    }
}

/// The outcome of a full-profile [`restore`].
#[derive(Clone, Debug)]
pub struct RestoreReport {
    /// Where the previous live files were moved before the restore (so the user
    /// can recover the state that was replaced). Empty if the profile had no
    /// live files (fresh restore).
    pub pre_restore_dir: Option<PathBuf>,
    /// The number of files copied into place from the backup.
    pub files_restored: usize,
}

// --- Create ---------------------------------------------------------------

/// Create a consistent backup snapshot of the profile at `profile_dir`.
///
/// `dest_root` is where the timestamped backup directory is created; pass the
/// profile's own `backups/` dir for the default location, or an external
/// drive/NAS path via the CLI `--to`. `keep` bounds rotation: after a successful
/// create, backup directories beyond the newest `keep` in `dest_root` are pruned
/// (a failed create never deletes anything).
///
/// Returns the created backup's [`BackupInfo`].
///
/// # Errors
///
/// - [`Error::NotFound`] if `profile_dir` has no account store.
/// - [`Error::Io`] / [`Error::Sqlite`] on a filesystem or snapshot failure. On
///   any failure the partial backup directory is removed and nothing is pruned.
pub fn create(profile_dir: &Path, dest_root: &Path, keep: usize) -> Result<BackupInfo> {
    let account_src = profile_dir.join(ACCOUNT_FILE);
    if !account_src.exists() {
        return Err(Error::NotFound("account store"));
    }

    let timestamp = utc_timestamp(db::now_millis());
    let backup_dir = dest_root.join(&timestamp);
    if backup_dir.exists() {
        return Err(Error::Invalid(
            "a backup with this timestamp already exists",
        ));
    }
    fs::create_dir_all(backup_dir.join(VAULTS_DIR))?;

    // Everything below is wrapped so a failure removes the partial dir.
    let result = create_inner(profile_dir, &backup_dir, &timestamp);
    match result {
        Ok(info) => {
            // Rotation runs ONLY after a fully successful create.
            prune_old(dest_root, keep)?;
            Ok(info)
        }
        Err(e) => {
            // Best-effort cleanup of the partial backup; keep the original error.
            let _ = fs::remove_dir_all(&backup_dir);
            Err(e)
        }
    }
}

/// The create body (snapshot account store + vaults, write manifest).
fn create_inner(profile_dir: &Path, backup_dir: &Path, timestamp: &str) -> Result<BackupInfo> {
    let account_src = profile_dir.join(ACCOUNT_FILE);
    let format_version = read_format_version(&account_src)?;

    let mut files = Vec::new();

    // 1) Account store (online-backup snapshot).
    let account_dst = backup_dir.join(ACCOUNT_FILE);
    online_backup(&account_src, &account_dst)?;
    files.push(manifest_file(backup_dir, &account_dst, None)?);

    // 2) Each live (non soft-deleted) vault from the registry. We snapshot the
    //    file identified by the registry so soft-deleted vaults are excluded.
    for vault_id in live_vault_ids(&account_src)? {
        let name = format!("{}.vault", vault_id.to_hyphenated());
        let vault_src = profile_dir.join(VAULTS_DIR).join(&name);
        if !vault_src.exists() {
            // Registry references a vault file that is not on disk. Skip it
            // rather than fail the whole backup; note it in the account count.
            continue;
        }
        let vault_dst = backup_dir.join(VAULTS_DIR).join(&name);
        online_backup(&vault_src, &vault_dst)?;
        let counts = vault_counts(&vault_dst)?;
        files.push(manifest_file(backup_dir, &vault_dst, Some(counts))?);
    }

    // 3) Manifest last (its presence marks the backup as complete).
    let manifest = BackupManifest {
        timestamp: timestamp.to_string(),
        format_version,
        files,
    };
    let manifest_bytes = serde_json::to_vec_pretty(&manifest)?;
    fs::write(backup_dir.join(MANIFEST_FILE), &manifest_bytes)?;

    let total_size = dir_size(backup_dir)?;
    Ok(BackupInfo {
        dir: backup_dir.to_path_buf(),
        total_size,
        manifest,
    })
}

// --- List -----------------------------------------------------------------

/// List all complete backups under `dest_root`, newest first (PRD §4.11
/// `backup list`).
///
/// A directory counts as a backup only if it contains a readable
/// [`MANIFEST_FILE`]; partial/aborted directories are ignored.
///
/// # Errors
///
/// [`Error::Io`] if `dest_root` cannot be read (a missing dir yields an empty
/// list, not an error).
pub fn list(dest_root: &Path) -> Result<Vec<BackupInfo>> {
    let mut out = Vec::new();
    if !dest_root.exists() {
        return Ok(out);
    }
    for entry in fs::read_dir(dest_root)? {
        let entry = entry?;
        if !entry.file_type()?.is_dir() {
            continue;
        }
        let dir = entry.path();
        // A backup is defined by a readable manifest; skip anything else
        // (including pre-restore-* dirs, which carry no manifest).
        let Ok(manifest) = BackupManifest::read(&dir) else {
            continue;
        };
        let total_size = dir_size(&dir).unwrap_or(0);
        out.push(BackupInfo {
            dir,
            total_size,
            manifest,
        });
    }
    // Newest first: the timestamp directory names sort lexicographically in
    // chronological order (fixed-width UTC `YYYYMMDDThhmmssZ`).
    out.sort_by(|a, b| b.manifest.timestamp.cmp(&a.manifest.timestamp));
    Ok(out)
}

// --- Verify ---------------------------------------------------------------

/// Verify a backup directory (PRD §4.11 `backup verify`).
///
/// Runs, in order:
///
/// 1. **Hashes** — every file's bytes hash to the manifest's recorded BLAKE3.
/// 2. **Integrity** — every SQLite file opens and passes `PRAGMA
///    integrity_check`.
/// 3. **Recoverable** (only if `creds` is `Some`) — the wrapped AccountKey
///    unwraps with the supplied master password + Secret Key, each vault's
///    VaultKey unwraps, and one newest item per vault decrypts.
///
/// Checks 1 and 2 run regardless of check 3's outcome, so a wrong password still
/// reports checks 1–2 as passing.
///
/// # Errors
///
/// [`Error::Io`] / [`Error::Serialization`] only for a structurally unreadable
/// backup (missing/corrupt manifest). A failing *check* is reported in the
/// returned [`VerifyReport`], not as an `Err`.
pub fn verify(backup_dir: &Path, creds: Option<(&str, &SecretKey)>) -> Result<VerifyReport> {
    let manifest = BackupManifest::read(backup_dir)?;
    let mut report = VerifyReport::default();

    // Check 1: hashes.
    let mut hashes_ok = true;
    for f in &manifest.files {
        let path = backup_dir.join(rel_to_native(&f.path));
        match fs::read(&path) {
            Ok(bytes) => {
                let got = hex_lower(&lp_crypto::blake3_256(&bytes));
                if got != f.blake3 {
                    hashes_ok = false;
                    report.notes.push(format!("hash mismatch for {}", f.path));
                }
            }
            Err(_) => {
                hashes_ok = false;
                report.notes.push(format!("missing file {}", f.path));
            }
        }
    }
    report.hashes_ok = hashes_ok;
    report.notes.push(if hashes_ok {
        "hashes: OK".to_string()
    } else {
        "hashes: FAILED".to_string()
    });

    // Check 2: SQLite integrity of each file.
    let mut integrity_ok = true;
    for f in &manifest.files {
        let path = backup_dir.join(rel_to_native(&f.path));
        if !sqlite_integrity_ok(&path) {
            integrity_ok = false;
            report
                .notes
                .push(format!("integrity_check FAILED for {}", f.path));
        }
    }
    report.integrity_ok = integrity_ok;
    report.notes.push(if integrity_ok {
        "integrity: OK".to_string()
    } else {
        "integrity: FAILED".to_string()
    });

    // Check 3: recoverable with the supplied credentials.
    if let Some((password, secret_key)) = creds {
        let (ok, note) = verify_recoverable(backup_dir, password, secret_key);
        report.decrypt_ok = Some(ok);
        report.notes.push(note);
    }

    Ok(report)
}

/// Check 3 body: unlock the backup like a normal profile and decrypt one newest
/// item per vault. Returns `(passed, human note)`.
fn verify_recoverable(backup_dir: &Path, password: &str, secret_key: &SecretKey) -> (bool, String) {
    // A backup directory has the exact profile layout (account.localpass +
    // vaults/), so the normal unlock flow applies directly.
    let session = match AccountStore::unlock(backup_dir, password, secret_key) {
        Ok(s) => s,
        Err(Error::DecryptionFailed) => {
            return (
                false,
                "recoverable: FAILED (wrong password or Secret Key)".to_string(),
            );
        }
        Err(e) => return (false, format!("recoverable: FAILED ({e})")),
    };

    let vaults = match session.list_vaults() {
        Ok(v) => v,
        Err(e) => return (false, format!("recoverable: FAILED (vault registry: {e})")),
    };

    for (vault_id, _name) in &vaults {
        let vault = match session.open_vault(*vault_id) {
            Ok(v) => v,
            Err(e) => {
                return (
                    false,
                    format!("recoverable: FAILED (vault key unwrap: {e})"),
                );
            }
        };
        // Decrypt the newest item, if any (proves VaultKey → ItemKey → payload).
        match newest_item(&vault) {
            Ok(None) => {} // empty vault: VaultKey already unwrapped above.
            Ok(Some(_)) => {}
            Err(e) => {
                return (false, format!("recoverable: FAILED (item decrypt: {e})"));
            }
        }
    }

    (
        true,
        "recoverable: OK (credentials unwrap the backup and an item decrypts)".to_string(),
    )
}

/// Decrypt the newest live item in a vault (highest `created_at`), if any.
fn newest_item(vault: &Vault<'_>) -> Result<Option<ItemPayload>> {
    let items = vault.list_items()?;
    Ok(items
        .into_iter()
        .max_by_key(|i| i.created_at)
        .map(|i| i.payload))
}

// --- Restore (full profile) ----------------------------------------------

/// Restore a full profile from a backup directory (PRD §4.11 restore).
///
/// **Never destroys live state.** The current live files (`account.localpass`
/// and `vaults/`) are moved to `<profile>/backups/pre-restore-<ts>/`; then each
/// backup file is staged into a temp dir on the same filesystem as the profile
/// and renamed into place. On any failure the pre-restore copies are rolled
/// back, so a half-restored profile is never left behind.
///
/// The caller (CLI) is responsible for refusing when a daemon is running for
/// this profile — this function only touches files.
///
/// # Errors
///
/// - [`Error::NotFound`] if the backup directory has no manifest.
/// - [`Error::Io`] on a filesystem failure (after which the profile is rolled
///   back to its pre-restore state).
pub fn restore(profile_dir: &Path, backup_dir: &Path) -> Result<RestoreReport> {
    let manifest =
        BackupManifest::read(backup_dir).map_err(|_| Error::NotFound("backup manifest"))?;

    fs::create_dir_all(profile_dir)?;
    let backups_dir = profile_dir.join(BACKUPS_DIR);
    fs::create_dir_all(&backups_dir)?;

    // 1) Move current live files aside into pre-restore-<ts>/ (never delete).
    let pre_ts = utc_timestamp(db::now_millis());
    let pre_restore = backups_dir.join(format!("pre-restore-{pre_ts}"));
    let moved = move_live_aside(profile_dir, &pre_restore)?;
    let pre_restore_dir = if moved {
        Some(pre_restore.clone())
    } else {
        None
    };

    // 2) Stage + install each backup file. On any error, roll back.
    let install = install_backup_files(profile_dir, backup_dir, &manifest);
    match install {
        Ok(files_restored) => Ok(RestoreReport {
            pre_restore_dir,
            files_restored,
        }),
        Err(e) => {
            // Roll back: remove any partially-installed files, then move the
            // pre-restore copies back into place.
            let _ = remove_live_files(profile_dir);
            if moved {
                let _ = move_aside_back(&pre_restore, profile_dir);
            }
            Err(e)
        }
    }
}

/// Stage each backup file into a same-filesystem temp dir, then rename into
/// place. Returns the number of files installed.
fn install_backup_files(
    profile_dir: &Path,
    backup_dir: &Path,
    manifest: &BackupManifest,
) -> Result<usize> {
    // A temp staging dir inside the profile guarantees the same filesystem, so
    // the final rename is atomic per file (no cross-device copy fallback).
    let staging = profile_dir.join(".restore-staging");
    let _ = fs::remove_dir_all(&staging);
    fs::create_dir_all(staging.join(VAULTS_DIR))?;

    fs::create_dir_all(profile_dir.join(VAULTS_DIR))?;

    let mut installed = 0usize;
    for f in &manifest.files {
        let rel = rel_to_native(&f.path);
        let src = backup_dir.join(&rel);
        let staged = staging.join(&rel);
        if let Some(parent) = staged.parent() {
            fs::create_dir_all(parent)?;
        }
        // Copy backup → staging (same fs), then atomic rename into place.
        fs::copy(&src, &staged)?;
        let dst = profile_dir.join(&rel);
        if let Some(parent) = dst.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::rename(&staged, &dst)?;
        db::restrict_permissions(&dst)?;
        installed += 1;
    }
    let _ = fs::remove_dir_all(&staging);
    Ok(installed)
}

/// Move the live `account.localpass` + `vaults/` (and their WAL/SHM sidecars)
/// into `dest`. Returns whether anything was moved.
fn move_live_aside(profile_dir: &Path, dest: &Path) -> Result<bool> {
    let account = profile_dir.join(ACCOUNT_FILE);
    let vaults = profile_dir.join(VAULTS_DIR);
    if !account.exists() && !vaults.exists() {
        return Ok(false);
    }
    fs::create_dir_all(dest)?;
    // Account store + its sidecars.
    for suffix in ["", "-wal", "-shm"] {
        let name = format!("{ACCOUNT_FILE}{suffix}");
        let from = profile_dir.join(&name);
        if from.exists() {
            fs::rename(&from, dest.join(&name))?;
        }
    }
    // The whole vaults/ directory.
    if vaults.exists() {
        fs::rename(&vaults, dest.join(VAULTS_DIR))?;
    }
    Ok(true)
}

/// Undo [`move_live_aside`]: move files from `src` back into the profile. Used
/// on rollback.
fn move_aside_back(src: &Path, profile_dir: &Path) -> Result<()> {
    for suffix in ["", "-wal", "-shm"] {
        let name = format!("{ACCOUNT_FILE}{suffix}");
        let from = src.join(&name);
        if from.exists() {
            let _ = fs::remove_file(profile_dir.join(&name));
            fs::rename(&from, profile_dir.join(&name))?;
        }
    }
    let vaults_src = src.join(VAULTS_DIR);
    if vaults_src.exists() {
        let _ = fs::remove_dir_all(profile_dir.join(VAULTS_DIR));
        fs::rename(&vaults_src, profile_dir.join(VAULTS_DIR))?;
    }
    let _ = fs::remove_dir_all(src);
    Ok(())
}

/// Remove the live account store + vaults dir (used before a rollback re-move).
fn remove_live_files(profile_dir: &Path) -> Result<()> {
    for suffix in ["", "-wal", "-shm"] {
        let _ = fs::remove_file(profile_dir.join(format!("{ACCOUNT_FILE}{suffix}")));
    }
    let _ = fs::remove_dir_all(profile_dir.join(VAULTS_DIR));
    Ok(())
}

// --- Restore (single item) ------------------------------------------------

/// Restore a single item from a backup into a live vault, as a **new version**
/// (PRD §4.11 single-item restore).
///
/// The item is decrypted from the backup vault's own keys (opened read-only
/// under the same credentials) and **re-created** in the live vault via the
/// normal create path — so it arrives as a fresh item/op, not a byte-copy of the
/// backup rows. The live vault's op chain stays valid
/// ([`Vault::verify_local_chain`](crate::Vault::verify_local_chain) still
/// passes) because a normal create appends one well-formed op.
///
/// `target` matches an item by title or by hyphenated id in the backup vault.
/// Returns the new [`ItemId`] created in the live vault.
///
/// # Errors
///
/// - [`Error::NotFound`] if the backup, its vault, or the target item is absent.
/// - [`Error::DecryptionFailed`] on wrong credentials.
/// - [`Error::Invalid`] if `target` is ambiguous (matches more than one title).
pub fn restore_single_item(
    backup_dir: &Path,
    password: &str,
    secret_key: &SecretKey,
    backup_vault_id: VaultId,
    target: &str,
    live_vault: &Vault<'_>,
) -> Result<ItemId> {
    // Open the backup as a read-only profile and locate the item.
    let backup_session = AccountStore::unlock(backup_dir, password, secret_key)?;
    let backup_vault = backup_session.open_vault(backup_vault_id)?;

    let payload = find_item_payload(&backup_vault, target)?;

    // Re-create in the live vault via the normal create path → new item + op.
    let new_id = live_vault.create_item(&payload)?;
    Ok(new_id)
}

/// Find an item's decrypted payload by title or hyphenated id within `vault`.
fn find_item_payload(vault: &Vault<'_>, target: &str) -> Result<ItemPayload> {
    // Try an id match first (a hyphenated UUID).
    if let Some(id) = parse_hyphenated_id(target) {
        match vault.get_item(id) {
            Ok(item) => return Ok(item.payload),
            Err(Error::NotFound(_)) => {}
            Err(e) => return Err(e),
        }
    }
    let items = vault.list_items()?;
    let matches: Vec<_> = items
        .into_iter()
        .filter(|i| i.payload.title == target)
        .collect();
    match matches.len() {
        0 => Err(Error::NotFound("item in backup")),
        1 => Ok(matches.into_iter().next().unwrap().payload),
        _ => Err(Error::Invalid(
            "item title is ambiguous in the backup; use the item id",
        )),
    }
}

/// Parse a hyphenated UUID string into an [`Id`], returning `None` for anything
/// that is not a UUID. We avoid a `uuid` string-parse dependency in this crate
/// by parsing the canonical hyphenated form by hand.
fn parse_hyphenated_id(s: &str) -> Option<Id> {
    let hex: String = s.chars().filter(|c| *c != '-').collect();
    if hex.len() != 32 || !hex.chars().all(|c| c.is_ascii_hexdigit()) {
        return None;
    }
    let mut bytes = [0u8; 16];
    for (i, b) in bytes.iter_mut().enumerate() {
        *b = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).ok()?;
    }
    Some(Id::from_bytes(bytes))
}

// --- Rotation -------------------------------------------------------------

/// Delete complete backups beyond the newest `keep` under `dest_root`.
///
/// Only *manifested* backup directories are considered (partial dirs and
/// `pre-restore-*` dirs are never counted or deleted). `keep == 0` is treated as
/// "keep everything" here defensively — the CLI enforces a sensible floor — so
/// prune never wipes all backups by accident.
///
/// # Errors
///
/// [`Error::Io`] on a read/delete failure.
pub fn prune_old(dest_root: &Path, keep: usize) -> Result<()> {
    if keep == 0 {
        return Ok(());
    }
    let backups = list(dest_root)?; // newest first
    for old in backups.into_iter().skip(keep) {
        fs::remove_dir_all(&old.dir)?;
    }
    Ok(())
}

// --- Internal helpers -----------------------------------------------------

/// Take an online-backup snapshot of the SQLite DB at `src` into a fresh file at
/// `dst`, driving the copy to completion in one call. Both connections use the
/// durability PRAGMAs; the source is opened read-only-ish (we only read from it).
fn online_backup(src: &Path, dst: &Path) -> Result<()> {
    // A fresh destination: remove any stale target first so the backup writes a
    // clean file.
    let _ = fs::remove_file(dst);
    let src_conn = db::open_connection(src)?;
    let mut dst_conn = Connection::open(dst)?;
    {
        let backup = Backup::new(&src_conn, &mut dst_conn)?;
        // `step(-1)` copies ALL remaining pages in one call, returning `Done`.
        // (rusqlite's `run_to_completion` asserts a *positive* page count, so we
        // drive the single-shot copy directly.) This produces a
        // transactionally-consistent snapshot of the source even while it is
        // live (WAL) — a guarantee a raw file copy cannot make.
        use rusqlite::backup::StepResult;
        match backup.step(-1)? {
            StepResult::Done => {}
            // A single full step should always finish; anything else means the
            // source was contended mid-copy. Surface it rather than ship a
            // partial snapshot. (`StepResult` is `#[non_exhaustive]`.)
            _ => {
                return Err(Error::Invalid("online backup did not complete in one step"));
            }
        }
    }
    db::restrict_permissions(dst)?;
    Ok(())
}

/// Build a [`ManifestFile`] for a file inside the backup directory.
fn manifest_file(
    backup_dir: &Path,
    file: &Path,
    counts: Option<(u64, u64)>,
) -> Result<ManifestFile> {
    let bytes = fs::read(file)?;
    let blake3 = hex_lower(&lp_crypto::blake3_256(&bytes));
    let rel = file
        .strip_prefix(backup_dir)
        .map_err(|_| Error::Invalid("backup file escaped the backup directory"))?;
    let path = rel.to_string_lossy().replace('\\', "/"); // forward-slash relative paths in the manifest
    let (item_count, version_count) = match counts {
        Some((i, v)) => (Some(i), Some(v)),
        None => (None, None),
    };
    Ok(ManifestFile {
        path,
        blake3,
        size: bytes.len() as u64,
        item_count,
        version_count,
    })
}

/// Read `(live_item_count, total_version_count)` from a vault file's plaintext
/// structural columns (no decryption).
fn vault_counts(vault_file: &Path) -> Result<(u64, u64)> {
    let conn = db::open_connection(vault_file)?;
    let items: i64 = conn.query_row(
        "SELECT COUNT(*) FROM items i
         WHERE NOT EXISTS (SELECT 1 FROM tombstones t WHERE t.item_id = i.item_id)",
        [],
        |r| r.get(0),
    )?;
    let versions: i64 = conn.query_row("SELECT COUNT(*) FROM item_versions", [], |r| r.get(0))?;
    Ok((
        u64::try_from(items).unwrap_or(0),
        u64::try_from(versions).unwrap_or(0),
    ))
}

/// Read `meta.format_version` from an account store / vault file.
fn read_format_version(file: &Path) -> Result<i64> {
    let conn = db::open_connection(file)?;
    let v: i64 = conn.query_row("SELECT format_version FROM meta WHERE id = 1", [], |r| {
        r.get(0)
    })?;
    Ok(v)
}

/// The live (non soft-deleted) vault ids from an account store's registry.
fn live_vault_ids(account_file: &Path) -> Result<Vec<VaultId>> {
    let conn = db::open_connection(account_file)?;
    let mut stmt = conn.prepare("SELECT vault_id FROM vault_registry WHERE deleted_at IS NULL")?;
    let rows = stmt.query_map([], |r| r.get::<_, Vec<u8>>(0))?;
    let mut out = Vec::new();
    for row in rows {
        out.push(Id::from_slice(&row?)?);
    }
    Ok(out)
}

/// Open a SQLite file and run `PRAGMA integrity_check`, returning whether it
/// reported `ok`.
fn sqlite_integrity_ok(file: &Path) -> bool {
    let Ok(conn) = Connection::open(file) else {
        return false;
    };
    let result: std::result::Result<String, _> =
        conn.query_row("PRAGMA integrity_check", [], |r| r.get(0));
    matches!(result, Ok(s) if s.eq_ignore_ascii_case("ok"))
}

/// Best-effort recursive size of a directory in bytes.
fn dir_size(dir: &Path) -> Result<u64> {
    let mut total = 0u64;
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        let meta = entry.metadata()?;
        if meta.is_dir() {
            total += dir_size(&entry.path())?;
        } else {
            total += meta.len();
        }
    }
    Ok(total)
}

/// Format a unix-millis instant as a fixed-width UTC directory timestamp
/// `YYYYMMDDThhmmssZ`. Sortable lexicographically in chronological order.
fn utc_timestamp(millis: i64) -> String {
    // Convert to civil date/time without a chrono dependency (this crate keeps a
    // minimal dep set). Days-from-epoch → y/m/d via Howard Hinnant's algorithm.
    let secs = millis.div_euclid(1000);
    let days = secs.div_euclid(86_400);
    let tod = secs.rem_euclid(86_400);
    let (hh, mm, ss) = (tod / 3600, (tod % 3600) / 60, tod % 60);
    let (y, mo, d) = civil_from_days(days);
    format!("{y:04}{mo:02}{d:02}T{hh:02}{mm:02}{ss:02}Z")
}

/// Convert days-since-1970-01-01 to a `(year, month, day)` civil date
/// (Hinnant's `civil_from_days`), valid for the full range we need.
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    let y = if m <= 2 { y + 1 } else { y };
    (y, m, d)
}

/// Lowercase hex of a byte slice.
fn hex_lower(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push(char::from_digit((b >> 4) as u32, 16).unwrap());
        s.push(char::from_digit((b & 0x0f) as u32, 16).unwrap());
    }
    s
}

/// Convert a manifest forward-slash relative path to a native `PathBuf`.
fn rel_to_native(rel: &str) -> PathBuf {
    rel.split('/').collect()
}
