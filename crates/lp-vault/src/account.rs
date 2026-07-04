//! The account store (`account.localpass`) and the unlocked [`Session`].
//!
//! The account store holds KDF params, the wrapped AccountKey, this device's
//! identity, and the vault registry (vault-format.md §2). [`AccountStore`] is
//! the create/unlock entry point; a successful unlock yields a [`Session`]
//! holding the live [`AccountKey`] and device identity, from which vaults are
//! created and opened.
//!
//! # Device identity persistence
//!
//! vault-format.md §2 stores the device Ed25519 signing seed and X25519 scalar
//! **wrapped under the AccountKey** so the identity is reconstructed at every
//! unlock. The private halves are exported via `lp-crypto`'s
//! `secret_seed()`/`secret_bytes()` (zeroizing buffers), sealed under the
//! AccountKey with the spec's exact AAD, and reconstructed at unlock with
//! `from_seed`/`from_secret_bytes`. After reconstruction the public halves are
//! checked against the stored plaintext publics — a mismatch fails the unlock
//! rather than silently authoring ops under a divergent identity. This keeps
//! the device's op-signing key stable across lock/unlock, which the sync hash
//! chain requires (sync-protocol.md §5: peers pin one public key per device).

use lp_crypto::{
    AccountKey, KdfParams, SealingKeyPair, SecretKey, SigningKeyPair, VaultKey,
    derive_master_unlock_key, unwrap_key, wrap_key,
};
use rusqlite::{Connection, OptionalExtension, params};
use std::path::{Path, PathBuf};

use crate::aad;
use crate::audit::{self, AuditKind, AuditRecord};
use crate::db;
use crate::error::{Error, Result};
use crate::ids::{DeviceId, Id, VaultId};
use crate::vault::Vault;

/// The account-store file name within a profile directory.
pub const ACCOUNT_FILE: &str = "account.localpass";
/// The subdirectory holding per-vault files.
pub const VAULTS_DIR: &str = "vaults";

/// KDF code for Argon2id (vault-format.md §2 `kdf_params.kdf`).
const KDF_ARGON2ID: i64 = 1;

/// The account store: create or unlock the on-disk account.
///
/// This is a thin, stateless entry point. All *unlocked* state lives in the
/// [`Session`] returned by [`create`](Self::create) / [`unlock`](Self::unlock).
pub struct AccountStore;

impl AccountStore {
    /// Create a brand-new account under `dir`.
    ///
    /// Generates a fresh [`SecretKey`] (returned to the caller for the Emergency
    /// Kit — vault-format.md §5.2 / PRD §4.11), derives the MUK from `password`
    /// at [`KdfParams::recommended`] cost with a fresh salt, generates and wraps
    /// a random [`AccountKey`] under the MUK, and generates this device's
    /// Ed25519 + X25519 identity (private halves wrapped under the AccountKey).
    ///
    /// The Secret Key is **only** returned here; it is never written to the
    /// store (only its 16-byte id is, `kdf_params.secret_key_id`).
    ///
    /// # Errors
    ///
    /// - [`Error::Invalid`] if an account store already exists at `dir`.
    /// - [`Error::Io`] / [`Error::Sqlite`] on filesystem or DB failure.
    /// - [`Error::Crypto`] on a key-wrap failure.
    pub fn create(dir: &Path, password: &str) -> Result<(Session, SecretKey)> {
        let path = dir.join(ACCOUNT_FILE);
        if path.exists() {
            return Err(Error::Invalid("account store already exists"));
        }
        std::fs::create_dir_all(dir)?;
        std::fs::create_dir_all(dir.join(VAULTS_DIR))?;

        let secret_key = SecretKey::generate();
        let params = KdfParams::recommended();
        let muk = derive_master_unlock_key(password.as_bytes(), &secret_key, &params)
            .map_err(Error::from_crypto)?;

        let account_key = AccountKey::generate();
        let wrapped_ak = wrap_key(
            muk.inner(),
            account_key.inner(),
            aad_str(&aad::account_key()),
        )
        .map_err(Error::from_crypto)?;

        let device = DeviceIdentity::generate();
        let now = db::now_millis();
        // A 16-byte id that identifies (never stores) the Secret Key.
        let secret_key_id = Id::new();

        let mut conn = db::open_connection(&path)?;
        db::restrict_permissions(&path)?;

        let tx = conn.transaction()?;
        tx.execute_batch(db::ACCOUNT_STORE_DDL)?;
        // The device-local audit log (PRD §4.9) lives in the account store; create
        // it up front so a fresh store never needs the forward-only migration.
        tx.execute_batch(db::AUDIT_LOG_DDL)?;
        tx.execute(
            "INSERT INTO meta (id, format_version, file_kind, cipher_suite, created_at, schema_migrated_at)
             VALUES (1, ?1, ?2, ?3, ?4, ?4)",
            params![db::FORMAT_VERSION, db::FILE_KIND_ACCOUNT, db::CIPHER_SUITE_XCHACHA, now],
        )?;
        tx.execute(
            "INSERT INTO kdf_params (id, kdf, argon2_m_kib, argon2_t, argon2_p, salt, secret_key_id)
             VALUES (1, ?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                KDF_ARGON2ID,
                i64::from(params.m_cost_kib()),
                i64::from(params.t_cost()),
                i64::from(params.p_cost()),
                params.salt().as_slice(),
                secret_key_id.to_vec(),
            ],
        )?;
        tx.execute(
            "INSERT INTO wrapped_account_key (id, envelope, wrapped_at) VALUES (1, ?1, ?2)",
            params![wrapped_ak.to_bytes(), now],
        )?;
        device.insert(&tx, &account_key, now)?;
        tx.commit()?;

        let session = Session {
            dir: dir.to_path_buf(),
            account_key,
            device,
        };
        Ok((session, secret_key))
    }

    /// Read the account store's plaintext creation timestamp (`meta.created_at`,
    /// unix millis) without unlocking. Used by the Emergency Kit to show the
    /// account creation date (PRD §4.11).
    ///
    /// # Errors
    ///
    /// - [`Error::NotFound`] if no account store exists at `dir`.
    /// - [`Error::Sqlite`] on a read failure.
    pub fn created_at(dir: &Path) -> Result<i64> {
        let path = dir.join(ACCOUNT_FILE);
        if !path.exists() {
            return Err(Error::NotFound("account store"));
        }
        let conn = db::open_connection(&path)?;
        let created: i64 =
            conn.query_row("SELECT created_at FROM meta WHERE id = 1", [], |r| r.get(0))?;
        Ok(created)
    }

    /// Unlock an existing account under `dir` with `password` and `secret_key`.
    ///
    /// Re-derives the MUK from the stored KDF params, unwraps the AccountKey
    /// (**a wrong password or Secret Key fails here** with
    /// [`Error::DecryptionFailed`] — vault-format.md §5.2 step 4, no partial
    /// state), and loads this device's public identity.
    ///
    /// # Audit (PRD §4.9)
    ///
    /// A successful unlock records an [`AuditKind::UnlockSuccess`]; a wrong
    /// password/Secret Key records an [`AuditKind::UnlockFailure`] **before**
    /// returning the error, so a brute-force attempt leaves a persistent,
    /// hash-chained trail even though no session was produced. Recording happens
    /// here (not in the CLI/daemon) so *every* unlock path is covered exactly
    /// once, with no double-logging. An audit-append failure never masks the
    /// unlock outcome (it is logged-and-ignored — the log is best-effort relative
    /// to the security-critical unlock result).
    ///
    /// # Errors
    ///
    /// - [`Error::NotFound`] if no account store exists at `dir`.
    /// - [`Error::DecryptionFailed`] on a wrong password or Secret Key.
    /// - [`Error::UnsupportedFormat`] if the file is newer than this build.
    /// - [`Error::Sqlite`] on a DB failure.
    pub fn unlock(dir: &Path, password: &str, secret_key: &SecretKey) -> Result<Session> {
        Self::unlock_inner(dir, password, secret_key, /* audit = */ true)
    }

    /// Unlock **without** touching the audit log (no `UnlockSuccess`/`Failure`
    /// record). Used to open a store that must stay **byte-for-byte read-only** —
    /// notably a **backup** being verified or restored, whose bytes are pinned by
    /// its manifest hash (a stray append would corrupt the hash check). Never use
    /// this for a real user unlock of the live profile; use [`unlock`](Self::unlock).
    ///
    /// # Errors
    ///
    /// Same as [`unlock`](Self::unlock).
    pub fn unlock_quiet(dir: &Path, password: &str, secret_key: &SecretKey) -> Result<Session> {
        Self::unlock_inner(dir, password, secret_key, /* audit = */ false)
    }

    /// The shared unlock body. When `audit` is true, a successful unlock appends
    /// an [`AuditKind::UnlockSuccess`] and a wrong-password/Secret-Key failure
    /// appends an [`AuditKind::UnlockFailure`] (PRD §4.9); when false, neither is
    /// written and the store is opened strictly read-only.
    fn unlock_inner(
        dir: &Path,
        password: &str,
        secret_key: &SecretKey,
        audit: bool,
    ) -> Result<Session> {
        let path = dir.join(ACCOUNT_FILE);
        if !path.exists() {
            return Err(Error::NotFound("account store"));
        }
        let conn = db::open_connection(&path)?;
        db::check_format_version(&conn)?;

        let (params, _skid) = read_kdf_params(&conn)?;
        let muk = derive_master_unlock_key(password.as_bytes(), secret_key, &params)
            .map_err(Error::from_crypto)?;

        let wrapped_ak_bytes: Vec<u8> = conn.query_row(
            "SELECT envelope FROM wrapped_account_key WHERE id = 1",
            [],
            |r| r.get(0),
        )?;
        let envelope =
            lp_crypto::Envelope::from_bytes(&wrapped_ak_bytes).map_err(Error::from_crypto)?;
        // MUK is verified here: a wrong password/Secret Key ⇒ DecryptionFailed.
        let account_key_inner =
            match unwrap_key(muk.inner(), &envelope, aad_str(&aad::account_key())) {
                Ok(inner) => inner,
                Err(e) => {
                    // Record the failed unlock (PRD §4.9) against this device before
                    // surfacing the auth error. We know the device id from the stored
                    // plaintext identity even without the AccountKey. Skipped for a
                    // read-only (backup) unlock, which must not mutate the file.
                    let mapped = Error::from_crypto(e);
                    if audit && matches!(mapped, Error::DecryptionFailed) {
                        Self::record_unlock_failure(dir).ok();
                    }
                    return Err(mapped);
                }
            };
        let account_key = AccountKey::from_inner(account_key_inner);

        let device = DeviceIdentity::load(&conn, &account_key)?;

        let session = Session {
            dir: dir.to_path_buf(),
            account_key,
            device,
        };
        // A successful unlock is an audited event. Best-effort: never fail the
        // unlock over an audit-append hiccup. Skipped on the read-only path.
        if audit {
            session.record_audit(AuditKind::UnlockSuccess, None).ok();
        }
        Ok(session)
    }

    /// Record an [`AuditKind::UnlockFailure`] against the device identity stored
    /// in the account store at `dir`, opening the store directly.
    ///
    /// This is the **no-session** failure path: on a wrong password/Secret Key
    /// there is no [`Session`], so the append cannot go through one. The device
    /// id is read from the plaintext `device_identity` row (a public, non-secret
    /// column), the audit table is ensured, and one `UnlockFailure` record is
    /// appended to this device's hash chain.
    ///
    /// Called automatically by [`unlock`](Self::unlock) on the auth-failure path;
    /// exposed publicly so a caller (or a test) can record a failure explicitly.
    ///
    /// # Errors
    ///
    /// - [`Error::NotFound`] if no account store exists at `dir`.
    /// - [`Error::Sqlite`] on a DB failure.
    pub fn record_unlock_failure(dir: &Path) -> Result<()> {
        let path = dir.join(ACCOUNT_FILE);
        if !path.exists() {
            return Err(Error::NotFound("account store"));
        }
        let mut conn = db::open_connection(&path)?;
        db::ensure_audit_table(&conn)?;
        let device_id = read_device_id(&conn)?;
        let tx = conn.transaction()?;
        append_audit_record(&tx, &device_id, AuditKind::UnlockFailure, None)?;
        tx.commit()?;
        Ok(())
    }
}

/// Read this device's id from the plaintext `device_identity` row (non-secret).
/// Used by the no-session unlock-failure audit path.
fn read_device_id(conn: &Connection) -> Result<DeviceId> {
    let bytes: Vec<u8> =
        conn.query_row("SELECT device_id FROM device_identity LIMIT 1", [], |r| {
            r.get(0)
        })?;
    Id::from_slice(&bytes)
}

/// Append one audit record to `audit_log` inside `tx` (PRD §4.9).
///
/// Computes the per-device gapless `seq` (`max(seq)+1`) and the `prev_hash` from
/// this device's previous record's canonical bytes (genesis for the first), then
/// inserts the fully-populated row. All within the caller's transaction, so the
/// append is atomic with whatever else the caller commits.
///
/// # Errors
///
/// [`Error::Sqlite`] on a read/write failure, [`Error::Invalid`] on a corrupt
/// stored row.
fn append_audit_record(
    tx: &Connection,
    device_id: &DeviceId,
    kind: AuditKind,
    detail: Option<&str>,
) -> Result<()> {
    // seq = max(seq for this device) + 1 (gapless, 1-based).
    let last_seq: i64 = tx
        .query_row(
            "SELECT COALESCE(MAX(seq), 0) FROM audit_log WHERE device_id = ?1",
            params![device_id.to_vec()],
            |r| r.get(0),
        )
        .unwrap_or(0);
    let seq = u64::try_from(last_seq + 1).map_err(|_| Error::Invalid("audit seq out of range"))?;

    // prev_hash = chain hash of this device's previous record, or genesis.
    let prev_hash = match read_last_audit_record(tx, device_id)? {
        Some(prev) => prev.chain_hash(),
        None => audit::genesis_hash(device_id),
    };

    let record = AuditRecord {
        seq,
        prev_hash,
        timestamp: db::now_millis(),
        device_id: *device_id,
        kind,
        detail: detail.map(str::to_string),
    };
    insert_audit_record(tx, &record)
}

/// INSERT a fully-formed [`AuditRecord`] into `audit_log`, spreading the
/// kind-specific ids/fields across the dedicated columns.
fn insert_audit_record(tx: &Connection, record: &AuditRecord) -> Result<()> {
    let (format, item_count) = match &record.kind {
        AuditKind::Export { format, item_count } => (
            Some(format.clone()),
            i64::try_from(*item_count).unwrap_or(0),
        ),
        _ => (None, 0),
    };
    let field = match &record.kind {
        AuditKind::ItemSecretRead { field, .. } => field.clone(),
        _ => None,
    };
    tx.execute(
        "INSERT INTO audit_log
            (seq, device_id, prev_hash, timestamp, kind, item_id, vault_id,
             peer_device_id, field, format, item_count, detail)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
        params![
            i64::try_from(record.seq).map_err(|_| Error::Invalid("audit seq out of range"))?,
            record.device_id.to_vec(),
            record.prev_hash.as_slice(),
            record.timestamp,
            i64::from(record.kind.code()),
            record.kind.item_id().map(Id::to_vec),
            record.kind.vault_id().map(Id::to_vec),
            record.kind.peer_device_id().map(Id::to_vec),
            field,
            format,
            item_count,
            record.detail,
        ],
    )?;
    Ok(())
}

/// Read this device's most recent audit record (highest `seq`), or `None` if the
/// device has no records yet.
fn read_last_audit_record(tx: &Connection, device_id: &DeviceId) -> Result<Option<AuditRecord>> {
    let cols = tx
        .query_row(
            "SELECT seq, prev_hash, timestamp, kind, item_id, vault_id, peer_device_id,
                    field, format, item_count, detail
               FROM audit_log WHERE device_id = ?1 ORDER BY seq DESC LIMIT 1",
            params![device_id.to_vec()],
            audit_row_columns,
        )
        .optional()?;
    match cols {
        Some(cols) => Ok(Some(audit_record_from_columns(*device_id, cols)?)),
        None => Ok(None),
    }
}

/// The raw column tuple of an `audit_log` row (before decoding the kind).
type AuditRowColumns = (
    i64,             // seq
    Vec<u8>,         // prev_hash
    i64,             // timestamp
    i64,             // kind code
    Option<Vec<u8>>, // item_id
    Option<Vec<u8>>, // vault_id
    Option<Vec<u8>>, // peer_device_id
    Option<String>,  // field
    Option<String>,  // format
    i64,             // item_count
    Option<String>,  // detail
);

/// Extract the raw columns of an `audit_log` row (SQLite-error domain only).
fn audit_row_columns(r: &rusqlite::Row<'_>) -> rusqlite::Result<AuditRowColumns> {
    Ok((
        r.get(0)?,
        r.get(1)?,
        r.get(2)?,
        r.get(3)?,
        r.get(4)?,
        r.get(5)?,
        r.get(6)?,
        r.get(7)?,
        r.get(8)?,
        r.get(9)?,
        r.get(10)?,
    ))
}

/// Rebuild an [`AuditRecord`] from a decoded column tuple.
fn audit_record_from_columns(device_id: DeviceId, cols: AuditRowColumns) -> Result<AuditRecord> {
    let (
        seq,
        prev_hash,
        timestamp,
        code,
        item_id,
        vault_id,
        peer_device_id,
        field,
        format,
        item_count,
        detail,
    ) = cols;
    let prev_hash: [u8; 32] = prev_hash
        .as_slice()
        .try_into()
        .map_err(|_| Error::Invalid("stored audit prev_hash not 32 bytes"))?;
    let kind = audit::kind_from_row(
        code,
        item_id.as_deref(),
        vault_id.as_deref(),
        peer_device_id.as_deref(),
        field,
        item_count,
        format,
    )?;
    Ok(AuditRecord {
        seq: u64::try_from(seq).map_err(|_| Error::Invalid("stored audit seq out of range"))?,
        prev_hash,
        timestamp,
        device_id,
        kind,
        detail,
    })
}

/// Read and rehydrate the stored [`KdfParams`] plus the Secret Key id.
fn read_kdf_params(conn: &Connection) -> Result<(KdfParams, Vec<u8>)> {
    conn.query_row(
        "SELECT argon2_m_kib, argon2_t, argon2_p, salt, secret_key_id FROM kdf_params WHERE id = 1",
        [],
        |r| {
            let m: i64 = r.get(0)?;
            let t: i64 = r.get(1)?;
            let p: i64 = r.get(2)?;
            let salt: Vec<u8> = r.get(3)?;
            let skid: Vec<u8> = r.get(4)?;
            Ok((m, t, p, salt, skid))
        },
    )
    .map_err(Error::from)
    .and_then(|(m, t, p, salt, skid)| {
        let salt: [u8; 16] = salt
            .as_slice()
            .try_into()
            .map_err(|_| Error::Invalid("stored salt was not 16 bytes"))?;
        let params = KdfParams::with_salt(
            u32::try_from(m).map_err(|_| Error::Invalid("m_cost out of range"))?,
            u32::try_from(t).map_err(|_| Error::Invalid("t_cost out of range"))?,
            u32::try_from(p).map_err(|_| Error::Invalid("p_cost out of range"))?,
            salt,
        );
        Ok((params, skid))
    })
}

/// Interpret AAD bytes as `&str` for the wrap/unwrap purpose parameter.
///
/// All AADs in the account store are ASCII/UTF-8 label strings (no raw binary),
/// so this is always valid; wrap/unwrap take `&str` while the symmetric `seal`
/// path takes `&[u8]`.
fn aad_str(bytes: &[u8]) -> &str {
    // The account-store AADs are constructed from UTF-8 label + hex + decimal,
    // so they are always valid UTF-8.
    std::str::from_utf8(bytes).expect("account-store AAD is UTF-8")
}

/// Open an AccountKey-sealed envelope expected to contain exactly 32 secret
/// bytes, returning them in a zeroizing buffer. The intermediate heap
/// plaintext is wiped on every path, including the length-mismatch error.
fn open_secret_32(
    account_key: &AccountKey,
    envelope_bytes: &[u8],
    aad: &[u8],
    len_err: &'static str,
) -> Result<zeroize::Zeroizing<[u8; 32]>> {
    use zeroize::Zeroize;
    let envelope = lp_crypto::Envelope::from_bytes(envelope_bytes).map_err(Error::from_crypto)?;
    let mut plain = account_key
        .open(&envelope, aad)
        .map_err(Error::from_crypto)?;
    if plain.len() != 32 {
        plain.zeroize();
        return Err(Error::Invalid(len_err));
    }
    let mut out = zeroize::Zeroizing::new([0u8; 32]);
    out.copy_from_slice(&plain);
    plain.zeroize();
    Ok(out)
}

/// Split a cross-device share blob: `u32 LE len || sealed_key || u32 LE len ||
/// sealed_name` (see [`Session::share_vault_key_to_peer`]). Structural only —
/// no crypto; both segments are still sealed.
fn split_share_blob(blob: &[u8]) -> Result<(&[u8], &[u8])> {
    fn take(b: &[u8]) -> Result<(&[u8], &[u8])> {
        if b.len() < 4 {
            return Err(Error::Invalid("share blob truncated (length prefix)"));
        }
        let (len_bytes, rest) = b.split_at(4);
        let n = u32::from_le_bytes(len_bytes.try_into().expect("4 bytes")) as usize;
        if rest.len() < n {
            return Err(Error::Invalid("share blob truncated (segment)"));
        }
        Ok(rest.split_at(n))
    }
    let (sealed_key, rest) = take(blob)?;
    let (sealed_name, tail) = take(rest)?;
    if !tail.is_empty() {
        return Err(Error::Invalid("share blob has trailing bytes"));
    }
    Ok((sealed_key, sealed_name))
}

/// This device's identity: the live keypairs and their public bytes.
///
/// Private keypairs are held in memory for the [`Session`] lifetime and dropped
/// (zeroized by `lp-crypto`'s own key types) when the session is locked.
pub(crate) struct DeviceIdentity {
    pub(crate) device_id: DeviceId,
    pub(crate) signing: SigningKeyPair,
    // The X25519 sealing half of the device identity. Generated and persisted
    // per vault-format.md §2; consumed by the sync key-sharing path
    // ([`Session::open_sealed_to_me`]). Held so the live identity is complete
    // and lock() zeroizes it too.
    pub(crate) sealing: SealingKeyPair,
    pub(crate) ed25519_pub: [u8; 32],
    pub(crate) x25519_pub: [u8; 32],
}

impl DeviceIdentity {
    /// Generate a fresh device identity (new device_id + keypairs).
    fn generate() -> Self {
        let signing = SigningKeyPair::generate();
        let sealing = SealingKeyPair::generate();
        let ed25519_pub = signing.verifying_key().to_bytes();
        let x25519_pub = sealing.public_key().to_bytes();
        Self {
            device_id: Id::new(),
            signing,
            sealing,
            ed25519_pub,
            x25519_pub,
        }
    }

    /// Insert the `device_identity` row.
    ///
    /// Publics are plaintext; the private halves are the **real** Ed25519 seed
    /// and X25519 secret, sealed under the AccountKey with the spec's exact
    /// AAD (vault-format.md §2), so [`DeviceIdentity::load`] can reconstruct
    /// the identity at every unlock.
    fn insert(&self, tx: &Connection, account_key: &AccountKey, now: i64) -> Result<()> {
        // secret_seed()/secret_bytes() return zeroizing buffers; they are
        // sealed immediately and never leave this scope in plaintext.
        let ed_seed = self.signing.secret_seed();
        let x_secret = self.sealing.secret_bytes();
        let ed_env = account_key
            .seal(&ed_seed[..], &aad::device_ed25519(&self.device_id))
            .map_err(Error::from_crypto)?;
        let x_env = account_key
            .seal(&x_secret[..], &aad::device_x25519(&self.device_id))
            .map_err(Error::from_crypto)?;
        tx.execute(
            "INSERT INTO device_identity
                (device_id, ed25519_pub, x25519_pub, ed25519_priv_env, x25519_priv_env, created_at, label)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, NULL)",
            params![
                self.device_id.to_vec(),
                self.ed25519_pub.as_slice(),
                self.x25519_pub.as_slice(),
                ed_env.to_bytes(),
                x_env.to_bytes(),
                now,
            ],
        )?;
        Ok(())
    }

    /// Load the device identity at unlock: decrypt the persisted Ed25519 seed
    /// and X25519 secret under the AccountKey and reconstruct the keypairs,
    /// then verify the reconstructed publics match the stored plaintext
    /// publics (fail the unlock on mismatch rather than author ops under a
    /// divergent identity).
    fn load(conn: &Connection, account_key: &AccountKey) -> Result<Self> {
        let (device_id, ed_pub, x_pub, ed_env, x_env) = conn.query_row(
            "SELECT device_id, ed25519_pub, x25519_pub, ed25519_priv_env, x25519_priv_env
               FROM device_identity LIMIT 1",
            [],
            |r| {
                let d: Vec<u8> = r.get(0)?;
                let e: Vec<u8> = r.get(1)?;
                let x: Vec<u8> = r.get(2)?;
                let ee: Vec<u8> = r.get(3)?;
                let xe: Vec<u8> = r.get(4)?;
                Ok((d, e, x, ee, xe))
            },
        )?;
        let device_id = Id::from_slice(&device_id)?;
        let ed25519_pub: [u8; 32] = ed_pub
            .as_slice()
            .try_into()
            .map_err(|_| Error::Invalid("stored ed25519_pub was not 32 bytes"))?;
        let x25519_pub: [u8; 32] = x_pub
            .as_slice()
            .try_into()
            .map_err(|_| Error::Invalid("stored x25519_pub was not 32 bytes"))?;

        let signing = SigningKeyPair::from_seed(&*open_secret_32(
            account_key,
            &ed_env,
            &aad::device_ed25519(&device_id),
            "stored ed25519 seed was not 32 bytes",
        )?);
        let sealing = SealingKeyPair::from_secret_bytes(&*open_secret_32(
            account_key,
            &x_env,
            &aad::device_x25519(&device_id),
            "stored x25519 secret was not 32 bytes",
        )?);

        if signing.verifying_key().to_bytes() != ed25519_pub
            || sealing.public_key().to_bytes() != x25519_pub
        {
            return Err(Error::Invalid(
                "device identity public keys do not match reconstructed secrets",
            ));
        }

        Ok(Self {
            device_id,
            signing,
            sealing,
            ed25519_pub,
            x25519_pub,
        })
    }
}

/// This device's public identity, as pinned by a peer at pairing
/// (sync-protocol.md §6). All fields are plaintext / non-secret.
#[derive(Clone, Copy, Debug)]
pub struct DeviceIdentityInfo {
    /// This device's id (16 bytes).
    pub device_id: DeviceId,
    /// The Ed25519 signing public key (op-signature verification anchor).
    pub ed25519_pub: [u8; 32],
    /// The X25519 sealing public key (key-share recipient).
    pub x25519_pub: [u8; 32],
}

/// A trusted peer device's pinned public keys (a `peer_devices` row,
/// vault-format.md §2).
#[derive(Clone, Debug)]
pub struct PeerDevice {
    /// The peer's device id (16 bytes).
    pub device_id: DeviceId,
    /// The peer's Ed25519 signing public key (op-author verification anchor;
    /// sync-protocol.md §5 step 1).
    pub ed25519_pub: [u8; 32],
    /// The peer's X25519 sealing public key (key-share recipient).
    pub x25519_pub: [u8; 32],
    /// When the SAS confirmation recorded this trust (unix millis).
    pub verified_at: i64,
    /// An optional user label ("laptop").
    pub label: Option<String>,
}

/// Coerce a byte slice into a fixed 32-byte array, erroring with a static,
/// secret-free message if the stored blob is the wrong width.
fn to_32(bytes: &[u8], err: &'static str) -> Result<[u8; 32]> {
    bytes.try_into().map_err(|_| Error::Invalid(err))
}

/// An unlocked account session.
///
/// Holds the live [`AccountKey`] and this device's identity. Vaults are created
/// and opened through it. **Not `Clone`** — a session is a live capability over
/// unlocked key material. On [`lock`](Self::lock) or drop, all key material is
/// zeroized (the `lp-crypto` key newtypes zeroize on drop).
pub struct Session {
    dir: PathBuf,
    account_key: AccountKey,
    pub(crate) device: DeviceIdentity,
}

impl Session {
    /// This device's id.
    #[must_use]
    pub fn device_id(&self) -> DeviceId {
        self.device.device_id
    }

    /// Create a new vault named `name` (vault-format.md §5.1).
    ///
    /// Generates a fresh [`VaultKey`] and UUIDv7, initializes the
    /// `<vault_id>.vault` file (meta + full DDL), commits it, then inserts the
    /// registry row in the account store (commit order per vault-format.md §7:
    /// vault file committed, then registry row).
    ///
    /// # Errors
    ///
    /// [`Error::Io`] / [`Error::Sqlite`] / [`Error::Crypto`] on failure.
    pub fn create_vault(&self, name: &str) -> Result<VaultId> {
        let vault_id = Id::new();
        let vault_key = VaultKey::generate();
        let now = db::now_millis();

        // 1) Initialize and commit the vault file first (§7 commit order).
        let vault_path = self.vault_path(&vault_id);
        {
            let mut vconn = db::open_connection(&vault_path)?;
            db::restrict_permissions(&vault_path)?;
            let tx = vconn.transaction()?;
            tx.execute_batch(db::VAULT_DDL)?;
            tx.execute(
                "INSERT INTO meta (id, format_version, file_kind, vault_id, cipher_suite, created_at, index_generation)
                 VALUES (1, ?1, ?2, ?3, ?4, ?5, 0)",
                params![
                    db::FORMAT_VERSION,
                    db::FILE_KIND_VAULT,
                    vault_id.to_vec(),
                    db::CIPHER_SUITE_XCHACHA,
                    now,
                ],
            )?;
            tx.commit()?;
        }

        // 2) Insert the registry row (name + wrapped VaultKey) in the account store.
        let name_env = self
            .account_key
            .seal(name.as_bytes(), &aad::vault_name(&vault_id))
            .map_err(Error::from_crypto)?;
        let wrapped_vk = wrap_key(
            self.account_key.inner(),
            vault_key.inner(),
            aad_str(&aad::vault_key(&vault_id)),
        )
        .map_err(Error::from_crypto)?;

        let conn = db::open_connection(&self.account_path())?;
        conn.execute(
            "INSERT INTO vault_registry
                (vault_id, name_env, wrapped_vault_key, cipher_suite, created_at, deleted_at)
             VALUES (?1, ?2, ?3, ?4, ?5, NULL)",
            params![
                vault_id.to_vec(),
                name_env.to_bytes(),
                wrapped_vk.to_bytes(),
                db::CIPHER_SUITE_XCHACHA,
                now,
            ],
        )?;
        Ok(vault_id)
    }

    /// Open a live [`Vault`] by id, unwrapping its VaultKey from the registry.
    ///
    /// # Errors
    ///
    /// - [`Error::NotFound`] if the vault is not in the registry or is
    ///   soft-deleted.
    /// - [`Error::DecryptionFailed`] if the wrapped VaultKey fails to unwrap.
    pub fn open_vault(&self, vault_id: VaultId) -> Result<Vault<'_>> {
        let conn = db::open_connection(&self.account_path())?;
        let (wrapped, deleted): (Vec<u8>, Option<i64>) = conn
            .query_row(
                "SELECT wrapped_vault_key, deleted_at FROM vault_registry WHERE vault_id = ?1",
                params![vault_id.to_vec()],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .map_err(|e| match e {
                rusqlite::Error::QueryReturnedNoRows => Error::NotFound("vault"),
                other => Error::Sqlite(other),
            })?;
        if deleted.is_some() {
            return Err(Error::NotFound("vault (soft-deleted)"));
        }
        let envelope = lp_crypto::Envelope::from_bytes(&wrapped).map_err(Error::from_crypto)?;
        let vault_key_inner = unwrap_key(
            self.account_key.inner(),
            &envelope,
            aad_str(&aad::vault_key(&vault_id)),
        )
        .map_err(Error::from_crypto)?;
        let vault_key = VaultKey::from_inner(vault_key_inner);

        Vault::open(self.vault_path(&vault_id), vault_id, vault_key, self)
    }

    /// List all live (non-deleted) vaults as `(id, decrypted name)`.
    ///
    /// # Errors
    ///
    /// [`Error::Sqlite`] / [`Error::DecryptionFailed`] on failure.
    pub fn list_vaults(&self) -> Result<Vec<(VaultId, String)>> {
        let conn = db::open_connection(&self.account_path())?;
        let mut stmt = conn.prepare(
            "SELECT vault_id, name_env FROM vault_registry WHERE deleted_at IS NULL ORDER BY created_at",
        )?;
        let rows = stmt.query_map([], |r| {
            let id: Vec<u8> = r.get(0)?;
            let name_env: Vec<u8> = r.get(1)?;
            Ok((id, name_env))
        })?;
        let mut out = Vec::new();
        for row in rows {
            let (id_bytes, name_env) = row?;
            let vault_id = Id::from_slice(&id_bytes)?;
            let envelope =
                lp_crypto::Envelope::from_bytes(&name_env).map_err(Error::from_crypto)?;
            let name_bytes = self
                .account_key
                .open(&envelope, &aad::vault_name(&vault_id))
                .map_err(Error::from_crypto)?;
            let name = String::from_utf8(name_bytes)
                .map_err(|_| Error::Invalid("decrypted vault name was not UTF-8"))?;
            out.push((vault_id, name));
        }
        Ok(out)
    }

    /// Soft-delete a vault: set `vault_registry.deleted_at` (vault-format.md
    /// §5.1). The vault file is left in place; it simply becomes unlisted and
    /// unopenable.
    ///
    /// # Errors
    ///
    /// [`Error::NotFound`] if the vault does not exist; [`Error::Sqlite`] on
    /// failure.
    pub fn soft_delete_vault(&self, vault_id: VaultId) -> Result<()> {
        let conn = db::open_connection(&self.account_path())?;
        let n = conn.execute(
            "UPDATE vault_registry SET deleted_at = ?2 WHERE vault_id = ?1 AND deleted_at IS NULL",
            params![vault_id.to_vec(), db::now_millis()],
        )?;
        if n == 0 {
            return Err(Error::NotFound("vault"));
        }
        Ok(())
    }

    /// Change the master password (vault-format.md §5.5): re-derive the MUK from
    /// `new_password` with a **fresh salt**, unwrap the AccountKey with the old
    /// MUK and re-wrap it under the new MUK, rewriting only `kdf_params` and
    /// `wrapped_account_key` in **one transaction**.
    ///
    /// **The AccountKey plaintext is unchanged** — VaultKeys, ItemKeys, and all
    /// payloads are untouched (invariant §5). The Secret Key is unchanged.
    ///
    /// # Errors
    ///
    /// - [`Error::DecryptionFailed`] if `old_password` (with `secret_key`) is
    ///   wrong.
    /// - [`Error::Sqlite`] / [`Error::Crypto`] on failure.
    pub fn change_password(
        &self,
        old_password: &str,
        new_password: &str,
        secret_key: &SecretKey,
    ) -> Result<()> {
        let mut conn = db::open_connection(&self.account_path())?;
        let (old_params, secret_key_id) = read_kdf_params(&conn)?;

        // Verify old password by unwrapping the AccountKey under the old MUK.
        let old_muk = derive_master_unlock_key(old_password.as_bytes(), secret_key, &old_params)
            .map_err(Error::from_crypto)?;
        let wrapped_bytes: Vec<u8> = conn.query_row(
            "SELECT envelope FROM wrapped_account_key WHERE id = 1",
            [],
            |r| r.get(0),
        )?;
        let old_env =
            lp_crypto::Envelope::from_bytes(&wrapped_bytes).map_err(Error::from_crypto)?;
        let account_key_inner = unwrap_key(old_muk.inner(), &old_env, aad_str(&aad::account_key()))
            .map_err(Error::from_crypto)?;
        let account_key = AccountKey::from_inner(account_key_inner);

        // Re-wrap under a new MUK with fresh salt / recommended params.
        let new_params = KdfParams::recommended();
        let new_muk = derive_master_unlock_key(new_password.as_bytes(), secret_key, &new_params)
            .map_err(Error::from_crypto)?;
        let new_env = wrap_key(
            new_muk.inner(),
            account_key.inner(),
            aad_str(&aad::account_key()),
        )
        .map_err(Error::from_crypto)?;

        let now = db::now_millis();
        let tx = conn.transaction()?;
        tx.execute(
            "UPDATE kdf_params
                SET argon2_m_kib = ?1, argon2_t = ?2, argon2_p = ?3, salt = ?4
              WHERE id = 1",
            params![
                i64::from(new_params.m_cost_kib()),
                i64::from(new_params.t_cost()),
                i64::from(new_params.p_cost()),
                new_params.salt().as_slice(),
            ],
        )?;
        // secret_key_id is unchanged by a password change; leave it as-is.
        let _ = secret_key_id;
        tx.execute(
            "UPDATE wrapped_account_key SET envelope = ?1, wrapped_at = ?2 WHERE id = 1",
            params![new_env.to_bytes(), now],
        )?;
        tx.commit()?;
        Ok(())
    }

    /// Explicitly lock the session, dropping (and thereby zeroizing) all held
    /// key material (vault-format.md §5.4). `Drop` does the same, so this is an
    /// explicit, self-documenting alternative to letting the value fall out of
    /// scope.
    pub fn lock(self) {
        // Consuming `self` runs `Drop`, which drops `account_key` and the device
        // keypairs — all of which zeroize their secrets on drop (lp-crypto).
        drop(self);
    }

    /// Borrow the live AccountKey (crate-internal; vaults never need it, but
    /// kept for completeness of the seam).
    #[allow(dead_code)]
    pub(crate) fn account_key(&self) -> &AccountKey {
        &self.account_key
    }

    /// The profile directory this session operates on.
    #[must_use]
    pub fn profile_dir(&self) -> &Path {
        &self.dir
    }

    /// The on-disk path of a vault's `.vault` file (for stats/size display).
    #[must_use]
    pub fn vault_file_path(&self, vault_id: &VaultId) -> PathBuf {
        self.vault_path(vault_id)
    }

    // --- Sync integration (additive; sync-protocol.md §5/§6/§7) ------------

    /// This device's public identity: `device_id`, Ed25519 signing pub, and
    /// X25519 sealing pub (all plaintext, non-secret). The trust anchor a peer
    /// pins when pairing (`localpass device export-identity`).
    #[must_use]
    pub fn device_public_identity(&self) -> DeviceIdentityInfo {
        DeviceIdentityInfo {
            device_id: self.device.device_id,
            ed25519_pub: self.device.ed25519_pub,
            x25519_pub: self.device.x25519_pub,
        }
    }

    /// Trust a peer device: insert (or replace) its public keys in
    /// `peer_devices` (sync-protocol.md §6 — SAS is at the CLI layer; this
    /// records the confirmed anchor). Only devices recorded here are accepted
    /// as op authors on ingest (sync-protocol.md §5 step 1).
    ///
    /// # Errors
    ///
    /// [`Error::Sqlite`] on a write failure.
    pub fn trust_peer_device(
        &self,
        device_id: &DeviceId,
        ed25519_pub: &[u8; 32],
        x25519_pub: &[u8; 32],
        label: Option<&str>,
    ) -> Result<()> {
        let conn = db::open_connection(&self.account_path())?;
        conn.execute(
            "INSERT INTO peer_devices (device_id, ed25519_pub, x25519_pub, verified_at, label)
             VALUES (?1, ?2, ?3, ?4, ?5)
             ON CONFLICT(device_id) DO UPDATE SET
                ed25519_pub = excluded.ed25519_pub,
                x25519_pub = excluded.x25519_pub,
                verified_at = excluded.verified_at,
                label = excluded.label",
            params![
                device_id.to_vec(),
                ed25519_pub.as_slice(),
                x25519_pub.as_slice(),
                db::now_millis(),
                label,
            ],
        )?;
        // Trusting a peer device is an audited action (PRD §4.9 "shares"): record
        // the pinned peer id (non-secret). Best-effort — never fail the trust over
        // an audit hiccup.
        self.record_device_trust(device_id).ok();
        Ok(())
    }

    /// List all trusted peer devices (their pinned public keys).
    ///
    /// # Errors
    ///
    /// [`Error::Sqlite`] / [`Error::Invalid`] on a corrupt row.
    pub fn peer_devices(&self) -> Result<Vec<PeerDevice>> {
        let conn = db::open_connection(&self.account_path())?;
        let mut stmt = conn.prepare(
            "SELECT device_id, ed25519_pub, x25519_pub, verified_at, label
               FROM peer_devices ORDER BY verified_at",
        )?;
        let rows = stmt.query_map([], |r| {
            Ok((
                r.get::<_, Vec<u8>>(0)?,
                r.get::<_, Vec<u8>>(1)?,
                r.get::<_, Vec<u8>>(2)?,
                r.get::<_, i64>(3)?,
                r.get::<_, Option<String>>(4)?,
            ))
        })?;
        let mut out = Vec::new();
        for row in rows {
            let (id, ed, x, verified_at, label) = row?;
            out.push(PeerDevice {
                device_id: Id::from_slice(&id)?,
                ed25519_pub: to_32(&ed, "stored peer ed25519_pub was not 32 bytes")?,
                x25519_pub: to_32(&x, "stored peer x25519_pub was not 32 bytes")?,
                verified_at,
                label,
            });
        }
        Ok(out)
    }

    /// Look up one trusted peer device by id (the verifier's author lookup;
    /// sync-protocol.md §5 step 1). `None` for an unknown device → reject.
    ///
    /// # Errors
    ///
    /// [`Error::Sqlite`] / [`Error::Invalid`] on a corrupt row.
    pub fn peer_device(&self, device_id: &DeviceId) -> Result<Option<PeerDevice>> {
        let conn = db::open_connection(&self.account_path())?;
        let row = conn
            .query_row(
                "SELECT ed25519_pub, x25519_pub, verified_at, label
                   FROM peer_devices WHERE device_id = ?1",
                params![device_id.to_vec()],
                |r| {
                    Ok((
                        r.get::<_, Vec<u8>>(0)?,
                        r.get::<_, Vec<u8>>(1)?,
                        r.get::<_, i64>(2)?,
                        r.get::<_, Option<String>>(3)?,
                    ))
                },
            )
            .optional()?;
        match row {
            None => Ok(None),
            Some((ed, x, verified_at, label)) => Ok(Some(PeerDevice {
                device_id: *device_id,
                ed25519_pub: to_32(&ed, "stored peer ed25519_pub was not 32 bytes")?,
                x25519_pub: to_32(&x, "stored peer x25519_pub was not 32 bytes")?,
                verified_at,
                label,
            })),
        }
    }

    /// Read a plaintext setting value from the account store `settings` table.
    /// Used for per-vault sync enrollment (the sync-root dir) — a non-sensitive
    /// scalar (vault-format.md §2 allows plaintext for non-secret settings).
    ///
    /// # Errors
    ///
    /// [`Error::Sqlite`] on a read failure.
    pub fn get_setting(&self, key: &str) -> Result<Option<String>> {
        let conn = db::open_connection(&self.account_path())?;
        let v = conn
            .query_row(
                "SELECT value FROM settings WHERE key = ?1",
                params![key],
                |r| r.get::<_, Option<String>>(0),
            )
            .optional()?
            .flatten();
        Ok(v)
    }

    /// Write a plaintext setting value (upsert) — see [`get_setting`](Self::get_setting).
    ///
    /// # Errors
    ///
    /// [`Error::Sqlite`] on a write failure.
    pub fn set_setting(&self, key: &str, value: &str) -> Result<()> {
        let conn = db::open_connection(&self.account_path())?;
        conn.execute(
            "INSERT INTO settings (key, value, value_env) VALUES (?1, ?2, NULL)
             ON CONFLICT(key) DO UPDATE SET value = excluded.value, value_env = NULL",
            params![key, value],
        )?;
        Ok(())
    }

    /// Seal `plaintext` to a peer device's X25519 public key via
    /// [`lp_crypto::seal_for`] (the recipient model behind `vault
    /// share-to-device`). A thin, additive bridge so the sync layer can ship a
    /// sealed blob without holding a crypto primitive itself.
    ///
    /// # Errors
    ///
    /// [`Error::Crypto`] on a seal failure (e.g. a low-order recipient key).
    pub fn seal_to_peer(
        &self,
        peer_x25519_pub: &[u8; 32],
        plaintext: &[u8],
        aad: &[u8],
    ) -> Result<Vec<u8>> {
        let recipient = lp_crypto::PublicSealingKey::from_bytes(*peer_x25519_pub);
        lp_crypto::seal_for(&recipient, plaintext, aad).map_err(Error::from_crypto)
    }

    /// Open a blob sealed to **this** device's X25519 key (the counterpart of
    /// [`seal_to_peer`](Self::seal_to_peer)).
    ///
    /// # Errors
    ///
    /// [`Error::DecryptionFailed`] if this device is not the recipient or the
    /// bytes were tampered; [`Error::Crypto`] on a malformed sealed message.
    pub fn open_sealed_to_me(&self, sealed: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
        self.device
            .sealing
            .open(sealed, aad)
            .map_err(Error::from_crypto)
    }

    /// Seal this vault's key and name to a trusted peer device for
    /// cross-device sharing (PRD §4.5, single-user multi-device). Returns the
    /// opaque share blob shipped via the sync channel's `keys/` dir.
    ///
    /// Blob layout: `u32 LE len || sealed_key || u32 LE len || sealed_name`.
    /// The key travels through lp-crypto's typed key transport
    /// ([`lp_crypto::seal_key_for`] → [`lp_crypto::SealingKeyPair::open_key`])
    /// so raw key bytes never surface; both AADs bind the vault id AND the
    /// recipient device id (no cross-vault or cross-recipient replay).
    ///
    /// # Errors
    ///
    /// - [`Error::NotFound`] if the vault is not in the registry (or is
    ///   soft-deleted).
    /// - [`Error::Crypto`] on a seal failure (e.g. a low-order peer key).
    pub fn share_vault_key_to_peer(
        &self,
        vault_id: &VaultId,
        peer: &PeerDevice,
    ) -> Result<Vec<u8>> {
        // Unwrap the VaultKey + name exactly as open_vault / list_vaults do.
        let conn = db::open_connection(&self.account_path())?;
        let (wrapped, name_env, deleted): (Vec<u8>, Vec<u8>, Option<i64>) = conn
            .query_row(
                "SELECT wrapped_vault_key, name_env, deleted_at FROM vault_registry
                  WHERE vault_id = ?1",
                params![vault_id.to_vec()],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .map_err(|e| match e {
                rusqlite::Error::QueryReturnedNoRows => Error::NotFound("vault"),
                other => Error::Sqlite(other),
            })?;
        if deleted.is_some() {
            return Err(Error::NotFound("vault (soft-deleted)"));
        }
        let envelope = lp_crypto::Envelope::from_bytes(&wrapped).map_err(Error::from_crypto)?;
        let vault_key = unwrap_key(
            self.account_key.inner(),
            &envelope,
            aad_str(&aad::vault_key(vault_id)),
        )
        .map_err(Error::from_crypto)?;
        let name_envelope =
            lp_crypto::Envelope::from_bytes(&name_env).map_err(Error::from_crypto)?;
        let name = self
            .account_key
            .open(&name_envelope, &aad::vault_name(vault_id))
            .map_err(Error::from_crypto)?;

        let recipient = lp_crypto::PublicSealingKey::from_bytes(peer.x25519_pub);
        let sealed_key = lp_crypto::seal_key_for(
            &recipient,
            &vault_key,
            &aad::share_vault_key(vault_id, &peer.device_id),
        )
        .map_err(Error::from_crypto)?;
        let sealed_name = lp_crypto::seal_for(
            &recipient,
            &name,
            &aad::share_vault_name(vault_id, &peer.device_id),
        )
        .map_err(Error::from_crypto)?;

        let mut blob = Vec::with_capacity(8 + sealed_key.len() + sealed_name.len());
        blob.extend_from_slice(&u32::try_from(sealed_key.len()).unwrap().to_le_bytes());
        blob.extend_from_slice(&sealed_key);
        blob.extend_from_slice(&u32::try_from(sealed_name.len()).unwrap().to_le_bytes());
        blob.extend_from_slice(&sealed_name);
        // Sharing a vault key to a peer is an audited action (PRD §4.9 "shares"):
        // record the vault id + recipient device id (both non-secret).
        self.record_vault_share(vault_id, &peer.device_id).ok();
        Ok(blob)
    }

    /// Import a share blob addressed to **this** device: unseal the VaultKey
    /// and name (typed key transport — raw bytes never surface), re-wrap them
    /// under this account's AccountKey, and register the vault locally
    /// (creating an empty vault file for ops to sync into).
    ///
    /// Idempotent: returns `Ok(false)` if the vault is already registered,
    /// `Ok(true)` on a fresh import.
    ///
    /// # Errors
    ///
    /// - [`Error::Invalid`] on a malformed blob.
    /// - [`Error::DecryptionFailed`] if this device is not the recipient, the
    ///   blob was tampered, or it was sealed for a different vault id.
    pub fn import_shared_vault_key(&self, vault_id: &VaultId, blob: &[u8]) -> Result<bool> {
        let (sealed_key, sealed_name) = split_share_blob(blob)?;
        let me = self.device.device_id;

        let key = self
            .device
            .sealing
            .open_key(sealed_key, &aad::share_vault_key(vault_id, &me))
            .map_err(Error::from_crypto)?;
        let vault_key = VaultKey::from_inner(key);
        let name = self
            .device
            .sealing
            .open(sealed_name, &aad::share_vault_name(vault_id, &me))
            .map_err(Error::from_crypto)?;

        let wrapped = wrap_key(
            self.account_key.inner(),
            vault_key.inner(),
            aad_str(&aad::vault_key(vault_id)),
        )
        .map_err(Error::from_crypto)?;
        let name_env = self
            .account_key
            .seal(&name, &aad::vault_name(vault_id))
            .map_err(Error::from_crypto)?;

        self.register_shared_vault(vault_id, &wrapped.to_bytes(), &name_env.to_bytes())
    }

    /// Import a VaultKey (already unwrapped to its registry-storable
    /// AccountKey-wrapped form by the caller) into the local registry so this
    /// device can open a shared vault, creating an empty vault file if missing.
    ///
    /// Idempotent: a vault already registered returns `Ok(false)`; a freshly
    /// imported one returns `Ok(true)`.
    ///
    /// The caller supplies the AccountKey-`wrap_key`ped VaultKey envelope bytes
    /// and the AccountKey-sealed name envelope (both produced through the public
    /// crypto API), so this method holds no key primitive itself.
    ///
    /// # Errors
    ///
    /// [`Error::Sqlite`] / [`Error::Io`] on failure.
    pub fn register_shared_vault(
        &self,
        vault_id: &VaultId,
        wrapped_vault_key_env: &[u8],
        name_env: &[u8],
    ) -> Result<bool> {
        let conn = db::open_connection(&self.account_path())?;
        let present: bool = conn
            .query_row(
                "SELECT 1 FROM vault_registry WHERE vault_id = ?1",
                params![vault_id.to_vec()],
                |_| Ok(true),
            )
            .optional()?
            .unwrap_or(false);
        if present {
            return Ok(false);
        }
        let now = db::now_millis();

        // Create the local vault file if missing (ops arrive via sync pull and
        // materialize into it).
        let vault_path = self.vault_path(vault_id);
        if !vault_path.exists() {
            let mut vconn = db::open_connection(&vault_path)?;
            db::restrict_permissions(&vault_path)?;
            let tx = vconn.transaction()?;
            tx.execute_batch(db::VAULT_DDL)?;
            tx.execute(
                "INSERT INTO meta (id, format_version, file_kind, vault_id, cipher_suite, created_at, index_generation)
                 VALUES (1, ?1, ?2, ?3, ?4, ?5, 0)",
                params![
                    db::FORMAT_VERSION,
                    db::FILE_KIND_VAULT,
                    vault_id.to_vec(),
                    db::CIPHER_SUITE_XCHACHA,
                    now,
                ],
            )?;
            tx.commit()?;
        }

        conn.execute(
            "INSERT INTO vault_registry
                (vault_id, name_env, wrapped_vault_key, cipher_suite, created_at, deleted_at)
             VALUES (?1, ?2, ?3, ?4, ?5, NULL)",
            params![
                vault_id.to_vec(),
                name_env,
                wrapped_vault_key_env,
                db::CIPHER_SUITE_XCHACHA,
                now,
            ],
        )?;
        Ok(true)
    }

    // --- Audit log (device-local, hash-chained; PRD §4.9) ------------------

    /// Append one audit record to this device's chain (PRD §4.9).
    ///
    /// Opens the account store, ensures the `audit_log` table exists (the
    /// forward-only migration for pre-existing stores), and appends `kind` with
    /// an optional non-secret `detail` string, in its own transaction. This is
    /// the general hook behind the typed helpers
    /// ([`record_secret_read`](Self::record_secret_read),
    /// [`record_export`](Self::record_export),
    /// [`record_vault_share`](Self::record_vault_share),
    /// [`record_device_trust`](Self::record_device_trust)) and the vault
    /// mutation paths.
    ///
    /// # Errors
    ///
    /// [`Error::Sqlite`] on a DB failure; [`Error::Invalid`] on a corrupt chain.
    pub fn record_audit(&self, kind: AuditKind, detail: Option<&str>) -> Result<()> {
        let mut conn = db::open_connection(&self.account_path())?;
        db::ensure_audit_table(&conn)?;
        let device_id = self.device.device_id;
        let tx = conn.transaction()?;
        append_audit_record(&tx, &device_id, kind, detail)?;
        tx.commit()?;
        Ok(())
    }

    /// Record an [`AuditKind::ItemSecretRead`] (PRD §4.9): a read that revealed a
    /// secret value of `item_id` in `vault_id`. `field` names the single field
    /// revealed (a non-secret label like `"password"`), or `None` for a
    /// whole-item reveal. **Only** reveal paths call this — a masked `item get`,
    /// `list`, and `search` must not.
    ///
    /// # Errors
    ///
    /// [`Error::Sqlite`] / [`Error::Invalid`] on failure.
    pub fn record_secret_read(
        &self,
        vault_id: &VaultId,
        item_id: &crate::ids::ItemId,
        field: Option<&str>,
    ) -> Result<()> {
        self.record_audit(
            AuditKind::ItemSecretRead {
                item_id: *item_id,
                vault_id: *vault_id,
                field: field.map(str::to_string),
            },
            None,
        )
    }

    /// Record an [`AuditKind::Export`] (PRD §4.9): `item_count` items exported in
    /// `format` (e.g. `"age"`, `"json"`). Never records item contents.
    ///
    /// # Errors
    ///
    /// [`Error::Sqlite`] / [`Error::Invalid`] on failure.
    pub fn record_export(&self, format: &str, item_count: u64) -> Result<()> {
        self.record_audit(
            AuditKind::Export {
                format: format.to_string(),
                item_count,
            },
            None,
        )
    }

    /// Record an [`AuditKind::VaultShare`] (PRD §4.9): `vault_id`'s key was
    /// shared to `peer_device_id`.
    ///
    /// # Errors
    ///
    /// [`Error::Sqlite`] / [`Error::Invalid`] on failure.
    pub fn record_vault_share(&self, vault_id: &VaultId, peer_device_id: &DeviceId) -> Result<()> {
        self.record_audit(
            AuditKind::VaultShare {
                vault_id: *vault_id,
                peer_device_id: *peer_device_id,
            },
            None,
        )
    }

    /// Record an [`AuditKind::DeviceTrust`] (PRD §4.9): `peer_device_id` was
    /// trusted (its keys pinned).
    ///
    /// # Errors
    ///
    /// [`Error::Sqlite`] / [`Error::Invalid`] on failure.
    pub fn record_device_trust(&self, peer_device_id: &DeviceId) -> Result<()> {
        self.record_audit(
            AuditKind::DeviceTrust {
                peer_device_id: *peer_device_id,
            },
            None,
        )
    }

    /// The full audit log for **this device**, oldest first (ascending `seq`).
    ///
    /// # Errors
    ///
    /// [`Error::Sqlite`] / [`Error::Invalid`] on a read/corrupt-row failure.
    pub fn audit_iter(&self) -> Result<Vec<AuditRecord>> {
        self.read_audit(None)
    }

    /// The audit records for this device with `timestamp >= since_millis`, oldest
    /// first (`--since` on the CLI).
    ///
    /// # Errors
    ///
    /// [`Error::Sqlite`] / [`Error::Invalid`] on a read/corrupt-row failure.
    pub fn audit_since(&self, since_millis: i64) -> Result<Vec<AuditRecord>> {
        self.read_audit(Some(since_millis))
    }

    /// Shared audit reader: all of this device's records (optionally filtered to
    /// `timestamp >= since`), ordered by `seq` ascending.
    fn read_audit(&self, since: Option<i64>) -> Result<Vec<AuditRecord>> {
        let conn = db::open_connection(&self.account_path())?;
        db::ensure_audit_table(&conn)?;
        let device_id = self.device.device_id;
        let mut stmt = conn.prepare(
            "SELECT seq, prev_hash, timestamp, kind, item_id, vault_id, peer_device_id,
                    field, format, item_count, detail
               FROM audit_log
              WHERE device_id = ?1 AND timestamp >= ?2
              ORDER BY seq",
        )?;
        // A `None` filter is expressed as the minimum timestamp so the same SQL
        // serves both (no dynamic query building).
        let floor = since.unwrap_or(i64::MIN);
        let rows = stmt.query_map(params![device_id.to_vec(), floor], audit_row_columns)?;
        let mut out = Vec::new();
        for row in rows {
            out.push(audit_record_from_columns(device_id, row?)?);
        }
        Ok(out)
    }

    /// Re-verify this device's entire audit chain (PRD §4.9, mirrors
    /// [`Vault::verify_local_chain`](crate::Vault::verify_local_chain)): check
    /// that `seq` is gapless from 1 and that each record's `prev_hash` links to
    /// the previous record's canonical hash (genesis for the first).
    ///
    /// # Errors
    ///
    /// [`Error::ChainVerification`] on any gap or broken link; [`Error::Sqlite`]
    /// on a read failure.
    pub fn verify_audit_chain(&self) -> Result<()> {
        let records = self.audit_iter()?;
        let device_id = self.device.device_id;
        let mut prev_hash = audit::genesis_hash(&device_id);
        for (expected_seq, record) in (1_u64..).zip(records.iter()) {
            if record.seq != expected_seq {
                return Err(Error::ChainVerification("audit seq is not gapless from 1"));
            }
            if record.prev_hash != prev_hash {
                return Err(Error::ChainVerification("audit prev_hash does not chain"));
            }
            prev_hash = record.chain_hash();
        }
        Ok(())
    }

    /// Append an audit record from a [`Vault`](crate::Vault) mutation (create /
    /// update / delete / restore). Crate-internal: the vault holds a `&Session`
    /// and calls this immediately after committing the vault write, so the audit
    /// record is written iff the mutation succeeded (no orphan audit rows on a
    /// failed write). Best-effort ordering after the vault commit is documented
    /// on the vault methods.
    pub(crate) fn record_mutation(&self, kind: AuditKind) -> Result<()> {
        self.record_audit(kind, None)
    }

    /// Path to the account-store file.
    pub(crate) fn account_path(&self) -> PathBuf {
        self.dir.join(ACCOUNT_FILE)
    }

    /// Path to a vault file.
    pub(crate) fn vault_path(&self, vault_id: &VaultId) -> PathBuf {
        self.dir
            .join(VAULTS_DIR)
            .join(format!("{}.vault", vault_id.to_hyphenated()))
    }
}

impl core::fmt::Debug for Session {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // Never print key material; only the device id (non-secret).
        f.debug_struct("Session")
            .field("device_id", &self.device.device_id)
            .field("account_key", &"<redacted>")
            .finish()
    }
}
