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
use rusqlite::{Connection, params};
use std::path::{Path, PathBuf};

use crate::aad;
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

    /// Unlock an existing account under `dir` with `password` and `secret_key`.
    ///
    /// Re-derives the MUK from the stored KDF params, unwraps the AccountKey
    /// (**a wrong password or Secret Key fails here** with
    /// [`Error::DecryptionFailed`] — vault-format.md §5.2 step 4, no partial
    /// state), and loads this device's public identity.
    ///
    /// # Errors
    ///
    /// - [`Error::NotFound`] if no account store exists at `dir`.
    /// - [`Error::DecryptionFailed`] on a wrong password or Secret Key.
    /// - [`Error::UnsupportedFormat`] if the file is newer than this build.
    /// - [`Error::Sqlite`] on a DB failure.
    pub fn unlock(dir: &Path, password: &str, secret_key: &SecretKey) -> Result<Session> {
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
        let account_key_inner = unwrap_key(muk.inner(), &envelope, aad_str(&aad::account_key()))
            .map_err(Error::from_crypto)?;
        let account_key = AccountKey::from_inner(account_key_inner);

        let device = DeviceIdentity::load(&conn, &account_key)?;

        Ok(Session {
            dir: dir.to_path_buf(),
            account_key,
            device,
        })
    }
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

/// This device's identity: the live keypairs and their public bytes.
///
/// Private keypairs are held in memory for the [`Session`] lifetime and dropped
/// (zeroized by `lp-crypto`'s own key types) when the session is locked.
pub(crate) struct DeviceIdentity {
    pub(crate) device_id: DeviceId,
    pub(crate) signing: SigningKeyPair,
    // The X25519 sealing half of the device identity. Generated and persisted
    // per vault-format.md §2, but not yet *consumed* here: device pairing and
    // team sharing (which seal to peer X25519 keys) are P2 / a later crate.
    // Held so the live identity is complete and lock() zeroizes it too.
    #[allow(dead_code)]
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
