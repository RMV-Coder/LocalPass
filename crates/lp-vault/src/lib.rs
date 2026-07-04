#![forbid(unsafe_code)]
#![warn(missing_docs)]
//! # LocalPass storage core (`lp-vault`)
//!
//! `lp-vault` implements the on-disk storage core specified in
//! `docs/specs/vault-format.md`: the **account store** (`account.localpass`), the
//! per-vault SQLite files, item versioning, folders, trash, and **local op-log
//! authoring** (`docs/specs/sync-protocol.md` §1–§5). It consumes only the
//! high-level API of [`lp_crypto`] and depends on **no** cryptographic primitive
//! crate directly (the crypto-boundary rule, `LESSONS.md`).
//!
//! ## The 30-second tour
//!
//! ```no_run
//! use lp_vault::{AccountStore, payload::{ItemPayload, TypeData}};
//! # fn main() -> lp_vault::Result<()> {
//! let dir = std::path::Path::new("/tmp/localpass-profile");
//!
//! // Create an account. The returned SecretKey is shown once in the Emergency
//! // Kit and never stored (vault-format.md §5.2 / PRD §4.11).
//! let (session, secret_key) = AccountStore::create(dir, "correct horse")?;
//! println!("Secret Key: {}", secret_key.to_display_string());
//!
//! // Create a vault and an item.
//! let vault_id = session.create_vault("personal")?;
//! let vault = session.open_vault(vault_id)?;
//! let note = ItemPayload::new(TypeData::Note {}, "shopping list");
//! let item_id = vault.create_item(&note)?;
//!
//! // Read it back.
//! let item = vault.get_item(item_id)?;
//! assert_eq!(item.payload.title, "shopping list");
//! # Ok(())
//! # }
//! ```
//!
//! ## Layout
//!
//! - [`AccountStore`] / [`Session`] — account create/unlock/lock, password
//!   change, and vault create/open/list/soft-delete ([`account`]).
//! - [`Vault`] — item create/get/update/delete/restore, history, folders,
//!   trash + purge, linear [`search`](Vault::search), and
//!   [`verify_local_chain`](Vault::verify_local_chain) ([`vault`]).
//! - [`payload`] — the canonical item model (the six MVP types).
//! - [`canonical`] — deterministic canonical-JSON encoding (a pragmatic RFC 8785
//!   / JCS profile; see its module docs for the documented UTF-8-vs-UTF-16
//!   key-sort deviation).
//! - [`Error`] — one error type; secret-dependent failures collapse to
//!   [`Error::DecryptionFailed`] (no oracles), and no variant carries plaintext.
//!
//! ## Durability (vault-format.md §7, normative)
//!
//! Every connection to either file kind sets `journal_mode=WAL`,
//! `synchronous=FULL`, and `foreign_keys=ON`. Each item mutation (create /
//! update / delete / restore) writes its op-log row **in the same transaction**
//! as the state change, so local vault state and the local op log never diverge.
//!
//! ## File permissions
//!
//! On Unix, freshly created store/vault files are `chmod 0600` (owner-only, PRD
//! §4.3). **On Windows** there is no POSIX mode: files inherit the user-profile
//! directory ACLs, which are owner-scoped by default under the per-user profile
//! locations LocalPass targets. This crate does not set Windows ACLs explicitly
//! (that would require a Win32 ACL dependency, out of scope here); it relies on
//! the profile-directory default and documents the difference here.
//!
//! ## Known `lp-crypto` API gap (device identity)
//!
//! vault-format.md §2 stores the device Ed25519 seed and X25519 scalar wrapped
//! under the AccountKey so the device identity is reconstructed at every unlock.
//! `lp_crypto`'s [`SigningKeyPair`](lp_crypto::SigningKeyPair) and
//! [`SealingKeyPair`](lp_crypto::SealingKeyPair) expose no private-seed export
//! and no from-seed constructor (only `generate()`), even though the underlying
//! dalek crates support both. `lp-vault` therefore keeps the live keypairs in
//! the [`Session`] and persists the **public** halves plaintext (as the spec
//! requires) plus correctly-AAD'd wrapped private envelopes; op-chain
//! *verification* uses the stored public key and is fully correct, while
//! authoring a new op *after a lock/unlock* uses a session-scoped key. Two small
//! additions to `lp-crypto` (`SigningKeyPair`/`SealingKeyPair` `from_bytes` +
//! `to_bytes`) would make this fully spec-exact with no schema change. See the
//! [`account`] module docs.

pub mod aad;
pub mod account;
pub mod backup;
pub mod canonical;
pub mod db;
pub mod error;
pub mod ids;
mod index;
pub mod op;
pub mod payload;
pub mod vault;

pub use account::{AccountStore, Session};
pub use error::{Error, Result};
// Re-export the `SecretKey` type: it is part of `AccountStore::create`'s public
// return and `unlock`'s public signature, so callers (and tests) need it without
// reaching into `lp-crypto` directly.
pub use backup::{
    BackupInfo, BackupManifest, ManifestFile, RestoreReport, VerifyReport, restore_single_item,
};
pub use ids::{DeviceId, FolderId, Id, ItemId, OpId, VaultId};
pub use lp_crypto::SecretKey;
pub use payload::{Field, FieldKind, ItemPayload, TypeData};
pub use vault::{Item, PruneReport, StorageStats, TrashEntry, Vault, VersionInfo};
