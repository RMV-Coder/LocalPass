//! Device identity persistence across lock/unlock (vault-format.md §2).
//!
//! The sync hash chain requires every op a device ever authors to verify
//! under the single public key peers pin for it (sync-protocol.md §5). These
//! tests prove the signing identity survives a lock/unlock cycle: ops
//! authored in a *second* session chain-verify together with ops from the
//! first.

use lp_vault::payload::{ItemPayload, TypeData};
use lp_vault::{AccountStore, Session};
use tempfile::TempDir;

fn note(title: &str, body: &str) -> ItemPayload {
    let mut p = ItemPayload::new(TypeData::Note {}, title);
    p.notes = body.to_string();
    p
}

fn unlock(dir: &TempDir, password: &str, sk: &lp_crypto::SecretKey) -> Session {
    AccountStore::unlock(dir.path(), password, sk).expect("unlock")
}

#[test]
fn op_chain_verifies_across_lock_unlock_sessions() {
    let dir = TempDir::new().unwrap();
    let (session, sk) = AccountStore::create(dir.path(), "test-password").unwrap();
    let device_id_1 = session.device_id();

    // Session 1: author some ops.
    let vault_id = session.create_vault("personal").unwrap();
    let item_id = {
        let vault = session.open_vault(vault_id).unwrap();
        let id = vault.create_item(&note("first", "v1")).unwrap();
        vault.update_item(id, &note("first", "v2")).unwrap();
        vault
            .verify_local_chain()
            .expect("chain valid in session 1");
        id
    };
    session.lock();

    // Session 2: the SAME device identity must be reconstructed, and new ops
    // must extend the same chain under the same public key.
    let session2 = unlock(&dir, "test-password", &sk);
    assert_eq!(
        session2.device_id(),
        device_id_1,
        "device id stable across unlock"
    );
    let vault = session2.open_vault(vault_id).unwrap();
    vault.update_item(item_id, &note("first", "v3")).unwrap();
    vault.delete_item(item_id, 30 * 24 * 3600 * 1000).unwrap();
    vault
        .verify_local_chain()
        .expect("ops from both sessions verify as one gapless chain");
}

#[test]
fn wrong_password_still_fails_closed_after_identity_persistence() {
    let dir = TempDir::new().unwrap();
    let (session, sk) = AccountStore::create(dir.path(), "correct").unwrap();
    session.lock();
    let err = AccountStore::unlock(dir.path(), "wrong", &sk).unwrap_err();
    assert!(matches!(err, lp_vault::Error::DecryptionFailed));
}
