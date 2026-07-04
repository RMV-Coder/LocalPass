//! Security-property integration tests: fail-closed unlock, password-change
//! semantics, AAD anti-cut-and-paste, version immutability, atomicity, and
//! tombstone semantics.

use lp_crypto::SecretKey;
use lp_vault::payload::{ItemPayload, TypeData};
use lp_vault::{AccountStore, Error};
use rusqlite::{Connection, params};
use tempfile::TempDir;

const PW: &str = "correct horse battery staple";

fn account_path(dir: &std::path::Path) -> std::path::PathBuf {
    dir.join("account.localpass")
}

fn open_raw(path: &std::path::Path) -> Connection {
    Connection::open(path).unwrap()
}

#[test]
fn wrong_password_fails_closed_with_decryption_failed() {
    let dir = TempDir::new().unwrap();
    let (session, sk) = AccountStore::create(dir.path(), PW).unwrap();
    session.lock();

    let err = AccountStore::unlock(dir.path(), "wrong password entirely", &sk).unwrap_err();
    assert!(matches!(err, Error::DecryptionFailed), "got {err:?}");
}

#[test]
fn wrong_secret_key_fails_closed_with_decryption_failed() {
    let dir = TempDir::new().unwrap();
    let (session, _sk) = AccountStore::create(dir.path(), PW).unwrap();
    session.lock();

    let other = SecretKey::generate();
    let err = AccountStore::unlock(dir.path(), PW, &other).unwrap_err();
    assert!(matches!(err, Error::DecryptionFailed), "got {err:?}");
}

#[test]
fn password_change_old_rejected_new_works_accountkey_unchanged() {
    let dir = TempDir::new().unwrap();
    let (session, sk) = AccountStore::create(dir.path(), PW).unwrap();
    let vault_id = session.create_vault("v").unwrap();
    let vault = session.open_vault(vault_id).unwrap();

    let mut p = ItemPayload::new(TypeData::Note {}, "secret note");
    p.notes = "the body".into();
    let item_id = vault.create_item(&p).unwrap();

    // Capture the wrapped VaultKey bytes BEFORE the password change. If the
    // AccountKey plaintext were regenerated, the VaultKey would have to be
    // re-wrapped and these bytes would change. They must NOT.
    let vk_before: Vec<u8> = open_raw(&account_path(dir.path()))
        .query_row(
            "SELECT wrapped_vault_key FROM vault_registry WHERE vault_id = ?1",
            params![vault_id.as_bytes().to_vec()],
            |r| r.get(0),
        )
        .unwrap();

    drop(vault);
    let new_pw = "a brand new passphrase here";
    session.change_password(PW, new_pw, &sk).unwrap();

    // Old password now fails; new password unlocks.
    session.lock();
    assert!(matches!(
        AccountStore::unlock(dir.path(), PW, &sk),
        Err(Error::DecryptionFailed)
    ));
    let session2 = AccountStore::unlock(dir.path(), new_pw, &sk).unwrap();

    // The wrapped VaultKey bytes are byte-identical → AccountKey unchanged.
    let vk_after: Vec<u8> = open_raw(&account_path(dir.path()))
        .query_row(
            "SELECT wrapped_vault_key FROM vault_registry WHERE vault_id = ?1",
            params![vault_id.as_bytes().to_vec()],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(vk_before, vk_after, "AccountKey must be invariant (§5.5)");

    // And all items still decrypt.
    let vault2 = session2.open_vault(vault_id).unwrap();
    let item = vault2.get_item(item_id).unwrap();
    assert_eq!(item.payload.title, "secret note");
    assert_eq!(item.payload.notes, "the body");
}

#[test]
fn changing_the_password_does_not_change_the_secret_key() {
    let dir = TempDir::new().unwrap();
    let (session, sk) = AccountStore::create(dir.path(), PW).unwrap();
    session.change_password(PW, "new new new new", &sk).unwrap();
    session.lock();
    // The SAME Secret Key still unlocks with the new password.
    AccountStore::unlock(dir.path(), "new new new new", &sk).unwrap();
}

#[test]
fn aad_swap_payload_env_between_two_items_fails() {
    let dir = TempDir::new().unwrap();
    let (session, sk) = AccountStore::create(dir.path(), PW).unwrap();
    let vault_id = session.create_vault("v").unwrap();
    let vault = session.open_vault(vault_id).unwrap();

    let a = vault
        .create_item(&ItemPayload::new(TypeData::Note {}, "item A"))
        .unwrap();
    let b = vault
        .create_item(&ItemPayload::new(TypeData::Note {}, "item B"))
        .unwrap();
    drop(vault);
    session.lock();

    // Raw SQL: swap the two items' v1 payload_env blobs.
    let vpath = dir
        .path()
        .join("vaults")
        .join(format!("{}.vault", vault_id.to_hyphenated()));
    {
        let conn = open_raw(&vpath);
        let pa: Vec<u8> = conn
            .query_row(
                "SELECT payload_env FROM item_versions WHERE item_id = ?1 AND version = 1",
                params![a.as_bytes().to_vec()],
                |r| r.get(0),
            )
            .unwrap();
        let pb: Vec<u8> = conn
            .query_row(
                "SELECT payload_env FROM item_versions WHERE item_id = ?1 AND version = 1",
                params![b.as_bytes().to_vec()],
                |r| r.get(0),
            )
            .unwrap();
        conn.execute(
            "UPDATE item_versions SET payload_env = ?2 WHERE item_id = ?1 AND version = 1",
            params![a.as_bytes().to_vec(), pb],
        )
        .unwrap();
        conn.execute(
            "UPDATE item_versions SET payload_env = ?2 WHERE item_id = ?1 AND version = 1",
            params![b.as_bytes().to_vec(), pa],
        )
        .unwrap();
    }

    // Both reads must now fail: the AAD binds item_id, so the relocated blob
    // won't authenticate under the other item's key.
    let session2 = AccountStore::unlock(dir.path(), PW, &sk).unwrap();
    let vault2 = session2.open_vault(vault_id).unwrap();
    assert!(matches!(vault2.get_item(a), Err(Error::DecryptionFailed)));
    assert!(matches!(vault2.get_item(b), Err(Error::DecryptionFailed)));
}

#[test]
fn aad_swap_payload_env_between_two_versions_fails() {
    let dir = TempDir::new().unwrap();
    let (session, sk) = AccountStore::create(dir.path(), PW).unwrap();
    let vault_id = session.create_vault("v").unwrap();
    let vault = session.open_vault(vault_id).unwrap();

    let item = vault
        .create_item(&ItemPayload::new(TypeData::Note {}, "v1 content"))
        .unwrap();
    let mut p2 = ItemPayload::new(TypeData::Note {}, "v2 content");
    p2.notes = "changed".into();
    vault.update_item(item, &p2).unwrap();
    drop(vault);
    session.lock();

    let vpath = dir
        .path()
        .join("vaults")
        .join(format!("{}.vault", vault_id.to_hyphenated()));
    {
        let conn = open_raw(&vpath);
        let p1: Vec<u8> = conn
            .query_row(
                "SELECT payload_env FROM item_versions WHERE item_id = ?1 AND version = 1",
                params![item.as_bytes().to_vec()],
                |r| r.get(0),
            )
            .unwrap();
        let p2b: Vec<u8> = conn
            .query_row(
                "SELECT payload_env FROM item_versions WHERE item_id = ?1 AND version = 2",
                params![item.as_bytes().to_vec()],
                |r| r.get(0),
            )
            .unwrap();
        // Swap version 1's and version 2's payloads (same item, different version
        // ⇒ different AAD ⇒ must fail).
        conn.execute(
            "UPDATE item_versions SET payload_env = ?2 WHERE item_id = ?1 AND version = 1",
            params![item.as_bytes().to_vec(), p2b],
        )
        .unwrap();
        conn.execute(
            "UPDATE item_versions SET payload_env = ?2 WHERE item_id = ?1 AND version = 2",
            params![item.as_bytes().to_vec(), p1],
        )
        .unwrap();
    }

    let session2 = AccountStore::unlock(dir.path(), PW, &sk).unwrap();
    let vault2 = session2.open_vault(vault_id).unwrap();
    assert!(matches!(
        vault2.get_item_version(item, 1),
        Err(Error::DecryptionFailed)
    ));
    assert!(matches!(
        vault2.get_item_version(item, 2),
        Err(Error::DecryptionFailed)
    ));
}

#[test]
fn aad_copy_wrapped_key_across_vaults_fails() {
    let dir = TempDir::new().unwrap();
    let (session, sk) = AccountStore::create(dir.path(), PW).unwrap();
    let v1 = session.create_vault("v1").unwrap();
    let v2 = session.create_vault("v2").unwrap();

    let vault1 = session.open_vault(v1).unwrap();
    let item1 = vault1
        .create_item(&ItemPayload::new(TypeData::Note {}, "in v1"))
        .unwrap();
    let vault2 = session.open_vault(v2).unwrap();
    let item2 = vault2
        .create_item(&ItemPayload::new(TypeData::Note {}, "in v2"))
        .unwrap();
    drop(vault1);
    drop(vault2);
    session.lock();

    let p1 = dir
        .path()
        .join("vaults")
        .join(format!("{}.vault", v1.to_hyphenated()));
    let p2 = dir
        .path()
        .join("vaults")
        .join(format!("{}.vault", v2.to_hyphenated()));

    // Copy v1's item1 wrapped_keys row into v2's item2 row. The wrap AAD binds
    // vault_id|item_id|version, so it cannot open under v2's VaultKey for item2.
    let wk1: Vec<u8> = open_raw(&p1)
        .query_row(
            "SELECT envelope FROM wrapped_keys WHERE item_id = ?1 AND version = 1",
            params![item1.as_bytes().to_vec()],
            |r| r.get(0),
        )
        .unwrap();
    open_raw(&p2)
        .execute(
            "UPDATE wrapped_keys SET envelope = ?2 WHERE item_id = ?1 AND version = 1",
            params![item2.as_bytes().to_vec(), wk1],
        )
        .unwrap();

    let session2 = AccountStore::unlock(dir.path(), PW, &sk).unwrap();
    let vault2b = session2.open_vault(v2).unwrap();
    assert!(matches!(
        vault2b.get_item(item2),
        Err(Error::DecryptionFailed)
    ));
}

#[test]
fn version_immutability_old_ciphertext_unchanged_after_edit() {
    let dir = TempDir::new().unwrap();
    let (session, _sk) = AccountStore::create(dir.path(), PW).unwrap();
    let vault_id = session.create_vault("v").unwrap();
    let vault = session.open_vault(vault_id).unwrap();

    let item = vault
        .create_item(&ItemPayload::new(TypeData::Note {}, "original"))
        .unwrap();

    let vpath = dir
        .path()
        .join("vaults")
        .join(format!("{}.vault", vault_id.to_hyphenated()));
    let v1_before: Vec<u8> = open_raw(&vpath)
        .query_row(
            "SELECT payload_env FROM item_versions WHERE item_id = ?1 AND version = 1",
            params![item.as_bytes().to_vec()],
            |r| r.get(0),
        )
        .unwrap();

    // Edit twice.
    let mut p = ItemPayload::new(TypeData::Note {}, "edited once");
    p.notes = "n1".into();
    vault.update_item(item, &p).unwrap();
    p.title = "edited twice".into();
    vault.update_item(item, &p).unwrap();

    // v1's ciphertext is byte-identical to before (never UPDATEd).
    let v1_after: Vec<u8> = open_raw(&vpath)
        .query_row(
            "SELECT payload_env FROM item_versions WHERE item_id = ?1 AND version = 1",
            params![item.as_bytes().to_vec()],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(v1_before, v1_after, "an existing version row was mutated");

    // Three distinct versions exist.
    let count: i64 = open_raw(&vpath)
        .query_row(
            "SELECT COUNT(*) FROM item_versions WHERE item_id = ?1",
            params![item.as_bytes().to_vec()],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(count, 3);
}

#[test]
fn transaction_atomicity_no_partial_rows_on_forced_failure() {
    let dir = TempDir::new().unwrap();
    let (session, _sk) = AccountStore::create(dir.path(), PW).unwrap();
    let vault_id = session.create_vault("v").unwrap();
    let vault = session.open_vault(vault_id).unwrap();

    // A successful create for baseline counts.
    vault
        .create_item(&ItemPayload::new(TypeData::Note {}, "ok"))
        .unwrap();

    let vpath = dir
        .path()
        .join("vaults")
        .join(format!("{}.vault", vault_id.to_hyphenated()));
    let ops_before: i64 = open_raw(&vpath)
        .query_row("SELECT COUNT(*) FROM ops", [], |r| r.get(0))
        .unwrap();
    let wk_before: i64 = open_raw(&vpath)
        .query_row("SELECT COUNT(*) FROM wrapped_keys", [], |r| r.get(0))
        .unwrap();

    // Force a mid-write failure: pre-insert a conflicting ops row is hard to
    // arrange from outside, so instead we inject a UNIQUE(device_id, seq)
    // collision by manually inserting the seq the next op will try to use.
    // The next create_item authors seq = max+1; we occupy exactly that seq.
    let device_id: Vec<u8> = open_raw(&vpath)
        .query_row("SELECT device_id FROM ops LIMIT 1", [], |r| r.get(0))
        .unwrap();
    let next_seq: i64 = open_raw(&vpath)
        .query_row("SELECT MAX(seq) + 1 FROM ops", [], |r| r.get(0))
        .unwrap();
    open_raw(&vpath)
        .execute(
            "INSERT INTO ops (op_id, vault_id, lamport, device_id, op_kind, target_item_id,
                              target_version, payload_env, signature, seq, prev_hash, created_at)
             VALUES (?1, ?2, 9999, ?3, 1, NULL, 0, x'01', x'00', ?4, x'00', 0)",
            params![
                lp_vault::Id::new().as_bytes().to_vec(),
                vault_id.as_bytes().to_vec(),
                device_id,
                next_seq
            ],
        )
        .unwrap();

    // This create tries to use seq = next_seq, hits the UNIQUE constraint, and
    // the whole transaction rolls back — no orphan wrapped_keys/item_versions.
    let result = vault.create_item(&ItemPayload::new(TypeData::Note {}, "doomed"));
    assert!(
        result.is_err(),
        "expected the constraint violation to surface"
    );

    // wrapped_keys count is unchanged (no orphan from the failed create); the
    // only new ops row is the one WE injected, not a partial op.
    let wk_after: i64 = open_raw(&vpath)
        .query_row("SELECT COUNT(*) FROM wrapped_keys", [], |r| r.get(0))
        .unwrap();
    assert_eq!(
        wk_before, wk_after,
        "orphan wrapped_keys row was left behind"
    );
    let ops_after: i64 = open_raw(&vpath)
        .query_row("SELECT COUNT(*) FROM ops", [], |r| r.get(0))
        .unwrap();
    // Exactly one more ops row than before — the injected one — proving the
    // failed create authored nothing that survived.
    assert_eq!(ops_after, ops_before + 1);
    // The doomed item never became visible.
    assert_eq!(vault.list_items().unwrap().len(), 1);
}

#[test]
fn tombstone_semantics_hidden_from_list_present_in_trash() {
    let dir = TempDir::new().unwrap();
    let (session, _sk) = AccountStore::create(dir.path(), PW).unwrap();
    let vault_id = session.create_vault("v").unwrap();
    let vault = session.open_vault(vault_id).unwrap();

    let mut note = ItemPayload::new(TypeData::Note {}, "findme");
    note.tags = vec!["searchable".into()];
    let item = vault.create_item(&note).unwrap();
    vault
        .create_item(&ItemPayload::new(TypeData::Note {}, "keeper"))
        .unwrap();

    // Before delete: visible in list and search.
    assert_eq!(vault.list_items().unwrap().len(), 2);
    assert_eq!(vault.search("findme", None).unwrap().len(), 1);

    let retention = 30 * 24 * 3600 * 1000;
    vault.delete_item(item, retention).unwrap();

    // After delete: absent from list/search, present in trash.
    assert_eq!(vault.list_items().unwrap().len(), 1);
    assert_eq!(vault.search("findme", None).unwrap().len(), 0);
    let trash = vault.list_trash().unwrap();
    assert_eq!(trash.len(), 1);
    assert_eq!(trash[0].item_id, item);
    assert!(trash[0].purge_after > trash[0].deleted_at);

    // Purge before the window does nothing; after it, the item is shredded.
    assert_eq!(vault.purge_expired_trash(0).unwrap(), 0);
    assert_eq!(vault.purge_expired_trash(i64::MAX / 2).unwrap(), 1);
    assert_eq!(vault.list_trash().unwrap().len(), 0);
    // Restore from trash is now impossible (rows shredded).
    assert!(vault.restore_version(item, 1).is_err());
}
