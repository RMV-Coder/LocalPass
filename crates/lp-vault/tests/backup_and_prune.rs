//! Integration tests for the `lp-vault` backup module and version pruning.
//!
//! Account create/unlock runs the real Argon2id KDF (~1s), so these batch many
//! assertions over few unlocks. Each test uses an isolated `tempfile` profile.

use std::fs;
use std::path::Path;

use lp_vault::backup;
use lp_vault::payload::{ItemPayload, TypeData};
use lp_vault::{AccountStore, SecretKey};
use tempfile::TempDir;

const PASSWORD: &str = "correct-horse-battery";

/// Create a fresh profile with an account + a `personal` vault, returning the
/// temp dir and the Secret Key.
fn init_profile() -> (TempDir, SecretKey) {
    let dir = tempfile::tempdir().expect("tempdir");
    let (session, secret_key) = AccountStore::create(dir.path(), PASSWORD).expect("create");
    session.create_vault("personal").expect("create vault");
    drop(session);
    (dir, secret_key)
}

/// Add a login item with a title to the (only) vault.
fn add_login(profile: &Path, secret_key: &SecretKey, title: &str) {
    let session = AccountStore::unlock(profile, PASSWORD, secret_key).expect("unlock");
    let (vault_id, _) = session.list_vaults().expect("list")[0];
    let vault = session.open_vault(vault_id).expect("open");
    let payload = ItemPayload::new(TypeData::Login { urls: vec![] }, title);
    vault.create_item(&payload).expect("create item");
}

/// backup create → list → verify happy path, plus the wrong-password contract.
#[test]
fn create_list_verify_happy_path_and_wrong_password() {
    let (dir, secret_key) = init_profile();
    add_login(dir.path(), &secret_key, "First");
    add_login(dir.path(), &secret_key, "Second");

    let root = dir.path().join(backup::BACKUPS_DIR);

    // create
    let info = backup::create(dir.path(), &root, 30).expect("create backup");
    assert_eq!(info.manifest.total_items(), 2);
    assert!(info.manifest.total_versions() >= 2);

    // list
    let backups = backup::list(&root).expect("list");
    assert_eq!(backups.len(), 1);
    let ts = backups[0].manifest.timestamp.clone();
    assert_eq!(ts, info.manifest.timestamp);

    let backup_dir = root.join(&ts);

    // verify — right credentials: all three checks pass.
    let report = backup::verify(&backup_dir, Some((PASSWORD, &secret_key))).expect("verify ok");
    assert!(report.hashes_ok, "check 1 hashes ok");
    assert!(report.integrity_ok, "check 2 integrity ok");
    assert_eq!(report.decrypt_ok, Some(true), "check 3 recoverable ok");
    assert!(report.all_ok());

    // verify — wrong password: checks 1-2 still pass, check 3 fails.
    let wrong = SecretKey::generate(); // a different Secret Key also fails check 3
    let bad_pw =
        backup::verify(&backup_dir, Some(("definitely-wrong", &secret_key))).expect("verify runs");
    assert!(bad_pw.hashes_ok, "check 1 still passes with wrong password");
    assert!(
        bad_pw.integrity_ok,
        "check 2 still passes with wrong password"
    );
    assert_eq!(bad_pw.decrypt_ok, Some(false), "check 3 fails");
    assert!(!bad_pw.all_ok());

    // A wrong Secret Key also fails only check 3.
    let bad_sk = backup::verify(&backup_dir, Some((PASSWORD, &wrong))).expect("verify runs");
    assert!(bad_sk.hashes_ok && bad_sk.integrity_ok);
    assert_eq!(bad_sk.decrypt_ok, Some(false));
}

/// A single flipped byte in a backup file trips the hash check (check 1).
#[test]
fn corrupt_backup_byte_fails_hash_check() {
    let (dir, secret_key) = init_profile();
    add_login(dir.path(), &secret_key, "One");
    let root = dir.path().join(backup::BACKUPS_DIR);
    let info = backup::create(dir.path(), &root, 30).expect("create");
    let backup_dir = info.dir.clone();

    // Sanity: it verifies clean first.
    assert!(backup::verify(&backup_dir, None).unwrap().hashes_ok);

    // Flip a byte in the account store snapshot.
    let account = backup_dir.join("account.localpass");
    let mut bytes = fs::read(&account).unwrap();
    let mid = bytes.len() / 2;
    bytes[mid] ^= 0xFF;
    fs::write(&account, &bytes).unwrap();

    let report = backup::verify(&backup_dir, None).unwrap();
    assert!(
        !report.hashes_ok,
        "hash check must fail on a corrupted byte"
    );
}

/// Rotation: 4 creates with keep=3 leaves the newest 3; a failed create (an
/// unwritable destination) deletes nothing.
#[test]
fn rotation_keeps_n_and_failed_create_deletes_nothing() {
    let (dir, secret_key) = init_profile();
    add_login(dir.path(), &secret_key, "Rotate");
    let root = dir.path().join(backup::BACKUPS_DIR);

    // Four creates with keep=3. Distinct second-resolution timestamps are
    // guaranteed by spacing the calls just past a second boundary is overkill;
    // instead we assert on the *count* which rotation bounds. To get four
    // distinct timestamp dirs we sleep ~1.1s between creates.
    let mut timestamps = Vec::new();
    for _ in 0..4 {
        let info = backup::create(dir.path(), &root, 3).expect("create");
        timestamps.push(info.manifest.timestamp.clone());
        std::thread::sleep(std::time::Duration::from_millis(1100));
    }

    let remaining = backup::list(&root).expect("list");
    assert_eq!(remaining.len(), 3, "keep=3 bounds the backup count");
    // The oldest timestamp must be gone; the newest three must remain.
    let remaining_ts: Vec<_> = remaining
        .iter()
        .map(|b| b.manifest.timestamp.clone())
        .collect();
    assert!(
        !remaining_ts.contains(&timestamps[0]),
        "oldest backup pruned"
    );
    for ts in &timestamps[1..] {
        assert!(remaining_ts.contains(ts), "recent backup {ts} retained");
    }

    // Failed create: point the destination at a path whose parent is a FILE, so
    // create_dir_all fails. Nothing existing must be deleted.
    let blocker = dir.path().join("not-a-dir");
    fs::write(&blocker, b"x").unwrap();
    let bad_root = blocker.join("under-a-file");
    let before = backup::list(&root).unwrap().len();
    let err = backup::create(dir.path(), &bad_root, 3);
    assert!(err.is_err(), "create into an unwritable dest fails");
    let after = backup::list(&root).unwrap().len();
    assert_eq!(before, after, "a failed create deletes nothing");
}

/// Full restore: a later item is gone after restore, the earlier state is back,
/// and the pre-restore copy contains the later item.
#[test]
fn full_restore_reverts_and_keeps_pre_restore_copy() {
    let (dir, secret_key) = init_profile();
    add_login(dir.path(), &secret_key, "Early");
    let root = dir.path().join(backup::BACKUPS_DIR);
    let info = backup::create(dir.path(), &root, 30).expect("create");

    // Add a later item AFTER the backup.
    add_login(dir.path(), &secret_key, "Later");

    // Restore the full profile from the backup.
    let report = backup::restore(dir.path(), &info.dir).expect("restore");
    assert_eq!(report.files_restored, 2, "account + one vault restored");
    let pre = report.pre_restore_dir.expect("pre-restore dir recorded");
    assert!(pre.exists(), "pre-restore copy exists");

    // Live profile: Later is gone, Early is back.
    let session = AccountStore::unlock(dir.path(), PASSWORD, &secret_key).expect("unlock");
    let (vault_id, _) = session.list_vaults().unwrap()[0];
    let vault = session.open_vault(vault_id).unwrap();
    let titles: Vec<_> = vault
        .list_items()
        .unwrap()
        .into_iter()
        .map(|i| i.payload.title)
        .collect();
    assert!(titles.contains(&"Early".to_string()), "Early restored");
    assert!(
        !titles.contains(&"Later".to_string()),
        "Later gone after restore"
    );
    drop(session);

    // The pre-restore copy is a full profile; unlock it directly (lp-vault's
    // unlock takes the SecretKey as a parameter — no on-disk secret-key file
    // exists at this layer) and confirm it holds Later.
    let pre_session =
        AccountStore::unlock(&pre, PASSWORD, &secret_key).expect("unlock pre-restore");
    let (pv, _) = pre_session.list_vaults().unwrap()[0];
    let pre_titles: Vec<_> = pre_session
        .open_vault(pv)
        .unwrap()
        .list_items()
        .unwrap()
        .into_iter()
        .map(|i| i.payload.title)
        .collect();
    assert!(
        pre_titles.contains(&"Later".to_string()),
        "pre-restore copy retains the later item"
    );
}

/// Corrupting the live profile then restoring recovers it.
#[test]
fn restore_recovers_a_corrupted_live_profile() {
    let (dir, secret_key) = init_profile();
    add_login(dir.path(), &secret_key, "Recoverable");
    let root = dir.path().join(backup::BACKUPS_DIR);
    let info = backup::create(dir.path(), &root, 30).expect("create");

    // Corrupt the live account store beyond opening.
    let account = dir.path().join("account.localpass");
    fs::write(&account, b"not a sqlite database at all").unwrap();
    // Also nuke WAL/SHM sidecars so the corruption sticks.
    let _ = fs::remove_file(dir.path().join("account.localpass-wal"));
    let _ = fs::remove_file(dir.path().join("account.localpass-shm"));

    // Unlock must now fail.
    assert!(AccountStore::unlock(dir.path(), PASSWORD, &secret_key).is_err());

    // Restore recovers it.
    backup::restore(dir.path(), &info.dir).expect("restore recovers");
    let session =
        AccountStore::unlock(dir.path(), PASSWORD, &secret_key).expect("unlock after restore");
    let (vault_id, _) = session.list_vaults().unwrap()[0];
    let titles: Vec<_> = session
        .open_vault(vault_id)
        .unwrap()
        .list_items()
        .unwrap()
        .into_iter()
        .map(|i| i.payload.title)
        .collect();
    assert!(titles.contains(&"Recoverable".to_string()));
}

/// Single-item restore brings an item back as a new version in the live vault
/// and the op chain still verifies afterwards.
#[test]
fn single_item_restore_adds_new_version_and_chain_stays_valid() {
    let (dir, secret_key) = init_profile();
    add_login(dir.path(), &secret_key, "KeepMe");
    let root = dir.path().join(backup::BACKUPS_DIR);
    let info = backup::create(dir.path(), &root, 30).expect("create");

    let session = AccountStore::unlock(dir.path(), PASSWORD, &secret_key).expect("unlock");
    let (vault_id, _) = session.list_vaults().unwrap()[0];
    let live_vault = session.open_vault(vault_id).unwrap();
    let before = live_vault.list_items().unwrap().len();

    // Restore the single item from the backup into the live vault.
    let new_id = backup::restore_single_item(
        &info.dir,
        PASSWORD,
        &secret_key,
        vault_id,
        "KeepMe",
        &live_vault,
    )
    .expect("single-item restore");

    let after = live_vault.list_items().unwrap();
    assert_eq!(after.len(), before + 1, "one new item created");
    assert!(
        after
            .iter()
            .any(|i| i.item_id == new_id && i.payload.title == "KeepMe"),
        "restored item present as a new item"
    );

    // The op chain still verifies (the restore appended one well-formed create).
    live_vault
        .verify_local_chain()
        .expect("op chain still valid after single-item restore");
}

/// Prune: an item with 12 versions, keep-last 10 → exactly 1 removed; the
/// current version survives; dry-run deletes nothing; stats reflect the drop;
/// verify_local_chain is unaffected.
#[test]
fn prune_keeps_current_and_removes_exactly_one() {
    let (dir, secret_key) = init_profile();
    let session = AccountStore::unlock(dir.path(), PASSWORD, &secret_key).expect("unlock");
    let (vault_id, _) = session.list_vaults().unwrap()[0];
    let vault = session.open_vault(vault_id).unwrap();

    // Create an item and edit it to 12 total versions.
    let mut payload = ItemPayload::new(TypeData::Login { urls: vec![] }, "Multi");
    let item_id = vault.create_item(&payload).unwrap(); // v1
    for i in 2..=12 {
        payload.notes = format!("edit {i}");
        vault.update_item(item_id, &payload).unwrap();
    }
    let stats_before = vault.storage_stats().unwrap();
    assert_eq!(stats_before.total_versions, 12);

    // Dry run removes nothing but reports exactly one.
    let dry = vault.prune_versions_dry_run(10, None).unwrap();
    assert_eq!(dry.versions_removed, 1, "dry-run: exactly one prunable");
    assert_eq!(
        vault.storage_stats().unwrap().total_versions,
        12,
        "dry-run deletes nothing"
    );

    // Real prune removes exactly one.
    let report = vault.prune_versions(10, None).unwrap();
    assert_eq!(report.versions_removed, 1, "keep-last 10 of 12 removes 1");
    assert_eq!(report.per_item.len(), 1);
    assert_eq!(report.per_item[0].1, 1);

    let stats_after = vault.storage_stats().unwrap();
    assert_eq!(
        stats_after.total_versions, 11,
        "stats reflect the reduction"
    );

    // The current version (v12) survives and is readable.
    let item = vault.get_item(item_id).unwrap();
    assert_eq!(item.current_version, 12);
    assert_eq!(item.payload.notes, "edit 12");

    // The pruned version (v1) is gone; the newest 10 non-current remain.
    assert!(vault.get_item_version(item_id, 1).is_err(), "v1 pruned");
    assert!(vault.get_item_version(item_id, 2).is_ok(), "v2 retained");
    assert!(
        vault.get_item_version(item_id, 12).is_ok(),
        "current retained"
    );

    // The op chain is unaffected (prune never touches ops).
    vault.verify_local_chain().expect("chain valid after prune");
}
