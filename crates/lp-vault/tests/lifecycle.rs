//! Full-lifecycle and feature integration tests for `lp-vault`.
//!
//! These exercise the real create/unlock cost (Argon2id at recommended params),
//! so they are intentionally few per file. Each uses an isolated `tempfile` dir.

use lp_vault::AccountStore;
use lp_vault::payload::{EnvEntry, Field, FieldKind, ItemPayload, TypeData};
use serde_json::json;
use tempfile::TempDir;

/// Build one payload of each of the six MVP types.
fn all_six_types() -> Vec<ItemPayload> {
    let mut login = ItemPayload::new(
        TypeData::Login {
            urls: vec!["https://alt.example".into()],
        },
        "ACME prod DB",
    );
    login.tags = vec!["prod".into(), "db".into()];
    login.favorite = true;
    login.fields = vec![
        Field {
            name: "username".into(),
            kind: FieldKind::Text,
            value: json!("svc_acme"),
        },
        Field {
            name: "password".into(),
            kind: FieldKind::Hidden,
            value: json!("hunter2"),
        },
        Field {
            name: "expires".into(),
            kind: FieldKind::Date,
            value: json!(1_788_134_400_000_i64),
        },
    ];

    vec![
        login,
        ItemPayload::new(TypeData::Note {}, "secure note body"),
        ItemPayload::new(
            TypeData::ApiKey {
                key: "AKIAEXAMPLE".into(),
                secret: "wJalr".into(),
                endpoint: "https://api.example".into(),
                expiry: Some(1_788_134_400_000),
                rotate_after: Some(1_790_000_000_000),
            },
            "prod api key",
        ),
        ItemPayload::new(
            TypeData::EnvSet {
                entries: vec![
                    EnvEntry {
                        key: "DATABASE_URL".into(),
                        value: "postgres://x".into(),
                    },
                    EnvEntry {
                        key: "REDIS_URL".into(),
                        value: "redis://y".into(),
                    },
                ],
            },
            "backend .env",
        ),
        ItemPayload::new(
            TypeData::SshKey {
                algo: "ed25519".into(),
                private_pem: "-----BEGIN PRIVATE KEY-----".into(),
                public_openssh: "ssh-ed25519 AAAAC3".into(),
                fingerprint: "SHA256:abcdef".into(),
            },
            "deploy key",
        ),
        ItemPayload::new(
            TypeData::Totp {
                secret_b32: "JBSWY3DPEHPK3PXP".into(),
                algo: "SHA1".into(),
                digits: 6,
                period: 30,
                issuer: "ACME".into(),
                account: "me@acme".into(),
            },
            "github 2fa",
        ),
    ]
}

#[test]
fn full_lifecycle_create_edit_history_restore_delete_purge_unlock() {
    let dir = TempDir::new().unwrap();
    let password = "correct horse battery staple";

    // Create account + vault + one item of every MVP type.
    let (session, secret_key) = AccountStore::create(dir.path(), password).unwrap();
    let vault_id = session.create_vault("personal").unwrap();
    let vault = session.open_vault(vault_id).unwrap();

    let mut item_ids = Vec::new();
    for payload in all_six_types() {
        item_ids.push(vault.create_item(&payload).unwrap());
    }
    assert_eq!(vault.list_items().unwrap().len(), 6);

    // Update the login item a few times → versions accrue.
    let login_id = item_ids[0];
    for i in 1..=3 {
        let mut p = vault.get_item(login_id).unwrap().payload;
        p.title = format!("ACME prod DB v{i}");
        let new_ver = vault.update_item(login_id, &p).unwrap();
        assert_eq!(new_ver, i + 1);
    }
    let hist = vault.history(login_id).unwrap();
    assert_eq!(hist.len(), 4); // v1 + 3 edits
    assert_eq!(hist[0].payload.title, "ACME prod DB");
    assert_eq!(hist[3].payload.title, "ACME prod DB v3");

    // Restore an old version → becomes a new version with the old content.
    let restored_ver = vault.restore_version(login_id, 1).unwrap();
    assert_eq!(restored_ver, 5);
    assert_eq!(
        vault.get_item(login_id).unwrap().payload.title,
        "ACME prod DB"
    );
    // History grew, old rows untouched.
    assert_eq!(vault.history(login_id).unwrap().len(), 5);

    // Delete an item → it leaves the live list, enters trash.
    let note_id = item_ids[1];
    vault.delete_item(note_id, 30 * 24 * 3600 * 1000).unwrap();
    assert_eq!(vault.list_items().unwrap().len(), 5);
    assert!(vault.get_item(note_id).is_err());
    assert_eq!(vault.list_trash().unwrap().len(), 1);

    // Purge with a `now` past the purge window → item is shredded, unrecoverable.
    let far_future = i64::MAX / 2;
    let purged = vault.purge_expired_trash(far_future).unwrap();
    assert_eq!(purged, 1);
    assert_eq!(vault.list_trash().unwrap().len(), 0);
    // The item's versions are gone: even get_item_version fails now.
    assert!(vault.get_item_version(note_id, 1).is_err());

    // The op chain is intact after all these mixed operations.
    vault.verify_local_chain().unwrap();

    // Lock and unlock; everything reads back.
    drop(vault);
    session.lock();

    let session2 = AccountStore::unlock(dir.path(), password, &secret_key).unwrap();
    let vaults = session2.list_vaults().unwrap();
    assert_eq!(vaults.len(), 1);
    assert_eq!(vaults[0].1, "personal");

    let vault2 = session2.open_vault(vault_id).unwrap();
    let items = vault2.list_items().unwrap();
    assert_eq!(items.len(), 5);
    // The login item still decrypts and reads its restored content.
    assert_eq!(
        vault2.get_item(login_id).unwrap().payload.title,
        "ACME prod DB"
    );
    // Every type still round-trips.
    for item in &items {
        match &item.payload.type_data {
            TypeData::Login { .. }
            | TypeData::ApiKey { .. }
            | TypeData::EnvSet { .. }
            | TypeData::SshKey { .. }
            | TypeData::Totp { .. } => {}
            TypeData::Note {} => panic!("the note was purged; should not appear"),
        }
    }
    vault2.verify_local_chain().unwrap();
}

#[test]
fn folders_crud_with_encrypted_names() {
    let dir = TempDir::new().unwrap();
    let (session, _sk) = AccountStore::create(dir.path(), "pw pw pw pw").unwrap();
    let vault = session
        .open_vault(session.create_vault("v").unwrap())
        .unwrap();

    let f1 = vault.create_folder("Work").unwrap();
    let _f2 = vault.create_folder("Personal").unwrap();
    let folders = vault.list_folders().unwrap();
    assert_eq!(folders.len(), 2);
    let names: Vec<&str> = folders.iter().map(|(_, n)| n.as_str()).collect();
    assert!(names.contains(&"Work"));
    assert!(names.contains(&"Personal"));

    vault.delete_folder(f1).unwrap();
    assert_eq!(vault.list_folders().unwrap().len(), 1);
    assert!(vault.delete_folder(f1).is_err()); // already gone
}

#[test]
fn search_linear_placeholder_matches_and_filters() {
    let dir = TempDir::new().unwrap();
    let (session, _sk) = AccountStore::create(dir.path(), "pw pw pw pw").unwrap();
    let vault = session
        .open_vault(session.create_vault("v").unwrap())
        .unwrap();

    let mut login = ItemPayload::new(TypeData::Login { urls: vec![] }, "GitHub login");
    login.tags = vec!["dev".into()];
    vault.create_item(&login).unwrap();
    let ssh = ItemPayload::new(
        TypeData::SshKey {
            algo: "ed25519".into(),
            private_pem: String::new(),
            public_openssh: String::new(),
            fingerprint: String::new(),
        },
        "prod deploy key",
    );
    vault.create_item(&ssh).unwrap();

    // Title substring.
    assert_eq!(vault.search("github", None).unwrap().len(), 1);
    // Tag substring.
    assert_eq!(vault.search("dev", None).unwrap().len(), 1);
    // Type filter.
    assert_eq!(vault.search("", Some("ssh_key")).unwrap().len(), 1);
    assert_eq!(vault.search("", Some("login")).unwrap().len(), 1);
    // Empty query, no filter → all live items.
    assert_eq!(vault.search("", None).unwrap().len(), 2);
    // No match.
    assert_eq!(vault.search("nonexistent", None).unwrap().len(), 0);
}

#[test]
fn multiple_vaults_are_isolated_and_listable() {
    let dir = TempDir::new().unwrap();
    let (session, _sk) = AccountStore::create(dir.path(), "pw pw pw pw").unwrap();

    let work = session.create_vault("work").unwrap();
    let personal = session.create_vault("personal").unwrap();
    assert_eq!(session.list_vaults().unwrap().len(), 2);

    let wv = session.open_vault(work).unwrap();
    wv.create_item(&ItemPayload::new(TypeData::Note {}, "work note"))
        .unwrap();
    let pv = session.open_vault(personal).unwrap();
    assert_eq!(wv.list_items().unwrap().len(), 1);
    assert_eq!(pv.list_items().unwrap().len(), 0); // isolated

    // Soft-delete one vault → it vanishes from the list and cannot be opened.
    session.soft_delete_vault(work).unwrap();
    assert_eq!(session.list_vaults().unwrap().len(), 1);
    assert!(session.open_vault(work).is_err());
}
