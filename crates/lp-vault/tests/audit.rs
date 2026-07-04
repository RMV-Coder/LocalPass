//! Audit-log integration tests (PRD §4.9): the device-local, hash-chained audit
//! log — chain integrity + tamper detection, event coverage per action, the
//! plaintext-metadata privacy contract (never a secret/title/username), and
//! append atomicity vs. failed writes.

use lp_vault::payload::{Field, FieldKind, ItemPayload, TypeData};
use lp_vault::{AccountStore, AuditKind, Error, Session, VaultId};
use rusqlite::{Connection, params};
use serde_json::json;
use tempfile::TempDir;

const PW: &str = "correct horse battery staple";

/// A planted secret + title + username we assert never appear in the audit log.
const SECRET_PW: &str = "sup3r-s3cr3t-pw-DO-NOT-LOG";
const TITLE: &str = "ACME production database";
const USERNAME: &str = "svc_acme_admin";

fn account_path(dir: &std::path::Path) -> std::path::PathBuf {
    dir.join("account.localpass")
}

/// A login payload carrying a hidden password field, a username, and a title —
/// all of which are secret/sensitive and must never reach the audit log.
fn secret_login() -> ItemPayload {
    let mut p = ItemPayload::new(TypeData::Login { urls: vec![] }, TITLE);
    p.fields = vec![
        Field {
            name: "username".into(),
            kind: FieldKind::Text,
            value: json!(USERNAME),
        },
        Field {
            name: "password".into(),
            kind: FieldKind::Hidden,
            value: json!(SECRET_PW),
        },
    ];
    p
}

/// Dump the entire `audit_log` table to a single debug string (every column of
/// every row), for privacy assertions and inspection.
fn dump_audit_table(dir: &std::path::Path) -> String {
    let conn = Connection::open(account_path(dir)).unwrap();
    let mut stmt = conn
        .prepare(
            "SELECT seq, hex(device_id), hex(prev_hash), timestamp, kind,
                    hex(item_id), hex(vault_id), hex(peer_device_id), field, format,
                    item_count, detail
               FROM audit_log ORDER BY device_id, seq",
        )
        .unwrap();
    let rows = stmt
        .query_map([], |r| {
            Ok(format!(
                "seq={} dev={} prev={} ts={} kind={} item={:?} vault={:?} peer={:?} \
                 field={:?} format={:?} count={} detail={:?}",
                r.get::<_, i64>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, String>(2)?,
                r.get::<_, i64>(3)?,
                r.get::<_, i64>(4)?,
                r.get::<_, Option<String>>(5)?,
                r.get::<_, Option<String>>(6)?,
                r.get::<_, Option<String>>(7)?,
                r.get::<_, Option<String>>(8)?,
                r.get::<_, Option<String>>(9)?,
                r.get::<_, i64>(10)?,
                r.get::<_, Option<String>>(11)?,
            ))
        })
        .unwrap();
    rows.map(Result::unwrap).collect::<Vec<_>>().join("\n")
}

/// Count audit rows of a given kind code across the whole table.
fn count_kind(dir: &std::path::Path, kind_code: i64) -> i64 {
    let conn = Connection::open(account_path(dir)).unwrap();
    conn.query_row(
        "SELECT COUNT(*) FROM audit_log WHERE kind = ?1",
        params![kind_code],
        |r| r.get(0),
    )
    .unwrap()
}

/// All audit records for the session's device, oldest first.
fn records(session: &Session) -> Vec<lp_vault::AuditRecord> {
    session.audit_iter().unwrap()
}

// --- Chain integrity ------------------------------------------------------

#[test]
fn mixed_events_verify_and_seq_is_gapless() {
    let dir = TempDir::new().unwrap();
    let (session, _sk) = AccountStore::create(dir.path(), PW).unwrap();
    let vault_id = session.create_vault("v").unwrap();
    let vault = session.open_vault(vault_id).unwrap();

    // A spread of events across kinds.
    let id = vault.create_item(&secret_login()).unwrap(); // ItemCreate
    let mut p = vault.get_item(id).unwrap().payload;
    p.title = "edited".into();
    vault.update_item(id, &p).unwrap(); // ItemUpdate
    vault.record_secret_read(&id, Some("password")).unwrap(); // ItemSecretRead
    session.record_export("age", 1).unwrap(); // Export
    vault.delete_item(id, 1000).unwrap(); // ItemDelete
    vault.restore_version(id, 1).unwrap(); // ItemRestore (revives)

    // The chain verifies and seq is a gapless 1..N.
    session.verify_audit_chain().unwrap();
    let recs = records(&session);
    assert!(
        recs.len() >= 6,
        "expected at least 6 records, got {}",
        recs.len()
    );
    for (i, r) in recs.iter().enumerate() {
        assert_eq!(r.seq, (i as u64) + 1, "seq must be gapless from 1");
    }
}

#[test]
fn genesis_is_correct_for_first_record() {
    let dir = TempDir::new().unwrap();
    let (session, _sk) = AccountStore::create(dir.path(), PW).unwrap();
    // The create did not audit; the first record comes from the first mutation.
    let vault_id = session.create_vault("v").unwrap();
    let vault = session.open_vault(vault_id).unwrap();
    vault.create_item(&secret_login()).unwrap();

    let recs = records(&session);
    let first = &recs[0];
    assert_eq!(first.seq, 1);
    assert_eq!(
        first.prev_hash,
        lp_vault::audit::genesis_hash(&session.device_id()),
        "first record's prev_hash must be the audit genesis"
    );
}

#[test]
fn corrupting_a_record_detail_breaks_verification() {
    let dir = TempDir::new().unwrap();
    let (session, sk) = AccountStore::create(dir.path(), PW).unwrap();
    let vault_id = session.create_vault("v").unwrap();
    let vault = session.open_vault(vault_id).unwrap();
    vault.create_item(&secret_login()).unwrap();
    vault
        .create_item(&ItemPayload::new(TypeData::Note {}, "n"))
        .unwrap();
    session.verify_audit_chain().unwrap();
    drop(vault);
    session.lock();

    // Tamper: flip the timestamp of the first record via raw SQL. The chain hash
    // of record 1 changes, so record 2's prev_hash link no longer matches.
    {
        let conn = Connection::open(account_path(dir.path())).unwrap();
        conn.execute(
            "UPDATE audit_log SET timestamp = timestamp + 1 WHERE seq = 1",
            [],
        )
        .unwrap();
    }

    let session2 = AccountStore::unlock(dir.path(), PW, &sk).unwrap();
    let err = session2.verify_audit_chain().unwrap_err();
    assert!(matches!(err, Error::ChainVerification(_)), "got {err:?}");
}

#[test]
fn deleting_a_middle_record_breaks_seq_gaplessness() {
    let dir = TempDir::new().unwrap();
    let (session, sk) = AccountStore::create(dir.path(), PW).unwrap();
    let vault_id = session.create_vault("v").unwrap();
    let vault = session.open_vault(vault_id).unwrap();
    for _ in 0..3 {
        vault
            .create_item(&ItemPayload::new(TypeData::Note {}, "n"))
            .unwrap();
    }
    drop(vault);
    session.lock();

    // Delete the middle record → a seq gap (1, 3) the verifier must catch.
    {
        let conn = Connection::open(account_path(dir.path())).unwrap();
        conn.execute("DELETE FROM audit_log WHERE seq = 2", [])
            .unwrap();
    }

    let session2 = AccountStore::unlock(dir.path(), PW, &sk).unwrap();
    // The unlock itself appended a fresh UnlockSuccess (seq bumps), but the gap at
    // the deleted position still breaks the chain.
    let err = session2.verify_audit_chain().unwrap_err();
    assert!(matches!(err, Error::ChainVerification(_)), "got {err:?}");
}

// --- Event coverage -------------------------------------------------------

#[test]
fn unlock_success_and_failure_are_logged_and_persist() {
    let dir = TempDir::new().unwrap();
    let (session, sk) = AccountStore::create(dir.path(), PW).unwrap();
    session.lock();

    // A wrong-password unlock logs an UnlockFailure and the record persists.
    let err = AccountStore::unlock(dir.path(), "wrong-password", &sk).unwrap_err();
    assert!(matches!(err, Error::DecryptionFailed));
    assert_eq!(count_kind(dir.path(), 2), 1, "one UnlockFailure recorded");

    // A correct unlock logs an UnlockSuccess.
    let session2 = AccountStore::unlock(dir.path(), PW, &sk).unwrap();
    assert_eq!(count_kind(dir.path(), 1), 1, "one UnlockSuccess recorded");
    // The failure record is still there (append-only).
    assert_eq!(count_kind(dir.path(), 2), 1, "UnlockFailure persisted");
    session2.verify_audit_chain().unwrap();
}

#[test]
fn mutations_log_their_kinds() {
    let dir = TempDir::new().unwrap();
    let (session, _sk) = AccountStore::create(dir.path(), PW).unwrap();
    let vault_id = session.create_vault("v").unwrap();
    let vault = session.open_vault(vault_id).unwrap();

    let id = vault.create_item(&secret_login()).unwrap();
    let mut p = vault.get_item(id).unwrap().payload;
    p.title = "edited".into();
    vault.update_item(id, &p).unwrap();
    vault.delete_item(id, 1000).unwrap();
    vault.restore_version(id, 1).unwrap();

    assert_eq!(count_kind(dir.path(), 4), 1, "ItemCreate");
    assert_eq!(count_kind(dir.path(), 5), 1, "ItemUpdate");
    assert_eq!(count_kind(dir.path(), 6), 1, "ItemDelete");
    assert_eq!(count_kind(dir.path(), 7), 1, "ItemRestore");
}

#[test]
fn secret_read_logs_the_right_item_and_field_with_no_secret() {
    let dir = TempDir::new().unwrap();
    let (session, _sk) = AccountStore::create(dir.path(), PW).unwrap();
    let vault_id = session.create_vault("v").unwrap();
    let vault = session.open_vault(vault_id).unwrap();
    let id = vault.create_item(&secret_login()).unwrap();

    vault.record_secret_read(&id, Some("password")).unwrap();

    let read = records(&session)
        .into_iter()
        .find(|r| matches!(r.kind, AuditKind::ItemSecretRead { .. }))
        .expect("a secret-read record");
    match &read.kind {
        AuditKind::ItemSecretRead {
            item_id,
            vault_id: vid,
            field,
        } => {
            assert_eq!(*item_id, id, "records the read item id");
            assert_eq!(*vid, vault_id, "records the vault id");
            assert_eq!(field.as_deref(), Some("password"), "records the field name");
        }
        other => panic!("wrong kind: {other:?}"),
    }
    // And the secret VALUE is nowhere in the whole table dump.
    let dump = dump_audit_table(dir.path());
    assert!(!dump.contains(SECRET_PW), "secret value must not be logged");
}

#[test]
fn export_logs_format_and_item_count() {
    let dir = TempDir::new().unwrap();
    let (session, _sk) = AccountStore::create(dir.path(), PW).unwrap();
    session.record_export("age", 7).unwrap();

    let rec = records(&session)
        .into_iter()
        .find(|r| matches!(r.kind, AuditKind::Export { .. }))
        .expect("an export record");
    match rec.kind {
        AuditKind::Export { format, item_count } => {
            assert_eq!(format, "age");
            assert_eq!(item_count, 7);
        }
        other => panic!("wrong kind: {other:?}"),
    }
}

#[test]
fn share_and_trust_are_logged() {
    let dir = TempDir::new().unwrap();
    let (session, _sk) = AccountStore::create(dir.path(), PW).unwrap();

    // Trust a fabricated peer → DeviceTrust.
    let peer_id = lp_vault::Id::new();
    session
        .trust_peer_device(&peer_id, &[1u8; 32], &[2u8; 32], Some("laptop"))
        .unwrap();
    assert_eq!(count_kind(dir.path(), 10), 1, "DeviceTrust logged");

    // Share a vault key to that peer → VaultShare.
    let vault_id = session.create_vault("v").unwrap();
    let peer = session.peer_device(&peer_id).unwrap().unwrap();
    let _ = session.share_vault_key_to_peer(&vault_id, &peer);
    assert_eq!(count_kind(dir.path(), 9), 1, "VaultShare logged");
    session.verify_audit_chain().unwrap();
}

#[test]
fn masked_reads_and_list_search_do_not_log_secret_reads() {
    let dir = TempDir::new().unwrap();
    let (session, _sk) = AccountStore::create(dir.path(), PW).unwrap();
    let vault_id = session.create_vault("v").unwrap();
    let vault = session.open_vault(vault_id).unwrap();
    let id = vault.create_item(&secret_login()).unwrap();

    // A plain get (masked), list, search, and history are NOT secret reads: they
    // never call record_secret_read.
    let _ = vault.get_item(id).unwrap();
    let _ = vault.list_items().unwrap();
    let _ = vault.search("ACME", None).unwrap();
    let _ = vault.history(id).unwrap();

    // No ItemSecretRead (kind 3) recorded by any of those.
    assert_eq!(
        count_kind(dir.path(), 3),
        0,
        "masked reads / list / search / history must not log a secret read"
    );
}

// --- Privacy: only non-secret metadata --------------------------------------

#[test]
fn audit_table_holds_ids_but_never_titles_usernames_or_secrets() {
    let dir = TempDir::new().unwrap();
    let (session, _sk) = AccountStore::create(dir.path(), PW).unwrap();
    let vault_id: VaultId = session.create_vault("v").unwrap();
    let vault = session.open_vault(vault_id).unwrap();

    // Exercise every kind that references content.
    let id = vault.create_item(&secret_login()).unwrap();
    let mut p = vault.get_item(id).unwrap().payload;
    p.title = "another secret title".into();
    vault.update_item(id, &p).unwrap();
    vault.record_secret_read(&id, Some("password")).unwrap();
    session.record_export("json", 1).unwrap();

    let dump = dump_audit_table(dir.path());

    // It DOES contain the item id (hex, no hyphens — 32 hex chars).
    let item_hex: String = id.as_bytes().iter().map(|b| format!("{b:02X}")).collect();
    assert!(
        dump.to_uppercase().contains(&item_hex),
        "audit log should contain the item id"
    );

    // It must NOT contain the title, username, password, or the field VALUE.
    assert!(!dump.contains(SECRET_PW), "no password value");
    assert!(!dump.contains(USERNAME), "no username");
    assert!(!dump.contains(TITLE), "no title");
    assert!(!dump.contains("another secret title"), "no edited title");
}

// --- Atomicity ------------------------------------------------------------

#[test]
fn a_failed_item_write_leaves_no_orphan_audit_record() {
    let dir = TempDir::new().unwrap();
    let (session, _sk) = AccountStore::create(dir.path(), PW).unwrap();
    let vault_id = session.create_vault("v").unwrap();
    let vault = session.open_vault(vault_id).unwrap();

    let before = count_kind(dir.path(), 5); // ItemUpdate count

    // An update of a NONEXISTENT item fails before any commit — no audit record.
    let missing = lp_vault::Id::new();
    let err = vault
        .update_item(missing, &ItemPayload::new(TypeData::Note {}, "x"))
        .unwrap_err();
    assert!(matches!(err, Error::NotFound(_)), "got {err:?}");

    let after = count_kind(dir.path(), 5);
    assert_eq!(
        before, after,
        "a failed update must not append an audit record"
    );

    // Likewise, deleting a nonexistent item logs nothing.
    let del_before = count_kind(dir.path(), 6);
    assert!(vault.delete_item(missing, 1000).is_err());
    assert_eq!(
        count_kind(dir.path(), 6),
        del_before,
        "no orphan ItemDelete"
    );
}

#[test]
fn chain_survives_reopen_and_keeps_growing() {
    let dir = TempDir::new().unwrap();
    let (session, sk) = AccountStore::create(dir.path(), PW).unwrap();
    let vault_id = session.create_vault("v").unwrap();
    {
        let vault = session.open_vault(vault_id).unwrap();
        vault
            .create_item(&ItemPayload::new(TypeData::Note {}, "a"))
            .unwrap();
    }
    let n1 = records(&session).len();
    session.lock();

    // Re-unlock (adds an UnlockSuccess), add more, and re-verify the whole chain.
    let session2 = AccountStore::unlock(dir.path(), PW, &sk).unwrap();
    let vault2 = session2.open_vault(vault_id).unwrap();
    vault2
        .create_item(&ItemPayload::new(TypeData::Note {}, "b"))
        .unwrap();
    let n2 = records(&session2).len();
    assert!(n2 > n1, "chain kept growing across a reopen ({n1} -> {n2})");
    session2.verify_audit_chain().unwrap();
}
