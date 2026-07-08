//! Integration tests for encrypted file attachments (`lp-vault`,
//! vault-format.md §8).
//!
//! Each test uses an isolated `tempfile` profile and exercises the real
//! create/unlock cost, so they are kept lean. They verify the round-trip, the
//! on-disk-is-ciphertext invariant (the critical security property), the AAD
//! binding (anti-cut-and-paste), the size cap, dedup-safe deletion, and
//! lock/unlock persistence.

use lp_vault::payload::{ItemPayload, TypeData};
use lp_vault::{AccountStore, Session, VaultId};
use rusqlite::{Connection, params};
use tempfile::TempDir;

const PASSWORD: &str = "correct horse battery staple";

/// Create an account + a "personal" vault + one note item, returning the temp
/// dir (kept alive), the session, the vault id, and the item id.
fn setup() -> (TempDir, Session, VaultId, lp_vault::ItemId) {
    let dir = TempDir::new().unwrap();
    let (session, _sk) = AccountStore::create(dir.path(), PASSWORD).unwrap();
    let vault_id = session.create_vault("personal").unwrap();
    let item_id = {
        let vault = session.open_vault(vault_id).unwrap();
        vault
            .create_item(&ItemPayload::new(TypeData::Note {}, "holder"))
            .unwrap()
    };
    (dir, session, vault_id, item_id)
}

/// The per-vault attachments directory of a profile.
fn attachments_dir(profile: &std::path::Path, vault_id: &VaultId) -> std::path::PathBuf {
    profile.join("attachments").join(vault_id.to_hyphenated())
}

/// The vault file path.
fn vault_path(profile: &std::path::Path, vault_id: &VaultId) -> std::path::PathBuf {
    profile
        .join("vaults")
        .join(format!("{}.vault", vault_id.to_hyphenated()))
}

#[test]
fn round_trip_bytes_and_filename() {
    let (_dir, session, vault_id, item_id) = setup();
    let vault = session.open_vault(vault_id).unwrap();

    let data = b"-----BEGIN CERTIFICATE-----\nMIIB...binary\x00\x01\x02payload\n";
    let id = vault.add_attachment(item_id, "server.pem", data).unwrap();

    let (name, out) = vault.get_attachment(id).unwrap();
    assert_eq!(name, "server.pem");
    assert_eq!(out, data, "get must return byte-identical plaintext");
}

#[test]
fn multiple_attachments_list_with_names_and_sizes() {
    let (_dir, session, vault_id, item_id) = setup();
    let vault = session.open_vault(vault_id).unwrap();

    vault.add_attachment(item_id, "a.txt", b"aaaa").unwrap();
    vault
        .add_attachment(item_id, "b.json", b"{\"k\":1}")
        .unwrap();
    vault.add_attachment(item_id, "c.bin", &[0u8; 100]).unwrap();

    let mut list = vault.list_attachments(item_id).unwrap();
    assert_eq!(list.len(), 3);
    list.sort_by(|x, y| x.filename.cmp(&y.filename));
    assert_eq!(list[0].filename, "a.txt");
    assert_eq!(list[0].size_plain, 4);
    assert_eq!(list[1].filename, "b.json");
    assert_eq!(list[1].size_plain, 7);
    assert_eq!(list[2].filename, "c.bin");
    assert_eq!(list[2].size_plain, 100);
}

/// CRITICAL: nothing on disk under the attachments dir may contain the
/// plaintext marker or the filename, and the blob file name equals the BLAKE3
/// hex of its bytes (content-addressed).
#[test]
fn on_disk_is_ciphertext_and_content_addressed() {
    let (dir, session, vault_id, item_id) = setup();
    let vault = session.open_vault(vault_id).unwrap();

    let marker = b"TOPSECRET-PLAINTEXT-MARKER-42";
    let filename = "very-secret-filename.key";
    vault.add_attachment(item_id, filename, marker).unwrap();

    let att_dir = attachments_dir(dir.path(), &vault_id);
    let mut blob_files = Vec::new();
    for entry in std::fs::read_dir(&att_dir).unwrap() {
        let path = entry.unwrap().path();
        if path.extension().and_then(|e| e.to_str()) == Some("blob") {
            blob_files.push(path);
        }
    }
    assert_eq!(blob_files.len(), 1, "exactly one blob on disk");

    // The blob's on-disk name equals BLAKE3(ciphertext) hex.
    let bytes = std::fs::read(&blob_files[0]).unwrap();
    let expected_hex = {
        let h = lp_crypto::blake3_256(&bytes);
        let mut s = String::new();
        for b in h {
            s.push_str(&format!("{b:02x}"));
        }
        s
    };
    let stem = blob_files[0].file_stem().unwrap().to_str().unwrap();
    assert_eq!(stem, expected_hex, "blob name is BLAKE3 hex of its bytes");

    // No plaintext marker and no filename anywhere under the attachments dir.
    for entry in std::fs::read_dir(&att_dir).unwrap() {
        let path = entry.unwrap().path();
        let contents = std::fs::read(&path).unwrap();
        assert!(
            !contains_subslice(&contents, marker),
            "plaintext marker must not appear on disk"
        );
        assert!(
            !contains_subslice(&contents, filename.as_bytes()),
            "filename must not appear in plaintext on disk"
        );
    }
}

/// AAD binding: copying a wrapped_key_env / filename_env onto a DIFFERENT
/// attachment row (raw SQLite) makes `get` fail closed.
#[test]
fn aad_binding_rejects_relocated_rows() {
    let (dir, session, vault_id, item_id) = setup();
    let vault = session.open_vault(vault_id).unwrap();

    let a = vault
        .add_attachment(item_id, "a.txt", b"alpha data")
        .unwrap();
    let b = vault
        .add_attachment(item_id, "b.txt", b"bravo data")
        .unwrap();
    drop(vault);

    // Overwrite b's wrapped_key_env + filename_env with a's (raw SQLite).
    let vpath = vault_path(dir.path(), &vault_id);
    let conn = Connection::open(&vpath).unwrap();
    let (a_key, a_name): (Vec<u8>, Vec<u8>) = conn
        .query_row(
            "SELECT wrapped_key_env, filename_env FROM attachments WHERE attachment_id = ?1",
            params![a.to_vec()],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .unwrap();
    conn.execute(
        "UPDATE attachments SET wrapped_key_env = ?1, filename_env = ?2 WHERE attachment_id = ?3",
        params![a_key, a_name, b.to_vec()],
    )
    .unwrap();
    drop(conn);

    let vault = session.open_vault(vault_id).unwrap();
    // b now carries a's wrapped key + filename, but the blob AAD binds b's id →
    // the per-attachment key unwraps under the WRONG attachment AAD → fail closed.
    let err = vault.get_attachment(b).unwrap_err();
    assert!(
        matches!(err, lp_vault::Error::DecryptionFailed),
        "relocated row must fail closed as DecryptionFailed, got {err:?}"
    );
    // a itself is unaffected.
    assert_eq!(vault.get_attachment(a).unwrap().1, b"alpha data");
}

/// A single-byte flip in the on-disk blob makes `get` fail closed.
#[test]
fn tampered_blob_fails_closed() {
    let (dir, session, vault_id, item_id) = setup();
    let vault = session.open_vault(vault_id).unwrap();
    let id = vault
        .add_attachment(item_id, "x.bin", b"some content here")
        .unwrap();
    drop(vault);

    let att_dir = attachments_dir(dir.path(), &vault_id);
    let blob = std::fs::read_dir(&att_dir)
        .unwrap()
        .map(|e| e.unwrap().path())
        .find(|p| p.extension().and_then(|e| e.to_str()) == Some("blob"))
        .unwrap();
    let mut bytes = std::fs::read(&blob).unwrap();
    let last = bytes.len() - 1;
    bytes[last] ^= 0x01;
    std::fs::write(&blob, &bytes).unwrap();

    let vault = session.open_vault(vault_id).unwrap();
    let err = vault.get_attachment(id).unwrap_err();
    assert!(
        matches!(err, lp_vault::Error::DecryptionFailed),
        "tampered blob must fail closed, got {err:?}"
    );
}

/// Size cap: data at the cap succeeds; data over the cap is rejected before any
/// blob is written. Uses the `LP_MAX_ATTACHMENT_BYTES` test override to exercise
/// the boundary without materializing 50 MiB. This test runs single-threaded to
/// avoid the process-global env var perturbing concurrent tests — see the
/// `#[serial]`-free note below (we simply pick a cap larger than any other
/// test's payload, and set/clear it within this test).
#[test]
fn size_cap_enforced_before_writing_blob() {
    const TEST_CAP: usize = 64 * 1024;
    // SAFETY: env var is process-global; other tests in this file use tiny
    // payloads (< 1 KiB) far below TEST_CAP, so a temporarily-lowered cap does
    // not affect them even under parallel execution.
    unsafe {
        std::env::set_var("LP_MAX_ATTACHMENT_BYTES", TEST_CAP.to_string());
    }

    let (dir, session, vault_id, item_id) = setup();
    let vault = session.open_vault(vault_id).unwrap();

    // At the cap: succeeds.
    let at_cap = vec![7u8; TEST_CAP];
    let id = vault.add_attachment(item_id, "big.bin", &at_cap).unwrap();
    assert_eq!(vault.get_attachment(id).unwrap().1.len(), TEST_CAP);

    // Over the cap: rejected, and NO new blob is written.
    let att_dir = attachments_dir(dir.path(), &vault_id);
    let before = std::fs::read_dir(&att_dir).unwrap().count();
    let over = vec![7u8; TEST_CAP + 1];
    let err = vault
        .add_attachment(item_id, "toobig.bin", &over)
        .unwrap_err();
    assert!(
        matches!(err, lp_vault::Error::Invalid(_)),
        "over-cap must be Invalid, got {err:?}"
    );
    let after = std::fs::read_dir(&att_dir).unwrap().count();
    assert_eq!(before, after, "no blob written for an over-cap attachment");

    unsafe {
        std::env::remove_var("LP_MAX_ATTACHMENT_BYTES");
    }
}

/// delete_attachment removes the row + blob; a second attachment with DIFFERENT
/// content is unaffected.
#[test]
fn delete_removes_row_and_blob_leaving_others() {
    let (dir, session, vault_id, item_id) = setup();
    let vault = session.open_vault(vault_id).unwrap();

    let a = vault.add_attachment(item_id, "a.txt", b"alpha").unwrap();
    let b = vault.add_attachment(item_id, "b.txt", b"bravo").unwrap();
    let att_dir = attachments_dir(dir.path(), &vault_id);
    assert_eq!(count_blobs(&att_dir), 2);

    vault.delete_attachment(a).unwrap();
    assert!(vault.get_attachment(a).is_err());
    assert_eq!(count_blobs(&att_dir), 1, "one blob removed");
    // b is fully intact.
    assert_eq!(vault.get_attachment(b).unwrap().1, b"bravo");
    assert_eq!(vault.list_attachments(item_id).unwrap().len(), 1);
}

/// Dedup: two attachments whose ciphertext hash differs are independent, but
/// deleting one never removes a blob another row references. (We assert the
/// dedup-safe delete path by pointing two rows at the same content_hash via a
/// second identical add is not possible since keys are random — so we verify the
/// reference check keeps the blob while a sibling references it, using raw SQL.)
#[test]
fn delete_is_dedup_safe() {
    let (dir, session, vault_id, item_id) = setup();
    let vault = session.open_vault(vault_id).unwrap();
    let a = vault
        .add_attachment(item_id, "a.txt", b"same-bytes")
        .unwrap();
    drop(vault);

    // Forge a second row referencing the SAME content_hash as `a` (a dedup
    // sibling). Deleting `a` must NOT unlink the shared blob.
    let vpath = vault_path(dir.path(), &vault_id);
    let conn = Connection::open(&vpath).unwrap();
    let (hash, ver, wk, fe): (Vec<u8>, i64, Vec<u8>, Vec<u8>) = conn
        .query_row(
            "SELECT content_hash, version, wrapped_key_env, filename_env
               FROM attachments WHERE attachment_id = ?1",
            params![a.to_vec()],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
        )
        .unwrap();
    let sibling = lp_vault::Id::new();
    conn.execute(
        "INSERT INTO attachments
            (attachment_id, item_id, version, content_hash, size_plain,
             wrapped_key_env, filename_env, created_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, 0)",
        params![
            sibling.to_vec(),
            item_id.to_vec(),
            ver,
            hash,
            10_i64,
            wk,
            fe,
        ],
    )
    .unwrap();
    drop(conn);

    let att_dir = attachments_dir(dir.path(), &vault_id);
    assert_eq!(count_blobs(&att_dir), 1);

    let vault = session.open_vault(vault_id).unwrap();
    vault.delete_attachment(a).unwrap();
    // The blob is still on disk because the sibling row references it.
    assert_eq!(
        count_blobs(&att_dir),
        1,
        "dedup-referenced blob must survive deletion of one row"
    );
}

/// Attachments added in one session are gettable after re-unlock (keys
/// reconstruct correctly).
#[test]
fn attachments_survive_lock_unlock() {
    let dir = TempDir::new().unwrap();
    let (session, sk) = AccountStore::create(dir.path(), PASSWORD).unwrap();
    let vault_id = session.create_vault("personal").unwrap();
    let (item_id, att_id) = {
        let vault = session.open_vault(vault_id).unwrap();
        let item_id = vault
            .create_item(&ItemPayload::new(TypeData::Note {}, "holder"))
            .unwrap();
        let att_id = vault
            .add_attachment(item_id, "secret.key", b"persisted-bytes")
            .unwrap();
        (item_id, att_id)
    };
    session.lock();

    let session2 = AccountStore::unlock(dir.path(), PASSWORD, &sk).unwrap();
    let vault2 = session2.open_vault(vault_id).unwrap();
    let (name, data) = vault2.get_attachment(att_id).unwrap();
    assert_eq!(name, "secret.key");
    assert_eq!(data, b"persisted-bytes");
    assert_eq!(vault2.list_attachments(item_id).unwrap().len(), 1);
}

/// Item trash interaction: an attachment stays retrievable while its item is
/// trashed (the item + version rows linger until purge), and only becomes
/// unreadable once the item is purged (the wrapped_keys row is shredded, so the
/// ItemKey — and thus the attachment key — can no longer be reconstructed).
#[test]
fn attachment_retrievable_until_item_purged() {
    let (_dir, session, vault_id, item_id) = setup();
    let vault = session.open_vault(vault_id).unwrap();
    let att = vault.add_attachment(item_id, "f.txt", b"payload").unwrap();

    // Trash the item: the attachment is STILL retrievable (rows linger).
    vault.delete_item(item_id, 30 * 24 * 3600 * 1000).unwrap();
    assert_eq!(
        vault.get_attachment(att).unwrap().1,
        b"payload",
        "attachment retrievable while item is in trash"
    );

    // Purge the item: its wrapped_keys are shredded, so the ItemKey is gone and
    // the attachment can no longer be decrypted (fails closed).
    let purged = vault.purge_expired_trash(i64::MAX / 2).unwrap();
    assert_eq!(purged, 1);
    let err = vault.get_attachment(att).unwrap_err();
    assert!(
        matches!(
            err,
            lp_vault::Error::NotFound(_) | lp_vault::Error::DecryptionFailed
        ),
        "after purge the attachment key cannot be reconstructed, got {err:?}"
    );
}

/// Adding/getting/deleting attachments does NOT author ops (local-only in this
/// wave) and leaves the op chain intact.
#[test]
fn attachments_do_not_touch_op_chain() {
    let (dir, session, vault_id, item_id) = setup();
    let vault = session.open_vault(vault_id).unwrap();

    // op count after item create (1 create op).
    let vpath = vault_path(dir.path(), &vault_id);
    let ops_before: i64 = {
        let conn = Connection::open(&vpath).unwrap();
        conn.query_row("SELECT COUNT(*) FROM ops", [], |r| r.get(0))
            .unwrap()
    };

    let a = vault.add_attachment(item_id, "a.txt", b"aaa").unwrap();
    vault.get_attachment(a).unwrap();
    vault.delete_attachment(a).unwrap();

    let ops_after: i64 = {
        let conn = Connection::open(&vpath).unwrap();
        conn.query_row("SELECT COUNT(*) FROM ops", [], |r| r.get(0))
            .unwrap()
    };
    assert_eq!(ops_before, ops_after, "attachments must not author ops");
    vault.verify_local_chain().unwrap();
}

// --- helpers --------------------------------------------------------------

fn count_blobs(dir: &std::path::Path) -> usize {
    std::fs::read_dir(dir)
        .map(|rd| {
            rd.filter_map(|e| e.ok())
                .filter(|e| e.path().extension().and_then(|x| x.to_str()) == Some("blob"))
                .count()
        })
        .unwrap_or(0)
}

fn contains_subslice(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() || haystack.len() < needle.len() {
        return false;
    }
    haystack.windows(needle.len()).any(|w| w == needle)
}
