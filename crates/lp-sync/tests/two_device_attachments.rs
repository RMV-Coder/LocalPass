//! Two-device attachment sync round-trip (sync-protocol.md §2/§7) with REAL
//! profiles. Device A attaches a file to a synced item and pushes; device B
//! pulls and gets both the AttachAdd op (metadata) AND the fetched+verified
//! blob, reading byte-identical file bytes. Then A deletes the attachment and B
//! pulls it gone. Also covers the tamper alarm (a flipped byte in the shipped
//! blob fails B's hash check) and the pending-not-error path (a referenced blob
//! missing from the channel is reported pending, and a later pull completes it).
//!
//! Two `AccountStore::create` calls run the real Argon2id KDF, so the whole flow
//! lives in one test function to amortize the cost.

use lp_sync::engine;
use lp_vault::AccountStore;
use lp_vault::payload::{ItemPayload, TypeData};

const ATTACH_BYTES: &[u8] = b"-----BEGIN CERTIFICATE-----\nMIIB..\x00\x01\x02 secret bytes\n";

#[test]
fn attachment_syncs_add_delete_tamper_and_pending() {
    // Device A: account + vault + one item.
    let dir_a = tempfile::tempdir().unwrap();
    let (session_a, _sk_a) = AccountStore::create(dir_a.path(), "pw-device-a").unwrap();
    let vault_id = session_a.create_vault("shared").unwrap();
    let item_id = {
        let vault_a = session_a.open_vault(vault_id).unwrap();
        vault_a
            .create_item(&ItemPayload::new(TypeData::Note {}, "holder"))
            .unwrap()
    };

    // Device B: its own account world.
    let dir_b = tempfile::tempdir().unwrap();
    let (session_b, _sk_b) = AccountStore::create(dir_b.path(), "pw-device-b").unwrap();

    // Mutual trust (sync-protocol.md §6).
    let ident_a = session_a.device_public_identity();
    let ident_b = session_b.device_public_identity();
    session_a
        .trust_peer_device(
            &ident_b.device_id,
            &ident_b.ed25519_pub,
            &ident_b.x25519_pub,
            Some("device-b"),
        )
        .unwrap();
    session_b
        .trust_peer_device(
            &ident_a.device_id,
            &ident_a.ed25519_pub,
            &ident_a.x25519_pub,
            Some("device-a"),
        )
        .unwrap();

    // A enrolls, pushes the item, and shares the VaultKey to B.
    let root = tempfile::tempdir().unwrap();
    engine::setup(&session_a, vault_id, root.path()).unwrap();
    {
        let vault_a = session_a.open_vault(vault_id).unwrap();
        engine::push(&session_a, &vault_a).unwrap();
    }
    engine::share_vault_to_device(&session_a, vault_id, &ident_b.device_id).unwrap();

    // B adopts + pulls: it materializes the item (no attachment yet).
    engine::adopt(&session_b, root.path()).unwrap();
    let vault_b = session_b.open_vault(vault_id).unwrap();
    engine::pull(&session_b, &vault_b).unwrap();

    // --- A attaches a file and pushes (metadata op + blob) ------------------
    let att_id = {
        let vault_a = session_a.open_vault(vault_id).unwrap();
        let att = vault_a
            .add_attachment(item_id, "server.pem", ATTACH_BYTES)
            .unwrap();
        let push = engine::push(&session_a, &vault_a).unwrap();
        assert_eq!(push.attachments_shipped, 1, "A ships one blob");
        att
    };

    // B pulls: gets the AttachAdd op (metadata) AND fetches+verifies the blob.
    let report = engine::pull(&session_b, &vault_b).unwrap();
    assert!(!report.has_alarms(), "clean pull, no alarms");
    assert_eq!(report.attachments_fetched, 1, "B fetched + verified 1 blob");
    assert_eq!(report.attachments_pending, 0);

    // B can now read the attachment bytes — identical to A's.
    let (name, bytes) = vault_b.get_attachment(att_id).unwrap();
    assert_eq!(name, "server.pem");
    assert_eq!(bytes, ATTACH_BYTES, "B reads byte-identical attachment");
    assert_eq!(vault_b.list_attachments(item_id).unwrap().len(), 1);

    // A pull that re-fetches nothing (already local) is a clean no-op.
    let again = engine::pull(&session_b, &vault_b).unwrap();
    assert_eq!(again.attachments_fetched, 0);
    assert_eq!(again.attachments_pending, 0);
    assert!(!again.has_alarms());
    vault_b.verify_local_chain().unwrap();

    // --- A deletes the attachment; B pulls it gone --------------------------
    {
        let vault_a = session_a.open_vault(vault_id).unwrap();
        vault_a.delete_attachment(att_id).unwrap();
        engine::push(&session_a, &vault_a).unwrap();
    }
    let del = engine::pull(&session_b, &vault_b).unwrap();
    assert!(!del.has_alarms());
    assert!(
        vault_b.get_attachment(att_id).is_err(),
        "attachment gone on B after delete syncs"
    );
    assert!(vault_b.list_attachments(item_id).unwrap().is_empty());

    // ========================================================================
    // Tamper: a flipped byte in a shipped blob fails B's hash check (alarm).
    // ========================================================================
    let dir_c = tempfile::tempdir().unwrap();
    let (session_c, _sk_c) = AccountStore::create(dir_c.path(), "pw-device-c").unwrap();
    let ident_c = session_c.device_public_identity();
    session_a
        .trust_peer_device(
            &ident_c.device_id,
            &ident_c.ed25519_pub,
            &ident_c.x25519_pub,
            Some("device-c"),
        )
        .unwrap();
    session_c
        .trust_peer_device(
            &ident_a.device_id,
            &ident_a.ed25519_pub,
            &ident_a.x25519_pub,
            Some("device-a"),
        )
        .unwrap();
    engine::share_vault_to_device(&session_a, vault_id, &ident_c.device_id).unwrap();
    engine::adopt(&session_c, root.path()).unwrap();
    let vault_c = session_c.open_vault(vault_id).unwrap();
    engine::pull(&session_c, &vault_c).unwrap();

    // A attaches a fresh file and pushes.
    let att2 = {
        let vault_a = session_a.open_vault(vault_id).unwrap();
        let att = vault_a
            .add_attachment(item_id, "second.bin", b"another-secret-body")
            .unwrap();
        engine::push(&session_a, &vault_a).unwrap();
        att
    };

    // Target att2's SPECIFIC shipped blob (the channel also still holds the
    // earlier deleted attachment's blob — push never GCs). Its content hash is
    // A's single live attachment hash (att1 was deleted on A).
    let att2_hash = {
        let vault_a = session_a.open_vault(vault_id).unwrap();
        let mut refd = vault_a.referenced_attachment_hashes().unwrap();
        refd.sort();
        assert_eq!(refd.len(), 1, "A has exactly att2 live");
        refd.pop().unwrap()
    };
    let attach_dir = root
        .path()
        .join(vault_id.to_hyphenated())
        .join("attachments");
    let blob_path = attach_dir.join(format!("{att2_hash}.blob"));
    {
        let mut b = std::fs::read(&blob_path).unwrap();
        let last = b.len() - 1;
        b[last] ^= 0x01;
        std::fs::write(&blob_path, &b).unwrap();
    }

    // C pulls: the op (metadata) applies, but the tampered blob fails the hash
    // check → ALARM (surfaced), not silently accepted, and the attachment stays
    // pending (bad bytes never stored).
    let tampered = engine::pull(&session_c, &vault_c).unwrap();
    assert!(tampered.has_alarms(), "tampered blob must raise an alarm");
    assert_eq!(tampered.attachments_tampered.len(), 1);
    assert_eq!(tampered.attachments_fetched, 0, "bad bytes never stored");
    assert!(
        vault_c.get_attachment(att2).is_err(),
        "attachment unreadable while its blob is rejected"
    );

    // ========================================================================
    // Pending-not-error: restore the good blob, but first prove that a
    // referenced-but-absent blob is reported pending (no error). We remove the
    // (tampered) blob entirely to simulate "peer hasn't shipped it yet".
    // ========================================================================
    std::fs::remove_file(&blob_path).unwrap();
    let pending = engine::pull(&session_c, &vault_c).unwrap();
    assert!(!pending.has_alarms(), "a missing blob is NOT an alarm");
    assert_eq!(pending.attachments_pending, 1, "referenced blob is pending");
    assert_eq!(pending.attachments_fetched, 0);

    // A re-pushes the correct blob; a later pull completes the attachment.
    {
        let vault_a = session_a.open_vault(vault_id).unwrap();
        engine::push(&session_a, &vault_a).unwrap();
    }
    let completed = engine::pull(&session_c, &vault_c).unwrap();
    assert!(!completed.has_alarms());
    assert_eq!(
        completed.attachments_fetched, 1,
        "blob arrives on a later pull"
    );
    assert_eq!(completed.attachments_pending, 0);
    assert_eq!(
        vault_c.get_attachment(att2).unwrap().1,
        b"another-secret-body",
        "C reads the attachment once its blob arrives"
    );
    vault_c.verify_local_chain().unwrap();
}
