//! End-to-end round-trip and merge-scenario tests through the file-shipping
//! engine (sync-protocol.md §4/§7): a peer publishes ops to a shared sync dir;
//! the local vault verifies, merges, and applies them; concurrent conflicts
//! preserve losers; delete-vs-edit keeps the item; and the local chain still
//! verifies afterwards.

mod common;

use lp_sync::engine;
use lp_sync::shipping::SyncDir;
use lp_sync::store::FsStoreFactory;
use lp_vault::op::OpKind;
use lp_vault::{Id, StoredOp};

use common::{PeerDevice, login, new_vault};

/// Publish a peer's contiguous op run into the vault's sync dir as a segment,
/// so a subsequent `pull` discovers it (simulates the peer's `push`).
fn publish(sync_root: &std::path::Path, vault_id: lp_vault::VaultId, ops: &[StoredOp]) {
    let dir = SyncDir::open(sync_root, vault_id).unwrap();
    dir.write_segment(ops).unwrap();
}

#[test]
fn peer_create_syncs_into_local_vault() {
    let tv = new_vault();
    let sync_root = tempfile::tempdir().unwrap();
    engine::setup(
        &tv.session,
        tv.vault_id,
        &sync_root.path().to_string_lossy(),
        &FsStoreFactory,
    )
    .unwrap();

    // A trusted peer creates an item and publishes it.
    let mut peer = PeerDevice::new();
    peer.trust_in(&tv.session);
    let item = Id::new();
    let op = {
        let vault = tv.session.open_vault(tv.vault_id).unwrap();
        peer.snapshot(
            &vault,
            OpKind::Create,
            item,
            1,
            1,
            &login("prod db", "hello"),
        )
    };
    publish(sync_root.path(), tv.vault_id, &[op]);

    // Pull applies it.
    let vault = tv.session.open_vault(tv.vault_id).unwrap();
    let report = engine::pull(&tv.session, &vault, &FsStoreFactory).unwrap();
    assert_eq!(report.applied, 1);
    assert!(!report.has_alarms());

    // The item is now readable in the local vault.
    let got = vault.get_item(item).unwrap();
    assert_eq!(got.payload.title, "prod db");

    // The local op chain still verifies (foreign ops did not corrupt it).
    vault.verify_local_chain().unwrap();
}

#[test]
fn pull_is_idempotent() {
    let tv = new_vault();
    let sync_root = tempfile::tempdir().unwrap();
    engine::setup(
        &tv.session,
        tv.vault_id,
        &sync_root.path().to_string_lossy(),
        &FsStoreFactory,
    )
    .unwrap();

    let mut peer = PeerDevice::new();
    peer.trust_in(&tv.session);
    let item = Id::new();
    let op = {
        let vault = tv.session.open_vault(tv.vault_id).unwrap();
        peer.snapshot(&vault, OpKind::Create, item, 1, 1, &login("x", "v1"))
    };
    publish(sync_root.path(), tv.vault_id, &[op]);

    let vault = tv.session.open_vault(tv.vault_id).unwrap();
    let first = engine::pull(&tv.session, &vault, &FsStoreFactory).unwrap();
    assert_eq!(first.applied, 1);
    // Second pull re-reads the same segment: nothing new applied.
    let second = engine::pull(&tv.session, &vault, &FsStoreFactory).unwrap();
    assert_eq!(second.applied, 0);
    assert_eq!(second.skipped, 1);
    vault.verify_local_chain().unwrap();
}

#[test]
fn concurrent_same_field_edit_keeps_winner_and_preserves_loser() {
    let tv = new_vault();
    let sync_root = tempfile::tempdir().unwrap();
    engine::setup(
        &tv.session,
        tv.vault_id,
        &sync_root.path().to_string_lossy(),
        &FsStoreFactory,
    )
    .unwrap();

    let mut a = PeerDevice::new();
    let mut b = PeerDevice::new();
    a.trust_in(&tv.session);
    b.trust_in(&tv.session);

    let item = Id::new();
    let (create, edit_a, edit_b) = {
        let vault = tv.session.open_vault(tv.vault_id).unwrap();
        let create = a.snapshot(&vault, OpKind::Create, item, 1, 1, &login("item", "base"));
        // Two CONCURRENT edits at the SAME lamport (2) from different devices,
        // both setting the same field to different values.
        let edit_a = a.snapshot(&vault, OpKind::Update, item, 2, 2, &login("item", "from-A"));
        let edit_b = b.snapshot(&vault, OpKind::Update, item, 1, 2, &login("item", "from-B"));
        (create, edit_a, edit_b)
    };
    publish(sync_root.path(), tv.vault_id, &[create, edit_a]);
    publish(sync_root.path(), tv.vault_id, std::slice::from_ref(&edit_b));

    let vault = tv.session.open_vault(tv.vault_id).unwrap();
    let report = engine::pull(&tv.session, &vault, &FsStoreFactory).unwrap();
    assert!(!report.has_alarms());

    // Winner = greater (lamport, device_id). Both edits are lamport 2, so the
    // greater device_id wins.
    let a_wins = a.device_id.as_bytes() > b.device_id.as_bytes();
    let expected_winner = if a_wins { "from-A" } else { "from-B" };
    let loser_value = if a_wins { "from-B" } else { "from-A" };

    let head = vault.get_item(item).unwrap();
    let field = head
        .payload
        .fields
        .iter()
        .find(|f| f.name == "note")
        .unwrap();
    assert_eq!(
        field.value,
        serde_json::Value::String(expected_winner.into())
    );

    // The loser is preserved as a real version (nothing discarded, §4.2).
    let history = vault.history(item).unwrap();
    assert_eq!(history.len(), 3, "create + both edits are all retained");
    let loser_survives = history.iter().any(|v| {
        v.payload
            .fields
            .iter()
            .any(|f| f.value == serde_json::Value::String(loser_value.into()))
    });
    assert!(
        loser_survives,
        "the conflict loser must survive as a version"
    );

    vault.verify_local_chain().unwrap();
}

#[test]
fn concurrent_delete_vs_edit_keeps_the_item() {
    let tv = new_vault();
    let sync_root = tempfile::tempdir().unwrap();
    engine::setup(
        &tv.session,
        tv.vault_id,
        &sync_root.path().to_string_lossy(),
        &FsStoreFactory,
    )
    .unwrap();

    let mut a = PeerDevice::new();
    let mut b = PeerDevice::new();
    a.trust_in(&tv.session);
    b.trust_in(&tv.session);

    let item = Id::new();
    let (create, edit, delete) = {
        let vault = tv.session.open_vault(tv.vault_id).unwrap();
        let create = a.snapshot(&vault, OpKind::Create, item, 1, 1, &login("keep me", "v1"));
        // Concurrent (same lamport 2): A edits, B deletes → edit wins (§4.3).
        let edit = a.snapshot(&vault, OpKind::Update, item, 2, 2, &login("keep me", "v2"));
        let delete = b.delete(&vault, item, 2);
        (create, edit, delete)
    };
    publish(sync_root.path(), tv.vault_id, &[create, edit]);
    publish(sync_root.path(), tv.vault_id, &[delete]);

    let vault = tv.session.open_vault(tv.vault_id).unwrap();
    engine::pull(&tv.session, &vault, &FsStoreFactory).unwrap();

    // Edit-wins: the item survives and is readable (not tombstoned).
    let got = vault.get_item(item).unwrap();
    assert_eq!(got.payload.title, "keep me");
    vault.verify_local_chain().unwrap();
}

#[test]
fn causal_update_after_delete_revives_item() {
    let tv = new_vault();
    let sync_root = tempfile::tempdir().unwrap();
    engine::setup(
        &tv.session,
        tv.vault_id,
        &sync_root.path().to_string_lossy(),
        &FsStoreFactory,
    )
    .unwrap();

    let mut a = PeerDevice::new();
    a.trust_in(&tv.session);
    let item = Id::new();
    let ops = {
        let vault = tv.session.open_vault(tv.vault_id).unwrap();
        let create = a.snapshot(&vault, OpKind::Create, item, 1, 1, &login("t", "v1"));
        let delete = a.delete(&vault, item, 2);
        // A later (higher-lamport, causally-after) update revives the item.
        let update = a.snapshot(&vault, OpKind::Update, item, 2, 3, &login("t", "revived"));
        vec![create, delete, update]
    };
    publish(sync_root.path(), tv.vault_id, &ops);

    let vault = tv.session.open_vault(tv.vault_id).unwrap();
    engine::pull(&tv.session, &vault, &FsStoreFactory).unwrap();

    let got = vault.get_item(item).unwrap();
    let field = got
        .payload
        .fields
        .iter()
        .find(|f| f.name == "note")
        .unwrap();
    assert_eq!(field.value, serde_json::Value::String("revived".into()));
}

#[test]
fn causal_delete_after_update_stays_deleted() {
    let tv = new_vault();
    let sync_root = tempfile::tempdir().unwrap();
    engine::setup(
        &tv.session,
        tv.vault_id,
        &sync_root.path().to_string_lossy(),
        &FsStoreFactory,
    )
    .unwrap();

    let mut a = PeerDevice::new();
    a.trust_in(&tv.session);
    let item = Id::new();
    let ops = {
        let vault = tv.session.open_vault(tv.vault_id).unwrap();
        let create = a.snapshot(&vault, OpKind::Create, item, 1, 1, &login("t", "v1"));
        let update = a.snapshot(&vault, OpKind::Update, item, 2, 2, &login("t", "v2"));
        // A later delete (causally after every edit) tombstones the item.
        let delete = a.delete(&vault, item, 3);
        vec![create, update, delete]
    };
    publish(sync_root.path(), tv.vault_id, &ops);

    let vault = tv.session.open_vault(tv.vault_id).unwrap();
    engine::pull(&tv.session, &vault, &FsStoreFactory).unwrap();

    // The item is tombstoned (hidden from get_item) but appears in trash.
    assert!(vault.get_item(item).is_err());
    let trash = vault.list_trash().unwrap();
    assert!(
        trash
            .iter()
            .any(|t| t.item_id.as_bytes() == item.as_bytes())
    );
}

#[test]
fn untrusted_peer_op_is_rejected_at_pull() {
    let tv = new_vault();
    let sync_root = tempfile::tempdir().unwrap();
    engine::setup(
        &tv.session,
        tv.vault_id,
        &sync_root.path().to_string_lossy(),
        &FsStoreFactory,
    )
    .unwrap();

    // Peer is NOT trusted (never trust_in).
    let mut peer = PeerDevice::new();
    let item = Id::new();
    let op = {
        let vault = tv.session.open_vault(tv.vault_id).unwrap();
        peer.snapshot(&vault, OpKind::Create, item, 1, 1, &login("x", "v"))
    };
    publish(sync_root.path(), tv.vault_id, &[op]);

    let vault = tv.session.open_vault(tv.vault_id).unwrap();
    let report = engine::pull(&tv.session, &vault, &FsStoreFactory).unwrap();
    assert_eq!(report.applied, 0);
    assert!(report.has_alarms());
    assert_eq!(report.quarantines[0].alarm, lp_sync::Alarm::UnknownDevice);
    // Nothing was applied.
    assert!(vault.get_item(item).is_err());
}

#[test]
fn forged_manifest_cannot_inject_state() {
    let tv = new_vault();
    let sync_root = tempfile::tempdir().unwrap();
    engine::setup(
        &tv.session,
        tv.vault_id,
        &sync_root.path().to_string_lossy(),
        &FsStoreFactory,
    )
    .unwrap();

    // Write a manifest claiming a device with ops, but NO backing segments.
    let dir = SyncDir::open(sync_root.path(), tv.vault_id).unwrap();
    let mut manifest = lp_sync::shipping::Manifest {
        vault_id: tv.vault_id.to_hyphenated(),
        devices: std::collections::BTreeMap::new(),
    };
    manifest.devices.insert("deadbeef-0000".into(), 99);
    dir.write_manifest(&manifest).unwrap();

    let vault = tv.session.open_vault(tv.vault_id).unwrap();
    let report = engine::pull(&tv.session, &vault, &FsStoreFactory).unwrap();
    // The advisory manifest injects nothing: no ops, no alarms.
    assert_eq!(report.applied, 0);
    assert!(!report.has_alarms());
    assert_eq!(vault.list_items().unwrap().len(), 0);
}

#[test]
fn dropped_segment_holds_pending_then_applies_when_filled() {
    let tv = new_vault();
    let sync_root = tempfile::tempdir().unwrap();
    engine::setup(
        &tv.session,
        tv.vault_id,
        &sync_root.path().to_string_lossy(),
        &FsStoreFactory,
    )
    .unwrap();

    let mut a = PeerDevice::new();
    a.trust_in(&tv.session);
    let item = Id::new();
    let (op1, op2) = {
        let vault = tv.session.open_vault(tv.vault_id).unwrap();
        let op1 = a.snapshot(&vault, OpKind::Create, item, 1, 1, &login("t", "v1"));
        let op2 = a.snapshot(&vault, OpKind::Update, item, 2, 2, &login("t", "v2"));
        (op1, op2)
    };

    // Deliver ONLY op2 first (op1 seg dropped): op2 held pending, not applied.
    publish(sync_root.path(), tv.vault_id, std::slice::from_ref(&op2));
    let vault = tv.session.open_vault(tv.vault_id).unwrap();
    let r1 = engine::pull(&tv.session, &vault, &FsStoreFactory).unwrap();
    assert_eq!(r1.applied, 0);
    assert_eq!(r1.pending, 1);
    assert!(!r1.has_alarms());
    assert!(vault.get_item(item).is_err());

    // Now the missing op1 arrives: both apply and converge.
    publish(sync_root.path(), tv.vault_id, &[op1]);
    let r2 = engine::pull(&tv.session, &vault, &FsStoreFactory).unwrap();
    assert_eq!(r2.applied, 2);
    let got = vault.get_item(item).unwrap();
    let field = got
        .payload
        .fields
        .iter()
        .find(|f| f.name == "note")
        .unwrap();
    assert_eq!(field.value, serde_json::Value::String("v2".into()));
    vault.verify_local_chain().unwrap();
}
