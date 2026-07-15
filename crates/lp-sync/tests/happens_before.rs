//! True happens-before merge tests (tracked follow-up #17): the merge must
//! decide delete-vs-edit concurrency from the per-op **observed-heads version
//! vector** (sync-protocol.md §3), NOT from the scalar Lamport clock. These
//! assert the exact cases the old scalar rule got wrong, plus a 3-device
//! scenario where scalar Lamport and true happens-before disagree, and a
//! property test tying the outcome to the happens-before definition.
//!
//! Simulated peers (`common::PeerDevice`) author genuine signed, hash-chained
//! ops carrying a correct causal summary; a test drives cross-device causality
//! explicitly with `PeerDevice::observe`.

mod common;

use std::collections::BTreeMap;
use std::sync::{Mutex, OnceLock};

use lp_sync::engine;
use lp_sync::shipping::SyncDir;
use lp_sync::store::FsStoreFactory;
use lp_vault::op::{ObservedHeads, OpKind};
use lp_vault::{Id, ItemId, StoredOp};

use common::{PeerDevice, login, new_vault};

/// One shared vault for the property test — the Argon2id KDF runs once, not per
/// case. The merge is a pure function that only reads the VaultKey to decrypt
/// op payloads, so sharing one handle across cases is sound (mirrors
/// `convergence.rs`).
fn shared_vault() -> &'static Mutex<common::TestVault> {
    static VAULT: OnceLock<Mutex<common::TestVault>> = OnceLock::new();
    VAULT.get_or_init(|| Mutex::new(new_vault()))
}

/// Publish a peer's contiguous op run into the vault's sync dir as a segment.
fn publish(sync_root: &std::path::Path, vault_id: lp_vault::VaultId, ops: &[StoredOp]) {
    let dir = SyncDir::open(sync_root, vault_id).unwrap();
    dir.write_segment(ops).unwrap();
}

/// The value of the `note` field of an item's current head (or `None` if
/// tombstoned / missing).
fn head_note(vault: &lp_vault::Vault<'_>, item: ItemId) -> Option<String> {
    let got = vault.get_item(item).ok()?;
    got.payload
        .fields
        .iter()
        .find(|f| f.name == "note")
        .map(|f| match &f.value {
            serde_json::Value::String(s) => s.clone(),
            other => other.to_string(),
        })
}

/// **The bug fix.** A concurrent edit vs delete where the DELETE has the HIGHER
/// Lamport. Under the old scalar-Lamport rule (`a→b iff a.lamport < b.lamport`)
/// the edit (lower Lamport) looked causally-before the delete → item wrongly
/// deleted. Under true happens-before the two are concurrent → **edit wins**,
/// item stays live, and the delete is preserved (recorded but overridden).
#[test]
fn concurrent_edit_vs_higher_lamport_delete_edit_wins() {
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
        // A creates the item (lamport 1).
        let create = a.snapshot(&vault, OpKind::Create, item, 1, 1, &login("keep me", "v2"));
        // B observes the create, so its delete is causally AFTER the create but
        // CONCURRENT with A's edit (A never saw B's delete; B never saw A's
        // edit). Crucially the delete carries the HIGHER Lamport (3 > 2).
        b.observe(&create);
        // A edits at lamport 2 (A only ever saw its own create).
        let edit = a.snapshot(
            &vault,
            OpKind::Update,
            item,
            2,
            2,
            &login("keep me", "v2-edited"),
        );
        // B deletes at lamport 3 — higher than the edit.
        let delete = b.delete(&vault, item, 3);
        (create, edit, delete)
    };
    publish(sync_root.path(), tv.vault_id, &[create, edit]);
    publish(sync_root.path(), tv.vault_id, &[delete]);

    let vault = tv.session.open_vault(tv.vault_id).unwrap();
    let report = engine::pull(&tv.session, &vault, &FsStoreFactory).unwrap();
    assert!(!report.has_alarms());

    // Edit wins despite the delete's higher Lamport: the item is live.
    assert_eq!(
        head_note(&vault, item).as_deref(),
        Some("v2-edited"),
        "concurrent edit must win over a higher-Lamport delete (§4.3)"
    );
    // The losing delete is preserved as a real op row (nothing discarded): it
    // is in the log and re-verifies, it simply did not tombstone the item.
    assert!(vault.get_item(item).is_ok());
    vault.verify_local_chain().unwrap();
}

/// Causal delete-after-edit: the delete OBSERVES the edit → delete wins, the
/// tombstone stands (sync-protocol.md §4.3 row 3).
#[test]
fn causal_delete_after_edit_deletes() {
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
        let create = a.snapshot(&vault, OpKind::Create, item, 1, 1, &login("t", "v1"));
        let edit = a.snapshot(&vault, OpKind::Update, item, 2, 2, &login("t", "v2"));
        // B observes BOTH the create and the edit, then deletes: the delete is
        // causally after every edit → it must win (even at a lower... here 3).
        b.observe(&create);
        b.observe(&edit);
        let delete = b.delete(&vault, item, 3);
        (create, edit, delete)
    };
    publish(sync_root.path(), tv.vault_id, &[create, edit]);
    publish(sync_root.path(), tv.vault_id, &[delete]);

    let vault = tv.session.open_vault(tv.vault_id).unwrap();
    engine::pull(&tv.session, &vault, &FsStoreFactory).unwrap();

    assert!(
        vault.get_item(item).is_err(),
        "causal delete must tombstone"
    );
    let trash = vault.list_trash().unwrap();
    assert!(
        trash
            .iter()
            .any(|t| t.item_id.as_bytes() == item.as_bytes())
    );
    vault.verify_local_chain().unwrap();
}

/// Causal edit-after-delete: the edit OBSERVES the delete → the item is revived
/// (sync-protocol.md §4.3 row 2). Here the reviving edit is on the SAME device
/// as the delete (chain order gives exact causality) AND a cross-device edit.
#[test]
fn causal_edit_after_delete_revives() {
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
    let (create, delete, revive) = {
        let vault = tv.session.open_vault(tv.vault_id).unwrap();
        let create = a.snapshot(&vault, OpKind::Create, item, 1, 1, &login("t", "v1"));
        // A deletes.
        let delete = a.delete(&vault, item, 2);
        // B observes the create AND the delete, then edits: causally after the
        // delete → revive.
        b.observe(&create);
        b.observe(&delete);
        let revive = b.snapshot(&vault, OpKind::Update, item, 2, 3, &login("t", "revived"));
        (create, delete, revive)
    };
    publish(sync_root.path(), tv.vault_id, &[create, delete]);
    publish(sync_root.path(), tv.vault_id, &[revive]);

    let vault = tv.session.open_vault(tv.vault_id).unwrap();
    engine::pull(&tv.session, &vault, &FsStoreFactory).unwrap();

    assert_eq!(
        head_note(&vault, item).as_deref(),
        Some("revived"),
        "an edit that observed the delete must revive the item"
    );
    vault.verify_local_chain().unwrap();
}

/// A 3-device scenario where scalar Lamport and true happens-before DISAGREE.
///
/// Timeline (all on one item):
///  - A: create (lamport 1)
///  - B observes A's create, then edits (lamport 5, artificially high)
///  - C observes ONLY A's create (never B's edit), then deletes (lamport 6)
///
/// Scalar Lamport would say edit(5) → delete(6) [edit before delete] and, since
/// that is the only edit, would tombstone the item. True happens-before says
/// the edit and delete are CONCURRENT (C never observed B's edit) → **edit
/// wins, item live**. This asserts the merge follows happens-before, not Lamport.
#[test]
fn three_device_lamport_vs_happens_before_disagree() {
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
    let mut c = PeerDevice::new();
    a.trust_in(&tv.session);
    b.trust_in(&tv.session);
    c.trust_in(&tv.session);

    let item = Id::new();
    let (create, edit, delete) = {
        let vault = tv.session.open_vault(tv.vault_id).unwrap();
        let create = a.snapshot(&vault, OpKind::Create, item, 1, 1, &login("shared", "base"));
        // B saw A's create, edits with a deliberately HIGH lamport.
        b.observe(&create);
        let edit = b.snapshot(
            &vault,
            OpKind::Update,
            item,
            2,
            5,
            &login("shared", "b-edit"),
        );
        // C saw ONLY A's create (NOT B's edit) and deletes at a higher lamport.
        c.observe(&create);
        let delete = c.delete(&vault, item, 6);
        (create, edit, delete)
    };
    publish(sync_root.path(), tv.vault_id, &[create]);
    publish(sync_root.path(), tv.vault_id, &[edit]);
    publish(sync_root.path(), tv.vault_id, &[delete]);

    let vault = tv.session.open_vault(tv.vault_id).unwrap();
    let report = engine::pull(&tv.session, &vault, &FsStoreFactory).unwrap();
    assert!(!report.has_alarms());

    // Happens-before wins: edit and delete are concurrent → item live with B's
    // edit as head. (Scalar Lamport would have tombstoned it.)
    assert_eq!(
        head_note(&vault, item).as_deref(),
        Some("b-edit"),
        "merge must follow happens-before, not scalar Lamport"
    );
    vault.verify_local_chain().unwrap();
}

// --- Property test: outcomes follow the happens-before definition ------------

/// A device-independent oracle for the delete/live outcome computed directly
/// from the happens-before definition (sync-protocol.md §3/§4.3), used to check
/// the merge against its own spec over random op sets.
///
/// Ops are described as `(device_idx, seq, kind, observed)` where `observed`
/// maps device_idx → highest observed seq. This mirrors the real relation:
///  - same device: `a → b` iff `a.seq < b.seq`;
///  - cross device: `a → b` iff `b.observed[a.device] >= a.seq`.
#[derive(Clone)]
struct OracleOp {
    device: usize,
    /// The authoring device's raw id bytes (the total-order tiebreak, matching
    /// `merge`'s `(lamport, device_id, op_id)` — op_id is unique so we proxy the
    /// final tiebreak with `device`+`seq`, never actually reached for deletes
    /// that differ in `(lamport, device)`).
    device_bytes: [u8; 16],
    seq: u64,
    lamport: u64,
    is_delete: bool,
    observed: BTreeMap<usize, u64>,
}

impl OracleOp {
    fn happens_before(&self, other: &OracleOp) -> bool {
        if self.device == other.device {
            self.seq < other.seq
        } else {
            other.observed.get(&self.device).copied().unwrap_or(0) >= self.seq
        }
    }

    /// The LWW total-order key mirroring `merge`'s `(lamport, device_id, …)`.
    fn order_key(&self) -> (u64, [u8; 16], u64) {
        (self.lamport, self.device_bytes, self.seq)
    }
}

/// The oracle: an item is deleted iff there is a surviving delete (one not
/// causally-before any snapshot — a delete a later edit observed is revived) and
/// EVERY snapshot happens-before the **canonical** surviving delete — the
/// greatest by total order. This mirrors `merge::resolve_tombstone` exactly:
/// picking a *different* survivor is wrong; the greatest-total-order one is the
/// single canonical delete.
fn oracle_is_deleted(ops: &[OracleOp]) -> bool {
    let snapshots: Vec<&OracleOp> = ops.iter().filter(|o| !o.is_delete).collect();
    if snapshots.is_empty() {
        return false;
    }
    let canonical = ops
        .iter()
        .filter(|o| o.is_delete)
        .filter(|d| !snapshots.iter().any(|s| d.happens_before(s)))
        .max_by(|a, b| a.order_key().cmp(&b.order_key()));
    let Some(canonical) = canonical else {
        return false;
    };
    snapshots.iter().all(|s| s.happens_before(canonical))
}

use proptest::prelude::*;

/// Strategy: a create then a random mix of updates/deletes across 2 devices,
/// with realistic observed-heads: each op observes a random prefix of the
/// already-authored ops per device.
fn scenario_strategy() -> impl Strategy<Value = Vec<(usize, bool, u64)>> {
    // (device, is_delete, observe_fraction_seed)
    let one = (0usize..2, any::<bool>(), any::<u64>());
    prop::collection::vec(one, 1..6)
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(200))]

    /// For random cross-device op sets with realistic causal summaries, the
    /// merge's delete/live outcome matches the happens-before oracle, and the
    /// result is permutation-independent (convergence).
    #[test]
    fn merge_outcome_matches_happens_before_oracle(spec in scenario_strategy(), perm_seed in any::<u64>()) {
        // Build a real signed op set + a parallel oracle description against the
        // shared vault (used only to seal/decrypt op payloads).
        let guard = shared_vault().lock().unwrap();
        let vault = guard.session.open_vault(guard.vault_id).unwrap();

        let mut devs = [PeerDevice::new(), PeerDevice::new()];
        for d in &devs {
            d.trust_in(&guard.session);
        }
        // Fresh item id per case so cases never collide in the shared vault.
        let item = Id::new();

        let mut real_ops: Vec<StoredOp> = Vec::new();
        let mut oracle_ops: Vec<OracleOp> = Vec::new();
        // Per-device authored ops (for observe wiring) and next-version counter.
        let mut authored: [Vec<StoredOp>; 2] = [Vec::new(), Vec::new()];
        // Accumulated observed state per device, mirroring `PeerDevice` exactly:
        // once a device observes an op it stays observed (monotone). The oracle
        // reads this same accumulated state, so it models reality faithfully.
        let mut dev_observed: [BTreeMap<usize, u64>; 2] = [BTreeMap::new(), BTreeMap::new()];
        let mut next_ver: u32 = 1;
        let mut item_created = false;

        for (i, (dev, is_delete_raw, obs_seed)) in spec.iter().enumerate() {
            let dev = *dev;
            // First op must be a create so a base version exists.
            let kind = if !item_created {
                item_created = true;
                OpKind::Create
            } else if *is_delete_raw {
                OpKind::Delete
            } else {
                OpKind::Update
            };

            // Observe a pseudo-random subset (a prefix) of the OTHER device's
            // ops, simulating partial replication before authoring.
            let other = 1 - dev;
            let observe_count = if authored[other].is_empty() {
                0
            } else {
                (*obs_seed as usize) % (authored[other].len() + 1)
            };
            // Observe a prefix of the other device's ops — accumulating into the
            // device's persistent observed state (monotone, like PeerDevice).
            for op in authored[other].iter().take(observe_count) {
                devs[dev].observe(op);
                let e = dev_observed[dev].entry(other).or_insert(0);
                *e = (*e).max(op.seq);
            }
            // Self prior head is observed too.
            if let Some(last) = authored[dev].last() {
                let e = dev_observed[dev].entry(dev).or_insert(0);
                *e = (*e).max(last.seq);
            }
            // The oracle's causal summary = this device's accumulated observed
            // state at author time (the exact vector PeerDevice stamps).
            let obs_map = dev_observed[dev].clone();

            let lamport = (i as u64) + 1;
            let op = match kind {
                OpKind::Create | OpKind::Update => {
                    let p = login("item", &format!("v{i}"));
                    let o = devs[dev].snapshot(&vault, kind, item, next_ver, lamport, &p);
                    next_ver += 1;
                    o
                }
                OpKind::Delete => devs[dev].delete(&vault, item, lamport),
                _ => unreachable!(),
            };
            oracle_ops.push(OracleOp {
                device: dev,
                device_bytes: *op.device_id.as_bytes(),
                seq: op.seq,
                lamport: op.lamport,
                is_delete: matches!(op.op_kind, OpKind::Delete),
                observed: obs_map,
            });
            authored[dev].push(op.clone());
            real_ops.push(op);
        }

        // Materialize the real op set and compare the tombstone outcome to the
        // oracle. Decrypt through the shared vault.
        let decrypt = |op_id: &lp_vault::OpId, env: &[u8]| {
            vault.decrypt_op_payload(op_id, env).map_err(Into::into)
        };
        let mat = lp_sync::merge::materialize(&real_ops, &decrypt, 1_000).unwrap();
        let merged_deleted = mat
            .items
            .iter()
            .find(|it| it.item_id.as_bytes() == item.as_bytes())
            .map(|it| it.tombstone.is_some())
            .unwrap_or(false);

        prop_assert_eq!(
            merged_deleted,
            oracle_is_deleted(&oracle_ops),
            "merge delete/live outcome must match the happens-before oracle"
        );

        // Convergence: a permutation of the same ops yields the same outcome.
        let mut permuted = real_ops.clone();
        deterministic_shuffle(&mut permuted, perm_seed);
        let mat2 = lp_sync::merge::materialize(&permuted, &decrypt, 1_000).unwrap();
        let merged_deleted2 = mat2
            .items
            .iter()
            .find(|it| it.item_id.as_bytes() == item.as_bytes())
            .map(|it| it.tombstone.is_some())
            .unwrap_or(false);
        prop_assert_eq!(merged_deleted, merged_deleted2, "outcome must be permutation-independent");
    }
}

/// A dependency-free deterministic Fisher–Yates shuffle from a `u64` seed.
fn deterministic_shuffle<T>(v: &mut [T], mut seed: u64) {
    let mut next = || {
        seed ^= seed << 13;
        seed ^= seed >> 7;
        seed ^= seed << 17;
        seed
    };
    let n = v.len();
    for i in (1..n).rev() {
        let j = (next() % (i as u64 + 1)) as usize;
        v.swap(i, j);
    }
}

/// Keep `ObservedHeads` referenced from a test (documents the type under test)
/// even though the property test builds vectors via the peer helper.
#[test]
fn observed_heads_type_is_reachable() {
    let mut o = ObservedHeads::new();
    let d = Id::from_bytes([1u8; 16]);
    o.observe(&d, 3);
    assert_eq!(o.get(&d), 3);
}
