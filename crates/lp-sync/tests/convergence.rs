//! Permutation-convergence property test (sync-protocol.md §4.4) — the crown
//! jewel. Generates arbitrary op sets across 2–3 simulated devices (creates /
//! updates / deletes on overlapping items with varied Lamport clocks), applies
//! **every sampled permutation**, and asserts the materialized state is
//! byte-identical and that no conflicting write is discarded (losers survive as
//! versions).
//!
//! The merge (`lp_sync::merge::materialize`) is a **pure function of the op
//! set**, so convergence is asserted at that level: for a given op multiset, the
//! resulting `(items, item_versions, tombstones)` projection must be identical
//! across all permutations. Payloads are sealed under a real shared VaultKey and
//! decrypted through the vault, exercising the true crypto path.

mod common;

use std::collections::BTreeMap;
use std::sync::{Mutex, OnceLock};

use lp_vault::op::OpKind;
use lp_vault::{ItemId, StoredOp};
use proptest::prelude::*;

use common::{login, new_vault};

/// A single shared vault for the whole property test — account creation runs the
/// (deliberately expensive) Argon2id KDF once, not per case. The merge is a pure
/// function that reads only the vault's VaultKey (for op-payload decryption), so
/// sharing one handle across cases is sound and keeps the suite fast.
fn shared_vault() -> &'static Mutex<common::TestVault> {
    static VAULT: OnceLock<Mutex<common::TestVault>> = OnceLock::new();
    VAULT.get_or_init(|| Mutex::new(new_vault()))
}

/// A device-neutral, comparable projection of a merge result: what actually
/// materialized, independent of ciphertext (which uses fresh per-version keys).
#[derive(Clone, Debug, PartialEq, Eq)]
struct StateProjection {
    /// Per item id (hex): `(current_version, tombstoned, [canonical version
    /// payloads in version order])`.
    items: BTreeMap<String, ItemView>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct ItemView {
    current_version: i64,
    tombstoned: bool,
    /// Canonical JSON of each version's payload, in ascending version order.
    versions: Vec<Vec<u8>>,
}

/// Project a `Materialization` into the comparable form (decrypted content +
/// structural facts, never ciphertext).
fn project(mat: &lp_vault::Materialization) -> StateProjection {
    let mut items = BTreeMap::new();
    for item in &mat.items {
        let mut versions: Vec<(i64, Vec<u8>)> = item
            .versions
            .iter()
            .map(|v| (v.version, v.payload.to_canonical().unwrap()))
            .collect();
        versions.sort_by_key(|(v, _)| *v);
        items.insert(
            hex(item.item_id.as_bytes()),
            ItemView {
                current_version: item.current_version,
                tombstoned: item.tombstone.is_some(),
                versions: versions.into_iter().map(|(_, p)| p).collect(),
            },
        );
    }
    StateProjection { items }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// A compact op recipe the property strategy generates, later realized into a
/// real signed `StoredOp` by a simulated device.
#[derive(Clone, Debug)]
struct OpRecipe {
    device: usize, // 0..num_devices
    item: usize,   // 0..num_items
    lamport: u64,
    kind: OpKind,
    field_value: String,
}

/// Strategy: a small set of op recipes over 2–3 devices and 1–2 items.
fn recipes_strategy() -> impl Strategy<Value = Vec<OpRecipe>> {
    let one = (
        0usize..3, // device
        0usize..2, // item
        1u64..8,   // lamport
        prop_oneof![
            Just(OpKind::Create),
            Just(OpKind::Update),
            Just(OpKind::Delete),
        ],
        "[a-z]{1,4}", // field value
    )
        .prop_map(|(device, item, lamport, kind, field_value)| OpRecipe {
            device,
            item,
            lamport,
            kind,
            field_value,
        });
    prop::collection::vec(one, 2..7)
}

/// Realize a set of recipes into real signed ops in the shared vault. Each
/// item's *first* op is forced to `Create` so a valid history exists.
fn realize(recipes: &[OpRecipe]) -> Vec<StoredOp> {
    let guard = shared_vault().lock().unwrap();
    let vault = guard.session.open_vault(guard.vault_id).unwrap();

    let num_devices = 3;
    let mut devices: Vec<common::PeerDevice> = (0..num_devices)
        .map(|_| common::PeerDevice::new())
        .collect();
    for d in &devices {
        d.trust_in(&guard.session);
    }

    // Fresh, unique item ids per realization (so cases never collide).
    let item_ids: Vec<ItemId> = (0..2).map(|_| lp_vault::Id::new()).collect();
    let mut item_seen = [false; 2];

    let mut ops = Vec::new();
    for r in recipes {
        let item = item_ids[r.item];
        // Force the first op per item to be a Create so there is a base version.
        let kind = if item_seen[r.item] {
            r.kind
        } else {
            item_seen[r.item] = true;
            OpKind::Create
        };
        let dev = &mut devices[r.device];
        let op = match kind {
            OpKind::Create | OpKind::Update => {
                let payload = login("item", &r.field_value);
                dev.snapshot(&vault, kind, item, 1, r.lamport, &payload)
            }
            OpKind::Delete => dev.delete(&vault, item, r.lamport),
            _ => unreachable!(),
        };
        ops.push(op);
    }
    ops
}

/// Materialize a permutation of `ops` against the shared vault (for decryption).
fn materialize_perm(ops: &[StoredOp]) -> lp_vault::Materialization {
    let guard = shared_vault().lock().unwrap();
    let vault = guard.session.open_vault(guard.vault_id).unwrap();
    let decrypt = |op_id: &lp_vault::OpId, env: &[u8]| {
        vault.decrypt_op_payload(op_id, env).map_err(Into::into)
    };
    lp_sync::merge::materialize(ops, &decrypt, 1_000).unwrap()
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(40))]

    /// Any permutation of the same op multiset yields byte-identical state.
    #[test]
    fn permutations_converge(recipes in recipes_strategy(), seed in any::<u64>()) {
        let ops = realize(&recipes);
        prop_assume!(!ops.is_empty());

        // Baseline: identity order.
        let baseline = project(&materialize_perm(&ops));

        // A few sampled permutations (deterministic shuffles from `seed`).
        for k in 0..4u64 {
            let mut permuted = ops.clone();
            deterministic_shuffle(&mut permuted, seed.wrapping_add(k));
            let got = project(&materialize_perm(&permuted));
            prop_assert_eq!(&got, &baseline, "materialized state diverged under permutation");
        }
    }

    /// No conflicting write is discarded: |versions| across live items equals
    /// the number of snapshot (create/update) ops on those items.
    #[test]
    fn no_conflicting_write_is_discarded(recipes in recipes_strategy()) {
        let ops = realize(&recipes);
        prop_assume!(!ops.is_empty());
        let mat = materialize_perm(&ops);

        // Count snapshot ops per item.
        let mut snap_per_item: BTreeMap<[u8;16], usize> = BTreeMap::new();
        for op in &ops {
            if matches!(op.op_kind, OpKind::Create | OpKind::Update | OpKind::Restore)
                && let Some(it) = op.target_item
            {
                *snap_per_item.entry(*it.as_bytes()).or_default() += 1;
            }
        }
        for item in &mat.items {
            let expected = snap_per_item.get(item.item_id.as_bytes()).copied().unwrap_or(0);
            prop_assert_eq!(
                item.versions.len(),
                expected,
                "a conflicting write was dropped (versions != snapshot ops)"
            );
        }
    }
}

/// A tiny deterministic Fisher–Yates shuffle from a `u64` seed (no rng dep).
fn deterministic_shuffle<T>(v: &mut [T], mut seed: u64) {
    // xorshift64* for a stable, dependency-free permutation.
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
