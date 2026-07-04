//! The deterministic total-merge (sync-protocol.md §4) — Part B, the crown jewel.
//!
//! Given the **full op set** for a vault (local + verified foreign ops), this
//! module materializes each touched item's state as a pure function of that set
//! — independent of arrival order (sync-protocol.md §4.4 convergence). It emits
//! a [`lp_vault::Materialization`] the storage layer applies atomically.
//!
//! # Total order (§4.1)
//!
//! Ops are totally ordered by `(lamport, device_id big-endian, op_id)`. This is
//! the last-writer-wins order: "later" = greater. `op_id` (UUIDv7) is the final,
//! collision-free tiebreak so the order is total even in adversarial input.
//!
//! # Per-field LWW with loser preservation (§4.2)
//!
//! Every `create`/`update`/`restore` op carries a **full canonical item
//! snapshot** as its payload (that is how `lp-vault` authors ops today — full
//! payloads, not field deltas; we reuse that encoding rather than diverge). So
//! per-field LWW degenerates to **whole-item LWW**: the greatest-total-order
//! snapshot op defines the head fields, and **every other** snapshot op is
//! preserved as a real `item_versions` row (a conflict loser is never dropped,
//! §4.2). When ops genuinely edit disjoint fields, whole-snapshot LWW still
//! never loses data because each snapshot is retained as a version — the
//! documented, convergence-safe MVP reading of the field-level rule.
//!
//! # Version-number assignment (§4.4 determinism)
//!
//! Version numbers are assigned by **ascending total order** of the snapshot ops
//! that produced them: the total-order-least snapshot is version 1, the next 2,
//! and so on. The head (`current_version`) is the version of the
//! total-order-greatest snapshot. Because the total order is a pure function of
//! the op set, so are the version numbers — identical on every device, in any
//! arrival order.
//!
//! # Delete / restore / edit interactions (§4.3)
//!
//! "Concurrent" = neither op is in the other's Lamport causal past (we use the
//! standard scalar-Lamport happens-before: `a → b` iff `a.lamport < b.lamport`;
//! same-device ops always have strictly increasing lamports, so their chain
//! order is preserved, and equal-lamport cross-device ops are concurrent).
//!
//! An item is **deleted** iff it has at least one delete op **and every**
//! snapshot op happens-before the greatest-total-order delete (i.e. no edit is
//! concurrent-with or after that delete). Otherwise it is **live** — which
//! yields:
//!
//! - concurrent update vs delete → **edit wins** (the update is not before the
//!   delete), item live, conflict badge derivable;
//! - delete then causally-later update → **update wins** (revived);
//! - update then causally-later delete → **delete wins** (tombstone stands);
//! - concurrent delete vs delete → a single tombstone from the
//!   greatest-total-order delete (idempotent).
//!
//! `restore` participates exactly like an `update` (its payload is the restored
//! version's full body; sync-protocol.md §4.3 "restore is an edit").

use std::cmp::Ordering;
use std::collections::BTreeMap;

use lp_vault::ids::{DeviceId, ItemId, OpId};
use lp_vault::op::OpKind;
use lp_vault::payload::ItemPayload;
use lp_vault::{
    ItemMaterialization, Materialization, StoredOp, TombstoneMaterialization,
    VersionMaterialization,
};

use crate::error::Result;

/// The default trash-retention window applied to a merged tombstone when the
/// delete op carries none of its own (PRD §4.10 default 30 days). The delete
/// op payload is `{}` (sync-protocol.md §1), so the window is a local policy
/// constant; it does not affect convergence of the *deleted/live* fact.
pub const DEFAULT_RETENTION_MS: i64 = 30 * 24 * 60 * 60 * 1000;

/// A payload decryptor: given an op id and its `payload_env` bytes, return the
/// decrypted plaintext (VaultKey `open`). The engine supplies this as a thin
/// closure over `Vault::decrypt_op_payload` so `merge` holds no key material.
pub type PayloadDecryptor<'a> = dyn Fn(&OpId, &[u8]) -> Result<Vec<u8>> + 'a;

/// One op lifted into merge form: its ordering key, kind, target, and — for
/// snapshot ops — its decoded payload.
struct MergeOp {
    op_id: OpId,
    device_id: DeviceId,
    lamport: u64,
    kind: OpKind,
    created_at: i64,
    /// The decoded full item snapshot for create/update/restore; `None` for
    /// delete/rewrap (which carry no item body).
    payload: Option<ItemPayload>,
}

impl MergeOp {
    /// The total-order key `(lamport, device_id big-endian bytes, op_id bytes)`
    /// (sync-protocol.md §4.1).
    fn order_key(&self) -> (u64, [u8; 16], [u8; 16]) {
        (
            self.lamport,
            *self.device_id.as_bytes(),
            *self.op_id.as_bytes(),
        )
    }

    /// Total-order comparison (§4.1).
    fn cmp_total(&self, other: &Self) -> Ordering {
        self.order_key().cmp(&other.order_key())
    }
}

/// Compute the materialization for a set of ops touching one or more items.
///
/// `ops` must be the **complete** op set for every item it references (local +
/// foreign), so the fold is over the whole history — that is what makes the
/// result independent of which subset just arrived (sync-protocol.md §4.4).
/// `now` stamps a merged tombstone's `deleted_at`/`purge_after` only when the
/// delete op is the canonical one and carries no explicit time.
///
/// # Errors
///
/// [`crate::Error::Vault`] if a snapshot op's payload fails to decrypt or parse.
pub fn materialize(
    ops: &[StoredOp],
    decrypt: &PayloadDecryptor<'_>,
    now: i64,
) -> Result<Materialization> {
    // Lift every item-scoped op into merge form (decoding snapshot payloads).
    let mut by_item: BTreeMap<[u8; 16], Vec<MergeOp>> = BTreeMap::new();
    for op in ops {
        let Some(item_id) = op.target_item else {
            // Vault-scope op (none in the MVP op kinds) — nothing to materialize.
            continue;
        };
        let payload = match op.op_kind {
            OpKind::Create | OpKind::Update | OpKind::Restore => {
                let plaintext = decrypt(&op.op_id, &op.payload_env)?;
                Some(ItemPayload::from_canonical(&plaintext)?)
            }
            OpKind::Delete | OpKind::Rewrap => None,
        };
        by_item
            .entry(*item_id.as_bytes())
            .or_default()
            .push(MergeOp {
                op_id: op.op_id,
                device_id: op.device_id,
                lamport: op.lamport,
                kind: op.op_kind,
                created_at: op.created_at,
                payload,
            });
    }

    let mut mat = Materialization {
        ops: ops.to_vec(),
        items: Vec::new(),
    };
    for (item_bytes, mut item_ops) in by_item {
        item_ops.sort_by(MergeOp::cmp_total);
        if let Some(item_mat) = materialize_item(ItemId::from_bytes(item_bytes), &item_ops, now) {
            mat.items.push(item_mat);
        }
    }
    Ok(mat)
}

/// Materialize one item from its ops (already sorted ascending by total order).
fn materialize_item(item_id: ItemId, ops: &[MergeOp], now: i64) -> Option<ItemMaterialization> {
    // Snapshot ops (create/update/restore) in ascending total order become the
    // version rows; version numbers = 1-based position in that order (§4.4).
    let snapshots: Vec<&MergeOp> = ops
        .iter()
        .filter(|o| matches!(o.kind, OpKind::Create | OpKind::Update | OpKind::Restore))
        .collect();

    if snapshots.is_empty() {
        // No content ops at all (e.g. a lone delete of an item we never saw a
        // create for). Nothing materializable; skip (a stray delete is inert).
        return None;
    }

    let mut versions = Vec::with_capacity(snapshots.len());
    let mut created_at = i64::MAX;
    for (idx, snap) in snapshots.iter().enumerate() {
        let version = i64::try_from(idx + 1).unwrap_or(i64::MAX);
        let payload = snap.payload.clone().expect("snapshot op carries a payload");
        created_at = created_at.min(snap.created_at);
        versions.push(VersionMaterialization {
            version,
            payload,
            created_at: snap.created_at,
            author_device_id: snap.device_id,
            op_id: snap.op_id,
        });
    }
    // The head is the greatest-total-order snapshot = the last one after sort.
    let current_version = i64::try_from(snapshots.len()).unwrap_or(i64::MAX);
    let head = snapshots.last().expect("non-empty");
    let updated_at = head.created_at;

    // Delete/edit resolution (§4.3). Deleted iff there is a delete op and every
    // snapshot happens-before the greatest-total-order delete.
    let tombstone = resolve_tombstone(ops, &snapshots, now);

    Some(ItemMaterialization {
        item_id,
        current_version,
        created_at: if created_at == i64::MAX {
            now
        } else {
            created_at
        },
        updated_at,
        versions,
        tombstone,
    })
}

/// Resolve whether the item is deleted, and if so the canonical tombstone
/// (§4.3). `snapshots` are the item's content ops (ascending total order).
fn resolve_tombstone(
    ops: &[MergeOp],
    snapshots: &[&MergeOp],
    now: i64,
) -> Option<TombstoneMaterialization> {
    // The greatest-total-order delete, if any (ops are ascending, so scan back).
    let last_delete = ops.iter().rev().find(|o| o.kind == OpKind::Delete)?;

    // Edit wins unless *every* snapshot happens-before this delete. A snapshot
    // that is concurrent-with or after the delete keeps the item live
    // (edit-wins / revive; §4.3 rows 1 & 2).
    let all_edits_before_delete = snapshots
        .iter()
        .all(|s| happens_before(s.lamport, last_delete.lamport));
    if !all_edits_before_delete {
        return None; // live
    }

    Some(TombstoneMaterialization {
        deleted_at: now,
        purge_after: now.saturating_add(DEFAULT_RETENTION_MS),
        deleted_by_device: last_delete.device_id,
        op_id: last_delete.op_id,
    })
}

/// Scalar-Lamport happens-before (§4.3): `a → b` iff `a.lamport < b.lamport`.
/// Equal lamports (from different devices) are concurrent. Same-device ops
/// always have strictly increasing lamports, so their chain order is respected.
fn happens_before(a_lamport: u64, b_lamport: u64) -> bool {
    a_lamport < b_lamport
}
