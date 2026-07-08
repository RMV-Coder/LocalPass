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
//! "Concurrent" = neither op is in the other's causal past, decided by the
//! per-op **observed-heads version vector** (sync-protocol.md §3) — *true*
//! happens-before, not the old scalar-Lamport approximation:
//!
//! - if `a.device == b.device`, `a → b` iff `a.seq < b.seq` (same-device chain
//!   order — a device totally orders its own ops);
//! - otherwise `a → b` iff `b.observed[a.device] >= a.seq` (b's author had
//!   applied a, or a later op from a's device, when b was authored);
//! - `a` and `b` are **concurrent** iff neither `a → b` nor `b → a`.
//!
//! This is exact: `observed` records, at author time, the highest seq applied
//! from every device, so it captures the real causal past. The scalar Lamport
//! clock is retained **only** as the LWW total-order tiebreak (§4.1) — it no
//! longer decides concurrency (a higher-Lamport concurrent op no longer looks
//! causal). The two roles are now cleanly split.
//!
//! An item is **deleted** iff it has at least one delete op **and every**
//! snapshot op happens-before the greatest-total-order delete (i.e. no edit is
//! concurrent-with or after that delete). Otherwise it is **live** — which
//! yields:
//!
//! - concurrent update vs delete → **edit wins** (the update is not before the
//!   delete), item live, conflict badge derivable — even when the delete has
//!   the higher Lamport (the case the old scalar rule got wrong);
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
use lp_vault::op::{ObservedHeads, OpKind};
use lp_vault::payload::ItemPayload;
use lp_vault::{
    AttachAddPayload, AttachDeletePayload, AttachmentMaterialization, ItemMaterialization,
    Materialization, StoredOp, TombstoneMaterialization, VersionMaterialization,
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

/// One op lifted into merge form: its ordering key, causal summary, kind,
/// target, and — for snapshot ops — its decoded payload.
struct MergeOp {
    op_id: OpId,
    device_id: DeviceId,
    /// Per-device sequence number (sync-protocol.md §5). Together with
    /// `observed` this decides true happens-before ([`MergeOp::happens_before`]).
    seq: u64,
    lamport: u64,
    /// The observed-heads causal summary this op was authored with
    /// (sync-protocol.md §3) — the version vector for happens-before.
    observed: ObservedHeads,
    kind: OpKind,
    created_at: i64,
    /// The decoded full item snapshot for create/update/restore; `None` for
    /// delete/rewrap (which carry no item body).
    payload: Option<ItemPayload>,
}

impl MergeOp {
    /// The total-order key `(lamport, device_id big-endian bytes, op_id bytes)`
    /// (sync-protocol.md §4.1). This decides the LWW winner among *concurrent*
    /// writers; it is **not** used to decide whether two ops are concurrent
    /// (that is [`happens_before`](Self::happens_before)).
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

    /// True happens-before (sync-protocol.md §3/§4.3): does `self → other`?
    ///
    /// - same device: chain order (`self.seq < other.seq`);
    /// - cross device: `other` observed `self` (or a later op from `self`'s
    ///   device) at author time — `other.observed[self.device] >= self.seq`.
    ///
    /// Neither `self → other` nor `other → self` ⇒ the two are **concurrent**.
    fn happens_before(&self, other: &MergeOp) -> bool {
        if self.device_id.as_bytes() == other.device_id.as_bytes() {
            self.seq < other.seq
        } else {
            other.observed.get(&self.device_id) >= self.seq
        }
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
            // Delete/rewrap carry no item body; attachment ops carry an
            // *attachment* payload (resolved in `materialize_attachments`), not
            // an item snapshot — so no item payload is decoded here.
            OpKind::Delete | OpKind::Rewrap | OpKind::AttachAdd | OpKind::AttachDelete => None,
        };
        by_item
            .entry(*item_id.as_bytes())
            .or_default()
            .push(MergeOp {
                op_id: op.op_id,
                device_id: op.device_id,
                seq: op.seq,
                lamport: op.lamport,
                observed: op.observed.clone(),
                kind: op.op_kind,
                created_at: op.created_at,
                payload,
            });
    }

    let mut mat = Materialization {
        ops: ops.to_vec(),
        items: Vec::new(),
        attachments: Vec::new(),
        attachment_tombstones: Vec::new(),
    };
    for (item_bytes, mut item_ops) in by_item {
        item_ops.sort_by(MergeOp::cmp_total);
        if let Some(item_mat) = materialize_item(ItemId::from_bytes(item_bytes), &item_ops, now) {
            mat.items.push(item_mat);
        }
    }

    // Attachment convergence (sync-protocol.md §2): exists iff there is an
    // AttachAdd for its id AND no AttachDelete for that id. Order-independent —
    // no LWW. Concurrent adds have distinct UUIDv7 ids so both survive; a delete
    // tombstones the id so a reordered add cannot resurrect it.
    materialize_attachments(ops, decrypt, &mut mat)?;

    Ok(mat)
}

/// Resolve the surviving attachment set over the whole op set (sync-protocol.md
/// §2). An attachment **exists iff** its id has an `AttachAdd` and **no**
/// `AttachDelete`. Every deleted id becomes a tombstone the apply removes; every
/// surviving id becomes a row to insert (its blob is fetched separately).
fn materialize_attachments(
    ops: &[StoredOp],
    decrypt: &PayloadDecryptor<'_>,
    mat: &mut Materialization,
) -> Result<()> {
    use std::collections::BTreeSet;

    // First pass: collect every AttachDelete's target id (the tombstone set).
    let mut deleted: BTreeSet<String> = BTreeSet::new();
    for op in ops {
        if op.op_kind == OpKind::AttachDelete {
            let plaintext = decrypt(&op.op_id, &op.payload_env)?;
            let payload: AttachDeletePayload =
                serde_json::from_slice(&plaintext).map_err(|_| {
                    crate::Error::Vault(lp_vault::Error::Invalid("attach-delete payload"))
                })?;
            deleted.insert(payload.attachment_id);
        }
    }

    // Second pass: every AttachAdd whose id is NOT tombstoned survives. Dedup by
    // attachment_id so a re-observed AttachAdd yields a single row (idempotent).
    let mut seen: BTreeSet<String> = BTreeSet::new();
    for op in ops {
        if op.op_kind != OpKind::AttachAdd {
            continue;
        }
        let plaintext = decrypt(&op.op_id, &op.payload_env)?;
        let payload: AttachAddPayload = serde_json::from_slice(&plaintext)
            .map_err(|_| crate::Error::Vault(lp_vault::Error::Invalid("attach-add payload")))?;
        if deleted.contains(&payload.attachment_id) || !seen.insert(payload.attachment_id.clone()) {
            continue;
        }
        mat.attachments
            .push(attachment_from_payload(&payload, op.created_at)?);
    }

    // Emit tombstones for every deleted id (idempotent removal on apply).
    for id_hex in &deleted {
        mat.attachment_tombstones.push(parse_id(id_hex)?);
    }
    Ok(())
}

/// Build an [`AttachmentMaterialization`] from a decoded `AttachAdd` payload.
fn attachment_from_payload(
    payload: &AttachAddPayload,
    created_at: i64,
) -> Result<AttachmentMaterialization> {
    Ok(AttachmentMaterialization {
        attachment_id: parse_id(&payload.attachment_id)?,
        item_id: parse_id(&payload.item_id)?,
        version: payload.version,
        content_hash: hex_bytes(&payload.content_hash)?,
        size_plain: payload.size_plain,
        wrapped_key_env: hex_bytes(&payload.wrapped_key_env)?,
        filename_env: hex_bytes(&payload.filename_env)?,
        created_at,
    })
}

/// Parse a 32-char hex id (the AAD id encoding) into an [`ItemId`]/[`AttachmentId`].
fn parse_id(hex: &str) -> Result<lp_vault::ids::Id> {
    let bytes = hex_bytes(hex)?;
    lp_vault::ids::Id::from_slice(&bytes).map_err(crate::Error::Vault)
}

/// Decode an even-length lowercase-hex string into bytes.
fn hex_bytes(hex: &str) -> Result<Vec<u8>> {
    if !hex.len().is_multiple_of(2) {
        return Err(crate::Error::Vault(lp_vault::Error::Invalid(
            "attach payload: odd-length hex",
        )));
    }
    let mut out = Vec::with_capacity(hex.len() / 2);
    let b = hex.as_bytes();
    for pair in b.chunks_exact(2) {
        let hi =
            (pair[0] as char)
                .to_digit(16)
                .ok_or(crate::Error::Vault(lp_vault::Error::Invalid(
                    "attach payload: bad hex",
                )))?;
        let lo =
            (pair[1] as char)
                .to_digit(16)
                .ok_or(crate::Error::Vault(lp_vault::Error::Invalid(
                    "attach payload: bad hex",
                )))?;
        out.push(((hi << 4) | lo) as u8);
    }
    Ok(out)
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
///
/// The item is deleted iff there is a delete op **and every** snapshot
/// *happens-before* the canonical delete under true happens-before
/// ([`MergeOp::happens_before`]) — so a snapshot that is concurrent-with or
/// causally-after the delete keeps the item live (edit-wins / revive; §4.3
/// rows 1 & 2). The canonical delete is the greatest-total-order delete that is
/// **not** happens-before any snapshot: a delete the winning edit already
/// observed (an earlier causal delete that a later edit revived) must not be
/// resurrected as the tombstone. When several deletes are mutually concurrent
/// with the edits, the greatest-total-order delete is canonical (idempotent
/// delete-vs-delete).
fn resolve_tombstone(
    ops: &[MergeOp],
    snapshots: &[&MergeOp],
    now: i64,
) -> Option<TombstoneMaterialization> {
    // Candidate deletes = deletes that are NOT causally before some snapshot
    // (a delete a later edit observed has been superseded — revive, §4.3 row 2).
    // Among the survivors, the greatest-total-order one is canonical.
    let canonical_delete = ops
        .iter()
        .filter(|o| o.kind == OpKind::Delete)
        .filter(|d| !snapshots.iter().any(|s| d.happens_before(s)))
        .max_by(|a, b| a.cmp_total(b))?;

    // Edit wins unless *every* snapshot happens-before this delete.
    let all_edits_before_delete = snapshots.iter().all(|s| s.happens_before(canonical_delete));
    if !all_edits_before_delete {
        return None; // live (concurrent edit-vs-delete, or edit-after-delete)
    }

    Some(TombstoneMaterialization {
        deleted_at: now,
        purge_after: now.saturating_add(DEFAULT_RETENTION_MS),
        deleted_by_device: canonical_delete.device_id,
        op_id: canonical_delete.op_id,
    })
}
