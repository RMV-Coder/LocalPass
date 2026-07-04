//! The ingest verifier (sync-protocol.md §5) — Part A.
//!
//! For a stream of foreign-device ops entering a local vault, per author device
//! and in `seq` order, verify:
//!
//! 1. **Signature** — Ed25519 over fields 1..10 under the author's *pinned*
//!    public key (from `peer_devices`). Unknown device → reject.
//! 2. **Seq contiguity** — each op's `seq` is exactly `last_seen + 1`.
//!    - a *gap* (`seq > last_seen + 1`, an earlier op not yet delivered) is
//!      **held pending**, not alarmed (out-of-order file delivery is normal);
//!    - a *regression* (`seq <= last_applied` with different bytes, or a lower
//!      seq than already recorded) alarms (rollback / replay);
//!    - an *exact re-read* of an op we already hold (same `op_id`) is an
//!      idempotent no-op (sync-protocol.md §7.3).
//! 3. **prev_hash chain** — equals the recomputed BLAKE3 of the author's
//!    previous op (fields 1..11). A mismatch alarms (rewritten/forked history).
//! 4. **Lamport monotonicity** — `lamport >= previous op's lamport` for the
//!    author.
//!
//! On any alarm, that op **and every later op from the same device** are
//! quarantined; other devices continue independently (sync-protocol.md §5).
//!
//! # What this module is (and is not)
//!
//! This is the pure verification *policy*. It reads the local chain state via
//! the [`ChainState`] the caller assembles from `lp_vault` (last applied op,
//! pinned keys), takes the incoming ops, and returns a [`VerifyReport`]:
//! the accepted ops (ready for the §4 merge), the pending holds, and the
//! quarantines. It performs no I/O and no state mutation, so it is trivially
//! testable and deterministic.

use std::collections::BTreeMap;

use lp_crypto::{VerifyingKey, blake3_256};
use lp_vault::StoredOp;
use lp_vault::ids::DeviceId;
use lp_vault::op::{OpFields, chain_hash, genesis_hash};

use crate::error::{Alarm, Quarantine};
use crate::wire;

/// The local chain state the verifier needs for one author device: the pinned
/// Ed25519 public key, and the author's last **already-applied** op (for the
/// `seq`/`prev_hash`/`lamport` continuity checks). `None` last op = the author
/// has no ops locally yet (expect `seq == 1`, `prev_hash == genesis`).
#[derive(Clone)]
pub struct DeviceChainState {
    /// The pinned Ed25519 public key of this author (from `peer_devices`).
    pub verifying_key: VerifyingKey,
    /// The author's highest already-applied `seq` (0 if none).
    pub last_seq: u64,
    /// The full canonical bytes (fields 1..11) of the author's last applied op,
    /// whose hash the next op's `prev_hash` must equal. `None` if none yet.
    pub last_op_full_bytes: Option<Vec<u8>>,
    /// The author's last applied op's lamport (for monotonicity; 0 if none).
    pub last_lamport: u64,
    /// The op_ids this vault already holds for this device (idempotent re-read
    /// detection — a re-delivered op we already applied is skipped, not
    /// re-verified or double-applied).
    pub known_op_ids: std::collections::BTreeSet<[u8; 16]>,
}

/// Everything the verifier needs about the whole ingest batch: per-device chain
/// state plus the vault id (to recompute genesis for first ops).
pub struct ChainState {
    /// The vault the ops belong to (genesis-hash input, sync-protocol.md §5).
    pub vault_id: DeviceId,
    /// Per author device, its local chain state. A device *absent* from this
    /// map is **untrusted** → its ops are rejected ([`Alarm::UnknownDevice`]).
    pub devices: BTreeMap<[u8; 16], DeviceChainState>,
}

/// The verifier's outcome for one device's incoming run.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DeviceOutcome {
    /// All presented ops were accepted (ready to merge) — the device is fully
    /// caught up to the presented run.
    Accepted,
    /// A contiguity **gap**: ops from `first_missing_seq` onward are held
    /// pending until the earlier op(s) arrive (not an alarm).
    Pending {
        /// The earliest `seq` we are waiting on before ingest can resume.
        first_missing_seq: u64,
    },
    /// A verification failure quarantined this device from `seq` onward.
    Quarantined(Quarantine),
}

/// The full verification report over an ingest batch.
#[derive(Debug, Default)]
pub struct VerifyReport {
    /// Ops that passed every check, in per-device `seq` order, concatenated
    /// across devices. Feed these to the §4 merge.
    pub accepted: Vec<StoredOp>,
    /// Ops already present locally (idempotent re-reads) — counted, not applied.
    pub skipped_idempotent: usize,
    /// Ops held pending because an earlier op has not arrived, per device.
    pub pending: Vec<StoredOp>,
    /// Quarantine records (typed alarms), one per offending device.
    pub quarantines: Vec<Quarantine>,
    /// Per-device outcome summary (for `status` reporting).
    pub outcomes: Vec<(DeviceId, DeviceOutcome)>,
}

impl VerifyReport {
    /// Whether any device quarantined (any alarm fired).
    #[must_use]
    pub fn has_alarms(&self) -> bool {
        !self.quarantines.is_empty()
    }
}

/// Verify an ingest batch. `incoming` is grouped per device internally; each
/// device's run is processed in ascending `seq`.
///
/// This is a pure function of `(state, incoming)` — no I/O, no mutation.
#[must_use]
pub fn verify_batch(state: &ChainState, incoming: &[StoredOp]) -> VerifyReport {
    // Group incoming ops by author device, each sorted by seq.
    let mut by_device: BTreeMap<[u8; 16], Vec<StoredOp>> = BTreeMap::new();
    for op in incoming {
        by_device
            .entry(*op.device_id.as_bytes())
            .or_default()
            .push(op.clone());
    }
    for run in by_device.values_mut() {
        run.sort_by_key(|o| o.seq);
    }

    let mut report = VerifyReport::default();
    for (dev_bytes, run) in by_device {
        let device_id = DeviceId::from_bytes(dev_bytes);
        let Some(chain) = state.devices.get(&dev_bytes) else {
            // Untrusted author: reject the whole run at its first seq.
            let first_seq = run.first().map_or(0, |o| o.seq);
            let q = Quarantine {
                device_id,
                seq: first_seq,
                alarm: Alarm::UnknownDevice,
            };
            report.quarantines.push(q);
            report
                .outcomes
                .push((device_id, DeviceOutcome::Quarantined(q)));
            continue;
        };
        let outcome = verify_device_run(state.vault_id, device_id, chain, &run, &mut report);
        report.outcomes.push((device_id, outcome));
    }
    report
}

/// Verify one device's ascending-seq run; append accepted/pending ops and any
/// quarantine to `report`, and return the device's [`DeviceOutcome`].
fn verify_device_run(
    vault_id: DeviceId,
    device_id: DeviceId,
    chain: &DeviceChainState,
    run: &[StoredOp],
    report: &mut VerifyReport,
) -> DeviceOutcome {
    // Rolling state as we accept ops within this batch.
    let mut expected_seq = chain.last_seq + 1;
    let mut prev_full = chain
        .last_op_full_bytes
        .as_ref()
        .map_or_else(|| genesis_hash(&vault_id, &device_id), |b| chain_hash(b));
    let mut last_lamport = chain.last_lamport;

    for op in run {
        // Idempotent re-read: an op we already hold is skipped (not re-applied,
        // not re-verified). It also does not advance our rolling state — the
        // stored copy already did.
        if chain.known_op_ids.contains(op.op_id.as_bytes()) {
            report.skipped_idempotent += 1;
            // If this known op is the one at `expected_seq`, advance past it so
            // a later new op in the same run stays contiguous.
            if op.seq == expected_seq {
                expected_seq += 1;
                prev_full = chain_hash(&wire::encode_op(op));
                last_lamport = op.lamport;
            }
            continue;
        }

        // Regression / replay: a seq at or below what we already applied, but
        // with bytes we do not have, is a rollback/fork (T13).
        if op.seq < expected_seq {
            let alarm = if op.seq <= chain.last_seq {
                Alarm::SeqRegression
            } else {
                Alarm::SeqReplay
            };
            return quarantine(device_id, op.seq, alarm, report);
        }

        // Gap: an earlier op has not been delivered yet. Hold this and the rest
        // pending (NOT an alarm) — out-of-order file delivery is expected.
        if op.seq > expected_seq {
            report.pending.push(op.clone());
            // Everything after a gap is also pending (kept contiguous by seq).
            for later in run.iter().filter(|o| o.seq > op.seq) {
                if !chain.known_op_ids.contains(later.op_id.as_bytes()) {
                    report.pending.push((*later).clone());
                }
            }
            return DeviceOutcome::Pending {
                first_missing_seq: expected_seq,
            };
        }

        // seq == expected_seq: run the full verification chain.

        // (1) Signature over fields 1..10 under the pinned key.
        if verify_signature(&chain.verifying_key, op).is_err() {
            return quarantine(device_id, op.seq, Alarm::SignatureInvalid, report);
        }
        // (3) prev_hash chains to the recomputed previous-op hash.
        if op.prev_hash != prev_full {
            return quarantine(device_id, op.seq, Alarm::ChainMismatch, report);
        }
        // (4) Lamport monotonicity for this author.
        if op.lamport < last_lamport {
            return quarantine(device_id, op.seq, Alarm::LamportRegression, report);
        }

        // Accept. Advance the rolling state.
        report.accepted.push(op.clone());
        expected_seq += 1;
        prev_full = chain_hash(&wire::encode_op(op));
        last_lamport = op.lamport;
    }

    DeviceOutcome::Accepted
}

/// Record a quarantine and return the matching outcome.
fn quarantine(
    device_id: DeviceId,
    seq: u64,
    alarm: Alarm,
    report: &mut VerifyReport,
) -> DeviceOutcome {
    let q = Quarantine {
        device_id,
        seq,
        alarm,
    };
    report.quarantines.push(q);
    DeviceOutcome::Quarantined(q)
}

/// Verify an op's Ed25519 signature (field 11) over its signed region (fields
/// 1..10) under `key`.
fn verify_signature(key: &VerifyingKey, op: &StoredOp) -> crate::error::Result<()> {
    let fields = op_fields(op);
    fields
        .verify(key, &op.signature)
        .map_err(crate::error::Error::from)
}

/// Reconstruct `OpFields` (fields 1..10 + prev_hash) from a [`StoredOp`] for
/// signature verification (reuses lp-vault's canonical encoder via `verify`).
fn op_fields(op: &StoredOp) -> OpFields {
    use lp_vault::op::ItemTarget;
    let target = match &op.target_item {
        Some(id) => ItemTarget::item(id),
        None => ItemTarget::none(),
    };
    OpFields {
        op_id: op.op_id,
        vault_id: op.vault_id,
        device_id: op.device_id,
        seq: op.seq,
        prev_hash: op.prev_hash,
        lamport: op.lamport,
        op_kind: op.op_kind,
        target_item: target,
        target_version: op.target_version,
        payload_env: op.payload_env.clone(),
    }
}

/// Recompute the full-op hash of `op` (fields 1..11) — the value the *next*
/// op's `prev_hash` must equal. Exposed for the caller to seed
/// [`DeviceChainState::last_op_full_bytes`] consistently.
#[must_use]
pub fn op_full_bytes(op: &StoredOp) -> Vec<u8> {
    wire::encode_op(op)
}

/// The BLAKE3-256 of an op's full bytes (the chain link). Thin re-export so the
/// engine and tests do not re-derive the hashing.
#[must_use]
pub fn op_chain_hash(op: &StoredOp) -> [u8; 32] {
    blake3_256(&wire::encode_op(op))
}
