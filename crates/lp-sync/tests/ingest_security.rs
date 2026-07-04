//! Ingest-security tests (sync-protocol.md §5): the verifier detects and
//! quarantines tamper / replay / drop / rollback / untrusted-author, and holds
//! genuine gaps pending rather than alarming. These operate at the pure
//! `verify` layer with real Ed25519-signed ops (no vault / KDF needed — the
//! payload bytes are opaque to signature verification).

use std::collections::{BTreeMap, BTreeSet};

use lp_crypto::SigningKeyPair;
use lp_sync::Alarm;
use lp_sync::verify::{self, ChainState, DeviceChainState};
use lp_vault::op::{ItemTarget, ObservedHeads, OpFields, OpKind, chain_hash, genesis_hash};
use lp_vault::{Id, StoredOp};

/// A tiny signer that produces a valid §5 chain for one device.
struct Signer {
    device_id: lp_vault::DeviceId,
    vault_id: lp_vault::VaultId,
    kp: SigningKeyPair,
    seq: u64,
    prev_full: Option<Vec<u8>>,
}

impl Signer {
    fn new() -> Self {
        Self {
            device_id: Id::from_bytes([7u8; 16]),
            vault_id: Id::from_bytes([2u8; 16]),
            kp: SigningKeyPair::generate(),
            seq: 0,
            prev_full: None,
        }
    }

    /// Author the next valid op at `lamport` with an arbitrary payload.
    fn next(&mut self, lamport: u64) -> StoredOp {
        self.seq += 1;
        let op_id = Id::new();
        let prev_hash = self.prev_full.as_ref().map_or_else(
            || genesis_hash(&self.vault_id, &self.device_id),
            |b| chain_hash(b),
        );
        let payload_env = vec![0xAB, 0xCD, self.seq as u8];
        // A self-consistent causal summary: this device's own prior head.
        let observed = ObservedHeads::from_pairs([(*self.device_id.as_bytes(), self.seq - 1)]);
        let fields = OpFields {
            op_id,
            vault_id: self.vault_id,
            device_id: self.device_id,
            seq: self.seq,
            prev_hash,
            lamport,
            op_kind: OpKind::Create,
            target_item: ItemTarget::item(&Id::from_bytes([4u8; 16])),
            target_version: 1,
            payload_env: payload_env.clone(),
            observed: observed.clone(),
        };
        let signature = fields.sign(&self.kp).unwrap();
        self.prev_full = Some(fields.full_bytes(&signature));
        StoredOp {
            op_id,
            vault_id: self.vault_id,
            device_id: self.device_id,
            seq: self.seq,
            prev_hash,
            lamport,
            op_kind: OpKind::Create,
            target_item: Some(Id::from_bytes([4u8; 16])),
            target_version: 1,
            payload_env,
            observed,
            signature,
            created_at: 0,
        }
    }
}

/// A `ChainState` trusting `signer`'s device with a fresh (no-local-ops) chain.
fn trusting_state(signer: &Signer) -> ChainState {
    let mut devices = BTreeMap::new();
    devices.insert(
        *signer.device_id.as_bytes(),
        DeviceChainState {
            verifying_key: signer.kp.verifying_key(),
            last_seq: 0,
            last_op_full_bytes: None,
            last_lamport: 0,
            known_op_ids: BTreeSet::new(),
        },
    );
    ChainState {
        vault_id: signer.vault_id,
        devices,
    }
}

#[test]
fn clean_chain_is_fully_accepted() {
    let mut s = Signer::new();
    let ops = vec![s.next(1), s.next(2), s.next(3)];
    let report = verify::verify_batch(&trusting_state(&s), &ops);
    assert_eq!(report.accepted.len(), 3);
    assert!(!report.has_alarms());
}

#[test]
fn untrusted_device_is_rejected() {
    let mut s = Signer::new();
    let ops = vec![s.next(1)];
    // Empty device map ⇒ the author is untrusted.
    let state = ChainState {
        vault_id: s.vault_id,
        devices: BTreeMap::new(),
    };
    let report = verify::verify_batch(&state, &ops);
    assert!(report.accepted.is_empty());
    assert_eq!(report.quarantines.len(), 1);
    assert_eq!(report.quarantines[0].alarm, Alarm::UnknownDevice);
}

#[test]
fn tampered_payload_fails_signature() {
    let mut s = Signer::new();
    let mut op = s.next(1);
    // Flip a payload byte after signing ⇒ the signature no longer verifies.
    op.payload_env[0] ^= 0xFF;
    let report = verify::verify_batch(&trusting_state(&s), &[op]);
    assert!(report.accepted.is_empty());
    assert_eq!(report.quarantines[0].alarm, Alarm::SignatureInvalid);
}

#[test]
fn dropped_segment_holds_pending_not_alarm() {
    let mut s = Signer::new();
    let op1 = s.next(1);
    let _op2_dropped = s.next(2);
    let op3 = s.next(3);
    // Deliver op1 and op3 but not op2 (a dropped middle segment).
    let report = verify::verify_batch(&trusting_state(&s), &[op1, op3]);
    // op1 applies; op3 is held pending (gap at seq 2), and NO alarm fires.
    assert_eq!(report.accepted.len(), 1);
    assert_eq!(report.accepted[0].seq, 1);
    assert_eq!(report.pending.len(), 1);
    assert_eq!(report.pending[0].seq, 3);
    assert!(!report.has_alarms());
}

#[test]
fn replayed_old_segment_is_idempotent_noop() {
    let mut s = Signer::new();
    let op1 = s.next(1);
    let op2 = s.next(2);
    // The vault already holds op1 (known) with op2 not yet applied.
    let mut state = trusting_state(&s);
    let chain = state.devices.get_mut(s.device_id.as_bytes()).unwrap();
    chain.last_seq = 1;
    chain.last_op_full_bytes = Some(verify::op_full_bytes(&op1));
    chain.last_lamport = 1;
    chain.known_op_ids.insert(*op1.op_id.as_bytes());

    // Re-deliver op1 (replay) plus the new op2.
    let report = verify::verify_batch(&state, &[op1, op2.clone()]);
    assert_eq!(report.skipped_idempotent, 1, "the re-read op1 is a no-op");
    assert_eq!(report.accepted.len(), 1);
    assert_eq!(report.accepted[0].seq, 2);
    assert!(!report.has_alarms());
}

#[test]
fn seq_regression_alarms() {
    let mut s = Signer::new();
    let op1 = s.next(1);
    let op2 = s.next(2);
    // Local state has already applied through seq 2.
    let mut state = trusting_state(&s);
    let chain = state.devices.get_mut(s.device_id.as_bytes()).unwrap();
    chain.last_seq = 2;
    chain.last_op_full_bytes = Some(verify::op_full_bytes(&op2));
    chain.last_lamport = 2;
    chain.known_op_ids.insert(*op1.op_id.as_bytes());
    chain.known_op_ids.insert(*op2.op_id.as_bytes());

    // A DIFFERENT op claiming seq 1 (rollback attempt).
    let mut forged = op1.clone();
    forged.op_id = Id::new();
    forged.payload_env = vec![0xFF];
    let report = verify::verify_batch(&state, &[forged]);
    assert_eq!(report.quarantines[0].alarm, Alarm::SeqRegression);
}

#[test]
fn chain_mismatch_alarms_on_forked_prev_hash() {
    let mut s = Signer::new();
    let op1 = s.next(1);
    let mut op2 = s.next(2);
    // Corrupt op2's prev_hash (a rewritten history), then RE-SIGN so the
    // signature is valid but the chain link is wrong.
    op2.prev_hash = [0x00; 32];
    let fields = OpFields {
        op_id: op2.op_id,
        vault_id: op2.vault_id,
        device_id: op2.device_id,
        seq: op2.seq,
        prev_hash: op2.prev_hash,
        lamport: op2.lamport,
        op_kind: op2.op_kind,
        target_item: ItemTarget::item(&op2.target_item.unwrap()),
        target_version: op2.target_version,
        payload_env: op2.payload_env.clone(),
        observed: op2.observed.clone(),
    };
    op2.signature = fields.sign(&s.kp).unwrap();

    let report = verify::verify_batch(&trusting_state(&s), &[op1, op2]);
    // op1 accepted; op2's prev_hash does not chain ⇒ ChainMismatch.
    assert_eq!(report.accepted.len(), 1);
    assert_eq!(report.quarantines[0].alarm, Alarm::ChainMismatch);
}

#[test]
fn lamport_regression_alarms() {
    let mut s = Signer::new();
    let op1 = s.next(5);
    // op2 has a LOWER lamport than op1 (non-monotone author clock). Author it
    // with a valid chain but a regressed lamport.
    let op2 = s.next(2);
    let report = verify::verify_batch(&trusting_state(&s), &[op1, op2]);
    assert_eq!(report.accepted.len(), 1);
    assert_eq!(report.quarantines[0].alarm, Alarm::LamportRegression);
}

#[test]
fn quarantine_halts_the_device_but_not_others() {
    // Device A is clean; device B tampers. A's ops still apply.
    let mut a = Signer::new();
    a.device_id = Id::from_bytes([0xAA; 16]);
    let mut b = Signer::new();
    b.device_id = Id::from_bytes([0xBB; 16]);

    let a1 = a.next(1);
    let a2 = a.next(2);
    let mut b1 = b.next(1);
    b1.payload_env[0] ^= 0xFF; // tamper ⇒ signature invalid

    let mut devices = BTreeMap::new();
    devices.insert(
        *a.device_id.as_bytes(),
        DeviceChainState {
            verifying_key: a.kp.verifying_key(),
            last_seq: 0,
            last_op_full_bytes: None,
            last_lamport: 0,
            known_op_ids: BTreeSet::new(),
        },
    );
    devices.insert(
        *b.device_id.as_bytes(),
        DeviceChainState {
            verifying_key: b.kp.verifying_key(),
            last_seq: 0,
            last_op_full_bytes: None,
            last_lamport: 0,
            known_op_ids: BTreeSet::new(),
        },
    );
    let state = ChainState {
        vault_id: a.vault_id,
        devices,
    };
    let report = verify::verify_batch(&state, &[a1, a2, b1]);
    // A's two ops accepted; B quarantined.
    assert_eq!(report.accepted.len(), 2);
    assert!(
        report
            .accepted
            .iter()
            .all(|o| o.device_id.as_bytes() == a.device_id.as_bytes())
    );
    assert_eq!(report.quarantines.len(), 1);
    assert_eq!(
        report.quarantines[0].device_id.as_bytes(),
        b.device_id.as_bytes()
    );
}
