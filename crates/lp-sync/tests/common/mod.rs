//! Shared test harness: build real accounts/vaults, simulate peer devices that
//! author genuine signed ops into a shared vault, and drive the sync engine.
//!
//! A "simulated peer" is a real Ed25519 signing identity (via `lp_crypto`) whose
//! ops are assembled as canonical, signed, hash-chained [`StoredOp`]s — exactly
//! the bytes a real second device sharing the VaultKey would produce. The op
//! payloads are sealed under the *local* vault's shared VaultKey through the
//! additive `Vault::seal_op_payload` seam, so they decrypt on ingest just like
//! real peer ops (single-user multi-device: one VaultKey across devices).

#![allow(dead_code)]

use lp_crypto::{SigningKeyPair, blake3_256};
use lp_vault::op::{ItemTarget, OpFields, OpKind, chain_hash, genesis_hash};
use lp_vault::payload::{ItemPayload, TypeData};
use lp_vault::{AccountStore, Id, Session, StoredOp, Vault, VaultId};

/// The Ed25519 signing context ops are signed under (mirrors
/// `lp_vault::op::OP_SIGN_CONTEXT`).
const OP_SIGN_CONTEXT: &str = "localpass/v1/op";

/// A live local account + one vault, in an isolated temp profile.
pub struct TestVault {
    pub _dir: tempfile::TempDir,
    pub session: Session,
    pub vault_id: VaultId,
}

/// Create a fresh account + a `personal` vault in a temp profile.
pub fn new_vault() -> TestVault {
    let dir = tempfile::tempdir().unwrap();
    let (session, _sk) = AccountStore::create(dir.path(), "correct horse battery").unwrap();
    let vault_id = session.create_vault("personal").unwrap();
    TestVault {
        _dir: dir,
        session,
        vault_id,
    }
}

/// A simulated peer device: a signing identity plus a rolling per-device chain
/// (seq, prev_hash, lamport) so authored ops form a valid §5 chain.
pub struct PeerDevice {
    pub device_id: lp_vault::DeviceId,
    pub signing: SigningKeyPair,
    seq: u64,
    prev_full: Option<Vec<u8>>,
    lamport: u64,
}

impl PeerDevice {
    /// Generate a fresh peer identity.
    #[must_use]
    pub fn new() -> Self {
        Self {
            device_id: Id::new(),
            signing: SigningKeyPair::generate(),
            seq: 0,
            prev_full: None,
            lamport: 0,
        }
    }

    /// This peer's Ed25519 public key bytes.
    #[must_use]
    pub fn ed25519_pub(&self) -> [u8; 32] {
        self.signing.verifying_key().to_bytes()
    }

    /// Register this peer as trusted in `session`'s `peer_devices` (an X25519
    /// key is required by the schema; a throwaway all-zero-ish placeholder is
    /// fine for op-signature verification, which only uses the Ed25519 key).
    pub fn trust_in(&self, session: &Session) {
        session
            .trust_peer_device(
                &self.device_id,
                &self.ed25519_pub(),
                &[0u8; 32],
                Some("peer"),
            )
            .unwrap();
    }

    /// Author the next op for this peer at an explicit `lamport`, sealing the
    /// payload under `vault`'s shared VaultKey. Returns the signed [`StoredOp`].
    pub fn author(
        &mut self,
        vault: &Vault<'_>,
        kind: OpKind,
        item: lp_vault::ItemId,
        target_version: u32,
        lamport: u64,
        payload_plaintext: &[u8],
    ) -> StoredOp {
        let op_id = Id::new();
        self.seq += 1;
        self.lamport = self.lamport.max(lamport);

        let payload_env = vault.seal_op_payload(&op_id, payload_plaintext).unwrap();
        let prev_hash = self.prev_full.as_ref().map_or_else(
            || genesis_hash(&vault.vault_id(), &self.device_id),
            |b| chain_hash(b),
        );

        let fields = OpFields {
            op_id,
            vault_id: vault.vault_id(),
            device_id: self.device_id,
            seq: self.seq,
            prev_hash,
            lamport,
            op_kind: kind,
            target_item: ItemTarget::item(&item),
            target_version,
            payload_env: payload_env.clone(),
        };
        let signature = fields.sign(&self.signing).unwrap();
        self.prev_full = Some(fields.full_bytes(&signature));

        StoredOp {
            op_id,
            vault_id: vault.vault_id(),
            device_id: self.device_id,
            seq: self.seq,
            prev_hash,
            lamport,
            op_kind: kind,
            target_item: Some(item),
            target_version,
            payload_env,
            signature,
            created_at: lp_vault::db::now_millis(),
        }
    }

    /// Author a `create`/`update` snapshot op carrying `payload`.
    pub fn snapshot(
        &mut self,
        vault: &Vault<'_>,
        kind: OpKind,
        item: lp_vault::ItemId,
        version: u32,
        lamport: u64,
        payload: &ItemPayload,
    ) -> StoredOp {
        let bytes = payload.to_canonical().unwrap();
        self.author(vault, kind, item, version, lamport, &bytes)
    }

    /// Author a `delete` op (payload `{}`).
    pub fn delete(&mut self, vault: &Vault<'_>, item: lp_vault::ItemId, lamport: u64) -> StoredOp {
        self.author(vault, OpKind::Delete, item, 0, lamport, b"{}")
    }
}

impl Default for PeerDevice {
    fn default() -> Self {
        Self::new()
    }
}

/// A convenience login payload with a single custom field, for conflict tests.
#[must_use]
pub fn login(title: &str, field_value: &str) -> ItemPayload {
    let mut p = ItemPayload::new(TypeData::Login { urls: vec![] }, title);
    p.fields = vec![lp_vault::Field {
        name: "note".into(),
        kind: lp_vault::FieldKind::Text,
        value: serde_json::Value::String(field_value.into()),
    }];
    p
}

/// The full canonical chain hash of an op's wire bytes (test assertion helper).
#[must_use]
pub fn op_hash(op: &StoredOp) -> [u8; 32] {
    blake3_256(&lp_sync::wire::encode_op(op))
}
