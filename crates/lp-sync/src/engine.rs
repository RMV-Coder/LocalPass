//! The sync engine: `setup` / `push` / `pull` / `status` over a live
//! [`Session`] + [`Vault`], wiring the §5 verifier, the §4 merge, and the §7
//! file shipping together (sync-protocol.md §7.3 reader algorithm).
//!
//! # Layering
//!
//! ```text
//!   engine (this)  ── drives ──►  verify (§5)  ──►  merge (§4)  ──►  lp-vault apply (§7 atomicity)
//!        │
//!        └── reads/writes ──►  shipping (§7 files)
//! ```
//!
//! The engine holds no key material of its own: it borrows the unlocked
//! [`Session`]/[`Vault`] and calls their additive foreign-op API. Verification
//! and merge are pure functions the engine feeds; only `pull`'s final apply
//! mutates the vault (in one transaction per batch, vault-format.md §7).

use std::collections::{BTreeMap, BTreeSet};

use lp_crypto::VerifyingKey;
use lp_vault::ids::{DeviceId, VaultId};
use lp_vault::{Session, StoredOp, Vault};

use crate::error::{Error, Quarantine, Result};
use crate::merge;
use crate::shipping::{Manifest, SyncDir};
use crate::verify::{self, ChainState, DeviceChainState};

/// The account-store settings key holding a vault's enrolled sync-root dir.
fn sync_root_key(vault_id: &VaultId) -> String {
    format!("sync.root.{}", vault_id.to_hyphenated())
}

/// Enroll a vault for file-based sync under `sync_root` (`localpass sync setup`).
/// Stores the root in the account-store `settings` table and creates the
/// per-vault directory scaffold (sync-protocol.md §7.1).
///
/// # Errors
///
/// [`Error::Vault`] / [`Error::Io`] on failure.
pub fn setup(session: &Session, vault_id: VaultId, sync_root: &std::path::Path) -> Result<()> {
    // Materialize the directory (validates it is creatable) and record the root.
    SyncDir::open(sync_root, vault_id)?;
    session.set_setting(&sync_root_key(&vault_id), &sync_root.to_string_lossy())?;
    Ok(())
}

/// The enrolled sync-root path for a vault, if `setup` has run.
///
/// # Errors
///
/// [`Error::Vault`] on a read failure.
pub fn enrolled_root(session: &Session, vault_id: VaultId) -> Result<Option<std::path::PathBuf>> {
    Ok(session
        .get_setting(&sync_root_key(&vault_id))?
        .map(std::path::PathBuf::from))
}

/// Resolve the enrolled sync dir for a vault, erroring if not enrolled.
fn open_dir(session: &Session, vault_id: VaultId) -> Result<SyncDir> {
    let root = enrolled_root(session, vault_id)?.ok_or(Error::Invalid(
        "vault is not enrolled for sync (run `sync setup`)",
    ))?;
    SyncDir::open(&root, vault_id)
}

/// The outcome of a `push`.
#[derive(Clone, Debug, Default)]
pub struct PushReport {
    /// Per device, the highest `seq` now published to the channel
    /// `(device_id, high_water_seq)`.
    pub published: Vec<(DeviceId, u64)>,
    /// Number of segment files written (new; excludes already-present ranges).
    pub segments_written: usize,
}

/// Publish this vault's ops (this device's own ops **and** re-publishable peer
/// ops it holds — store-and-forward for offline peers) as segment files, then
/// refresh the advisory manifest and chain heads (sync-protocol.md §7.1/§7.3).
///
/// Each device's ops are written as **one** contiguous segment spanning
/// `[1, last_seq]`; an unchanged range is skipped (idempotent re-push).
///
/// # Errors
///
/// [`Error::Vault`] / [`Error::Io`] on failure.
pub fn push(session: &Session, vault: &Vault<'_>) -> Result<PushReport> {
    let vault_id = vault.vault_id();
    let dir = open_dir(session, vault_id)?;

    // Group all stored ops by author device, ascending seq.
    let ops = vault.stored_ops()?;
    let mut by_device: BTreeMap<[u8; 16], Vec<StoredOp>> = BTreeMap::new();
    for op in ops {
        by_device
            .entry(*op.device_id.as_bytes())
            .or_default()
            .push(op);
    }

    let mut report = PushReport::default();
    let mut manifest = Manifest {
        vault_id: vault_id.to_hyphenated(),
        devices: BTreeMap::new(),
    };
    for (dev_bytes, mut run) in by_device {
        run.sort_by_key(|o| o.seq);
        let device_id = DeviceId::from_bytes(dev_bytes);
        let last_seq = run.last().map_or(0, |o| o.seq);
        // One segment covering the whole contiguous [1, last_seq] range.
        if let Some(seg) = dir.write_segment(&run)? {
            // Count only freshly-written files (write_segment returns the
            // existing one without rewriting if the range is already present).
            report.segments_written += 1;
            let head_hash = verify::op_chain_hash(run.last().unwrap());
            dir.write_head(&device_id, seg.seq_hi, &head_hash)?;
        }
        report.published.push((device_id, last_seq));
        manifest.devices.insert(device_id.to_hyphenated(), last_seq);
    }
    dir.write_manifest(&manifest)?;
    Ok(report)
}

/// The outcome of a `pull`.
#[derive(Clone, Debug, Default)]
pub struct PullReport {
    /// Number of foreign ops verified and applied.
    pub applied: usize,
    /// Number of ops skipped as idempotent re-reads (already held).
    pub skipped: usize,
    /// Number of ops held pending (an earlier op has not arrived yet).
    pub pending: usize,
    /// Quarantines (typed alarms) raised during ingest.
    pub quarantines: Vec<Quarantine>,
    /// Whether a shared-VaultKey blob addressed to this device was found (Part D
    /// key import; the actual unwrap is gated — see [`import_shared_key`]).
    pub key_blob_present: bool,
}

impl PullReport {
    /// Whether any alarm fired (any device quarantined).
    #[must_use]
    pub fn has_alarms(&self) -> bool {
        !self.quarantines.is_empty()
    }
}

/// Read the channel, verify every foreign op (§5), merge (§4), and apply into
/// the vault atomically (§7.3 reader algorithm). Idempotent: re-reading an
/// already-applied segment is a no-op.
///
/// # Errors
///
/// [`Error::Vault`] / [`Error::Io`] / [`Error::Malformed`] on failure. A
/// verification alarm is **not** an error — it is reported in
/// [`PullReport::quarantines`] and halts only the offending device.
pub fn pull(session: &Session, vault: &Vault<'_>) -> Result<PullReport> {
    let vault_id = vault.vault_id();
    let dir = open_dir(session, vault_id)?;

    // 1) Read every op from the channel (per-device, seq_lo order).
    let channel_ops = dir.read_all_ops()?;

    // 2) Build the verifier's per-device chain state from local storage +
    //    pinned peer keys, then filter to ops we do NOT already hold.
    let state = build_chain_state(session, vault, vault_id, &channel_ops)?;

    // Drop this device's OWN ops from the incoming set (we authored them; the
    // channel may echo them back via store-and-forward). We only ingest peers.
    let self_id = session.device_id();
    let incoming: Vec<StoredOp> = channel_ops
        .into_iter()
        .filter(|o| o.device_id.as_bytes() != self_id.as_bytes())
        .collect();

    // 3) Verify (§5).
    let vreport = verify::verify_batch(&state, &incoming);

    let mut report = PullReport {
        skipped: vreport.skipped_idempotent,
        pending: vreport.pending.len(),
        quarantines: vreport.quarantines.clone(),
        ..Default::default()
    };

    // 4) Merge (§4) + apply (§7 atomicity). We fold the WHOLE op set — local
    //    ops plus the newly-accepted foreign ops — so materialization is a pure
    //    function of the complete set (convergence, §4.4).
    if !vreport.accepted.is_empty() {
        let now = lp_vault::db::now_millis();

        // Wire-decoded foreign ops carry no trustworthy insert time (`created_at`
        // is not signed and not on the wire), so stamp the local ingest time.
        // This is the version/tombstone `created_at` for the applied rows;
        // it never affects the merge order (which uses lamport/device/op_id).
        let accepted: Vec<StoredOp> = vreport
            .accepted
            .iter()
            .cloned()
            .map(|mut op| {
                op.created_at = now;
                op
            })
            .collect();

        let mut full_set = vault.stored_ops()?;
        full_set.extend(accepted.iter().cloned());

        let decrypt = |op_id: &lp_vault::ids::OpId, env: &[u8]| -> Result<Vec<u8>> {
            vault.decrypt_op_payload(op_id, env).map_err(Error::from)
        };
        let mut mat = merge::materialize(&full_set, &decrypt, now)?;
        // Only the newly-accepted ops need INSERTing; the local ones are already
        // recorded. Restrict the op rows to the accepted set (idempotent insert
        // skips any that slipped through anyway).
        mat.ops = accepted.clone();
        // Restrict the item rewrites to items an accepted foreign op actually
        // touched — folding the full set is required for *correct* per-item
        // resolution, but rewriting untouched local-only items every pull is
        // wasteful (and re-seals their versions needlessly). Correctness is
        // unchanged: the merge is deterministic, so an untouched item's
        // materialization equals its current on-disk state.
        let touched: BTreeSet<[u8; 16]> = accepted
            .iter()
            .filter_map(|o| o.target_item.map(|i| *i.as_bytes()))
            .collect();
        mat.items
            .retain(|it| touched.contains(it.item_id.as_bytes()));
        vault.apply_foreign_ops(&mat)?;
        report.applied = vreport.accepted.len();
    }

    // 5) A shared-VaultKey blob addressed to us? (Part D — import is gated.)
    report.key_blob_present = dir.read_key_blob(&self_id)?.is_some();

    Ok(report)
}

/// Build the §5 [`ChainState`]: for every device that appears in `incoming`
/// (except this device), gather its pinned Ed25519 key (from `peer_devices`)
/// and its local chain tail (last applied op bytes, seq, lamport, known op_ids).
fn build_chain_state(
    session: &Session,
    vault: &Vault<'_>,
    vault_id: VaultId,
    incoming: &[StoredOp],
) -> Result<ChainState> {
    let self_id = session.device_id();
    let mut devices: BTreeMap<[u8; 16], DeviceChainState> = BTreeMap::new();

    // Which foreign devices does the incoming batch reference?
    let mut foreign: BTreeSet<[u8; 16]> = BTreeSet::new();
    for op in incoming {
        if op.device_id.as_bytes() != self_id.as_bytes() {
            foreign.insert(*op.device_id.as_bytes());
        }
    }

    for dev_bytes in foreign {
        let device_id = DeviceId::from_bytes(dev_bytes);
        // Untrusted device → omit from the map so the verifier rejects it.
        let Some(peer) = session.peer_device(&device_id)? else {
            continue;
        };
        let verifying_key = VerifyingKey::from_bytes(&peer.ed25519_pub)
            .map_err(|e| Error::Vault(lp_vault::Error::Crypto(e)))?;

        // Local chain tail for this author.
        let local_ops = vault.stored_ops_for(&device_id)?;
        let last = local_ops.last();
        let last_seq = last.map_or(0, |o| o.seq);
        let last_lamport = last.map_or(0, |o| o.lamport);
        let last_op_full_bytes = last.map(verify::op_full_bytes);
        let known_op_ids: BTreeSet<[u8; 16]> =
            local_ops.iter().map(|o| *o.op_id.as_bytes()).collect();

        devices.insert(
            dev_bytes,
            DeviceChainState {
                verifying_key,
                last_seq,
                last_op_full_bytes,
                last_lamport,
                known_op_ids,
            },
        );
    }

    Ok(ChainState { vault_id, devices })
}

/// Per-device sync status: high-water marks + pending/quarantined counts
/// (`localpass sync status`, sync-protocol.md §7.3).
#[derive(Clone, Debug, Default)]
pub struct SyncStatus {
    /// Whether the vault is enrolled for sync.
    pub enrolled: bool,
    /// The enrolled sync-root (if any).
    pub root: Option<String>,
    /// Per device: `(local_high_water, channel_high_water)` seq marks.
    pub devices: Vec<DeviceStatus>,
    /// Ops currently held pending across all peers.
    pub pending: usize,
    /// Quarantines currently in effect (recomputed from a dry verify).
    pub quarantines: Vec<Quarantine>,
}

/// Per-device seq marks for `status`.
#[derive(Clone, Debug)]
pub struct DeviceStatus {
    /// The device id.
    pub device_id: DeviceId,
    /// Whether this is the local (self) device.
    pub is_self: bool,
    /// Whether this device is a trusted peer (or self).
    pub trusted: bool,
    /// Highest `seq` applied locally for this device.
    pub local_seq: u64,
    /// Highest `seq` this device has published to the channel (advisory).
    pub channel_seq: u64,
}

/// Compute `sync status` without mutating anything: local vs channel seq marks,
/// plus a dry verify to surface pending/quarantine counts.
///
/// # Errors
///
/// [`Error::Vault`] / [`Error::Io`] on failure.
pub fn status(session: &Session, vault: &Vault<'_>) -> Result<SyncStatus> {
    let vault_id = vault.vault_id();
    let self_id = session.device_id();

    let root = enrolled_root(session, vault_id)?;
    let Some(root_path) = root.clone() else {
        return Ok(SyncStatus {
            enrolled: false,
            ..Default::default()
        });
    };
    let dir = SyncDir::open(&root_path, vault_id)?;
    let manifest = dir.read_manifest();
    let channel_ops = dir.read_all_ops()?;

    // Local high-water per device.
    let mut local_high: BTreeMap<[u8; 16], u64> = BTreeMap::new();
    for op in vault.stored_ops()? {
        let e = local_high.entry(*op.device_id.as_bytes()).or_insert(0);
        *e = (*e).max(op.seq);
    }

    // Channel high-water per device (from actual segment ops, not the advisory
    // manifest — trust the ops, §7.2).
    let mut channel_high: BTreeMap<[u8; 16], u64> = BTreeMap::new();
    for op in &channel_ops {
        let e = channel_high.entry(*op.device_id.as_bytes()).or_insert(0);
        *e = (*e).max(op.seq);
    }

    // Dry verify to surface pending/quarantine counts (no apply).
    let incoming: Vec<StoredOp> = channel_ops
        .iter()
        .filter(|o| o.device_id.as_bytes() != self_id.as_bytes())
        .cloned()
        .collect();
    let state = build_chain_state(session, vault, vault_id, &incoming)?;
    let vreport = verify::verify_batch(&state, &incoming);

    // Union of device ids across local + channel.
    let mut all: BTreeSet<[u8; 16]> = BTreeSet::new();
    all.extend(local_high.keys().copied());
    all.extend(channel_high.keys().copied());

    let mut devices = Vec::new();
    for dev_bytes in all {
        let device_id = DeviceId::from_bytes(dev_bytes);
        let is_self = dev_bytes == *self_id.as_bytes();
        let trusted = is_self || session.peer_device(&device_id)?.is_some();
        devices.push(DeviceStatus {
            device_id,
            is_self,
            trusted,
            local_seq: local_high.get(&dev_bytes).copied().unwrap_or(0),
            channel_seq: channel_high.get(&dev_bytes).copied().unwrap_or(0),
        });
    }

    let _ = manifest; // manifest is advisory; status trusts the ops.
    Ok(SyncStatus {
        enrolled: true,
        root: Some(root_path.to_string_lossy().into_owned()),
        devices,
        pending: vreport.pending.len(),
        quarantines: vreport.quarantines,
    })
}

/// Check whether a shared-VaultKey blob addressed to this device is waiting on
/// the channel, and report the gap: importing it requires a raw-key transport
/// primitive not exposed across the `lp-crypto` boundary in this build.
///
/// The blob shipping (`vault share-to-device`) and this detection are fully
/// wired; only the final unseal→register step is gated (see [`Error::KeySharingUnavailable`]).
///
/// # Errors
///
/// Always returns [`Error::KeySharingUnavailable`] when a blob is present (the
/// documented boundary gap); `Ok(false)` when no blob is present.
pub fn import_shared_key(session: &Session, vault_id: VaultId) -> Result<bool> {
    let dir = open_dir(session, vault_id)?;
    let self_id = session.device_id();
    if dir.read_key_blob(&self_id)?.is_some() {
        return Err(Error::KeySharingUnavailable(
            "unwrapping a peer-sealed VaultKey needs a raw-key bridge behind the lp-crypto boundary",
        ));
    }
    Ok(false)
}
