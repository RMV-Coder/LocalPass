//! The six-round exchange (`lan-transport.md` §6).
//!
//! In every round the initiator writes first and the responder reads before it
//! writes; what a side writes depends only on earlier rounds, so neither
//! direction ever waits on the other and full TCP buffers cannot deadlock.

use std::collections::{BTreeMap, BTreeSet};

use lp_vault::ids::{DeviceId, Id, VaultId};
use lp_vault::{PeerDevice, Session, StoredOp};

use super::channel::{self, SecureChannel};
use super::message::{
    self, BlobWants, Inventory, MSG_BLOB, MSG_BLOB_WANT, MSG_BLOBS_END, MSG_DONE, MSG_HELLO,
    MSG_INVENTORY, MSG_OPS, MSG_OPS_END,
};
use super::{
    INGEST_BUFFER_BYTES, Local, OPS_BATCH_BYTES, Role, SessionOptions, SessionReport, Stream,
    VaultSyncReport,
};
use crate::engine;
use crate::error::{Error, Result};
use crate::wire;

/// The `LPS2` share-blob magic (`sync-protocol.md` §7.1).
const SHARE_MAGIC: &[u8; 4] = b"LPS2";

/// Run one nearby-sync session over an already-connected `stream`, as `role`:
/// [`handshake`], then [`Linked::exchange`].
///
/// # Errors
///
/// As [`handshake`] and [`Linked::exchange`].
pub fn run<S: Stream, L: Local>(
    stream: S,
    role: Role,
    local: &L,
    options: &SessionOptions,
) -> Result<SessionReport> {
    handshake(stream, role, local, options)?.exchange(local, options)
}

/// Run the handshake (`lan-transport.md` §4) over an already-connected
/// `stream`, as `role`. Any device that is not pinned — or is not
/// `options.expected_peer` when set — is refused here, before anything else
/// is read from it.
///
/// # Errors
///
/// - [`Error::Invalid`] if `options.share` is non-empty without an
///   `expected_peer` (checked before any I/O).
/// - [`Error::Refused`] if the handshake refused the peer.
/// - [`Error::Protocol`] / [`Error::Timeout`] / [`Error::Io`] if the link broke.
pub fn handshake<S: Stream, L: Local>(
    mut stream: S,
    role: Role,
    local: &L,
    options: &SessionOptions,
) -> Result<Linked<S>> {
    if !options.share.is_empty() && options.expected_peer.is_none() {
        return Err(Error::Invalid(
            "sharing a vault over the local network needs the device it is for",
        ));
    }
    let (transport, peer) = channel::handshake(
        &mut stream,
        role,
        local,
        options.expected_peer,
        &options.limits,
    )?;
    Ok(Linked {
        ch: SecureChannel::new(stream, transport, &options.limits),
        peer,
        role,
    })
}

/// A link whose handshake succeeded: the other end is an authenticated, pinned
/// device.
pub struct Linked<S> {
    ch: SecureChannel<S>,
    peer: PeerDevice,
    role: Role,
}

impl<S: Stream> Linked<S> {
    /// The authenticated peer (its pinned `peer_devices` row).
    #[must_use]
    pub fn peer(&self) -> &PeerDevice {
        &self.peer
    }

    /// Run the exchange (`lan-transport.md` §6). Received ops are verified and
    /// merged by [`engine::ingest`], exactly as a file pull would.
    ///
    /// # Errors
    ///
    /// - [`Error::Protocol`] / [`Error::Timeout`] / [`Error::Io`] if the link
    ///   broke or the peer broke the protocol. Ops already verified and applied
    ///   stay applied — every ingest is atomic and idempotent.
    /// - [`Error::Vault`] on a local storage failure, or a vault to share that
    ///   does not exist.
    ///
    /// A verification alarm is not an error: it is in the report
    /// ([`SessionReport::has_alarms`]).
    pub fn exchange<L: Local>(self, local: &L, options: &SessionOptions) -> Result<SessionReport> {
        let Linked { mut ch, peer, role } = self;
        exchange(&mut ch, role, &peer, local, options)
    }
}

fn exchange<S: Stream, L: Local>(
    ch: &mut SecureChannel<S>,
    role: Role,
    peer: &PeerDevice,
    local: &L,
    options: &SessionOptions,
) -> Result<SessionReport> {
    let mut report = SessionReport {
        peer: peer.device_id,
        peer_label: peer.label.clone(),
        vaults: Vec::new(),
        shares_sent: Vec::new(),
        shares_adopted: Vec::new(),
        shares_rejected: Vec::new(),
    };

    // Round 1 — HELLO: vault-key shares for this peer.
    let shares = local.with_session(|s| build_shares(s, peer, &options.share))?;
    let hello = message::encode_hello(&shares)?;
    let theirs = round(ch, role, MSG_HELLO, &hello)?;
    report.shares_sent = shares.iter().map(|(v, _)| *v).collect();
    let received = message::decode_hello(&theirs)?;
    local.with_session(|s| import_shares(s, peer, received, &mut report))?;

    // Round 2 — INVENTORY: every vault held, with per-device heads.
    let mine = local.with_session(inventory)?;
    let theirs = message::decode_inventory(&round(
        ch,
        role,
        MSG_INVENTORY,
        &message::encode_inventory(&mine)?,
    )?)?;
    let common: Vec<[u8; 16]> = mine
        .keys()
        .filter(|v| theirs.contains_key(*v))
        .copied()
        .collect();
    let mut vaults: BTreeMap<[u8; 16], VaultSyncReport> = common
        .iter()
        .map(|v| (*v, VaultSyncReport::new(Id::from_bytes(*v))))
        .collect();

    // Round 3 — OPS: what the other side lacks, then OPS_END.
    let peer_id = peer.device_id;
    match role {
        Role::Initiator => {
            send_ops(ch, local, &common, &theirs, peer_id, &mut vaults)?;
            recv_ops(ch, local, &mut vaults)?;
        }
        Role::Responder => {
            recv_ops(ch, local, &mut vaults)?;
            send_ops(ch, local, &common, &theirs, peer_id, &mut vaults)?;
        }
    }

    // Round 4 — BLOB_WANT: attachment blobs still missing after ingest.
    let my_wants = local.with_session(|s| blob_wants(s, &common))?;
    let their_wants = message::decode_blob_want(&round(
        ch,
        role,
        MSG_BLOB_WANT,
        &message::encode_blob_want(&my_wants)?,
    )?)?;

    // Round 5 — BLOB…, BLOBS_END.
    match role {
        Role::Initiator => {
            send_blobs(ch, local, &their_wants, &mut vaults)?;
            recv_blobs(ch, local, &my_wants, &mut vaults)?;
        }
        Role::Responder => {
            recv_blobs(ch, local, &my_wants, &mut vaults)?;
            send_blobs(ch, local, &their_wants, &mut vaults)?;
        }
    }

    // Round 6 — DONE.
    round(ch, role, MSG_DONE, &[])?;

    // Best-effort audit record: the security gate was the handshake, not the
    // log line, so a failed write never fails a finished session.
    let _ = local.with_session(|s| Ok(s.record_nearby_sync(&peer_id).ok()));

    report.vaults = vaults.into_values().collect();
    Ok(report)
}

/// One single-message round: the initiator sends then reads, the responder
/// reads then sends. Returns the peer's message body.
fn round<S: Stream>(
    ch: &mut SecureChannel<S>,
    role: Role,
    kind: u8,
    body: &[u8],
) -> Result<Vec<u8>> {
    match role {
        Role::Initiator => {
            ch.send(kind, body)?;
            ch.expect(kind)
        }
        Role::Responder => {
            let theirs = ch.expect(kind)?;
            ch.send(kind, body)?;
            Ok(theirs)
        }
    }
}

// --- Round 1: shares --------------------------------------------------------

/// Seal each requested vault's key to the authenticated peer (`LPS2`, signed by
/// this device).
fn build_shares(
    session: &Session,
    peer: &PeerDevice,
    share: &[VaultId],
) -> Result<Vec<(VaultId, Vec<u8>)>> {
    let mut ids: Vec<VaultId> = share.to_vec();
    ids.sort_by_key(|v| *v.as_bytes());
    ids.dedup();
    let mut out = Vec::with_capacity(ids.len());
    for vault_id in ids {
        let blob = session.share_vault_key_to_peer(&vault_id, peer)?;
        out.push((vault_id, blob));
    }
    Ok(out)
}

/// Import the shares the peer sent (`lan-transport.md` §6.6). A share whose
/// sender is not the authenticated peer, or that fails `lp-vault`'s own checks
/// (pinned sender, signature before unsealing), is refused and reported; it
/// never stops the session.
fn import_shares(
    session: &Session,
    peer: &PeerDevice,
    shares: Vec<(VaultId, Vec<u8>)>,
    report: &mut SessionReport,
) -> Result<()> {
    for (vault_id, blob) in shares {
        let sender_ok = blob.len() >= 20
            && &blob[..4] == SHARE_MAGIC
            && blob[4..20] == *peer.device_id.as_bytes();
        if !sender_ok {
            report.shares_rejected.push((
                vault_id,
                "the share was not signed by the connected device".into(),
            ));
            continue;
        }
        match session.import_shared_vault_key(&vault_id, &blob) {
            Ok(true) => report.shares_adopted.push(vault_id),
            Ok(false) => {} // already held: idempotent
            Err(e @ (lp_vault::Error::Invalid(_) | lp_vault::Error::DecryptionFailed)) => {
                report.shares_rejected.push((vault_id, e.to_string()));
            }
            Err(other) => return Err(other.into()),
        }
    }
    Ok(())
}

// --- Round 2: inventory -----------------------------------------------------

/// Every vault this device holds, with per-device heads.
fn inventory(session: &Session) -> Result<Inventory> {
    let mut inv = Inventory::new();
    for (vault_id, _name) in session.list_vaults()? {
        let vault = session.open_vault(vault_id)?;
        inv.insert(*vault_id.as_bytes(), engine::vault_heads(&vault)?);
    }
    Ok(inv)
}

// --- Round 3: ops -----------------------------------------------------------

/// The ops of `vault_id` the peer lacks according to `their_heads`, minus the
/// peer's own (`lan-transport.md` §6.3), ascending by `(device_id, seq)`.
fn ops_to_send(
    session: &Session,
    vault_id: &[u8; 16],
    their_heads: &BTreeMap<[u8; 16], u64>,
    peer: DeviceId,
) -> Result<Vec<StoredOp>> {
    let vault = session.open_vault(Id::from_bytes(*vault_id))?;
    let mut ops: Vec<StoredOp> = vault
        .stored_ops()?
        .into_iter()
        .filter(|o| o.device_id != peer)
        .filter(|o| {
            o.seq
                > their_heads
                    .get(o.device_id.as_bytes())
                    .copied()
                    .unwrap_or(0)
        })
        .collect();
    ops.sort_by_key(|o| (*o.device_id.as_bytes(), o.seq));
    Ok(ops)
}

/// Send, per common vault, the ops the peer lacks in ~1 MiB `OPS` messages,
/// then `OPS_END`. The session lock is held only while collecting a vault's
/// ops, never while writing.
fn send_ops<S: Stream, L: Local>(
    ch: &mut SecureChannel<S>,
    local: &L,
    common: &[[u8; 16]],
    theirs: &Inventory,
    peer: DeviceId,
    vaults: &mut BTreeMap<[u8; 16], VaultSyncReport>,
) -> Result<()> {
    let empty = BTreeMap::new();
    for vault_id in common {
        let heads = theirs.get(vault_id).unwrap_or(&empty);
        let ops = local.with_session(|s| ops_to_send(s, vault_id, heads, peer))?;
        let vid = Id::from_bytes(*vault_id);
        let mut batch: Vec<StoredOp> = Vec::new();
        let mut batch_bytes = 0usize;
        for op in ops {
            let len = wire::encode_op(&op).len() + 4;
            if !batch.is_empty() && batch_bytes + len > OPS_BATCH_BYTES {
                ch.send(MSG_OPS, &message::encode_ops(&vid, &batch))?;
                batch.clear();
                batch_bytes = 0;
            }
            batch_bytes += len;
            batch.push(op);
            if let Some(v) = vaults.get_mut(vault_id) {
                v.ops_sent += 1;
            }
        }
        if !batch.is_empty() {
            ch.send(MSG_OPS, &message::encode_ops(&vid, &batch))?;
        }
    }
    ch.send(MSG_OPS_END, &[])
}

/// Receive `OPS` messages until `OPS_END`, ingesting through
/// [`engine::ingest`] whenever ~32 MiB is buffered and at the end.
fn recv_ops<S: Stream, L: Local>(
    ch: &mut SecureChannel<S>,
    local: &L,
    vaults: &mut BTreeMap<[u8; 16], VaultSyncReport>,
) -> Result<()> {
    let mut buffered: BTreeMap<[u8; 16], Vec<StoredOp>> = BTreeMap::new();
    let mut buffered_bytes = 0usize;
    loop {
        let Some((kind, body)) = ch.recv()? else {
            return Err(Error::Protocol(
                "the peer closed the connection before the session finished",
            ));
        };
        match kind {
            MSG_OPS => {
                let (vault_id, ops) = message::decode_ops(&body)?;
                if !vaults.contains_key(vault_id.as_bytes()) {
                    return Err(Error::Protocol(
                        "ops for a vault this device does not share",
                    ));
                }
                buffered_bytes += body.len();
                buffered
                    .entry(*vault_id.as_bytes())
                    .or_default()
                    .extend(ops);
                if buffered_bytes >= INGEST_BUFFER_BYTES {
                    flush(local, &mut buffered, vaults)?;
                    buffered_bytes = 0;
                }
            }
            MSG_OPS_END => {
                return flush(local, &mut buffered, vaults);
            }
            _ => return Err(Error::Protocol("unexpected message")),
        }
    }
}

/// Ingest everything buffered, one vault at a time.
fn flush<L: Local>(
    local: &L,
    buffered: &mut BTreeMap<[u8; 16], Vec<StoredOp>>,
    vaults: &mut BTreeMap<[u8; 16], VaultSyncReport>,
) -> Result<()> {
    for (vault_id, ops) in std::mem::take(buffered) {
        let got = local.with_session(|s| {
            let vault = s.open_vault(Id::from_bytes(vault_id))?;
            engine::ingest(s, &vault, ops)
        })?;
        if let Some(v) = vaults.get_mut(&vault_id) {
            v.applied += got.applied;
            v.skipped += got.skipped;
            v.pending += got.pending;
            v.quarantines.extend(got.quarantines);
        }
    }
    Ok(())
}

// --- Rounds 4–5: attachment blobs -------------------------------------------

/// Per common vault, the blobs live attachments reference but this device does
/// not hold (`sync-protocol.md` §7.3 step 5).
fn blob_wants(session: &Session, common: &[[u8; 16]]) -> Result<BlobWants> {
    let mut out = BlobWants::new();
    for vault_id in common {
        let vault = session.open_vault(Id::from_bytes(*vault_id))?;
        let referenced: BTreeSet<String> =
            vault.referenced_attachment_hashes()?.into_iter().collect();
        let held: BTreeSet<String> = vault.local_attachment_hashes()?.into_iter().collect();
        let missing: Vec<[u8; 32]> = referenced
            .difference(&held)
            .filter_map(|h| message::hash_from_hex(h))
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect();
        if !missing.is_empty() {
            out.insert(*vault_id, missing);
        }
    }
    Ok(out)
}

/// Send each wanted blob this device's vault references and holds — never an
/// unreferenced one — then `BLOBS_END`.
fn send_blobs<S: Stream, L: Local>(
    ch: &mut SecureChannel<S>,
    local: &L,
    wants: &BlobWants,
    vaults: &mut BTreeMap<[u8; 16], VaultSyncReport>,
) -> Result<()> {
    for (vault_id, hashes) in wants {
        if !vaults.contains_key(vault_id) {
            continue;
        }
        let referenced: BTreeSet<String> = local.with_session(|s| {
            let vault = s.open_vault(Id::from_bytes(*vault_id))?;
            Ok(vault
                .referenced_attachment_hashes()?
                .into_iter()
                .collect::<BTreeSet<String>>())
        })?;
        for hash in hashes {
            let hex = message::hash_hex(hash);
            if !referenced.contains(&hex) {
                continue;
            }
            let bytes = local.with_session(|s| {
                let vault = s.open_vault(Id::from_bytes(*vault_id))?;
                Ok(vault.read_attachment_blob(&hex)?)
            })?;
            if let Some(bytes) = bytes {
                ch.send(
                    MSG_BLOB,
                    &message::encode_blob(&Id::from_bytes(*vault_id), hash, &bytes),
                )?;
                if let Some(v) = vaults.get_mut(vault_id) {
                    v.blobs_sent += 1;
                }
            }
        }
    }
    ch.send(MSG_BLOBS_END, &[])
}

/// Receive blobs until `BLOBS_END`. Only blobs this device asked for are
/// accepted; each is re-hashed by `Vault::store_attachment_blob` before it is
/// stored, and a mismatch is an alarm.
fn recv_blobs<S: Stream, L: Local>(
    ch: &mut SecureChannel<S>,
    local: &L,
    wants: &BlobWants,
    vaults: &mut BTreeMap<[u8; 16], VaultSyncReport>,
) -> Result<()> {
    let mut outstanding: BTreeSet<([u8; 16], [u8; 32])> = wants
        .iter()
        .flat_map(|(v, hs)| hs.iter().map(move |h| (*v, *h)))
        .collect();
    loop {
        let Some((kind, body)) = ch.recv()? else {
            return Err(Error::Protocol(
                "the peer closed the connection before the session finished",
            ));
        };
        match kind {
            MSG_BLOB => {
                let (vault_id, hash, bytes) = message::decode_blob(&body)?;
                let key = (*vault_id.as_bytes(), hash);
                if !outstanding.remove(&key) {
                    return Err(Error::Protocol(
                        "an attachment blob this device did not ask for",
                    ));
                }
                let hex = message::hash_hex(&hash);
                let stored = local.with_session(|s| {
                    let vault = s.open_vault(vault_id)?;
                    match vault.store_attachment_blob(&hex, bytes) {
                        Ok(()) => Ok(true),
                        // A content-hash mismatch (or an over-cap blob): never
                        // stored, surfaced as an alarm.
                        Err(lp_vault::Error::Invalid(_)) => Ok(false),
                        Err(e) => Err(Error::from(e)),
                    }
                })?;
                if let Some(v) = vaults.get_mut(&key.0) {
                    if stored {
                        v.blobs_fetched += 1;
                    } else {
                        v.blobs_tampered.push(hex);
                    }
                }
            }
            MSG_BLOBS_END => {
                for (vault_id, _) in outstanding {
                    if let Some(v) = vaults.get_mut(&vault_id) {
                        v.blobs_pending += 1;
                    }
                }
                // Tampered blobs are still missing: count them pending too.
                for v in vaults.values_mut() {
                    v.blobs_pending += v.blobs_tampered.len();
                }
                return Ok(());
            }
            _ => return Err(Error::Protocol("unexpected message")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn account() -> (tempfile::TempDir, Session) {
        let dir = tempfile::tempdir().unwrap();
        let (session, _sk) =
            lp_vault::AccountStore::create(dir.path(), "correct horse battery").unwrap();
        (dir, session)
    }

    fn pin(a: &Session, b: &Session) -> PeerDevice {
        let id = b.device_public_identity();
        a.trust_peer_device(&id.device_id, &id.ed25519_pub, &id.x25519_pub, None)
            .unwrap();
        a.peer_device(&id.device_id).unwrap().unwrap()
    }

    fn empty_report(peer: DeviceId) -> SessionReport {
        SessionReport {
            peer,
            peer_label: None,
            vaults: Vec::new(),
            shares_sent: Vec::new(),
            shares_adopted: Vec::new(),
            shares_rejected: Vec::new(),
        }
    }

    /// A genuine LPS2 share relayed by a different device than its signer is
    /// refused, even though the signer is pinned (`lan-transport.md` §6.6).
    #[test]
    fn a_share_signed_by_anyone_but_the_connected_peer_is_refused() {
        let (_da, a) = account();
        let (_db, b) = account();
        let (_dc, c) = account();
        let b_on_a = pin(&a, &b);
        pin(&a, &c);
        let a_on_c = pin(&c, &a);
        let vault = c.create_vault("from-c").unwrap();
        let blob = c.share_vault_key_to_peer(&vault, &a_on_c).unwrap();

        // B is the authenticated peer, but the blob is C's.
        let mut report = empty_report(b_on_a.device_id);
        import_shares(&a, &b_on_a, vec![(vault, blob.clone())], &mut report).unwrap();
        assert!(report.shares_adopted.is_empty());
        assert_eq!(report.shares_rejected.len(), 1);
        assert!(a.list_vaults().unwrap().iter().all(|(v, _)| *v != vault));

        // The same blob from its real sender is adopted.
        let c_on_a = a.peer_device(&c.device_id()).unwrap().unwrap();
        let mut report = empty_report(c_on_a.device_id);
        import_shares(&a, &c_on_a, vec![(vault, blob)], &mut report).unwrap();
        assert_eq!(report.shares_adopted, vec![vault]);
    }
}
