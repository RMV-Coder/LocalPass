//! The bundle: what one QR transfer (or one `.lpqr` file) carries
//! (`qr-transport.md` §3, §9).
//!
//! ```text
//! header  "LPQB" || version || flags || sender[16] || recipient[16]
//!         || u16 n || n × vault_id[16] || u32 body_len || hash[32]
//! body    u32 len || HELLO body                       (shares)
//!         n × ( u32 len || OPS body )                 (ops, one per vault id)
//!         [ u32 k || k × ( u32 len || BLOB body ) ]   (attachments, flag bit 0)
//! hash  = BLAKE3( header bytes before the hash || body )
//! ```
//!
//! The `HELLO`, `OPS` and `BLOB` bodies are the nearby link's encodings
//! (`lan-transport.md` §6.2), written and read by the same codecs. Nothing in
//! the header is authenticated (§3.2): ops are checked by the §5 verifier
//! inside [`crate::engine::ingest`], shares by `lp-vault`'s signature check
//! against the pinned sender, blobs by their content hash.

use std::collections::{BTreeMap, BTreeSet};

use lp_vault::ids::{DeviceId, Id, VaultId};
use lp_vault::{Session, StoredOp};

use super::have::HaveCode;
use super::{MAX_BUNDLE_BYTES, PROTOCOL_VERSION};
use crate::engine;
use crate::error::{Error, Quarantine, Result};
use crate::nearby::exchange::{build_shares, ops_to_send};
use crate::nearby::message;
use crate::nearby::{MAX_SHARES, MAX_VAULTS};

const BUNDLE_MAGIC: &[u8; 4] = b"LPQB";
/// The `LPS2` share-blob magic (`sync-protocol.md` §7.1).
const SHARE_MAGIC: &[u8; 4] = b"LPS2";
/// Flag bit 0: the body has an attachments section.
const FLAG_ATTACHMENTS: u8 = 0x01;
/// magic, version, flags, sender, recipient, vault count.
const FIXED_HEADER_LEN: usize = 4 + 1 + 1 + 16 + 16 + 2;
/// The all-zero recipient: "built without knowing the receiver".
const NO_DEVICE: [u8; 16] = [0; 16];
/// Most attachment blobs one bundle may carry.
const MAX_BLOBS: usize = 4096;

/// What to put in a bundle (`qr-transport.md` §3.3).
#[derive(Clone, Debug, Default)]
pub struct ExportOptions {
    /// Vaults whose ops to send. Empty = every vault this device holds.
    pub vaults: Vec<VaultId>,
    /// The receiver's "what I have" code, to send only what it lacks.
    pub have: Option<HaveCode>,
    /// Vaults whose key to seal to `peer` and send (each travels in full).
    pub share: Vec<VaultId>,
    /// The pinned device to share with. Required when `share` is non-empty.
    pub peer: Option<DeviceId>,
    /// Include attachment blobs (off by default: §3.5).
    pub attachments: bool,
}

/// One attachment blob: its content hash and its (encrypted) bytes.
type Blob = ([u8; 32], Vec<u8>);

/// What [`export`] put in the bundle.
#[derive(Clone, Debug)]
pub struct ExportSummary {
    /// The bundle's size in bytes.
    pub bytes: usize,
    /// The transfer id its frames carry.
    pub transfer_id: [u8; 8],
    /// The device the bundle was built for, if known.
    pub recipient: Option<DeviceId>,
    /// Ops per vault, ascending by vault id.
    pub vaults: Vec<(VaultId, usize)>,
    /// Vaults whose key travels.
    pub shares: Vec<VaultId>,
    /// Attachment blobs included.
    pub blobs: usize,
    /// Attachment blobs left out because the bundle would have been too large.
    pub blobs_left_out: usize,
}

/// Build a bundle from this device's vaults (`qr-transport.md` §3.3).
///
/// # Errors
///
/// - [`Error::Invalid`] if `share` is set without a pinned `peer`, a named
///   vault does not exist, or the "what I have" code is from a different device
///   than `peer`.
/// - [`Error::Qr`] if the bundle would exceed [`MAX_BUNDLE_BYTES`], or there is
///   nothing to send.
/// - [`Error::Vault`] on a read or seal failure.
pub fn export(session: &Session, opts: &ExportOptions) -> Result<(Vec<u8>, ExportSummary)> {
    let peer = match opts.peer {
        Some(id) => Some(
            session
                .peer_device(&id)?
                .ok_or(Error::Invalid("that device is not trusted on this device"))?,
        ),
        None => None,
    };
    if !opts.share.is_empty() && peer.is_none() {
        return Err(Error::Invalid(
            "sharing a vault by QR needs the device it is for",
        ));
    }
    if let (Some(p), Some(h)) = (&peer, &opts.have)
        && p.device_id != h.device_id
    {
        return Err(Error::Invalid(
            "the scanned code came from a different device than the one you are sharing with",
        ));
    }
    let recipient: Option<DeviceId> = peer
        .as_ref()
        .map(|p| p.device_id)
        .or(opts.have.as_ref().map(|h| h.device_id));

    let held: BTreeSet<[u8; 16]> = session
        .list_vaults()?
        .into_iter()
        .map(|(v, _)| *v.as_bytes())
        .collect();
    for v in opts.vaults.iter().chain(&opts.share) {
        if !held.contains(v.as_bytes()) {
            return Err(Error::Invalid("no such vault on this device"));
        }
    }
    let picked: BTreeSet<[u8; 16]> = if opts.vaults.is_empty() {
        held.clone()
    } else {
        opts.vaults.iter().map(|v| *v.as_bytes()).collect()
    };
    let shared: BTreeSet<[u8; 16]> = opts.share.iter().map(|v| *v.as_bytes()).collect();

    // Shares first: sealed to the pinned peer, signed by this device.
    let shares = match &peer {
        Some(p) if !opts.share.is_empty() => build_shares(session, p, &opts.share)?,
        _ => Vec::new(),
    };

    // Ops: what the receiver lacks (§3.3), per vault, ascending.
    let empty = BTreeMap::new();
    let skip_author: DeviceId = recipient.unwrap_or(Id::from_bytes(NO_DEVICE));
    let mut sections: Vec<([u8; 16], Vec<StoredOp>)> = Vec::new();
    for vault_id in picked.union(&shared) {
        let heads = if shared.contains(vault_id) {
            &empty
        } else if let Some(have) = &opts.have {
            match have.heads.get(vault_id) {
                Some(h) => h,
                None => continue, // the receiver does not hold it
            }
        } else {
            &empty
        };
        let ops = ops_to_send(session, vault_id, heads, skip_author)?;
        if !ops.is_empty() {
            sections.push((*vault_id, ops));
        }
    }

    let mut body = Vec::new();
    put_section(&mut body, &message::encode_hello(&shares)?)?;
    for (vault_id, ops) in &sections {
        put_section(
            &mut body,
            &message::encode_ops(&Id::from_bytes(*vault_id), ops),
        )?;
    }
    if sections.is_empty() && shares.is_empty() {
        return Err(Error::Qr(
            "there is nothing to send: the other device is up to date",
        ));
    }

    let mut flags = 0u8;
    let mut blobs = 0usize;
    let mut blobs_left_out = 0usize;
    if opts.attachments {
        flags |= FLAG_ATTACHMENTS;
        let vault_ids: BTreeSet<[u8; 16]> = sections
            .iter()
            .map(|(v, _)| *v)
            .chain(
                opts.have
                    .iter()
                    .flat_map(|h| h.heads.keys().copied())
                    .filter(|v| picked.contains(v)),
            )
            .chain(shared.iter().copied())
            .collect();
        let header_estimate = FIXED_HEADER_LEN + 16 * sections.len() + 4 + 32;
        let mut entries: Vec<Vec<u8>> = Vec::new();
        let mut size = header_estimate + body.len() + 4;
        for vault_id in &vault_ids {
            let vault = session.open_vault(Id::from_bytes(*vault_id))?;
            let referenced: BTreeSet<String> =
                vault.referenced_attachment_hashes()?.into_iter().collect();
            for hex in referenced {
                let (Some(hash), Some(bytes)) = (
                    message::hash_from_hex(&hex),
                    vault.read_attachment_blob(&hex)?,
                ) else {
                    continue;
                };
                let entry = message::encode_blob(&Id::from_bytes(*vault_id), &hash, &bytes);
                if size + 4 + entry.len() > MAX_BUNDLE_BYTES || entries.len() >= MAX_BLOBS {
                    blobs_left_out += 1;
                    continue;
                }
                size += 4 + entry.len();
                entries.push(entry);
            }
        }
        blobs = entries.len();
        put_u32(&mut body, entries.len())?;
        for e in &entries {
            put_section(&mut body, e)?;
        }
    }

    let mut out = Vec::with_capacity(FIXED_HEADER_LEN + 16 * sections.len() + 36 + body.len());
    out.extend_from_slice(BUNDLE_MAGIC);
    out.push(PROTOCOL_VERSION);
    out.push(flags);
    out.extend_from_slice(session.device_id().as_bytes());
    out.extend_from_slice(recipient.as_ref().map_or(&NO_DEVICE, |r| r.as_bytes()));
    out.extend_from_slice(
        &u16::try_from(sections.len())
            .map_err(|_| Error::Qr("too many vaults for one transfer"))?
            .to_le_bytes(),
    );
    for (vault_id, _) in &sections {
        out.extend_from_slice(vault_id);
    }
    put_u32(&mut out, body.len())?;
    let hash = hash_of(&out, &body);
    out.extend_from_slice(&hash);
    out.extend_from_slice(&body);
    if out.len() > MAX_BUNDLE_BYTES {
        return Err(Error::Qr(
            "this is too much to send by QR (over 8 MiB): pick fewer vaults, scan the other device's code first, or use the folder or a nearby sync",
        ));
    }

    let summary = ExportSummary {
        bytes: out.len(),
        transfer_id: hash[..8].try_into().expect("8 bytes"),
        recipient,
        vaults: sections
            .iter()
            .map(|(v, ops)| (Id::from_bytes(*v), ops.len()))
            .collect(),
        shares: shares.iter().map(|(v, _)| *v).collect(),
        blobs,
        blobs_left_out,
    };
    Ok((out, summary))
}

fn put_u32(out: &mut Vec<u8>, n: usize) -> Result<()> {
    let n = u32::try_from(n).map_err(|_| Error::Qr("a bundle section is too large"))?;
    out.extend_from_slice(&n.to_le_bytes());
    Ok(())
}

fn put_section(out: &mut Vec<u8>, section: &[u8]) -> Result<()> {
    put_u32(out, section.len())?;
    out.extend_from_slice(section);
    Ok(())
}

fn hash_of(header_before_hash: &[u8], body: &[u8]) -> [u8; 32] {
    let mut all = Vec::with_capacity(header_before_hash.len() + body.len());
    all.extend_from_slice(header_before_hash);
    all.extend_from_slice(body);
    lp_crypto::blake3_256(&all)
}

/// A bundle whose hash and structure checked out. Its contents are still
/// unverified — ingest decides what is accepted.
#[derive(Clone, Debug)]
pub struct Bundle {
    /// The device that built it, as the header claims.
    pub sender: DeviceId,
    /// The device it was built for, as the header claims.
    pub recipient: Option<DeviceId>,
    /// The transfer id (the first 8 bytes of the hash).
    pub transfer_id: [u8; 8],
    /// Signed `LPS2` shares, ascending by vault id.
    pub shares: Vec<(VaultId, Vec<u8>)>,
    /// Ops per vault, ascending by vault id.
    pub ops: Vec<(VaultId, Vec<StoredOp>)>,
    /// Whether the body had an attachments section.
    pub has_attachments: bool,
    /// Attachment blobs: vault, content hash, bytes.
    pub blobs: Vec<(VaultId, [u8; 32], Vec<u8>)>,
}

/// A forward-only, length-checked reader.
struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        let end = self
            .pos
            .checked_add(n)
            .filter(|e| *e <= self.buf.len())
            .ok_or(Error::Qr("the bundle is truncated"))?;
        let s = &self.buf[self.pos..end];
        self.pos = end;
        Ok(s)
    }

    fn u16(&mut self) -> Result<usize> {
        Ok(usize::from(u16::from_le_bytes(
            self.take(2)?.try_into().expect("2"),
        )))
    }

    fn u32(&mut self) -> Result<usize> {
        Ok(u32::from_le_bytes(self.take(4)?.try_into().expect("4")) as usize)
    }

    fn id(&mut self) -> Result<[u8; 16]> {
        Ok(self.take(16)?.try_into().expect("16"))
    }

    fn section(&mut self) -> Result<&'a [u8]> {
        let n = self.u32()?;
        self.take(n)
    }
}

/// Check a bundle's hash and parse it, within every cap
/// (`qr-transport.md` §8, §9.1). Fails closed: any problem refuses the whole
/// bundle.
///
/// # Errors
///
/// [`Error::Qr`] for a damaged, malformed, oversize or unknown-version bundle.
pub fn parse(bytes: &[u8]) -> Result<Bundle> {
    if bytes.len() > MAX_BUNDLE_BYTES {
        return Err(Error::Qr("the bundle is larger than a QR transfer allows"));
    }
    let mut r = Reader { buf: bytes, pos: 0 };
    if r.take(4).ok() != Some(BUNDLE_MAGIC.as_slice()) {
        return Err(Error::Qr("not a LocalPass QR bundle"));
    }
    if r.take(1)?[0] != PROTOCOL_VERSION {
        return Err(Error::Qr(
            "the bundle was made by a different LocalPass version",
        ));
    }
    let flags = r.take(1)?[0];
    if flags & !FLAG_ATTACHMENTS != 0 {
        return Err(Error::Qr(
            "the bundle was made by a different LocalPass version",
        ));
    }
    let sender: DeviceId = Id::from_bytes(r.id()?);
    let recipient_raw = r.id()?;
    let n = r.u16()?;
    if n > MAX_VAULTS {
        return Err(Error::Qr("the bundle lists too many vaults"));
    }
    let mut vault_ids: Vec<[u8; 16]> = Vec::with_capacity(n);
    for _ in 0..n {
        let v = r.id()?;
        if vault_ids.last().is_some_and(|p| *p >= v) {
            return Err(Error::Qr("the bundle's vault list is not in order"));
        }
        vault_ids.push(v);
    }
    let body_len = r.u32()?;
    let header_before_hash = &bytes[..r.pos];
    let hash: [u8; 32] = r.take(32)?.try_into().expect("32");
    let body = r.take(body_len)?;
    if r.pos != bytes.len() {
        return Err(Error::Qr("the bundle has trailing bytes"));
    }
    if hash_of(header_before_hash, body) != hash {
        return Err(Error::Qr(
            "the bundle was damaged (its hash does not match)",
        ));
    }

    // The body: every section length-prefixed, decoded by the nearby codecs.
    let bad = |_| Error::Qr("the bundle's contents are malformed");
    let mut b = Reader { buf: body, pos: 0 };
    let shares = message::decode_hello(b.section()?).map_err(bad)?;
    if shares.len() > MAX_SHARES {
        return Err(Error::Qr("the bundle carries too many shares"));
    }
    let mut ops = Vec::with_capacity(n);
    for v in &vault_ids {
        let (vault_id, vault_ops) = message::decode_ops(b.section()?).map_err(bad)?;
        if vault_id.as_bytes() != v {
            return Err(Error::Qr("the bundle's ops do not match its vault list"));
        }
        ops.push((vault_id, vault_ops));
    }
    let has_attachments = flags & FLAG_ATTACHMENTS != 0;
    let mut blobs = Vec::new();
    if has_attachments {
        let k = b.u32()?;
        if k > MAX_BLOBS {
            return Err(Error::Qr("the bundle carries too many attachments"));
        }
        for _ in 0..k {
            let (vault_id, h, data) = message::decode_blob(b.section()?).map_err(bad)?;
            blobs.push((vault_id, h, data.to_vec()));
        }
    }
    if b.pos != body.len() {
        return Err(Error::Qr("the bundle has trailing bytes"));
    }
    Ok(Bundle {
        sender,
        recipient: (recipient_raw != NO_DEVICE).then(|| Id::from_bytes(recipient_raw)),
        transfer_id: hash[..8].try_into().expect("8"),
        shares,
        ops,
        has_attachments,
        blobs,
    })
}

/// Per vault: what the bundle carried and what the §5 verifier did with it.
#[derive(Clone, Debug)]
pub struct VaultImport {
    /// The vault.
    pub vault_id: VaultId,
    /// Ops the bundle carried for it.
    pub ops: usize,
    /// Verified and applied.
    pub applied: usize,
    /// Already held (idempotent).
    pub skipped: usize,
    /// Held pending (an earlier op is missing).
    pub pending: usize,
    /// Devices the verifier quarantined (alarms).
    pub quarantines: Vec<Quarantine>,
    /// Attachment blobs re-hashed and stored.
    pub blobs_stored: usize,
    /// Attachment blobs in the bundle this vault did not need.
    pub blobs_ignored: usize,
    /// Attachment blobs whose content did not match their hash (alarm).
    pub blobs_tampered: Vec<String>,
    /// Attachments this vault still lacks a blob for.
    pub blobs_missing: usize,
}

impl VaultImport {
    fn new(vault_id: VaultId) -> Self {
        Self {
            vault_id,
            ops: 0,
            applied: 0,
            skipped: 0,
            pending: 0,
            quarantines: Vec::new(),
            blobs_stored: 0,
            blobs_ignored: 0,
            blobs_tampered: Vec::new(),
            blobs_missing: 0,
        }
    }
}

/// What [`import`] did (`qr-transport.md` §9.5).
#[derive(Clone, Debug)]
pub struct ImportReport {
    /// The device that built the bundle, **as it claims**.
    pub sender: DeviceId,
    /// Its label, if it is a pinned device here.
    pub sender_label: Option<String>,
    /// Whether the claimed sender is a pinned device here.
    pub sender_trusted: bool,
    /// The device the bundle was built for, as it claims.
    pub recipient: Option<DeviceId>,
    /// Per vault whose ops this device ingested.
    pub vaults: Vec<VaultImport>,
    /// Vaults in the bundle this device does not hold (skipped).
    pub not_held: Vec<VaultId>,
    /// Vaults shared to this device and newly adopted.
    pub shares_adopted: Vec<VaultId>,
    /// Shares refused, with the reason (an alarm).
    pub shares_rejected: Vec<(VaultId, String)>,
}

impl ImportReport {
    /// Whether anything is worth alarming on: a quarantine, a tampered blob or
    /// a refused share.
    #[must_use]
    pub fn has_alarms(&self) -> bool {
        !self.shares_rejected.is_empty()
            || self
                .vaults
                .iter()
                .any(|v| !v.quarantines.is_empty() || !v.blobs_tampered.is_empty())
    }

    /// Whether the bundle was built for another device.
    #[must_use]
    pub fn meant_for_another_device(&self, this_device: &DeviceId) -> bool {
        self.recipient.is_some_and(|r| r != *this_device)
    }
}

/// Check, parse and ingest a received bundle (`qr-transport.md` §9): shares
/// first (each must name the bundle's sender, be signed by a **pinned** device
/// and be sealed to this one), then every vault's ops through
/// [`engine::ingest`] — the §5 verifier and §4 merge `pull` uses — then any
/// attachment blobs this device's vaults reference and lack.
///
/// `transfer_id` is the id the frames carried, when the bundle came from a QR
/// stream; it must match the bundle's own hash.
///
/// # Errors
///
/// [`Error::Qr`] if the bundle is damaged or malformed (nothing is ingested);
/// [`Error::Vault`] on a local storage failure. A verification alarm is not an
/// error: it is in the report.
pub fn import(
    session: &Session,
    bytes: &[u8],
    transfer_id: Option<[u8; 8]>,
) -> Result<ImportReport> {
    let bundle = parse(bytes)?;
    if transfer_id.is_some_and(|t| t != bundle.transfer_id) {
        return Err(Error::Qr("the stream's codes do not belong to this bundle"));
    }
    ingest(session, bundle)
}

fn ingest(session: &Session, bundle: Bundle) -> Result<ImportReport> {
    let pinned = session.peer_device(&bundle.sender)?;
    let mut report = ImportReport {
        sender: bundle.sender,
        sender_label: pinned.as_ref().and_then(|p| p.label.clone()),
        sender_trusted: pinned.is_some(),
        recipient: bundle.recipient,
        vaults: Vec::new(),
        not_held: Vec::new(),
        shares_adopted: Vec::new(),
        shares_rejected: Vec::new(),
    };

    // Shares (§9.2).
    for (vault_id, blob) in bundle.shares {
        let from_sender = blob.len() >= 20
            && &blob[..4] == SHARE_MAGIC
            && blob[4..20] == *bundle.sender.as_bytes();
        if !from_sender {
            report.shares_rejected.push((
                vault_id,
                "the share was not made by the sending device".into(),
            ));
            continue;
        }
        match session.import_shared_vault_key(&vault_id, &blob) {
            Ok(true) => report.shares_adopted.push(vault_id),
            Ok(false) => {} // already held
            Err(e @ (lp_vault::Error::Invalid(_) | lp_vault::Error::DecryptionFailed)) => {
                report.shares_rejected.push((vault_id, e.to_string()));
            }
            Err(other) => return Err(other.into()),
        }
    }

    // Ops (§9.3): the one ingest path every transport uses.
    let held: BTreeSet<[u8; 16]> = session
        .list_vaults()?
        .into_iter()
        .map(|(v, _)| *v.as_bytes())
        .collect();
    let mut vaults: BTreeMap<[u8; 16], VaultImport> = BTreeMap::new();
    for (vault_id, ops) in bundle.ops {
        if !held.contains(vault_id.as_bytes()) {
            report.not_held.push(vault_id);
            continue;
        }
        let mut line = VaultImport::new(vault_id);
        line.ops = ops.len();
        let vault = session.open_vault(vault_id)?;
        let got = engine::ingest(session, &vault, ops)?;
        line.applied = got.applied;
        line.skipped = got.skipped;
        line.pending = got.pending;
        line.quarantines = got.quarantines;
        vaults.insert(*vault_id.as_bytes(), line);
    }

    // Attachments (§9.4): only referenced-but-missing blobs, re-hashed.
    let mut by_vault: BTreeMap<[u8; 16], Vec<Blob>> = BTreeMap::new();
    for (vault_id, hash, data) in bundle.blobs {
        by_vault
            .entry(*vault_id.as_bytes())
            .or_default()
            .push((hash, data));
    }
    let touched: BTreeSet<[u8; 16]> = vaults
        .keys()
        .copied()
        .chain(by_vault.keys().copied().filter(|v| held.contains(v)))
        .collect();
    for vault_id in touched {
        let vid = Id::from_bytes(vault_id);
        let vault = session.open_vault(vid)?;
        let referenced: BTreeSet<String> =
            vault.referenced_attachment_hashes()?.into_iter().collect();
        let local: BTreeSet<String> = vault.local_attachment_hashes()?.into_iter().collect();
        let mut missing: BTreeSet<String> = referenced.difference(&local).cloned().collect();
        let line = vaults
            .entry(vault_id)
            .or_insert_with(|| VaultImport::new(vid));
        for (hash, data) in by_vault.remove(&vault_id).unwrap_or_default() {
            let hex = message::hash_hex(&hash);
            if !missing.contains(&hex) {
                line.blobs_ignored += 1;
                continue;
            }
            match vault.store_attachment_blob(&hex, &data) {
                Ok(()) => {
                    missing.remove(&hex);
                    line.blobs_stored += 1;
                }
                // A content-hash mismatch or an over-cap blob: never stored.
                Err(lp_vault::Error::Invalid(_)) => line.blobs_tampered.push(hex),
                Err(e) => return Err(e.into()),
            }
        }
        line.blobs_missing = missing.len();
    }
    // Whatever is left in `by_vault` is for vaults this device does not hold:
    // dropped unread.
    report.vaults = vaults.into_values().collect();
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fake_bundle(flags: u8, vaults: &[[u8; 16]], body: &[u8]) -> Vec<u8> {
        let mut out = BUNDLE_MAGIC.to_vec();
        out.push(PROTOCOL_VERSION);
        out.push(flags);
        out.extend_from_slice(&[1; 16]);
        out.extend_from_slice(&NO_DEVICE);
        out.extend_from_slice(&(vaults.len() as u16).to_le_bytes());
        for v in vaults {
            out.extend_from_slice(v);
        }
        out.extend_from_slice(&(body.len() as u32).to_le_bytes());
        let h = hash_of(&out, body);
        out.extend_from_slice(&h);
        out.extend_from_slice(body);
        out
    }

    fn empty_body() -> Vec<u8> {
        let mut body = Vec::new();
        put_section(&mut body, &message::encode_hello(&[]).unwrap()).unwrap();
        body
    }

    #[test]
    fn a_minimal_bundle_parses() {
        let b = parse(&fake_bundle(0, &[], &empty_body())).unwrap();
        assert!(b.shares.is_empty() && b.ops.is_empty() && b.recipient.is_none());
    }

    #[test]
    fn any_flipped_bit_is_refused_whole() {
        let good = fake_bundle(0, &[], &empty_body());
        for i in 0..good.len() {
            let mut bad = good.clone();
            bad[i] ^= 0x01;
            assert!(parse(&bad).is_err(), "byte {i}");
        }
    }

    #[test]
    fn unknown_flags_trailing_bytes_and_bad_order_are_refused() {
        assert!(parse(&fake_bundle(0x02, &[], &empty_body())).is_err());
        let mut body = empty_body();
        body.push(0);
        assert!(parse(&fake_bundle(0, &[], &body)).is_err());
        let mut trailing = fake_bundle(0, &[], &empty_body());
        trailing.push(0);
        assert!(parse(&trailing).is_err());
        // Two vault ids out of order (the body would not matter).
        assert!(parse(&fake_bundle(0, &[[2; 16], [1; 16]], &empty_body())).is_err());
    }

    #[test]
    fn an_oversize_header_is_refused_before_allocation() {
        // 65 535 vault ids claimed in a few bytes.
        let mut b = BUNDLE_MAGIC.to_vec();
        b.extend_from_slice(&[PROTOCOL_VERSION, 0]);
        b.extend_from_slice(&[0; 32]);
        b.extend_from_slice(&u16::MAX.to_le_bytes());
        assert!(matches!(parse(&b), Err(Error::Qr(_))));
        // A body length of 4 GiB.
        let mut b = BUNDLE_MAGIC.to_vec();
        b.extend_from_slice(&[PROTOCOL_VERSION, 0]);
        b.extend_from_slice(&[0; 32]);
        b.extend_from_slice(&0u16.to_le_bytes());
        b.extend_from_slice(&u32::MAX.to_le_bytes());
        b.extend_from_slice(&[0; 32]);
        assert!(matches!(parse(&b), Err(Error::Qr(_))));
        // More than the bundle cap.
        assert!(parse(&vec![0u8; MAX_BUNDLE_BYTES + 1]).is_err());
    }
}
