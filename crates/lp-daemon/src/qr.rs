#![forbid(unsafe_code)]
//! Sync by QR code (`docs/specs/qr-transport.md` §10.2): the daemon side of
//! [`lp_sync::qr`].
//!
//! Bundles move **by path**, like attachments: `QrExport` writes the file and
//! `QrImport` reads it, so bundle bytes never cross the IPC pipe and the
//! client never holds a vault-side object. The client (the GUI) turns the file
//! into QR frames, or a scanned stream back into a file; it decides nothing.
//!
//! Nothing here verifies anything itself: shares go through `lp-vault`'s
//! signed-share import and ops through [`lp_sync::engine::ingest`], inside
//! [`lp_sync::qr::bundle::import`].

use std::path::Path;

use lp_sync::qr::{self, ExportOptions, ExportSummary, HaveCode, ImportReport};
use lp_vault::Session;
use lp_vault::ids::VaultId;

use crate::protocol::{Response, WireAdoptedVault, WireQrExport, WireQrImport, WireQrVault};
use crate::sync::{map_sync_error, parse_device_id};

fn usage(message: impl Into<String>) -> Response {
    Response::Error {
        auth: false,
        message: message.into(),
    }
}

/// An [`lp_sync::Error`] from the QR layer as a plain-language message: a
/// refused bundle, code or frame reads as itself, not as "sync error: …".
fn qr_err(e: lp_sync::Error) -> Response {
    match e {
        lp_sync::Error::Qr(m) | lp_sync::Error::Invalid(m) => usage(m),
        other => map_sync_error(other),
    }
}

/// Resolve vault names or ids, sharing the engine's matching rules.
fn resolve_vaults(
    session: &Session,
    refs: &[String],
    resolve: &dyn Fn(&Session, &str) -> Result<VaultId, Response>,
) -> Result<Vec<VaultId>, Response> {
    refs.iter().map(|r| resolve(session, r)).collect()
}

fn vault_name(session: &Session, id: &VaultId) -> String {
    session
        .list_vaults()
        .ok()
        .and_then(|vs| vs.into_iter().find(|(v, _)| v == id).map(|(_, n)| n))
        .unwrap_or_default()
}

fn hex8(id: &[u8; 8]) -> String {
    id.iter().map(|b| format!("{b:02x}")).collect()
}

fn parse_hex8(s: &str) -> Option<[u8; 8]> {
    let s = s.trim();
    if s.len() != 16 {
        return None;
    }
    let mut out = [0u8; 8];
    for (i, b) in out.iter_mut().enumerate() {
        *b = u8::from_str_radix(s.get(i * 2..i * 2 + 2)?, 16).ok()?;
    }
    Some(out)
}

/// [`crate::protocol::Request::QrHaveCode`].
pub(crate) fn have_code(
    session: &Session,
    vaults: &[String],
    resolve: &dyn Fn(&Session, &str) -> Result<VaultId, Response>,
) -> Result<Response, Response> {
    let ids = resolve_vaults(session, vaults, resolve)?;
    let code = HaveCode::build(session, &ids).map_err(qr_err)?;
    Ok(Response::QrHaveCode {
        vaults: code.heads.len(),
        code: code.to_text().map_err(qr_err)?,
    })
}

/// Render an [`ExportSummary`] for the wire.
#[must_use]
pub fn render_export(summary: &ExportSummary, session: &Session) -> WireQrExport {
    let recipient_label = summary
        .recipient
        .and_then(|r| session.peer_device(&r).ok().flatten())
        .and_then(|p| p.label);
    WireQrExport {
        bytes: summary.bytes,
        transfer_id: hex8(&summary.transfer_id),
        recipient: summary.recipient.map(|r| r.to_hyphenated()),
        recipient_label,
        vaults: summary
            .vaults
            .iter()
            .map(|(v, ops)| WireQrVault {
                vault_id: v.to_hyphenated(),
                name: vault_name(session, v),
                ops: *ops,
                applied: 0,
                skipped: 0,
                pending: 0,
                blobs_stored: 0,
                blobs_missing: 0,
            })
            .collect(),
        shared: summary.shares.iter().map(|v| v.to_hyphenated()).collect(),
        blobs: summary.blobs,
        blobs_left_out: summary.blobs_left_out,
    }
}

/// [`crate::protocol::Request::QrExport`]: build the bundle and write it to
/// `out_path` (refusing to overwrite unless `force`).
#[allow(clippy::too_many_arguments)]
pub(crate) fn export(
    session: &Session,
    out_path: &str,
    vaults: &[String],
    have: Option<&str>,
    peer: Option<&str>,
    share: &[String],
    attachments: bool,
    force: bool,
    resolve: &dyn Fn(&Session, &str) -> Result<VaultId, Response>,
) -> Result<Response, Response> {
    let dest = Path::new(out_path);
    if dest.exists() && !force {
        return Err(usage(
            "the destination file already exists; pass force to overwrite",
        ));
    }
    let opts = ExportOptions {
        vaults: resolve_vaults(session, vaults, resolve)?,
        have: have.map(HaveCode::from_text).transpose().map_err(qr_err)?,
        share: resolve_vaults(session, share, resolve)?,
        peer: peer.map(parse_device_id).transpose()?,
        attachments,
    };
    let (bundle, summary) = qr::bundle::export(session, &opts).map_err(qr_err)?;
    write_file(dest, &bundle)
        .map_err(|e| usage(format!("could not write the bundle file: {e}")))?;
    Ok(Response::QrExported {
        summary: render_export(&summary, session),
    })
}

/// Render an [`ImportReport`] for the wire. Secret-free: ids, names (vault
/// metadata over the same-user channel), counts and alarm descriptions.
#[must_use]
pub fn render_import(report: &ImportReport, session: &Session) -> WireQrImport {
    let mut alarms: Vec<String> = report
        .shares_rejected
        .iter()
        .map(|(v, why)| format!("refused a vault-key share for {}: {why}", v.to_hyphenated()))
        .collect();
    for v in &report.vaults {
        for q in &v.quarantines {
            alarms.push(format!(
                "device {} quarantined at seq {} — {}",
                q.device_id.to_hyphenated(),
                q.seq,
                q.alarm
            ));
        }
        for h in &v.blobs_tampered {
            alarms.push(format!("attachment blob {h} failed its content check"));
        }
    }
    WireQrImport {
        sender_device_id: report.sender.to_hyphenated(),
        sender_label: report.sender_label.clone(),
        sender_trusted: report.sender_trusted,
        for_another_device: report.meant_for_another_device(&session.device_id()),
        vaults: report
            .vaults
            .iter()
            .map(|v| WireQrVault {
                vault_id: v.vault_id.to_hyphenated(),
                name: vault_name(session, &v.vault_id),
                ops: v.ops,
                applied: v.applied,
                skipped: v.skipped,
                pending: v.pending,
                blobs_stored: v.blobs_stored,
                blobs_missing: v.blobs_missing,
            })
            .collect(),
        not_held: report.not_held.iter().map(|v| v.to_hyphenated()).collect(),
        adopted: report
            .shares_adopted
            .iter()
            .map(|v| WireAdoptedVault {
                vault_id: v.to_hyphenated(),
                name: vault_name(session, v),
            })
            .collect(),
        alarms,
    }
}

/// The largest file `QrImport` will read: a bundle is at most
/// [`qr::MAX_BUNDLE_BYTES`].
fn read_bundle(path: &Path) -> Result<Vec<u8>, Response> {
    let meta = std::fs::metadata(path)
        .map_err(|e| usage(format!("could not read the bundle file: {e}")))?;
    if meta.len() > qr::MAX_BUNDLE_BYTES as u64 {
        return Err(usage(
            "the file is larger than a QR transfer allows (8 MiB); it is not a LocalPass bundle",
        ));
    }
    std::fs::read(path).map_err(|e| usage(format!("could not read the bundle file: {e}")))
}

/// [`crate::protocol::Request::QrImport`].
pub(crate) fn import(
    session: &Session,
    path: &str,
    transfer_id: Option<&str>,
) -> Result<Response, Response> {
    let transfer = match transfer_id {
        Some(t) => Some(parse_hex8(t).ok_or_else(|| usage("invalid transfer id"))?),
        None => None,
    };
    let bytes = read_bundle(Path::new(path))?;
    let report = qr::bundle::import(session, &bytes, transfer).map_err(qr_err)?;
    Ok(Response::QrImported {
        report: render_import(&report, session),
    })
}

/// Write the bundle, creating parent directories; owner-only on Unix. The
/// bundle is ciphertext and metadata — what the sync folder holds — but there
/// is no reason for anyone else to read it.
fn write_file(path: &Path, data: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
    {
        std::fs::create_dir_all(parent)?;
    }
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut f = opts.open(path)?;
    f.write_all(data)?;
    f.sync_all()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn transfer_ids_round_trip_as_hex() {
        let id = [0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef];
        assert_eq!(hex8(&id), "0123456789abcdef");
        assert_eq!(parse_hex8("0123456789abcdef"), Some(id));
        assert_eq!(parse_hex8("0123"), None);
        assert_eq!(parse_hex8("zz23456789abcdef"), None);
    }
}
