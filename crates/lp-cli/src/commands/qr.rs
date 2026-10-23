//! `localpass sync qr have|export|import` — the QR channel without the camera
//! (`docs/specs/qr-transport.md` §10.3).
//!
//! The bundle file is byte-identical to what a QR stream carries, so these
//! commands move a bundle by file (a USB stick) and test the channel end to end
//! without a screen or a camera. Like every `localpass sync` command they run
//! on the directly-unlocked session; the checks are the daemon's and the GUI's:
//! [`lp_sync::qr::bundle::import`] verifies the hash, the shares' signatures
//! against pinned senders, and every op through the §5 verifier.

use std::path::Path;

use anyhow::{Result, bail};
use serde_json::json;

use crate::cli::QrCommand;
use crate::commands::sync::map_sync_error;
use crate::error::CliError;

use lp_sync::qr::{self, ExportOptions, HaveCode};
use lp_vault::Session;
use lp_vault::ids::VaultId;

/// Run a `localpass sync qr ...` subcommand.
///
/// # Errors
///
/// Storage and sync failures, a refused bundle, and any alarm.
pub fn run(session: &Session, command: &QrCommand) -> Result<()> {
    match command {
        QrCommand::Have { vaults, json } => have(session, vaults, *json),
        QrCommand::Export {
            out,
            vaults,
            have,
            peer,
            share,
            attachments,
            force,
            json,
        } => {
            let opts = ExportOptions {
                vaults: resolve(session, vaults)?,
                have: have
                    .as_deref()
                    .map(HaveCode::from_text)
                    .transpose()
                    .map_err(map_sync_error)?,
                share: resolve(session, share)?,
                peer: peer.as_deref().map(parse_device).transpose()?,
                attachments: *attachments,
            };
            export(session, out, &opts, *force, *json)
        }
        QrCommand::Import { file, json } => import(session, file, *json),
    }
}

fn resolve(session: &Session, refs: &[String]) -> Result<Vec<VaultId>> {
    refs.iter()
        .map(|r| Ok(crate::resolve::open_vault(session, r)?.vault_id()))
        .collect()
}

fn parse_device(s: &str) -> Result<lp_vault::ids::DeviceId> {
    let uuid = uuid::Uuid::parse_str(s.trim())
        .map_err(|_| CliError::usage("--peer must be a device id (a UUID)"))?;
    Ok(lp_vault::Id::from_bytes(*uuid.as_bytes()))
}

fn have(session: &Session, vaults: &[String], json_out: bool) -> Result<()> {
    let ids = resolve(session, vaults)?;
    let code = HaveCode::build(session, &ids).map_err(map_sync_error)?;
    let text = code.to_text().map_err(map_sync_error)?;
    if json_out {
        println!(
            "{}",
            serde_json::to_string_pretty(&json!({
                "code": text,
                "device_id": code.device_id.to_hyphenated(),
                "vaults": code.heads.len(),
            }))?
        );
    } else {
        println!("{text}");
    }
    Ok(())
}

fn export(
    session: &Session,
    out: &Path,
    opts: &ExportOptions,
    force: bool,
    json_out: bool,
) -> Result<()> {
    if out.exists() && !force {
        bail!(CliError::usage(format!(
            "{} already exists (pass --force to overwrite)",
            out.display()
        )));
    }
    let (bundle, summary) = qr::bundle::export(session, opts).map_err(map_sync_error)?;
    std::fs::write(out, &bundle)
        .map_err(|e| CliError::usage(format!("could not write {}: {e}", out.display())))?;
    let wire = lp_daemon::qr::render_export(&summary, session);
    if json_out {
        println!("{}", serde_json::to_string_pretty(&wire)?);
    } else {
        println!(
            "wrote {} ({} bytes, about {} QR frames)",
            out.display(),
            wire.bytes,
            wire.bytes.div_ceil(usize::from(qr::DEFAULT_SYMBOL_SIZE))
        );
        if let Some(r) = &wire.recipient {
            let label = wire
                .recipient_label
                .as_deref()
                .map_or_else(String::new, |l| format!(" ({l})"));
            println!("  made for device {r}{label}");
        }
        for v in &wire.vaults {
            println!("  vault \"{}\": {} op(s)", v.name, v.ops);
        }
        for v in &wire.shared {
            println!("  carries the key of vault {v}");
        }
        if opts.attachments {
            println!(
                "  attachments: {} included, {} left out (too large)",
                wire.blobs, wire.blobs_left_out
            );
        }
    }
    Ok(())
}

fn import(session: &Session, file: &Path, json_out: bool) -> Result<()> {
    let len = std::fs::metadata(file)
        .map_err(|e| CliError::usage(format!("could not read {}: {e}", file.display())))?
        .len();
    if len > qr::MAX_BUNDLE_BYTES as u64 {
        bail!(CliError::usage(
            "the file is larger than a QR transfer allows (8 MiB); it is not a LocalPass bundle"
        ));
    }
    let bytes = std::fs::read(file)
        .map_err(|e| CliError::usage(format!("could not read {}: {e}", file.display())))?;
    let report = qr::bundle::import(session, &bytes, None).map_err(map_sync_error)?;
    let wire = lp_daemon::qr::render_import(&report, session);
    if json_out {
        println!("{}", serde_json::to_string_pretty(&wire)?);
    } else {
        let who = match (&wire.sender_label, wire.sender_trusted) {
            (Some(l), true) => format!("{} ({l})", wire.sender_device_id),
            (None, true) => wire.sender_device_id.clone(),
            (_, false) => format!("{} (NOT a trusted device)", wire.sender_device_id),
        };
        println!("Bundle from {who}, as it claims.");
        if wire.for_another_device {
            println!("  it was made for another device");
        }
        for v in &wire.adopted {
            println!("  adopted vault \"{}\" ({})", v.name, v.vault_id);
        }
        for v in &wire.vaults {
            println!(
                "  vault \"{}\": {} op(s): applied {}, already here {}, pending {}; attachments stored {}, missing {}",
                v.name, v.ops, v.applied, v.skipped, v.pending, v.blobs_stored, v.blobs_missing
            );
        }
        for v in &wire.not_held {
            println!("  skipped vault {v} (not on this device)");
        }
        for a in &wire.alarms {
            eprintln!("ALARM: {a}");
        }
    }
    if !wire.alarms.is_empty() {
        bail!(CliError::usage(format!(
            "{} alarm(s) during the import (see above)",
            wire.alarms.len()
        )));
    }
    Ok(())
}
