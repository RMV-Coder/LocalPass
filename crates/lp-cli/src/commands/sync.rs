//! `localpass sync setup|push|pull|status` — file-based op-log sync
//! (sync-protocol.md §7; PRD §11 #6). Always uses the direct-unlock path (the
//! daemon has no sync proxying in the MVP).

use std::path::Path;

use anyhow::{Result, bail};
use serde_json::json;

use crate::cli::SyncCommand;
use crate::error::{CliError, map_vault_error};
use crate::unlock::{self, PasswordSource};

use lp_sync::engine;

/// Run a `localpass sync ...` subcommand.
///
/// # Errors
///
/// Propagates unlock, storage, and sync failures (mapped to exit codes).
pub fn run(profile_dir: &Path, src: PasswordSource, command: &SyncCommand) -> Result<()> {
    let (session, _sk) = unlock::unlock(profile_dir, src)?;
    match command {
        SyncCommand::Setup { dir, vault } => setup(&session, vault, dir),
        SyncCommand::Push { vault, json } => push(&session, vault, *json),
        SyncCommand::Pull { vault, json } => pull(&session, vault, *json),
        SyncCommand::Status { vault, json } => status(&session, vault, *json),
    }
}

/// `sync setup` — enroll a vault under a shared sync-root directory.
fn setup(session: &lp_vault::Session, vault_ref: &str, dir: &Path) -> Result<()> {
    let vault = crate::resolve::open_vault(session, vault_ref)?;
    engine::setup(session, vault.vault_id(), dir).map_err(map_sync_error)?;
    println!(
        "enrolled vault {vault_ref:?} for sync under {}",
        dir.display()
    );
    Ok(())
}

/// `sync push` — publish this device's ops to the channel.
fn push(session: &lp_vault::Session, vault_ref: &str, json_out: bool) -> Result<()> {
    let vault = crate::resolve::open_vault(session, vault_ref)?;
    let report = engine::push(session, &vault).map_err(map_sync_error)?;
    if json_out {
        let published: Vec<_> = report
            .published
            .iter()
            .map(|(id, seq)| json!({ "device_id": id.to_hyphenated(), "seq": seq }))
            .collect();
        println!(
            "{}",
            serde_json::to_string_pretty(&json!({
                "vault": vault_ref,
                "segments_written": report.segments_written,
                "published": published,
            }))?
        );
    } else {
        println!(
            "pushed {} segment(s); {} device chain(s) published",
            report.segments_written,
            report.published.len()
        );
    }
    Ok(())
}

/// `sync pull` — verify + merge peers' ops into this vault.
fn pull(session: &lp_vault::Session, vault_ref: &str, json_out: bool) -> Result<()> {
    let vault = crate::resolve::open_vault(session, vault_ref)?;
    let report = engine::pull(session, &vault).map_err(map_sync_error)?;

    if json_out {
        let alarms: Vec<_> = report
            .quarantines
            .iter()
            .map(|q| {
                json!({
                    "device_id": q.device_id.to_hyphenated(),
                    "seq": q.seq,
                    "alarm": q.alarm.code(),
                })
            })
            .collect();
        println!(
            "{}",
            serde_json::to_string_pretty(&json!({
                "vault": vault_ref,
                "applied": report.applied,
                "skipped": report.skipped,
                "pending": report.pending,
                "key_blob_present": report.key_blob_present,
                "alarms": alarms,
            }))?
        );
    } else {
        println!(
            "applied {}, skipped {}, pending {}",
            report.applied, report.skipped, report.pending
        );
        if report.key_blob_present {
            println!(
                "note: a shared-vault key addressed to this device is waiting \
                 (import is not available in this build; see `vault share-to-device --help`)"
            );
        }
        for q in &report.quarantines {
            eprintln!(
                "ALARM: device {} quarantined at seq {} — {}",
                q.device_id.to_hyphenated(),
                q.seq,
                q.alarm
            );
        }
    }
    // An alarm is a security event: exit non-zero so scripts notice, but only
    // after applying every clean device's ops.
    if report.has_alarms() {
        bail!(CliError::usage(format!(
            "{} device(s) quarantined during pull (see alarms above)",
            report.quarantines.len()
        )));
    }
    Ok(())
}

/// `sync status` — per-device seq marks + pending/quarantine counts.
fn status(session: &lp_vault::Session, vault_ref: &str, json_out: bool) -> Result<()> {
    let vault = crate::resolve::open_vault(session, vault_ref)?;
    let st = engine::status(session, &vault).map_err(map_sync_error)?;

    if json_out {
        let devices: Vec<_> = st
            .devices
            .iter()
            .map(|d| {
                json!({
                    "device_id": d.device_id.to_hyphenated(),
                    "is_self": d.is_self,
                    "trusted": d.trusted,
                    "local_seq": d.local_seq,
                    "channel_seq": d.channel_seq,
                })
            })
            .collect();
        let alarms: Vec<_> = st
            .quarantines
            .iter()
            .map(|q| {
                json!({
                    "device_id": q.device_id.to_hyphenated(),
                    "seq": q.seq,
                    "alarm": q.alarm.code(),
                })
            })
            .collect();
        println!(
            "{}",
            serde_json::to_string_pretty(&json!({
                "vault": vault_ref,
                "enrolled": st.enrolled,
                "root": st.root,
                "pending": st.pending,
                "devices": devices,
                "alarms": alarms,
            }))?
        );
        return Ok(());
    }

    if !st.enrolled {
        println!("vault {vault_ref:?} is not enrolled for sync (run `localpass sync setup`)");
        return Ok(());
    }
    println!("Vault:   {vault_ref}");
    println!("Sync dir: {}", st.root.as_deref().unwrap_or("(none)"));
    println!("Pending: {}", st.pending);
    if st.devices.is_empty() {
        println!("Devices: (none seen yet)");
    } else {
        println!("Devices (local_seq / channel_seq):");
        for d in &st.devices {
            let tag = if d.is_self {
                " (this device)"
            } else if d.trusted {
                " (trusted)"
            } else {
                " (UNTRUSTED)"
            };
            println!(
                "  {}  {} / {}{tag}",
                d.device_id.to_hyphenated(),
                d.local_seq,
                d.channel_seq
            );
        }
    }
    for q in &st.quarantines {
        println!(
            "ALARM: device {} quarantined at seq {} — {}",
            q.device_id.to_hyphenated(),
            q.seq,
            q.alarm
        );
    }
    Ok(())
}

/// Map an `lp_sync::Error` to a [`CliError`] with a sensible exit code.
pub fn map_sync_error(e: lp_sync::Error) -> CliError {
    match e {
        lp_sync::Error::Vault(v) => map_vault_error(v),
        lp_sync::Error::Invalid(m) => CliError::Usage(m.to_string()),
        lp_sync::Error::KeySharingUnavailable(m) => CliError::Usage(format!(
            "vault key sharing is unavailable in this build: {m}"
        )),
        other => CliError::Internal(anyhow::anyhow!("{other}")),
    }
}
