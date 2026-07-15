//! `localpass sync setup|push|pull|status` — file-based op-log sync
//! (sync-protocol.md §7; PRD §11 #6). Always uses the direct-unlock path (the
//! daemon has no sync proxying in the MVP).
//!
//! # The channel is always the filesystem here
//!
//! [`lp_sync::engine`] resolves a vault's enrolled sync root through a
//! caller-supplied [`lp_sync::store::StoreFactory`]. The CLI is a desktop
//! program whose sync
//! root is always an ordinary directory, so it passes [`FsStoreFactory`] — the
//! backend the engine used to hard-code. A [`Path`] from the command line is
//! converted to the engine's opaque root **string** exactly once, at the call
//! (see [`root_str`]).

use std::path::Path;

use anyhow::{Result, bail};
use serde_json::json;

use crate::cli::SyncCommand;
use crate::error::{CliError, map_vault_error};
use crate::unlock::{self, PasswordSource};

use lp_sync::engine;
use lp_sync::store::FsStoreFactory;

/// The engine's opaque root string for a filesystem sync dir named on the
/// command line.
///
/// [`std::path::Path::to_string_lossy`] is the exact conversion the engine
/// itself used to perform before persisting `sync.root.<vault_id>`, so an
/// already-enrolled profile keeps matching byte-for-byte.
fn root_str(dir: &Path) -> String {
    dir.to_string_lossy().into_owned()
}

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
        SyncCommand::Adopt { dir } => adopt(&session, dir),
    }
}

/// `sync setup` — enroll a vault under a shared sync-root directory.
fn setup(session: &lp_vault::Session, vault_ref: &str, dir: &Path) -> Result<()> {
    let vault = crate::resolve::open_vault(session, vault_ref)?;
    engine::setup(session, vault.vault_id(), &root_str(dir), &FsStoreFactory)
        .map_err(map_sync_error)?;
    println!(
        "enrolled vault {vault_ref:?} for sync under {}",
        dir.display()
    );
    Ok(())
}

/// `sync push` — publish this device's ops to the channel.
fn push(session: &lp_vault::Session, vault_ref: &str, json_out: bool) -> Result<()> {
    let vault = crate::resolve::open_vault(session, vault_ref)?;
    let report = engine::push(session, &vault, &FsStoreFactory).map_err(map_sync_error)?;
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
    let report = engine::pull(session, &vault, &FsStoreFactory).map_err(map_sync_error)?;

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
                "key_imported": report.key_imported,
                "alarms": alarms,
            }))?
        );
    } else {
        println!(
            "applied {}, skipped {}, pending {}",
            report.applied, report.skipped, report.pending
        );
        if report.key_imported {
            println!("imported a shared vault key addressed to this device");
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
    let st = engine::status(session, &vault, &FsStoreFactory).map_err(map_sync_error)?;

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

/// `localpass sync adopt` — join vaults shared to this device: scan the root
/// for key blobs addressed to us, import + enroll each, then pull its items.
fn adopt(session: &lp_vault::Session, dir: &Path) -> Result<()> {
    let adopted =
        engine::adopt(session, &root_str(dir), &FsStoreFactory).map_err(map_sync_error)?;
    if adopted.is_empty() {
        println!(
            "no shared vaults addressed to this device under {}",
            dir.display()
        );
        return Ok(());
    }
    let names = session.list_vaults().map_err(map_vault_error)?;
    for vault_id in adopted {
        let vault = session.open_vault(vault_id).map_err(map_vault_error)?;
        let report = engine::pull(session, &vault, &FsStoreFactory).map_err(map_sync_error)?;
        let name = names
            .iter()
            .find(|(id, _)| *id == vault_id)
            .map_or_else(|| vault_id.to_hyphenated(), |(_, n)| n.clone());
        println!(
            "adopted vault \"{name}\" ({}): applied {} ops",
            vault_id.to_hyphenated(),
            report.applied
        );
    }
    Ok(())
}

/// Map an `lp_sync::Error` to a [`CliError`] with a sensible exit code.
pub fn map_sync_error(e: lp_sync::Error) -> CliError {
    match e {
        lp_sync::Error::Vault(v) => map_vault_error(v),
        lp_sync::Error::Invalid(m) => CliError::Usage(m.to_string()),
        other => CliError::Internal(anyhow::anyhow!("{other}")),
    }
}
