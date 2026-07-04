//! `localpass vault list|create` — vault registry operations.

use std::path::Path;

use anyhow::{Result, bail};
use serde_json::json;

use crate::cli::VaultCommand;
use crate::daemonctl::{self, Route};
use crate::error::{CliError, map_vault_error};
use crate::unlock::{self, PasswordSource};

use lp_daemon::protocol::{Request, Response};

/// Run a `localpass vault ...` subcommand (daemon-first, direct fallback).
///
/// Note: `vault create` is not proxied (the daemon has no create-vault request
/// in the MVP); it always uses the direct path. `vault list` proxies when the
/// daemon is unlocked.
///
/// # Errors
///
/// Propagates unlock and storage failures.
pub fn run(
    profile_dir: &Path,
    src: PasswordSource,
    no_daemon: bool,
    command: &VaultCommand,
) -> Result<()> {
    // vault list can proxy; vault create falls through to direct.
    if let VaultCommand::List { json: json_out } = command
        && let Route::Proxy(mut client) = daemonctl::route(profile_dir, no_daemon)
    {
        let resp = daemonctl::call(
            &mut client,
            &Request::ListVaults {
                profile: profile_dir.display().to_string(),
            },
        )?;
        daemonctl::check_error(&resp)?;
        let Response::Vaults { vaults } = resp else {
            bail!(CliError::internal(anyhow::anyhow!(
                "unexpected daemon response: {}",
                resp.kind()
            )));
        };
        if *json_out {
            let arr: Vec<_> = vaults
                .iter()
                .map(|(id, name)| json!({ "id": id, "name": name }))
                .collect();
            println!("{}", serde_json::to_string_pretty(&arr)?);
        } else if vaults.is_empty() {
            println!("(no vaults)");
        } else {
            for (id, name) in &vaults {
                println!("{name}\t{id}");
            }
        }
        return Ok(());
    }

    let (session, _sk) = unlock::unlock(profile_dir, src)?;
    match command {
        VaultCommand::List { json: json_out } => {
            let vaults = session.list_vaults().map_err(map_vault_error)?;
            if *json_out {
                let arr: Vec<_> = vaults
                    .iter()
                    .map(|(id, name)| json!({ "id": id.to_hyphenated(), "name": name }))
                    .collect();
                println!("{}", serde_json::to_string_pretty(&arr)?);
            } else if vaults.is_empty() {
                println!("(no vaults)");
            } else {
                for (id, name) in &vaults {
                    println!("{name}\t{}", id.to_hyphenated());
                }
            }
        }
        VaultCommand::Create { name } => {
            let id = session.create_vault(name).map_err(map_vault_error)?;
            println!("created vault {name:?} ({})", id.to_hyphenated());
        }
        VaultCommand::Stats { vault, json } => stats(&session, vault, *json)?,
        VaultCommand::Prune {
            vault,
            keep_last,
            older_than,
            dry_run,
            force,
            json,
        } => prune(
            &session,
            vault,
            *keep_last,
            older_than.as_deref(),
            *dry_run,
            *force,
            *json,
            src,
        )?,
        VaultCommand::ShareToDevice { device_id, vault } => {
            share_to_device(&session, vault, device_id)?;
        }
    }
    Ok(())
}

/// `localpass vault share-to-device` — seal this vault's key to a trusted peer
/// device (typed key transport; raw key bytes never surface) and ship it via
/// the sync `keys/` dir. The peer picks it up with `localpass sync adopt`.
fn share_to_device(session: &lp_vault::Session, vault_ref: &str, device_ref: &str) -> Result<()> {
    // Resolve + validate the vault exists and the target is a trusted peer.
    let vault = crate::resolve::open_vault(session, vault_ref)?;
    let vault_id = vault.vault_id();
    let device_id = uuid::Uuid::parse_str(device_ref)
        .map(|u| lp_vault::Id::from_bytes(*u.as_bytes()))
        .map_err(|_| CliError::usage(format!("device id {device_ref:?} is not a valid UUID")))?;

    lp_sync::engine::share_vault_to_device(session, vault_id, &device_id)
        .map_err(crate::commands::sync::map_sync_error)?;
    println!(
        "sealed the \"{vault_ref}\" vault key to device {device_ref} and shipped it via the \
         sync channel. On that device, run: localpass sync adopt --dir <sync-root>"
    );
    Ok(())
}

/// `localpass vault stats` — the PRD's "very visible storage statistics"
/// (PRD §4.10): items, versions, trash, index segments, and the vault file size.
fn stats(session: &lp_vault::Session, vault_ref: &str, json_out: bool) -> Result<()> {
    let vault = crate::resolve::open_vault(session, vault_ref)?;
    let s = vault.storage_stats().map_err(map_vault_error)?;
    let file_size = vault_file_size(session, &vault);

    if json_out {
        println!(
            "{}",
            serde_json::to_string_pretty(&json!({
                "vault": vault_ref,
                "live_items": s.live_items,
                "total_versions": s.total_versions,
                "trashed": s.trashed,
                "index_segments": s.index_segments,
                "file_size_bytes": file_size,
            }))?
        );
    } else {
        println!("Vault:          {vault_ref}");
        println!("Live items:     {}", s.live_items);
        println!("Total versions: {}", s.total_versions);
        println!("In trash:       {}", s.trashed);
        println!("Index segments: {}", s.index_segments);
        match file_size {
            Some(b) => println!("File size:      {}", human_size(b)),
            None => println!("File size:      (unavailable)"),
        }
    }
    Ok(())
}

/// `localpass vault prune` — reclaim local storage by removing old item versions
/// (PRD §11 #8). Dry-run prints the report without deleting; a real run asks for
/// confirmation unless `--force`. The op log is never touched.
#[allow(clippy::too_many_arguments, clippy::fn_params_excessive_bools)]
fn prune(
    session: &lp_vault::Session,
    vault_ref: &str,
    keep_last: u32,
    older_than: Option<&str>,
    dry_run: bool,
    force: bool,
    json_out: bool,
    src: PasswordSource,
) -> Result<()> {
    let vault = crate::resolve::open_vault(session, vault_ref)?;

    // Parse --older-than into an absolute cutoff (now - duration).
    let older_than_ms = match older_than {
        Some(spec) => {
            let dur_ms = parse_duration_ms(spec)?;
            Some(lp_vault::db::now_millis().saturating_sub(dur_ms))
        }
        None => None,
    };

    if dry_run {
        // Preview without deleting: the dry-run selection is identical to a real
        // prune's, but the transaction is rolled back so nothing is removed.
        let report = vault
            .prune_versions_dry_run(keep_last, older_than_ms)
            .map_err(map_vault_error)?;
        emit_prune_report(&report, vault_ref, true, json_out);
        return Ok(());
    }

    if !force {
        confirm_prune(vault_ref, keep_last, older_than, src)?;
    }

    let report = vault
        .prune_versions(keep_last, older_than_ms)
        .map_err(map_vault_error)?;
    emit_prune_report(&report, vault_ref, false, json_out);
    Ok(())
}

/// Render a [`lp_vault::PruneReport`] (dry-run or real) in human or JSON form.
fn emit_prune_report(
    report: &lp_vault::PruneReport,
    vault_ref: &str,
    dry_run: bool,
    json_out: bool,
) {
    if json_out {
        let per_item: Vec<_> = report
            .per_item
            .iter()
            .map(|(id, n)| json!({ "item_id": id.to_hyphenated(), "versions_removed": n }))
            .collect();
        let obj = json!({
            "vault": vault_ref,
            "dry_run": dry_run,
            "versions_removed": report.versions_removed,
            "bytes_reclaimed": report.bytes_reclaimed,
            "items_affected": report.per_item.len(),
            "per_item": per_item,
        });
        println!("{}", serde_json::to_string_pretty(&obj).unwrap_or_default());
        return;
    }

    let verb = if dry_run { "would remove" } else { "removed" };
    println!(
        "{verb} {} version(s) across {} item(s), ~{} reclaimed",
        report.versions_removed,
        report.per_item.len(),
        human_size(report.bytes_reclaimed),
    );
    if dry_run {
        println!("(dry run — nothing was deleted)");
    }
}

/// Confirm a real prune (it permanently removes old versions).
fn confirm_prune(
    vault_ref: &str,
    keep_last: u32,
    older_than: Option<&str>,
    src: PasswordSource,
) -> Result<()> {
    use std::io::{IsTerminal, Write};
    if src.no_input {
        bail!(CliError::usage(
            "refusing to prune without confirmation under --no-input; pass --force (or --dry-run)"
        ));
    }
    if !std::io::stdin().is_terminal() {
        bail!(CliError::usage(
            "not a terminal; pass --force to prune non-interactively (or --dry-run to preview)"
        ));
    }
    let age = older_than.map_or_else(String::new, |a| format!(", older than {a}"));
    println!(
        "Prune old versions in vault {vault_ref:?} (keeping the newest {keep_last} per item{age})."
    );
    println!("The current version is always kept; the op log is not touched.");
    print!("Proceed? [y/N] ");
    std::io::stdout().flush()?;
    let mut line = String::new();
    std::io::stdin().read_line(&mut line)?;
    let ans = line.trim().to_ascii_lowercase();
    if ans != "y" && ans != "yes" {
        bail!(CliError::usage("aborted"));
    }
    Ok(())
}

/// The size in bytes of a vault's SQLite file, if it can be stat'd.
fn vault_file_size(session: &lp_vault::Session, vault: &lp_vault::Vault<'_>) -> Option<u64> {
    let path = session.vault_file_path(&vault.vault_id());
    std::fs::metadata(path).ok().map(|m| m.len())
}

/// Parse a duration like `365d`, `12h`, `30m`, `45s`, or a bare integer
/// (milliseconds) into milliseconds.
fn parse_duration_ms(spec: &str) -> Result<i64> {
    let spec = spec.trim();
    if spec.is_empty() {
        bail!(CliError::usage("empty --older-than duration"));
    }
    let (num_part, unit_ms): (&str, i64) = if let Some(n) = spec.strip_suffix('d') {
        (n, 24 * 60 * 60 * 1000)
    } else if let Some(n) = spec.strip_suffix('h') {
        (n, 60 * 60 * 1000)
    } else if let Some(n) = spec.strip_suffix('m') {
        (n, 60 * 1000)
    } else if let Some(n) = spec.strip_suffix('s') {
        (n, 1000)
    } else {
        (spec, 1) // bare integer = milliseconds
    };
    let value: i64 = num_part
        .trim()
        .parse()
        .map_err(|_| CliError::usage(format!("invalid --older-than duration {spec:?}")))?;
    if value < 0 {
        bail!(CliError::usage("--older-than must not be negative"));
    }
    Ok(value.saturating_mul(unit_ms))
}

/// Format a byte count as a compact human size (KiB/MiB).
fn human_size(bytes: u64) -> String {
    #[allow(clippy::cast_precision_loss)]
    let b = bytes as f64;
    if bytes >= 1024 * 1024 {
        format!("{:.1} MiB", b / (1024.0 * 1024.0))
    } else if bytes >= 1024 {
        format!("{:.1} KiB", b / 1024.0)
    } else {
        format!("{bytes} B")
    }
}
