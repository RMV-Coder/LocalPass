//! `localpass backup create|list|verify|restore` (PRD §4.11).
//!
//! Backups are file operations over the profile's SQLite files; the heavy
//! lifting (consistent snapshots, manifest, verify checks, atomic restore) lives
//! in [`lp_vault::backup`]. This module is the CLI surface: argument handling,
//! timestamp/path resolution, daemon-running refusal on restore, confirmation
//! prompts, and human/JSON rendering.
//!
//! # Daemon safety on restore
//!
//! A full restore swaps the live files out from under any process holding them
//! open. If a daemon is running for this profile we **refuse** and tell the user
//! to `daemon stop` first — a restore must not race the daemon's open handles.

use std::io::{IsTerminal, Write};
use std::path::{Path, PathBuf};

use anyhow::{Result, bail};
use serde_json::json;

use lp_daemon::protocol::{Request, Response};

use crate::cli::BackupCommand;
use crate::daemonctl;
use crate::error::{CliError, map_vault_error};
use crate::profile;
use crate::unlock::{self, PasswordSource};

/// Run a `localpass backup ...` subcommand.
///
/// # Errors
///
/// Propagates unlock, filesystem, and verification failures with the documented
/// exit codes.
pub fn run(
    profile_dir: &Path,
    src: PasswordSource,
    no_daemon: bool,
    command: &BackupCommand,
) -> Result<()> {
    match command {
        BackupCommand::Create { to, keep } => create(profile_dir, to.as_deref(), *keep),
        BackupCommand::List { from, json } => list(profile_dir, from.as_deref(), *json),
        BackupCommand::Verify {
            backup,
            from,
            no_recover,
        } => verify(profile_dir, src, backup, from.as_deref(), *no_recover),
        BackupCommand::Restore {
            backup,
            from,
            item,
            vault,
            force,
        } => restore(
            profile_dir,
            src,
            no_daemon,
            backup,
            from.as_deref(),
            item.as_deref(),
            vault,
            *force,
        ),
    }
}

/// The default backups root: `<profile>/backups`.
fn default_root(profile_dir: &Path) -> PathBuf {
    profile_dir.join(lp_vault::backup::BACKUPS_DIR)
}

// --- create ---------------------------------------------------------------

fn create(profile_dir: &Path, to: Option<&Path>, keep: Option<usize>) -> Result<()> {
    if !profile::account_exists(profile_dir) {
        bail!(CliError::usage(format!(
            "no account at {} — run `localpass init` first",
            profile_dir.display()
        )));
    }
    let root = to.map_or_else(|| default_root(profile_dir), Path::to_path_buf);
    let keep = keep.unwrap_or(lp_vault::backup::DEFAULT_KEEP);

    let info = lp_vault::backup::create(profile_dir, &root, keep).map_err(map_vault_error)?;
    println!(
        "created backup {} ({} items, {} versions, {})",
        info.manifest.timestamp,
        info.manifest.total_items(),
        info.manifest.total_versions(),
        human_size(info.total_size),
    );
    println!("  at {}", info.dir.display());
    Ok(())
}

// --- list -----------------------------------------------------------------

fn list(profile_dir: &Path, from: Option<&Path>, json_out: bool) -> Result<()> {
    let root = from.map_or_else(|| default_root(profile_dir), Path::to_path_buf);
    let backups = lp_vault::backup::list(&root).map_err(map_vault_error)?;

    if json_out {
        let arr: Vec<_> = backups
            .iter()
            .map(|b| {
                json!({
                    "timestamp": b.manifest.timestamp,
                    "path": b.dir.display().to_string(),
                    "size": b.total_size,
                    "items": b.manifest.total_items(),
                    "versions": b.manifest.total_versions(),
                })
            })
            .collect();
        println!("{}", serde_json::to_string_pretty(&arr)?);
        return Ok(());
    }

    if backups.is_empty() {
        println!("(no backups in {})", root.display());
        return Ok(());
    }
    println!(
        "{:<18}  {:>8}  {:>6}  {:>8}",
        "TIMESTAMP", "SIZE", "ITEMS", "VERSIONS"
    );
    for b in &backups {
        println!(
            "{:<18}  {:>8}  {:>6}  {:>8}",
            b.manifest.timestamp,
            human_size(b.total_size),
            b.manifest.total_items(),
            b.manifest.total_versions(),
        );
    }
    Ok(())
}

// --- verify ---------------------------------------------------------------

fn verify(
    profile_dir: &Path,
    src: PasswordSource,
    backup: &str,
    from: Option<&Path>,
    no_recover: bool,
) -> Result<()> {
    let backup_dir = resolve_backup(profile_dir, backup, from)?;

    // Check 3 needs credentials. Load the on-device Secret Key + password unless
    // the user opted out with --no-recover.
    let report = if no_recover {
        lp_vault::backup::verify(&backup_dir, None).map_err(map_vault_error)?
    } else {
        let secret_key = profile::load_secret_key(profile_dir).map_err(CliError::usage_from)?;
        let password = unlock::acquire_password(src, "Master password: ")?;
        lp_vault::backup::verify(&backup_dir, Some((&password, &secret_key)))
            .map_err(map_vault_error)?
    };

    // Print each check line.
    for note in &report.notes {
        println!("{note}");
    }

    if report.all_ok() {
        println!("backup OK");
        Ok(())
    } else if report.decrypt_ok == Some(false) && report.hashes_ok && report.integrity_ok {
        // Only the credential check failed → auth exit code (2), so the "wrong
        // password fails check 3, checks 1-2 still pass" contract is observable.
        bail!(CliError::auth(
            "backup is intact but not recoverable with the supplied credentials"
        ));
    } else {
        bail!(CliError::usage("backup verification failed"));
    }
}

// --- restore --------------------------------------------------------------

#[allow(clippy::too_many_arguments)]
fn restore(
    profile_dir: &Path,
    src: PasswordSource,
    no_daemon: bool,
    backup: &str,
    from: Option<&Path>,
    item: Option<&str>,
    vault_ref: &str,
    force: bool,
) -> Result<()> {
    let backup_dir = resolve_backup(profile_dir, backup, from)?;

    if let Some(target) = item {
        return restore_single_item(profile_dir, src, &backup_dir, target, vault_ref);
    }

    // Full restore: refuse if a daemon is running for THIS profile.
    refuse_if_daemon_running(profile_dir, no_daemon)?;

    if !force {
        confirm_full_restore(profile_dir, &backup_dir, src)?;
    }

    let report = lp_vault::backup::restore(profile_dir, &backup_dir).map_err(map_vault_error)?;
    println!(
        "restored {} files from {}",
        report.files_restored,
        backup_dir.display()
    );
    if let Some(pre) = &report.pre_restore_dir {
        println!(
            "  your previous files were moved to {} (delete once you have verified the restore)",
            pre.display()
        );
    }
    Ok(())
}

/// Single-item restore: decrypt the item from the backup and re-create it in the
/// live vault as a new version. Requires an unlock of the live profile (to open
/// the destination vault) and reuses the same credentials for the backup.
fn restore_single_item(
    profile_dir: &Path,
    src: PasswordSource,
    backup_dir: &Path,
    target: &str,
    vault_ref: &str,
) -> Result<()> {
    // Unlock the live profile once; reuse its password + Secret Key for the
    // backup (a backup is recoverable with the CURRENT credentials).
    if !profile::account_exists(profile_dir) {
        bail!(CliError::usage(format!(
            "no account at {} — run `localpass init` first",
            profile_dir.display()
        )));
    }
    let secret_key = profile::load_secret_key(profile_dir).map_err(CliError::usage_from)?;
    let password = unlock::acquire_password(src, "Master password: ")?;

    let session = match lp_vault::AccountStore::unlock(profile_dir, &password, &secret_key) {
        Ok(s) => s,
        Err(lp_vault::Error::DecryptionFailed) => {
            bail!(CliError::auth("wrong master password or Secret Key"))
        }
        Err(e) => bail!(CliError::internal(anyhow::anyhow!("unlock failed: {e}"))),
    };

    // Resolve the destination vault in the LIVE profile.
    let live_vault = crate::resolve::open_vault(&session, vault_ref)?;
    // The backup vault must have the same id (single-item restore stays within a
    // vault): reuse the live vault's id to open the matching backup vault.
    let backup_vault_id = live_vault.vault_id();

    let new_id = lp_vault::backup::restore_single_item(
        backup_dir,
        &password,
        &secret_key,
        backup_vault_id,
        target,
        &live_vault,
    )
    .map_err(map_vault_error)?;

    println!(
        "restored item {:?} into vault {} as a new item ({})",
        target,
        vault_ref,
        new_id.to_hyphenated()
    );
    println!("  (arrives as a new version/op — the op chain stays valid)");
    Ok(())
}

/// Refuse a full restore while a daemon serves this profile (its open file
/// handles would race the file swap). `--no-daemon` skips the check.
fn refuse_if_daemon_running(profile_dir: &Path, no_daemon: bool) -> Result<()> {
    if no_daemon || !daemonctl::is_running() {
        return Ok(());
    }
    // A daemon is up; ask which profile it serves. Only refuse if it is THIS one.
    let Ok(mut client) = lp_daemon::client::Client::connect() else {
        return Ok(());
    };
    let resp = client.call(&Request::Status {
        profile: profile_dir.display().to_string(),
    });
    if let Ok(Response::Status {
        profile: served, ..
    }) = resp
    {
        let same = Path::new(&served) == profile_dir
            || std::fs::canonicalize(&served).ok() == std::fs::canonicalize(profile_dir).ok();
        if same {
            bail!(CliError::usage(
                "a daemon is running for this profile; run `localpass daemon stop` before restoring"
            ));
        }
    }
    Ok(())
}

/// Prompt to confirm a full restore (it replaces the live profile).
fn confirm_full_restore(profile_dir: &Path, backup_dir: &Path, src: PasswordSource) -> Result<()> {
    if src.no_input {
        bail!(CliError::usage(
            "refusing a full restore without confirmation under --no-input; pass --force"
        ));
    }
    if !std::io::stdin().is_terminal() {
        bail!(CliError::usage(
            "not a terminal; pass --force to restore non-interactively"
        ));
    }
    println!(
        "This will REPLACE the live profile at {} with the backup at {}.",
        profile_dir.display(),
        backup_dir.display()
    );
    println!("Your current files will be moved aside first (not deleted).");
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

// --- helpers --------------------------------------------------------------

/// Resolve a `<timestamp-or-path>` argument to a backup directory.
///
/// If it exists as a path (absolute or relative), use it directly; otherwise
/// treat it as a bare timestamp under `--from` / the default backups root.
fn resolve_backup(profile_dir: &Path, backup: &str, from: Option<&Path>) -> Result<PathBuf> {
    let as_path = PathBuf::from(backup);
    if as_path.join(lp_vault::backup::MANIFEST_FILE).exists() {
        return Ok(as_path);
    }
    let root = from.map_or_else(|| default_root(profile_dir), Path::to_path_buf);
    let candidate = root.join(backup);
    if candidate.join(lp_vault::backup::MANIFEST_FILE).exists() {
        return Ok(candidate);
    }
    Err(CliError::usage(format!(
        "no backup {backup:?} found (looked for a path and under {})",
        root.display()
    ))
    .into())
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
