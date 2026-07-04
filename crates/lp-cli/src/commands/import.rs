//! `localpass import <format> <path>` — import a foreign export into a vault.
//!
//! # Routing
//!
//! Import always unlocks **directly** against the storage core (never proxied
//! through the daemon). The daemon's MVP wire protocol has no bulk item-create
//! request, and this work unit may not extend it (it lives in `lp-daemon`).
//! `--no-daemon` is therefore a no-op for import; the flag is still accepted for
//! uniformity. Creating N items directly is correct and safe — each `create_item`
//! is its own durable transaction.
//!
//! # What it does
//!
//! Parse the file with [`lp_porter::import`], then `create_item` each parsed
//! [`ItemPayload`](lp_vault::ItemPayload) in the chosen vault. Reports the count
//! imported and, on a partial parse, the skipped entries **by title only**. The
//! input file is only read — never modified or deleted (see the report note vs
//! PRD §4.6's shred aspiration).
//!
//! # Secret hygiene
//!
//! No secret value is ever printed: the skip report shows titles and value-free
//! reasons; a create failure names the item title, never its contents.

use std::io::Read;
use std::path::Path;

use anyhow::{Result, bail};
use lp_porter::import::csv_generic::ColumnMap;
use lp_porter::{ImportOutcome, PorterError};
use lp_vault::Session;
use zeroize::Zeroizing;

use crate::cli::{ImportArgs, ImportFormat};
use crate::error::{CliError, map_vault_error};
use crate::resolve;
use crate::unlock::{self, PasswordSource};

/// Run `localpass import ...`.
///
/// # Errors
///
/// - [`CliError::Usage`] (exit 1) on a bad file, malformed input, unknown vault,
///   or the KDBX stub.
/// - [`CliError::Auth`] (exit 2) on a wrong master password.
/// - [`CliError::Internal`] (exit 3) on a storage failure.
pub fn run(
    profile_dir: &Path,
    src: PasswordSource,
    _no_daemon: bool,
    args: &ImportArgs,
) -> Result<()> {
    // Parse the foreign file FIRST (before unlocking) so a bad file fails fast
    // and cheaply, without paying the Argon2 unlock cost.
    let outcome = parse(args, src)?;

    // Now unlock and create the items.
    let (session, _sk) = unlock::unlock(profile_dir, src)?;
    create_all(&session, &args.vault, outcome)
}

/// Parse the input file for `args`'s format into an [`ImportOutcome`].
fn parse(args: &ImportArgs, src: PasswordSource) -> Result<ImportOutcome> {
    use lp_porter::import::{bitwarden, csv_generic, dotenv, kdbx, lastpass, onepux};

    let path = args.path.as_path();
    let outcome = match args.format {
        ImportFormat::OnePassword => onepux::parse_file(path).map_err(porter_usage)?,
        ImportFormat::Bitwarden => {
            bitwarden::parse_bytes(&read_bytes(path)?).map_err(porter_usage)?
        }
        ImportFormat::Lastpass => {
            lastpass::parse_bytes(&read_bytes(path)?).map_err(porter_usage)?
        }
        ImportFormat::Csv => {
            let map = build_column_map(&args.map)?;
            csv_generic::parse_bytes(&read_bytes(path)?, &map).map_err(porter_usage)?
        }
        ImportFormat::Env => {
            dotenv::parse_file(path, args.title.as_deref()).map_err(porter_usage)?
        }
        ImportFormat::Kdbx => {
            // Prompt/read the KDBX password (the stub ignores it, but we honour
            // the documented input path so wiring a real parser later is a
            // drop-in and the flag behaves).
            let password = acquire_archive_passphrase(src, args.kdbx_password_stdin, false)?;
            kdbx::parse_file(path, &password).map_err(porter_usage)?
        }
        ImportFormat::Age => {
            let passphrase = acquire_archive_passphrase(src, args.kdbx_password_stdin, false)?;
            let archive =
                lp_porter::export::archive::decrypt_archive(&read_bytes(path)?, &passphrase)
                    .map_err(porter_usage)?;
            let mut o = ImportOutcome::new();
            for item in archive.all_items() {
                o.push(item);
            }
            o
        }
    };
    Ok(outcome)
}

/// Read a whole file into bytes, mapping IO errors to a clean usage error.
fn read_bytes(path: &Path) -> Result<Vec<u8>> {
    std::fs::read(path)
        .map_err(|e| CliError::usage(format!("cannot read {}: {e}", path.display())).into())
}

/// Build a [`ColumnMap`] from repeated `--map field=COLUMN` flags.
fn build_column_map(entries: &[String]) -> Result<ColumnMap> {
    let mut map = ColumnMap::default();
    for e in entries {
        let Some((field, column)) = e.split_once('=') else {
            bail!(CliError::usage(format!(
                "malformed --map {e:?} (expected field=COLUMN)"
            )));
        };
        let column = column.to_string();
        match field.trim().to_ascii_lowercase().as_str() {
            "title" => map.title = Some(column),
            "username" => map.username = Some(column),
            "password" => map.password = Some(column),
            "url" => map.url = Some(column),
            "notes" => map.notes = Some(column),
            other => bail!(CliError::usage(format!(
                "unknown --map field {other:?} (expected title/username/password/url/notes)"
            ))),
        }
    }
    if map.title.is_none() {
        bail!(CliError::usage(
            "generic CSV import needs at least --map title=COLUMN"
        ));
    }
    Ok(map)
}

/// Prompt for (or read from stdin) the archive/KDBX passphrase, zeroized.
///
/// `confirm` asks twice on the interactive path (used by export, not import).
fn acquire_archive_passphrase(
    src: PasswordSource,
    stdin: bool,
    confirm: bool,
) -> Result<Zeroizing<String>> {
    if stdin {
        let mut buf = String::new();
        std::io::stdin().read_to_string(&mut buf).map_err(|e| {
            CliError::internal(anyhow::anyhow!("reading passphrase from stdin: {e}"))
        })?;
        let pw = buf
            .strip_suffix('\n')
            .map_or(buf.as_str(), |s| s.strip_suffix('\r').unwrap_or(s));
        return Ok(Zeroizing::new(pw.to_string()));
    }
    if src.no_input {
        bail!(CliError::usage(
            "no passphrase available: pass --kdbx-password-stdin / --passphrase-stdin or drop --no-input"
        ));
    }
    let first = rpassword::prompt_password("Archive passphrase: ")
        .map_err(|e| CliError::internal(anyhow::anyhow!("reading passphrase: {e}")))?;
    if confirm {
        let again = rpassword::prompt_password("Confirm passphrase: ")
            .map_err(|e| CliError::internal(anyhow::anyhow!("reading passphrase: {e}")))?;
        if first != again {
            bail!(CliError::usage("passphrases did not match"));
        }
    }
    Ok(Zeroizing::new(first))
}

/// Create every parsed item in `vault_ref`, then print a value-free summary.
fn create_all(session: &Session, vault_ref: &str, outcome: ImportOutcome) -> Result<()> {
    let vault = resolve::open_vault(session, vault_ref)?;
    let mut created = 0usize;
    let mut skipped = outcome.skipped;
    for item in &outcome.items {
        match vault.create_item(item) {
            Ok(_) => created += 1,
            Err(e) => {
                // Record but keep going; name the title only, never contents.
                skipped.push(lp_porter::SkippedEntry {
                    title: item.title.clone(),
                    reason: format!("storage error: {}", map_vault_error(e)),
                });
            }
        }
    }

    println!("imported {created} item(s) into {vault_ref:?}");
    if !skipped.is_empty() {
        println!("skipped {} entr(y/ies):", skipped.len());
        for s in &skipped {
            // Titles + value-free reason only.
            println!("  {:?}: {}", s.title, s.reason);
        }
    }
    Ok(())
}

/// Map a porter error to a clean [`CliError::Usage`] (exit 1). Parse failures are
/// user-level: the file was bad, or the format is unsupported. The message is
/// already value-free by construction in `lp-porter`.
fn porter_usage(e: PorterError) -> CliError {
    CliError::usage(e.to_string())
}
