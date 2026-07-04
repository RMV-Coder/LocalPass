//! `localpass export <format> <path>` — export items to a file.
//!
//! # Routing
//!
//! Like import, export always unlocks **directly** (never proxied): the daemon's
//! MVP protocol has no "dump all items" request and this work unit may not
//! extend it. `--no-daemon` is a no-op here.
//!
//! # Formats
//!
//! - `age` — the recoverable encrypted archive ([`lp_porter::export::archive`]).
//!   Prompts for a passphrase twice (or `--passphrase-stdin`). The output is
//!   decryptable by the standalone `age` CLI.
//! - `json` / `csv` — full-secret **plaintext**, refused unless
//!   `--i-understand-plaintext-export` is set; a stern warning prints to stderr.
//! - `dotenv` — a single env-set item → `KEY=value` lines.
//!
//! # Secret hygiene
//!
//! The age passphrase is a [`Zeroizing`] string handled like a master password.
//! The output file is written owner-only (0600 on Unix). No secret is ever
//! logged; the plaintext formats' contents go only to the target file.

use std::io::{Read, Write};
use std::path::Path;

use anyhow::{Result, bail};
use lp_vault::{ItemPayload, Session};
use zeroize::Zeroizing;

use crate::cli::{ExportArgs, ExportFormat};
use crate::error::{CliError, map_vault_error};
use crate::resolve;
use crate::unlock::{self, PasswordSource};

/// Run `localpass export ...`.
///
/// # Errors
///
/// - [`CliError::Usage`] (exit 1) on a missing guard flag, unknown vault/item,
///   or a write failure.
/// - [`CliError::Auth`] (exit 2) on a wrong master password.
pub fn run(
    profile_dir: &Path,
    src: PasswordSource,
    _no_daemon: bool,
    args: &ExportArgs,
) -> Result<()> {
    // Guard the plaintext formats BEFORE unlocking, so a forgotten flag fails
    // fast and loudly without touching the vault.
    if matches!(args.format, ExportFormat::Json | ExportFormat::Csv)
        && !args.i_understand_plaintext_export
    {
        bail!(CliError::usage(
            "refusing to write a PLAINTEXT export: this writes ALL your secrets \
             unencrypted to disk. Re-run with --i-understand-plaintext-export if \
             you really mean it (prefer `export age`)."
        ));
    }

    let (session, _sk) = unlock::unlock(profile_dir, src)?;

    match args.format {
        ExportFormat::Age => export_age(&session, args, src),
        ExportFormat::Json | ExportFormat::Csv => export_plaintext(&session, args),
        ExportFormat::Dotenv => export_dotenv(&session, args),
    }
}

/// Which vaults to export: the `--vault` list, or `personal` by default.
fn vault_refs(args: &ExportArgs) -> Vec<String> {
    if args.vault.is_empty() {
        vec!["personal".to_string()]
    } else {
        args.vault.clone()
    }
}

/// Gather `(vault_name, items)` for each selected vault.
fn gather(session: &Session, refs: &[String]) -> Result<Vec<(String, Vec<ItemPayload>)>> {
    let mut out = Vec::new();
    for r in refs {
        let vault = resolve::open_vault(session, r)?;
        let items = vault.list_items().map_err(map_vault_error)?;
        let payloads: Vec<ItemPayload> = items.into_iter().map(|it| it.payload).collect();
        out.push((r.clone(), payloads));
    }
    Ok(out)
}

/// The age-encrypted archive (the recommended, recoverable export).
fn export_age(session: &Session, args: &ExportArgs, src: PasswordSource) -> Result<()> {
    let vaults = gather(session, &vault_refs(args))?;
    let total: usize = vaults.iter().map(|(_, v)| v.len()).sum();

    let passphrase = acquire_passphrase(src, args.passphrase_stdin, true)?;
    let now = now_millis();
    let bytes = lp_porter::export::archive::encrypt_archive(&vaults, now, &passphrase)
        .map_err(|e| CliError::internal(anyhow::anyhow!("{e}")))?;

    write_owner_only(&args.path, &bytes)?;
    eprintln!(
        "wrote age archive with {total} item(s) to {} (decrypt with `age -d`)",
        args.path.display()
    );
    Ok(())
}

/// Plaintext JSON or CSV (already guarded by the caller).
fn export_plaintext(session: &Session, args: &ExportArgs) -> Result<()> {
    let vaults = gather(session, &vault_refs(args))?;
    let total: usize = vaults.iter().map(|(_, v)| v.len()).sum();

    eprintln!(
        "WARNING: writing {total} item(s) as PLAINTEXT (secrets in cleartext) to {}",
        args.path.display()
    );
    let now = now_millis();
    let bytes = match args.format {
        ExportFormat::Json => lp_porter::export::plaintext::to_json(&vaults, now),
        ExportFormat::Csv => lp_porter::export::plaintext::to_csv(&vaults),
        _ => unreachable!("guarded caller only routes json/csv here"),
    }
    .map_err(|e| CliError::internal(anyhow::anyhow!("{e}")))?;

    write_owner_only(&args.path, &bytes)?;
    eprintln!("wrote {} (PLAINTEXT)", args.path.display());
    Ok(())
}

/// A single env-set item → dotenv lines.
fn export_dotenv(session: &Session, args: &ExportArgs) -> Result<()> {
    let Some(set_ref) = &args.env_set else {
        bail!(CliError::usage(
            "dotenv export needs --env-set <title|id> to choose the env-set item"
        ));
    };
    // Use the first --vault (or personal) as the lookup vault.
    let vault_ref = vault_refs(args).into_iter().next().unwrap_or_default();
    let vault = resolve::open_vault(session, &vault_ref)?;
    let item = resolve::find_item(&vault, set_ref)?;
    let rendered = lp_porter::export::dotenv::to_dotenv(&item.payload)
        .map_err(|e| CliError::usage(e.to_string()))?;

    write_owner_only(&args.path, rendered.as_bytes())?;
    eprintln!("wrote env-set to {} (0600 on Unix)", args.path.display());
    Ok(())
}

/// Prompt for (or read from stdin) the age passphrase, zeroized. Prompts twice
/// on the interactive path when `confirm`.
fn acquire_passphrase(
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
        if pw.is_empty() {
            bail!(CliError::usage("empty passphrase"));
        }
        return Ok(Zeroizing::new(pw.to_string()));
    }
    if src.no_input {
        bail!(CliError::usage(
            "no passphrase available: pass --passphrase-stdin or drop --no-input"
        ));
    }
    let first = rpassword::prompt_password("Archive passphrase: ")
        .map_err(|e| CliError::internal(anyhow::anyhow!("reading passphrase: {e}")))?;
    if first.is_empty() {
        bail!(CliError::usage("empty passphrase"));
    }
    if confirm {
        let again = rpassword::prompt_password("Confirm passphrase: ")
            .map_err(|e| CliError::internal(anyhow::anyhow!("reading passphrase: {e}")))?;
        if first != again {
            bail!(CliError::usage("passphrases did not match"));
        }
    }
    Ok(Zeroizing::new(first))
}

/// Current unix-millis (best-effort; 0 if the clock is before the epoch).
fn now_millis() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| i64::try_from(d.as_millis()).unwrap_or(i64::MAX))
        .unwrap_or(0)
}

/// Write `bytes` to `path`, owner-only (0600 on Unix). Mirrors the env-export
/// writer.
fn write_owner_only(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut f = opts
        .open(path)
        .map_err(|e| CliError::usage(format!("cannot write {}: {e}", path.display())))?;
    f.write_all(bytes)
        .map_err(|e| CliError::internal(anyhow::anyhow!("writing {}: {e}", path.display())))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
            .map_err(|e| CliError::internal(anyhow::anyhow!("chmod {}: {e}", path.display())))?;
    }
    Ok(())
}
