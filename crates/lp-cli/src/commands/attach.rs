//! `localpass attach ...` — encrypted file attachments on an item (PRD §4.1).
//!
//! Each subcommand unlocks **directly** (the daemon-proxied path for attachments
//! is a later wave), resolves the target vault (`--vault`, default `personal`)
//! and item (title or id), and acts. Blob bytes are never printed; the decrypted
//! plaintext leaves the vault only via `attach get --out <path>`, which writes to
//! a user-chosen destination.

use std::io::{IsTerminal, Write};
use std::path::Path;

use anyhow::{Result, bail};
use serde_json::json;
use uuid::Uuid;

use crate::cli::AttachCommand;
use crate::error::{CliError, map_vault_error};
use crate::resolve;
use crate::unlock::{self, PasswordSource};

use lp_vault::{AttachmentId, AttachmentInfo, Id, Vault};

/// Run a `localpass attach ...` subcommand.
///
/// Always uses the direct-unlock path — daemon proxying for attachments is the
/// next wave (a plain direct implementation is intentional here).
///
/// # Errors
///
/// Propagates unlock, resolution, and storage failures with the documented exit
/// codes (1 usage, 2 auth, 3 internal).
pub fn run(profile_dir: &Path, src: PasswordSource, command: &AttachCommand) -> Result<()> {
    let (session, _sk) = unlock::unlock(profile_dir, src)?;
    match command {
        AttachCommand::Add {
            item,
            path,
            vault,
            name,
        } => add(&session, vault, item, path, name.as_deref()),
        AttachCommand::List { item, vault, json } => list(&session, vault, item, *json),
        AttachCommand::Get {
            item,
            attachment,
            out,
            vault,
            force,
        } => get(&session, vault, item, attachment, out, *force),
        AttachCommand::Rm {
            item,
            attachment,
            vault,
            force,
        } => rm(&session, vault, item, attachment, *force, src),
    }
}

// --- add -------------------------------------------------------------------

fn add(
    session: &lp_vault::Session,
    vault_ref: &str,
    item_ref: &str,
    path: &Path,
    name: Option<&str>,
) -> Result<()> {
    let vault = resolve::open_vault(session, vault_ref)?;
    let item = resolve::find_item(&vault, item_ref)?;

    // Derive the stored filename: --name, else the source file's base name.
    let filename = match name {
        Some(n) => n.to_string(),
        None => path
            .file_name()
            .and_then(|f| f.to_str())
            .map(str::to_string)
            .ok_or_else(|| CliError::usage("could not derive a filename; pass --name"))?,
    };

    // Read the file. A friendly error if it is over the cap (checked again in
    // the vault before any blob write, but we give a clear message up front).
    let data = std::fs::read(path)
        .map_err(|e| CliError::usage(format!("cannot read {}: {e}", path.display())))?;
    if data.len() > lp_vault::MAX_ATTACHMENT_BYTES {
        bail!(CliError::usage(format!(
            "{} is {} bytes, over the {} MiB attachment limit",
            path.display(),
            data.len(),
            lp_vault::MAX_ATTACHMENT_BYTES / (1024 * 1024),
        )));
    }

    let id = vault
        .add_attachment(item.item_id, &filename, &data)
        .map_err(map_vault_error)?;
    println!("attached {filename:?} ({})", id.to_hyphenated());
    Ok(())
}

// --- list ------------------------------------------------------------------

fn list(
    session: &lp_vault::Session,
    vault_ref: &str,
    item_ref: &str,
    json_out: bool,
) -> Result<()> {
    let vault = resolve::open_vault(session, vault_ref)?;
    let item = resolve::find_item(&vault, item_ref)?;
    let attachments = vault
        .list_attachments(item.item_id)
        .map_err(map_vault_error)?;

    if json_out {
        let arr: Vec<_> = attachments
            .iter()
            .map(|a| {
                json!({
                    "id": a.attachment_id.to_hyphenated(),
                    "name": a.filename,
                    "size": a.size_plain,
                    "version": a.version,
                })
            })
            .collect();
        println!("{}", serde_json::to_string_pretty(&arr)?);
    } else if attachments.is_empty() {
        println!("(no attachments)");
    } else {
        print_table(&attachments);
    }
    Ok(())
}

/// Print an `id  size  name` table (never any blob bytes).
fn print_table(attachments: &[AttachmentInfo]) {
    println!("{:<36}  {:>10}  NAME", "ID", "SIZE");
    for a in attachments {
        println!(
            "{:<36}  {:>10}  {}",
            a.attachment_id.to_hyphenated(),
            human_size(u64::try_from(a.size_plain).unwrap_or(0)),
            a.filename,
        );
    }
}

// --- get -------------------------------------------------------------------

fn get(
    session: &lp_vault::Session,
    vault_ref: &str,
    item_ref: &str,
    attachment_ref: &str,
    out: &Path,
    force: bool,
) -> Result<()> {
    let vault = resolve::open_vault(session, vault_ref)?;
    let item = resolve::find_item(&vault, item_ref)?;
    let attachment_id = resolve_attachment(&vault, item.item_id, attachment_ref)?;

    // Refuse to overwrite an existing file unless --force.
    if out.exists() && !force {
        bail!(CliError::usage(format!(
            "{} already exists; pass --force to overwrite",
            out.display()
        )));
    }

    let (filename, data) = vault
        .get_attachment(attachment_id)
        .map_err(map_vault_error)?;

    write_out_0600(out, &data)?;
    println!(
        "wrote {} ({} bytes) from attachment {filename:?}",
        out.display(),
        data.len()
    );
    Ok(())
}

/// Write `data` to `path`, creating it with 0600 permissions on Unix (the
/// decrypted plaintext lands here — that is inherent to saving a file). On
/// Windows the file inherits the parent directory's ACLs.
fn write_out_0600(path: &Path, data: &[u8]) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(path)
            .map_err(|e| CliError::internal(anyhow::anyhow!("writing {}: {e}", path.display())))?;
        f.write_all(data)
            .map_err(|e| CliError::internal(anyhow::anyhow!("writing {}: {e}", path.display())))?;
    }
    #[cfg(not(unix))]
    {
        std::fs::write(path, data)
            .map_err(|e| CliError::internal(anyhow::anyhow!("writing {}: {e}", path.display())))?;
    }
    Ok(())
}

// --- rm --------------------------------------------------------------------

fn rm(
    session: &lp_vault::Session,
    vault_ref: &str,
    item_ref: &str,
    attachment_ref: &str,
    force: bool,
    src: PasswordSource,
) -> Result<()> {
    let vault = resolve::open_vault(session, vault_ref)?;
    let item = resolve::find_item(&vault, item_ref)?;
    let attachment_id = resolve_attachment(&vault, item.item_id, attachment_ref)?;

    if !force {
        confirm_delete(attachment_ref, src)?;
    }

    vault
        .delete_attachment(attachment_id)
        .map_err(map_vault_error)?;
    println!("removed attachment {}", attachment_id.to_hyphenated());
    Ok(())
}

fn confirm_delete(attachment_ref: &str, src: PasswordSource) -> Result<()> {
    if src.no_input {
        bail!(CliError::usage(
            "refusing to remove without confirmation under --no-input; pass --force"
        ));
    }
    if !std::io::stdin().is_terminal() {
        bail!(CliError::usage(
            "not a terminal; pass --force to remove non-interactively"
        ));
    }
    print!("Remove attachment {attachment_ref:?}? [y/N] ");
    std::io::stdout().flush()?;
    let mut line = String::new();
    std::io::stdin().read_line(&mut line)?;
    let ans = line.trim().to_ascii_lowercase();
    if ans != "y" && ans != "yes" {
        bail!(CliError::usage("aborted"));
    }
    Ok(())
}

// --- resolution ------------------------------------------------------------

/// Resolve an attachment reference (its id or its decrypted name) to an
/// [`AttachmentId`] within `item_id`.
///
/// # Errors
///
/// [`CliError::Usage`] if no attachment matches, or a name is ambiguous.
fn resolve_attachment(
    vault: &Vault<'_>,
    item_id: lp_vault::ItemId,
    reference: &str,
) -> Result<AttachmentId> {
    let attachments = vault.list_attachments(item_id).map_err(map_vault_error)?;

    // Id path: an attachment id is a UUID that matches a listed attachment.
    if let Ok(uuid) = Uuid::parse_str(reference) {
        let id = Id::from_bytes(*uuid.as_bytes());
        if attachments.iter().any(|a| a.attachment_id == id) {
            return Ok(id);
        }
    }

    // Name path: match on the decrypted filename.
    let matches: Vec<AttachmentId> = attachments
        .iter()
        .filter(|a| a.filename == reference)
        .map(|a| a.attachment_id)
        .collect();
    match matches.as_slice() {
        [] => Err(CliError::usage(format!(
            "no attachment named or id {reference:?} on this item"
        ))
        .into()),
        [only] => Ok(*only),
        _ => Err(CliError::usage(format!(
            "attachment name {reference:?} is ambiguous ({} match); use the attachment id",
            matches.len()
        ))
        .into()),
    }
}

// --- shared ----------------------------------------------------------------

/// Format a byte count as a compact human size (B / KiB / MiB).
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
