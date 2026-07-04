//! `localpass item ...` — the item CRUD surface.
//!
//! All subcommands unlock, resolve the target vault (`--vault`, default
//! `personal`), and act. Secret values are masked by default and only revealed
//! by `item get --reveal` / `--field`.

use std::io::{IsTerminal, Write};
use std::path::Path;

use anyhow::{Result, bail};
use lp_vault::Item;

use crate::cli::{ItemAddArgs, ItemCommand, ItemEditArgs};
use crate::content;
use crate::error::{CliError, map_vault_error};
use crate::output;
use crate::resolve;
use crate::unlock::{self, PasswordSource};

/// The default trash retention window: 30 days in milliseconds (PRD §4.10).
const TRASH_RETENTION_MS: i64 = 30 * 24 * 60 * 60 * 1000;

/// Run a `localpass item ...` subcommand.
///
/// # Errors
///
/// Propagates unlock, resolution, and storage failures with the documented
/// exit codes.
pub fn run(profile_dir: &Path, src: PasswordSource, command: &ItemCommand) -> Result<()> {
    let (session, _sk) = unlock::unlock(profile_dir, src)?;
    match command {
        ItemCommand::Add(args) => add(&session, args),
        ItemCommand::Get {
            target,
            vault,
            reveal,
            field,
            json,
        } => get(&session, vault, target, *reveal, field.as_deref(), *json),
        ItemCommand::List { vault, json } => list(&session, vault, *json),
        ItemCommand::Edit(args) => edit(&session, args),
        ItemCommand::Rm {
            target,
            vault,
            force,
        } => rm(&session, vault, target, *force, src),
        ItemCommand::History {
            target,
            vault,
            json,
        } => history(&session, vault, target, *json),
        ItemCommand::Restore {
            target,
            version,
            vault,
        } => restore(&session, vault, target, *version),
    }
}

// --- add -----------------------------------------------------------------

fn add(session: &lp_vault::Session, args: &ItemAddArgs) -> Result<()> {
    let vault = resolve::open_vault(session, &args.content.vault)?;
    let (payload, built) = content::build_new(args.item_type, &args.title, &args.content)?;
    let id = vault.create_item(&payload).map_err(map_vault_error)?;
    println!("added {:?} ({})", args.title, id.to_hyphenated());
    if let Some(pw) = built.generated_password {
        // The generated password is shown once, on its own line, so the user
        // can capture it. (This is an explicit user action: --generate.)
        println!("generated password: {pw}");
    }
    Ok(())
}

// --- get -----------------------------------------------------------------

fn get(
    session: &lp_vault::Session,
    vault_ref: &str,
    target: &str,
    reveal: bool,
    field: Option<&str>,
    json_out: bool,
) -> Result<()> {
    let vault = resolve::open_vault(session, vault_ref)?;
    let item = resolve::find_item(&vault, target)?;
    let fields = output::display_fields(&item.payload);

    // --field: print exactly one raw value to stdout and nothing else.
    if let Some(name) = field {
        let Some(f) = output::find_field(&fields, name) else {
            bail!(CliError::usage(format!("item has no field {name:?}")));
        };
        // Raw value, one trailing newline. --field is an explicit reveal of
        // that single field (secret or not), for scripting.
        let mut stdout = std::io::stdout().lock();
        stdout.write_all(f.value.as_bytes())?;
        stdout.write_all(b"\n")?;
        return Ok(());
    }

    if json_out {
        println!(
            "{}",
            serde_json::to_string_pretty(&output::item_to_json(&item, reveal))?
        );
        return Ok(());
    }

    // Human view.
    println!("Title:   {}", item.payload.title);
    println!("Type:    {}", item.payload.type_data.type_str());
    println!("Id:      {}", item.item_id.to_hyphenated());
    println!("Version: {}", item.current_version);
    if !item.payload.tags.is_empty() {
        println!("Tags:    {}", item.payload.tags.join(", "));
    }
    if !item.payload.notes.is_empty() {
        println!("Notes:   {}", item.payload.notes);
    }
    if fields.is_empty() {
        println!("(no fields)");
    } else {
        println!("Fields:");
        for f in &fields {
            let marker = if f.secret { " (secret)" } else { "" };
            println!("  {}{}: {}", f.name, marker, f.shown(reveal));
        }
    }
    if !reveal && fields.iter().any(|f| f.secret) {
        eprintln!("(secrets masked; pass --reveal to show, or --field <name> for one value)");
    }
    Ok(())
}

// --- list ----------------------------------------------------------------

fn list(session: &lp_vault::Session, vault_ref: &str, json_out: bool) -> Result<()> {
    let vault = resolve::open_vault(session, vault_ref)?;
    let items = vault.list_items().map_err(map_vault_error)?;
    if json_out {
        let arr: Vec<_> = items.iter().map(output::item_summary_json).collect();
        println!("{}", serde_json::to_string_pretty(&arr)?);
    } else if items.is_empty() {
        println!("(no items)");
    } else {
        print_item_table(&items);
    }
    Ok(())
}

/// Print a plain `title  type  updated` table (never any secret value). Shared
/// by `item list` and `search`.
pub fn print_item_table(items: &[Item]) {
    // Compute a title column width (bounded so a pathological title cannot blow
    // out the layout).
    let width = items
        .iter()
        .map(|i| i.payload.title.chars().count())
        .max()
        .unwrap_or(5)
        .clamp(5, 40);
    println!("{:<width$}  {:<8}  UPDATED", "TITLE", "TYPE", width = width);
    for it in items {
        println!(
            "{:<width$}  {:<8}  {}",
            truncate(&it.payload.title, width),
            it.payload.type_data.type_str(),
            it.updated_at,
            width = width
        );
    }
}

/// Truncate a title to `max` chars with an ellipsis, for table display only.
fn truncate(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        s.to_string()
    } else {
        let head: String = s.chars().take(max.saturating_sub(1)).collect();
        format!("{head}…")
    }
}

// --- edit ----------------------------------------------------------------

fn edit(session: &lp_vault::Session, args: &ItemEditArgs) -> Result<()> {
    let vault = resolve::open_vault(session, &args.content.vault)?;
    let item = resolve::find_item(&vault, &args.target)?;
    let mut payload = item.payload;
    let built = content::apply_edit(&mut payload, args.title.as_deref(), &args.content)?;
    let version = vault
        .update_item(item.item_id, &payload)
        .map_err(map_vault_error)?;
    println!(
        "updated {} → version {version}",
        item.item_id.to_hyphenated()
    );
    if let Some(pw) = built.generated_password {
        println!("generated password: {pw}");
    }
    Ok(())
}

// --- rm ------------------------------------------------------------------

fn rm(
    session: &lp_vault::Session,
    vault_ref: &str,
    target: &str,
    force: bool,
    src: PasswordSource,
) -> Result<()> {
    let vault = resolve::open_vault(session, vault_ref)?;
    let item = resolve::find_item(&vault, target)?;

    if !force {
        confirm_delete(&item, src)?;
    }

    vault
        .delete_item(item.item_id, TRASH_RETENTION_MS)
        .map_err(map_vault_error)?;
    println!(
        "moved {:?} to trash (recoverable for 30 days)",
        item.payload.title
    );
    Ok(())
}

/// Prompt (stdin y/N) to confirm a deletion, unless `--no-input` is set (in
/// which case a delete without `--force` is refused).
fn confirm_delete(item: &Item, src: PasswordSource) -> Result<()> {
    if src.no_input {
        bail!(CliError::usage(
            "refusing to delete without confirmation under --no-input; pass --force"
        ));
    }
    if !std::io::stdin().is_terminal() {
        bail!(CliError::usage(
            "not a terminal; pass --force to delete non-interactively"
        ));
    }
    print!("Delete {:?} → trash? [y/N] ", item.payload.title);
    std::io::stdout().flush()?;
    let mut line = String::new();
    std::io::stdin().read_line(&mut line)?;
    let ans = line.trim().to_ascii_lowercase();
    if ans != "y" && ans != "yes" {
        bail!(CliError::usage("aborted"));
    }
    Ok(())
}

// --- history -------------------------------------------------------------

fn history(
    session: &lp_vault::Session,
    vault_ref: &str,
    target: &str,
    json_out: bool,
) -> Result<()> {
    let vault = resolve::open_vault(session, vault_ref)?;
    // Resolve to an id first (title or id), then read history by id.
    let item = resolve::find_item(&vault, target)?;
    let versions = vault.history(item.item_id).map_err(map_vault_error)?;

    if json_out {
        let arr: Vec<_> = versions
            .iter()
            .map(|v| {
                serde_json::json!({
                    "version": v.version,
                    "created_at": v.created_at,
                    "title": v.payload.title,
                    "type": v.payload.type_data.type_str(),
                })
            })
            .collect();
        println!("{}", serde_json::to_string_pretty(&arr)?);
    } else {
        println!("History of {}:", item.item_id.to_hyphenated());
        for v in &versions {
            println!(
                "  v{:<4} {:<10} {}",
                v.version, v.created_at, v.payload.title
            );
        }
    }
    Ok(())
}

// --- restore -------------------------------------------------------------

fn restore(session: &lp_vault::Session, vault_ref: &str, target: &str, version: i64) -> Result<()> {
    let vault = resolve::open_vault(session, vault_ref)?;
    let item = resolve::find_item(&vault, target)?;
    let new_version = vault
        .restore_version(item.item_id, version)
        .map_err(map_vault_error)?;
    println!(
        "restored version {version} of {} as new version {new_version}",
        item.item_id.to_hyphenated()
    );
    Ok(())
}
