//! `localpass search <query>` — find items by title, tag, or type.
//!
//! Backed by [`lp_vault::Vault::search`] (a linear, secret-free scan in the
//! MVP). Never prints secret values.

use std::path::Path;

use anyhow::{Result, bail};

use crate::cli::ItemType;
use crate::daemonctl::{self, Route};
use crate::error::{CliError, map_vault_error};
use crate::output;
use crate::resolve;
use crate::unlock::{self, PasswordSource};

use lp_daemon::protocol::{Request, Response};

/// Run `localpass search` (daemon-first, direct fallback).
///
/// # Errors
///
/// Propagates unlock and storage failures; `CliError::Usage` if the vault is
/// unknown.
pub fn run(
    profile_dir: &Path,
    src: PasswordSource,
    no_daemon: bool,
    query: &str,
    item_type: Option<ItemType>,
    vault_ref: &str,
    json_out: bool,
) -> Result<()> {
    let type_filter = item_type.map(ItemType::type_str);

    if let Route::Proxy(mut client) = daemonctl::route(profile_dir, no_daemon) {
        let resp = daemonctl::call(
            &mut client,
            &Request::Search {
                profile: profile_dir.display().to_string(),
                vault: vault_ref.to_string(),
                query: query.to_string(),
                type_filter: type_filter.map(str::to_string),
            },
        )?;
        daemonctl::check_error(&resp)?;
        let Response::Items { items } = resp else {
            bail!(CliError::internal(anyhow::anyhow!(
                "unexpected daemon response: {}",
                resp.kind()
            )));
        };
        if json_out {
            let arr: Vec<_> = items.iter().map(daemonctl::summary_to_json).collect();
            println!("{}", serde_json::to_string_pretty(&arr)?);
        } else if items.is_empty() {
            println!("(no matches)");
        } else {
            daemonctl::print_summary_table(&items);
        }
        return Ok(());
    }

    let (session, _sk) = unlock::unlock(profile_dir, src)?;
    let vault = resolve::open_vault(&session, vault_ref)?;
    let hits = vault.search(query, type_filter).map_err(map_vault_error)?;

    if json_out {
        let arr: Vec<_> = hits.iter().map(output::item_summary_json).collect();
        println!("{}", serde_json::to_string_pretty(&arr)?);
    } else if hits.is_empty() {
        println!("(no matches)");
    } else {
        crate::commands::item::print_item_table(&hits);
    }
    Ok(())
}
