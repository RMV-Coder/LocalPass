//! `localpass search <query>` — find items by title, tag, or type.
//!
//! Backed by [`lp_vault::Vault::search`] (a linear, secret-free scan in the
//! MVP). Never prints secret values.

use std::path::Path;

use anyhow::Result;

use crate::cli::ItemType;
use crate::error::map_vault_error;
use crate::output;
use crate::resolve;
use crate::unlock::{self, PasswordSource};

/// Run `localpass search`.
///
/// # Errors
///
/// Propagates unlock and storage failures; `CliError::Usage` if the vault is
/// unknown.
pub fn run(
    profile_dir: &Path,
    src: PasswordSource,
    query: &str,
    item_type: Option<ItemType>,
    vault_ref: &str,
    json_out: bool,
) -> Result<()> {
    let (session, _sk) = unlock::unlock(profile_dir, src)?;
    let vault = resolve::open_vault(&session, vault_ref)?;

    let type_filter = item_type.map(ItemType::type_str);
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
