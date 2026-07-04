//! `localpass vault list|create` — vault registry operations.

use std::path::Path;

use anyhow::Result;
use serde_json::json;

use crate::cli::VaultCommand;
use crate::error::map_vault_error;
use crate::unlock::{self, PasswordSource};

/// Run a `localpass vault ...` subcommand.
///
/// # Errors
///
/// Propagates unlock and storage failures.
pub fn run(profile_dir: &Path, src: PasswordSource, command: &VaultCommand) -> Result<()> {
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
    }
    Ok(())
}
