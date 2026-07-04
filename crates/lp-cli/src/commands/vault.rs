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
    }
    Ok(())
}
