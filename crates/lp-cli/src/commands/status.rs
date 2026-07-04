//! `localpass status` — profile path, account presence, and vault count.
//!
//! Honest about the no-daemon MVP: there is no persistent unlocked session, so
//! "lock state" is not applicable and is reported as such. The vault count
//! requires unlocking (vault names/registry are encrypted), so `status` unlocks
//! only when an account exists.

use std::path::Path;

use anyhow::Result;
use serde_json::json;

use crate::error::map_vault_error;
use crate::profile;
use crate::unlock::{self, PasswordSource};

/// Run `localpass status`.
///
/// # Errors
///
/// Propagates unlock failures (wrong password → auth exit) only when an account
/// exists and a vault count is therefore requested.
pub fn run(profile_dir: &Path, src: PasswordSource, json_out: bool) -> Result<()> {
    let exists = profile::account_exists(profile_dir);
    let has_secret_key = profile::secret_key_path(profile_dir).exists();

    // Vault count needs an unlock; only attempt it when an account exists.
    let vault_count: Option<usize> = if exists {
        let (session, _sk) = unlock::unlock(profile_dir, src)?;
        let vaults = session.list_vaults().map_err(map_vault_error)?;
        Some(vaults.len())
    } else {
        None
    };

    if json_out {
        let obj = json!({
            "profile": profile_dir.display().to_string(),
            "account_exists": exists,
            "secret_key_on_device": has_secret_key,
            "vault_count": vault_count,
            // No daemon in this build: there is no persistent lock state.
            "lock_state": "n/a (no daemon; each command unlocks directly)",
        });
        println!("{}", serde_json::to_string_pretty(&obj)?);
    } else {
        println!("Profile:        {}", profile_dir.display());
        println!("Account exists: {}", yes_no(exists));
        println!("Secret Key here: {}", yes_no(has_secret_key));
        match vault_count {
            Some(n) => println!("Vaults:         {n}"),
            None => println!("Vaults:         (n/a — no account)"),
        }
        println!("Lock state:     n/a (no daemon; each command unlocks directly)");
    }
    Ok(())
}

fn yes_no(b: bool) -> &'static str {
    if b { "yes" } else { "no" }
}
