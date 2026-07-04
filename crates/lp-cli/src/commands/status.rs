//! `localpass status` — profile path, account presence, vault count, and (if a
//! daemon is running) its lock state.
//!
//! When a daemon is running and unlocked for this profile, `status` reports its
//! state and gets the vault count from the daemon (no re-prompt). When no daemon
//! is running (or `--no-daemon`), it behaves exactly as before: it unlocks
//! directly to read the encrypted vault count, and reports the lock state as
//! "n/a (no daemon)".

use std::path::Path;

use anyhow::Result;
use serde_json::json;

use crate::daemonctl::{self, Route};
use crate::error::map_vault_error;
use crate::profile;
use crate::unlock::{self, PasswordSource};

use lp_daemon::protocol::{LockState, Request, Response};

/// Run `localpass status`.
///
/// # Errors
///
/// Propagates unlock failures (wrong password → auth exit) only when an account
/// exists and a vault count is therefore requested via the direct path.
pub fn run(profile_dir: &Path, src: PasswordSource, no_daemon: bool, json_out: bool) -> Result<()> {
    let exists = profile::account_exists(profile_dir);
    let has_secret_key = profile::secret_key_path(profile_dir).exists();

    // If a daemon is running and unlocked for this profile, report its state and
    // take the vault count from it (no direct unlock / re-prompt).
    if let Route::Proxy(mut client) = daemonctl::route(profile_dir, no_daemon) {
        let resp = daemonctl::call(
            &mut client,
            &Request::Status {
                profile: profile_dir.display().to_string(),
            },
        )?;
        if let Response::Status {
            state, vault_count, ..
        } = resp
        {
            let lock_state = match state {
                LockState::Unlocked => "unlocked (daemon)",
                LockState::Locked => "locked (daemon)",
            };
            emit(
                json_out,
                profile_dir,
                exists,
                has_secret_key,
                vault_count,
                lock_state,
            );
            return Ok(());
        }
    }

    // Direct path: vault count needs an unlock; only attempt it when an account
    // exists. Lock state is n/a without a running daemon.
    let vault_count: Option<usize> = if exists {
        let (session, _sk) = unlock::unlock(profile_dir, src)?;
        let vaults = session.list_vaults().map_err(map_vault_error)?;
        Some(vaults.len())
    } else {
        None
    };
    emit(
        json_out,
        profile_dir,
        exists,
        has_secret_key,
        vault_count,
        "n/a (no daemon; each command unlocks directly)",
    );
    Ok(())
}

/// Emit the status block in human or JSON form.
fn emit(
    json_out: bool,
    profile_dir: &Path,
    exists: bool,
    has_secret_key: bool,
    vault_count: Option<usize>,
    lock_state: &str,
) {
    if json_out {
        let obj = json!({
            "profile": profile_dir.display().to_string(),
            "account_exists": exists,
            "secret_key_on_device": has_secret_key,
            "vault_count": vault_count,
            "lock_state": lock_state,
        });
        println!("{}", serde_json::to_string_pretty(&obj).unwrap_or_default());
    } else {
        println!("Profile:        {}", profile_dir.display());
        println!("Account exists: {}", yes_no(exists));
        println!("Secret Key here: {}", yes_no(has_secret_key));
        match vault_count {
            Some(n) => println!("Vaults:         {n}"),
            None => println!("Vaults:         (n/a — no account)"),
        }
        println!("Lock state:     {lock_state}");
    }
}

fn yes_no(b: bool) -> &'static str {
    if b { "yes" } else { "no" }
}
