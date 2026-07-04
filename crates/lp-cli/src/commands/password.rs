//! `localpass password change` — rotate the master password.
//!
//! Unlocks with the old password (which verifies it), then re-wraps the
//! AccountKey under a MUK derived from the new password (a fresh salt); the
//! AccountKey plaintext and the Secret Key are unchanged
//! ([`lp_vault::Session::change_password`]).

use std::path::Path;

use anyhow::{Result, bail};
use lp_vault::AccountStore;

use crate::cli::PasswordCommand;
use crate::error::{CliError, map_vault_error};
use crate::profile;
use crate::unlock::{self, PasswordSource};

/// Minimum length for the new password (mirrors `init`).
const MIN_PASSWORD_LEN: usize = 10;

/// Run `localpass password ...`.
///
/// # Errors
///
/// - [`CliError::Auth`] if the old password / Secret Key is wrong.
/// - [`CliError::Usage`] if the new password is too short or no account exists.
pub fn run(profile_dir: &Path, src: PasswordSource, command: &PasswordCommand) -> Result<()> {
    match command {
        PasswordCommand::Change => change(profile_dir, src),
    }
}

fn change(profile_dir: &Path, src: PasswordSource) -> Result<()> {
    if !profile::account_exists(profile_dir) {
        bail!(CliError::usage(format!(
            "no account at {} — run `localpass init` first",
            profile_dir.display()
        )));
    }
    let secret_key = profile::load_secret_key(profile_dir).map_err(CliError::usage_from)?;

    // Acquire the OLD password once and unlock with it (verifies it).
    let old_password = unlock::acquire_password(src, "Current master password: ")?;
    let session = match AccountStore::unlock(profile_dir, &old_password, &secret_key) {
        Ok(s) => s,
        Err(lp_vault::Error::DecryptionFailed) => {
            return Err(CliError::auth("wrong master password or Secret Key").into());
        }
        Err(e) => return Err(map_vault_error(e).into()),
    };

    let new_password = unlock::acquire_new_password(src, "New master password: ")?;
    if new_password.chars().count() < MIN_PASSWORD_LEN {
        return Err(CliError::usage(format!(
            "new master password must be at least {MIN_PASSWORD_LEN} characters"
        ))
        .into());
    }

    session
        .change_password(&old_password, &new_password, &secret_key)
        .map_err(map_vault_error)?;
    println!("master password changed.");
    Ok(())
}
