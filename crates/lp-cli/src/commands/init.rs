//! `localpass init` — create the account and print the Emergency Kit.
//!
//! Flow (PRD §4.11):
//! 1. Refuse if an account already exists in the profile.
//! 2. Prompt for the master password twice (hidden), enforcing a minimum length.
//! 3. [`lp_vault::AccountStore::create`] — generates the Secret Key + AccountKey,
//!    writes the account store.
//! 4. Create a default vault named `personal`.
//! 5. Store the Secret Key on-device at `<profile>/secret-key` (owner-only).
//! 6. Print the **Emergency Kit**: the Secret Key display string, the profile
//!    path, and the stern no-recovery guidance — shown **once**.

use std::path::Path;

use anyhow::{Result, bail};
use lp_vault::AccountStore;

use crate::error::{CliError, map_vault_error};
use crate::profile;
use crate::unlock::{self, PasswordSource};

/// Minimum master-password length. zxcvbn-style strength feedback is out of
/// scope for this MVP; a clear length floor is the honest interim guard
/// (the Secret Key is what makes even a weak password non-offline-crackable,
/// PRD §4.3 / T12).
const MIN_PASSWORD_LEN: usize = 10;

/// The default vault created at init.
const DEFAULT_VAULT: &str = "personal";

/// Run `localpass init`.
///
/// # Errors
///
/// - [`CliError::Usage`] if an account already exists or the password is too
///   short.
/// - [`CliError::Internal`] on a storage failure.
pub fn run(profile_dir: &Path, src: PasswordSource) -> Result<()> {
    if profile::account_exists(profile_dir) {
        bail!(CliError::usage(format!(
            "an account already exists at {} — refusing to overwrite",
            profile_dir.display()
        )));
    }

    let password = unlock::acquire_new_password(src, "Choose a master password: ")?;
    if password.chars().count() < MIN_PASSWORD_LEN {
        bail!(CliError::usage(format!(
            "master password must be at least {MIN_PASSWORD_LEN} characters"
        )));
    }

    // Create the account. The Secret Key is returned exactly once here.
    let (session, secret_key) = AccountStore::create(profile_dir, &password).map_err(|e| {
        // create() maps "already exists" to Invalid; other paths are internal.
        match e {
            lp_vault::Error::Invalid(_) => CliError::usage(format!(
                "an account already exists at {}",
                profile_dir.display()
            )),
            other => map_vault_error(other),
        }
    })?;

    // Default vault.
    session
        .create_vault(DEFAULT_VAULT)
        .map_err(map_vault_error)?;

    // Persist the Secret Key on-device (MVP keychain stand-in).
    profile::store_secret_key(profile_dir, &secret_key).map_err(CliError::internal)?;

    print_emergency_kit(profile_dir, &secret_key.to_display_string());
    Ok(())
}

/// Print the Emergency Kit block to stdout. The Secret Key is shown **once**;
/// there is no command to reprint it (only the printed kit and the on-device
/// file hold it).
fn print_emergency_kit(profile_dir: &Path, secret_key: &str) {
    let bar = "=".repeat(64);
    println!("{bar}");
    println!("  LocalPass EMERGENCY KIT — store this OFFLINE, now.");
    println!("{bar}");
    println!();
    println!("  Secret Key:   {secret_key}");
    println!("  Profile path: {}", profile_dir.display());
    println!();
    println!("  This Secret Key is a 128-bit second factor mixed into your");
    println!("  master password. Together they are the ONLY way into your data.");
    println!();
    println!("  >> PRINT THIS AND STORE IT OFFLINE (a safe, a drawer, on paper). <<");
    println!();
    println!("  There is NO cloud reset and NO recovery service. If you lose your");
    println!("  master password AND this Secret Key AND all your devices, your");
    println!("  data is gone forever. That is the design (PRD §4.11).");
    println!();
    println!("  A copy of the Secret Key is stored on THIS device at:");
    println!("      {}", profile::secret_key_path(profile_dir).display());
    println!("  with owner-only permissions. That on-device copy is the MVP");
    println!("  stand-in for OS-keychain storage; it is only as safe as this");
    println!("  machine's file permissions. The printed kit is authoritative.");
    println!();
    println!("  A default vault named \"{DEFAULT_VAULT}\" has been created.");
    println!("{bar}");
}
