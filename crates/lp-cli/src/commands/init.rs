//! `localpass init` — create the account and print the Emergency Kit.
//!
//! Flow (PRD §4.11):
//! 1. Refuse if an account already exists in the profile.
//! 2. Prompt for the master password twice (hidden), enforcing a minimum length.
//! 3. [`lp_vault::AccountStore::create`] — generates the Secret Key + AccountKey,
//!    writes the account store.
//! 4. Create a default vault named `personal`.
//! 5. Store the Secret Key on-device at `<profile>/secret-key` (owner-only).
//! 6. Print the **Emergency Kit** (rendered by [`crate::commands::kit`]) to
//!    stdout — shown **once** — and, if `--kit-out` was given, also save a copy
//!    to a file **outside** the profile.

use std::path::Path;

use anyhow::{Result, bail};
use lp_vault::AccountStore;

use crate::cli::InitArgs;
use crate::commands::kit;
use crate::error::{CliError, map_vault_error};
use crate::profile;
use crate::timestamp;
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
pub fn run(profile_dir: &Path, src: PasswordSource, args: &InitArgs) -> Result<()> {
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

    // Render the Emergency Kit once, print to stdout (as before), and — if
    // requested — also save a copy to a file OUTSIDE the profile.
    let secret_key_display = secret_key.to_display_string();
    let created_ms =
        AccountStore::created_at(profile_dir).unwrap_or_else(|_| lp_vault::db::now_millis());
    let created = timestamp::format_millis_utc(created_ms);

    print!(
        "{}",
        kit::render_text(profile_dir, &secret_key_display, &created)
    );
    println!("  A default vault named \"{DEFAULT_VAULT}\" has been created.");

    if let Some(out) = &args.kit_out {
        // Reuse the kit command's guard: never write inside the profile.
        kit::save_kit_file(
            profile_dir,
            out,
            args.kit_format,
            &secret_key_display,
            &created,
        )
        .map_err(|e| {
            // A bad --kit-out path is a usage error, not a fatal init failure —
            // the account was created and the kit was printed. Surface it clearly.
            CliError::usage(format!("account created, but --kit-out failed: {e}"))
        })?;
        println!("  Emergency Kit also written to {}", out.display());
    }

    Ok(())
}
