//! The unlock flow shared by every command that touches a vault.
//!
//! Steps (PRD §4.3 / §7.2, minus the daemon — each command unlocks directly):
//!
//! 1. Load the on-device Secret Key from `<profile>/secret-key`
//!    ([`crate::profile::load_secret_key`]).
//! 2. Acquire the master password (env var → `--password-stdin` → hidden
//!    prompt), honouring `--no-input`.
//! 3. Call [`lp_vault::AccountStore::unlock`], which re-derives the MUK and
//!    unwraps the AccountKey — a wrong password or Secret Key fails **here**
//!    with `DecryptionFailed`, mapped to the auth exit code by the caller.
//!
//! # Password sources & their trade-offs
//!
//! | Source                | When                          | Note |
//! |-----------------------|-------------------------------|------|
//! | `LOCALPASS_PASSWORD`  | always checked first          | script-only; env vars can leak into process listings and are inherited by children — prefer stdin |
//! | `--password-stdin`    | flag set                      | read one line from stdin; the recommended scripted path (pipe it) |
//! | hidden TTY prompt     | interactive, no other source  | via `rpassword`; never echoed |
//!
//! Under `--no-input`, the prompt path is disabled: if neither the env var nor
//! `--password-stdin` supplied a password, the command fails rather than block.

use std::io::{IsTerminal, Read};
use std::path::Path;

use anyhow::{Context, Result, anyhow, bail};
use lp_crypto::SecretKey;
use lp_vault::{AccountStore, Session};

use crate::error::CliError;
use crate::profile;

/// The environment variable a script may set to supply the master password.
pub const PASSWORD_ENV: &str = "LOCALPASS_PASSWORD";

/// How the password should be acquired for a single command invocation.
#[derive(Debug, Clone, Copy)]
pub struct PasswordSource {
    /// `--no-input`: never prompt.
    pub no_input: bool,
    /// `--password-stdin`: read one line from stdin.
    pub stdin: bool,
}

/// Acquire the master password from (in order) the env var, stdin, or a hidden
/// prompt.
///
/// `prompt` is the label shown on the interactive path (e.g.
/// `"Master password: "`).
///
/// # Errors
///
/// - [`CliError::Usage`] if no source is available under `--no-input`, or if
///   stdin was requested but empty.
/// - [`CliError::Internal`] on an IO failure reading stdin or the TTY.
pub fn acquire_password(src: PasswordSource, prompt: &str) -> Result<String> {
    // 1) Environment variable (script-only path). Present-but-empty is treated
    //    as "set" so a caller can force an empty password deliberately.
    if let Ok(pw) = std::env::var(PASSWORD_ENV) {
        return Ok(pw);
    }

    // 2) Explicit stdin pipe.
    if src.stdin {
        let mut buf = String::new();
        std::io::stdin()
            .read_to_string(&mut buf)
            .context("reading master password from stdin")
            .map_err(CliError::internal)?;
        // Strip exactly one trailing line ending (LF or CRLF) — the password
        // itself may legitimately contain interior whitespace, so we do not
        // fully trim.
        let pw = buf
            .strip_suffix('\n')
            .map_or(buf.as_str(), |s| s.strip_suffix('\r').unwrap_or(s));
        return Ok(pw.to_string());
    }

    // 3) Interactive prompt — forbidden under --no-input.
    if src.no_input {
        return Err(CliError::usage(format!(
            "no password available: set {PASSWORD_ENV}, pass --password-stdin, or drop --no-input"
        ))
        .into());
    }
    if !std::io::stdin().is_terminal() {
        return Err(CliError::usage(format!(
            "stdin is not a terminal and no password was provided; pipe it with --password-stdin or set {PASSWORD_ENV}"
        ))
        .into());
    }
    let pw = rpassword::prompt_password(prompt)
        .context("reading master password from the terminal")
        .map_err(CliError::internal)?;
    Ok(pw)
}

/// Prompt for a *new* password twice (confirmation) on the interactive path.
///
/// Used by `init` and `password change`. Honours the env var / stdin / no-input
/// sources for the first entry so scripted flows still work; when a
/// non-interactive source supplies the value there is no second confirmation to
/// compare against, so it is accepted as-is.
///
/// # Errors
///
/// - [`CliError::Usage`] if the two interactive entries differ, or no source is
///   available under `--no-input`.
pub fn acquire_new_password(src: PasswordSource, first_prompt: &str) -> Result<String> {
    // Non-interactive sources: a single value, no confirmation possible.
    if std::env::var(PASSWORD_ENV).is_ok() || src.stdin {
        return acquire_password(src, first_prompt);
    }
    if src.no_input {
        return Err(CliError::usage(format!(
            "no password available: set {PASSWORD_ENV}, pass --password-stdin, or drop --no-input"
        ))
        .into());
    }
    if !std::io::stdin().is_terminal() {
        return Err(CliError::usage(
            "stdin is not a terminal; provide the new password with --password-stdin or LOCALPASS_PASSWORD".to_string(),
        )
        .into());
    }
    let first = rpassword::prompt_password(first_prompt)
        .context("reading new password")
        .map_err(CliError::internal)?;
    let again = rpassword::prompt_password("Confirm master password: ")
        .context("reading password confirmation")
        .map_err(CliError::internal)?;
    if first != again {
        return Err(CliError::usage("passwords did not match".to_string()).into());
    }
    Ok(first)
}

/// Load the Secret Key and unlock the account at `profile`.
///
/// # Errors
///
/// - [`CliError::Usage`] if no account exists at `profile`.
/// - [`CliError::Auth`] on a wrong password or Secret Key.
/// - [`CliError::Internal`] on other storage failures.
pub fn unlock(profile_dir: &Path, src: PasswordSource) -> Result<(Session, SecretKey)> {
    if !profile::account_exists(profile_dir) {
        bail!(CliError::usage(format!(
            "no account at {} — run `localpass init` first",
            profile_dir.display()
        )));
    }
    let secret_key = profile::load_secret_key(profile_dir).map_err(CliError::usage_from)?;
    let password = acquire_password(src, "Master password: ")?;

    match AccountStore::unlock(profile_dir, &password, &secret_key) {
        Ok(session) => Ok((session, secret_key)),
        Err(lp_vault::Error::DecryptionFailed) => {
            Err(CliError::auth("wrong master password or Secret Key").into())
        }
        Err(lp_vault::Error::NotFound(_)) => Err(CliError::usage(format!(
            "no account at {} — run `localpass init` first",
            profile_dir.display()
        ))
        .into()),
        Err(e) => Err(CliError::internal(anyhow!("unlock failed: {e}")).into()),
    }
}
