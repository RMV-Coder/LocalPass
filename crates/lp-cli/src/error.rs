//! CLI error taxonomy and the exit-code contract.
//!
//! Every command returns `anyhow::Result<()>`. When it fails, `main` downcasts
//! to [`CliError`] to pick the process exit code and prints **one** clean line
//! to stderr — never a Rust `Debug` dump, never a secret value.
//!
//! # Exit codes (PRD §4.4)
//!
//! | Code | Meaning            | Variant             |
//! |------|--------------------|---------------------|
//! | 0    | success            | (no error)          |
//! | 1    | user error         | [`CliError::Usage`] |
//! | 2    | authentication     | [`CliError::Auth`]  |
//! | 3    | internal error     | [`CliError::Internal`] and any non-`CliError` error |
//!
//! `Usage` covers bad arguments, not-found items/vaults, and precondition
//! failures ("account already exists"). `Auth` is *only* a wrong master
//! password / Secret Key. `Internal` is a bug or an unexpected IO/DB failure.

use std::fmt;

/// A CLI-level error carrying the message to show and the exit code to use.
#[derive(Debug)]
pub enum CliError {
    /// Exit code 1 — bad input, missing item/vault, or a violated precondition.
    Usage(String),
    /// Exit code 2 — a wrong master password or Secret Key.
    Auth(String),
    /// Exit code 3 — an unexpected internal/IO/DB failure. Wraps the source so
    /// context is preserved for the one-line render, but never a secret.
    Internal(anyhow::Error),
}

impl CliError {
    /// The process exit code for this error.
    #[must_use]
    pub fn exit_code(&self) -> i32 {
        match self {
            CliError::Usage(_) => 1,
            CliError::Auth(_) => 2,
            CliError::Internal(_) => 3,
        }
    }

    /// Construct a [`CliError::Usage`].
    #[must_use]
    pub fn usage(msg: impl Into<String>) -> Self {
        CliError::Usage(msg.into())
    }

    /// Turn an arbitrary error into a [`CliError::Usage`] (using its message).
    #[must_use]
    pub fn usage_from(e: impl fmt::Display) -> Self {
        CliError::Usage(e.to_string())
    }

    /// Construct a [`CliError::Auth`].
    #[must_use]
    pub fn auth(msg: impl Into<String>) -> Self {
        CliError::Auth(msg.into())
    }

    /// Construct a [`CliError::Internal`] from any error.
    #[must_use]
    pub fn internal(e: impl Into<anyhow::Error>) -> Self {
        CliError::Internal(e.into())
    }
}

impl fmt::Display for CliError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CliError::Usage(m) | CliError::Auth(m) => f.write_str(m),
            CliError::Internal(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for CliError {}

/// Map a raw `lp_vault::Error` to a [`CliError`] with sensible exit codes.
///
/// `DecryptionFailed` at the vault level after unlock is an internal issue
/// (unlock already gates auth), not a user auth failure; `NotFound` / `Invalid`
/// are user errors.
#[must_use]
pub fn map_vault_error(e: lp_vault::Error) -> CliError {
    match e {
        lp_vault::Error::NotFound(what) => CliError::Usage(format!("not found: {what}")),
        lp_vault::Error::Invalid(what) => CliError::Usage(format!("invalid: {what}")),
        lp_vault::Error::UnsupportedFormat { found, supported } => CliError::Usage(format!(
            "vault file format {found} is newer than this build supports ({supported}); upgrade LocalPass"
        )),
        other => CliError::Internal(anyhow::anyhow!("{other}")),
    }
}
