//! Profile-directory resolution and on-device Secret Key storage.
//!
//! A *profile* is the directory holding the account store
//! (`account.localpass`), the `vaults/` subdirectory, and — as the MVP
//! stand-in for OS-keychain integration — the [`SECRET_KEY_FILE`].
//!
//! # Where the profile lives
//!
//! With no `--profile`, LocalPass uses the platform data directory via the
//! `directories` crate:
//!
//! | OS      | Default profile path                         |
//! |---------|----------------------------------------------|
//! | Windows | `%APPDATA%\localpass`                        |
//! | macOS   | `~/Library/Application Support/localpass`    |
//! | Linux   | `$XDG_DATA_HOME/localpass` (`~/.local/share/localpass`) |
//!
//! # Secret Key on device (PRD §4.3 — keychain is P2)
//!
//! The Secret Key is a 128-bit second KDF factor. The final product stores it
//! in the OS keychain (Keychain / Credential Manager / libsecret); that is
//! **P2**. For this MVP the CLI persists the Secret Key **display string** in a
//! plain file at `<profile>/secret-key` with owner-only permissions (`0600` on
//! Unix; owner-scoped profile-directory ACLs on Windows — the same posture
//! `lp-vault` documents for the vault files). This is called out in `--help`
//! and the crate docs: on a shared machine, the file's security reduces to the
//! OS file permissions until keychain support lands.

use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, anyhow};
use lp_crypto::SecretKey;

/// The file name, within a profile, holding the Secret Key display string.
pub const SECRET_KEY_FILE: &str = "secret-key";

/// Resolve the profile directory: `explicit` if given, else the platform data
/// dir (`directories::ProjectDirs`). Does not create it.
///
/// # Errors
///
/// Fails if no explicit profile was given and the platform data directory
/// cannot be determined (e.g. no `HOME`/`%APPDATA%`).
pub fn resolve(explicit: Option<&Path>) -> Result<PathBuf> {
    if let Some(dir) = explicit {
        return Ok(dir.to_path_buf());
    }
    // Qualifier / organization are empty; application "localpass" yields
    // `<data_dir>/localpass` on every platform.
    let dirs = directories::ProjectDirs::from("", "", "localpass").ok_or_else(|| {
        anyhow!(
            "could not determine a platform data directory; pass --profile <dir> to set one explicitly"
        )
    })?;
    Ok(dirs.data_dir().to_path_buf())
}

/// The path to the account-store file within `profile`.
#[must_use]
pub fn account_path(profile: &Path) -> PathBuf {
    profile.join(lp_vault::account::ACCOUNT_FILE)
}

/// Whether an account store already exists in `profile`.
#[must_use]
pub fn account_exists(profile: &Path) -> bool {
    account_path(profile).exists()
}

/// The path to the on-device Secret Key file within `profile`.
#[must_use]
pub fn secret_key_path(profile: &Path) -> PathBuf {
    profile.join(SECRET_KEY_FILE)
}

/// Persist the Secret Key display string to `<profile>/secret-key` with
/// owner-only permissions.
///
/// The file is created (or truncated) and, on Unix, `chmod 0600`. On Windows
/// there is no portable owner-only chmod without a Win32 ACL dependency (out of
/// scope, matching `lp-vault`'s stance); the file inherits the profile
/// directory's owner-scoped ACLs.
///
/// # Errors
///
/// Fails on any filesystem error writing or permissioning the file.
pub fn store_secret_key(profile: &Path, secret_key: &SecretKey) -> Result<()> {
    let path = secret_key_path(profile);
    // Newline-terminated so the file is a well-formed text line.
    let contents = format!("{}\n", secret_key.to_display_string());
    write_owner_only(&path, contents.as_bytes())
        .with_context(|| format!("writing Secret Key file at {}", path.display()))?;
    Ok(())
}

/// Load the Secret Key from `<profile>/secret-key`.
///
/// # Errors
///
/// - A clear message (not a raw IO error) if the file is missing — the account
///   may exist but the on-device Secret Key was moved or never stored on this
///   machine (the user must re-supply it, a future `unlock --secret-key` path).
/// - An error if the stored string is not a valid Secret Key encoding.
pub fn load_secret_key(profile: &Path) -> Result<SecretKey> {
    let path = secret_key_path(profile);
    let raw = fs::read_to_string(&path).map_err(|e| {
        if e.kind() == std::io::ErrorKind::NotFound {
            anyhow!(
                "no Secret Key on this device at {} — it is required to unlock. \
                 Restore it from your Emergency Kit (PRD §4.11).",
                path.display()
            )
        } else {
            anyhow::Error::new(e).context(format!("reading Secret Key file at {}", path.display()))
        }
    })?;
    SecretKey::from_display_string(raw.trim())
        .map_err(|_| anyhow!("the stored Secret Key at {} is malformed", path.display()))
}

/// Write `bytes` to `path`, creating the file owner-only.
///
/// On Unix we set the mode at creation time via `OpenOptions` so the secret is
/// never briefly world-readable between create and chmod.
fn write_owner_only(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    let mut opts = fs::OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut f = opts.open(path)?;
    f.write_all(bytes)?;
    // Re-assert 0600 in case the file pre-existed with looser perms (create
    // does not lower an existing file's mode).
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    }
    f.sync_all()?;
    Ok(())
}
