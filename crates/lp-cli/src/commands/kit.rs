//! The Emergency Kit: rendering + the `localpass kit` command (PRD §4.11).
//!
//! The Emergency Kit is the offline record that, together with the master
//! password, is the *only* way back into the data — there is no cloud reset. It
//! contains the Secret Key display string, the profile path, the creation date,
//! step-by-step recovery instructions, and the no-recovery doctrine.
//!
//! This module owns the kit *content* ([`render_text`] / [`render_html`]) so
//! both [`init`](crate::commands::init) (which prints the kit at setup) and
//! `localpass kit` (which regenerates it anytime) render identical text.
//!
//! # Why we refuse to write into the profile
//!
//! Writing the kit into `<profile>/` would co-locate the Secret Key with the
//! vault it protects — an attacker who steals the profile would then have both
//! halves. So `localpass kit` **refuses** any `--out` inside the profile
//! directory and defaults to the user's Documents directory, warning loudly that
//! the file holds the Secret Key and should be printed then deleted.

use std::path::{Path, PathBuf};

use anyhow::{Result, bail};
use lp_crypto::SecretKey;

use crate::cli::{KitArgs, KitFormat};
use crate::error::CliError;
use crate::profile;
use crate::timestamp;
use crate::unlock::{self, PasswordSource};

/// The default kit file stem (extension chosen by format).
const KIT_STEM: &str = "localpass-emergency-kit";

/// Run `localpass kit`.
///
/// Requires an unlock (to prove the caller can open the account), reads the
/// Secret Key (from the on-device file, or `--secret-key` if that file is
/// missing), then writes the kit to a path **outside** the profile.
///
/// # Errors
///
/// - [`CliError::Usage`] if no account exists, `--out` is inside the profile, or
///   the Secret Key is unavailable and `--secret-key` was not supplied.
/// - [`CliError::Auth`] on a wrong master password / Secret Key.
/// - [`CliError::Internal`] on a filesystem failure.
pub fn run(profile_dir: &Path, src: PasswordSource, args: &KitArgs) -> Result<()> {
    if !profile::account_exists(profile_dir) {
        bail!(CliError::usage(format!(
            "no account at {} — run `localpass init` first",
            profile_dir.display()
        )));
    }

    // Resolve the Secret Key: prefer an explicit --secret-key, else the on-device
    // file. We need it as a display string for the kit body.
    let secret_key_display = resolve_secret_key(profile_dir, args.secret_key.as_deref())?;

    // Unlock proves the caller holds the credentials (and validates the Secret
    // Key against the account). Use the resolved key so an explicit --secret-key
    // is honoured even when the on-device file is absent.
    let secret_key = SecretKey::from_display_string(&secret_key_display)
        .map_err(|_| CliError::usage("the supplied Secret Key is malformed"))?;
    let password = unlock::acquire_password(src, "Master password: ")?;
    match lp_vault::AccountStore::unlock(profile_dir, &password, &secret_key) {
        Ok(_session) => {}
        Err(lp_vault::Error::DecryptionFailed) => {
            bail!(CliError::auth("wrong master password or Secret Key"));
        }
        Err(e) => bail!(CliError::internal(anyhow::anyhow!("unlock failed: {e}"))),
    }

    // Resolve the output path (default: Documents dir with the format's ext).
    let out = resolve_out_path(profile_dir, args.out.as_deref(), args.format)?;

    // The account's creation date (PRD §4.11 "creation date").
    let created_ms = lp_vault::AccountStore::created_at(profile_dir)
        .map_err(|e| CliError::internal(anyhow::anyhow!("{e}")))?;
    let created = timestamp::format_millis_utc(created_ms);

    save_kit_file(
        profile_dir,
        &out,
        args.format,
        &secret_key_display,
        &created,
    )?;

    println!("Emergency Kit written to {}", out.display());
    println!(
        "WARNING: this file contains your Secret Key in cleartext. Print it, \
         store it offline, then DELETE the file."
    );
    Ok(())
}

/// Render the kit in `format` and write it to `out`, refusing any path inside
/// the profile directory. Shared by `localpass kit` and `init --kit-out`.
///
/// # Errors
///
/// - [`CliError::Usage`] if `out` is inside the profile.
/// - [`CliError::Internal`] on a filesystem failure.
pub fn save_kit_file(
    profile_dir: &Path,
    out: &Path,
    format: KitFormat,
    secret_key_display: &str,
    created: &str,
) -> Result<()> {
    guard_outside_profile(profile_dir, out)?;
    let body = match format {
        KitFormat::Text => render_text(profile_dir, secret_key_display, created),
        KitFormat::Html => render_html(profile_dir, secret_key_display, created),
    };
    write_kit(out, body.as_bytes()).map_err(CliError::internal)?;
    Ok(())
}

/// Resolve the Secret Key display string: `--secret-key` wins; otherwise read
/// the on-device file; otherwise a clear usage error telling the user to pass
/// `--secret-key`.
fn resolve_secret_key(profile_dir: &Path, explicit: Option<&str>) -> Result<String> {
    if let Some(s) = explicit {
        // Validate it now so a typo fails early with a clear message.
        SecretKey::from_display_string(s)
            .map_err(|_| CliError::usage("the supplied --secret-key is malformed"))?;
        return Ok(s.to_string());
    }
    match profile::load_secret_key(profile_dir) {
        Ok(sk) => Ok(sk.to_display_string()),
        Err(_) => Err(CliError::usage(format!(
            "no Secret Key on this device at {} — supply it with --secret-key <LP1-...> \
             (from your existing Emergency Kit)",
            profile::secret_key_path(profile_dir).display()
        ))
        .into()),
    }
}

/// Resolve the output file path: explicit `--out`, or the default in the user's
/// Documents directory with the format's extension.
fn resolve_out_path(
    _profile_dir: &Path,
    explicit: Option<&Path>,
    format: KitFormat,
) -> Result<PathBuf> {
    if let Some(p) = explicit {
        return Ok(p.to_path_buf());
    }
    let ext = match format {
        KitFormat::Text => "txt",
        KitFormat::Html => "html",
    };
    let file = format!("{KIT_STEM}.{ext}");
    // Default to the user's Documents dir; fall back to the home dir, then the
    // current dir — never the profile.
    let base = directories::UserDirs::new()
        .and_then(|d| d.document_dir().map(Path::to_path_buf))
        .or_else(|| directories::UserDirs::new().map(|d| d.home_dir().to_path_buf()))
        .unwrap_or_else(|| PathBuf::from("."));
    Ok(base.join(file))
}

/// Refuse to write the kit inside the profile directory (co-locating the Secret
/// Key with the vault it protects defeats the kit's purpose).
fn guard_outside_profile(profile_dir: &Path, out: &Path) -> Result<()> {
    // Compare canonicalized ancestors where possible; fall back to a lexical
    // prefix check so a not-yet-existing target is still guarded.
    let prof = std::fs::canonicalize(profile_dir).unwrap_or_else(|_| profile_dir.to_path_buf());
    // Canonicalize the out path's existing parent (the file itself may not exist).
    let out_parent = out.parent().unwrap_or(out);
    let out_canon = std::fs::canonicalize(out_parent).unwrap_or_else(|_| out_parent.to_path_buf());

    if out_canon == prof || out_canon.starts_with(&prof) {
        bail!(CliError::usage(format!(
            "refusing to write the Emergency Kit inside the profile ({}) — that would \
             store your Secret Key next to the vault it protects. Choose a path outside \
             the profile with --out.",
            profile_dir.display()
        )));
    }
    Ok(())
}

/// Write the kit to `path` (owner-only on Unix), creating parents as needed.
fn write_kit(path: &Path, bytes: &[u8]) -> anyhow::Result<()> {
    use std::io::Write;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut f = opts.open(path)?;
    f.write_all(bytes)?;
    f.sync_all()?;
    Ok(())
}

// --- Rendering ------------------------------------------------------------

/// Render the plain-text Emergency Kit body.
///
/// Shared by `init` (stdout) and `localpass kit` (file), so the printed and
/// saved kits are identical.
#[must_use]
pub fn render_text(profile_dir: &Path, secret_key: &str, created: &str) -> String {
    let bar = "=".repeat(64);
    let profile = profile_dir.display();
    let secret_key_path = profile::secret_key_path(profile_dir);
    format!(
        "{bar}\n\
         \x20 LocalPass EMERGENCY KIT — store this OFFLINE, now.\n\
         {bar}\n\
         \n\
         \x20 Secret Key:   {secret_key}\n\
         \x20 Profile path: {profile}\n\
         \x20 Created:      {created}\n\
         \n\
         \x20 This Secret Key is a 128-bit second factor mixed into your\n\
         \x20 master password. Together they are the ONLY way into your data.\n\
         \n\
         \x20 >> PRINT THIS AND STORE IT OFFLINE (a safe, a drawer, on paper). <<\n\
         \n\
         \x20 RECOVERY — to get back into your data on a new machine:\n\
         \x20   1. Install LocalPass (localpass.example / your package manager).\n\
         \x20   2. Restore your data: either `localpass backup restore <backup>`\n\
         \x20      from a backup you kept, or copy your profile directory\n\
         \x20      ({profile}) onto the new machine.\n\
         \x20   3. Unlock with your master password AND this Secret Key\n\
         \x20      (supply the Secret Key when prompted, or place it in the\n\
         \x20      profile's secret-key file).\n\
         \n\
         \x20 THE NO-RECOVERY DOCTRINE:\n\
         \x20 There is NO cloud reset and NO recovery service. If you lose your\n\
         \x20 master password AND this Secret Key AND all your devices, your\n\
         \x20 data is gone forever. That is the design (PRD §4.11).\n\
         \n\
         \x20 A copy of the Secret Key is stored on THIS device at:\n\
         \x20     {secret_key_path}\n\
         \x20 with owner-only permissions — the MVP stand-in for OS-keychain\n\
         \x20 storage. The printed kit is the authoritative offline copy.\n\
         {bar}\n",
        secret_key_path = secret_key_path.display(),
    )
}

/// Render a print-friendly single-file HTML Emergency Kit.
///
/// Self-contained (inline CSS), so it opens and prints without any external
/// assets. Values are HTML-escaped.
#[must_use]
pub fn render_html(profile_dir: &Path, secret_key: &str, created: &str) -> String {
    let profile = escape_html(&profile_dir.display().to_string());
    let secret_key = escape_html(secret_key);
    let created = escape_html(created);
    let secret_key_path = escape_html(&profile::secret_key_path(profile_dir).display().to_string());
    format!(
        "<!DOCTYPE html>\n\
<html lang=\"en\">\n\
<head>\n\
<meta charset=\"utf-8\">\n\
<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n\
<title>LocalPass Emergency Kit</title>\n\
<style>\n\
  body {{ font-family: system-ui, -apple-system, Segoe UI, Roboto, sans-serif; \
          max-width: 42rem; margin: 2rem auto; padding: 0 1rem; line-height: 1.5; }}\n\
  h1 {{ font-size: 1.4rem; border-bottom: 2px solid #333; padding-bottom: .3rem; }}\n\
  .key {{ font-family: ui-monospace, Consolas, monospace; font-size: 1.15rem; \
          background: #f2f2f2; padding: .5rem .75rem; border-radius: .4rem; \
          word-break: break-all; }}\n\
  .warn {{ color: #a00; font-weight: 700; }}\n\
  code {{ font-family: ui-monospace, Consolas, monospace; }}\n\
  dl {{ display: grid; grid-template-columns: max-content 1fr; gap: .25rem .75rem; }}\n\
  dt {{ font-weight: 600; }}\n\
  @media print {{ body {{ margin: 0; }} }}\n\
</style>\n\
</head>\n\
<body>\n\
<h1>LocalPass Emergency Kit</h1>\n\
<p class=\"warn\">Store this OFFLINE. Print it, then delete the file.</p>\n\
<p>Secret Key:</p>\n\
<p class=\"key\">{secret_key}</p>\n\
<dl>\n\
  <dt>Profile path</dt><dd><code>{profile}</code></dd>\n\
  <dt>Created</dt><dd>{created}</dd>\n\
</dl>\n\
<p>This Secret Key is a 128-bit second factor mixed into your master password. \
Together they are the <strong>only</strong> way into your data.</p>\n\
<h2>Recovery</h2>\n\
<ol>\n\
  <li>Install LocalPass on the new machine.</li>\n\
  <li>Restore your data: run <code>localpass backup restore &lt;backup&gt;</code> from a \
      backup you kept, or copy your profile directory (<code>{profile}</code>) across.</li>\n\
  <li>Unlock with your master password <strong>and</strong> this Secret Key.</li>\n\
</ol>\n\
<h2>The no-recovery doctrine</h2>\n\
<p>There is <strong>no</strong> cloud reset and <strong>no</strong> recovery service. \
If you lose your master password AND this Secret Key AND all your devices, your data is \
gone forever. That is the design (PRD §4.11).</p>\n\
<p>A copy of the Secret Key is stored on this device at <code>{secret_key_path}</code> \
with owner-only permissions — the MVP stand-in for OS-keychain storage. This printed kit \
is the authoritative offline copy.</p>\n\
</body>\n\
</html>\n"
    )
}

/// Minimal HTML text escaping for the kit values.
fn escape_html(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}
