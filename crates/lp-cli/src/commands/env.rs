//! `localpass env export|import|diff` — `.env` interop (PRD §4.8).
//!
//! - `export` materializes an env-set to stdout (discouraged; secrets leak into
//!   scrollback) or to a 0600 file, in dotenv / shell / json form.
//! - `import` parses a dotenv file into a new env-set item; values are never
//!   echoed.
//! - `diff` compares a dotenv file against a stored env-set and reports which
//!   keys differ — **never the values** (only `(differs)`). Exit 1 on drift.

use std::io::Write;
use std::path::Path;

use anyhow::{Result, bail};
use lp_vault::Session;
use lp_vault::payload::{EnvEntry, ItemPayload, TypeData};

use crate::cli::{EnvCommand, EnvFormat};
use crate::dotenv;
use crate::error::{CliError, map_vault_error};
use crate::resolve;
use crate::unlock::{self, PasswordSource};

/// Run a `localpass env ...` subcommand.
///
/// # Errors
///
/// Propagates unlock, resolution, and storage failures with the documented exit
/// codes. `diff` returns [`CliError::Usage`] (exit 1) when the file and item
/// differ.
pub fn run(profile_dir: &Path, src: PasswordSource, command: &EnvCommand) -> Result<()> {
    let (session, _sk) = unlock::unlock(profile_dir, src)?;
    match command {
        EnvCommand::Export {
            env_set,
            vault,
            format,
            file,
        } => export(&session, vault, env_set, *format, file.as_deref()),
        EnvCommand::Import { path, title, vault } => import(&session, vault, path, title),
        EnvCommand::Diff {
            path,
            env_set,
            vault,
        } => diff(&session, vault, path, env_set),
    }
}

/// Load an env-set item's entries (erroring if the target is not an env-set).
fn load_entries(session: &Session, vault_ref: &str, set_ref: &str) -> Result<Vec<EnvEntry>> {
    let vault = resolve::open_vault(session, vault_ref)?;
    let item = resolve::find_item(&vault, set_ref)?;
    match item.payload.type_data {
        TypeData::EnvSet { entries } => Ok(entries),
        other => Err(CliError::usage(format!(
            "{set_ref:?} is a {} item, not an env-set",
            other.type_str()
        ))
        .into()),
    }
}

// --- export --------------------------------------------------------------

fn export(
    session: &Session,
    vault_ref: &str,
    set_ref: &str,
    format: EnvFormat,
    file: Option<&Path>,
) -> Result<()> {
    let entries = load_entries(session, vault_ref, set_ref)?;
    let rendered = render(&entries, format);

    if let Some(path) = file {
        write_owner_only(path, rendered.as_bytes())?;
        // Confirm on stderr (not stdout) so `--file` output stays clean; do not
        // print any value.
        eprintln!(
            "wrote {} variable(s) to {} (0600 on Unix)",
            entries.len(),
            path.display()
        );
    } else {
        // stdout path — the explicit, discouraged flow.
        let mut stdout = std::io::stdout().lock();
        stdout.write_all(rendered.as_bytes())?;
    }
    Ok(())
}

/// Render entries in the requested format.
fn render(entries: &[EnvEntry], format: EnvFormat) -> String {
    match format {
        EnvFormat::Dotenv => {
            let mut s = String::new();
            for e in entries {
                s.push_str(&e.key);
                s.push('=');
                s.push_str(&e.value);
                s.push('\n');
            }
            s
        }
        EnvFormat::Shell => {
            let mut s = String::new();
            for e in entries {
                s.push_str("export ");
                s.push_str(&e.key);
                s.push('=');
                s.push_str(&shell_single_quote(&e.value));
                s.push('\n');
            }
            s
        }
        EnvFormat::Json => {
            // A flat object. serde_json handles all string escaping.
            let map: serde_json::Map<String, serde_json::Value> = entries
                .iter()
                .map(|e| (e.key.clone(), serde_json::Value::String(e.value.clone())))
                .collect();
            let mut s = serde_json::to_string_pretty(&serde_json::Value::Object(map))
                .unwrap_or_else(|_| "{}".to_string());
            s.push('\n');
            s
        }
    }
}

/// Single-quote a value for POSIX shells: wrap in `'...'` and replace every
/// embedded `'` with `'\''` (close-quote, escaped quote, reopen-quote). This is
/// safe for arbitrary bytes — nothing inside single quotes is special except the
/// single quote itself.
fn shell_single_quote(value: &str) -> String {
    let mut out = String::with_capacity(value.len() + 2);
    out.push('\'');
    for ch in value.chars() {
        if ch == '\'' {
            out.push_str("'\\''");
        } else {
            out.push(ch);
        }
    }
    out.push('\'');
    out
}

// --- import ---------------------------------------------------------------

fn import(session: &Session, vault_ref: &str, path: &Path, title: &str) -> Result<()> {
    let parsed = dotenv::parse_file(path)?;
    let entries: Vec<EnvEntry> = parsed
        .into_iter()
        .map(|e| EnvEntry {
            key: e.key,
            value: e.value,
        })
        .collect();
    let count = entries.len();

    let vault = resolve::open_vault(session, vault_ref)?;
    let payload = ItemPayload::new(TypeData::EnvSet { entries }, title);
    let id = vault.create_item(&payload).map_err(map_vault_error)?;
    // Never echo any value; report the count and the new id only.
    println!(
        "imported {count} variable(s) into env-set {title:?} ({})",
        id.to_hyphenated()
    );
    Ok(())
}

// --- diff -----------------------------------------------------------------

fn diff(session: &Session, vault_ref: &str, path: &Path, set_ref: &str) -> Result<()> {
    let file_entries = dotenv::parse_file(path)?;
    let item_entries = load_entries(session, vault_ref, set_ref)?;

    // Build sorted maps of key → value for a deterministic, value-free report.
    let file_map: std::collections::BTreeMap<&str, &str> = file_entries
        .iter()
        .map(|e| (e.key.as_str(), e.value.as_str()))
        .collect();
    let item_map: std::collections::BTreeMap<&str, &str> = item_entries
        .iter()
        .map(|e| (e.key.as_str(), e.value.as_str()))
        .collect();

    let only_in_file: Vec<&str> = file_map
        .keys()
        .filter(|k| !item_map.contains_key(*k))
        .copied()
        .collect();
    let only_in_item: Vec<&str> = item_map
        .keys()
        .filter(|k| !file_map.contains_key(*k))
        .copied()
        .collect();
    let changed: Vec<&str> = file_map
        .keys()
        .filter(|k| item_map.get(*k).is_some_and(|iv| *iv != file_map[*k]))
        .copied()
        .collect();

    let drift = !only_in_file.is_empty() || !only_in_item.is_empty() || !changed.is_empty();

    if !drift {
        println!("no drift: {} matches {set_ref:?}", path.display());
        return Ok(());
    }

    // Report keys only. VALUES ARE NEVER PRINTED — a changed key shows
    // `(differs)`, never the two values.
    println!("drift between {} and {set_ref:?}:", path.display());
    print_section("only in file", &only_in_file, "");
    print_section("only in item", &only_in_item, "");
    print_section("changed", &changed, "(differs)");

    // Exit 1 on drift (a usage-level signal), like a failing `diff(1)`.
    bail!(CliError::usage("env drift detected"))
}

/// Print a diff section (a header and one key per line), skipping empties.
fn print_section(header: &str, keys: &[&str], suffix: &str) {
    if keys.is_empty() {
        return;
    }
    println!("  {header}:");
    for k in keys {
        if suffix.is_empty() {
            println!("    {k}");
        } else {
            println!("    {k} {suffix}");
        }
    }
}

// --- 0600 file write ------------------------------------------------------

/// Write `bytes` to `path`, owner-only (0600 on Unix; owner-scoped ACLs
/// otherwise). Mirrors [`crate::profile`]'s Secret Key writer.
fn write_owner_only(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut f = opts
        .open(path)
        .map_err(|e| CliError::usage(format!("cannot write {}: {e}", path.display())))?;
    f.write_all(bytes)
        .map_err(|e| CliError::internal(anyhow::anyhow!("writing {}: {e}", path.display())))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
            .map_err(|e| CliError::internal(anyhow::anyhow!("chmod {}: {e}", path.display())))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entries() -> Vec<EnvEntry> {
        vec![
            EnvEntry {
                key: "DATABASE_URL".into(),
                value: "postgres://localhost/db".into(),
            },
            EnvEntry {
                key: "QUOTE".into(),
                value: "it's a 'test'".into(),
            },
            EnvEntry {
                key: "SPECIAL".into(),
                value: "a b$c\"d".into(),
            },
        ]
    }

    #[test]
    fn dotenv_render_is_key_equals_value() {
        let out = render(&entries(), EnvFormat::Dotenv);
        assert_eq!(
            out,
            "DATABASE_URL=postgres://localhost/db\nQUOTE=it's a 'test'\nSPECIAL=a b$c\"d\n"
        );
    }

    #[test]
    fn shell_render_single_quotes_and_escapes() {
        let out = render(&entries(), EnvFormat::Shell);
        // Each line is `export KEY='...'`.
        assert!(out.contains("export DATABASE_URL='postgres://localhost/db'\n"));
        // A single quote in the value becomes '\'' .
        assert!(out.contains("export QUOTE='it'\\''s a '\\''test'\\'''\n"));
        // $ and " are literal inside single quotes.
        assert!(out.contains("export SPECIAL='a b$c\"d'\n"));
    }

    #[test]
    fn json_render_is_a_flat_object() {
        let out = render(&entries(), EnvFormat::Json);
        let v: serde_json::Value = serde_json::from_str(out.trim()).unwrap();
        assert_eq!(v["DATABASE_URL"], "postgres://localhost/db");
        assert_eq!(v["QUOTE"], "it's a 'test'");
    }

    #[test]
    fn shell_quote_roundtrips_through_sh_semantics() {
        // Property: for a value with no NUL, wrapping in our single-quote form
        // yields exactly the original when the shell unquotes it. We simulate
        // the shell's single-quote rule: content between the outermost quotes,
        // with '\'' sequences collapsing to a literal quote.
        for v in ["plain", "with space", "it's", "a'b'c", "$x", "\"q\"", ""] {
            let quoted = shell_single_quote(v);
            assert_eq!(unquote_sh(&quoted), v, "value {v:?}");
        }
    }

    /// Minimal POSIX single-quote un-quoter for the test above.
    fn unquote_sh(s: &str) -> String {
        // Concatenated single-quoted and escaped-quote pieces.
        let mut out = String::new();
        let bytes: Vec<char> = s.chars().collect();
        let mut i = 0;
        while i < bytes.len() {
            match bytes[i] {
                '\'' => {
                    // opening quote: consume until the next quote.
                    i += 1;
                    while i < bytes.len() && bytes[i] != '\'' {
                        out.push(bytes[i]);
                        i += 1;
                    }
                    i += 1; // closing quote
                }
                '\\' if i + 1 < bytes.len() && bytes[i + 1] == '\'' => {
                    out.push('\'');
                    i += 2;
                }
                other => {
                    out.push(other);
                    i += 1;
                }
            }
        }
        out
    }
}
