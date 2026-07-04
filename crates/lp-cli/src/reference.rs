//! Resolving secret **references** to plaintext values (PRD §4.8, §11 #4).
//!
//! A reference names a single secret to pull out of a vault at spawn time:
//!
//! ```text
//! localpass://<vault>/<item>/<field>
//! op://<vault>/<item>/<field>          # 1Password-compatible alias, identical
//! ```
//!
//! - `<vault>` — a vault **name** or **id** (hyphenated UUID).
//! - `<item>`  — an item **title** or **id**.
//! - `<field>` — a field name, or — for an `env_set` item — an entry **key**.
//!
//! Each path segment is percent-decoded (`%2F` → `/`, etc.), so a name that
//! itself contains a `/` or a space can be encoded. The `op://` scheme resolves
//! **identically** to `localpass://` — it is a pure spelling alias.
//!
//! # Whole-item references are rejected
//!
//! A reference must name a field. `localpass://work/myapp-db` (no field) is a
//! usage error pointing the user at `--env-set`, which is the correct way to
//! pull an entire env-set into the environment.
//!
//! # Secret hygiene
//!
//! A failed resolution never includes the *value* (there is none yet) — but it
//! also never echoes a partially-resolved secret. Errors name the reference and
//! the missing piece only. Resolution happens **once**, at spawn; the returned
//! `String` is the only plaintext copy this process holds for that variable.

use anyhow::Result;
use lp_vault::Session;
use lp_vault::payload::TypeData;

use crate::dotenv::percent_decode;
use crate::error::CliError;
use crate::output;
use crate::resolve;

/// The two accepted reference scheme prefixes.
const LOCALPASS_SCHEME: &str = "localpass://";
const OP_SCHEME: &str = "op://";

/// A parsed reference: vault / item / field, each already percent-decoded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Reference {
    /// Vault name or id.
    pub vault: String,
    /// Item title or id.
    pub item: String,
    /// Field name (or env-set entry key).
    pub field: String,
}

/// Whether `s` looks like a secret reference (either scheme). Used to decide, in
/// an `--env-file`, whether a value is a reference to resolve or a literal to
/// pass through.
#[must_use]
pub fn is_reference(s: &str) -> bool {
    s.starts_with(LOCALPASS_SCHEME) || s.starts_with(OP_SCHEME)
}

/// Parse a `localpass://` or `op://` reference into its decoded segments.
///
/// # Errors
///
/// [`CliError::Usage`] if the scheme is unknown, a segment is empty, the field
/// segment is missing (whole-item reference), there are too many segments, or a
/// segment fails to percent-decode.
pub fn parse(reference: &str) -> Result<Reference> {
    let rest = if let Some(r) = reference.strip_prefix(LOCALPASS_SCHEME) {
        r
    } else if let Some(r) = reference.strip_prefix(OP_SCHEME) {
        r
    } else {
        return Err(CliError::usage(format!(
            "reference {reference:?} must start with localpass:// or op://"
        ))
        .into());
    };

    // Split into at most vault / item / field. A trailing empty segment (e.g.
    // a stray slash) is caught by the empty-segment check below.
    let segments: Vec<&str> = rest.split('/').collect();
    match segments.as_slice() {
        [_vault, _item] => Err(CliError::usage(format!(
            "reference {reference:?} names a whole item with no field; \
             to inject an entire env-set use --env-set instead"
        ))
        .into()),
        [vault, item, field] => {
            if vault.is_empty() || item.is_empty() {
                return Err(CliError::usage(format!(
                    "reference {reference:?} has an empty vault or item segment"
                ))
                .into());
            }
            if field.is_empty() {
                return Err(CliError::usage(format!(
                    "reference {reference:?} has an empty field segment"
                ))
                .into());
            }
            Ok(Reference {
                vault: percent_decode(vault).map_err(CliError::usage_from)?,
                item: percent_decode(item).map_err(CliError::usage_from)?,
                field: percent_decode(field).map_err(CliError::usage_from)?,
            })
        }
        [""] => Err(
            CliError::usage(format!("reference {reference:?} is empty after the scheme")).into(),
        ),
        [_vault] => Err(CliError::usage(format!(
            "reference {reference:?} is missing the item and field \
             (expected <scheme>vault/item/field)"
        ))
        .into()),
        _ => Err(CliError::usage(format!(
            "reference {reference:?} has too many path segments \
             (expected exactly vault/item/field)"
        ))
        .into()),
    }
}

/// Resolve a parsed [`Reference`] against an unlocked `session` to its plaintext
/// value.
///
/// The field lookup first consults an `env_set` item's entries (by entry key),
/// then falls back to the flattened display fields (login username/password,
/// api-key key/secret, custom fields, …) via [`output::find_field`], matching
/// the same names the user sees in `item get`.
///
/// # Errors
///
/// [`CliError::Usage`] if the vault, item, or field cannot be found. The error
/// never contains a secret value.
pub fn resolve_value(session: &Session, r: &Reference) -> Result<String> {
    let vault = resolve::open_vault(session, &r.vault)?;
    let item = resolve::find_item(&vault, &r.item)?;

    // env-set items resolve a field as an entry key first (exact, then
    // case-insensitive) — an env-set's keys are the natural field names.
    if let TypeData::EnvSet { entries } = &item.payload.type_data {
        if let Some(e) = entries.iter().find(|e| e.key == r.field) {
            audit_reference_read(&vault, &item.item_id, &e.key);
            return Ok(e.value.clone());
        }
        if let Some(e) = entries
            .iter()
            .find(|e| e.key.eq_ignore_ascii_case(&r.field))
        {
            audit_reference_read(&vault, &item.item_id, &e.key);
            return Ok(e.value.clone());
        }
    }

    // Fall back to the flattened display fields (same source `item get` uses).
    let fields = output::display_fields(&item.payload);
    if let Some(f) = output::find_field(&fields, &r.field) {
        audit_reference_read(&vault, &item.item_id, &f.name);
        return Ok(f.value.clone());
    }

    Err(CliError::usage(format!(
        "item {:?} in vault {:?} has no field {:?}",
        r.item, r.vault, r.field
    ))
    .into())
}

/// Audit a reference resolution as an [`ItemSecretRead`](lp_vault::AuditKind)
/// (PRD §4.9): resolving a `localpass://`/`op://` reference discloses the
/// field's plaintext value into a child process's environment, so it is a secret
/// read. Records the field name (never its value). Best-effort — a reference
/// resolution is never failed over an audit-append hiccup.
fn audit_reference_read(vault: &lp_vault::Vault<'_>, item_id: &lp_vault::ItemId, field: &str) {
    vault.record_secret_read(item_id, Some(field)).ok();
}

/// Parse **and** resolve a reference in one step.
///
/// # Errors
///
/// See [`parse`] and [`resolve_value`].
pub fn resolve_str(session: &Session, reference: &str) -> Result<String> {
    let parsed = parse(reference)?;
    resolve_value(session, &parsed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn is_reference_detects_both_schemes() {
        assert!(is_reference("localpass://v/i/f"));
        assert!(is_reference("op://v/i/f"));
        assert!(!is_reference("plainvalue"));
        assert!(!is_reference("https://example.com/a/b"));
    }

    #[test]
    fn parse_localpass_and_op_are_identical() {
        let a = parse("localpass://work/db/url").unwrap();
        let b = parse("op://work/db/url").unwrap();
        assert_eq!(a, b);
        assert_eq!(a.vault, "work");
        assert_eq!(a.item, "db");
        assert_eq!(a.field, "url");
    }

    #[test]
    fn parse_percent_decodes_segments() {
        let r = parse("localpass://my%20vault/app%2Fdev/DATABASE%5FURL").unwrap();
        assert_eq!(r.vault, "my vault");
        assert_eq!(r.item, "app/dev");
        assert_eq!(r.field, "DATABASE_URL");
    }

    #[test]
    fn whole_item_reference_points_at_env_set() {
        let err = parse("localpass://work/myapp-db").unwrap_err();
        let msg = format!("{err:#}");
        assert!(
            msg.contains("--env-set"),
            "message guides to --env-set: {msg}"
        );
    }

    #[test]
    fn unknown_scheme_is_rejected() {
        let err = parse("vault://a/b/c").unwrap_err();
        assert!(format!("{err:#}").contains("localpass:// or op://"));
    }

    #[test]
    fn too_many_segments_is_rejected() {
        assert!(parse("localpass://a/b/c/d").is_err());
    }

    #[test]
    fn empty_segments_are_rejected() {
        assert!(parse("localpass://a//c").is_err());
        assert!(parse("localpass://a/b/").is_err());
        assert!(parse("localpass://").is_err());
    }
}
