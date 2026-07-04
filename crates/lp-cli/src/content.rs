//! Building and mutating [`ItemPayload`]s from the shared `add`/`edit` content
//! flags.
//!
//! `add` builds a fresh payload of a chosen type; `edit` overlays only the
//! flags the user provided onto the current payload (so unspecified fields are
//! left untouched, and a new version is created by the caller).
//!
//! # Secret hygiene
//!
//! `--password` / `--secret-field` / `--env` values are parsed but **never**
//! echoed — parse errors name only the key, never the value. Generated
//! passwords are returned to the caller so it can decide whether to surface
//! them (add: printed once; edit: silent).

use std::path::Path;

use anyhow::{Context, Result, bail};
use lp_vault::payload::{EnvEntry, Field, FieldKind, ItemPayload, TypeData};
use serde_json::json;

use crate::cli::{ContentArgs, ItemType};
use crate::generate;

/// The outcome of applying content flags: the payload plus an optional
/// generated password the caller may want to display (add-time).
#[derive(Debug)]
pub struct BuiltContent {
    /// A password that was freshly generated for this item (`--generate`), if
    /// any. The caller decides whether/how to show it.
    pub generated_password: Option<String>,
}

/// Split a `KEY=VALUE` flag argument into its two parts, erroring without ever
/// including the value in the message.
fn split_kv(arg: &str, flag: &str) -> Result<(String, String)> {
    match arg.split_once('=') {
        Some((k, v)) if !k.is_empty() => Ok((k.to_string(), v.to_string())),
        _ => bail!("malformed --{flag} (expected KEY=VALUE with a non-empty KEY)"),
    }
}

/// Parse a simple `.env` file into ordered `(KEY, VALUE)` entries.
///
/// Rules (deliberately minimal): ignore blank lines and lines whose first
/// non-space character is `#`; accept `KEY=VALUE`; strip an optional leading
/// `export ` and surrounding quotes on the value. Values are never echoed on
/// error.
fn parse_env_file(path: &Path) -> Result<Vec<EnvEntry>> {
    let text = std::fs::read_to_string(path)
        .with_context(|| format!("reading env file {}", path.display()))?;
    let mut out = Vec::new();
    for (lineno, raw) in text.lines().enumerate() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let line = line.strip_prefix("export ").unwrap_or(line);
        let Some((key, val)) = line.split_once('=') else {
            bail!(
                "malformed line {} in {} (expected KEY=VALUE)",
                lineno + 1,
                path.display()
            );
        };
        let key = key.trim();
        if key.is_empty() {
            bail!("empty key on line {} in {}", lineno + 1, path.display());
        }
        // Strip matching surrounding quotes from the value only.
        let val = val.trim();
        let val = strip_quotes(val);
        out.push(EnvEntry {
            key: key.to_string(),
            value: val.to_string(),
        });
    }
    Ok(out)
}

/// Strip a single pair of matching surrounding single/double quotes.
fn strip_quotes(s: &str) -> &str {
    let bytes = s.as_bytes();
    if bytes.len() >= 2
        && (bytes[0] == b'"' || bytes[0] == b'\'')
        && bytes[bytes.len() - 1] == bytes[0]
    {
        &s[1..s.len() - 1]
    } else {
        s
    }
}

/// Build the base [`TypeData`] for a new item of `item_type`, populated from the
/// type-specific flags.
fn build_type_data(item_type: ItemType, args: &ContentArgs) -> Result<TypeData> {
    Ok(match item_type {
        ItemType::Login => TypeData::Login { urls: Vec::new() },
        ItemType::Note => TypeData::Note {},
        ItemType::ApiKey => TypeData::ApiKey {
            key: String::new(),
            secret: String::new(),
            endpoint: args.url.clone().unwrap_or_default(),
            expiry: None,
            rotate_after: None,
        },
        ItemType::EnvSet => TypeData::EnvSet {
            entries: collect_env_entries(args)?,
        },
        ItemType::SshKey => TypeData::SshKey {
            algo: String::new(),
            private_pem: String::new(),
            public_openssh: String::new(),
            fingerprint: String::new(),
        },
        ItemType::Totp => TypeData::Totp {
            secret_b32: String::new(),
            algo: String::new(),
            digits: 0,
            period: 0,
            issuer: String::new(),
            account: String::new(),
        },
    })
}

/// Gather env entries from `--env` flags and/or `--from-env-file`.
fn collect_env_entries(args: &ContentArgs) -> Result<Vec<EnvEntry>> {
    let mut entries = Vec::new();
    if let Some(path) = &args.from_env_file {
        entries.extend(parse_env_file(path)?);
    }
    for e in &args.env {
        let (key, value) = split_kv(e, "env")?;
        entries.push(EnvEntry { key, value });
    }
    Ok(entries)
}

/// Apply the common (non-type) content flags to `payload`: username/password/
/// url/note/tags/custom fields. Returns any generated password.
///
/// `is_login` controls whether username/password/url map to login fields.
fn apply_common(
    payload: &mut ItemPayload,
    item_type: ItemType,
    args: &ContentArgs,
) -> Result<Option<String>> {
    // Note body.
    if let Some(note) = &args.note {
        payload.notes = note.clone();
    }
    // Tags: append (dedup preserving order).
    for tag in &args.tags {
        if !payload.tags.contains(tag) {
            payload.tags.push(tag.clone());
        }
    }

    // Password (explicit or generated).
    let mut generated = None;
    let password_value: Option<String> = if args.generate {
        let g = generate::password(24, true)?;
        generated = Some(g.secret.clone());
        Some(g.secret)
    } else {
        args.password.clone()
    };

    // username / password / url land in different places by type.
    match item_type {
        ItemType::ApiKey => {
            if let TypeData::ApiKey { secret, key, .. } = &mut payload.type_data {
                if let Some(pw) = &password_value {
                    secret.clone_from(pw);
                }
                if let Some(u) = &args.username {
                    key.clone_from(u);
                }
            }
        }
        ItemType::Login | ItemType::Note | ItemType::EnvSet | ItemType::SshKey | ItemType::Totp => {
            // For login (and, permissively, other types) map the common auth
            // flags to custom fields so the data is not silently dropped.
            if let Some(u) = &args.username {
                upsert_field(payload, "username", FieldKind::Text, json!(u));
            }
            if let Some(pw) = &password_value {
                upsert_field(payload, "password", FieldKind::Hidden, json!(pw));
            }
            if let Some(url) = &args.url {
                upsert_field(payload, "url", FieldKind::Url, json!(url));
            }
        }
    }
    // For api-key, an explicit --url already went to `endpoint` at construction
    // (add path). On edit we also honour --url → endpoint below.
    if item_type == ItemType::ApiKey
        && let (Some(url), TypeData::ApiKey { endpoint, .. }) = (&args.url, &mut payload.type_data)
    {
        endpoint.clone_from(url);
    }

    // Custom text + hidden fields.
    for f in &args.fields {
        let (key, value) = split_kv(f, "field")?;
        upsert_field(payload, &key, FieldKind::Text, json!(value));
    }
    for f in &args.secret_fields {
        let (key, value) = split_kv(f, "secret-field")?;
        upsert_field(payload, &key, FieldKind::Hidden, json!(value));
    }

    Ok(generated)
}

/// Insert or replace a custom field by name (preserving position on replace).
fn upsert_field(payload: &mut ItemPayload, name: &str, kind: FieldKind, value: serde_json::Value) {
    if let Some(existing) = payload.fields.iter_mut().find(|f| f.name == name) {
        existing.kind = kind;
        existing.value = value;
    } else {
        payload.fields.push(Field {
            name: name.to_string(),
            kind,
            value,
        });
    }
}

/// Build a brand-new payload for `item add`.
///
/// # Errors
///
/// Fails on malformed `key=value` flags, an unreadable env file, or a
/// generation failure.
pub fn build_new(
    item_type: ItemType,
    title: &str,
    args: &ContentArgs,
) -> Result<(ItemPayload, BuiltContent)> {
    let type_data = build_type_data(item_type, args)?;
    let mut payload = ItemPayload::new(type_data, title);
    let generated_password = apply_common(&mut payload, item_type, args)?;
    Ok((payload, BuiltContent { generated_password }))
}

/// Overlay `edit` flags onto an existing `payload` (in place). The item type is
/// taken from the existing payload — `edit` cannot change an item's type.
///
/// # Errors
///
/// Fails on malformed `key=value` flags, an unreadable env file, or a
/// generation failure.
pub fn apply_edit(
    payload: &mut ItemPayload,
    new_title: Option<&str>,
    args: &ContentArgs,
) -> Result<BuiltContent> {
    if let Some(t) = new_title {
        payload.title = t.to_string();
    }
    let item_type = type_of(payload);

    // For env-set edits, --env / --from-env-file append to the existing set.
    if item_type == ItemType::EnvSet {
        let added = collect_env_entries(args)?;
        if let TypeData::EnvSet { entries } = &mut payload.type_data {
            for entry in added {
                if let Some(existing) = entries.iter_mut().find(|e| e.key == entry.key) {
                    existing.value = entry.value;
                } else {
                    entries.push(entry);
                }
            }
        }
    }

    let generated_password = apply_common(payload, item_type, args)?;
    Ok(BuiltContent { generated_password })
}

/// Map an existing payload's `TypeData` back to the CLI [`ItemType`].
fn type_of(payload: &ItemPayload) -> ItemType {
    match payload.type_data {
        TypeData::Login { .. } => ItemType::Login,
        TypeData::Note {} => ItemType::Note,
        TypeData::ApiKey { .. } => ItemType::ApiKey,
        TypeData::EnvSet { .. } => ItemType::EnvSet,
        TypeData::SshKey { .. } => ItemType::SshKey,
        TypeData::Totp { .. } => ItemType::Totp,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn empty_args() -> ContentArgs {
        ContentArgs {
            vault: "personal".into(),
            username: None,
            password: None,
            generate: false,
            url: None,
            note: None,
            tags: vec![],
            fields: vec![],
            secret_fields: vec![],
            env: vec![],
            from_env_file: None,
        }
    }

    #[test]
    fn login_maps_username_password_url_to_fields() {
        let mut args = empty_args();
        args.username = Some("alice".into());
        args.password = Some("hunter2".into());
        args.url = Some("https://example.com".into());
        let (p, built) = build_new(ItemType::Login, "Example", &args).unwrap();
        assert!(built.generated_password.is_none());
        let f = crate::output::display_fields(&p);
        assert_eq!(
            crate::output::find_field(&f, "username").unwrap().value,
            "alice"
        );
        let pw = crate::output::find_field(&f, "password").unwrap();
        assert!(pw.secret);
        assert_eq!(pw.value, "hunter2");
    }

    #[test]
    fn generate_flag_yields_a_password() {
        let mut args = empty_args();
        args.generate = true;
        let (p, built) = build_new(ItemType::Login, "Gen", &args).unwrap();
        let pw = built.generated_password.expect("a password was generated");
        assert_eq!(pw.chars().count(), 24);
        // The generated password is stored in the payload's hidden field.
        let f = crate::output::display_fields(&p);
        assert_eq!(crate::output::find_field(&f, "password").unwrap().value, pw);
    }

    #[test]
    fn env_flags_and_file_merge_in_order() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(".env");
        std::fs::write(&path, "# comment\n\nFOO=1\nexport BAR=\"two\"\n").unwrap();
        let mut args = empty_args();
        args.from_env_file = Some(path);
        args.env = vec!["BAZ=3".into()];
        let (p, _) = build_new(ItemType::EnvSet, "env", &args).unwrap();
        if let TypeData::EnvSet { entries } = &p.type_data {
            assert_eq!(entries.len(), 3);
            assert_eq!(entries[0].key, "FOO");
            assert_eq!(entries[0].value, "1");
            assert_eq!(entries[1].key, "BAR");
            assert_eq!(entries[1].value, "two");
            assert_eq!(entries[2].key, "BAZ");
        } else {
            panic!("not an env-set");
        }
    }

    #[test]
    fn malformed_kv_never_contains_value() {
        let mut args = empty_args();
        args.fields = vec!["novalue".into()];
        let err = build_new(ItemType::Login, "x", &args).unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("field"));
        assert!(!msg.contains("novalue") || msg.contains("KEY=VALUE"));
    }

    #[test]
    fn edit_overlays_only_given_flags() {
        let mut p = ItemPayload::new(TypeData::Login { urls: vec![] }, "Old");
        crate::content::upsert_field(&mut p, "username", FieldKind::Text, json!("bob"));
        let mut args = empty_args();
        args.password = Some("newpass".into());
        apply_edit(&mut p, Some("New"), &args).unwrap();
        assert_eq!(p.title, "New");
        let f = crate::output::display_fields(&p);
        // username preserved, password added.
        assert_eq!(
            crate::output::find_field(&f, "username").unwrap().value,
            "bob"
        );
        assert_eq!(
            crate::output::find_field(&f, "password").unwrap().value,
            "newpass"
        );
    }
}
