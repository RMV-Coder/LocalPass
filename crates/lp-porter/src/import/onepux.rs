//! 1Password `.1pux` import.
//!
//! A `.1pux` file is a **ZIP** archive whose `export.data` entry is a JSON
//! document. The relevant shape (1Password's documented 1PUX format):
//!
//! ```text
//! { "accounts": [ { "vaults": [ { "items": [ <item>, ... ] } ] } ] }
//! ```
//!
//! Each item has a `categoryUuid`, an `overview` (title, url, urls, tags), and
//! `details` (loginFields, sections, notesPlain, password). We map the common
//! developer/consumer categories:
//!
//! | categoryUuid | 1Password type | LocalPass type |
//! |--------------|----------------|----------------|
//! | `001` | Login | [`Login`](lp_vault::TypeData::Login) |
//! | `005` | Password | [`Login`](lp_vault::TypeData::Login) |
//! | `003` | Secure Note | [`Note`](lp_vault::TypeData::Note) |
//! | `112` | API Credential | [`ApiKey`](lp_vault::TypeData::ApiKey) |
//! | `114` | SSH Key | [`SshKey`](lp_vault::TypeData::SshKey) |
//! | (any other) | — | [`Note`](lp_vault::TypeData::Note) (data preserved as fields) |
//!
//! Field mapping:
//! - `loginFields` with `designation` `username`/`password` → the `username`
//!   (text) / `password` (hidden) fields; other login fields become custom
//!   fields by their `name`.
//! - `sections[].fields[]` → custom fields named by the field `title` (falling
//!   back to `id`). The field `value` is a tagged object (`{ "concealed": ".." }`,
//!   `{ "string": ".." }`, `{ "totp": ".." }`, `{ "url": ".." }`, …); we extract
//!   the single present value and mark `concealed`/`totp`/`creditCardNumber`
//!   hidden, `url` as a URL, and everything else text.
//! - `overview.url` / `overview.urls[]` → the `url` field + extra autofill URLs.
//! - `overview.tags` → tags; `overview.title` → title; `details.notesPlain` →
//!   notes.
//!
//! Nothing is echoed on error: a bad container or bad JSON yields a value-free
//! [`PorterError`].

use std::io::Read;

use lp_vault::payload::TypeData;
use lp_vault::{FieldKind, ItemPayload};
use serde::Deserialize;
use serde_json::json;

use crate::error::{PorterError, Result};
use crate::import::{add_hidden, add_text, add_url, upsert_field};
use crate::model::ImportOutcome;

/// The JSON entry name inside the `.1pux` ZIP.
const EXPORT_ENTRY: &str = "export.data";

#[derive(Deserialize)]
struct Export {
    #[serde(default)]
    accounts: Vec<Account>,
}

#[derive(Deserialize)]
struct Account {
    #[serde(default)]
    vaults: Vec<Vault>,
}

#[derive(Deserialize)]
struct Vault {
    #[serde(default)]
    items: Vec<Item>,
}

#[derive(Deserialize)]
struct Item {
    #[serde(default, rename = "categoryUuid")]
    category: String,
    /// `"active"` items only; archived/deleted are skipped.
    #[serde(default)]
    state: Option<String>,
    #[serde(default)]
    overview: Overview,
    #[serde(default)]
    details: Details,
}

#[derive(Deserialize, Default)]
struct Overview {
    #[serde(default)]
    title: String,
    #[serde(default)]
    url: String,
    #[serde(default)]
    urls: Vec<UrlEntry>,
    #[serde(default)]
    tags: Vec<String>,
}

#[derive(Deserialize)]
struct UrlEntry {
    #[serde(default)]
    url: String,
}

#[derive(Deserialize, Default)]
struct Details {
    #[serde(default, rename = "loginFields")]
    login_fields: Vec<LoginField>,
    #[serde(default)]
    sections: Vec<Section>,
    #[serde(default, rename = "notesPlain")]
    notes_plain: String,
    #[serde(default)]
    password: Option<String>,
}

#[derive(Deserialize)]
struct LoginField {
    #[serde(default)]
    value: String,
    #[serde(default)]
    name: String,
    #[serde(default)]
    designation: String,
}

#[derive(Deserialize)]
struct Section {
    #[serde(default)]
    fields: Vec<SectionField>,
}

#[derive(Deserialize)]
struct SectionField {
    #[serde(default)]
    title: String,
    #[serde(default)]
    id: String,
    /// The tagged value object, e.g. `{ "concealed": "..." }`.
    #[serde(default)]
    value: serde_json::Map<String, serde_json::Value>,
}

/// Parse a `.1pux` archive at `path` into an [`ImportOutcome`].
///
/// # Errors
///
/// - [`PorterError::Zip`] if the file is not a valid ZIP or lacks `export.data`.
/// - [`PorterError::Json`] if `export.data` is not valid 1PUX JSON.
pub fn parse_file(path: &std::path::Path) -> Result<ImportOutcome> {
    let file = std::fs::File::open(path)?;
    parse_reader(file)
}

/// Parse a `.1pux` archive from any seekable reader.
///
/// # Errors
///
/// As [`parse_file`].
pub fn parse_reader<R: Read + std::io::Seek>(reader: R) -> Result<ImportOutcome> {
    let mut zip = zip::ZipArchive::new(reader).map_err(|e| PorterError::Zip(e.to_string()))?;
    let mut json = String::new();
    {
        let mut entry = zip
            .by_name(EXPORT_ENTRY)
            .map_err(|_| PorterError::Zip(format!("missing {EXPORT_ENTRY} entry")))?;
        entry.read_to_string(&mut json)?;
    }
    parse_export_json(json.as_bytes())
}

/// Parse the decompressed `export.data` JSON bytes. Exposed for tests that want
/// to skip the ZIP layer.
///
/// # Errors
///
/// [`PorterError::Json`] on invalid JSON.
pub fn parse_export_json(bytes: &[u8]) -> Result<ImportOutcome> {
    let export: Export = serde_json::from_slice(bytes)?;
    let mut outcome = ImportOutcome::new();
    for account in export.accounts {
        for vault in account.vaults {
            for item in vault.items {
                // Skip archived/trashed items.
                if let Some(state) = &item.state
                    && state != "active"
                {
                    continue;
                }
                outcome.push(map_item(item));
            }
        }
    }
    Ok(outcome)
}

/// Map one 1PUX item to an [`ItemPayload`].
fn map_item(item: Item) -> ItemPayload {
    let title = if item.overview.title.is_empty() {
        "(untitled)".to_string()
    } else {
        item.overview.title.clone()
    };

    let mut payload = base_payload(&item, &title);

    // Login/password designation fields.
    for lf in &item.details.login_fields {
        match lf.designation.as_str() {
            "username" => add_text(&mut payload, "username", &lf.value),
            "password" => add_hidden(&mut payload, "password", &lf.value),
            _ if !lf.name.is_empty() && !lf.value.is_empty() => {
                add_text(&mut payload, &lf.name, &lf.value);
            }
            _ => {}
        }
    }

    // A Password item's top-level `password`.
    if let Some(pw) = &item.details.password {
        add_hidden(&mut payload, "password", pw);
    }

    // Section fields.
    for section in &item.details.sections {
        for f in &section.fields {
            map_section_field(&mut payload, f);
        }
    }

    // Overview URLs → url field + extra autofill urls.
    apply_urls(&mut payload, &item.overview);

    // Common metadata.
    payload.notes = item.details.notes_plain.clone();
    payload.tags = item.overview.tags.clone();
    payload
}

/// Choose the base payload type from `categoryUuid` and seed type-specific data.
fn base_payload(item: &Item, title: &str) -> ItemPayload {
    match item.category.as_str() {
        // Login, Password → Login.
        "001" | "005" => ItemPayload::new(TypeData::Login { urls: Vec::new() }, title),
        // Secure Note.
        "003" => ItemPayload::new(TypeData::Note {}, title),
        // API Credential.
        "112" => ItemPayload::new(
            TypeData::ApiKey {
                key: String::new(),
                secret: String::new(),
                endpoint: String::new(),
                expiry: None,
                rotate_after: None,
            },
            title,
        ),
        // SSH Key.
        "114" => ItemPayload::new(
            TypeData::SshKey {
                algo: String::new(),
                private_pem: String::new(),
                public_openssh: String::new(),
                fingerprint: String::new(),
            },
            title,
        ),
        // Anything else: a note that still carries all the fields losslessly.
        _ => ItemPayload::new(TypeData::Note {}, title),
    }
}

/// Extract a section field's single tagged value and add it under the field's
/// display name (title, falling back to id).
fn map_section_field(payload: &mut ItemPayload, f: &SectionField) {
    let name = if f.title.is_empty() { &f.id } else { &f.title };
    if name.is_empty() {
        return;
    }
    // The value object has exactly one meaningful key (concealed/string/totp/…).
    let Some((tag, val)) = f.value.iter().next() else {
        return;
    };
    let text = match val {
        serde_json::Value::String(s) => s.clone(),
        serde_json::Value::Null => return,
        other => other.to_string(),
    };
    if text.is_empty() {
        return;
    }
    match tag.as_str() {
        "concealed" | "totp" | "creditCardNumber" => {
            add_hidden(payload, name, &text);
        }
        "url" => add_url(payload, name, &text),
        // string, email, phone, date, monthYear, menu, gender, cctype, address…
        _ => add_text(payload, name, &text),
    }
}

/// Apply the overview primary URL (as the `url` field) and any additional URLs
/// (as login autofill URLs when the item is a login).
fn apply_urls(payload: &mut ItemPayload, overview: &Overview) {
    let mut all: Vec<String> = Vec::new();
    if !overview.url.is_empty() {
        all.push(overview.url.clone());
    }
    for u in &overview.urls {
        if !u.url.is_empty() && !all.contains(&u.url) {
            all.push(u.url.clone());
        }
    }
    if all.is_empty() {
        return;
    }
    // First URL → the `url` field (text/url).
    upsert_field(payload, "url", FieldKind::Url, json!(all[0]));
    // Remaining → login autofill urls (only meaningful on a Login).
    if all.len() > 1
        && let TypeData::Login { urls } = &mut payload.type_data
    {
        urls.extend(all[1..].iter().cloned());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Cursor, Write};

    fn field<'a>(p: &'a ItemPayload, name: &str) -> Option<&'a lp_vault::Field> {
        p.fields.iter().find(|f| f.name == name)
    }

    const EXPORT: &str = r#"
{
  "accounts": [{
    "vaults": [{
      "items": [
        {
          "categoryUuid": "001",
          "state": "active",
          "overview": {
            "title": "GitHub",
            "url": "https://github.com",
            "urls": [ { "url": "https://github.com" }, { "url": "https://gist.github.com" } ],
            "tags": [ "dev", "work" ]
          },
          "details": {
            "loginFields": [
              { "value": "octocat", "name": "username", "designation": "username" },
              { "value": "gh_secret", "name": "password", "designation": "password" }
            ],
            "notesPlain": "primary dev login",
            "sections": [
              { "fields": [
                { "title": "one-time password", "id": "TOTP_x", "value": { "totp": "JBSWY3DPEHPK3PXP" } },
                { "title": "API note", "id": "s1", "value": { "string": "visible text" } }
              ]}
            ]
          }
        },
        {
          "categoryUuid": "003",
          "state": "active",
          "overview": { "title": "My Note" },
          "details": { "notesPlain": "note body here" }
        },
        {
          "categoryUuid": "112",
          "state": "active",
          "overview": { "title": "Stripe API" },
          "details": {
            "sections": [ { "fields": [
              { "title": "credential", "id": "c", "value": { "concealed": "sk_live_xxx" } }
            ]}]
          }
        },
        {
          "categoryUuid": "005",
          "state": "archived",
          "overview": { "title": "Old archived" },
          "details": { "password": "shouldnotappear" }
        }
      ]
    }]
  }]
}
"#;

    /// Build an in-memory .1pux (a ZIP with export.data) around `json`.
    fn make_1pux(json: &str) -> Vec<u8> {
        let mut buf = Vec::new();
        {
            let mut zw = zip::ZipWriter::new(Cursor::new(&mut buf));
            let opts: zip::write::FileOptions<'_, ()> = zip::write::FileOptions::default();
            zw.start_file(EXPORT_ENTRY, opts).unwrap();
            zw.write_all(json.as_bytes()).unwrap();
            zw.finish().unwrap();
        }
        buf
    }

    #[test]
    fn parses_container_and_maps_types() {
        let bytes = make_1pux(EXPORT);
        let o = parse_reader(Cursor::new(bytes)).unwrap();
        // login + note + api-credential imported; the archived item skipped.
        assert_eq!(o.count(), 3);

        let gh = &o.items[0];
        assert_eq!(gh.title, "GitHub");
        assert_eq!(gh.type_data.type_str(), "login");
        assert_eq!(field(gh, "username").unwrap().value, "octocat");
        let pw = field(gh, "password").unwrap();
        assert_eq!(pw.kind, FieldKind::Hidden);
        assert_eq!(pw.value, "gh_secret");
        // totp section field → hidden
        assert_eq!(
            field(gh, "one-time password").unwrap().kind,
            FieldKind::Hidden
        );
        // string section field → text
        assert_eq!(field(gh, "API note").unwrap().kind, FieldKind::Text);
        assert_eq!(gh.tags, vec!["dev".to_string(), "work".to_string()]);
        assert_eq!(gh.notes, "primary dev login");
        // extra autofill url
        if let TypeData::Login { urls } = &gh.type_data {
            assert_eq!(urls, &vec!["https://gist.github.com".to_string()]);
        } else {
            panic!("not a login");
        }

        let note = &o.items[1];
        assert_eq!(note.type_data.type_str(), "note");
        assert_eq!(note.notes, "note body here");

        let api = &o.items[2];
        assert_eq!(api.type_data.type_str(), "api_key");
        assert_eq!(field(api, "credential").unwrap().kind, FieldKind::Hidden);
    }

    #[test]
    fn truncated_zip_is_clean_error_no_panic() {
        // A ZIP magic followed by garbage — must not panic.
        let bytes = b"PK\x03\x04 not really a zip";
        let err = parse_reader(Cursor::new(bytes.to_vec())).unwrap_err();
        assert!(matches!(err, PorterError::Zip(_)));
    }

    #[test]
    fn missing_export_data_entry_errors() {
        let mut buf = Vec::new();
        {
            let mut zw = zip::ZipWriter::new(Cursor::new(&mut buf));
            let opts: zip::write::FileOptions<'_, ()> = zip::write::FileOptions::default();
            zw.start_file("other.txt", opts).unwrap();
            zw.write_all(b"hi").unwrap();
            zw.finish().unwrap();
        }
        let err = parse_reader(Cursor::new(buf)).unwrap_err();
        assert!(matches!(err, PorterError::Zip(_)));
    }

    #[test]
    fn bad_json_inside_zip_is_clean_error() {
        let bytes = make_1pux("{ not json ]");
        let err = parse_reader(Cursor::new(bytes)).unwrap_err();
        assert!(matches!(err, PorterError::Json(_)));
    }
}
