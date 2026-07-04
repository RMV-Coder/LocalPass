//! Bitwarden **unencrypted** JSON export import.
//!
//! Bitwarden's plaintext export is a JSON object with `folders` and `items`.
//! Each item has an integer `type`:
//!
//! | `type` | Bitwarden meaning | LocalPass mapping |
//! |--------|-------------------|-------------------|
//! | 1 | login | [`Login`](lp_vault::TypeData::Login) |
//! | 2 | secure note | [`Note`](lp_vault::TypeData::Note) |
//! | 3 | card | [`Note`](lp_vault::TypeData::Note) + card fields |
//! | 4 | identity | [`Note`](lp_vault::TypeData::Note) + identity fields |
//!
//! Mapping details:
//! - login: `login.username` → text `username`, `login.password` → hidden
//!   `password`, `login.totp` → hidden `totp`, `login.uris[].uri` → the first as
//!   the `url` field and the rest as extra autofill URLs.
//! - `folderId` → resolved to the folder's name and added as a **tag** (PRD
//!   §4.6 allows folders→tags; LocalPass folders need a real folder id which a
//!   fresh import doesn't have, so a tag is the faithful, lossless choice).
//! - `favorite` → the favorite flag; `notes` → the item notes; `fields[]` →
//!   custom fields (text for type 0/2, hidden for type 1).
//! - An unknown `type` is skipped and reported by name only.

use std::collections::HashMap;

use lp_vault::ItemPayload;
use lp_vault::payload::TypeData;
use serde::Deserialize;

use crate::error::Result;
use crate::import::{add_hidden, add_text, add_url};
use crate::model::ImportOutcome;

#[derive(Deserialize)]
struct Export {
    #[serde(default)]
    folders: Vec<Folder>,
    #[serde(default)]
    items: Vec<Item>,
}

#[derive(Deserialize)]
struct Folder {
    #[serde(default)]
    id: Option<String>,
    #[serde(default)]
    name: String,
}

#[derive(Deserialize)]
struct Item {
    #[serde(default, rename = "type")]
    item_type: i64,
    #[serde(default)]
    name: String,
    #[serde(default)]
    notes: Option<String>,
    #[serde(default)]
    favorite: bool,
    #[serde(default, rename = "folderId")]
    folder_id: Option<String>,
    #[serde(default)]
    login: Option<Login>,
    #[serde(default)]
    fields: Vec<CustomField>,
    #[serde(default)]
    card: Option<serde_json::Map<String, serde_json::Value>>,
    #[serde(default)]
    identity: Option<serde_json::Map<String, serde_json::Value>>,
}

#[derive(Deserialize)]
struct Login {
    #[serde(default)]
    username: Option<String>,
    #[serde(default)]
    password: Option<String>,
    #[serde(default)]
    totp: Option<String>,
    #[serde(default)]
    uris: Vec<Uri>,
}

#[derive(Deserialize)]
struct Uri {
    #[serde(default)]
    uri: Option<String>,
}

#[derive(Deserialize)]
struct CustomField {
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    value: Option<String>,
    /// Bitwarden field type: 0=text, 1=hidden, 2=boolean, 3=linked.
    #[serde(default, rename = "type")]
    field_type: i64,
}

/// Parse Bitwarden JSON `bytes` into an [`ImportOutcome`].
///
/// # Errors
///
/// [`PorterError::Json`](crate::PorterError::Json) if the bytes are not a valid
/// Bitwarden export object.
pub fn parse_bytes(bytes: &[u8]) -> Result<ImportOutcome> {
    let export: Export = serde_json::from_slice(bytes)?;

    // folderId → folder name.
    let folder_names: HashMap<String, String> = export
        .folders
        .into_iter()
        .filter_map(|f| f.id.map(|id| (id, f.name)))
        .collect();

    let mut outcome = ImportOutcome::new();
    for item in export.items {
        let title = if item.name.is_empty() {
            "(untitled)".to_string()
        } else {
            item.name.clone()
        };

        let mut payload = match item.item_type {
            1 => build_login(&title, item.login.as_ref()),
            2 => ItemPayload::new(TypeData::Note {}, &title),
            3 => build_structured(&title, item.card.as_ref()),
            4 => build_structured(&title, item.identity.as_ref()),
            other => {
                outcome.skip(title, format!("unsupported bitwarden item type {other}"));
                continue;
            }
        };

        // Common fields.
        if let Some(notes) = &item.notes {
            payload.notes = notes.clone();
        }
        payload.favorite = item.favorite;
        if let Some(fid) = &item.folder_id
            && let Some(name) = folder_names.get(fid)
            && !name.is_empty()
        {
            payload.tags.push(name.clone());
        }
        // Custom fields (type 1 = hidden).
        for f in &item.fields {
            let (Some(name), Some(value)) = (&f.name, &f.value) else {
                continue;
            };
            if name.is_empty() {
                continue;
            }
            if f.field_type == 1 {
                add_hidden(&mut payload, name, value);
            } else {
                add_text(&mut payload, name, value);
            }
        }

        outcome.push(payload);
    }
    Ok(outcome)
}

/// Build a login payload from Bitwarden's `login` object.
fn build_login(title: &str, login: Option<&Login>) -> ItemPayload {
    let mut extra_urls = Vec::new();
    let mut payload = ItemPayload::new(TypeData::Login { urls: Vec::new() }, title);

    if let Some(l) = login {
        add_text(
            &mut payload,
            "username",
            l.username.as_deref().unwrap_or(""),
        );
        add_hidden(
            &mut payload,
            "password",
            l.password.as_deref().unwrap_or(""),
        );
        add_hidden(&mut payload, "totp", l.totp.as_deref().unwrap_or(""));

        let mut uris = l
            .uris
            .iter()
            .filter_map(|u| u.uri.as_deref())
            .filter(|u| !u.is_empty());
        if let Some(first) = uris.next() {
            add_url(&mut payload, "url", first);
        }
        for extra in uris {
            extra_urls.push(extra.to_string());
        }
    }
    if !extra_urls.is_empty() {
        payload.type_data = TypeData::Login { urls: extra_urls };
    }
    payload
}

/// Build a note payload carrying a card/identity's scalar sub-fields as custom
/// text fields (so the data survives losslessly even though LocalPass has no
/// dedicated card/identity type in the MVP).
fn build_structured(
    title: &str,
    obj: Option<&serde_json::Map<String, serde_json::Value>>,
) -> ItemPayload {
    let mut payload = ItemPayload::new(TypeData::Note {}, title);
    if let Some(map) = obj {
        for (k, v) in map {
            let value = match v {
                serde_json::Value::String(s) => s.clone(),
                serde_json::Value::Null => continue,
                other => other.to_string(),
            };
            if value.is_empty() {
                continue;
            }
            // Card number / security code and identity SSN/passport are sensitive
            // → hidden; the rest are text. Conservative name-based heuristic.
            let lname = k.to_ascii_lowercase();
            let sensitive = lname.contains("number")
                || lname.contains("code")
                || lname.contains("ssn")
                || lname.contains("passport");
            if sensitive {
                add_hidden(&mut payload, k, &value);
            } else {
                add_text(&mut payload, k, &value);
            }
        }
    }
    payload
}

#[cfg(test)]
mod tests {
    use super::*;
    use lp_vault::FieldKind;

    fn field<'a>(p: &'a ItemPayload, name: &str) -> Option<&'a lp_vault::Field> {
        p.fields.iter().find(|f| f.name == name)
    }

    const SAMPLE: &str = r#"
{
  "folders": [ { "id": "f1", "name": "Work" } ],
  "items": [
    {
      "type": 1,
      "name": "GitHub",
      "notes": "my dev account",
      "favorite": true,
      "folderId": "f1",
      "login": {
        "username": "octocat",
        "password": "gh_secret",
        "totp": "JBSWY3DPEHPK3PXP",
        "uris": [ { "uri": "https://github.com" }, { "uri": "https://gist.github.com" } ]
      },
      "fields": [ { "name": "recovery", "value": "codes-here", "type": 1 } ]
    },
    {
      "type": 2,
      "name": "Wifi Password",
      "notes": "the note body"
    },
    {
      "type": 3,
      "name": "Visa",
      "card": { "cardholderName": "A B", "number": "4111111111111111", "code": "123" }
    },
    {
      "type": 9,
      "name": "Future Type"
    }
  ]
}
"#;

    #[test]
    fn maps_login_note_card_and_skips_unknown() {
        let o = parse_bytes(SAMPLE.as_bytes()).unwrap();
        // login + note + card imported; the type-9 item skipped.
        assert_eq!(o.count(), 3);
        assert_eq!(o.skipped.len(), 1);
        assert_eq!(o.skipped[0].title, "Future Type");

        let gh = &o.items[0];
        assert_eq!(gh.title, "GitHub");
        assert_eq!(gh.type_data.type_str(), "login");
        assert_eq!(field(gh, "username").unwrap().value, "octocat");
        let pw = field(gh, "password").unwrap();
        assert_eq!(pw.kind, FieldKind::Hidden);
        assert_eq!(pw.value, "gh_secret");
        assert_eq!(field(gh, "totp").unwrap().value, "JBSWY3DPEHPK3PXP");
        assert_eq!(field(gh, "url").unwrap().value, "https://github.com");
        // second uri → extra autofill url
        if let TypeData::Login { urls } = &gh.type_data {
            assert_eq!(urls, &vec!["https://gist.github.com".to_string()]);
        } else {
            panic!("not a login");
        }
        assert!(gh.favorite);
        assert_eq!(gh.tags, vec!["Work".to_string()]);
        assert_eq!(gh.notes, "my dev account");
        // hidden custom field
        assert_eq!(field(gh, "recovery").unwrap().kind, FieldKind::Hidden);

        let note = &o.items[1];
        assert_eq!(note.type_data.type_str(), "note");
        assert_eq!(note.notes, "the note body");

        let card = &o.items[2];
        assert_eq!(card.type_data.type_str(), "note");
        // number/code are hidden; cardholderName is text.
        assert_eq!(field(card, "number").unwrap().kind, FieldKind::Hidden);
        assert_eq!(field(card, "code").unwrap().kind, FieldKind::Hidden);
        assert_eq!(field(card, "cardholderName").unwrap().kind, FieldKind::Text);
    }

    #[test]
    fn bad_json_is_clean_error_no_panic() {
        let err = parse_bytes(b"{ not json").unwrap_err();
        assert!(err.to_string().contains("JSON"));
    }

    #[test]
    fn empty_items_ok() {
        let o = parse_bytes(br#"{"items":[]}"#).unwrap();
        assert_eq!(o.count(), 0);
    }
}
