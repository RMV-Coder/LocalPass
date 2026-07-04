//! Guarded plaintext export — full item data, **including secrets**, in cleartext.
//!
//! This module produces the bytes; it does **not** enforce the guard. The CLI
//! must obtain explicit consent (`--i-understand-plaintext-export`) and print a
//! stern warning before calling here — the whole point is that plaintext export
//! is a loaded footgun (secrets land in a file, shell history, backups, etc.).
//!
//! - [`to_json`] emits the same [`Archive`] JSON the age
//!   archive wraps, but *unencrypted* — so it round-trips through
//!   [`archive::decrypt_archive`](crate::export::archive::decrypt_archive)'s JSON
//!   parser conceptually and stays a documented shape.
//! - [`to_csv`] emits a flat `title,type,username,password,url,notes` CSV — a
//!   lowest-common-denominator table for spreadsheet import.

use lp_vault::ItemPayload;
use lp_vault::payload::TypeData;

use crate::error::Result;
use crate::model::{Archive, ArchiveVault};

/// Serialize `vaults` to pretty JSON (the [`Archive`] shape, unencrypted).
///
/// # Errors
///
/// [`PorterError::Json`](crate::PorterError::Json) if serialization fails.
pub fn to_json(vaults: &[(String, Vec<ItemPayload>)], exported_at: i64) -> Result<Vec<u8>> {
    let archive = Archive::new(
        exported_at,
        vaults
            .iter()
            .map(|(name, items)| ArchiveVault {
                name: name.clone(),
                items: items.clone(),
            })
            .collect(),
    );
    Ok(serde_json::to_vec_pretty(&archive)?)
}

/// Serialize all items (flattened across vaults) to a flat CSV with columns
/// `title,type,username,password,url,notes`. Values come from the login-style
/// fields (`username`/`password`/`url`) plus the item title/type/notes; other
/// custom fields and type-specific data are not represented (CSV is lossy by
/// design — the JSON/age exports are lossless).
///
/// # Errors
///
/// [`PorterError::Csv`](crate::PorterError::Csv) on a write failure.
pub fn to_csv(vaults: &[(String, Vec<ItemPayload>)]) -> Result<Vec<u8>> {
    let mut wtr = csv::Writer::from_writer(Vec::new());
    wtr.write_record(["title", "type", "username", "password", "url", "notes"])?;
    for (_name, items) in vaults {
        for item in items {
            let username = field_value(item, "username");
            let password = field_value(item, "password");
            let url = field_value(item, "url");
            wtr.write_record([
                item.title.as_str(),
                item.type_data.type_str(),
                &username,
                &password,
                &url,
                item.notes.as_str(),
            ])?;
        }
    }
    let inner = wtr
        .into_inner()
        .map_err(|e| crate::PorterError::Csv(e.to_string()))?;
    Ok(inner)
}

/// Pull a field's string value (empty if absent or non-string).
fn field_value(item: &ItemPayload, name: &str) -> String {
    // env-set entries are not login-style; leave the login columns empty for
    // them (their data lives in the JSON/age exports).
    if matches!(item.type_data, TypeData::EnvSet { .. }) {
        return String::new();
    }
    item.fields
        .iter()
        .find(|f| f.name == name)
        .and_then(|f| f.value.as_str())
        .unwrap_or("")
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::Archive;

    fn vaults() -> Vec<(String, Vec<ItemPayload>)> {
        let mut login = ItemPayload::new(TypeData::Login { urls: vec![] }, "GitHub");
        crate::import::add_text(&mut login, "username", "octocat");
        crate::import::add_hidden(&mut login, "password", "s3cret");
        crate::import::add_url(&mut login, "url", "https://github.com");
        login.notes = "dev".into();
        vec![("personal".to_string(), vec![login])]
    }

    #[test]
    fn json_is_the_archive_shape() {
        let bytes = to_json(&vaults(), 42).unwrap();
        let archive: Archive = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(archive.exported_at, 42);
        assert_eq!(archive.vaults[0].items[0].title, "GitHub");
    }

    #[test]
    fn csv_has_header_and_row_with_secret() {
        let bytes = to_csv(&vaults()).unwrap();
        let text = String::from_utf8(bytes).unwrap();
        assert!(text.starts_with("title,type,username,password,url,notes\n"));
        assert!(text.contains("GitHub,login,octocat,s3cret,https://github.com,dev"));
    }

    #[test]
    fn csv_quotes_embedded_commas() {
        let mut item = ItemPayload::new(TypeData::Note {}, "a,b");
        item.notes = "line with, comma".into();
        let bytes = to_csv(&[("v".into(), vec![item])]).unwrap();
        let text = String::from_utf8(bytes).unwrap();
        // csv crate quotes fields containing the delimiter.
        assert!(text.contains("\"a,b\""));
        assert!(text.contains("\"line with, comma\""));
    }
}
