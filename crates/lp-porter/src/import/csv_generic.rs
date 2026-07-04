//! Generic CSV import with an explicit column mapping.
//!
//! The caller supplies a [`ColumnMap`] naming which CSV **column** feeds each
//! LocalPass field (`title`, `username`, `password`, `url`, `notes`). Only
//! `title` is required. Each row becomes a login item (title + the mapped
//! username/password/url fields + notes); rows whose title column is empty are
//! skipped and reported (by row number, never by value).
//!
//! This is the escape hatch for exports LocalPass has no dedicated importer for:
//! point the five slots at the right headers and go.

use lp_vault::ItemPayload;
use lp_vault::payload::TypeData;

use crate::error::{PorterError, Result};
use crate::import::{add_hidden, add_text, add_url};
use crate::model::ImportOutcome;

/// Which CSV column name maps to each LocalPass field. Column names are matched
/// case-insensitively against the CSV header row. Only [`title`](ColumnMap::title)
/// is required; the rest are optional.
#[derive(Debug, Clone, Default)]
pub struct ColumnMap {
    /// Column feeding the item title (required).
    pub title: Option<String>,
    /// Column feeding the `username` field.
    pub username: Option<String>,
    /// Column feeding the (hidden) `password` field.
    pub password: Option<String>,
    /// Column feeding the `url` field.
    pub url: Option<String>,
    /// Column feeding the item notes.
    pub notes: Option<String>,
}

impl ColumnMap {
    /// True if no mapping at all was provided.
    fn is_empty(&self) -> bool {
        self.title.is_none()
            && self.username.is_none()
            && self.password.is_none()
            && self.url.is_none()
            && self.notes.is_none()
    }
}

/// Parse generic CSV `bytes` using `map` into an [`ImportOutcome`].
///
/// # Errors
///
/// - [`PorterError::Malformed`] if `map` has no `title` (or is empty), or if a
///   mapped column name is not present in the header row.
/// - [`PorterError::Csv`] on a ragged/invalid CSV.
pub fn parse_bytes(bytes: &[u8], map: &ColumnMap) -> Result<ImportOutcome> {
    if map.is_empty() {
        return Err(PorterError::malformed(
            "csv",
            "no column mapping provided (need at least title=COLUMN)",
        ));
    }
    let Some(title_col) = &map.title else {
        return Err(PorterError::malformed(
            "csv",
            "column mapping must include title=COLUMN",
        ));
    };

    let mut rdr = csv::ReaderBuilder::new()
        .has_headers(true)
        .flexible(false)
        .from_reader(bytes);
    let headers = rdr.headers()?.clone();

    // Resolve each mapped column name to an index, erroring on an unknown name.
    let resolve = |name: &Option<String>| -> Result<Option<usize>> {
        match name {
            None => Ok(None),
            Some(n) => headers
                .iter()
                .position(|h| h.eq_ignore_ascii_case(n))
                .map(Some)
                .ok_or_else(|| {
                    PorterError::malformed("csv", format!("column {n:?} not found in header"))
                }),
        }
    };
    let i_title = resolve(&Some(title_col.clone()))?;
    let i_username = resolve(&map.username)?;
    let i_password = resolve(&map.password)?;
    let i_url = resolve(&map.url)?;
    let i_notes = resolve(&map.notes)?;

    let get = |rec: &csv::StringRecord, idx: Option<usize>| -> String {
        idx.and_then(|i| rec.get(i)).unwrap_or("").to_string()
    };

    let mut outcome = ImportOutcome::new();
    for (row_idx, result) in rdr.records().enumerate() {
        let rec = result?;
        let title = get(&rec, i_title);
        if title.is_empty() {
            // No title → skip, reported by row number (1-based data row).
            outcome.skip(format!("(row {})", row_idx + 1), "empty title column");
            continue;
        }
        let mut p = ItemPayload::new(TypeData::Login { urls: Vec::new() }, &title);
        add_text(&mut p, "username", &get(&rec, i_username));
        add_hidden(&mut p, "password", &get(&rec, i_password));
        add_url(&mut p, "url", &get(&rec, i_url));
        p.notes = get(&rec, i_notes);
        outcome.push(p);
    }
    Ok(outcome)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn field<'a>(p: &'a ItemPayload, name: &str) -> Option<&'a lp_vault::Field> {
        p.fields.iter().find(|f| f.name == name)
    }

    fn map() -> ColumnMap {
        ColumnMap {
            title: Some("Account".into()),
            username: Some("Login".into()),
            password: Some("Pass".into()),
            url: Some("Website".into()),
            notes: Some("Memo".into()),
        }
    }

    #[test]
    fn maps_columns_to_fields() {
        let csv = "\
Account,Login,Pass,Website,Memo
GitHub,octocat,gh_pw,https://github.com,work account
";
        let o = parse_bytes(csv.as_bytes(), &map()).unwrap();
        assert_eq!(o.count(), 1);
        let p = &o.items[0];
        assert_eq!(p.title, "GitHub");
        assert_eq!(field(p, "username").unwrap().value, "octocat");
        assert_eq!(field(p, "password").unwrap().value, "gh_pw");
        assert_eq!(field(p, "url").unwrap().value, "https://github.com");
        assert_eq!(p.notes, "work account");
    }

    #[test]
    fn column_order_independent_and_case_insensitive() {
        // Different order + different header casing than the map.
        let csv = "\
memo,website,pass,login,account
n,https://x,pw,u,Title Here
";
        let o = parse_bytes(csv.as_bytes(), &map()).unwrap();
        assert_eq!(o.items[0].title, "Title Here");
        assert_eq!(field(&o.items[0], "username").unwrap().value, "u");
    }

    #[test]
    fn empty_title_row_is_skipped_by_number() {
        let csv = "\
Account,Login,Pass,Website,Memo
,noname,pw,,
Good,u,p,,
";
        let o = parse_bytes(csv.as_bytes(), &map()).unwrap();
        assert_eq!(o.count(), 1);
        assert_eq!(o.skipped.len(), 1);
        assert_eq!(o.skipped[0].title, "(row 1)");
        // No value leaked in the skip reason.
        assert!(!o.skipped[0].reason.contains("noname"));
    }

    #[test]
    fn missing_title_mapping_errors() {
        let m = ColumnMap::default();
        assert!(parse_bytes(b"a,b\n1,2\n", &m).is_err());
    }

    #[test]
    fn unknown_column_name_errors() {
        let m = ColumnMap {
            title: Some("Nonexistent".into()),
            ..Default::default()
        };
        let err = parse_bytes(b"Account,Login\nx,y\n", &m).unwrap_err();
        assert!(err.to_string().contains("not found"));
    }
}
