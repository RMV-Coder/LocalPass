//! LastPass CSV import.
//!
//! LastPass exports a header-row CSV with columns:
//! `url,username,password,totp,extra,name,grouping,fav`.
//!
//! Mapping:
//! - The **secure-note** sentinel URL `http://sn` (LastPass's marker for a note)
//!   → a LocalPass [`Note`](lp_vault::TypeData::Note); `extra` becomes the note
//!   body.
//! - Everything else → a [`Login`](lp_vault::TypeData::Login): `username` /
//!   `password` / `url` fields, `totp` as a hidden `totp` field when present,
//!   `extra` as the note body, `grouping` as a tag, `fav` → the favorite flag.
//! - `name` is the item title (blank → `"(untitled)"`).

use lp_vault::ItemPayload;
use lp_vault::payload::TypeData;

use crate::error::Result;
use crate::import::{add_hidden, add_text, add_url};
use crate::model::ImportOutcome;

/// LastPass's secure-note marker in the `url` column.
const SECURE_NOTE_URL: &str = "http://sn";

/// Parse LastPass CSV `bytes` into an [`ImportOutcome`].
///
/// # Errors
///
/// [`PorterError::Csv`](crate::PorterError::Csv) on a ragged/invalid CSV, or
/// [`PorterError::Malformed`](crate::PorterError::Malformed) if the required
/// header columns are absent.
pub fn parse_bytes(bytes: &[u8]) -> Result<ImportOutcome> {
    let mut rdr = csv::ReaderBuilder::new()
        .has_headers(true)
        .flexible(false)
        .from_reader(bytes);

    // Map header names → column indices so column order doesn't matter.
    let headers = rdr.headers()?.clone();
    let col = |name: &str| headers.iter().position(|h| h.eq_ignore_ascii_case(name));
    let (Some(c_name), Some(c_url)) = (col("name"), col("url")) else {
        return Err(crate::PorterError::malformed(
            "lastpass csv",
            "missing required 'name' or 'url' column",
        ));
    };
    let c_username = col("username");
    let c_password = col("password");
    let c_totp = col("totp");
    let c_extra = col("extra");
    let c_grouping = col("grouping");
    let c_fav = col("fav");

    let get = |rec: &csv::StringRecord, idx: Option<usize>| -> String {
        idx.and_then(|i| rec.get(i)).unwrap_or("").to_string()
    };

    let mut outcome = ImportOutcome::new();
    for result in rdr.records() {
        let rec = result?;
        let mut title = get(&rec, Some(c_name));
        if title.is_empty() {
            title = "(untitled)".to_string();
        }
        let url = get(&rec, Some(c_url));
        let extra = get(&rec, c_extra);
        let grouping = get(&rec, c_grouping);
        let fav = get(&rec, c_fav);

        let mut payload = if url == SECURE_NOTE_URL {
            ItemPayload::new(TypeData::Note {}, &title)
        } else {
            let mut p = ItemPayload::new(TypeData::Login { urls: Vec::new() }, &title);
            add_text(&mut p, "username", &get(&rec, c_username));
            add_hidden(&mut p, "password", &get(&rec, c_password));
            add_url(&mut p, "url", &url);
            add_hidden(&mut p, "totp", &get(&rec, c_totp));
            p
        };

        payload.notes = extra;
        if !grouping.is_empty() {
            payload.tags.push(grouping);
        }
        // LastPass 'fav' is "1" for favorites.
        payload.favorite = fav.trim() == "1";

        outcome.push(payload);
    }
    Ok(outcome)
}

#[cfg(test)]
mod tests {
    use super::*;
    use lp_vault::FieldKind;

    fn field<'a>(p: &'a ItemPayload, name: &str) -> Option<&'a lp_vault::Field> {
        p.fields.iter().find(|f| f.name == name)
    }

    #[test]
    fn login_and_note_mapping() {
        let csv = "\
url,username,password,totp,extra,name,grouping,fav
https://example.com,alice,hunter2,,some notes,Example Login,Work,1
http://sn,,,,secret body,My Note,Personal,0
";
        let o = parse_bytes(csv.as_bytes()).unwrap();
        assert_eq!(o.count(), 2);

        let login = &o.items[0];
        assert_eq!(login.title, "Example Login");
        assert_eq!(login.type_data.type_str(), "login");
        assert_eq!(field(login, "username").unwrap().value, "alice");
        let pw = field(login, "password").unwrap();
        assert_eq!(pw.kind, FieldKind::Hidden);
        assert_eq!(pw.value, "hunter2");
        assert_eq!(field(login, "url").unwrap().value, "https://example.com");
        assert_eq!(login.notes, "some notes");
        assert_eq!(login.tags, vec!["Work".to_string()]);
        assert!(login.favorite);

        let note = &o.items[1];
        assert_eq!(note.type_data.type_str(), "note");
        assert_eq!(note.title, "My Note");
        assert_eq!(note.notes, "secret body");
        assert!(!note.favorite);
    }

    #[test]
    fn totp_preserved_as_hidden_field() {
        let csv = "\
url,username,password,totp,extra,name,grouping,fav
https://x.com,bob,pw,JBSWY3DPEHPK3PXP,,TOTP Login,,0
";
        let o = parse_bytes(csv.as_bytes()).unwrap();
        let totp = field(&o.items[0], "totp").unwrap();
        assert_eq!(totp.kind, FieldKind::Hidden);
        assert_eq!(totp.value, "JBSWY3DPEHPK3PXP");
    }

    #[test]
    fn missing_columns_is_error() {
        let csv = "foo,bar\n1,2\n";
        assert!(parse_bytes(csv.as_bytes()).is_err());
    }

    #[test]
    fn ragged_row_is_clean_error_no_panic() {
        let csv = "\
url,username,password,totp,extra,name,grouping,fav
https://x.com,onlytwo
";
        let err = parse_bytes(csv.as_bytes()).unwrap_err();
        // A value-free CSV error, not a panic.
        assert!(err.to_string().contains("csv"));
    }
}
