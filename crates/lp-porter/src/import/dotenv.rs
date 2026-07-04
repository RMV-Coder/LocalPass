//! `.env` file import → **one** [`TypeData::EnvSet`] item.
//!
//! The dotenv semantics mirror lp-cli's `dotenv` module conceptually (blank/
//! comment skipping, `export ` prefix tolerance, single surrounding quote-pair
//! stripping, **no** interpolation or escape processing so secret values stay
//! byte-exact) but are re-implemented here so `lp-porter` does not depend on
//! `lp-cli` (the dependency would point the wrong way — the CLI depends on the
//! porter).
//!
//! Values are never echoed: a malformed line names only its line number.

use lp_vault::ItemPayload;
use lp_vault::payload::{EnvEntry, TypeData};

use crate::error::{PorterError, Result};
use crate::model::ImportOutcome;

/// Parse dotenv `text` into a single env-set item titled `title`.
///
/// # Errors
///
/// [`PorterError::Malformed`] on a line missing `=` or with an empty key. The
/// offending value is never included.
pub fn parse_str(text: &str, title: &str) -> Result<ImportOutcome> {
    let entries = parse_entries(text)?;
    let payload = ItemPayload::new(TypeData::EnvSet { entries }, title);
    let mut outcome = ImportOutcome::new();
    outcome.push(payload);
    Ok(outcome)
}

/// Read and parse a `.env` file at `path` into a single env-set item.
///
/// `title` defaults to the file stem if `None`.
///
/// # Errors
///
/// Propagates read errors and [`parse_str`] parse errors.
pub fn parse_file(path: &std::path::Path, title: Option<&str>) -> Result<ImportOutcome> {
    let text = std::fs::read_to_string(path)?;
    let default_title = path
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("imported-env");
    parse_str(&text, title.unwrap_or(default_title))
}

/// The core line parser (shared by string/file entry points).
fn parse_entries(text: &str) -> Result<Vec<EnvEntry>> {
    let mut out = Vec::new();
    for (idx, raw) in text.lines().enumerate() {
        let lineno = idx + 1;
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let line = line.strip_prefix("export ").unwrap_or(line);
        let Some((key, val)) = line.split_once('=') else {
            return Err(PorterError::malformed(
                "env",
                format!("line {lineno}: expected KEY=VALUE"),
            ));
        };
        let key = key.trim();
        if key.is_empty() {
            return Err(PorterError::malformed(
                "env",
                format!("line {lineno}: empty key"),
            ));
        }
        out.push(EnvEntry {
            key: key.to_string(),
            value: unquote(val.trim()).to_string(),
        });
    }
    Ok(out)
}

/// Strip a single pair of matching surrounding single/double quotes, if present.
fn unquote(s: &str) -> &str {
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

#[cfg(test)]
mod tests {
    use super::*;

    fn entries_of(o: &ImportOutcome) -> Vec<EnvEntry> {
        match &o.items[0].type_data {
            TypeData::EnvSet { entries } => entries.clone(),
            _ => panic!("not an env-set"),
        }
    }

    #[test]
    fn one_env_set_with_n_entries() {
        let text = "# header\n\nFOO=1\nexport BAR=\"two\"\nBAZ='three'\n";
        let o = parse_str(text, "dev").unwrap();
        assert_eq!(o.count(), 1);
        assert_eq!(o.items[0].title, "dev");
        let e = entries_of(&o);
        assert_eq!(e.len(), 3);
        assert_eq!(
            e[0],
            EnvEntry {
                key: "FOO".into(),
                value: "1".into()
            }
        );
        assert_eq!(
            e[1],
            EnvEntry {
                key: "BAR".into(),
                value: "two".into()
            }
        );
        assert_eq!(
            e[2],
            EnvEntry {
                key: "BAZ".into(),
                value: "three".into()
            }
        );
    }

    #[test]
    fn preserves_order_and_literal_specials() {
        let text = "Z=last\nA=first\nURL=postgres://u:p@h/db?x=1#frag\n";
        let e = entries_of(&parse_str(text, "t").unwrap());
        assert_eq!(e[0].key, "Z");
        assert_eq!(e[1].key, "A");
        // '#' mid-value is literal, no interpolation.
        assert_eq!(e[2].value, "postgres://u:p@h/db?x=1#frag");
    }

    #[test]
    fn missing_equals_is_error_without_value() {
        let err = parse_str("SECRETVALUE_NO_EQUALS\n", "t").unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("line 1"));
        assert!(!msg.contains("SECRETVALUE_NO_EQUALS"));
    }

    #[test]
    fn empty_key_is_error() {
        let err = parse_str("=oops\n", "t").unwrap_err();
        assert!(err.to_string().contains("empty key"));
    }
}
