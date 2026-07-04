//! A small, hand-rolled dotenv parser and percent-decoder.
//!
//! Used by `env import`, `env diff`, and `run --env-file`. Kept intentionally
//! minimal and dependency-free (LESSONS.md minimal-dep posture): a `.env` here
//! is a sequence of `KEY=VALUE` lines with these rules —
//!
//! - Blank lines and lines whose first non-space char is `#` are skipped.
//! - A leading `export ` prefix is tolerated and stripped.
//! - The key is everything up to the first `=`, trimmed; it must be non-empty.
//! - The value is everything after the first `=`. Leading/trailing ASCII
//!   whitespace is trimmed, then a *single* pair of matching surrounding single
//!   or double quotes is removed. There is **no** variable interpolation and no
//!   escape processing — a value is taken literally (this keeps secret values,
//!   which may contain `$`, `\`, or `#`, byte-exact).
//!
//! Values are never echoed on a parse error — messages name only the line
//! number and, at most, the key.

use std::path::Path;

use anyhow::{Context, Result, bail};

/// One parsed `KEY=VALUE` pair from a dotenv file, in file order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DotenvEntry {
    /// The variable name (left of the first `=`).
    pub key: String,
    /// The literal value (quotes stripped, not interpolated).
    pub value: String,
}

/// Parse dotenv `text` into ordered entries.
///
/// `origin` is a human label (usually the file path) used only in error
/// messages; it is never required to be a real path.
///
/// # Errors
///
/// Fails on a line that has no `=`, or whose key is empty. The offending value
/// is never included in the message.
pub fn parse_str(text: &str, origin: &str) -> Result<Vec<DotenvEntry>> {
    let mut out = Vec::new();
    for (idx, raw) in text.lines().enumerate() {
        let lineno = idx + 1;
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let line = line.strip_prefix("export ").unwrap_or(line);
        let Some((key, val)) = line.split_once('=') else {
            bail!("malformed line {lineno} in {origin} (expected KEY=VALUE)");
        };
        let key = key.trim();
        if key.is_empty() {
            bail!("empty key on line {lineno} in {origin}");
        }
        let value = unquote(val.trim()).to_string();
        out.push(DotenvEntry {
            key: key.to_string(),
            value,
        });
    }
    Ok(out)
}

/// Parse a dotenv file at `path`.
///
/// # Errors
///
/// Propagates read errors and [`parse_str`] parse errors.
pub fn parse_file(path: &Path) -> Result<Vec<DotenvEntry>> {
    let text = std::fs::read_to_string(path)
        .with_context(|| format!("reading env file {}", path.display()))?;
    parse_str(&text, &path.display().to_string())
}

/// Strip a single pair of matching surrounding single/double quotes, if present.
#[must_use]
pub fn unquote(s: &str) -> &str {
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

/// Percent-decode a URL path segment (`%XX` → byte), used for
/// `localpass://vault/item/field` reference segments so a name containing `/`,
/// spaces, or other reserved characters can be encoded.
///
/// A stray `%` not followed by two hex digits is left verbatim (lenient: names
/// with a literal `%` that was never encoded still resolve). The decoded bytes
/// must be valid UTF-8.
///
/// # Errors
///
/// Fails only if the decoded bytes are not valid UTF-8.
pub fn percent_decode(s: &str) -> Result<String> {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%'
            && i + 2 < bytes.len()
            && let (Some(hi), Some(lo)) = (hex_val(bytes[i + 1]), hex_val(bytes[i + 2]))
        {
            out.push(hi * 16 + lo);
            i += 3;
            continue;
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8(out).context("percent-decoded reference segment is not valid UTF-8")
}

/// Map an ASCII hex digit to its value, or `None`.
fn hex_val(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn skips_comments_and_blanks() {
        let text = "# a comment\n\n   \nFOO=1\n  # indented comment\nBAR=2\n";
        let entries = parse_str(text, "test").unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(
            entries[0],
            DotenvEntry {
                key: "FOO".into(),
                value: "1".into()
            }
        );
        assert_eq!(entries[1].key, "BAR");
    }

    #[test]
    fn tolerates_export_prefix() {
        let entries = parse_str("export TOKEN=abc\n", "test").unwrap();
        assert_eq!(entries[0].key, "TOKEN");
        assert_eq!(entries[0].value, "abc");
    }

    #[test]
    fn strips_matching_quotes_only() {
        let entries =
            parse_str("A=\"double\"\nB='single'\nC=\"mismatch'\nD=plain\n", "test").unwrap();
        assert_eq!(entries[0].value, "double");
        assert_eq!(entries[1].value, "single");
        // Mismatched quotes are left verbatim.
        assert_eq!(entries[2].value, "\"mismatch'");
        assert_eq!(entries[3].value, "plain");
    }

    #[test]
    fn no_interpolation_or_escapes() {
        // A value with $, \, and # is taken literally (# only starts a comment
        // at line start, not mid-value).
        let entries = parse_str("URL=postgres://u:p@h/db?x=1#frag\nS=$HOME\\n\n", "test").unwrap();
        assert_eq!(entries[0].value, "postgres://u:p@h/db?x=1#frag");
        assert_eq!(entries[1].value, "$HOME\\n");
    }

    #[test]
    fn value_may_contain_equals() {
        let entries = parse_str("KEY=a=b=c\n", "test").unwrap();
        assert_eq!(entries[0].value, "a=b=c");
    }

    #[test]
    fn empty_value_is_ok() {
        let entries = parse_str("EMPTY=\n", "test").unwrap();
        assert_eq!(entries[0].value, "");
    }

    #[test]
    fn missing_equals_is_error_without_value() {
        let err = parse_str("JUSTAKEY\n", "myfile").unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("line 1"));
        assert!(msg.contains("myfile"));
    }

    #[test]
    fn empty_key_is_error() {
        let err = parse_str("=value\n", "f").unwrap_err();
        assert!(format!("{err:#}").contains("empty key"));
    }

    #[test]
    fn percent_decode_basic() {
        assert_eq!(percent_decode("my%2Fapp").unwrap(), "my/app");
        assert_eq!(percent_decode("a%20b").unwrap(), "a b");
        assert_eq!(percent_decode("plain").unwrap(), "plain");
    }

    #[test]
    fn percent_decode_leaves_bare_percent() {
        // A % not followed by two hex digits stays literal.
        assert_eq!(percent_decode("100%done").unwrap(), "100%done");
        assert_eq!(percent_decode("tail%").unwrap(), "tail%");
        assert_eq!(percent_decode("%zz").unwrap(), "%zz");
    }

    #[test]
    fn percent_decode_utf8() {
        // %C3%A9 is é.
        assert_eq!(percent_decode("caf%C3%A9").unwrap(), "café");
    }
}
