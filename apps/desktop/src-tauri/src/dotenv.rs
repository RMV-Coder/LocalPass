// SPDX-License-Identifier: MPL-2.0
// This file is part of the LocalPass desktop GUI. See apps/desktop/LICENSE.

//! A small, **pure** dotenv parser for the GUI's "Paste .env" import.
//!
//! It mirrors the canonical LocalPass dotenv rules (`lp-porter`'s
//! `import::dotenv` and `lp-cli`'s `dotenv`) exactly, re-implemented here so the
//! GUI backend stays a self-contained daemon client (it does not depend on the
//! porter):
//!
//! - blank lines and `#` comment lines are skipped;
//! - a leading `export ` prefix is tolerated;
//! - the line splits on the **first** `=` (so `=` may appear in the value);
//! - a single matching pair of surrounding single **or** double quotes is
//!   stripped from the value; nothing else is un-escaped;
//! - **no** variable interpolation and **no** `#`-mid-value comment stripping —
//!   values stay byte-exact so a secret is never mangled;
//! - keys are trimmed and must be non-empty; a line missing `=` or with an empty
//!   key is **skipped** (lenient), so a stray line in a pasted blob never blocks
//!   the whole import.
//!
//! Parsing runs in Rust (not JS) so the import shares one tested implementation.
//! The pasted text is no more secret than the resulting entries and never leaves
//! the app; it is not a widening of the secret boundary.

use serde::Serialize;

/// One parsed `KEY=value` entry (mirrors the frontend `EnvEntryInput`).
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct EnvEntryView {
    /// The variable name (trimmed, non-empty).
    pub key: String,
    /// The variable value (quotes stripped; otherwise byte-exact).
    pub value: String,
}

/// Parse raw dotenv `text` into ordered `KEY=value` entries.
///
/// Duplicate keys are **kept in place** (both entries are emitted, in order);
/// last-wins deduplication is applied by the caller/UI where it matters, matching
/// dotenv "later assignment wins" semantics while preserving the paste order for
/// display. Malformed lines (no `=`, empty key) are skipped rather than erroring,
/// so one bad line never rejects an otherwise-valid paste.
pub fn parse(text: &str) -> Vec<EnvEntryView> {
    let mut out = Vec::new();
    for raw in text.lines() {
        // `lines()` already drops the trailing `\n`; trimming also removes a
        // stray `\r` from CRLF input and any surrounding whitespace.
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let line = line.strip_prefix("export ").unwrap_or(line);
        let Some((key, val)) = line.split_once('=') else {
            // No `=` → not a KEY=VALUE line. Skip it (lenient).
            continue;
        };
        let key = key.trim();
        if key.is_empty() {
            continue;
        }
        out.push(EnvEntryView {
            key: key.to_string(),
            value: unquote(val.trim()).to_string(),
        });
    }
    out
}

/// Strip a single pair of matching surrounding single/double quotes, if present.
/// Mirrors the canonical `unquote` in `lp-porter`'s dotenv importer.
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

    fn kv(k: &str, v: &str) -> EnvEntryView {
        EnvEntryView {
            key: k.into(),
            value: v.into(),
        }
    }

    #[test]
    fn skips_blank_and_comment_lines() {
        let e = parse("\n# a comment\n   \nFOO=1\n   # indented comment\nBAR=2\n");
        assert_eq!(e, vec![kv("FOO", "1"), kv("BAR", "2")]);
    }

    #[test]
    fn tolerates_export_prefix() {
        let e = parse("export FOO=1\nexport BAR=two\n");
        assert_eq!(e, vec![kv("FOO", "1"), kv("BAR", "two")]);
    }

    #[test]
    fn strips_single_and_double_quotes() {
        let e = parse("A=\"double\"\nB='single'\n");
        assert_eq!(e, vec![kv("A", "double"), kv("B", "single")]);
    }

    #[test]
    fn splits_on_first_equals_only() {
        // A `=` inside the value (e.g. a base64 pad or a query string) is kept.
        let e = parse("URL=postgres://u:p@h/db?x=1\nTOKEN=abc==\n");
        assert_eq!(
            e,
            vec![kv("URL", "postgres://u:p@h/db?x=1"), kv("TOKEN", "abc==")]
        );
    }

    #[test]
    fn empty_value_is_allowed() {
        let e = parse("EMPTY=\nexport ALSO_EMPTY=\n");
        assert_eq!(e, vec![kv("EMPTY", ""), kv("ALSO_EMPTY", "")]);
    }

    #[test]
    fn handles_crlf_line_endings() {
        let e = parse("FOO=1\r\nBAR=2\r\n");
        assert_eq!(e, vec![kv("FOO", "1"), kv("BAR", "2")]);
    }

    #[test]
    fn trims_surrounding_spaces_on_key_and_value() {
        // Leading/trailing spaces around the key and value are trimmed; the
        // quote pair (if any) is stripped after trimming.
        let e = parse("  SPACED_KEY  =  spaced value  \n  Q  = \" quoted \" \n");
        assert_eq!(
            e,
            vec![kv("SPACED_KEY", "spaced value"), kv("Q", " quoted ")]
        );
    }

    #[test]
    fn no_interpolation_and_hash_in_value_is_literal() {
        // `#` mid-value is literal (no comment stripping); `$VAR` is not expanded.
        let e = parse("PW=p@ss#word\nREF=$OTHER/keep\n");
        assert_eq!(e, vec![kv("PW", "p@ss#word"), kv("REF", "$OTHER/keep")]);
    }

    #[test]
    fn malformed_lines_are_skipped_consistently() {
        // A line with no `=` and a line with an empty key are both skipped; the
        // valid lines around them still parse.
        let e = parse("JUST_A_WORD\nFOO=1\n=novalue\nBAR=2\n");
        assert_eq!(e, vec![kv("FOO", "1"), kv("BAR", "2")]);
    }

    #[test]
    fn preserves_paste_order_including_duplicate_keys() {
        // Duplicates are emitted in order; last-wins dedup is the UI's job.
        let e = parse("K=first\nK=second\n");
        assert_eq!(e, vec![kv("K", "first"), kv("K", "second")]);
    }

    #[test]
    fn unmatched_or_single_quote_is_left_literal() {
        // Only a *matching* surrounding pair is stripped; a lone quote stays.
        let e = parse("A=\"unterminated\nB='mixed\"\nC=\"\n");
        assert_eq!(
            e,
            vec![
                kv("A", "\"unterminated"),
                kv("B", "'mixed\""),
                // A single `"` is length 1 → no pair to strip.
                kv("C", "\""),
            ]
        );
    }
}
