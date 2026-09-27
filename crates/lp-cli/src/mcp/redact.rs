//! Redacting injected secret values out of a child process's captured output.
//!
//! [`run_with_secrets`](super::tools) is the one MCP tool that puts real
//! plaintext anywhere: into the **child process's environment**. The child may
//! then echo it — deliberately (`env`, `printenv`) or accidentally (a debug log
//! line, a stack trace, a `curl -v` header dump). Its stdout/stderr flow back
//! into the agent transcript, so every injected value is scrubbed from the
//! captured bytes before the tool result is built. That is what this module
//! does, and it is the last line of the no-secrets-in-transcript invariant.
//!
//! # The contract
//!
//! For each injected `(VAR, value)` pair, every occurrence of `value` in the
//! captured text is replaced by `[REDACTED:VAR]`.
//!
//! # The length threshold
//!
//! Values shorter than [`MIN_REDACT_LEN`] characters are **not** redacted. A
//! one- or two-character value (`0`, `1`, `on`, `us`) occurs constantly in
//! ordinary program output; redacting it would shred the output into noise
//! while protecting nothing an attacker could not guess in a handful of tries.
//! The threshold is a deliberate, documented trade-off, not an oversight —
//! `LOG_LEVEL=1` stays readable, `AWS_SECRET_ACCESS_KEY=…` does not survive.
//!
//! # Overlap handling
//!
//! Values are applied **longest first**, so when one injected value contains
//! another (`postgres://user:pw@host` and `pw`) the longer, more specific one is
//! redacted before the shorter one can chop it in half.
//!
//! # Transformed echoes
//!
//! A child rarely prints a secret only verbatim. The everyday transformed
//! forms are redacted too (see [`variants`]):
//!
//! - **JSON-escaped**: a value with `"` or `\` inside a logged JSON body;
//! - **percent-encoded**: upper- and lower-case hex, and the form-encoded
//!   `+`-for-space flavour, as in a logged URL or query string;
//! - **base64**: standard and URL-safe alphabets, at all three byte
//!   alignments, so the value is found even *inside* a larger encoded blob such
//!   as an HTTP Basic `Authorization` header (`base64("user:" + password)`, the
//!   classic `curl -v` leak). Only the characters fully determined by the value
//!   are matched, and only when that core is at least [`MIN_BASE64_CORE`] long;
//! - **UTF-16** (LE and BE) of an ASCII value, as a Windows console or
//!   PowerShell redirect writes it and lossy UTF-8 decoding preserves it.
//!
//! This is still pattern matching, not a boundary: a child that deliberately
//! encrypts, reverses, or splits a value gets it past any redactor. The spec
//! (docs/specs/mcp-server.md section 7) says so.

/// Values shorter than this many characters are left alone (see the module
/// docs for why). Four is the shortest value where redaction is more signal
/// than noise.
pub const MIN_REDACT_LEN: usize = 4;

/// Base64 cores shorter than this are not matched: a short run of base64
/// characters occurs by chance in ordinary output (hashes, ids, words).
pub const MIN_BASE64_CORE: usize = 8;

/// Whether a value is long enough to be worth redacting.
#[must_use]
pub fn is_redactable(value: &str) -> bool {
    value.chars().count() >= MIN_REDACT_LEN
}

/// Every form of `value` the redactor looks for: the value itself first, then
/// its JSON-escaped, percent-encoded, base64 and UTF-16 renderings (each only
/// when it differs from the value and is long enough to be meaningful).
#[must_use]
pub fn variants(value: &str) -> Vec<String> {
    let mut out = vec![value.to_string()];
    let mut push = |v: String| {
        if v.chars().count() >= MIN_REDACT_LEN && !out.contains(&v) {
            out.push(v);
        }
    };

    // JSON string-literal escaping, minus the surrounding quotes.
    if let Ok(quoted) = serde_json::to_string(value) {
        push(quoted[1..quoted.len() - 1].to_string());
    }

    // Percent-encoding (RFC 3986 unreserved set kept), both hex cases, and the
    // form-encoded flavour where a space becomes `+`.
    let upper = percent_encode(value);
    push(lowercase_hex(&upper));
    push(upper.replace("%20", "+"));
    push(upper);

    // Base64 cores at every byte alignment, both alphabets.
    for alphabet in [STANDARD, URL_SAFE] {
        for shift in 0..3 {
            let core = base64_core(value.as_bytes(), shift, alphabet);
            if core.len() >= MIN_BASE64_CORE {
                push(core);
            }
        }
    }

    // UTF-16 of an ASCII value (each character paired with a NUL).
    if value.is_ascii() {
        push(value.chars().flat_map(|c| [c, '\0']).collect());
        push(value.chars().flat_map(|c| ['\0', c]).collect());
    }
    out
}

const STANDARD: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
const URL_SAFE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

/// Unpadded base64 of `bytes` in `alphabet`.
fn base64(bytes: &[u8], alphabet: &[u8; 64]) -> String {
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let n = chunk
            .iter()
            .enumerate()
            .fold(0u32, |acc, (i, b)| acc | (u32::from(*b) << (16 - 8 * i)));
        // 1 byte -> 2 chars, 2 -> 3, 3 -> 4.
        for i in 0..=chunk.len() {
            out.push(char::from(alphabet[((n >> (18 - 6 * i)) & 0x3f) as usize]));
        }
    }
    out
}

/// The base64 characters that encode ONLY bits of `value` when it sits
/// `shift` bytes past a 3-byte boundary of some larger encoded blob. The
/// leading characters that mix in the preceding (unknown) bytes and the
/// trailing one that mixes in the following bytes are dropped, so the core
/// matches wherever the value appears inside any base64 text.
fn base64_core(value: &[u8], shift: usize, alphabet: &[u8; 64]) -> String {
    let mut padded = vec![0u8; shift];
    padded.extend_from_slice(value);
    let encoded = base64(&padded, alphabet);
    let skip = (8 * shift).div_ceil(6);
    let end = (8 * padded.len()) / 6;
    if end <= skip {
        return String::new();
    }
    encoded[skip..end].to_string()
}

/// Lower-case only the two hex digits after each `%`.
fn lowercase_hex(encoded: &str) -> String {
    let mut out = String::with_capacity(encoded.len());
    let mut after_pct = 0;
    for c in encoded.chars() {
        if after_pct > 0 {
            out.push(c.to_ascii_lowercase());
            after_pct -= 1;
        } else {
            if c == '%' {
                after_pct = 2;
            }
            out.push(c);
        }
    }
    out
}

/// Percent-encode every byte outside the RFC 3986 unreserved set, upper-case hex.
fn percent_encode(value: &str) -> String {
    use std::fmt::Write as _;
    let mut out = String::with_capacity(value.len() * 3);
    for b in value.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~') {
            out.push(char::from(b));
        } else {
            let _ = write!(out, "%{b:02X}");
        }
    }
    out
}

/// Replace every occurrence of each injected secret in `text` with
/// `[REDACTED:<VAR>]`.
///
/// `injected` is `(variable name, value)` in injection order. Values below
/// [`MIN_REDACT_LEN`] characters and empty values are skipped. Longer values are
/// applied first so nested values cannot be split by a shorter match.
#[must_use]
pub fn redact(text: &str, injected: &[(String, String)]) -> String {
    // Every form of every value; longest first, ties broken by name for a
    // deterministic result.
    let mut order: Vec<(&str, String)> = injected
        .iter()
        .filter(|(_, v)| is_redactable(v))
        .flat_map(|(name, v)| {
            variants(v)
                .into_iter()
                .map(move |form| (name.as_str(), form))
        })
        .collect();
    order.sort_by(|a, b| b.1.len().cmp(&a.1.len()).then_with(|| a.0.cmp(b.0)));

    let mut out = text.to_string();
    for (name, form) in order {
        if out.contains(form.as_str()) {
            out = out.replace(form.as_str(), &format!("[REDACTED:{name}]"));
        }
    }
    out
}

/// Whether any injected value still appears verbatim in `text`.
///
/// The server asserts this is `false` on every `run_with_secrets` result before
/// sending it — a cheap, self-checking guard against a redaction bug ever
/// reaching a transcript.
#[must_use]
pub fn contains_secret(text: &str, injected: &[(String, String)]) -> bool {
    injected
        .iter()
        .filter(|(_, v)| is_redactable(v))
        .any(|(_, v)| variants(v).iter().any(|form| text.contains(form.as_str())))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pairs(v: &[(&str, &str)]) -> Vec<(String, String)> {
        v.iter()
            .map(|(a, b)| ((*a).to_string(), (*b).to_string()))
            .collect()
    }

    #[test]
    fn value_appearing_in_stdout_is_redacted() {
        let injected = pairs(&[("API_TOKEN", "sk_live_0123456789")]);
        let out = redact("token is sk_live_0123456789 ok", &injected);
        assert_eq!(out, "token is [REDACTED:API_TOKEN] ok");
        assert!(!contains_secret(&out, &injected));
    }

    #[test]
    fn value_appearing_in_stderr_is_redacted() {
        // Same function, applied to the stderr stream by the caller.
        let injected = pairs(&[("DB_PASSWORD", "hunter2-hunter2")]);
        let err = redact(
            "FATAL: auth failed for password hunter2-hunter2\n",
            &injected,
        );
        assert_eq!(
            err,
            "FATAL: auth failed for password [REDACTED:DB_PASSWORD]\n"
        );
    }

    #[test]
    fn every_occurrence_is_redacted_not_just_the_first() {
        let injected = pairs(&[("TOK", "abcdefgh")]);
        let out = redact("abcdefgh and abcdefgh again", &injected);
        assert_eq!(out, "[REDACTED:TOK] and [REDACTED:TOK] again");
    }

    #[test]
    fn multiple_values_are_all_redacted() {
        let injected = pairs(&[
            ("A_KEY", "alpha-value-1"),
            ("B_KEY", "bravo-value-2"),
            ("C_KEY", "charlie-value-3"),
        ]);
        let out = redact("alpha-value-1 / bravo-value-2 / charlie-value-3", &injected);
        assert_eq!(
            out,
            "[REDACTED:A_KEY] / [REDACTED:B_KEY] / [REDACTED:C_KEY]"
        );
        assert!(!contains_secret(&out, &injected));
    }

    #[test]
    fn short_values_are_left_alone_below_the_threshold() {
        let injected = pairs(&[("LOG_LEVEL", "1"), ("MODE", "dev")]);
        let out = redact("level 1 mode dev running 1 1 1", &injected);
        assert_eq!(
            out, "level 1 mode dev running 1 1 1",
            "sub-threshold values must not shred the output"
        );
        assert!(!is_redactable("1"));
        assert!(!is_redactable("dev"), "3 chars is below the threshold");
        assert!(is_redactable("devs"), "4 chars is at the threshold");
    }

    #[test]
    fn longest_value_wins_when_one_contains_another() {
        let injected = pairs(&[
            ("SHORT", "s3cr3t"),
            ("LONG", "postgres://u:s3cr3t@db.internal/app"),
        ]);
        let out = redact("DSN=postgres://u:s3cr3t@db.internal/app", &injected);
        assert_eq!(out, "DSN=[REDACTED:LONG]");
        assert!(!contains_secret(&out, &injected));
    }

    #[test]
    fn empty_and_absent_values_are_no_ops() {
        let injected = pairs(&[("EMPTY", ""), ("MISSING", "never-appears-here")]);
        assert_eq!(redact("plain output", &injected), "plain output");
    }

    fn b64(s: &str) -> String {
        base64(s.as_bytes(), STANDARD)
    }

    #[test]
    fn base64_matches_the_rfc_4648_vectors() {
        for (plain, enc) in [
            ("f", "Zg"),
            ("fo", "Zm8"),
            ("foo", "Zm9v"),
            ("foob", "Zm9vYg"),
            ("fooba", "Zm9vYmE"),
            ("foobar", "Zm9vYmFy"),
        ] {
            assert_eq!(b64(plain), enc);
        }
    }

    #[test]
    fn a_password_inside_a_basic_auth_header_is_redacted_at_every_alignment() {
        let secret = "hunter2-correct-horse";
        let injected = pairs(&[("DB_PASSWORD", secret)]);
        for user in ["a", "al", "ali", "alice", "bob-the-builder"] {
            let header = format!(
                "Authorization: Basic {}==",
                b64(&format!("{user}:{secret}"))
            );
            let out = redact(&header, &injected);
            assert!(
                out.contains("[REDACTED:DB_PASSWORD]"),
                "user {user:?}: {out}"
            );
            assert!(!contains_secret(&out, &injected), "user {user:?}: {out}");
        }
    }

    #[test]
    fn a_base64_encoded_value_on_its_own_is_redacted_in_both_alphabets() {
        let secret = "sk_live_0123456789abcdef?>";
        let injected = pairs(&[("STRIPE_KEY", secret)]);
        let url_safe = base64(secret.as_bytes(), URL_SAFE);
        for text in [
            format!("token={}", b64(secret)),
            format!("token={url_safe}"),
        ] {
            assert!(contains_secret(&text, &injected), "{text}");
            assert!(!contains_secret(&redact(&text, &injected), &injected));
        }
    }

    #[test]
    fn json_escaped_values_are_redacted() {
        let secret = r#"p"a\ss/w0rd"#;
        let injected = pairs(&[("PW", secret)]);
        let body = serde_json::json!({ "password": secret }).to_string();
        assert_eq!(redact(&body, &injected), r#"{"password":"[REDACTED:PW]"}"#);
    }

    #[test]
    fn percent_encoded_values_are_redacted_in_both_hex_cases_and_form_encoding() {
        let secret = "p@ss w0rd/äö";
        let injected = pairs(&[("PW", secret)]);
        let upper = percent_encode(secret);
        assert_eq!(upper, "p%40ss%20w0rd%2F%C3%A4%C3%B6");
        for text in [
            format!("GET /login?pw={upper}"),
            format!("GET /login?pw={}", lowercase_hex(&upper)),
            format!("pw={}", upper.replace("%20", "+")),
        ] {
            let out = redact(&text, &injected);
            assert!(out.contains("[REDACTED:PW]"), "{text} -> {out}");
            assert!(!contains_secret(&out, &injected));
        }
    }

    #[test]
    fn utf16_console_output_is_redacted() {
        let secret = "sekret-value-42";
        let injected = pairs(&[("K", secret)]);
        let line = format!("value: {secret}\n");
        let le: String = line.chars().flat_map(|c| [c, '\0']).collect();
        let be: String = line.chars().flat_map(|c| ['\0', c]).collect();
        for text in [le, be] {
            assert!(contains_secret(&text, &injected));
            assert!(!contains_secret(&redact(&text, &injected), &injected));
        }
    }

    #[test]
    fn a_short_value_does_not_shred_unrelated_output() {
        // "4821"'s base64 cores are under MIN_BASE64_CORE, so they are not
        // matched on their own and ordinary text is left alone.
        let injected = pairs(&[("PIN", "4821")]);
        let text = "build 4822 finished in 48.21s, hash YmFy";
        assert_eq!(redact(text, &injected), text);
    }

    #[test]
    fn variants_start_with_the_value_and_have_no_duplicates() {
        let v = variants("plain-ascii-value");
        assert_eq!(v[0], "plain-ascii-value");
        let mut dedup = v.clone();
        dedup.sort();
        dedup.dedup();
        assert_eq!(dedup.len(), v.len());
    }

    #[test]
    fn contains_secret_detects_a_leak() {
        let injected = pairs(&[("K", "leaked-value-xyz")]);
        assert!(contains_secret("oops leaked-value-xyz", &injected));
        assert!(!contains_secret("nothing here", &injected));
    }
}
