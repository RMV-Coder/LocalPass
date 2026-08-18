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

/// Values shorter than this many characters are left alone (see the module
/// docs for why). Four is the shortest value where redaction is more signal
/// than noise.
pub const MIN_REDACT_LEN: usize = 4;

/// Whether a value is long enough to be worth redacting.
#[must_use]
pub fn is_redactable(value: &str) -> bool {
    value.chars().count() >= MIN_REDACT_LEN
}

/// Replace every occurrence of each injected secret in `text` with
/// `[REDACTED:<VAR>]`.
///
/// `injected` is `(variable name, value)` in injection order. Values below
/// [`MIN_REDACT_LEN`] characters and empty values are skipped. Longer values are
/// applied first so nested values cannot be split by a shorter match.
#[must_use]
pub fn redact(text: &str, injected: &[(String, String)]) -> String {
    // Longest value first; ties broken by name for a deterministic result.
    let mut order: Vec<&(String, String)> =
        injected.iter().filter(|(_, v)| is_redactable(v)).collect();
    order.sort_by(|a, b| b.1.len().cmp(&a.1.len()).then_with(|| a.0.cmp(&b.0)));

    let mut out = text.to_string();
    for (name, value) in order {
        if out.contains(value.as_str()) {
            out = out.replace(value.as_str(), &format!("[REDACTED:{name}]"));
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
        .any(|(_, v)| is_redactable(v) && text.contains(v.as_str()))
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

    #[test]
    fn contains_secret_detects_a_leak() {
        let injected = pairs(&[("K", "leaked-value-xyz")]);
        assert!(contains_secret("oops leaked-value-xyz", &injected));
        assert!(!contains_secret("nothing here", &injected));
    }
}
