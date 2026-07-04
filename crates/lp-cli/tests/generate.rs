//! Integration tests for `localpass generate` — no account/unlock needed, so
//! these are cheap and can assert broadly on lengths, charsets, entropy, and
//! distinctness.

use assert_cmd::Command;
use predicates::str::contains;

fn generate() -> Command {
    Command::cargo_bin("localpass").expect("built binary")
}

/// Only the secret goes to stdout (entropy is on stderr), at the requested
/// length, alphanumeric+symbol by default.
#[test]
fn password_default_length_and_stdout_is_secret_only() {
    let out = generate()
        .args(["generate", "--length", "32"])
        .output()
        .unwrap();
    let stdout = String::from_utf8(out.stdout).unwrap();
    let secret = stdout.trim_end();
    assert_eq!(secret.chars().count(), 32, "requested length honoured");
    // Entropy is reported on stderr, not stdout (clean for piping).
    let stderr = String::from_utf8(out.stderr).unwrap();
    assert!(stderr.contains("entropy"), "entropy on stderr");
    assert!(!stdout.contains("entropy"), "no entropy on stdout");
}

/// `--no-symbols` restricts to `[A-Za-z0-9]`.
#[test]
fn password_no_symbols_is_alphanumeric() {
    let out = generate()
        .args(["generate", "--length", "48", "--no-symbols"])
        .output()
        .unwrap();
    let secret = String::from_utf8(out.stdout)
        .unwrap()
        .trim_end()
        .to_string();
    assert_eq!(secret.chars().count(), 48);
    assert!(
        secret.chars().all(|c| c.is_ascii_alphanumeric()),
        "no symbols present: {secret}"
    );
}

/// A diceware passphrase has the requested number of words joined by the
/// separator, and reports entropy.
#[test]
fn passphrase_word_count_and_separator() {
    let out = generate()
        .args(["generate", "--words", "6", "--separator", "."])
        .output()
        .unwrap();
    let secret = String::from_utf8(out.stdout)
        .unwrap()
        .trim_end()
        .to_string();
    let words: Vec<&str> = secret.split('.').collect();
    assert_eq!(words.len(), 6, "six words: {secret}");
    assert!(words.iter().all(|w| !w.is_empty()));
}

/// `--json` includes the secret and an entropy estimate, and parses.
#[test]
fn generate_json_has_secret_and_entropy() {
    let out = generate()
        .args(["generate", "--length", "20", "--json"])
        .output()
        .unwrap();
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).expect("valid JSON");
    assert_eq!(v["kind"], "password");
    assert_eq!(v["secret"].as_str().unwrap().chars().count(), 20);
    assert!(v["entropy_bits"].as_f64().unwrap() > 100.0);
}

/// Two generations produce distinct outputs (CSPRNG-backed).
#[test]
fn distinct_outputs() {
    let a = generate()
        .args(["generate", "--length", "24"])
        .output()
        .unwrap()
        .stdout;
    let b = generate()
        .args(["generate", "--length", "24"])
        .output()
        .unwrap()
        .stdout;
    assert_ne!(a, b, "two generations must differ");
}

/// A zero length is a clean user error, not a panic.
#[test]
fn zero_length_is_user_error() {
    generate()
        .args(["generate", "--length", "0"])
        .assert()
        .failure()
        .stderr(contains("at least 1"));
}
