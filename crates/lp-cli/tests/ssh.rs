//! CLI integration tests for `localpass ssh generate | list | public`.
//!
//! These drive the real `localpass` binary against a tempdir profile with
//! `--no-daemon` (the direct-unlock path), so they never spawn a daemon or touch
//! the fixed, system-wide SSH agent endpoint — keeping them isolated and free of
//! contention with the daemon crate's `ssh_agent` integration test.

mod common;

use common::TestProfile;
use predicates::str::contains;

/// `ssh generate` prints ONLY the public key (never the private key), stores an
/// ssh_key item, and `ssh list` then shows it with its fingerprint.
#[test]
fn generate_prints_public_only_and_list_shows_it() {
    let profile = TestProfile::initialized();

    let out = profile
        .cmd()
        .args([
            "--no-daemon",
            "ssh",
            "generate",
            "--title",
            "ci key",
            "--algo",
            "ed25519",
        ])
        .assert()
        .success();
    let stdout = String::from_utf8_lossy(&out.get_output().stdout).into_owned();

    // The single stdout line is the OpenSSH public key.
    assert!(
        stdout.trim().starts_with("ssh-ed25519 "),
        "public key printed to stdout, got: {stdout:?}"
    );
    // The private key must NEVER appear anywhere in the output.
    assert!(
        !stdout.contains("PRIVATE KEY"),
        "private key must not be printed"
    );

    // `ssh list` shows the key with a SHA256 fingerprint and its comment.
    profile
        .cmd()
        .args(["--no-daemon", "ssh", "list"])
        .assert()
        .success()
        .stdout(contains("ssh-ed25519"))
        .stdout(contains("SHA256:"))
        .stdout(contains("ci key"));
}

/// `ssh public` prints the stored item's public key for authorized_keys, and
/// refuses a non-ssh item.
#[test]
fn public_prints_key_and_rejects_non_ssh() {
    let profile = TestProfile::initialized();

    // Generate a key.
    profile
        .cmd()
        .args(["--no-daemon", "ssh", "generate", "--title", "deploy key"])
        .assert()
        .success();

    // `ssh public` prints its public key.
    profile
        .cmd()
        .args(["--no-daemon", "ssh", "public", "deploy key"])
        .assert()
        .success()
        .stdout(contains("ssh-ed25519 "));

    // A login item is not an SSH key: `ssh public` refuses it (exit 1).
    profile
        .cmd()
        .args([
            "--no-daemon",
            "item",
            "add",
            "--type",
            "login",
            "--title",
            "not-a-key",
        ])
        .assert()
        .success();
    profile
        .cmd()
        .args(["--no-daemon", "ssh", "public", "not-a-key"])
        .assert()
        .failure()
        .code(1)
        .stderr(contains("not an SSH key"));
}

/// `ssh list --json` emits a machine-readable array with fingerprint/comment/algo.
#[test]
fn list_json_shape() {
    let profile = TestProfile::initialized();
    profile
        .cmd()
        .args(["--no-daemon", "ssh", "generate", "--title", "json key"])
        .assert()
        .success();

    let out = profile
        .cmd()
        .args(["--no-daemon", "ssh", "list", "--json"])
        .assert()
        .success();
    let stdout = String::from_utf8_lossy(&out.get_output().stdout).into_owned();
    let v: serde_json::Value = serde_json::from_str(&stdout).expect("valid JSON");
    let arr = v.as_array().expect("array");
    assert_eq!(arr.len(), 1);
    let obj = &arr[0];
    assert_eq!(obj["comment"], "json key");
    assert_eq!(obj["algo"], "ssh-ed25519");
    assert!(
        obj["fingerprint"]
            .as_str()
            .unwrap_or_default()
            .starts_with("SHA256:")
    );
}
