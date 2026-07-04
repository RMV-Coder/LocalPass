//! End-to-end CLI integration tests: init, item CRUD round-trips, masking,
//! trash, and auth failures.
//!
//! These spawn the real `localpass` binary against a tempdir profile with the
//! password supplied via `LOCALPASS_PASSWORD`. Argon2id at recommended cost
//! means every unlock is ~1s, so tests batch several assertions over one
//! initialized profile.

mod common;

use common::{TEST_PASSWORD, TestProfile};
use predicates::prelude::*;
use predicates::str::contains;

/// `init` creates the account, prints the Emergency Kit with the Secret Key
/// exactly once, writes the on-device secret-key file, and creates the default
/// `personal` vault. A second `init` is refused.
#[test]
fn init_creates_account_secret_key_and_default_vault() {
    let profile = TestProfile::empty();

    let out = profile.cmd().arg("init").assert().success();
    let stdout = String::from_utf8_lossy(&out.get_output().stdout).into_owned();

    // Emergency Kit and a single Secret Key line.
    assert!(stdout.contains("EMERGENCY KIT"), "kit header printed");
    let key_lines: Vec<&str> = stdout
        .lines()
        .filter(|l| l.contains("Secret Key:") && l.contains("LP1-"))
        .collect();
    assert_eq!(key_lines.len(), 1, "Secret Key printed exactly once");

    // On-device secret-key file exists.
    assert!(
        profile.path().join("secret-key").exists(),
        "secret-key file written"
    );
    // Account store exists.
    assert!(profile.path().join("account.localpass").exists());

    // Default vault present.
    profile
        .cmd()
        .args(["vault", "list"])
        .assert()
        .success()
        .stdout(contains("personal"));

    // A second init is refused (exit 1) and does not print a second key.
    profile
        .cmd()
        .arg("init")
        .assert()
        .failure()
        .code(1)
        .stderr(contains("already exists"));
}

/// Full login round-trip: add → get (masked by default) → --reveal → --field →
/// edit (new version) → history → restore → rm → trash → absent from list.
#[test]
fn login_item_round_trip() {
    let profile = TestProfile::initialized();

    // add
    profile
        .cmd()
        .args([
            "item",
            "add",
            "--type",
            "login",
            "--title",
            "GitHub",
            "--username",
            "octocat",
            "--password",
            "s3cr3t",
            "--url",
            "https://github.com",
            "--tag",
            "dev",
        ])
        .assert()
        .success();

    // get masked: the secret must NOT appear; the mask must.
    profile
        .cmd()
        .args(["item", "get", "GitHub"])
        .assert()
        .success()
        .stdout(contains("octocat"))
        .stdout(contains("s3cr3t").not())
        .stdout(contains("••••••"));

    // get --reveal: the secret appears.
    profile
        .cmd()
        .args(["item", "get", "GitHub", "--reveal"])
        .assert()
        .success()
        .stdout(contains("s3cr3t"));

    // get --field password: exactly the raw value + newline on stdout.
    profile
        .cmd()
        .args(["item", "get", "GitHub", "--field", "password"])
        .assert()
        .success()
        .stdout("s3cr3t\n");

    // edit → new version; username changes.
    profile
        .cmd()
        .args(["item", "edit", "GitHub", "--username", "octocat2"])
        .assert()
        .success()
        .stdout(contains("version 2"));
    profile
        .cmd()
        .args(["item", "get", "GitHub", "--field", "username"])
        .assert()
        .success()
        .stdout("octocat2\n");

    // history shows two versions.
    profile
        .cmd()
        .args(["item", "history", "GitHub", "--json"])
        .assert()
        .success()
        .stdout(contains("\"version\": 1"))
        .stdout(contains("\"version\": 2"));

    // restore v1 → username reverts to octocat (as a new version).
    profile
        .cmd()
        .args(["item", "restore", "GitHub", "--version", "1"])
        .assert()
        .success();
    profile
        .cmd()
        .args(["item", "get", "GitHub", "--field", "username"])
        .assert()
        .success()
        .stdout("octocat\n");

    // rm --force → trash; then absent from list.
    profile
        .cmd()
        .args(["item", "rm", "GitHub", "--force"])
        .assert()
        .success()
        .stdout(contains("trash"));
    profile
        .cmd()
        .args(["item", "list"])
        .assert()
        .success()
        .stdout(contains("GitHub").not());
}

/// env-set round-trip: build from a `.env` file (+ inline `--env`), values are
/// masked by default and revealed with `--reveal`; a note round-trips too.
#[test]
fn env_set_and_note_round_trip() {
    let profile = TestProfile::initialized();

    // Write a small .env file with a comment, blank line, export, and quotes.
    let env_path = profile.path().join("app.env");
    std::fs::write(
        &env_path,
        "# db config\n\nDATABASE_URL=postgres://localhost\nexport TOKEN=\"sk_live_xyz\"\n",
    )
    .unwrap();

    profile
        .cmd()
        .args(["item", "add", "--type", "env-set", "--title", "myapp/dev"])
        .arg("--from-env-file")
        .arg(&env_path)
        .args(["--env", "EXTRA=plain"])
        .assert()
        .success();

    // Masked by default: no secret values, mask present.
    profile
        .cmd()
        .args(["item", "get", "myapp/dev"])
        .assert()
        .success()
        .stdout(contains("DATABASE_URL"))
        .stdout(contains("postgres://localhost").not())
        .stdout(contains("sk_live_xyz").not())
        .stdout(contains("••••••"));

    // Revealed: values present, in order.
    profile
        .cmd()
        .args(["item", "get", "myapp/dev", "--reveal"])
        .assert()
        .success()
        .stdout(contains("postgres://localhost"))
        .stdout(contains("sk_live_xyz"))
        .stdout(contains("plain"));

    // Fetch a single env value for scripting.
    profile
        .cmd()
        .args(["item", "get", "myapp/dev", "--field", "TOKEN"])
        .assert()
        .success()
        .stdout("sk_live_xyz\n");

    // A note round-trips its body.
    profile
        .cmd()
        .args([
            "item", "add", "--type", "note", "--title", "TODO", "--note", "buy milk",
        ])
        .assert()
        .success();
    profile
        .cmd()
        .args(["item", "get", "TODO"])
        .assert()
        .success()
        .stdout(contains("buy milk"));
}

/// A wrong master password fails with the auth exit code (2), and never leaks a
/// stored value.
#[test]
fn wrong_password_exits_with_auth_code() {
    let profile = TestProfile::initialized();

    profile
        .cmd_with_password("definitely-not-the-password")
        .args(["item", "list"])
        .assert()
        .failure()
        .code(2)
        .stderr(contains("password").or(contains("Secret Key")));
}

/// `--json` output parses as JSON for the commands that offer it.
#[test]
fn json_outputs_parse() {
    let profile = TestProfile::initialized();

    profile
        .cmd()
        .args([
            "item",
            "add",
            "--title",
            "Site",
            "--username",
            "u",
            "--password",
            "p",
        ])
        .assert()
        .success();

    // status --json
    assert_json(
        &profile
            .cmd()
            .args(["status", "--json"])
            .output()
            .unwrap()
            .stdout,
    );
    // vault list --json
    assert_json(
        &profile
            .cmd()
            .args(["vault", "list", "--json"])
            .output()
            .unwrap()
            .stdout,
    );
    // item list --json
    assert_json(
        &profile
            .cmd()
            .args(["item", "list", "--json"])
            .output()
            .unwrap()
            .stdout,
    );
    // item get --json
    assert_json(
        &profile
            .cmd()
            .args(["item", "get", "Site", "--json"])
            .output()
            .unwrap()
            .stdout,
    );
    // search --json
    assert_json(
        &profile
            .cmd()
            .args(["search", "Site", "--json"])
            .output()
            .unwrap()
            .stdout,
    );
}

/// search finds an item by title (and honours `--type`).
#[test]
fn search_finds_by_title_and_type() {
    let profile = TestProfile::initialized();
    profile
        .cmd()
        .args(["item", "add", "--title", "AcmeBank", "--username", "me"])
        .assert()
        .success();
    profile
        .cmd()
        .args([
            "item",
            "add",
            "--type",
            "note",
            "--title",
            "AcmeNotes",
            "--note",
            "x",
        ])
        .assert()
        .success();

    // Title substring match.
    profile
        .cmd()
        .args(["search", "Acme"])
        .assert()
        .success()
        .stdout(contains("AcmeBank"))
        .stdout(contains("AcmeNotes"));

    // Type filter narrows to the login.
    profile
        .cmd()
        .args(["search", "Acme", "--type", "login"])
        .assert()
        .success()
        .stdout(contains("AcmeBank"))
        .stdout(contains("AcmeNotes").not());
}

/// A missing item is a user error (exit 1), not an auth or internal failure.
#[test]
fn missing_item_is_user_error() {
    let profile = TestProfile::initialized();
    profile
        .cmd()
        .args(["item", "get", "Nonexistent"])
        .assert()
        .failure()
        .code(1);
}

/// `--no-input` with no password source fails cleanly rather than blocking.
#[test]
fn no_input_without_password_fails() {
    let profile = TestProfile::initialized();
    // Clear the env var this profile would otherwise set.
    let mut cmd = assert_cmd::Command::cargo_bin("localpass").unwrap();
    cmd.env_remove("LOCALPASS_PASSWORD")
        .arg("--profile")
        .arg(profile.path())
        .arg("--no-input")
        .args(["item", "list"])
        .assert()
        .failure()
        .code(1);
    // silence unused-const warning if TEST_PASSWORD is not referenced elsewhere.
    let _ = TEST_PASSWORD;
}

/// Assert that `bytes` is valid, non-empty JSON.
fn assert_json(bytes: &[u8]) {
    let s = String::from_utf8_lossy(bytes);
    let v: serde_json::Value = serde_json::from_str(s.trim())
        .unwrap_or_else(|e| panic!("output was not valid JSON: {e}\n---\n{s}\n---"));
    assert!(!v.is_null(), "JSON was null");
}
