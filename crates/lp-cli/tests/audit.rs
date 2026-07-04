//! Integration tests for `localpass audit` (PRD §4.9), driving the built binary
//! via `assert_cmd`.
//!
//! `init` runs Argon2id (~1s), so a single initialized profile is reused and the
//! assertions are batched. Every command passes `--no-daemon` so the CLI unlocks
//! directly and audit recording is deterministic (no dependence on a background
//! daemon that another test might have left running).

mod common;

use common::TestProfile;
use predicates::prelude::*;
use predicates::str::contains;

/// The planted secret/username/title used to assert they never reach the log.
const SECRET_PW: &str = "sup3r-s3cr3t-audit-pw";
const USERNAME: &str = "svc_audit_user";
const TITLE: &str = "AuditTargetItem";

/// Add a login item with a secret password + username to the `personal` vault.
fn add_login(profile: &TestProfile) {
    profile
        .cmd()
        .args([
            "--no-daemon",
            "item",
            "add",
            "--type",
            "login",
            "--title",
            TITLE,
            "--username",
            USERNAME,
            "--password",
            SECRET_PW,
        ])
        .assert()
        .success();
}

/// The `audit --json` output as parsed JSON.
fn audit_json(profile: &TestProfile) -> serde_json::Value {
    let out = profile
        .cmd()
        .args(["--no-daemon", "audit", "--json"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    serde_json::from_slice(&out).expect("audit --json parses")
}

#[test]
fn audit_json_parses_and_records_mutations_and_reveals() {
    let profile = TestProfile::initialized();
    add_login(&profile);

    // A revealed get logs an ItemSecretRead; a masked get does not.
    profile
        .cmd()
        .args(["--no-daemon", "item", "get", TITLE, "--reveal"])
        .assert()
        .success();
    // Masked get (no --reveal): must NOT add a secret read.
    profile
        .cmd()
        .args(["--no-daemon", "item", "get", TITLE])
        .assert()
        .success();
    // A single-field reveal for scripting logs a secret read of that field.
    profile
        .cmd()
        .args(["--no-daemon", "item", "get", TITLE, "--field", "password"])
        .assert()
        .success()
        .stdout(contains(SECRET_PW)); // --field prints the raw value

    let arr = audit_json(&profile);
    let items = arr.as_array().expect("json array");

    // We expect: item_create (from add), then exactly two item_secret_read
    // (the --reveal and the --field), and no read from the masked get.
    let kinds: Vec<&str> = items.iter().map(|r| r["kind"].as_str().unwrap()).collect();
    assert!(kinds.contains(&"item_create"), "kinds: {kinds:?}");
    let reveals = kinds.iter().filter(|k| **k == "item_secret_read").count();
    assert_eq!(
        reveals, 2,
        "one --reveal + one --field, no masked read; {kinds:?}"
    );

    // The --field read record names the field but never the value.
    let field_read = items
        .iter()
        .find(|r| r["kind"] == "item_secret_read" && r["field"] == "password")
        .expect("a password field read");
    assert!(
        field_read["item_id"].is_string(),
        "read carries the item id"
    );
}

#[test]
fn audit_never_prints_a_secret_or_title() {
    let profile = TestProfile::initialized();
    add_login(&profile);
    // Reveal (to generate a secret-read record) then dump the audit log both ways.
    profile
        .cmd()
        .args(["--no-daemon", "item", "get", TITLE, "--reveal"])
        .assert()
        .success();

    // Human table: no secret, no username, no title.
    profile
        .cmd()
        .args(["--no-daemon", "audit"])
        .assert()
        .success()
        .stdout(contains(SECRET_PW).not())
        .stdout(contains(USERNAME).not())
        .stdout(contains(TITLE).not());

    // JSON: same contract.
    profile
        .cmd()
        .args(["--no-daemon", "audit", "--json"])
        .assert()
        .success()
        .stdout(contains(SECRET_PW).not())
        .stdout(contains(USERNAME).not())
        .stdout(contains(TITLE).not());
}

#[test]
fn audit_verify_exits_zero_on_a_good_chain() {
    let profile = TestProfile::initialized();
    add_login(&profile);
    profile
        .cmd()
        .args(["--no-daemon", "audit", "--verify"])
        .assert()
        .success()
        .stdout(contains("OK"));
}

#[test]
fn audit_verify_exits_nonzero_on_a_tampered_chain() {
    let profile = TestProfile::initialized();
    add_login(&profile);

    // Tamper with the audit log directly: flip a record's timestamp so its chain
    // hash no longer matches the next record's prev_hash.
    let account = profile.path().join("account.localpass");
    let conn = rusqlite::Connection::open(&account).unwrap();
    conn.execute(
        "UPDATE audit_log SET timestamp = timestamp + 5 WHERE seq = 1",
        [],
    )
    .unwrap();
    drop(conn);

    profile
        .cmd()
        .args(["--no-daemon", "audit", "--verify"])
        .assert()
        .failure()
        .stderr(contains("FAILED"));
}

#[test]
fn audit_since_filters_by_time() {
    let profile = TestProfile::initialized();
    add_login(&profile);

    // A far-future --since (absolute unix-millis) filters everything out.
    let far_future = "99999999999999"; // year ~5138
    profile
        .cmd()
        .args(["--no-daemon", "audit", "--since", far_future])
        .assert()
        .success()
        .stdout(contains("no audit records"));

    // A generous relative window keeps recent records.
    let out = profile
        .cmd()
        .args(["--no-daemon", "audit", "--since", "365d", "--json"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let arr: serde_json::Value = serde_json::from_slice(&out).unwrap();
    assert!(
        !arr.as_array().unwrap().is_empty(),
        "recent records within 365d"
    );
}

#[test]
fn export_is_audited() {
    let profile = TestProfile::initialized();
    add_login(&profile);

    let out_path = profile.path().join("export.json");
    profile
        .cmd()
        .args([
            "--no-daemon",
            "export",
            "json",
            out_path.to_str().unwrap(),
            "--i-understand-plaintext-export",
        ])
        .assert()
        .success();

    let arr = audit_json(&profile);
    let export_rec = arr
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["kind"] == "export")
        .expect("an export record");
    assert_eq!(export_rec["export_format"], "json");
    assert_eq!(export_rec["item_count"], 1);
}
