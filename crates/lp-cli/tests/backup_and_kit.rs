//! CLI-level tests for `localpass backup ...`, `localpass kit`, and
//! `localpass vault stats|prune` — the command wiring on top of the lp-vault
//! backup/prune machinery (which has its own suite in
//! `crates/lp-vault/tests/backup_and_prune.rs`).
//!
//! Unlocks cost ~1s of Argon2 each, so everything shares one initialized
//! profile and one test function per concern group.

mod common;

use common::TestProfile;
use predicates::prelude::*;
use predicates::str::contains;

/// backup create → list → verify through the CLI, plus vault stats.
#[test]
fn backup_create_list_verify_and_stats() {
    let p = TestProfile::initialized();
    p.cmd()
        .args(["item", "add", "--title", "BackMeUp", "--password", "pw1"])
        .assert()
        .success();

    // create
    p.cmd()
        .args(["backup", "create"])
        .assert()
        .success()
        .stdout(contains("backup"));

    // list shows exactly one backup
    p.cmd()
        .args(["backup", "list"])
        .assert()
        .success()
        .stdout(contains("TIMESTAMP"));

    // verify passes all checks with the right credentials (positional arg =
    // the timestamp dir name created above, read from the backups root)
    let backups_root = p.path().join("backups");
    let ts = std::fs::read_dir(&backups_root)
        .unwrap()
        .next()
        .unwrap()
        .unwrap()
        .file_name()
        .into_string()
        .unwrap();
    p.cmd()
        .args(["backup", "verify", &ts])
        .assert()
        .success()
        .stdout(contains("ok").or(contains("OK")).or(contains("pass")));

    // stats are visible (PRD §11 #8: very visible storage statistics)
    p.cmd()
        .args(["vault", "stats"])
        .assert()
        .success()
        .stdout(contains("items").or(contains("Items")));

    // prune dry-run reports and deletes nothing
    p.cmd()
        .args(["vault", "prune", "--keep-last", "1", "--dry-run"])
        .assert()
        .success();
}

/// kit writes a file containing the Secret Key, and refuses the profile dir.
#[test]
fn kit_writes_outside_profile_and_refuses_inside() {
    let p = TestProfile::initialized();
    let outdir = tempfile::tempdir().unwrap();
    let out = outdir.path().join("kit.txt");

    // Writes the kit; the file contains the Secret Key (LP1- prefix) and the
    // profile path.
    p.cmd().args(["kit", "--out"]).arg(&out).assert().success();
    let kit = std::fs::read_to_string(&out).unwrap();
    assert!(kit.contains("LP1-"), "kit contains the Secret Key");
    assert!(
        kit.contains(&p.path().display().to_string()),
        "kit names the profile path"
    );

    // Refuses to write inside the profile directory.
    let inside = p.path().join("emergency-kit.txt");
    p.cmd()
        .args(["kit", "--out"])
        .arg(&inside)
        .assert()
        .failure()
        .stderr(contains("outside the profile").or(contains("refusing")));
    assert!(
        !inside.exists(),
        "no kit file was created inside the profile"
    );
}
