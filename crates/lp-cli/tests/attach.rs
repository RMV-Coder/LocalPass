//! End-to-end CLI integration tests for `localpass attach ...`.
//!
//! These spawn the real `localpass` binary against a tempdir profile with the
//! password supplied via `LOCALPASS_PASSWORD`. A single initialized profile is
//! reused within each test to amortize the ~1s Argon2id unlock cost.

mod common;

use std::fs;

use common::TestProfile;
use predicates::str::contains;

/// Create a source file with `contents` under the profile temp dir and return
/// its path.
fn write_source(profile: &TestProfile, name: &str, contents: &[u8]) -> std::path::PathBuf {
    let path = profile.path().join(name);
    fs::write(&path, contents).expect("write source file");
    path
}

/// add → list → get round-trips the bytes; get --out writes the file.
#[test]
fn add_list_get_roundtrip() {
    let profile = TestProfile::initialized();

    // An item to attach to.
    profile
        .cmd()
        .args(["item", "add", "--title", "Deploy", "--username", "root"])
        .assert()
        .success();

    let secret = b"-----BEGIN CERTIFICATE-----\nbinary\x00\x01payload\n";
    let src = write_source(&profile, "cert.pem", secret);

    // add
    profile
        .cmd()
        .args(["attach", "add", "Deploy"])
        .arg(&src)
        .assert()
        .success()
        .stdout(contains("cert.pem"));

    // list shows the name + a size, never the bytes.
    profile
        .cmd()
        .args(["attach", "list", "Deploy"])
        .assert()
        .success()
        .stdout(contains("cert.pem"));

    // get --out writes the decrypted file, byte-identical.
    let out = profile.path().join("recovered.pem");
    profile
        .cmd()
        .args(["attach", "get", "Deploy", "cert.pem", "--out"])
        .arg(&out)
        .assert()
        .success();
    let recovered = fs::read(&out).expect("read recovered file");
    assert_eq!(recovered, secret, "get --out round-trips the bytes");
}

/// list as JSON exposes id/name/size (and never blob bytes).
#[test]
fn list_json_shape() {
    let profile = TestProfile::initialized();
    profile
        .cmd()
        .args(["item", "add", "--title", "Box"])
        .assert()
        .success();
    let src = write_source(&profile, "data.bin", &[9u8; 32]);
    profile
        .cmd()
        .args(["attach", "add", "Box"])
        .arg(&src)
        .assert()
        .success();

    let out = profile
        .cmd()
        .args(["attach", "list", "Box", "--json"])
        .assert()
        .success();
    let stdout = String::from_utf8_lossy(&out.get_output().stdout).into_owned();
    let arr: serde_json::Value = serde_json::from_str(&stdout).expect("valid JSON");
    let first = &arr[0];
    assert_eq!(first["name"], "data.bin");
    assert_eq!(first["size"], 32);
    assert!(first["id"].as_str().is_some());
}

/// An oversized file is rejected with a clear error (exit 1), before storing.
#[test]
fn oversized_is_rejected() {
    let profile = TestProfile::initialized();
    profile
        .cmd()
        .args(["item", "add", "--title", "Big"])
        .assert()
        .success();

    // Just over the 50 MiB cap.
    let over = vec![0u8; 50 * 1024 * 1024 + 1];
    let src = write_source(&profile, "huge.bin", &over);

    profile
        .cmd()
        .args(["attach", "add", "Big"])
        .arg(&src)
        .assert()
        .failure()
        .code(1)
        .stderr(contains("limit"));

    // Nothing was stored.
    profile
        .cmd()
        .args(["attach", "list", "Big"])
        .assert()
        .success()
        .stdout(contains("(no attachments)"));
}

/// rm removes the attachment; a subsequent get is a clear error.
#[test]
fn rm_removes_attachment() {
    let profile = TestProfile::initialized();
    profile
        .cmd()
        .args(["item", "add", "--title", "Trashy"])
        .assert()
        .success();
    let src = write_source(&profile, "gone.txt", b"delete me");
    profile
        .cmd()
        .args(["attach", "add", "Trashy"])
        .arg(&src)
        .assert()
        .success();

    profile
        .cmd()
        .args(["attach", "rm", "Trashy", "gone.txt", "--force"])
        .assert()
        .success()
        .stdout(contains("removed"));

    profile
        .cmd()
        .args(["attach", "list", "Trashy"])
        .assert()
        .success()
        .stdout(contains("(no attachments)"));
}

/// get of a missing attachment is a clear usage error (exit 1).
#[test]
fn get_missing_attachment_errors() {
    let profile = TestProfile::initialized();
    profile
        .cmd()
        .args(["item", "add", "--title", "Empty"])
        .assert()
        .success();

    let out = profile.path().join("nope.out");
    profile
        .cmd()
        .args(["attach", "get", "Empty", "does-not-exist", "--out"])
        .arg(&out)
        .assert()
        .failure()
        .code(1)
        .stderr(contains("no attachment"));
    assert!(!out.exists(), "no file written for a missing attachment");
}

/// get refuses to overwrite an existing file without --force, and honors --force.
#[test]
fn get_refuses_overwrite_without_force() {
    let profile = TestProfile::initialized();
    profile
        .cmd()
        .args(["item", "add", "--title", "Over"])
        .assert()
        .success();
    let src = write_source(&profile, "payload.dat", b"real-content");
    profile
        .cmd()
        .args(["attach", "add", "Over"])
        .arg(&src)
        .assert()
        .success();

    // Pre-create the output path.
    let out = profile.path().join("exists.dat");
    fs::write(&out, b"old").unwrap();

    // Without --force: refused.
    profile
        .cmd()
        .args(["attach", "get", "Over", "payload.dat", "--out"])
        .arg(&out)
        .assert()
        .failure()
        .code(1)
        .stderr(contains("already exists"));

    // With --force: overwritten with the decrypted content.
    profile
        .cmd()
        .args(["attach", "get", "Over", "payload.dat", "--force", "--out"])
        .arg(&out)
        .assert()
        .success();
    assert_eq!(fs::read(&out).unwrap(), b"real-content");
}

/// --name overrides the stored filename.
#[test]
fn add_with_custom_name() {
    let profile = TestProfile::initialized();
    profile
        .cmd()
        .args(["item", "add", "--title", "Named"])
        .assert()
        .success();
    let src = write_source(&profile, "on-disk-name.bin", b"xyz");
    profile
        .cmd()
        .args(["attach", "add", "Named", "--name", "stored-as.bin"])
        .arg(&src)
        .assert()
        .success()
        .stdout(contains("stored-as.bin"));

    profile
        .cmd()
        .args(["attach", "list", "Named"])
        .assert()
        .success()
        .stdout(contains("stored-as.bin"));
}
