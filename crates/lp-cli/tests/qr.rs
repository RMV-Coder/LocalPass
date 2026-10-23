//! `localpass sync qr have|export|import` end to end: two real profiles move a
//! vault, then a delta, by bundle file — the QR channel minus the camera
//! (`qr-transport.md` §10.3).

mod common;

use common::TestProfile;
use predicates::str::contains;

/// `(device_id, identity, fingerprint)` from `device export-identity --json`.
fn identity(p: &TestProfile) -> (String, String, String) {
    let out = p
        .cmd()
        .args(["device", "export-identity", "--json"])
        .output()
        .unwrap();
    assert!(out.status.success());
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    (
        v["device_id"].as_str().unwrap().to_string(),
        v["identity"].as_str().unwrap().to_string(),
        v["fingerprint"].as_str().unwrap().to_string(),
    )
}

fn trust(on: &TestProfile, other: &TestProfile, label: &str) {
    let (_, id, fp) = identity(other);
    on.cmd()
        .args([
            "device",
            "trust",
            &id,
            "--fingerprint",
            &fp,
            "--label",
            label,
        ])
        .assert()
        .success();
}

fn json(cmd: &mut assert_cmd::Command) -> serde_json::Value {
    let out = cmd.output().unwrap();
    assert!(
        out.status.success(),
        "failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    serde_json::from_slice(&out.stdout).unwrap()
}

#[test]
fn a_vault_and_then_only_the_missing_changes_travel_by_bundle_file() {
    let a = TestProfile::initialized();
    let b = TestProfile::initialized();
    trust(&a, &b, "phone");
    trust(&b, &a, "laptop");
    let (b_id, _, _) = identity(&b);
    a.cmd()
        .args(["item", "add", "--title", "Server", "--username", "root"])
        .assert()
        .success();
    let dir = tempfile::tempdir().unwrap();
    let first = dir.path().join("first.lpqr");

    // A shares its vault with B in a bundle.
    let summary = json(a.cmd().args([
        "sync",
        "qr",
        "export",
        "--out",
        first.to_str().unwrap(),
        "--peer",
        &b_id,
        "--share",
        "personal",
        "--json",
    ]));
    assert_eq!(summary["recipient"], b_id.as_str());
    assert_eq!(summary["recipient_label"], "phone");
    assert_eq!(summary["vaults"][0]["ops"], 1);
    let shared = summary["shared"][0].as_str().unwrap().to_string();

    // Exporting over an existing file needs --force.
    a.cmd()
        .args(["sync", "qr", "export", "--out", first.to_str().unwrap()])
        .assert()
        .failure()
        .stderr(contains("--force"));

    // B imports: the vault is adopted and filled.
    let report = json(
        b.cmd()
            .args(["sync", "qr", "import", first.to_str().unwrap(), "--json"]),
    );
    assert_eq!(report["sender_trusted"], true);
    assert_eq!(report["sender_label"], "laptop");
    assert_eq!(report["adopted"][0]["vault_id"], shared.as_str());
    assert_eq!(report["vaults"][0]["applied"], 1);
    assert!(report["alarms"].as_array().unwrap().is_empty());
    b.cmd()
        .args(["item", "list", "--vault", &shared])
        .assert()
        .success()
        .stdout(contains("Server"));

    // A adds two more; B's "what I have" code makes the next bundle carry
    // only those two.
    for t in ["Router", "NAS"] {
        a.cmd()
            .args(["item", "add", "--vault", &shared, "--title", t])
            .assert()
            .success();
    }
    let code = json(b.cmd().args(["sync", "qr", "have", "--json"]));
    let code = code["code"].as_str().unwrap().to_string();
    assert!(code.starts_with("LPHAVE1-"));
    let second = dir.path().join("second.lpqr");
    let summary = json(a.cmd().args([
        "sync",
        "qr",
        "export",
        "--out",
        second.to_str().unwrap(),
        "--have",
        &code,
        "--json",
    ]));
    let vaults = summary["vaults"].as_array().unwrap();
    assert_eq!(vaults.len(), 1);
    assert_eq!(vaults[0]["ops"], 2);
    let report = json(
        b.cmd()
            .args(["sync", "qr", "import", second.to_str().unwrap(), "--json"]),
    );
    assert_eq!(report["vaults"][0]["applied"], 2);
    b.cmd()
        .args(["item", "list", "--vault", &shared])
        .assert()
        .success()
        .stdout(contains("Router"))
        .stdout(contains("NAS"));

    // Nothing left to send: said plainly, non-zero.
    let code = json(b.cmd().args(["sync", "qr", "have", "--json"]));
    a.cmd()
        .args([
            "sync",
            "qr",
            "export",
            "--out",
            dir.path().join("third.lpqr").to_str().unwrap(),
            "--have",
            code["code"].as_str().unwrap(),
        ])
        .assert()
        .failure()
        .stderr(contains("nothing to send"));
}

#[test]
fn a_damaged_bundle_and_a_share_from_an_untrusted_device_are_refused() {
    let a = TestProfile::initialized();
    let b = TestProfile::initialized();
    // A trusts B, but B never trusted A.
    trust(&a, &b, "b");
    let (b_id, _, _) = identity(&b);
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("share.lpqr");
    a.cmd()
        .args([
            "sync",
            "qr",
            "export",
            "--out",
            file.to_str().unwrap(),
            "--peer",
            &b_id,
            "--share",
            "personal",
        ])
        .assert()
        .success();

    // A flipped byte: refused whole by the hash.
    let mut bytes = std::fs::read(&file).unwrap();
    let last = bytes.len() - 1;
    bytes[last] ^= 0x01;
    let damaged = dir.path().join("damaged.lpqr");
    std::fs::write(&damaged, &bytes).unwrap();
    b.cmd()
        .args(["sync", "qr", "import", damaged.to_str().unwrap()])
        .assert()
        .failure()
        .stderr(contains("damaged"));

    // Intact, but from a device B does not trust: the share is refused (an
    // alarm, non-zero) and no vault appears.
    let before = b.cmd().args(["vault", "list"]).output().unwrap().stdout;
    b.cmd()
        .args(["sync", "qr", "import", file.to_str().unwrap()])
        .assert()
        .failure()
        .stdout(contains("NOT a trusted device"))
        .stderr(contains("refused a vault-key share"));
    let after = b.cmd().args(["vault", "list"]).output().unwrap().stdout;
    assert_eq!(before, after);

    // Not a bundle at all.
    let junk = dir.path().join("junk.lpqr");
    std::fs::write(&junk, b"hello").unwrap();
    b.cmd()
        .args(["sync", "qr", "import", junk.to_str().unwrap()])
        .assert()
        .failure()
        .stderr(contains("not a LocalPass QR bundle"));
}
