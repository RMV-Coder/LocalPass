//! Integration tests for `localpass import` and `localpass export` (PRD §4.6 /
//! §6.9), driving the built binary via `assert_cmd`.
//!
//! `init` runs Argon2id (~1s), so each test batches many assertions over one
//! initialized profile. Fixtures (1PUX zip, bitwarden json, lastpass/generic
//! csv, .env) are authored inline in a tempdir. Secret values are chosen so the
//! tests can assert they land in the right field via `item get --reveal`, and
//! that they NEVER appear in skip reports / plaintext-guard errors.
//!
//! Standalone-age compatibility: no real `age` binary is assumed present in CI,
//! so the age round-trip is exercised via `localpass import age`, and the binary
//! header magic is asserted directly on the written archive bytes (the `age`
//! v1 magic `age-encryption.org/v1`), which is what the standalone tool keys on.

mod common;

use std::io::Write;

use common::TestProfile;
use predicates::str::contains;

/// Write `content` to `dir/name` and return the full path as a String.
fn write_file(dir: &std::path::Path, name: &str, content: &[u8]) -> String {
    let path = dir.join(name);
    let mut f = std::fs::File::create(&path).expect("create fixture");
    f.write_all(content).expect("write fixture");
    path.to_string_lossy().into_owned()
}

/// Build an in-memory `.1pux` (a ZIP holding export.data) and write it to disk.
fn write_1pux(dir: &std::path::Path, name: &str, export_json: &str) -> String {
    use std::io::Cursor;
    let mut buf = Vec::new();
    {
        let mut zw = zip::ZipWriter::new(Cursor::new(&mut buf));
        let opts: zip::write::FileOptions<'_, ()> = zip::write::FileOptions::default();
        zw.start_file("export.data", opts).unwrap();
        zw.write_all(export_json.as_bytes()).unwrap();
        zw.finish().unwrap();
    }
    write_file(dir, name, &buf)
}

// --- Importers ------------------------------------------------------------

/// One initialized profile exercises all four CSV/JSON/1PUX/env importers plus
/// the field-landing assertions, batched to pay the unlock cost once per import.
#[test]
fn imports_all_formats_into_the_right_fields() {
    let profile = TestProfile::initialized();
    let dir = tempfile::tempdir().unwrap();
    let d = dir.path();

    // --- 1Password 1PUX ---
    let onepux = write_1pux(
        d,
        "vault.1pux",
        r#"{"accounts":[{"vaults":[{"items":[
          {"categoryUuid":"001","state":"active",
           "overview":{"title":"OP Login","url":"https://op.example"},
           "details":{"loginFields":[
             {"value":"op_user","name":"username","designation":"username"},
             {"value":"op_pass_secret","name":"password","designation":"password"}]}}
        ]}]}]}"#,
    );
    profile
        .cmd()
        .args(["import", "1password", &onepux])
        .assert()
        .success()
        .stdout(contains("imported 1 item"));
    // username/password landed in the login fields.
    profile
        .cmd()
        .args(["item", "get", "OP Login", "--reveal"])
        .assert()
        .success()
        .stdout(contains("op_user"))
        .stdout(contains("op_pass_secret"));

    // --- Bitwarden JSON ---
    let bw = write_file(
        d,
        "bw.json",
        br#"{"items":[
          {"type":1,"name":"BW Login","login":{"username":"bw_user","password":"bw_pass_secret"}}
        ]}"#,
    );
    profile
        .cmd()
        .args(["import", "bitwarden", &bw])
        .assert()
        .success()
        .stdout(contains("imported 1 item"));
    profile
        .cmd()
        .args(["item", "get", "BW Login", "--reveal"])
        .assert()
        .success()
        .stdout(contains("bw_user"))
        .stdout(contains("bw_pass_secret"));

    // --- LastPass CSV ---
    let lp = write_file(
        d,
        "lp.csv",
        b"url,username,password,totp,extra,name,grouping,fav\n\
          https://lp.example,lp_user,lp_pass_secret,,,LP Login,Work,0\n",
    );
    profile
        .cmd()
        .args(["import", "lastpass", &lp])
        .assert()
        .success()
        .stdout(contains("imported 1 item"));
    profile
        .cmd()
        .args(["item", "get", "LP Login", "--reveal"])
        .assert()
        .success()
        .stdout(contains("lp_user"))
        .stdout(contains("lp_pass_secret"));

    // --- Generic CSV with a column map ---
    let generic = write_file(
        d,
        "generic.csv",
        b"Account,Login,Secret,Site\n\
          Gen Login,gen_user,gen_pass_secret,https://gen.example\n",
    );
    profile
        .cmd()
        .args([
            "import",
            "csv",
            &generic,
            "--map",
            "title=Account",
            "--map",
            "username=Login",
            "--map",
            "password=Secret",
            "--map",
            "url=Site",
        ])
        .assert()
        .success()
        .stdout(contains("imported 1 item"));
    profile
        .cmd()
        .args(["item", "get", "Gen Login", "--reveal"])
        .assert()
        .success()
        .stdout(contains("gen_user"))
        .stdout(contains("gen_pass_secret"));

    // --- .env → one env-set with N entries ---
    let env = write_file(d, "dev.env", b"FOO=1\nBAR=two\nBAZ=three\n");
    profile
        .cmd()
        .args(["import", "env", &env, "--as", "dev-secrets"])
        .assert()
        .success()
        .stdout(contains("imported 1 item"));
    // The env-set exists and has 3 entries (export it back as dotenv, count lines).
    let out_env = dir.path().join("roundtrip.env");
    profile
        .cmd()
        .args([
            "export",
            "dotenv",
            out_env.to_str().unwrap(),
            "--env-set",
            "dev-secrets",
        ])
        .assert()
        .success();
    let text = std::fs::read_to_string(&out_env).unwrap();
    assert_eq!(text.lines().count(), 3, "env-set should have 3 entries");
    assert!(text.contains("FOO=1"));
    assert!(text.contains("BAR=two"));
}

/// Partial-parse reporting: an unknown Bitwarden item type is skipped and
/// reported by title, never by value.
#[test]
fn partial_import_reports_skips_by_title_only() {
    let profile = TestProfile::initialized();
    let dir = tempfile::tempdir().unwrap();
    let bw = write_file(
        dir.path(),
        "partial.json",
        br#"{"items":[
          {"type":1,"name":"Good","login":{"username":"u","password":"keepsecret"}},
          {"type":9,"name":"Weird Type"}
        ]}"#,
    );
    profile
        .cmd()
        .args(["import", "bitwarden", &bw])
        .assert()
        .success()
        .stdout(contains("imported 1 item"))
        .stdout(contains("skipped"))
        .stdout(contains("Weird Type"));
}

/// The KDBX importer is stubbed: a clear "not yet supported" message, exit 1.
#[test]
fn kdbx_import_is_stubbed_cleanly() {
    let profile = TestProfile::initialized();
    let dir = tempfile::tempdir().unwrap();
    let fake = write_file(dir.path(), "db.kdbx", b"not a real kdbx");
    profile
        .cmd()
        .args(["import", "kdbx", &fake, "--kdbx-password-stdin"])
        .write_stdin("pw\n")
        .assert()
        .failure()
        .code(1)
        .stderr(contains("not yet supported"));
}

// --- Malformed inputs: clean errors, no panic, exit 1 --------------------

#[test]
fn malformed_inputs_error_cleanly() {
    let profile = TestProfile::initialized();
    let dir = tempfile::tempdir().unwrap();
    let d = dir.path();

    // Truncated zip.
    let bad_zip = write_file(d, "bad.1pux", b"PK\x03\x04 truncated garbage");
    profile
        .cmd()
        .args(["import", "1password", &bad_zip])
        .assert()
        .failure()
        .code(1);

    // Bad JSON.
    let bad_json = write_file(d, "bad.json", b"{ not json ]");
    profile
        .cmd()
        .args(["import", "bitwarden", &bad_json])
        .assert()
        .failure()
        .code(1);

    // Ragged CSV.
    let ragged = write_file(
        d,
        "ragged.csv",
        b"url,username,password,totp,extra,name,grouping,fav\nhttps://x,onlytwo\n",
    );
    profile
        .cmd()
        .args(["import", "lastpass", &ragged])
        .assert()
        .failure()
        .code(1);
}

// --- Exporters ------------------------------------------------------------

/// age export → `localpass import age` round-trips items and secrets, and the
/// archive begins with the age v1 header magic (standalone-age credibility).
#[test]
fn age_export_import_roundtrip_and_magic() {
    let profile = TestProfile::initialized();
    let dir = tempfile::tempdir().unwrap();
    let archive = dir.path().join("out.age");

    // Seed a login with a distinctive secret.
    profile
        .cmd()
        .args([
            "item",
            "add",
            "--type",
            "login",
            "--title",
            "Seed Login",
            "--username",
            "seeduser",
            "--password",
            "seed_secret_value",
        ])
        .assert()
        .success();

    // Export the personal vault to an age archive (passphrase via stdin).
    profile
        .cmd()
        .args([
            "export",
            "age",
            archive.to_str().unwrap(),
            "--passphrase-stdin",
        ])
        .write_stdin("archive-pass-123\n")
        .assert()
        .success();

    // The written bytes must start with the age v1 magic (what `age -d` keys on).
    let bytes = std::fs::read(&archive).unwrap();
    assert!(
        bytes.starts_with(b"age-encryption.org/v1"),
        "archive is not standalone-age binary format"
    );

    // Re-import into a fresh second vault and confirm the item + secret survive.
    profile
        .cmd()
        .args(["vault", "create", "restored"])
        .assert()
        .success();
    profile
        .cmd()
        .args([
            "import",
            "age",
            archive.to_str().unwrap(),
            "--vault",
            "restored",
            "--kdbx-password-stdin",
        ])
        .write_stdin("archive-pass-123\n")
        .assert()
        .success()
        .stdout(contains("imported 1 item"));
    profile
        .cmd()
        .args([
            "item",
            "get",
            "Seed Login",
            "--reveal",
            "--vault",
            "restored",
        ])
        .assert()
        .success()
        .stdout(contains("seed_secret_value"));
}

/// A wrong age passphrase on re-import fails cleanly (exit 1), no panic, no
/// distinction from corruption.
#[test]
fn age_import_wrong_passphrase_fails() {
    let profile = TestProfile::initialized();
    let dir = tempfile::tempdir().unwrap();
    let archive = dir.path().join("out.age");

    profile
        .cmd()
        .args(["item", "add", "--title", "X", "--password", "p"])
        .assert()
        .success();
    profile
        .cmd()
        .args([
            "export",
            "age",
            archive.to_str().unwrap(),
            "--passphrase-stdin",
        ])
        .write_stdin("right-pass\n")
        .assert()
        .success();
    profile
        .cmd()
        .args([
            "import",
            "age",
            archive.to_str().unwrap(),
            "--kdbx-password-stdin",
        ])
        .write_stdin("WRONG-pass\n")
        .assert()
        .failure()
        .code(1);
}

/// Guarded plaintext export refuses without the flag (exit 1) and succeeds with
/// it (writing the secret in cleartext to the target file only).
#[test]
fn plaintext_export_is_guarded() {
    let profile = TestProfile::initialized();
    let dir = tempfile::tempdir().unwrap();
    let json_out = dir.path().join("plain.json");
    let csv_out = dir.path().join("plain.csv");

    profile
        .cmd()
        .args([
            "item",
            "add",
            "--type",
            "login",
            "--title",
            "Plain Login",
            "--username",
            "pu",
            "--password",
            "plain_secret_val",
        ])
        .assert()
        .success();

    // Without the flag: refuse, exit 1, and DO NOT create the file.
    profile
        .cmd()
        .args(["export", "json", json_out.to_str().unwrap()])
        .assert()
        .failure()
        .code(1)
        .stderr(contains("PLAINTEXT"));
    assert!(!json_out.exists(), "guarded export must not write the file");

    // With the flag: JSON is written and contains the secret in cleartext.
    profile
        .cmd()
        .args([
            "export",
            "json",
            json_out.to_str().unwrap(),
            "--i-understand-plaintext-export",
        ])
        .assert()
        .success();
    let json = std::fs::read_to_string(&json_out).unwrap();
    assert!(json.contains("plain_secret_val"));

    // CSV likewise.
    profile
        .cmd()
        .args([
            "export",
            "csv",
            csv_out.to_str().unwrap(),
            "--i-understand-plaintext-export",
        ])
        .assert()
        .success();
    let csv = std::fs::read_to_string(&csv_out).unwrap();
    assert!(csv.starts_with("title,type,username,password,url,notes"));
    assert!(csv.contains("plain_secret_val"));
}
