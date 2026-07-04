//! End-to-end CLI integration tests for `localpass totp` and the
//! `item add --type totp --otpauth-uri` import path.
//!
//! The correctness check does NOT hard-code an expected code (the code depends
//! on wall-clock time, which is not frozen). Instead it computes the expected
//! code with `lp_crypto::totp` at the same unix second and compares — retrying
//! once if we straddled a 30-second period boundary between the two reads
//! (documented boundary-race handling). The RFC 6238 *vectors* themselves are
//! pinned in `lp-crypto`'s own unit tests; here we only prove the CLI wiring
//! (item → decode → compute → print) agrees with the crypto core.

mod common;

use common::TestProfile;
use predicates::prelude::*;
use predicates::str::contains;

/// The RFC 6238 SHA-1 seed "12345678901234567890" in base32 (no padding).
const RFC_SEED_B32: &str = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
/// The same seed as raw bytes, for the independent `lp_crypto` computation.
const RFC_SEED: &[u8] = b"12345678901234567890";

/// Current unix time in whole seconds.
fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

/// `item add --type totp --otpauth-uri` imports every field; the secret is
/// masked in `item get`; `localpass totp` prints a code that matches an
/// independent `lp_crypto` computation at the same second; `--json` carries the
/// metadata.
#[test]
fn totp_import_and_code_matches_crypto_core() {
    let profile = TestProfile::initialized();

    // Import via an otpauth URI (8 digits, period 30, SHA1 default).
    let uri = format!(
        "otpauth://totp/ACME%20Co:alice@acme.com?secret={RFC_SEED_B32}&issuer=ACME%20Co&digits=8&period=30"
    );
    profile
        .cmd()
        .args([
            "item",
            "add",
            "--type",
            "totp",
            "--title",
            "RFC",
            "--otpauth-uri",
        ])
        .arg(&uri)
        .assert()
        .success();

    // The imported metadata round-trips, and the secret is masked (never shown).
    profile
        .cmd()
        .args(["item", "get", "RFC"])
        .assert()
        .success()
        .stdout(contains("SHA1"))
        .stdout(contains("ACME Co"))
        .stdout(contains("alice@acme.com"))
        .stdout(contains("digits: 8"))
        .stdout(contains("period: 30"))
        // The base32 secret must be masked, never printed.
        .stdout(contains(RFC_SEED_B32).not())
        .stdout(contains("••••••"));

    // `localpass totp` prints exactly the code to stdout (+ a stderr hint). We
    // compare against lp_crypto at the same unix second, retrying once on a
    // period-boundary straddle (the CLI process and this thread can land in
    // different windows).
    let mut matched = false;
    for _ in 0..3 {
        let before = now_secs();
        let out = profile
            .cmd()
            .args(["totp", "RFC"])
            .output()
            .expect("run totp");
        let after = now_secs();
        assert!(out.status.success(), "totp exited non-zero");

        let printed = String::from_utf8_lossy(&out.stdout).trim().to_string();
        // stdout is ONLY the code (the "expires in Ns" hint goes to stderr).
        assert_eq!(printed.len(), 8, "code should be 8 digits, got {printed:?}");
        assert!(printed.chars().all(|c| c.is_ascii_digit()));
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(stderr.contains("expires in"), "hint on stderr: {stderr}");

        // Only assert equality when the CLI ran entirely inside one 30s window.
        if before / 30 == after / 30 {
            let expected =
                lp_crypto::totp::code(RFC_SEED, lp_crypto::TotpAlgo::Sha1, 8, 30, before).unwrap();
            assert_eq!(
                printed, expected,
                "CLI code must match lp_crypto at second {before}"
            );
            matched = true;
            break;
        }
        // Straddled a boundary — retry.
    }
    assert!(
        matched,
        "could not land inside a single period after retries"
    );

    // --json carries the code + metadata as a stable object.
    let out = profile
        .cmd()
        .args(["totp", "RFC", "--json"])
        .output()
        .expect("run totp --json");
    assert!(out.status.success());
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).expect("totp --json is JSON");
    assert_eq!(v["digits"], 8);
    assert_eq!(v["period"], 30);
    assert_eq!(v["algo"], "SHA1");
    assert!(v["code"].as_str().unwrap().len() == 8);
    let rem = v["seconds_remaining"].as_u64().unwrap();
    assert!((1..=30).contains(&rem));
}

/// `localpass totp` on a non-totp item is a clear usage error (exit 1), not an
/// auth or internal failure.
#[test]
fn totp_on_wrong_type_is_usage_error() {
    let profile = TestProfile::initialized();

    // A plain login item.
    profile
        .cmd()
        .args([
            "item",
            "add",
            "--title",
            "GitHub",
            "--username",
            "octocat",
            "--password",
            "pw",
        ])
        .assert()
        .success();

    profile
        .cmd()
        .args(["totp", "GitHub"])
        .assert()
        .failure()
        .code(1)
        .stderr(contains("not a totp item"));
}

/// `item add --otpauth-uri` rejects an `otpauth://hotp` URI with a clear message
/// (exit 1), and rejects `--otpauth-uri` on a non-totp `--type`.
#[test]
fn otpauth_hotp_and_type_mismatch_rejected() {
    let profile = TestProfile::initialized();

    // hotp is rejected.
    profile
        .cmd()
        .args([
            "item",
            "add",
            "--type",
            "totp",
            "--title",
            "H",
            "--otpauth-uri",
        ])
        .arg(format!("otpauth://hotp/x?secret={RFC_SEED_B32}&counter=0"))
        .assert()
        .failure()
        .code(1)
        .stderr(contains("hotp").or(contains("HOTP")));

    // --otpauth-uri on a non-totp type is a usage error.
    profile
        .cmd()
        .args([
            "item",
            "add",
            "--type",
            "login",
            "--title",
            "L",
            "--otpauth-uri",
        ])
        .arg(format!("otpauth://totp/x?secret={RFC_SEED_B32}"))
        .assert()
        .failure()
        .code(1)
        .stderr(contains("totp"));
}

/// A missing totp item is a user error (exit 1).
#[test]
fn totp_missing_item_is_user_error() {
    let profile = TestProfile::initialized();
    profile
        .cmd()
        .args(["totp", "Nonexistent"])
        .assert()
        .failure()
        .code(1);
}
