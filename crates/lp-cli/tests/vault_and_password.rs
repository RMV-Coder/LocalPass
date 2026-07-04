//! Integration tests for `vault create` and `password change`.
//!
//! `password change` in the MVP takes its password(s) from one source
//! (`LOCALPASS_PASSWORD` / stdin / prompt). A scripted run therefore supplies a
//! single value for both old and new; this still exercises the full re-wrap
//! path (a fresh salt + re-derived MUK), and the account must still unlock
//! afterward. Distinct old/new passwords are an interactive-only flow here.

mod common;

use common::TestProfile;
use predicates::prelude::*;
use predicates::str::contains;

/// `vault create` adds a vault that then appears in `vault list`, and items can
/// be added to it via `--vault`.
#[test]
fn vault_create_and_use() {
    let profile = TestProfile::initialized();

    profile
        .cmd()
        .args(["vault", "create", "work"])
        .assert()
        .success()
        .stdout(contains("work"));

    profile
        .cmd()
        .args(["vault", "list"])
        .assert()
        .success()
        .stdout(contains("personal"))
        .stdout(contains("work"));

    // Add an item to the new vault and read it back from there.
    profile
        .cmd()
        .args([
            "item",
            "add",
            "--vault",
            "work",
            "--title",
            "Server",
            "--username",
            "root",
        ])
        .assert()
        .success();
    profile
        .cmd()
        .args(["item", "list", "--vault", "work"])
        .assert()
        .success()
        .stdout(contains("Server"));
    // It is NOT in the default vault.
    profile
        .cmd()
        .args(["item", "list"])
        .assert()
        .success()
        .stdout(contains("Server").not());
}

/// `password change` re-wraps the AccountKey (fresh salt) and the account still
/// unlocks afterward.
#[test]
fn password_change_rewraps_and_still_unlocks() {
    let profile = TestProfile::initialized();

    // Add an item so we can prove data survives the re-wrap.
    profile
        .cmd()
        .args(["item", "add", "--title", "Keep", "--username", "me"])
        .assert()
        .success();

    // Change the password (old == new via the single env source): exercises the
    // full unlock + re-derive + re-wrap path.
    profile
        .cmd()
        .args(["password", "change"])
        .assert()
        .success()
        .stdout(contains("changed"));

    // The account still unlocks and the item is intact.
    profile
        .cmd()
        .args(["item", "get", "Keep", "--field", "username"])
        .assert()
        .success()
        .stdout("me\n");
}
