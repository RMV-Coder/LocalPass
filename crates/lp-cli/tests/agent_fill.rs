//! CLI-level tests for `localpass agent-fill` (`docs/specs/agent-fill.md` §7).
//!
//! The window itself lives in the daemon, and its behaviour is covered at that
//! layer (`lp-daemon/tests/agent_fill.rs`). What is checked here is the surface
//! a user actually touches: that arming is possible **without the GUI**, that it
//! refuses to arm without naming items, and that the no-daemon case explains
//! itself rather than pretending to have armed something.
//!
//! Every test runs `--no-daemon` so it never touches a stray developer daemon.

mod common;

use common::TestProfile;

#[test]
fn agent_fill_status_reports_off_without_a_daemon() {
    let profile = TestProfile::initialized();
    let out = profile
        .cmd()
        .args(["--no-daemon", "agent-fill", "status", "--json"])
        .assert()
        .success();
    let stdout = String::from_utf8(out.get_output().stdout.clone()).unwrap();
    let v: serde_json::Value = serde_json::from_str(&stdout).expect("json");
    assert_eq!(v["daemon"], serde_json::json!(false));
    assert_eq!(v["agent_fill"], serde_json::json!(false));
    assert_eq!(v["remaining_secs"], serde_json::Value::Null);
}

#[test]
fn agent_fill_status_explains_itself_in_human_form() {
    let profile = TestProfile::initialized();
    profile
        .cmd()
        .args(["--no-daemon", "agent-fill", "status"])
        .assert()
        .success()
        .stdout(predicates::str::contains("daemon-session control"));
}

/// There is deliberately no "arm the whole vault": arming names its items, and
/// clap enforces that before the request is ever built.
#[test]
fn arming_without_an_item_is_a_usage_error() {
    let profile = TestProfile::initialized();
    profile
        .cmd()
        .args(["--no-daemon", "agent-fill", "arm"])
        .assert()
        .failure()
        .stderr(predicates::str::contains("--item"));
}

/// The help text has to say what the window is and that it lapses, because this
/// command IS the consent gesture — a user reading only `--help` should
/// understand what they are agreeing to.
#[test]
fn the_help_explains_the_window_and_its_scope() {
    let profile = TestProfile::initialized();
    let out = profile
        .cmd()
        .args(["agent-fill", "--help"])
        .assert()
        .success();
    let stdout = String::from_utf8(out.get_output().stdout.clone()).unwrap();
    for expected in ["3-minute", "PER-ITEM", "lapses", "notification"] {
        assert!(stdout.contains(expected), "help must mention {expected:?}");
    }
}

/// Arming with no daemon does not claim to have armed anything.
#[test]
fn arming_without_a_daemon_says_so() {
    let profile = TestProfile::initialized();
    profile
        .cmd()
        .args(["--no-daemon", "agent-fill", "arm", "--item", "whatever"])
        .assert()
        .success()
        .stdout(predicates::str::contains("nothing to arm"));
}
