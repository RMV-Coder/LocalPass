//! End-to-end daemon integration tests driving the real `localpass` binary.
//!
//! Each test uses a fresh tempdir profile and an **isolated endpoint**: the
//! daemon endpoint embeds the username (named pipe `localpass-<username>` on
//! Windows / socket `daemon-<username>.sock` on Unix), so every test overrides
//! `USERNAME`/`USER` with a unique value and concurrent tests never collide on
//! one endpoint. The spawned daemon inherits that env, so client and daemon
//! agree on the same isolated endpoint.
//!
//! Windows note (LESSONS.md): these exercise detached child-process spawning and
//! named-pipe IPC; they are run via `cargo test`, which the harness drives from
//! PowerShell for correct Windows child-process behavior.

use std::path::Path;

use assert_cmd::Command;
use predicates::prelude::*;
use predicates::str::contains;

const TEST_PASSWORD: &str = "correct-horse-battery";

/// A test profile with an isolated per-test daemon endpoint.
struct DaemonProfile {
    dir: tempfile::TempDir,
    endpoint_user: String,
}

impl DaemonProfile {
    /// Create an initialized profile with a unique endpoint username.
    fn initialized(tag: &str) -> Self {
        let dir = tempfile::tempdir().expect("tempdir");
        // Unique per test + pid so parallel runs never share an endpoint.
        let endpoint_user = format!("lpdtest-{tag}-{}", std::process::id());
        let p = Self { dir, endpoint_user };
        p.cmd().arg("init").assert().success();
        p
    }

    fn path(&self) -> &Path {
        self.dir.path()
    }

    /// A `localpass` command wired with the profile, the password env var, and
    /// the isolated endpoint username (so the daemon it spawns uses it too).
    fn cmd(&self) -> Command {
        let mut cmd = Command::cargo_bin("localpass").expect("built binary");
        cmd.env("LOCALPASS_PASSWORD", TEST_PASSWORD)
            .env("USERNAME", &self.endpoint_user) // Windows endpoint name
            .env("USER", &self.endpoint_user) // Unix socket file name
            .arg("--profile")
            .arg(self.path());
        cmd
    }

    /// A command with NO password env var (proves session reuse: if the daemon
    /// isn't holding keys, this would fail with --no-input).
    fn cmd_no_password(&self) -> Command {
        let mut cmd = Command::cargo_bin("localpass").expect("built binary");
        cmd.env_remove("LOCALPASS_PASSWORD")
            .env("USERNAME", &self.endpoint_user)
            .env("USER", &self.endpoint_user)
            .arg("--profile")
            .arg(self.path());
        cmd
    }

    /// Best-effort stop of this profile's daemon (used at test end).
    fn stop_daemon(&self) {
        let _ = self.cmd().args(["daemon", "stop"]).assert();
    }
}

impl Drop for DaemonProfile {
    fn drop(&mut self) {
        // Ensure no orphaned daemon survives the test.
        self.stop_daemon();
    }
}

/// The headline acceptance test: start → unlock → two consecutive
/// `item get --field` calls succeed with NO password and no prompt (proving
/// session reuse) → lock → next call falls back and, with --no-input, exits 2 →
/// stop.
#[test]
fn session_reuse_across_calls_then_lock() {
    let p = DaemonProfile::initialized("reuse");

    // Seed an item (direct path; daemon not started yet).
    p.cmd()
        .args([
            "item",
            "add",
            "--title",
            "GitHub",
            "--username",
            "octocat",
            "--password",
            "s3cr3t",
        ])
        .assert()
        .success();

    // Start the daemon.
    p.cmd()
        .args(["daemon", "start"])
        .assert()
        .success()
        .stdout(contains("daemon"));

    // Unlock via the daemon (password from env; the daemon now holds keys).
    p.cmd().arg("unlock").assert().success();

    // Two consecutive field reads with NO password set and --no-input: these can
    // ONLY succeed if the daemon is serving the unlocked session (a direct
    // unlock would fail with no password under --no-input).
    p.cmd_no_password()
        .args(["--no-input", "item", "get", "GitHub", "--field", "password"])
        .assert()
        .success()
        .stdout("s3cr3t\n");
    p.cmd_no_password()
        .args(["--no-input", "item", "get", "GitHub", "--field", "username"])
        .assert()
        .success()
        .stdout("octocat\n");

    // Lock the daemon.
    p.cmd().arg("lock").assert().success();

    // Now a no-password call under --no-input must fail with the auth/usage
    // exit code (the daemon is locked, so it falls back to a direct unlock,
    // which has no password → exit 1 usage under --no-input).
    p.cmd_no_password()
        .args(["--no-input", "item", "get", "GitHub", "--field", "password"])
        .assert()
        .failure()
        .code(predicate::in_iter([1, 2]));

    // Stop the daemon.
    p.cmd().args(["daemon", "stop"]).assert().success();
}

/// `daemon status` reflects locked vs unlocked, and a wrong-password unlock
/// leaves the daemon locked.
#[test]
fn status_and_wrong_password() {
    let p = DaemonProfile::initialized("status");

    p.cmd().args(["daemon", "start"]).assert().success();

    // Before unlock: status shows locked.
    p.cmd()
        .args(["daemon", "status"])
        .assert()
        .success()
        .stdout(contains("locked"));

    // Wrong password: unlock fails (auth exit) and leaves it locked.
    p.cmd()
        .env("LOCALPASS_PASSWORD", "definitely-not-the-password")
        .arg("unlock")
        .assert()
        .failure()
        .code(2);
    p.cmd()
        .args(["daemon", "status"])
        .assert()
        .success()
        .stdout(contains("locked").and(contains("unlocked").not()));

    // Correct unlock: status shows unlocked.
    p.cmd().arg("unlock").assert().success();
    p.cmd()
        .args(["daemon", "status"])
        .assert()
        .success()
        .stdout(contains("unlocked"));

    p.cmd().args(["daemon", "stop"]).assert().success();
}

/// Auto-lock with a short timeout actually locks after the idle window.
///
/// The window is 4s (not 1s): each CLI invocation is a fresh process whose
/// spawn + connect overhead can exceed a second on a cold machine, and a
/// 1-second window let the daemon lock before the first status check could
/// land (observed post-reboot). 4s gives the check ample headroom while the
/// post-window sleep (6s) still stays well past it.
#[test]
fn autolock_locks_after_idle() {
    let p = DaemonProfile::initialized("autolock");

    // Start with a 4-second idle auto-lock.
    p.cmd()
        .args(["daemon", "start", "--autolock", "4"])
        .assert()
        .success();
    p.cmd().arg("unlock").assert().success();

    // Immediately unlocked (this status itself resets the idle timer).
    p.cmd()
        .args(["daemon", "status"])
        .assert()
        .success()
        .stdout(contains("unlocked"));

    // Wait past the idle window, then it must be locked.
    std::thread::sleep(std::time::Duration::from_secs(6));
    p.cmd()
        .args(["daemon", "status"])
        .assert()
        .success()
        .stdout(contains("locked").and(contains("unlocked").not()));

    p.cmd().args(["daemon", "stop"]).assert().success();
}

/// `--no-daemon` bypasses a running (unlocked) daemon: with no password and
/// --no-input it must fail (proving it did NOT use the daemon's session).
#[test]
fn no_daemon_flag_bypasses_running_daemon() {
    let p = DaemonProfile::initialized("nodaemon");

    p.cmd()
        .args([
            "item",
            "add",
            "--title",
            "Site",
            "--username",
            "u",
            "--password",
            "pw",
        ])
        .assert()
        .success();
    p.cmd().args(["daemon", "start"]).assert().success();
    p.cmd().arg("unlock").assert().success();

    // With the daemon unlocked, a normal no-password call succeeds (proxied).
    p.cmd_no_password()
        .args(["--no-input", "item", "get", "Site", "--field", "password"])
        .assert()
        .success()
        .stdout("pw\n");

    // But --no-daemon forces the direct path, which has no password → fails.
    p.cmd_no_password()
        .args([
            "--no-daemon",
            "--no-input",
            "item",
            "get",
            "Site",
            "--field",
            "password",
        ])
        .assert()
        .failure()
        .code(predicate::in_iter([1, 2]));

    p.cmd().args(["daemon", "stop"]).assert().success();
}

/// A second `daemon start` while one is already running is a friendly no-op
/// (exit 0), and `daemon stop` cleanly removes the endpoint.
#[test]
fn second_start_is_noop_and_stop_cleans_up() {
    let p = DaemonProfile::initialized("noop");

    p.cmd()
        .args(["daemon", "start"])
        .assert()
        .success()
        .stdout(contains("started"));

    // Second start: friendly no-op.
    p.cmd()
        .args(["daemon", "start"])
        .assert()
        .success()
        .stdout(contains("already running"));

    // Stop it.
    p.cmd()
        .args(["daemon", "stop"])
        .assert()
        .success()
        .stdout(contains("stopped"));

    // After stop, status shows not running, and a second stop is a no-op.
    p.cmd()
        .args(["daemon", "status"])
        .assert()
        .success()
        .stdout(contains("not running"));
    p.cmd()
        .args(["daemon", "stop"])
        .assert()
        .success()
        .stdout(contains("no daemon"));
}

/// Regression guard: with NO daemon ever started, every command behaves exactly
/// as before (direct unlock). This is the "daemon absent" row of the matrix.
#[test]
fn daemon_absent_behaves_as_before() {
    let p = DaemonProfile::initialized("absent");

    // A normal add/get round-trip with the password env var works with no daemon.
    p.cmd()
        .args([
            "item", "add", "--title", "Note", "--type", "note", "--note", "hi",
        ])
        .assert()
        .success();
    p.cmd()
        .args(["item", "get", "Note"])
        .assert()
        .success()
        .stdout(contains("hi"));

    // status shows the no-daemon lock state.
    p.cmd()
        .args(["status"])
        .assert()
        .success()
        .stdout(contains("no daemon"));

    // No daemon was started, so nothing to stop.
    p.cmd()
        .args(["daemon", "status"])
        .assert()
        .success()
        .stdout(contains("not running"));
}

/// `localpass totp` works through the daemon with NO password (proving the
/// proxied path), the printed code matches `lp_crypto` at the same second, and
/// the base32 secret never appears on stdout/stderr (it stays inside the daemon).
#[test]
fn totp_proxied_through_daemon_without_password() {
    // The RFC 6238 SHA-1 seed "12345678901234567890" in base32, and raw.
    const RFC_SEED_B32: &str = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
    const RFC_SEED: &[u8] = b"12345678901234567890";

    let p = DaemonProfile::initialized("totp");

    // Seed a totp item via the otpauth URI (direct path; daemon not up yet).
    p.cmd()
        .args([
            "item",
            "add",
            "--type",
            "totp",
            "--title",
            "RFC",
            "--otpauth-uri",
        ])
        .arg(format!(
            "otpauth://totp/x?secret={RFC_SEED_B32}&digits=8&period=30"
        ))
        .assert()
        .success();

    // Start + unlock the daemon.
    p.cmd().args(["daemon", "start"]).assert().success();
    p.cmd().arg("unlock").assert().success();

    // `localpass totp` with NO password under --no-input: only the daemon's held
    // session makes this succeed. Retry once on a period-boundary straddle.
    let mut matched = false;
    for _ in 0..3 {
        let before = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let out = p
            .cmd_no_password()
            .args(["--no-input", "totp", "RFC"])
            .output()
            .expect("run totp");
        let after = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        assert!(out.status.success(), "proxied totp exited non-zero");

        let code = String::from_utf8_lossy(&out.stdout).trim().to_string();
        let stderr = String::from_utf8_lossy(&out.stderr);
        // The secret must never appear anywhere in the output.
        assert!(!code.contains(RFC_SEED_B32));
        assert!(!stderr.contains(RFC_SEED_B32));
        assert_eq!(code.len(), 8);

        if before / 30 == after / 30 {
            let expected =
                lp_crypto::totp::code(RFC_SEED, lp_crypto::TotpAlgo::Sha1, 8, 30, before).unwrap();
            assert_eq!(code, expected, "proxied code matches lp_crypto at {before}");
            matched = true;
            break;
        }
    }
    assert!(matched, "could not land inside one period after retries");

    p.cmd().args(["daemon", "stop"]).assert().success();
}

/// Sanity that the built daemon binary exists next to the CLI (the sibling the
/// launcher resolves). Guards against a packaging regression.
#[test]
fn daemon_binary_is_built_alongside_cli() {
    let cli = assert_cmd::cargo::cargo_bin("localpass");
    let dir = cli.parent().expect("bin dir");
    #[cfg(windows)]
    let daemon = dir.join("localpass-daemon.exe");
    #[cfg(not(windows))]
    let daemon = dir.join("localpass-daemon");
    assert!(
        daemon.exists(),
        "expected the daemon binary at {}",
        daemon.display()
    );
}
