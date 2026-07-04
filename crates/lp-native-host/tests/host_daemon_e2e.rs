//! End-to-end integration test: drive the real `localpass-native-host` binary
//! over stdio against a real daemon.
//!
//! The flow mirrors what a browser extension does:
//!
//! 1. Start a daemon (via the `localpass` CLI) on an isolated tempdir profile and
//!    an isolated per-test endpoint (unique `USERNAME`/`USER`), and unlock it.
//! 2. Seed a `login` item with url `https://example.com`.
//! 3. Spawn `localpass-native-host` with the same isolated endpoint env so it
//!    connects to the *test* daemon, and write framed native-messaging requests
//!    to its stdin, reading framed responses from its stdout.
//! 4. Assert: `ping`→pong; `status`→unlocked+vaults; `credentials_for` for the
//!    matching origin returns the candidate and NEVER a password; `fill` for the
//!    matching origin returns the password; `fill`/`credentials_for` for a
//!    cross-origin lookalike are refused / empty; a locked daemon yields locked.
//!
//! Windows note (LESSONS.md): this exercises detached child-process spawning and
//! named-pipe IPC; `cargo test` is driven from PowerShell by the harness for
//! correct Windows child-process behavior.

use std::io::{Read, Write};
use std::path::Path;
use std::process::{Child, Command, Stdio};

use assert_cmd::cargo::cargo_bin;

const TEST_PASSWORD: &str = "correct-horse-battery";

/// An isolated test profile + daemon endpoint, driven through the `localpass`
/// CLI (to control the daemon) and the `localpass-native-host` binary.
struct Fixture {
    dir: tempfile::TempDir,
    endpoint_user: String,
}

impl Fixture {
    fn new(tag: &str) -> Self {
        let dir = tempfile::tempdir().expect("tempdir");
        let endpoint_user = format!("lpnhtest-{tag}-{}", std::process::id());
        let f = Self { dir, endpoint_user };
        f.cli(&["init"]).assert_success();
        f
    }

    fn path(&self) -> &Path {
        self.dir.path()
    }

    /// A `localpass` CLI command wired with the profile, password, and the
    /// isolated endpoint username.
    fn cli(&self, args: &[&str]) -> CliCmd {
        let mut cmd = Command::new(cargo_bin("localpass"));
        cmd.env("LOCALPASS_PASSWORD", TEST_PASSWORD)
            .env("USERNAME", &self.endpoint_user)
            .env("USER", &self.endpoint_user)
            .arg("--profile")
            .arg(self.path());
        for a in args {
            cmd.arg(a);
        }
        CliCmd(cmd)
    }

    /// Spawn the native-messaging host with the isolated endpoint env so it
    /// connects to THIS test's daemon. Returns a handle to drive over stdio.
    fn spawn_host(&self) -> HostProc {
        let mut cmd = Command::new(cargo_bin("localpass-native-host"));
        cmd.env("USERNAME", &self.endpoint_user)
            .env("USER", &self.endpoint_user)
            .env("LOCALPASS_PROFILE", self.path())
            .arg("--quiet")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null());
        let child = cmd.spawn().expect("spawn native host");
        HostProc { child }
    }

    fn stop_daemon(&self) {
        let _ = self.cli(&["daemon", "stop"]).0.output();
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        self.stop_daemon();
    }
}

/// A thin wrapper to run a CLI command and assert success/failure.
struct CliCmd(Command);

impl CliCmd {
    fn assert_success(mut self) {
        let out = self.0.output().expect("run localpass");
        assert!(
            out.status.success(),
            "localpass failed: status={:?}\nstdout={}\nstderr={}",
            out.status.code(),
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
    }
}

/// A running native-messaging host process, driven over stdio with native
/// framing (native-endian length prefix).
struct HostProc {
    child: Child,
}

impl HostProc {
    /// Send a JSON request framed the way the browser does, then read one framed
    /// JSON response.
    fn round_trip(&mut self, request: &serde_json::Value) -> serde_json::Value {
        let body = serde_json::to_vec(request).unwrap();
        let stdin = self.child.stdin.as_mut().expect("host stdin");
        let len = u32::try_from(body.len()).unwrap();
        stdin.write_all(&len.to_ne_bytes()).unwrap();
        stdin.write_all(&body).unwrap();
        stdin.flush().unwrap();

        let stdout = self.child.stdout.as_mut().expect("host stdout");
        let mut len_buf = [0u8; 4];
        read_exact(stdout, &mut len_buf).expect("read response length");
        let rlen = u32::from_ne_bytes(len_buf) as usize;
        let mut rbody = vec![0u8; rlen];
        read_exact(stdout, &mut rbody).expect("read response body");
        serde_json::from_slice(&rbody).expect("parse response json")
    }

    /// Close stdin (EOF) so the host loop exits, then reap the process.
    fn finish(mut self) {
        // Dropping stdin sends EOF; take it to drop early.
        drop(self.child.stdin.take());
        let _ = self.child.wait();
    }
}

/// Read exactly `buf.len()` bytes, looping over partial reads.
fn read_exact<R: Read>(r: &mut R, buf: &mut [u8]) -> std::io::Result<()> {
    let mut read = 0;
    while read < buf.len() {
        match r.read(&mut buf[read..])? {
            0 => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "eof mid-frame",
                ));
            }
            n => read += n,
        }
    }
    Ok(())
}

/// The headline acceptance test.
#[test]
fn native_host_fill_scoped_flow() {
    let f = Fixture::new("flow");

    // Seed a login item with url https://example.com (direct path; daemon down).
    f.cli(&[
        "item",
        "add",
        "--title",
        "GitHub",
        "--username",
        "octocat",
        "--password",
        "s3cr3t-pw",
        "--url",
        "https://example.com/login",
    ])
    .assert_success();

    // Start + unlock the daemon.
    f.cli(&["daemon", "start"]).assert_success();
    f.cli(&["unlock"]).assert_success();

    let mut host = f.spawn_host();

    // 1. ping -> pong
    let pong = host.round_trip(&serde_json::json!({"v":1,"type":"ping"}));
    assert_eq!(pong["type"], "pong");

    // 2. status -> unlocked, at least one vault, available
    let status = host.round_trip(&serde_json::json!({"v":1,"type":"status"}));
    assert_eq!(status["type"], "status");
    assert_eq!(status["locked"], false);
    assert_eq!(status["available"], true);
    assert!(status["vaults"].as_u64().unwrap() >= 1);

    // 3. credentials_for the matching origin -> candidate, NO password anywhere.
    let creds = host.round_trip(&serde_json::json!({
        "v":1,"type":"credentials_for","origin":"https://www.example.com/login","kind":"login"
    }));
    assert_eq!(creds["type"], "credentials");
    let candidates = creds["candidates"].as_array().unwrap();
    assert_eq!(candidates.len(), 1, "expected one matching candidate");
    let cand = &candidates[0];
    assert_eq!(cand["title"], "GitHub");
    assert_eq!(cand["username"], "octocat");
    let item_id = cand["item_id"].as_str().unwrap().to_string();
    // The whole credentials response must never contain the password.
    let creds_str = serde_json::to_string(&creds).unwrap();
    assert!(
        !creds_str.contains("s3cr3t-pw"),
        "credentials_for leaked a password: {creds_str}"
    );
    assert!(!creds_str.contains("password"));

    // 4. fill the matching origin -> username + password.
    let fill = host.round_trip(&serde_json::json!({
        "v":1,"type":"fill","item_id":item_id,"origin":"https://www.example.com/login"
    }));
    assert_eq!(fill["type"], "fill");
    assert_eq!(fill["username"], "octocat");
    assert_eq!(fill["password"], "s3cr3t-pw");

    // 5. fill a cross-origin lookalike -> REFUSED (error), never the secret (T7).
    let bad = host.round_trip(&serde_json::json!({
        "v":1,"type":"fill","item_id":item_id,"origin":"https://example.com.evil.com/"
    }));
    assert_eq!(bad["type"], "error", "cross-origin fill must be refused");
    let bad_str = serde_json::to_string(&bad).unwrap();
    assert!(
        !bad_str.contains("s3cr3t-pw"),
        "refused fill leaked the secret: {bad_str}"
    );

    // 6. credentials_for a lookalike -> empty (no candidate).
    let none = host.round_trip(&serde_json::json!({
        "v":1,"type":"credentials_for","origin":"https://evil-example.com/","kind":"login"
    }));
    assert_eq!(none["type"], "credentials");
    assert_eq!(none["candidates"].as_array().unwrap().len(), 0);

    // 7. an unsupported request type -> unsupported.
    let unsup = host.round_trip(&serde_json::json!({"v":1,"type":"exfiltrate"}));
    assert_eq!(unsup["type"], "error");
    assert_eq!(unsup["error"], "unsupported");

    host.finish();
    f.cli(&["daemon", "stop"]).assert_success();
}

/// A locked daemon yields locked responses for credentials_for/fill, and status
/// reports locked — the host never hangs and never reveals a secret.
#[test]
fn locked_daemon_yields_locked() {
    let f = Fixture::new("locked");

    f.cli(&[
        "item",
        "add",
        "--title",
        "Site",
        "--username",
        "u",
        "--password",
        "pw-secret",
        "--url",
        "https://example.com",
    ])
    .assert_success();

    // Start the daemon but do NOT unlock (it stays locked).
    f.cli(&["daemon", "start"]).assert_success();

    let mut host = f.spawn_host();

    // status -> locked, available.
    let status = host.round_trip(&serde_json::json!({"v":1,"type":"status"}));
    assert_eq!(status["locked"], true);
    assert_eq!(status["available"], true);

    // credentials_for -> locked (the extension should prompt the user to unlock).
    let creds = host.round_trip(&serde_json::json!({
        "v":1,"type":"credentials_for","origin":"https://example.com","kind":"login"
    }));
    assert_eq!(creds["type"], "locked");

    // fill -> locked, never the secret.
    let fill = host.round_trip(&serde_json::json!({
        "v":1,"type":"fill","item_id":"whatever","origin":"https://example.com"
    }));
    assert_eq!(fill["type"], "locked");
    let fill_str = serde_json::to_string(&fill).unwrap();
    assert!(!fill_str.contains("pw-secret"));

    host.finish();
    f.cli(&["daemon", "stop"]).assert_success();
}

/// With NO daemon running at all, the host still answers immediately (never
/// hangs): ping works, status reports unavailable, credentials_for reports
/// locked.
#[test]
fn no_daemon_does_not_hang() {
    let f = Fixture::new("nodaemon");

    let mut host = f.spawn_host();

    let pong = host.round_trip(&serde_json::json!({"v":1,"type":"ping"}));
    assert_eq!(pong["type"], "pong");

    let status = host.round_trip(&serde_json::json!({"v":1,"type":"status"}));
    assert_eq!(status["type"], "status");
    assert_eq!(status["available"], false);
    assert_eq!(status["locked"], true);

    let creds = host.round_trip(&serde_json::json!({
        "v":1,"type":"credentials_for","origin":"https://example.com","kind":"login"
    }));
    assert_eq!(creds["type"], "locked");

    host.finish();
}

/// The host binary is built alongside the CLI + daemon (packaging regression
/// guard — an installer lays all three side by side).
#[test]
fn host_binary_is_built() {
    let host = cargo_bin("localpass-native-host");
    assert!(host.exists(), "expected host binary at {}", host.display());
}
