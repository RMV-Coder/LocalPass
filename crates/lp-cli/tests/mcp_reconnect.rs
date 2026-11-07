//! `localpass mcp` against a real daemon, launched the way an agent host launches
//! it: no password anywhere, and stdin a pipe (`mcp-server.md` §3).
//!
//! The server must start while the vault is locked, say so from its tools rather
//! than exit, and pick up by itself after an unlock, a lock, or a daemon restart.
//! The daemon records the connection and its end for the desktop app to show.
//!
//! `daemon start` launches the `localpass-daemon` built beside the test binary, so
//! run this after building the workspace (`cargo test --workspace` does), or it
//! exercises a stale daemon.

use std::io::{BufRead, BufReader, Write};
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};
use std::time::{Duration, Instant};

use assert_cmd::cargo::CommandCargoExt;
use serde_json::{Value, json};

const TEST_PASSWORD: &str = "correct-horse-battery";

/// A profile with its own daemon endpoint, so a developer's daemon is untouched.
struct Fixture {
    dir: tempfile::TempDir,
    endpoint: String,
}

impl Fixture {
    fn new(tag: &str) -> Self {
        let fixture = Self {
            dir: tempfile::tempdir().expect("tempdir"),
            endpoint: format!("lpmcp-{tag}-{}", std::process::id()),
        };
        fixture.cli(&["--no-daemon", "init"]);
        fixture
    }

    fn command(&self) -> Command {
        let mut cmd = Command::cargo_bin("localpass").expect("built binary");
        cmd.env("USERNAME", &self.endpoint)
            .env("USER", &self.endpoint)
            .arg("--profile")
            .arg(self.dir.path());
        cmd
    }

    /// Run a CLI command that may unlock, and require it to succeed.
    fn cli(&self, args: &[&str]) -> String {
        let out = self
            .command()
            .env("LOCALPASS_PASSWORD", TEST_PASSWORD)
            .args(args)
            .output()
            .expect("run localpass");
        assert!(
            out.status.success(),
            "localpass {args:?} failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        String::from_utf8_lossy(&out.stdout).into_owned()
    }

    fn start_daemon(&self) {
        self.cli(&["daemon", "start"]);
    }

    fn stop_daemon(&self) {
        self.cli(&["daemon", "stop"]);
    }

    /// The agent-activity records, oldest first, as `(kind, detail)`.
    fn agent_records(&self) -> Vec<(String, String)> {
        let out = self.cli(&["--no-daemon", "audit", "--json"]);
        let parsed: Value = serde_json::from_str(&out).expect("audit --json");
        let records = parsed
            .as_array()
            .or_else(|| parsed["records"].as_array())
            .expect("an array of records");
        let mut seen: Vec<(u64, String, String)> = records
            .iter()
            .filter(|r| {
                r["kind"]
                    .as_str()
                    .is_some_and(|kind| kind.starts_with("agent_"))
                    && !r["kind"]
                        .as_str()
                        .is_some_and(|kind| kind.starts_with("agent_fill"))
            })
            .map(|r| {
                (
                    r["seq"].as_u64().unwrap_or(0),
                    r["kind"].as_str().unwrap_or("").to_string(),
                    r["detail"].as_str().unwrap_or("").to_string(),
                )
            })
            .collect();
        seen.sort();
        seen.into_iter().map(|(_, k, d)| (k, d)).collect()
    }

    /// Wait until the agent records contain `(kind, detail)`.
    fn wait_for_record(&self, kind: &str, detail: &str) {
        let deadline = Instant::now() + Duration::from_secs(15);
        loop {
            let records = self.agent_records();
            if records.iter().any(|(k, d)| k == kind && d == detail) {
                return;
            }
            assert!(
                Instant::now() < deadline,
                "no {kind} record with detail {detail:?}; have {records:?}"
            );
            std::thread::sleep(Duration::from_millis(100));
        }
    }
}

/// A running `localpass mcp`, started with no password source at all.
struct Server {
    child: Child,
    stdin: Option<ChildStdin>,
    stdout: BufReader<ChildStdout>,
    next_id: u64,
}

impl Server {
    fn spawn(fixture: &Fixture) -> Self {
        let mut child = fixture
            .command()
            .env_remove("LOCALPASS_PASSWORD")
            .arg("mcp")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn localpass mcp");
        let stdin = child.stdin.take();
        let stdout = BufReader::new(child.stdout.take().expect("stdout"));
        Self {
            child,
            stdin,
            stdout,
            next_id: 0,
        }
    }

    fn request(&mut self, method: &str, params: Value) -> Value {
        self.next_id += 1;
        let frame = json!({
            "jsonrpc": "2.0", "id": self.next_id, "method": method, "params": params,
        });
        let stdin = self.stdin.as_mut().expect("stdin open");
        writeln!(stdin, "{frame}").expect("write frame");
        stdin.flush().expect("flush");
        let mut line = String::new();
        self.stdout.read_line(&mut line).expect("read frame");
        assert!(!line.is_empty(), "the server exited instead of answering");
        serde_json::from_str(&line).expect("JSON frame")
    }

    /// Call a tool, returning `(is_error, text)`.
    fn tool(&mut self, name: &str) -> (bool, String) {
        let response = self.request("tools/call", json!({ "name": name, "arguments": {} }));
        let result = &response["result"];
        (
            result["isError"].as_bool().unwrap_or(false),
            result["content"][0]["text"]
                .as_str()
                .unwrap_or("")
                .to_string(),
        )
    }

    /// Close stdin, as a host does, and wait for the process to exit.
    fn close(&mut self) {
        self.stdin = None;
        let deadline = Instant::now() + Duration::from_secs(15);
        while self.child.try_wait().expect("try_wait").is_none() {
            assert!(Instant::now() < deadline, "the server did not exit");
            std::thread::sleep(Duration::from_millis(50));
        }
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Stops the fixture's daemon even when an assertion fails.
struct DaemonGuard<'a>(&'a Fixture);

impl Drop for DaemonGuard<'_> {
    fn drop(&mut self) {
        let _ = self
            .0
            .command()
            .env("LOCALPASS_PASSWORD", TEST_PASSWORD)
            .args(["daemon", "stop"])
            .output();
    }
}

#[test]
fn starts_locked_and_recovers_from_a_lock_and_a_daemon_restart() {
    let fixture = Fixture::new("recover");
    let _daemon = DaemonGuard(&fixture);

    // No daemon, no password: the host still gets a working server.
    let mut server = Server::spawn(&fixture);
    let init = server.request("initialize", json!({ "protocolVersion": "2025-06-18" }));
    assert_eq!(init["result"]["serverInfo"]["name"], json!("localpass"));
    let (is_error, text) = server.tool("list_vaults");
    assert!(is_error, "{text}");
    assert!(text.contains("not running"), "{text}");

    // The daemon appears, still locked.
    fixture.start_daemon();
    let (is_error, text) = server.tool("list_vaults");
    assert!(is_error, "{text}");
    assert!(text.contains("locked"), "{text}");
    assert!(text.contains("does not need to be restarted"), "{text}");

    // A person unlocks: the same server now works, with no restart.
    fixture.cli(&["unlock"]);
    let (is_error, text) = server.tool("list_vaults");
    assert!(!is_error, "{text}");
    assert!(text.contains("personal"), "{text}");

    // Locked again (the window closing does this), then unlocked again.
    fixture.cli(&["lock"]);
    let (is_error, text) = server.tool("list_vaults");
    assert!(is_error && text.contains("locked"), "{text}");
    fixture.cli(&["unlock"]);
    let (is_error, text) = server.tool("list_vaults");
    assert!(!is_error, "{text}");

    // The daemon restarts underneath the held connection.
    fixture.stop_daemon();
    fixture.wait_for_record("agent_disconnected", "service_stopped");
    let (is_error, text) = server.tool("list_vaults");
    assert!(is_error && text.contains("not running"), "{text}");
    fixture.start_daemon();
    fixture.cli(&["unlock"]);
    let (is_error, text) = server.tool("list_vaults");
    assert!(!is_error, "{text}");

    // The host closes it; the daemon records that and why.
    server.close();
    fixture.wait_for_record("agent_disconnected", "host_closed");

    let records = fixture.agent_records();
    assert!(
        records.iter().any(|(k, _)| k == "agent_connected"),
        "{records:?}"
    );
    assert!(
        records
            .iter()
            .any(|(k, d)| k == "agent_tool_call" && d == "list_vaults"),
        "{records:?}"
    );
    assert!(
        records
            .iter()
            .any(|(k, d)| k == "agent_tool_call" && d == "list_vaults:failed"),
        "{records:?}"
    );
}

#[test]
fn a_killed_server_is_recorded_as_a_lost_connection() {
    let fixture = Fixture::new("killed");
    let _daemon = DaemonGuard(&fixture);
    fixture.start_daemon();

    let mut server = Server::spawn(&fixture);
    server.request("initialize", json!({ "protocolVersion": "2025-06-18" }));
    fixture.wait_for_record("agent_connected", "");

    server.child.kill().expect("kill");
    server.child.wait().expect("wait");
    fixture.wait_for_record("agent_disconnected", "connection_lost");
}

#[test]
fn with_no_account_the_server_still_refuses_to_start() {
    let dir = tempfile::tempdir().expect("tempdir");
    let out = Command::cargo_bin("localpass")
        .expect("built binary")
        .env_remove("LOCALPASS_PASSWORD")
        .env("USERNAME", format!("lpmcp-none-{}", std::process::id()))
        .arg("--profile")
        .arg(dir.path())
        .arg("mcp")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("run");
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("no account"));
}
