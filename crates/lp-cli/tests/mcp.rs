//! End-to-end integration test for `localpass mcp` — the MCP stdio server.
//!
//! Unlike the other CLI tests this one cannot use `assert_cmd`'s one-shot
//! `assert()`: an MCP server is a *conversation*. It spawns the built binary
//! with piped stdin/stdout, drives the real newline-delimited JSON-RPC
//! handshake, and asserts on the frames that come back.
//!
//! The whole suite runs against **one** server process over **one** initialized
//! profile: `init` plus the server's own unlock are two Argon2id derivations
//! (~1s each), so batching keeps the test cheap.
//!
//! The property under test is the module's load-bearing invariant: **a planted
//! secret value must never appear anywhere in an MCP reply.** Every assertion
//! below is a different way for that to fail.

mod common;

use std::io::{BufRead, BufReader, Write};
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};

use common::{TEST_PASSWORD, TestProfile};
use serde_json::{Value, json};

/// The password planted on the login item. Long and distinctive so a substring
/// search over a whole JSON reply is meaningful.
const PLANTED_PASSWORD: &str = "planted-login-password-9f3c2a";
/// The value planted in the env-set entry that `run_with_secrets` injects.
const PLANTED_ENV_VALUE: &str = "planted-env-value-4d81b7";
/// The RFC 6238 SHA-1 seed in base32 (also used by `tests/totp.rs`).
const RFC_SEED_B32: &str = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";

/// A live `localpass mcp` child, with its two pipes.
struct McpServer {
    child: Child,
    stdin: ChildStdin,
    stdout: BufReader<ChildStdout>,
    next_id: i64,
}

impl McpServer {
    /// Spawn `localpass --profile <dir> mcp` with piped stdio.
    fn spawn(profile: &TestProfile) -> Self {
        let exe = assert_cmd::cargo::cargo_bin("localpass");
        let mut child = Command::new(exe)
            .arg("--profile")
            .arg(profile.path())
            .arg("--no-daemon") // hermetic: never touch a stray developer daemon
            .arg("mcp")
            .env("LOCALPASS_PASSWORD", TEST_PASSWORD)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn localpass mcp");
        let stdin = child.stdin.take().expect("stdin pipe");
        let stdout = BufReader::new(child.stdout.take().expect("stdout pipe"));
        Self {
            child,
            stdin,
            stdout,
            next_id: 0,
        }
    }

    /// Send a request and read the matching response frame.
    fn request(&mut self, method: &str, params: Value) -> Value {
        self.next_id += 1;
        let id = self.next_id;
        self.send(&json!({
            "jsonrpc": "2.0",
            "id": id,
            "method": method,
            "params": params,
        }));
        let frame = self.read_frame();
        assert_eq!(frame["id"], json!(id), "response id must match the request");
        assert_eq!(frame["jsonrpc"], json!("2.0"));
        frame
    }

    /// Send a notification (no id, no reply expected).
    fn notify(&mut self, method: &str) {
        self.send(&json!({ "jsonrpc": "2.0", "method": method }));
    }

    fn send(&mut self, frame: &Value) {
        let line = serde_json::to_string(frame).expect("serialize frame");
        writeln!(self.stdin, "{line}").expect("write to server stdin");
        self.stdin.flush().expect("flush server stdin");
    }

    fn read_frame(&mut self) -> Value {
        let mut line = String::new();
        let n = self
            .stdout
            .read_line(&mut line)
            .expect("read from server stdout");
        assert!(n > 0, "server closed stdout before answering");
        serde_json::from_str(&line).unwrap_or_else(|e| panic!("bad frame {line:?}: {e}"))
    }

    /// Call a tool and return `(result_object, parsed_text_body)`.
    fn call_tool(&mut self, name: &str, arguments: Value) -> (Value, Value) {
        let frame = self.request(
            "tools/call",
            json!({ "name": name, "arguments": arguments }),
        );
        assert!(
            frame.get("error").is_none(),
            "a tool failure must be an isError result, not a JSON-RPC error: {frame}"
        );
        let result = frame["result"].clone();
        let blocks = result["content"]
            .as_array()
            .expect("content must be an array");
        assert_eq!(blocks.len(), 1, "exactly one content block: {result}");
        assert_eq!(blocks[0]["type"], json!("text"));
        let text = blocks[0]["text"].as_str().expect("text block body");
        let body = serde_json::from_str(text)
            .unwrap_or_else(|e| panic!("tool body must be JSON ({e}): {text}"));
        (result, body)
    }

    /// Close stdin (EOF) and assert the server shut down cleanly.
    fn shutdown(mut self) {
        drop(self.stdin);
        let status = self.child.wait().expect("wait for server");
        assert!(
            status.success(),
            "EOF on stdin must be a clean shutdown, got {status:?}"
        );
    }
}

/// Populate the profile the server will serve: a login item with a planted
/// password, an env-set with a planted value, and a totp item.
fn seed(profile: &TestProfile) {
    profile
        .cmd()
        .args([
            "item",
            "add",
            "--type",
            "login",
            "--title",
            "Prod DB",
            "--username",
            "alice",
            "--password",
            PLANTED_PASSWORD,
        ])
        .assert()
        .success();

    profile
        .cmd()
        .args([
            "item",
            "add",
            "--type",
            "env-set",
            "--title",
            "myapp-dev",
            "--env",
            &format!("APP_SECRET={PLANTED_ENV_VALUE}"),
        ])
        .assert()
        .success();

    let uri = format!("otpauth://totp/ACME:alice@acme.com?secret={RFC_SEED_B32}&issuer=ACME");
    profile
        .cmd()
        .args([
            "item",
            "add",
            "--type",
            "totp",
            "--title",
            "ACME 2FA",
            "--otpauth-uri",
            &uri,
        ])
        .assert()
        .success();
}

/// A command that echoes an environment variable, portable across platforms
/// (mirrors `tests/run_and_env.rs`). Returned as a JSON array so no tokenizing
/// happens in the middle of the assertion.
fn echo_var_command(name: &str) -> Value {
    #[cfg(windows)]
    {
        json!(["cmd", "/c", "echo", format!("%{name}%")])
    }
    #[cfg(not(windows))]
    {
        json!(["sh", "-c", format!("printf '%s\\n' \"${name}\"")])
    }
}

#[test]
fn mcp_server_serves_tools_without_ever_returning_a_secret() {
    let profile = TestProfile::initialized();
    seed(&profile);

    let mut mcp = McpServer::spawn(&profile);

    // --- handshake -------------------------------------------------------
    let init = mcp.request(
        "initialize",
        json!({
            "protocolVersion": "2025-06-18",
            "capabilities": {},
            "clientInfo": { "name": "integration-test", "version": "0" },
        }),
    );
    let r = &init["result"];
    assert_eq!(r["protocolVersion"], json!("2025-06-18"));
    assert!(r["capabilities"]["tools"].is_object(), "tools capability");
    assert_eq!(r["serverInfo"]["name"], json!("localpass"));
    mcp.notify("notifications/initialized");

    // `ping` keeps working after the handshake.
    assert_eq!(mcp.request("ping", json!({}))["result"], json!({}));

    // An unknown method is a protocol error, not a tool error.
    let unknown = mcp.request("does/not/exist", json!({}));
    assert_eq!(unknown["error"]["code"], json!(-32601));

    // --- tools/list ------------------------------------------------------
    let list = mcp.request("tools/list", json!({}));
    let names: Vec<String> = list["result"]["tools"]
        .as_array()
        .expect("tools array")
        .iter()
        .map(|t| t["name"].as_str().unwrap().to_string())
        .collect();
    for expected in [
        "list_vaults",
        "list_items",
        "get_item",
        "run_with_secrets",
        "totp_code",
    ] {
        assert!(names.contains(&expected.to_string()), "missing {expected}");
    }

    // --- list_vaults -----------------------------------------------------
    let (_, vaults) = mcp.call_tool("list_vaults", json!({}));
    let vault_names: Vec<&str> = vaults["vaults"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v["name"].as_str().unwrap())
        .collect();
    assert!(vault_names.contains(&"personal"), "got {vault_names:?}");

    // --- list_items: field NAMES present, values masked -------------------
    let (list_result, items) = mcp.call_tool("list_items", json!({ "vault": "personal" }));
    assert_eq!(list_result["isError"], json!(false));
    let titles: Vec<&str> = items["items"]
        .as_array()
        .unwrap()
        .iter()
        .map(|i| i["title"].as_str().unwrap())
        .collect();
    assert!(titles.contains(&"Prod DB"), "got {titles:?}");
    assert!(titles.contains(&"myapp-dev"), "got {titles:?}");

    let raw_list = list_result.to_string();
    assert!(
        raw_list.contains("password"),
        "field NAMES must survive: {raw_list}"
    );
    assert!(
        raw_list.contains("APP_SECRET"),
        "env-set entry KEYS are field names and must survive"
    );
    assert_no_secret(&raw_list, "list_items");

    // --- get_item: no raw value anywhere in the whole reply ---------------
    let (get_result, item) = mcp.call_tool("get_item", json!({ "item": "Prod DB" }));
    assert_eq!(item["item"]["title"], json!("Prod DB"));
    let fields = item["item"]["fields"].as_array().unwrap();
    let pw = fields
        .iter()
        .find(|f| f["name"] == json!("password"))
        .expect("password field present by NAME");
    assert_eq!(pw["secret"], json!(true));
    assert_ne!(pw["value"], json!(PLANTED_PASSWORD));
    let user = fields
        .iter()
        .find(|f| f["name"] == json!("username"))
        .expect("username field");
    assert_eq!(
        user["value"],
        json!("alice"),
        "non-secret values must NOT be masked"
    );
    assert_no_secret(&get_result.to_string(), "get_item");

    // A missing item is an isError result, not a JSON-RPC error.
    let (missing, _) = mcp.call_tool("get_item", json!({ "item": "no-such-item" }));
    assert_eq!(missing["isError"], json!(true));

    // --- run_with_secrets: child SEES the value, reply does NOT -----------
    let (run_result, run_body) = mcp.call_tool(
        "run_with_secrets",
        json!({
            "env": { "INJECTED": "localpass://personal/myapp-dev/APP_SECRET" },
            "command": echo_var_command("INJECTED"),
            "timeout_secs": 60,
        }),
    );
    assert_eq!(run_result["isError"], json!(false), "{run_result}");
    assert_eq!(run_body["exit_code"], json!(0), "{run_body}");
    assert_eq!(run_body["timed_out"], json!(false));
    assert_eq!(run_body["injected_vars"], json!(["INJECTED"]));

    let stdout = run_body["stdout"].as_str().expect("stdout string");
    // The child really did receive the plaintext (it echoed *something* in the
    // value's place)…
    assert!(
        stdout.contains("[REDACTED:INJECTED]"),
        "the child must have echoed the injected value, which is then redacted; got {stdout:?}"
    );
    // …and the value itself is nowhere in the reply.
    assert!(
        !stdout.contains(PLANTED_ENV_VALUE),
        "redaction failed: {stdout:?}"
    );
    assert_no_secret(&run_result.to_string(), "run_with_secrets");

    // The env-set item form injects every entry.
    let (_, by_item) = mcp.call_tool(
        "run_with_secrets",
        json!({
            "item": "myapp-dev",
            "command": echo_var_command("APP_SECRET"),
            "timeout_secs": 60,
        }),
    );
    assert_eq!(by_item["injected_vars"], json!(["APP_SECRET"]));
    let stdout = by_item["stdout"].as_str().unwrap();
    assert!(
        stdout.contains("[REDACTED:APP_SECRET]") && !stdout.contains(PLANTED_ENV_VALUE),
        "env-set injection must be redacted too; got {stdout:?}"
    );

    // A bad reference fails as a tool error, and does not take the server down.
    let (bad_ref, _) = mcp.call_tool(
        "run_with_secrets",
        json!({
            "env": { "NOPE": "localpass://personal/myapp-dev/NO_SUCH_KEY" },
            "command": echo_var_command("NOPE"),
        }),
    );
    assert_eq!(bad_ref["isError"], json!(true));

    // --- totp_code: shape ------------------------------------------------
    let (totp_result, totp) = mcp.call_tool("totp_code", json!({ "item": "ACME 2FA" }));
    assert_eq!(totp_result["isError"], json!(false), "{totp_result}");
    let code = totp["code"].as_str().expect("code string");
    assert_eq!(code.len(), 6, "default digits is 6: {code:?}");
    assert!(
        code.chars().all(|c| c.is_ascii_digit()),
        "code must be digits: {code:?}"
    );
    assert_eq!(totp["period"], json!(30));
    assert_eq!(totp["digits"], json!(6));
    assert!(totp["seconds_remaining"].as_u64().unwrap() <= 30);
    assert!(
        !totp_result.to_string().contains(RFC_SEED_B32),
        "the TOTP SEED must never be returned"
    );

    // A non-totp item is a tool error, not a protocol error.
    let (wrong_type, _) = mcp.call_tool("totp_code", json!({ "item": "Prod DB" }));
    assert_eq!(wrong_type["isError"], json!(true));

    // --- clean shutdown on EOF -------------------------------------------
    mcp.shutdown();
}

/// Assert no planted secret appears anywhere in a serialized reply.
fn assert_no_secret(reply: &str, what: &str) {
    for planted in [PLANTED_PASSWORD, PLANTED_ENV_VALUE, TEST_PASSWORD] {
        assert!(
            !reply.contains(planted),
            "{what} leaked {planted:?} into its reply: {reply}"
        );
    }
}
