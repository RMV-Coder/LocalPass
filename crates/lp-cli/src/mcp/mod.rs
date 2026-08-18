//! `localpass mcp` — a Model Context Protocol server over stdio, so an AI
//! coding agent can **use** LocalPass secrets without ever **seeing** them.
//!
//! # The invariant
//!
//! > **No MCP tool result ever contains a raw secret value.**
//!
//! This is the whole point of the surface, and it is load-bearing: everything an
//! MCP tool returns is copied verbatim into an agent's transcript, which is
//! logged, replayed, summarized, and frequently shipped to a third party. A
//! password that reaches a transcript must be treated as disclosed. So instead
//! of *returning* secrets, this server **spends** them: the only way a value
//! leaves the vault is into a child process's environment, via
//! [`run_with_secrets`](tools).
//!
//! Three mechanisms hold the invariant up, in depth:
//!
//! 1. **Structural masking.** Item reads leave [`backend`] as a
//!    [`mask::ItemView`], which is deliberately *not* `Serialize`. The only way
//!    to obtain something serializable is [`mask::item_view_masked`], which
//!    consumes the view and drops every secret value. A call site cannot forget
//!    to mask, because it is never handed a maskable-but-unmasked shape. (Same
//!    pattern as the desktop GUI's `model::item_view_masked` choke point — see
//!    `LESSONS.md`; the implementation here is independent, since the AGPL core
//!    must not depend on the MPL-2.0 app.)
//! 2. **Masking at the source too.** On the daemon route, items are fetched with
//!    `reveal = false`, so the daemon masks them before they even cross the IPC
//!    pipe. The choke point then runs over already-masked values — belt and
//!    braces, one code path.
//! 3. **Output redaction.** `run_with_secrets` scrubs every injected value out
//!    of the child's captured stdout/stderr ([`redact`]) and then *re-checks*
//!    that none survived before it will build a result at all.
//!
//! `totp_code` is the one deliberate exception, and it is not a secret: a
//! six-digit code valid for the rest of the current 30-second window is a
//! short-lived derivative, not the seed. The seed never leaves the vault (on the
//! daemon route it never leaves the daemon).
//!
//! # Transport
//!
//! MCP stdio transport, protocol version [`PROTOCOL_VERSION`]: newline-delimited
//! JSON-RPC 2.0 on stdin/stdout. **stdout carries protocol frames and nothing
//! else** — every diagnostic goes to stderr through [`log`], which is why no
//! part of this module ever calls `println!`. Log lines carry method and tool
//! names only, never arguments, never a value, never the master password.
//!
//! Implemented methods: `initialize`, `notifications/initialized`, `tools/list`,
//! `tools/call`, `ping`. Anything else gets a JSON-RPC `-32601`. EOF on stdin is
//! a clean shutdown (the client closed the pipe), which is how MCP hosts stop a
//! stdio server.
//!
//! The protocol is implemented by hand on `serde_json` rather than through an
//! SDK: the needed subset is a few hundred lines, and the repo's dependency
//! culture (the KDBX decision in `LESSONS.md`) prefers a focused hand-written
//! implementation of a well-specified format over a large transitive tree.
//!
//! # Unlock
//!
//! The server unlocks **once at startup**, through the same
//! [`crate::daemonctl::route`] matrix every other subcommand uses — daemon-first
//! with a direct-unlock fallback, honouring `--profile`, `--no-daemon`,
//! `LOCALPASS_PASSWORD` and `--password-stdin` — and serves until stdin EOF.
//! There is no MCP tool to unlock, lock, create, edit, or delete anything: the
//! surface is deliberately read-plus-inject only.

pub mod backend;
pub mod exec;
pub mod jsonrpc;
pub mod mask;
pub mod redact;
pub mod tools;

use std::io::{BufRead, Write};
use std::path::Path;

use anyhow::Result;
use serde_json::{Value, json};

use crate::error::CliError;
use crate::unlock::PasswordSource;
use backend::Backend;

/// The MCP protocol version this server implements and advertises.
pub const PROTOCOL_VERSION: &str = "2025-06-18";

/// Older MCP revisions whose `initialize` we answer in the client's own version
/// rather than forcing an upgrade. A version outside this set is answered with
/// [`PROTOCOL_VERSION`], which is what the spec asks a server to do when it does
/// not support what the client proposed — the client then decides whether to
/// continue.
pub const SUPPORTED_PROTOCOL_VERSIONS: &[&str] = &["2025-06-18", "2025-03-26", "2024-11-05"];

/// The server name reported in `initialize`.
const SERVER_NAME: &str = "localpass";

/// Write one diagnostic line to **stderr**.
///
/// stdout belongs to the protocol. Callers must pass method/tool names and
/// counts only — never an argument value, never a secret, never the master
/// password.
fn log(msg: &str) {
    eprintln!("localpass mcp: {msg}");
}

/// Run the MCP stdio server until stdin reaches EOF.
///
/// # Errors
///
/// [`CliError::Auth`] on a wrong master password / Secret Key at startup,
/// [`CliError::Usage`] when there is no account at `profile_dir`, or
/// [`CliError::Internal`] if stdout cannot be written (the client vanished
/// mid-frame).
pub fn run(profile_dir: &Path, src: PasswordSource, no_daemon: bool) -> Result<()> {
    let mut backend = Backend::acquire(profile_dir, src, no_daemon)?;
    log(&format!(
        "serving profile {} via {} route; protocol {PROTOCOL_VERSION}",
        profile_dir.display(),
        backend.route_label()
    ));

    let stdin = std::io::stdin();
    let mut reader = stdin.lock();
    let mut line = String::new();
    loop {
        line.clear();
        match reader.read_line(&mut line) {
            Ok(0) => {
                log("stdin closed; shutting down");
                return Ok(());
            }
            Ok(_) => {}
            Err(e) => {
                log(&format!("stdin read failed: {e}; shutting down"));
                return Ok(());
            }
        }
        if line.trim().is_empty() {
            continue;
        }
        if let Some(frame) = handle_line(&mut backend, line.trim()) {
            write_frame(&frame)?;
        }
    }
}

/// Handle one input line, returning the frame to write back (or `None` for a
/// notification, which JSON-RPC forbids answering).
fn handle_line(backend: &mut Backend, line: &str) -> Option<Value> {
    let msg: jsonrpc::Incoming = match serde_json::from_str(line) {
        Ok(m) => m,
        Err(e) => {
            log(&format!("dropping unparseable frame: {e}"));
            return Some(jsonrpc::error(
                Value::Null,
                jsonrpc::PARSE_ERROR,
                "invalid JSON",
            ));
        }
    };

    let Some(method) = msg.method.clone() else {
        return msg.id.clone().map(|id| {
            jsonrpc::error(
                id,
                jsonrpc::INVALID_REQUEST,
                "request is missing a `method`",
            )
        });
    };

    // No `id` ⇒ a notification: act on it, answer nothing.
    let Some(id) = msg.id.clone() else {
        log(&format!("notification {method}"));
        return None;
    };

    log(&format!("request {method}"));
    Some(dispatch(backend, id, &method, &msg.params()))
}

/// Route one *request* (a message with an id) to its handler.
fn dispatch(backend: &mut Backend, id: Value, method: &str, params: &Value) -> Value {
    match method {
        "initialize" => jsonrpc::result(id, initialize(params)),
        "ping" => jsonrpc::result(id, json!({})),
        "tools/list" => jsonrpc::result(id, json!({ "tools": tools::tool_definitions() })),
        "tools/call" => tools_call(backend, id, params),
        other => jsonrpc::error(
            id,
            jsonrpc::METHOD_NOT_FOUND,
            format!("unknown method {other:?}"),
        ),
    }
}

/// The `initialize` result: echo a protocol version we support, else our own.
fn initialize(params: &Value) -> Value {
    let requested = params.get("protocolVersion").and_then(Value::as_str);
    let negotiated = match requested {
        Some(v) if SUPPORTED_PROTOCOL_VERSIONS.contains(&v) => v,
        Some(v) => {
            log(&format!(
                "client asked for protocol {v}; answering {PROTOCOL_VERSION}"
            ));
            PROTOCOL_VERSION
        }
        None => PROTOCOL_VERSION,
    };
    json!({
        "protocolVersion": negotiated,
        "capabilities": { "tools": { "listChanged": false } },
        "serverInfo": {
            "name": SERVER_NAME,
            "version": env!("CARGO_PKG_VERSION"),
        },
        "instructions":
            "LocalPass never returns secret values. list_items/get_item show field NAMES with \
             masked values; to actually use a secret, call run_with_secrets, which injects it \
             into a child process's environment and redacts it out of the captured output.",
    })
}

/// `tools/call`: a *tool* failure is an `isError: true` result, not a JSON-RPC
/// error. Only a missing/!string tool name is a protocol-level `-32602`.
fn tools_call(backend: &mut Backend, id: Value, params: &Value) -> Value {
    let Some(name) = params.get("name").and_then(Value::as_str) else {
        return jsonrpc::error(
            id,
            jsonrpc::INVALID_PARAMS,
            "tools/call requires a string `name`",
        );
    };
    let args = match params.get("arguments") {
        Some(v @ Value::Object(_)) => v.clone(),
        _ => json!({}),
    };
    match tools::call(backend, name, &args) {
        Ok(result) => jsonrpc::result(id, result),
        Err(e) => {
            // The CLI's error taxonomy already guarantees secret-free messages.
            let message = format!("{e:#}");
            log(&format!("tool {name} failed"));
            jsonrpc::result(id, tools::error_result(&message))
        }
    }
}

/// Write one newline-delimited frame to stdout and flush it.
fn write_frame(frame: &Value) -> Result<()> {
    let line = serde_json::to_string(frame)
        .map_err(|e| CliError::internal(anyhow::anyhow!("serializing a response frame: {e}")))?;
    let mut out = std::io::stdout().lock();
    out.write_all(line.as_bytes())
        .and_then(|()| out.write_all(b"\n"))
        .and_then(|()| out.flush())
        .map_err(|e| CliError::internal(anyhow::anyhow!("writing to stdout: {e}")))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn initialize_echoes_a_supported_client_version() {
        for v in SUPPORTED_PROTOCOL_VERSIONS {
            let r = initialize(&json!({ "protocolVersion": v }));
            assert_eq!(r["protocolVersion"], json!(v));
        }
    }

    #[test]
    fn initialize_falls_back_for_an_unknown_version() {
        let r = initialize(&json!({ "protocolVersion": "1999-01-01" }));
        assert_eq!(r["protocolVersion"], json!(PROTOCOL_VERSION));
        let r = initialize(&json!({}));
        assert_eq!(r["protocolVersion"], json!(PROTOCOL_VERSION));
    }

    #[test]
    fn initialize_advertises_tools_and_server_identity() {
        let r = initialize(&json!({}));
        assert!(r["capabilities"]["tools"].is_object());
        assert_eq!(r["serverInfo"]["name"], json!(SERVER_NAME));
        assert!(r["serverInfo"]["version"].as_str().is_some());
    }

    #[test]
    fn the_advertised_version_is_the_newest_supported_one() {
        assert_eq!(SUPPORTED_PROTOCOL_VERSIONS[0], PROTOCOL_VERSION);
    }
}
