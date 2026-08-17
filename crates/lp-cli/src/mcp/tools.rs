//! The five MCP tools LocalPass exposes, their JSON schemas, and their
//! dispatch.
//!
//! Every tool returns a **single JSON text content block** — one `text` item
//! whose body is pretty-printed JSON — so an agent gets one predictable shape
//! to parse. A tool that fails returns a normal result with `isError: true`
//! (per MCP, a tool failure is data the model can react to, not a transport
//! error); only a malformed frame or an unknown *method* is a JSON-RPC error.
//!
//! # What may cross this boundary
//!
//! | Tool | Returns | Secret? |
//! |------|---------|---------|
//! | `list_vaults` | vault ids + names | no |
//! | `list_items` | item ids/titles/kinds + field **names**, values masked | no |
//! | `get_item` | one item's metadata + field names, values masked | no |
//! | `run_with_secrets` | child exit code + **redacted** stdout/stderr | no |
//! | `totp_code` | the current 6-digit code | short-lived derivative only |
//!
//! `run_with_secrets` is the only path by which a plaintext value goes
//! anywhere, and it goes exactly one place: the child process's environment.

use std::path::PathBuf;
use std::time::Duration;

use anyhow::Result;
use serde_json::{Value, json};

use crate::envmap::OrderedEnv;
use crate::error::CliError;
use crate::mcp::backend::Backend;
use crate::mcp::{exec, mask, redact};

/// Default wall-clock budget for a `run_with_secrets` child, in seconds.
pub const DEFAULT_TIMEOUT_SECS: u64 = 120;

/// Hard ceiling on `timeout_secs`, so a runaway agent cannot pin the server
/// forever on one call.
pub const MAX_TIMEOUT_SECS: u64 = 3600;

/// The vault used when a tool call omits `vault` — the same default the CLI's
/// `--vault` flag carries.
pub const DEFAULT_VAULT: &str = "personal";

/// The `tools/list` payload: every tool's name, description, and input schema.
#[must_use]
pub fn tool_definitions() -> Value {
    json!([
        {
            "name": "list_vaults",
            "description":
                "List the LocalPass vaults available in this profile. Returns vault ids and \
                 names only — no secrets.",
            "inputSchema": { "type": "object", "properties": {}, "additionalProperties": false },
        },
        {
            "name": "list_items",
            "description":
                "List the items in a vault: id, title, kind, and each item's FIELD NAMES. \
                 Secret values are masked and are never returned. Use this to discover what \
                 references exist before calling run_with_secrets.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "vault": {
                        "type": "string",
                        "description": "Vault name or id (default: \"personal\").",
                    },
                },
                "additionalProperties": false,
            },
        },
        {
            "name": "get_item",
            "description":
                "Get one item's metadata and field names. Secret values are masked and are \
                 never returned — to USE a secret, pass a localpass:// reference to \
                 run_with_secrets instead.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "vault": {
                        "type": "string",
                        "description": "Vault name or id (default: \"personal\").",
                    },
                    "item": {
                        "type": "string",
                        "description": "Item title or id.",
                    },
                },
                "required": ["item"],
                "additionalProperties": false,
            },
        },
        {
            "name": "run_with_secrets",
            "description":
                "Run a command with LocalPass secrets injected as environment variables. The \
                 values are placed only in the child process's environment — they are never \
                 returned. Any occurrence of an injected value in the captured stdout/stderr \
                 is replaced with [REDACTED:<VAR>] before the result is sent.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "vault": {
                        "type": "string",
                        "description": "Default vault for `item` (default: \"personal\").",
                    },
                    "item": {
                        "type": "string",
                        "description":
                            "An env_set item (title or id); every one of its entries is \
                             injected.",
                    },
                    "env": {
                        "type": "object",
                        "description":
                            "Explicit VAR -> localpass://<vault>/<item>/<field> (or op://) \
                             mappings. Applied after `item`, so these win on a name clash.",
                        "additionalProperties": { "type": "string" },
                    },
                    "command": {
                        "description":
                            "The command to run: either a string (split on whitespace, \
                             honouring quotes) or an array of [program, ...args]. It is NOT \
                             run through a shell.",
                        "anyOf": [
                            { "type": "string" },
                            { "type": "array", "items": { "type": "string" }, "minItems": 1 },
                        ],
                    },
                    "cwd": {
                        "type": "string",
                        "description": "Working directory for the child (default: inherited).",
                    },
                    "timeout_secs": {
                        "type": "integer",
                        "minimum": 1,
                        "maximum": MAX_TIMEOUT_SECS,
                        "description":
                            "Wall-clock budget; the child is killed past it (default 120).",
                    },
                },
                "required": ["command"],
                "additionalProperties": false,
            },
        },
        {
            "name": "totp_code",
            "description":
                "Get the current TOTP code for a totp item. Returns only the short-lived \
                 code and its remaining validity — never the TOTP seed.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "vault": {
                        "type": "string",
                        "description": "Vault name or id (default: \"personal\").",
                    },
                    "item": {
                        "type": "string",
                        "description": "The totp item (title or id).",
                    },
                },
                "required": ["item"],
                "additionalProperties": false,
            },
        },
    ])
}

/// Wrap a JSON body as the single text content block of a successful tool
/// result.
#[must_use]
pub fn ok_result(body: &Value) -> Value {
    json!({
        "content": [{
            "type": "text",
            "text": serde_json::to_string_pretty(body)
                .unwrap_or_else(|_| "{}".to_string()),
        }],
        "isError": false,
    })
}

/// Wrap a message as a failed tool result (`isError: true`), not a JSON-RPC
/// error.
#[must_use]
pub fn error_result(message: &str) -> Value {
    json!({
        "content": [{ "type": "text", "text": json!({ "error": message }).to_string() }],
        "isError": true,
    })
}

/// Dispatch one `tools/call`.
///
/// Returns `Ok(result)` for a tool that succeeded and `Err` for one that
/// failed; the caller renders the latter through [`error_result`]. An unknown
/// tool name is a tool failure, not a protocol error, so an agent that guessed
/// wrong is told so in-band.
///
/// # Errors
///
/// Any tool-level failure (unknown vault/item, unresolvable reference, spawn
/// failure, wrong item type).
pub fn call(backend: &mut Backend, name: &str, args: &Value) -> Result<Value> {
    match name {
        "list_vaults" => list_vaults(backend),
        "list_items" => list_items(backend, args),
        "get_item" => get_item(backend, args),
        "run_with_secrets" => run_with_secrets(backend, args),
        "totp_code" => totp_code(backend, args),
        other => Err(CliError::usage(format!(
            "unknown tool {other:?}; call tools/list for the available tools"
        ))
        .into()),
    }
}

// --- argument helpers -----------------------------------------------------

/// A required string argument.
fn req_str(args: &Value, key: &str) -> Result<String> {
    args.get(key)
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .map(ToString::to_string)
        .ok_or_else(|| CliError::usage(format!("missing required string argument {key:?}")).into())
}

/// An optional string argument.
fn opt_str(args: &Value, key: &str) -> Option<String> {
    args.get(key)
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .map(ToString::to_string)
}

/// The `vault` argument, defaulting like the CLI's `--vault` flag.
fn vault_arg(args: &Value) -> String {
    opt_str(args, "vault").unwrap_or_else(|| DEFAULT_VAULT.to_string())
}

// --- tools ----------------------------------------------------------------

fn list_vaults(backend: &mut Backend) -> Result<Value> {
    let vaults: Vec<Value> = backend
        .list_vaults()?
        .into_iter()
        .map(|v| json!({ "id": v.id, "name": v.name }))
        .collect();
    Ok(ok_result(&json!({ "vaults": vaults })))
}

fn list_items(backend: &mut Backend, args: &Value) -> Result<Value> {
    let vault = vault_arg(args);
    // Every view goes through the masking choke point before it can be
    // serialized — `ItemView` is not `Serialize`, so this is structural.
    let items: Vec<mask::MaskedItem> = backend
        .list_items(&vault)?
        .into_iter()
        .map(mask::item_view_masked)
        .collect();
    Ok(ok_result(&json!({ "vault": vault, "items": items })))
}

fn get_item(backend: &mut Backend, args: &Value) -> Result<Value> {
    let vault = vault_arg(args);
    let item = req_str(args, "item")?;
    let view = backend.get_item(&vault, &item)?;
    let masked = mask::item_view_masked(view);
    Ok(ok_result(&json!({ "vault": vault, "item": masked })))
}

fn totp_code(backend: &mut Backend, args: &Value) -> Result<Value> {
    let vault = vault_arg(args);
    let item = req_str(args, "item")?;
    let c = backend.totp(&vault, &item)?;
    Ok(ok_result(&json!({
        "code": c.code,
        "seconds_remaining": c.seconds_remaining,
        "period": c.period,
        "digits": c.digits,
        "algo": c.algo,
    })))
}

fn run_with_secrets(backend: &mut Backend, args: &Value) -> Result<Value> {
    let vault = vault_arg(args);

    // 1) Compose the injected variables: the env-set item first, then the
    //    explicit mappings (same precedence order as `localpass run`).
    let mut injected = OrderedEnv::new();
    if let Some(item) = opt_str(args, "item") {
        for (k, v) in backend.env_set_entries(&vault, &item)? {
            injected.set(k, v);
        }
    }
    if let Some(map) = args.get("env") {
        let obj = map.as_object().ok_or_else(|| {
            CliError::usage("`env` must be an object of VAR -> localpass reference")
        })?;
        for (key, value) in obj {
            let reference = value.as_str().ok_or_else(|| {
                CliError::usage(format!(
                    "`env.{key}` must be a localpass:// reference string"
                ))
            })?;
            let resolved = backend.resolve_reference(key, reference)?;
            injected.set(key.clone(), resolved);
        }
    }

    // 2) Build the child environment: inherited (minus LocalPass's own password
    //    channel) with the injected vars layered on top.
    let mut child_env = inherited_env();
    for (k, v) in injected.iter() {
        child_env.set(k, v);
    }

    // 3) Program + args.
    let argv = command_argv(args)?;
    let (program, rest) = argv.split_first().expect("command_argv rejects empty argv");

    let timeout = timeout_arg(args)?;
    let cwd = opt_str(args, "cwd").map(PathBuf::from);
    let captured = exec::run_capture(program, rest, &child_env, cwd.as_deref(), timeout)?;

    // 4) Redact every injected value out of the captured streams, then assert
    //    the invariant held before the result can be built.
    let secrets: Vec<(String, String)> = injected
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();
    let stdout = redact::redact(&captured.stdout, &secrets);
    let stderr = redact::redact(&captured.stderr, &secrets);
    if redact::contains_secret(&stdout, &secrets) || redact::contains_secret(&stderr, &secrets) {
        return Err(CliError::internal(anyhow::anyhow!(
            "refusing to return output: redaction did not remove every injected value"
        ))
        .into());
    }

    let names: Vec<&str> = injected.iter().map(|(k, _)| k).collect();
    Ok(ok_result(&json!({
        "exit_code": captured.exit_code,
        "timed_out": captured.timed_out,
        "stdout": stdout,
        "stderr": stderr,
        "injected_vars": names,
        "redaction": {
            "marker": "[REDACTED:<VAR>]",
            "min_value_length": redact::MIN_REDACT_LEN,
        },
    })))
}

/// The child's base environment: this process's, minus the master-password
/// channel.
///
/// [`crate::envmap::base_env`] inherits everything, which is right for
/// `localpass run` (the child's output goes to the user's own terminal). Here
/// the child's output is captured and returned to a model, so `LOCALPASS_PASSWORD`
/// — which a scripted launcher may well have set for us — must not be reachable
/// by a child that runs `env`.
fn inherited_env() -> OrderedEnv {
    let mut env = OrderedEnv::new();
    for (k, v) in std::env::vars() {
        if k == crate::unlock::PASSWORD_ENV {
            continue;
        }
        env.set(k, v);
    }
    env
}

/// Read `command` as either an array of strings or a tokenized string.
fn command_argv(args: &Value) -> Result<Vec<String>> {
    match args.get("command") {
        Some(Value::Array(items)) => {
            let mut argv = Vec::with_capacity(items.len());
            for it in items {
                let s = it.as_str().ok_or_else(|| {
                    CliError::usage("`command` array entries must all be strings")
                })?;
                argv.push(s.to_string());
            }
            if argv.is_empty() {
                return Err(CliError::usage("`command` array is empty").into());
            }
            Ok(argv)
        }
        Some(Value::String(s)) => exec::tokenize(s),
        _ => Err(CliError::usage(
            "missing required argument `command` (a string or an array of strings)",
        )
        .into()),
    }
}

/// Read and bound `timeout_secs`.
fn timeout_arg(args: &Value) -> Result<Duration> {
    let secs = match args.get("timeout_secs") {
        None | Some(Value::Null) => DEFAULT_TIMEOUT_SECS,
        Some(v) => v
            .as_u64()
            .ok_or_else(|| CliError::usage("`timeout_secs` must be a positive integer"))?,
    };
    if secs == 0 || secs > MAX_TIMEOUT_SECS {
        return Err(CliError::usage(format!(
            "`timeout_secs` must be between 1 and {MAX_TIMEOUT_SECS}"
        ))
        .into());
    }
    Ok(Duration::from_secs(secs))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_tool_declares_a_name_description_and_object_schema() {
        let tools = tool_definitions();
        let arr = tools.as_array().unwrap();
        assert_eq!(arr.len(), 5);
        for t in arr {
            assert!(t["name"].as_str().is_some_and(|s| !s.is_empty()));
            assert!(t["description"].as_str().is_some_and(|s| !s.is_empty()));
            assert_eq!(t["inputSchema"]["type"], "object");
        }
    }

    #[test]
    fn tool_names_are_the_documented_five() {
        let tools = tool_definitions();
        let names: Vec<&str> = tools
            .as_array()
            .unwrap()
            .iter()
            .map(|t| t["name"].as_str().unwrap())
            .collect();
        assert_eq!(
            names,
            [
                "list_vaults",
                "list_items",
                "get_item",
                "run_with_secrets",
                "totp_code"
            ]
        );
    }

    #[test]
    fn error_results_are_tool_errors_not_protocol_errors() {
        let r = error_result("nope");
        assert_eq!(r["isError"], json!(true));
        assert_eq!(r["content"][0]["type"], "text");
        assert!(r["content"][0]["text"].as_str().unwrap().contains("nope"));
    }

    #[test]
    fn ok_results_carry_exactly_one_text_block() {
        let r = ok_result(&json!({"a": 1}));
        assert_eq!(r["isError"], json!(false));
        assert_eq!(r["content"].as_array().unwrap().len(), 1);
        assert_eq!(r["content"][0]["type"], "text");
    }

    #[test]
    fn vault_defaults_to_personal() {
        assert_eq!(vault_arg(&json!({})), "personal");
        assert_eq!(vault_arg(&json!({"vault": "work"})), "work");
    }

    #[test]
    fn command_accepts_a_string_or_an_array() {
        assert_eq!(
            command_argv(&json!({"command": "echo hi"})).unwrap(),
            ["echo", "hi"]
        );
        assert_eq!(
            command_argv(&json!({"command": ["echo", "hi there"]})).unwrap(),
            ["echo", "hi there"]
        );
        assert!(command_argv(&json!({})).is_err());
        assert!(command_argv(&json!({"command": []})).is_err());
        assert!(command_argv(&json!({"command": [1, 2]})).is_err());
    }

    #[test]
    fn timeout_defaults_and_is_bounded() {
        assert_eq!(
            timeout_arg(&json!({})).unwrap(),
            Duration::from_secs(DEFAULT_TIMEOUT_SECS)
        );
        assert_eq!(
            timeout_arg(&json!({"timeout_secs": 5})).unwrap(),
            Duration::from_secs(5)
        );
        assert!(timeout_arg(&json!({"timeout_secs": 0})).is_err());
        assert!(timeout_arg(&json!({"timeout_secs": MAX_TIMEOUT_SECS + 1})).is_err());
        assert!(timeout_arg(&json!({"timeout_secs": "soon"})).is_err());
    }

    #[test]
    fn the_master_password_env_var_never_reaches_the_child() {
        let env = inherited_env();
        assert!(
            !env.iter().any(|(k, _)| k == crate::unlock::PASSWORD_ENV),
            "LOCALPASS_PASSWORD must be stripped from the child environment"
        );
    }
}
