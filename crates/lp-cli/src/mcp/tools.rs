//! The six MCP tools LocalPass exposes, their JSON schemas, and their
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
//! | `fill_login` | `empty`/`filled` booleans for the fields filled | no |
//!
//! `run_with_secrets` is the only path by which a plaintext value goes
//! anywhere, and it goes exactly one place: the child process's environment.
//! `fill_login` is the second **spend**, not return: the credential goes from
//! the daemon to the browser extension and into the page's DOM, and what comes
//! back here is a handful of booleans (`agent-fill.md` §3). Its result type is
//! structurally incapable of carrying a value, a length, a prefix, or a hash —
//! see [`lp_daemon::protocol::FillReport`], which has no string field at all.

use std::path::PathBuf;
use std::time::Duration;

use anyhow::Result;
use serde_json::{Value, json};

use crate::envmap::OrderedEnv;
use crate::error::CliError;
use crate::mcp::backend::Backend;
use crate::mcp::{exec, mask, redact};

use lp_daemon::protocol::{FieldState, FieldStates, FillField, FillRefusal};

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
            "name": "fill_login",
            "description":
                "Fill a login form in the browser WITHOUT the password being returned to you. \
                 LocalPass sends the credential straight from the vault to the LocalPass \
                 browser extension, which types it into the page; you get back only whether \
                 each field was empty before and filled after. Requires the user to have \
                 armed agent-fill mode for this item first (`localpass agent-fill arm`); \
                 otherwise this is refused with `agent_fill_not_armed`. It never submits the \
                 form — click the submit button yourself, as a user would.\n\n\
                 DO NOT read `input.value` for the filled fields, and do not evaluate \
                 JavaScript against the login form: the before/after state you need is \
                 returned here, so there is no reason to touch the page, and reading the \
                 value would put the credential in this transcript. Identify fields by \
                 label, aria-label, or name instead.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "vault": {
                        "type": "string",
                        "description":
                            "Vault name or id. Omit to search every vault, which is how \
                             browser autofill resolves an item.",
                    },
                    "item": {
                        "type": "string",
                        "description": "The login item to fill (title or id).",
                    },
                    "tab_id": {
                        "type": "integer",
                        "minimum": 0,
                        "description":
                            "The browser tab to fill. Optional but strongly preferred: \
                             without it the extension refuses when several tabs share the \
                             origin (`ambiguous_tab`).",
                    },
                    "origin": {
                        "type": "string",
                        "description":
                            "The page origin, e.g. \"https://github.com\". Re-checked \
                             against the item's stored URL inside the daemon.",
                    },
                    "overwrite": {
                        "type": "boolean",
                        "description":
                            "Allow overwriting a field that already has something in it \
                             (default false, which refuses with `field_not_empty`).",
                    },
                },
                "required": ["item", "origin"],
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
        "fill_login" => fill_login(backend, args),
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

/// An optional non-negative integer argument.
fn opt_u64(args: &Value, key: &str) -> Result<Option<u64>> {
    match args.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(v) => v.as_u64().map(Some).ok_or_else(|| {
            CliError::usage(format!("`{key}` must be a non-negative integer")).into()
        }),
    }
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

/// The `empty`/`filled` token for one field, or `null` when the page had no
/// such field. The **only** two words this tool can say about a field.
fn field_state_json(state: Option<FieldState>) -> Value {
    match state {
        Some(FieldState::Empty) => json!("empty"),
        Some(FieldState::Filled) => json!("filled"),
        None => Value::Null,
    }
}

/// Render a [`FieldStates`] as `{"username": …, "password": …}`.
fn field_states_json(states: FieldStates) -> Value {
    json!({
        "username": field_state_json(states.username),
        "password": field_state_json(states.password),
    })
}

/// The `fill_login` tool (`agent-fill.md` §3/§11).
///
/// **The result is booleans by construction.** Everything it can contain is
/// built here, by hand, out of a [`lp_daemon::protocol::FillReport`] — a type
/// with no string field — plus the item id, tab id, and origin the *caller*
/// already supplied. There is no path by which a value, a length, a prefix, or a
/// hash could reach it, on success or on any refusal: a refusal renders one
/// closed token from [`FillRefusal::token`] and nothing else.
fn fill_login(backend: &mut Backend, args: &Value) -> Result<Value> {
    let vault = opt_str(args, "vault");
    let item = req_str(args, "item")?;
    let origin = req_str(args, "origin")?;
    let tab_id = opt_u64(args, "tab_id")?;
    let overwrite = match args.get("overwrite") {
        None | Some(Value::Null) => false,
        Some(v) => v
            .as_bool()
            .ok_or_else(|| CliError::usage("`overwrite` must be a boolean"))?,
    };

    let finished = match backend.fill_login(vault.as_deref(), &item, tab_id, &origin, overwrite)? {
        Ok(finished) => finished,
        Err(reason) => return Err(CliError::usage(refusal_message(reason)).into()),
    };
    let report = finished.report;
    if !report.filled {
        let reason = report.reason.unwrap_or(FillRefusal::NoLoginForm);
        return Err(CliError::usage(refusal_message(reason)).into());
    }
    let fields: Vec<&str> = report
        .fields
        .iter()
        .map(|f| match f {
            FillField::Username => "username",
            FillField::Password => "password",
        })
        .collect();
    Ok(ok_result(&json!({
        "filled": true,
        "fields": fields,
        "before": field_states_json(report.before),
        "after": field_states_json(report.after),
        "tab": { "id": finished.tab_id, "origin": finished.origin },
        "item_id": finished.item_id,
    })))
}

/// The one-line, **value-free** message for a refusal: the `agent-fill.md` §10
/// token, plus a fixed sentence saying what to do about it.
fn refusal_message(reason: FillRefusal) -> String {
    let hint = match reason {
        FillRefusal::AgentFillNotArmed => {
            "agent-fill mode is not armed; ask the user to run \
             `localpass agent-fill arm --item <item>` (or arm it in the desktop app)"
        }
        FillRefusal::ItemNotArmed => {
            "that item is outside the armed set; ask the user to arm it specifically"
        }
        FillRefusal::Locked => "the LocalPass vault is locked; ask the user to unlock it",
        FillRefusal::ItemNotFound => "no login item matches that reference",
        FillRefusal::AmbiguousItem => "that title matches more than one item; use the item id",
        FillRefusal::OriginMismatch => "the item's stored URL does not match that origin",
        FillRefusal::TabNotFound => "the tab you named is gone",
        FillRefusal::AmbiguousTab => "several tabs match that origin; pass tab_id",
        FillRefusal::OriginChanged => "the tab navigated after the fill was armed; try again",
        FillRefusal::IntentExpired => {
            "the fill was not redeemed in time; check the extension is installed and armed"
        }
        FillRefusal::FieldNotEmpty => {
            "a target field already has something in it; pass overwrite: true to replace it"
        }
        FillRefusal::ExtensionUnavailable => {
            "no LocalPass daemon/extension is reachable; agent fill needs the running daemon \
             and the browser extension"
        }
        FillRefusal::NoLoginForm => "no fillable password field was found on that page",
    };
    format!("{}: {hint}", reason.token())
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
/// channel. [`crate::envmap::base_env`] strips `LOCALPASS_PASSWORD` for every
/// child spawner (`localpass run` included) — doubly important here, where the
/// child's output is captured and returned to a model.
fn inherited_env() -> OrderedEnv {
    crate::envmap::base_env(true)
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
        assert_eq!(arr.len(), 6);
        for t in arr {
            assert!(t["name"].as_str().is_some_and(|s| !s.is_empty()));
            assert!(t["description"].as_str().is_some_and(|s| !s.is_empty()));
            assert_eq!(t["inputSchema"]["type"], "object");
        }
    }

    #[test]
    fn tool_names_are_the_documented_six() {
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
                "fill_login",
                "totp_code"
            ]
        );
    }

    /// The `fill_login` description must carry the §3 prohibition, because that
    /// wording is the entire mechanism: it is a contract with the agent, not a
    /// control LocalPass can enforce.
    #[test]
    fn fill_login_tells_the_agent_not_to_read_the_value() {
        let tools = tool_definitions();
        let t = tools
            .as_array()
            .unwrap()
            .iter()
            .find(|t| t["name"] == "fill_login")
            .expect("fill_login is declared");
        let desc = t["description"].as_str().unwrap();
        assert!(desc.contains("input.value"), "{desc}");
        assert!(
            desc.contains("never submits") || desc.contains("never submit"),
            "{desc}"
        );
        // `origin` is required; a fill with no origin cannot be origin-checked.
        let required: Vec<&str> = t["inputSchema"]["required"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_str().unwrap())
            .collect();
        assert!(required.contains(&"origin"));
        assert!(required.contains(&"item"));
    }

    /// Every §10 refusal renders as its own token and a fixed hint — never a
    /// message that could echo a value back.
    #[test]
    fn refusal_messages_are_the_taxonomy_tokens() {
        for r in [
            FillRefusal::AgentFillNotArmed,
            FillRefusal::ItemNotArmed,
            FillRefusal::Locked,
            FillRefusal::ItemNotFound,
            FillRefusal::AmbiguousItem,
            FillRefusal::OriginMismatch,
            FillRefusal::TabNotFound,
            FillRefusal::AmbiguousTab,
            FillRefusal::OriginChanged,
            FillRefusal::IntentExpired,
            FillRefusal::FieldNotEmpty,
            FillRefusal::ExtensionUnavailable,
            FillRefusal::NoLoginForm,
        ] {
            let m = refusal_message(r);
            assert!(m.starts_with(r.token()), "{m}");
        }
    }

    /// The field-state renderer has a two-word vocabulary, and `null` for a
    /// field that was not there at all.
    #[test]
    fn a_field_state_is_only_ever_empty_or_filled() {
        assert_eq!(field_state_json(Some(FieldState::Empty)), json!("empty"));
        assert_eq!(field_state_json(Some(FieldState::Filled)), json!("filled"));
        assert_eq!(field_state_json(None), Value::Null);
        assert_eq!(
            field_states_json(FieldStates {
                username: Some(FieldState::Empty),
                password: Some(FieldState::Filled),
            }),
            json!({ "username": "empty", "password": "filled" })
        );
    }

    #[test]
    fn tab_id_must_be_a_non_negative_integer() {
        assert_eq!(opt_u64(&json!({}), "tab_id").unwrap(), None);
        assert_eq!(opt_u64(&json!({"tab_id": 7}), "tab_id").unwrap(), Some(7));
        assert!(opt_u64(&json!({"tab_id": -1}), "tab_id").is_err());
        assert!(opt_u64(&json!({"tab_id": "seven"}), "tab_id").is_err());
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
