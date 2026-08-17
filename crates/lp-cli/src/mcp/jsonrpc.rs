//! A minimal, hand-rolled JSON-RPC 2.0 layer for the MCP stdio transport.
//!
//! LocalPass implements MCP by hand on `serde_json` rather than pulling an SDK.
//! The subset MCP's stdio transport actually needs is small — a request
//! envelope, a notification (a request with no `id`), a result, and an error —
//! and the repo's dependency culture (see the KDBX decision in `LESSONS.md`)
//! prefers a focused hand-written reader over a large transitive tree for a
//! well-specified wire format.
//!
//! # Framing
//!
//! MCP stdio transport is **newline-delimited JSON**: exactly one JSON value per
//! line, no embedded newlines. `stdout` carries protocol frames and nothing
//! else — every diagnostic goes to `stderr` (see [`super::log`]).

use serde::Deserialize;
use serde_json::{Value, json};

/// JSON-RPC: the request was not valid JSON.
pub const PARSE_ERROR: i64 = -32700;
/// JSON-RPC: the envelope was well-formed JSON but not a valid request.
pub const INVALID_REQUEST: i64 = -32600;
/// JSON-RPC: the requested method does not exist.
pub const METHOD_NOT_FOUND: i64 = -32601;
/// JSON-RPC: the method exists but the params are wrong.
pub const INVALID_PARAMS: i64 = -32602;

/// One decoded incoming JSON-RPC message.
///
/// A message with no `id` is a **notification**: per JSON-RPC 2.0 it must never
/// be answered, not even with an error.
///
/// The `"jsonrpc"` tag is deliberately **not** captured. Every real MCP client
/// sends `"2.0"`, and refusing an otherwise well-formed frame over the tag would
/// trade interoperability for nothing — the method name is what actually selects
/// behaviour. Our own outgoing frames always carry it (see [`result`]/[`error`]).
#[derive(Debug, Deserialize)]
pub struct Incoming {
    /// The correlation id, or `None` for a notification.
    #[serde(default)]
    pub id: Option<Value>,
    /// The method name.
    #[serde(default)]
    pub method: Option<String>,
    /// The method parameters (shape is per-method).
    #[serde(default)]
    pub params: Option<Value>,
}

impl Incoming {
    /// The `params` object, or an empty object when absent/not an object.
    #[must_use]
    pub fn params(&self) -> Value {
        match &self.params {
            Some(v @ Value::Object(_)) => v.clone(),
            _ => json!({}),
        }
    }
}

/// Build a successful JSON-RPC response frame.
#[must_use]
pub fn result(id: Value, result: Value) -> Value {
    json!({ "jsonrpc": "2.0", "id": id, "result": result })
}

/// Build a JSON-RPC error response frame.
///
/// These are **protocol** errors (bad frame, unknown method). A *tool* that
/// fails is not a protocol error — it returns a normal result with
/// `isError: true` (see [`super::tools::error_result`]).
#[must_use]
pub fn error(id: Value, code: i64, message: impl Into<String>) -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": id,
        "error": { "code": code, "message": message.into() },
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_message_without_an_id_is_a_notification() {
        let m: Incoming =
            serde_json::from_str(r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#)
                .unwrap();
        assert!(m.id.is_none());
        assert_eq!(m.method.as_deref(), Some("notifications/initialized"));
    }

    #[test]
    fn params_defaults_to_an_empty_object() {
        let m: Incoming =
            serde_json::from_str(r#"{"jsonrpc":"2.0","id":1,"method":"ping"}"#).unwrap();
        assert_eq!(m.params(), json!({}));
    }

    #[test]
    fn non_object_params_are_normalized_to_empty() {
        let m: Incoming =
            serde_json::from_str(r#"{"jsonrpc":"2.0","id":1,"method":"x","params":[1,2]}"#)
                .unwrap();
        assert_eq!(m.params(), json!({}));
    }

    #[test]
    fn frames_carry_the_protocol_tag_and_id() {
        assert_eq!(
            result(json!(7), json!({"ok": true})),
            json!({"jsonrpc": "2.0", "id": 7, "result": {"ok": true}})
        );
        assert_eq!(
            error(json!(null), PARSE_ERROR, "bad json"),
            json!({
                "jsonrpc": "2.0",
                "id": null,
                "error": {"code": PARSE_ERROR, "message": "bad json"},
            })
        );
    }

    #[test]
    fn frames_serialize_to_a_single_line() {
        let s = serde_json::to_string(&result(json!(1), json!({"a": "b\nc"}))).unwrap();
        assert!(
            !s.contains('\n'),
            "a frame must never contain a raw newline: {s}"
        );
    }
}
