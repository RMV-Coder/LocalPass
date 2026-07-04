#![forbid(unsafe_code)]
//! The **extension ↔ host** JSON message schema (the native-messaging wire
//! contract), separate from the host ↔ daemon IPC ([`lp_daemon::protocol`]).
//!
//! Every message carries a version field `"v"` pinned to [`PROTOCOL_VERSION`];
//! crypto/agility is by versioned headers, never negotiation (matches the daemon
//! IPC). A message with an unknown `v` is answered with an error, not
//! best-effort parsed.
//!
//! # Requests (extension → host)
//!
//! Tagged by `"type"`:
//!
//! - `ping` → [`HostResponse::Pong`].
//! - `status` → [`HostResponse::Status`] `{locked, vaults}`. Never blocks: if the
//!   daemon is down it reports `unavailable` + `locked`, it does not hang.
//! - `credentials_for {origin, kind:"login"}` → [`HostResponse::Credentials`] — a
//!   list of **non-secret** candidate descriptors `{item_id, title, username,
//!   vault}` whose stored login URLs match `origin`'s registrable domain.
//!   **Never contains a password.**
//! - `fill {item_id, origin}` → [`HostResponse::Fill`] `{username, password}` for
//!   exactly that item, **re-checked server-side** (in the daemon) that the
//!   item's URL matches `origin`'s registrable domain. The only response carrying
//!   a secret, and only for one user-selected item.
//! - anything else → [`HostResponse::Error`] `{error:"unsupported"}`.
//!
//! When the daemon is locked, `credentials_for`/`fill` return
//! [`HostResponse::Locked`] so the extension can prompt the user to unlock via the
//! CLI/daemon — the host holds no keys and cannot unlock.
//!
//! # Secret hygiene
//!
//! Only [`HostResponse::Fill`] carries a secret. Its `Debug` (and every request's)
//! is derived, but the host never logs a full message body — see the host loop
//! ([`crate::host`]), which logs message *types* only to stderr.

use serde::{Deserialize, Serialize};

/// The extension↔host protocol version carried in every message (`"v"`).
pub const PROTOCOL_VERSION: u32 = 1;

/// A request from the browser extension to the host, tagged by `"type"`.
///
/// Unknown `type` values deserialize to [`HostRequest::Unknown`] via
/// `#[serde(other)]` so the host answers `unsupported` instead of failing to
/// parse (a hostile page cannot crash the host with a bad `type`).
#[derive(Debug, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum HostRequest {
    /// Liveness probe.
    Ping,
    /// Report daemon lock state + vault count without ever blocking the browser.
    Status,
    /// List non-secret login candidates matching `origin`'s registrable domain.
    CredentialsFor {
        /// The page origin (full origin/URL or bare host).
        origin: String,
        /// The credential kind requested. Only `"login"` is supported; other
        /// values yield an empty candidate list.
        #[serde(default)]
        kind: Option<String>,
    },
    /// Reveal one item's `{username, password}` after a server-side origin
    /// re-check. The only request that can return a secret.
    Fill {
        /// The item id (hyphenated) chosen by the user from a prior
        /// `credentials_for` result.
        item_id: String,
        /// The page origin the fill is for (re-validated by the daemon).
        origin: String,
    },
    /// Any unrecognized `type` — answered with `unsupported`.
    #[serde(other)]
    Unknown,
}

/// The versioned request envelope on the wire: `{"v":1, "type":"...", ...}`.
#[derive(Debug, Deserialize)]
pub struct RequestEnvelope {
    /// The protocol version (must equal [`PROTOCOL_VERSION`]).
    pub v: u32,
    /// The request payload (flattened alongside `v`).
    #[serde(flatten)]
    pub request: HostRequest,
}

/// A non-secret login candidate descriptor sent to the extension. **No
/// password** — the extension shows a picker, then requests the secret per item
/// via `fill`.
#[derive(Debug, Clone, Serialize)]
pub struct Candidate {
    /// The item id (hyphenated) — the handle for a later `fill`.
    pub item_id: String,
    /// The item title (for the picker).
    pub title: String,
    /// The login username (non-secret). Empty when unset.
    pub username: String,
    /// The vault name (for display / disambiguation).
    pub vault: String,
}

/// A response from the host to the browser extension, tagged by `"type"`.
///
/// Only [`HostResponse::Fill`] carries a secret value (`password`).
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum HostResponse {
    /// Answer to `ping`.
    Pong,
    /// Answer to `status`: whether the vault is locked and how many vaults exist.
    /// `available = false` means the daemon could not be reached (reported as
    /// locked/unavailable rather than hanging).
    Status {
        /// Whether the daemon session is locked (or unavailable).
        locked: bool,
        /// Whether the daemon was reachable at all.
        available: bool,
        /// Vault count when unlocked; `0` when locked/unavailable.
        vaults: usize,
    },
    /// Answer to `credentials_for`: the non-secret candidates (may be empty).
    Credentials {
        /// The matching candidates.
        candidates: Vec<Candidate>,
    },
    /// Answer to `fill`: the `{username, password}` for one item (the only
    /// secret-bearing response), returned only after the daemon re-validated the
    /// origin↔URL match.
    Fill {
        /// The login username.
        username: String,
        /// The login password (the secret).
        password: String,
    },
    /// The daemon is locked (or has no session): the extension should prompt the
    /// user to unlock via the CLI/daemon. Returned for `credentials_for`/`fill`
    /// when locked. The host cannot unlock.
    Locked,
    /// A structured error. `error` is a short machine token (`"unsupported"`,
    /// `"bad_request"`, `"daemon_error"`, `"origin_mismatch"`); `message` is a
    /// human line and **never** contains a secret.
    Error {
        /// A short machine-readable error token.
        error: String,
        /// A human-readable, secret-free detail line.
        message: String,
    },
}

impl HostResponse {
    /// The `unsupported` error for an unrecognized request `type`.
    #[must_use]
    pub fn unsupported() -> Self {
        HostResponse::Error {
            error: "unsupported".into(),
            message: "unsupported request type".into(),
        }
    }

    /// A `bad_request` error (malformed body / unknown version) with `detail`.
    #[must_use]
    pub fn bad_request(detail: impl Into<String>) -> Self {
        HostResponse::Error {
            error: "bad_request".into(),
            message: detail.into(),
        }
    }
}

/// The versioned response envelope written on the wire: `{"v":1, "type":"...",
/// ...}`.
#[derive(Debug, Serialize)]
pub struct ResponseEnvelope {
    /// The protocol version (always [`PROTOCOL_VERSION`]).
    pub v: u32,
    /// The response payload (flattened alongside `v`).
    #[serde(flatten)]
    pub response: HostResponse,
}

impl ResponseEnvelope {
    /// Wrap `response` in the current-version envelope.
    #[must_use]
    pub fn new(response: HostResponse) -> Self {
        Self {
            v: PROTOCOL_VERSION,
            response,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(json: &str) -> std::result::Result<RequestEnvelope, serde_json::Error> {
        serde_json::from_str(json)
    }

    #[test]
    fn parses_ping() {
        let env = parse(r#"{"v":1,"type":"ping"}"#).unwrap();
        assert_eq!(env.v, 1);
        assert!(matches!(env.request, HostRequest::Ping));
    }

    #[test]
    fn parses_credentials_for() {
        let env = parse(
            r#"{"v":1,"type":"credentials_for","origin":"https://example.com","kind":"login"}"#,
        )
        .unwrap();
        match env.request {
            HostRequest::CredentialsFor { origin, kind } => {
                assert_eq!(origin, "https://example.com");
                assert_eq!(kind.as_deref(), Some("login"));
            }
            other => panic!("wrong variant: {other:?}"),
        }
    }

    #[test]
    fn parses_fill() {
        let env = parse(r#"{"v":1,"type":"fill","item_id":"abc","origin":"https://example.com"}"#)
            .unwrap();
        match env.request {
            HostRequest::Fill { item_id, origin } => {
                assert_eq!(item_id, "abc");
                assert_eq!(origin, "https://example.com");
            }
            other => panic!("wrong variant: {other:?}"),
        }
    }

    #[test]
    fn unknown_type_maps_to_unknown() {
        let env = parse(r#"{"v":1,"type":"exfiltrate_everything"}"#).unwrap();
        assert!(matches!(env.request, HostRequest::Unknown));
    }

    #[test]
    fn credentials_response_has_no_password_field() {
        let resp = HostResponse::Credentials {
            candidates: vec![Candidate {
                item_id: "id".into(),
                title: "GitHub".into(),
                username: "octocat".into(),
                vault: "personal".into(),
            }],
        };
        let json = serde_json::to_string(&ResponseEnvelope::new(resp)).unwrap();
        assert!(!json.contains("password"));
        assert!(json.contains("octocat"));
        assert!(json.contains("\"v\":1"));
    }

    #[test]
    fn fill_response_serializes_username_and_password() {
        let resp = HostResponse::Fill {
            username: "octocat".into(),
            password: "s3cr3t".into(),
        };
        let json = serde_json::to_string(&ResponseEnvelope::new(resp)).unwrap();
        assert!(json.contains("s3cr3t"));
        assert!(json.contains("\"type\":\"fill\""));
    }
}
