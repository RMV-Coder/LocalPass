#![forbid(unsafe_code)]
//! The daemon IPC wire protocol: versioned, length-prefixed JSON.
//!
//! This module is the **canonical protocol spec** (destined for
//! `docs/specs/daemon-ipc.md`). It defines the framing, the versioned envelope,
//! and every request/response the [`crate::client`] sends and the
//! [`crate::server`] answers.
//!
//! # Framing
//!
//! Every message on the wire is:
//!
//! ```text
//!   u32 length (little-endian)  ||  <length> bytes of UTF-8 JSON
//! ```
//!
//! The length prefix counts only the JSON body. A message is refused before
//! allocation if its length exceeds [`MAX_FRAME_LEN`] — a hostile or corrupt
//! peer cannot make us allocate unbounded memory.
//!
//! # Envelope & versioning
//!
//! Both [`Request`] and [`Response`] carry a `"v"` field pinned to
//! [`PROTOCOL_VERSION`]. Crypto agility in LocalPass is by versioned headers,
//! never runtime negotiation (PRD §5.1); the IPC protocol follows the same rule.
//! A peer that sends a `v` we do not understand is rejected with
//! [`Response::Error`] rather than best-effort parsed.
//!
//! # Secret handling on the channel
//!
//! The master password (in [`Request::Unlock`]) and revealed secret values (in
//! [`Response::Item`] with `reveal = true`, and [`Response::Field`]) cross this
//! channel **in the clear**. That is safe **only because the channel is
//! same-user-only** by construction: on Windows the pipe's DACL grants access to
//! the current user's SID alone; on Unix the socket lives in a `0700` directory,
//! is `0600`, and every connection's peer uid is checked against our euid
//! (PRD §7.3, §8 T8). No other process — not another user, not the network —
//! can open the endpoint. The daemon therefore treats the peer as itself.
//!
//! The request/response `Debug` impls are hand-written to render the request
//! *kind* only (never the password or a secret value), so `--verbose` logging
//! and any accidental `{:?}` cannot leak.

use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

/// The protocol version carried in every envelope (`"v"`). Bump on any
/// breaking wire change; a mismatch is a hard error, never negotiated.
pub const PROTOCOL_VERSION: u32 = 1;

/// Maximum accepted JSON body length (16 MiB). Generous for any realistic
/// item/env-set payload, but a hard ceiling so a bad length prefix cannot force
/// an unbounded allocation. Applied on both read directions.
pub const MAX_FRAME_LEN: u32 = 16 * 1024 * 1024;

/// A request from a client to the daemon.
///
/// Every vault-touching request carries `profile`: the absolute profile
/// directory the client is operating on. A single-profile daemon (the MVP)
/// refuses requests whose `profile` does not match the one it was started for
/// (see [`Response::WrongProfile`]).
#[derive(Clone, Serialize, Deserialize)]
#[serde(tag = "kind")]
pub enum Request {
    /// Liveness probe. Answered by [`Response::Pong`] whether locked or not.
    Ping,
    /// Report lock state, profile, and (when unlocked) the vault count.
    Status {
        /// The profile the caller expects this daemon to serve.
        profile: String,
    },
    /// Unlock the session with a master password (and optionally the Secret Key
    /// display string; if omitted the daemon reads `<profile>/secret-key`).
    Unlock {
        /// The profile directory to unlock.
        profile: String,
        /// The master password (crosses the same-user-only channel; see module
        /// docs). Zeroized after use on both ends.
        password: String,
        /// Optional Secret Key display string (`LP1-…`). When `None`, the daemon
        /// loads it from `<profile>/secret-key` itself.
        secret_key: Option<String>,
        /// Optional idle auto-lock override, in seconds (`0` = never). When
        /// `None`, the daemon keeps its configured/default timeout.
        autolock_secs: Option<u64>,
    },
    /// Drop the unlocked session now (zeroizing key material). Idempotent.
    Lock,
    /// List all vaults as `(id, name)` (requires an unlocked session).
    ListVaults {
        /// The profile directory being operated on.
        profile: String,
    },
    /// List all live items in a vault (metadata + non-secret fields only).
    ListItems {
        /// The profile directory being operated on.
        profile: String,
        /// Vault name or id.
        vault: String,
    },
    /// Get one item. With `reveal = true` the response carries secret values.
    GetItem {
        /// The profile directory being operated on.
        profile: String,
        /// Vault name or id.
        vault: String,
        /// Item title or id.
        target: String,
        /// A specific version (default: current) — `None` = current.
        version: Option<i64>,
        /// Whether to include secret field values in the response.
        reveal: bool,
    },
    /// An item's version history (metadata per version; never secret values).
    History {
        /// The profile directory being operated on.
        profile: String,
        /// Vault name or id.
        vault: String,
        /// Item title or id.
        target: String,
    },
    /// Search a vault by title/tag/type; never returns secret values.
    Search {
        /// The profile directory being operated on.
        profile: String,
        /// Vault name or id.
        vault: String,
        /// The query text.
        query: String,
        /// Optional item-type filter (e.g. `"login"`).
        type_filter: Option<String>,
    },
    /// Resolve one field of one item to its plaintext value (for `run`/`env`
    /// reference resolution). Returns [`Response::Field`].
    ResolveField {
        /// The profile directory being operated on.
        profile: String,
        /// Vault name or id.
        vault: String,
        /// Item title or id.
        item: String,
        /// Field name (or env-set entry key).
        field: String,
    },
    /// Fetch an item's **raw canonical payload** (the full `ItemPayload` JSON,
    /// including all secret values). Used by `item edit` proxying: the CLI
    /// overlays its edit flags onto the current payload locally (keeping that
    /// logic in one place) and sends it back via [`Request::UpdateItem`]. Same
    /// secret exposure as [`Request::GetItem`] with `reveal` — it crosses the
    /// same-user-only channel.
    GetRawPayload {
        /// The profile directory being operated on.
        profile: String,
        /// Vault name or id.
        vault: String,
        /// Item title or id.
        target: String,
    },
    /// Create an item from a canonical item payload (the JSON the CLI builds).
    CreateItem {
        /// The profile directory being operated on.
        profile: String,
        /// Vault name or id.
        vault: String,
        /// The full item payload as canonical JSON (mirrors `ItemPayload`).
        payload: serde_json::Value,
    },
    /// Update an item (creates a new version) from a canonical payload.
    UpdateItem {
        /// The profile directory being operated on.
        profile: String,
        /// Vault name or id.
        vault: String,
        /// Item title or id.
        target: String,
        /// The full replacement payload as canonical JSON.
        payload: serde_json::Value,
    },
    /// Move an item to the trash.
    DeleteItem {
        /// The profile directory being operated on.
        profile: String,
        /// Vault name or id.
        vault: String,
        /// Item title or id.
        target: String,
    },
    /// Restore a prior version as a new current version.
    RestoreVersion {
        /// The profile directory being operated on.
        profile: String,
        /// Vault name or id.
        vault: String,
        /// Item title or id.
        target: String,
        /// The version number to restore.
        version: i64,
    },
    /// Terminate the daemon: drop the session and exit, removing the endpoint.
    Shutdown,
}

impl Request {
    /// A short, non-secret label for logging (`--verbose` logs request kinds
    /// and timings only, never arguments or secrets).
    #[must_use]
    pub fn kind(&self) -> &'static str {
        match self {
            Request::Ping => "Ping",
            Request::Status { .. } => "Status",
            Request::Unlock { .. } => "Unlock",
            Request::Lock => "Lock",
            Request::ListVaults { .. } => "ListVaults",
            Request::ListItems { .. } => "ListItems",
            Request::GetItem { .. } => "GetItem",
            Request::History { .. } => "History",
            Request::Search { .. } => "Search",
            Request::ResolveField { .. } => "ResolveField",
            Request::GetRawPayload { .. } => "GetRawPayload",
            Request::CreateItem { .. } => "CreateItem",
            Request::UpdateItem { .. } => "UpdateItem",
            Request::DeleteItem { .. } => "DeleteItem",
            Request::RestoreVersion { .. } => "RestoreVersion",
            Request::Shutdown => "Shutdown",
        }
    }

    /// Best-effort zeroize of the in-memory password after the request has been
    /// handled. Only [`Request::Unlock`] carries one.
    pub fn zeroize_secrets(&mut self) {
        if let Request::Unlock {
            password,
            secret_key,
            ..
        } = self
        {
            password.zeroize();
            if let Some(sk) = secret_key {
                sk.zeroize();
            }
        }
    }
}

/// A `Debug` that never prints the password or secret payloads — only the kind.
impl core::fmt::Debug for Request {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Request")
            .field("kind", &self.kind())
            .finish()
    }
}

/// One field of an item as sent to the client. Secret values are already
/// masked by the server unless the request asked to reveal them, so the client
/// renders exactly what it receives.
#[derive(Clone, Serialize, Deserialize)]
pub struct WireField {
    /// The field name.
    pub name: String,
    /// The (possibly-masked) value.
    pub value: String,
    /// Whether the field is secret (masked when not revealed).
    pub secret: bool,
}

/// A single item rendered for the wire (metadata + flattened display fields).
///
/// This mirrors the CLI's own display model so the client can render items
/// identically whether it went through the daemon or unlocked directly.
#[derive(Clone, Serialize, Deserialize)]
pub struct WireItem {
    /// Hyphenated item id.
    pub id: String,
    /// The item title.
    pub title: String,
    /// The item type string (e.g. `"login"`).
    pub type_str: String,
    /// The current (or requested) version number.
    pub version: i64,
    /// Creation time (unix millis).
    pub created_at: i64,
    /// Last-update time (unix millis).
    pub updated_at: i64,
    /// Tags.
    pub tags: Vec<String>,
    /// Favorite flag.
    pub favorite: bool,
    /// Notes body.
    pub notes: String,
    /// Flattened display fields (already masked unless revealed).
    pub fields: Vec<WireField>,
}

/// One entry in an item's version history (metadata only; no field values).
#[derive(Clone, Serialize, Deserialize)]
pub struct WireVersion {
    /// The version number.
    pub version: i64,
    /// When this version was written (unix millis).
    pub created_at: i64,
    /// The title at this version.
    pub title: String,
    /// The item type string at this version.
    pub type_str: String,
}

/// A compact item summary for `list`/`search` (never carries field values).
#[derive(Clone, Serialize, Deserialize)]
pub struct WireItemSummary {
    /// Hyphenated item id.
    pub id: String,
    /// The item title.
    pub title: String,
    /// The item type string.
    pub type_str: String,
    /// Last-update time (unix millis).
    pub updated_at: i64,
    /// Tags.
    pub tags: Vec<String>,
}

/// The unlock/lock state reported by [`Response::Status`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum LockState {
    /// A session is held (key material is in memory).
    Unlocked,
    /// No session is held.
    Locked,
}

/// A response from the daemon to the client.
#[derive(Clone, Serialize, Deserialize)]
#[serde(tag = "kind")]
pub enum Response {
    /// Answer to [`Request::Ping`].
    Pong,
    /// Answer to [`Request::Status`].
    Status {
        /// Current lock state.
        state: LockState,
        /// The profile this daemon serves (absolute path).
        profile: String,
        /// Vault count when unlocked; `None` when locked.
        vault_count: Option<usize>,
        /// The effective idle auto-lock timeout in seconds (`0` = never).
        autolock_secs: u64,
        /// Seconds remaining until idle auto-lock when unlocked (`None` when
        /// locked or when auto-lock is disabled).
        idle_remaining_secs: Option<u64>,
        /// The SSH agent endpoint label (pipe name / socket path) when the agent
        /// is enabled, else `None` (started with `--no-ssh-agent`).
        ssh_agent_endpoint: Option<String>,
        /// How many SSH identities the agent is currently serving (0 when locked
        /// or when the agent is disabled).
        ssh_identity_count: usize,
    },
    /// A generic "did it" acknowledgement (Unlock, Lock, mutations).
    Ok {
        /// An optional human message (e.g. `"unlocked"`, `"version 2"`), never
        /// a secret value.
        message: Option<String>,
    },
    /// A list of vaults as `(id, name)`.
    Vaults {
        /// The vaults.
        vaults: Vec<(String, String)>,
    },
    /// A list of item summaries (list/search).
    Items {
        /// The summaries.
        items: Vec<WireItemSummary>,
    },
    /// An item's version history (metadata per version).
    Versions {
        /// The item id (hyphenated).
        id: String,
        /// The versions, oldest first.
        versions: Vec<WireVersion>,
    },
    /// A single full item. Boxed so the [`Response`] enum stays small (a
    /// `WireItem` is the largest variant by far; boxing it keeps every
    /// `Result<_, Response>` in the engine cheap to move).
    Item {
        /// The item.
        item: Box<WireItem>,
    },
    /// A single resolved field value (ResolveField). Carries a plaintext secret
    /// value — same exposure as the CLI's own `--field` / reference path.
    Field {
        /// The resolved value.
        value: String,
    },
    /// An item's raw canonical payload JSON (GetRawPayload). Carries every
    /// secret value in the clear — for `item edit` overlay on the client side.
    RawPayload {
        /// The item id (hyphenated), so the client can address the update.
        id: String,
        /// The full canonical `ItemPayload` as JSON.
        payload: serde_json::Value,
    },
    /// The requested operation needs an unlocked session and none is held.
    Locked,
    /// This daemon serves a different profile than the request named.
    WrongProfile {
        /// The profile this daemon actually serves.
        expected: String,
    },
    /// A structured error. `auth = true` marks a wrong password / Secret Key
    /// (so the client can map it to the auth exit code); otherwise it is a
    /// usage/not-found style error. The message never contains a secret.
    Error {
        /// Whether this is an authentication failure (wrong password/Secret Key).
        auth: bool,
        /// A one-line, secret-free message.
        message: String,
    },
}

impl Response {
    /// A short, non-secret label for logging.
    #[must_use]
    pub fn kind(&self) -> &'static str {
        match self {
            Response::Pong => "Pong",
            Response::Status { .. } => "Status",
            Response::Ok { .. } => "Ok",
            Response::Vaults { .. } => "Vaults",
            Response::Items { .. } => "Items",
            Response::Versions { .. } => "Versions",
            Response::Item { .. } => "Item",
            Response::Field { .. } => "Field",
            Response::RawPayload { .. } => "RawPayload",
            Response::Locked => "Locked",
            Response::WrongProfile { .. } => "WrongProfile",
            Response::Error { .. } => "Error",
        }
    }
}

/// A `Debug` that renders the response kind only (a `Field`/`Item` response
/// carries plaintext secrets when revealed; never let `{:?}` print them).
impl core::fmt::Debug for Response {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Response")
            .field("kind", &self.kind())
            .finish()
    }
}

/// The versioned request envelope actually placed on the wire: `{"v":1, ...}`.
#[derive(Serialize, Deserialize)]
pub(crate) struct RequestEnvelope {
    pub(crate) v: u32,
    #[serde(flatten)]
    pub(crate) request: Request,
}

/// The versioned response envelope actually placed on the wire.
#[derive(Serialize, Deserialize)]
pub(crate) struct ResponseEnvelope {
    pub(crate) v: u32,
    #[serde(flatten)]
    pub(crate) response: Response,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_debug_never_prints_password() {
        let req = Request::Unlock {
            profile: "/tmp/p".into(),
            password: "hunter2".into(),
            secret_key: Some("LP1-SECRET".into()),
            autolock_secs: Some(600),
        };
        let dbg = format!("{req:?}");
        assert!(!dbg.contains("hunter2"));
        assert!(!dbg.contains("LP1-SECRET"));
        assert!(dbg.contains("Unlock"));
    }

    #[test]
    fn response_debug_never_prints_field_value() {
        let resp = Response::Field {
            value: "s3cr3t-value".into(),
        };
        let dbg = format!("{resp:?}");
        assert!(!dbg.contains("s3cr3t-value"));
        assert!(dbg.contains("Field"));
    }

    #[test]
    fn zeroize_clears_unlock_password() {
        let mut req = Request::Unlock {
            profile: "/tmp/p".into(),
            password: "hunter2".into(),
            secret_key: Some("LP1-X".into()),
            autolock_secs: None,
        };
        req.zeroize_secrets();
        if let Request::Unlock {
            password,
            secret_key,
            ..
        } = &req
        {
            assert!(password.is_empty());
            assert_eq!(secret_key.as_deref(), Some(""));
        } else {
            panic!("still unlock");
        }
    }

    #[test]
    fn envelope_roundtrips_with_version() {
        let env = RequestEnvelope {
            v: PROTOCOL_VERSION,
            request: Request::Ping,
        };
        let bytes = serde_json::to_vec(&env).unwrap();
        let s = String::from_utf8(bytes.clone()).unwrap();
        assert!(s.contains("\"v\":1"));
        assert!(s.contains("\"kind\":\"Ping\""));
        let back: RequestEnvelope = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(back.v, PROTOCOL_VERSION);
        assert!(matches!(back.request, Request::Ping));
    }
}
