// SPDX-License-Identifier: MPL-2.0
// This file is part of the LocalPass desktop GUI. See apps/desktop/LICENSE.

//! View models returned by the Tauri commands, and the **pure** mapping from
//! [`lp_daemon`] wire types into them.
//!
//! # The secret boundary lives here
//!
//! These types are what cross into the webview. The masked item view
//! ([`ItemView`]) is built by [`item_view_masked`], which **drops every secret
//! field's value entirely** (replacing it with the empty string and marking it
//! `secret = true`), so a `get_item` response can never carry a secret into JS —
//! even though the underlying daemon channel *could* return one. A secret value
//! reaches the webview only through the dedicated `reveal_field` / `totp`
//! commands, on an explicit user gesture (PRD §6.5). Keeping the masking in one
//! small, `#[must_use]`, unit-tested function is how that boundary is enforced
//! rather than merely asserted.
//!
//! All functions in this module are pure (no IO, no daemon), so they are cheap
//! to unit-test exhaustively — see the tests at the bottom.

use lp_daemon::protocol::{LockState, Response, WireField, WireItem, WireItemSummary};
use serde::Serialize;

/// The lock/availability state the UI switches on. `serde` renders this as a
/// lowercase tag the Svelte store matches (`"unlocked"`, `"locked"`,
/// `"no_daemon"`, `"wrong_profile"`, `"error"`).
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum SessionState {
    /// A session is held; the vault UI can be shown.
    Unlocked {
        /// Number of vaults (from the daemon status).
        vault_count: usize,
        /// The profile the daemon serves (absolute path, display only).
        profile: String,
        /// Seconds until idle auto-lock (`None` if auto-lock disabled).
        idle_remaining_secs: Option<u64>,
    },
    /// A daemon is running but no session is held — show the unlock screen.
    Locked {
        /// The profile the daemon serves.
        profile: String,
    },
    /// No daemon is reachable — show the "start the daemon" guidance.
    NoDaemon,
    /// A daemon is running for this profile but **no account exists yet** — show
    /// the onboarding (account-creation) flow instead of the unlock screen. This
    /// is detected by the command layer (the `account.localpass` file is absent),
    /// not reported by the daemon's status.
    NoAccount {
        /// The profile the account would be created in.
        profile: String,
    },
    /// A daemon is running but serving a different profile than ours.
    WrongProfile {
        /// The profile the running daemon actually serves.
        expected: String,
    },
    /// An unexpected transport/daemon error (message is secret-free).
    Error {
        /// A one-line, secret-free message.
        message: String,
    },
}

/// A vault entry for the sidebar.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct VaultView {
    /// The vault id (hyphenated).
    pub id: String,
    /// The human vault name.
    pub name: String,
}

/// A compact item row for the list / search results.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ItemSummaryView {
    /// Item id (hyphenated).
    pub id: String,
    /// Item title.
    pub title: String,
    /// Item type string (e.g. `"login"`).
    pub type_str: String,
    /// Last-update time (unix millis).
    pub updated_at: i64,
    /// Tags.
    pub tags: Vec<String>,
}

/// One field in the masked item detail view.
///
/// For a secret field, `value` is **always empty** in this view — the real
/// value is fetched separately via `reveal_field`. For a non-secret field the
/// value is present (usernames, URLs, endpoints are not secrets).
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct FieldView {
    /// The field name.
    pub name: String,
    /// The non-secret value, or `""` for a secret field (masked).
    pub value: String,
    /// Whether this field holds a secret (renders masked, with a Reveal button).
    pub secret: bool,
}

/// The masked item detail view sent to the webview by `get_item`.
///
/// Secret field values are **not** included (see [`item_view_masked`]).
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ItemView {
    /// Item id (hyphenated).
    pub id: String,
    /// Item title.
    pub title: String,
    /// Item type string.
    pub type_str: String,
    /// Current/selected version number.
    pub version: i64,
    /// Creation time (unix millis).
    pub created_at: i64,
    /// Last-update time (unix millis).
    pub updated_at: i64,
    /// Tags.
    pub tags: Vec<String>,
    /// Favorite flag.
    pub favorite: bool,
    /// Notes body (Markdown for notes; non-secret metadata for others).
    pub notes: String,
    /// The item's fields, with secret values stripped.
    pub fields: Vec<FieldView>,
}

/// The result of `totp` — the finished code and its countdown metadata. The
/// TOTP *secret* never reaches here; the daemon computed the code.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct TotpView {
    /// The current zero-padded code.
    pub code: String,
    /// Whole seconds remaining in the current window.
    pub seconds_remaining: u32,
    /// The time step in seconds (e.g. 30).
    pub period: u32,
    /// Digit count.
    pub digits: u32,
    /// Algorithm token (`SHA1` / `SHA256` / `SHA512`).
    pub algo: String,
}

/// A generated secret plus its exact entropy in bits (from the generator).
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct GeneratedView {
    /// The generated secret. This *is* a secret value; it exists in JS only
    /// transiently in the generator screen's local state and is cleared on
    /// navigation, exactly like a revealed field.
    pub secret: String,
    /// Entropy of the generation process, in bits.
    pub entropy_bits: f64,
}

/// The result of a successful account creation, returned once to the webview so
/// it can render the Emergency Kit.
///
/// The `secret_key` here is the single-use display string minted by the daemon;
/// it crosses to the webview **exactly once** (the onboarding Emergency Kit
/// step), lives only in component-local state, and is cleared on navigation —
/// the same discipline a revealed field / generated password follows. It is
/// never stored in the backend and never re-fetchable.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct CreatedAccount {
    /// The Secret Key display string (`LP1-…`), shown once for the Emergency Kit.
    pub secret_key: String,
    /// The profile the account was created in (absolute path, display only).
    pub profile: String,
    /// The number of vaults created (the default `personal` vault → `1`).
    pub vault_count: usize,
}

/// Map a masked [`WireField`] to a [`FieldView`], **dropping the value of any
/// secret field**. This is the single choke point that guarantees no secret
/// value leaves the backend through `get_item`.
#[must_use]
fn field_view_masked(f: &WireField) -> FieldView {
    FieldView {
        name: f.name.clone(),
        // A secret field's value is stripped here regardless of what the daemon
        // sent (get_item calls the daemon with reveal=false anyway, so it is
        // already masked; this is belt-and-suspenders — the value never crosses
        // this function for a secret field).
        value: if f.secret {
            String::new()
        } else {
            f.value.clone()
        },
        secret: f.secret,
    }
}

/// Build the masked [`ItemView`] from a daemon [`WireItem`]. Secret field values
/// are stripped (see [`field_view_masked`]).
#[must_use]
pub fn item_view_masked(item: &WireItem) -> ItemView {
    ItemView {
        id: item.id.clone(),
        title: item.title.clone(),
        type_str: item.type_str.clone(),
        version: item.version,
        created_at: item.created_at,
        updated_at: item.updated_at,
        tags: item.tags.clone(),
        favorite: item.favorite,
        notes: item.notes.clone(),
        fields: item.fields.iter().map(field_view_masked).collect(),
    }
}

/// Map a daemon [`WireItemSummary`] to an [`ItemSummaryView`].
#[must_use]
pub fn summary_view(s: &WireItemSummary) -> ItemSummaryView {
    ItemSummaryView {
        id: s.id.clone(),
        title: s.title.clone(),
        type_str: s.type_str.clone(),
        updated_at: s.updated_at,
        tags: s.tags.clone(),
    }
}

/// Look up one field by name in a daemon [`WireItem`] (case-sensitive first,
/// then case-insensitive) — matches the CLI's `find_field` semantics. Returns
/// the *revealed* value (this is only ever called on a `reveal`-true response).
#[must_use]
pub fn find_field_value<'a>(item: &'a WireItem, name: &str) -> Option<&'a str> {
    item.fields
        .iter()
        .find(|f| f.name == name)
        .or_else(|| {
            item.fields
                .iter()
                .find(|f| f.name.eq_ignore_ascii_case(name))
        })
        .map(|f| f.value.as_str())
}

/// Map a daemon [`Response::Status`] into the [`SessionState`] the UI switches
/// on. A non-status response is mapped to a secret-free [`SessionState::Error`].
#[must_use]
pub fn session_state_from_status(resp: &Response) -> SessionState {
    match resp {
        Response::Status {
            state: LockState::Unlocked,
            profile,
            vault_count,
            idle_remaining_secs,
            ..
        } => SessionState::Unlocked {
            vault_count: vault_count.unwrap_or(0),
            profile: profile.clone(),
            idle_remaining_secs: *idle_remaining_secs,
        },
        Response::Status {
            state: LockState::Locked,
            profile,
            ..
        } => SessionState::Locked {
            profile: profile.clone(),
        },
        Response::WrongProfile { expected } => SessionState::WrongProfile {
            expected: expected.clone(),
        },
        Response::Locked => SessionState::Locked {
            profile: String::new(),
        },
        Response::Error { message, .. } => SessionState::Error {
            message: message.clone(),
        },
        other => SessionState::Error {
            message: format!("unexpected daemon response: {}", other.kind()),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use lp_daemon::protocol::{WireField, WireItem};

    fn wire_item_with_secret() -> WireItem {
        WireItem {
            id: "11112222-3333-4444-5555-666677778888".into(),
            title: "ACME prod DB".into(),
            type_str: "login".into(),
            version: 3,
            created_at: 1_000,
            updated_at: 2_000,
            tags: vec!["prod".into(), "db".into()],
            favorite: true,
            notes: "internal".into(),
            fields: vec![
                WireField {
                    name: "username".into(),
                    value: "svc_acme".into(),
                    secret: false,
                },
                WireField {
                    // Simulate a daemon that (incorrectly or via a reveal path)
                    // handed us a secret value — the masked view MUST drop it.
                    name: "password".into(),
                    value: "s3cr3t-should-be-dropped".into(),
                    secret: true,
                },
                WireField {
                    name: "url".into(),
                    value: "https://acme.example".into(),
                    secret: false,
                },
            ],
        }
    }

    #[test]
    fn masked_view_drops_secret_values_but_keeps_nonsecret() {
        let view = item_view_masked(&wire_item_with_secret());
        let pw = view.fields.iter().find(|f| f.name == "password").unwrap();
        assert!(pw.secret);
        assert_eq!(
            pw.value, "",
            "secret value must be stripped from masked view"
        );
        let user = view.fields.iter().find(|f| f.name == "username").unwrap();
        assert!(!user.secret);
        assert_eq!(user.value, "svc_acme", "non-secret value kept");
        // Metadata preserved.
        assert_eq!(view.title, "ACME prod DB");
        assert_eq!(view.version, 3);
        assert!(view.favorite);
        assert_eq!(view.tags, vec!["prod".to_string(), "db".to_string()]);
    }

    #[test]
    fn masked_view_never_serializes_a_secret_value() {
        // Belt-and-suspenders: the JSON that crosses to the webview must not
        // contain the secret string, even if the daemon leaked it in.
        let view = item_view_masked(&wire_item_with_secret());
        let json = serde_json::to_string(&view).unwrap();
        assert!(
            !json.contains("s3cr3t-should-be-dropped"),
            "masked item JSON leaked a secret: {json}"
        );
        assert!(json.contains("svc_acme"));
    }

    #[test]
    fn find_field_is_case_insensitive_fallback() {
        let item = wire_item_with_secret();
        assert_eq!(
            find_field_value(&item, "password"),
            Some("s3cr3t-should-be-dropped")
        );
        assert_eq!(
            find_field_value(&item, "PASSWORD"),
            Some("s3cr3t-should-be-dropped")
        );
        assert_eq!(find_field_value(&item, "nope"), None);
    }

    #[test]
    fn status_unlocked_maps_to_unlocked_state() {
        let resp = Response::Status {
            state: LockState::Unlocked,
            profile: "/home/u/.local/share/localpass".into(),
            vault_count: Some(2),
            autolock_secs: 600,
            idle_remaining_secs: Some(540),
            ssh_agent_endpoint: None,
            ssh_identity_count: 0,
        };
        let st = session_state_from_status(&resp);
        assert_eq!(
            st,
            SessionState::Unlocked {
                vault_count: 2,
                profile: "/home/u/.local/share/localpass".into(),
                idle_remaining_secs: Some(540),
            }
        );
    }

    #[test]
    fn status_locked_maps_to_locked_state() {
        let resp = Response::Status {
            state: LockState::Locked,
            profile: "/p".into(),
            vault_count: None,
            autolock_secs: 600,
            idle_remaining_secs: None,
            ssh_agent_endpoint: None,
            ssh_identity_count: 0,
        };
        assert_eq!(
            session_state_from_status(&resp),
            SessionState::Locked {
                profile: "/p".into()
            }
        );
    }

    #[test]
    fn wrong_profile_and_error_map_through() {
        assert_eq!(
            session_state_from_status(&Response::WrongProfile {
                expected: "/other".into()
            }),
            SessionState::WrongProfile {
                expected: "/other".into()
            }
        );
        assert_eq!(
            session_state_from_status(&Response::Error {
                auth: false,
                message: "boom".into()
            }),
            SessionState::Error {
                message: "boom".into()
            }
        );
    }

    #[test]
    fn session_state_serializes_with_snake_case_tag() {
        let json = serde_json::to_string(&SessionState::NoDaemon).unwrap();
        assert_eq!(json, r#"{"state":"no_daemon"}"#);
        let json = serde_json::to_string(&SessionState::Locked {
            profile: "/p".into(),
        })
        .unwrap();
        assert!(json.contains(r#""state":"locked""#));
    }

    #[test]
    fn no_account_serializes_with_snake_case_tag_and_profile() {
        let json = serde_json::to_string(&SessionState::NoAccount {
            profile: "/home/u/.local/share/localpass".into(),
        })
        .unwrap();
        assert!(json.contains(r#""state":"no_account""#));
        assert!(json.contains("/home/u/.local/share/localpass"));
    }
}
