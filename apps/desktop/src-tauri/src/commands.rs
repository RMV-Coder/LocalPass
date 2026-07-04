// SPDX-License-Identifier: MPL-2.0
// This file is part of the LocalPass desktop GUI. See apps/desktop/LICENSE.

//! The Tauri command surface — **the only bridge** between the webview and any
//! secret handling.
//!
//! # The security boundary (PRD §6.5 — the hard rule)
//!
//! The webview *renders and requests*; every secret stays in Rust. These
//! `#[tauri::command]` functions are the complete set of operations JS can
//! invoke. Their return types are the masked view models in [`crate::model`],
//! and the split is deliberate:
//!
//! - [`status`], [`list_vaults`], [`list_items`], [`get_item`], [`search`] never
//!   return a secret value. `get_item` calls the daemon with `reveal = false`
//!   **and** re-masks through [`crate::model::item_view_masked`], which drops any
//!   secret field's value entirely — double-locked.
//! - [`reveal_field`] and [`totp`] are the **only** commands that return a secret
//!   value, and only for a single field/item, on an explicit user gesture (a
//!   Reveal/Copy click or opening a TOTP item). They return the value straight
//!   to the caller; the webview holds it in component-local state, never a store,
//!   and clears it on navigation (enforced on the Svelte side).
//! - [`generate_password`] / [`generate_passphrase`] compute locally (no daemon;
//!   see [`crate::generate`]); the generated secret is likewise transient.
//!
//! The master password crosses exactly once, in [`unlock`], straight into the
//! daemon `Unlock` request, and is zeroized immediately after. No key material
//! or password is ever stored in the backend beyond that call.

use lp_daemon::protocol::{Request, Response};
use zeroize::Zeroize;

use crate::daemon::{self, DaemonError};
use crate::model::{
    self, GeneratedView, ItemSummaryView, ItemView, SessionState, TotpView, VaultView,
};

/// Map a [`DaemonError`] into the `SessionState`-flavoured error the UI shows.
/// `NotRunning` becomes [`SessionState::NoDaemon`]; a transport error becomes a
/// secret-free [`SessionState::Error`]. Both are serialized as the command's
/// `Err` payload so the frontend can render the right screen.
fn daemon_err_state(e: &DaemonError) -> SessionState {
    match e {
        DaemonError::NotRunning => SessionState::NoDaemon,
        DaemonError::Transport(m) => SessionState::Error { message: m.clone() },
    }
}

/// Turn a daemon [`Response::Error`] / `Locked` / `WrongProfile` into a
/// human-readable, secret-free command error string. Returns `Ok(())` for any
/// non-error response.
fn check_response_error(resp: &Response) -> Result<(), String> {
    match resp {
        Response::Error { message, .. } => Err(message.clone()),
        Response::Locked => Err("the vault is locked".into()),
        Response::WrongProfile { expected } => Err(format!(
            "the running daemon serves a different profile ({expected})"
        )),
        _ => Ok(()),
    }
}

/// Report the current session state (locked / unlocked / no-daemon / …).
///
/// This is the command the UI polls to decide which screen to show. It never
/// returns a secret. A `NoDaemon` / transport problem is surfaced as an `Ok`
/// [`SessionState`] (not an `Err`), because "no daemon" is a normal UI state,
/// not a failure — the unlock screen shows guidance.
#[tauri::command]
pub fn status() -> SessionState {
    let profile = match daemon::profile_string() {
        Ok(p) => p,
        Err(m) => return SessionState::Error { message: m },
    };
    match daemon::call(&Request::Status { profile }) {
        Ok(resp) => model::session_state_from_status(&resp),
        Err(DaemonError::NotRunning) => SessionState::NoDaemon,
        Err(DaemonError::Transport(m)) => SessionState::Error { message: m },
    }
}

/// Unlock the vault with the master password.
///
/// The password is forwarded straight into the daemon `Unlock` request and
/// **zeroized here immediately after** — the backend keeps no copy. The daemon
/// reads the on-device Secret Key from `<profile>/secret-key` itself (we pass
/// `secret_key: None`). On success returns the fresh [`SessionState`]; on a
/// wrong password returns an `Err` with a secret-free message the UI shows in
/// the error region (aria-live).
#[tauri::command]
pub fn unlock(mut password: String) -> Result<SessionState, String> {
    let profile = daemon::profile_string()?;
    let req = Request::Unlock {
        profile,
        password: password.clone(),
        secret_key: None,
        autolock_secs: None,
    };
    // Zeroize our local copies of the password as soon as the request owns it.
    password.zeroize();

    let result = daemon::call(&req);
    // The request struct still holds a password copy; drop it zeroized.
    let mut req = req;
    req.zeroize_secrets();

    match result {
        Ok(Response::Ok { .. }) => Ok(status()),
        Ok(Response::Error { message, .. }) => Err(message),
        Ok(Response::Locked) => Err("unlock failed: the vault is still locked".into()),
        Ok(Response::WrongProfile { expected }) => Err(format!(
            "the running daemon serves a different profile ({expected})"
        )),
        Ok(other) => Err(format!("unexpected daemon response: {}", other.kind())),
        Err(e) => Err(daemon_err_state(&e).error_message()),
    }
}

/// Lock the vault now (zeroizing key material in the daemon). Idempotent.
#[tauri::command]
pub fn lock() -> Result<SessionState, String> {
    match daemon::call(&Request::Lock) {
        Ok(_) => Ok(status()),
        Err(DaemonError::NotRunning) => Ok(SessionState::NoDaemon),
        Err(e) => Err(e.to_string()),
    }
}

/// List the vaults for the sidebar. Requires an unlocked session.
#[tauri::command]
pub fn list_vaults() -> Result<Vec<VaultView>, String> {
    let profile = daemon::profile_string()?;
    let resp = daemon::call(&Request::ListVaults { profile }).map_err(|e| e.to_string())?;
    check_response_error(&resp)?;
    match resp {
        Response::Vaults { vaults } => Ok(vaults
            .into_iter()
            .map(|(id, name)| VaultView { id, name })
            .collect()),
        other => Err(format!("unexpected daemon response: {}", other.kind())),
    }
}

/// List the items in `vault` (metadata + non-secret fields only).
#[tauri::command]
pub fn list_items(vault: String) -> Result<Vec<ItemSummaryView>, String> {
    let profile = daemon::profile_string()?;
    let resp = daemon::call(&Request::ListItems { profile, vault }).map_err(|e| e.to_string())?;
    check_response_error(&resp)?;
    match resp {
        Response::Items { items } => Ok(items.iter().map(model::summary_view).collect()),
        other => Err(format!("unexpected daemon response: {}", other.kind())),
    }
}

/// Get one item as a **masked** detail view — secret field values are NOT
/// included. The daemon is asked with `reveal = false`, and the result is
/// re-masked through [`model::item_view_masked`] for defense in depth.
#[tauri::command]
pub fn get_item(vault: String, id: String) -> Result<ItemView, String> {
    let profile = daemon::profile_string()?;
    let resp = daemon::call(&Request::GetItem {
        profile,
        vault,
        target: id,
        version: None,
        reveal: false,
    })
    .map_err(|e| e.to_string())?;
    check_response_error(&resp)?;
    match resp {
        Response::Item { item } => Ok(model::item_view_masked(&item)),
        other => Err(format!("unexpected daemon response: {}", other.kind())),
    }
}

/// Reveal exactly ONE secret field's value, on an explicit user gesture.
///
/// This is one of only two commands that return a secret. It fetches the item
/// with `reveal = true` and extracts the single named field, so the response
/// carries just that one value to the webview — which holds it transiently and
/// clears it on navigation.
#[tauri::command]
pub fn reveal_field(vault: String, id: String, field: String) -> Result<String, String> {
    let profile = daemon::profile_string()?;
    let resp = daemon::call(&Request::GetItem {
        profile,
        vault,
        target: id,
        version: None,
        reveal: true,
    })
    .map_err(|e| e.to_string())?;
    check_response_error(&resp)?;
    match resp {
        Response::Item { item } => model::find_field_value(&item, &field)
            .map(std::string::ToString::to_string)
            .ok_or_else(|| format!("no field named {field:?} on this item")),
        other => Err(format!("unexpected daemon response: {}", other.kind())),
    }
}

/// Full-text search within `vault`. Never returns secret values.
#[tauri::command]
pub fn search(vault: String, query: String) -> Result<Vec<ItemSummaryView>, String> {
    let profile = daemon::profile_string()?;
    let resp = daemon::call(&Request::Search {
        profile,
        vault,
        query,
        type_filter: None,
    })
    .map_err(|e| e.to_string())?;
    check_response_error(&resp)?;
    match resp {
        Response::Items { items } => Ok(items.iter().map(model::summary_view).collect()),
        other => Err(format!("unexpected daemon response: {}", other.kind())),
    }
}

/// Compute the live TOTP code for a `totp` item. The TOTP *secret* stays inside
/// the daemon — only the finished code and countdown metadata cross the wire.
#[tauri::command]
pub fn totp(vault: String, id: String) -> Result<TotpView, String> {
    let profile = daemon::profile_string()?;
    let resp = daemon::call(&Request::Totp {
        profile,
        vault,
        target: id,
    })
    .map_err(|e| e.to_string())?;
    check_response_error(&resp)?;
    match resp {
        Response::Totp {
            code,
            seconds_remaining,
            period,
            digits,
            algo,
        } => Ok(TotpView {
            code,
            seconds_remaining,
            period,
            digits,
            algo,
        }),
        other => Err(format!("unexpected daemon response: {}", other.kind())),
    }
}

/// Generate a random-character password locally (no daemon).
#[tauri::command]
pub fn generate_password(length: usize, symbols: bool) -> Result<GeneratedView, String> {
    crate::generate::password(length, symbols)
}

/// Generate an EFF-wordlist passphrase locally (no daemon).
#[tauri::command]
pub fn generate_passphrase(words: usize, separator: String) -> Result<GeneratedView, String> {
    crate::generate::passphrase(words, &separator)
}

impl SessionState {
    /// A secret-free message for the error-state variants (used when we need a
    /// `String` rather than a `SessionState`).
    fn error_message(&self) -> String {
        match self {
            SessionState::NoDaemon => "no LocalPass daemon is running".into(),
            SessionState::Error { message } => message.clone(),
            _ => "unexpected state".into(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn daemon_err_state_maps_notrunning_to_nodaemon() {
        assert_eq!(
            daemon_err_state(&DaemonError::NotRunning),
            SessionState::NoDaemon
        );
        assert_eq!(
            daemon_err_state(&DaemonError::Transport("x".into())),
            SessionState::Error {
                message: "x".into()
            }
        );
    }

    #[test]
    fn check_response_error_maps_error_variants() {
        assert!(check_response_error(&Response::Locked).is_err());
        assert!(
            check_response_error(&Response::Error {
                auth: true,
                message: "wrong password".into()
            })
            .is_err()
        );
        assert!(check_response_error(&Response::Pong).is_ok());
    }

    #[test]
    fn generate_commands_are_pure_and_work() {
        let p = generate_password(20, true).unwrap();
        assert_eq!(p.secret.chars().count(), 20);
        let pp = generate_passphrase(4, "-".into()).unwrap();
        assert_eq!(pp.secret.split('-').count(), 4);
    }
}
