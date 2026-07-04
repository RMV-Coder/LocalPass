// SPDX-License-Identifier: MPL-2.0
// This file is part of the LocalPass desktop GUI. See apps/desktop/LICENSE.

//! The daemon-client glue: profile resolution and one-shot request helpers.
//!
//! The Tauri backend is a **daemon client**, exactly like the CLI and the
//! browser native-messaging host (LESSONS.md, PRD §7.1). It never holds an
//! `lp_vault::Session`; it opens a short-lived [`lp_daemon::client::Client`] per
//! request over the same-user-only IPC channel and forwards a small,
//! read-and-fill command set. The only secret it ever *forwards* is the master
//! password on unlock, which goes straight into the daemon's `Unlock` request
//! and is zeroized immediately after (see [`crate::commands::unlock`]).
//!
//! If no daemon is running, or it is locked / serving another profile, the
//! request helpers return a typed error the command layer maps to a
//! [`crate::model::SessionState`] the UI switches on — never a hang, never a
//! crash (PRD §4.7 "never blocks").

use std::path::PathBuf;

use lp_daemon::client::Client;
use lp_daemon::protocol::{Request, Response};

/// A daemon-call failure the command layer can map to a UI state.
#[derive(Debug)]
pub enum DaemonError {
    /// No daemon is reachable — the UI shows "start the daemon" guidance.
    NotRunning,
    /// A transport/protocol failure (message is secret-free).
    Transport(String),
}

impl std::fmt::Display for DaemonError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DaemonError::NotRunning => write!(f, "no LocalPass daemon is running"),
            DaemonError::Transport(m) => write!(f, "daemon communication failed: {m}"),
        }
    }
}

/// Resolve the profile directory the GUI operates on.
///
/// Mirrors `lp-cli`'s `profile::resolve` with no explicit override: the platform
/// data directory via `directories::ProjectDirs` (`%APPDATA%\localpass`,
/// `~/Library/Application Support/localpass`, `~/.local/share/localpass`). This
/// is the same path the CLI and daemon default to, so the GUI unlocks the same
/// account store. An optional `LOCALPASS_PROFILE` env var override exists for
/// tests / non-standard installs.
///
/// # Errors
///
/// If the platform data directory cannot be determined and no override is set.
pub fn resolve_profile() -> Result<PathBuf, String> {
    if let Some(p) = std::env::var_os("LOCALPASS_PROFILE") {
        return Ok(PathBuf::from(p));
    }
    directories::ProjectDirs::from("", "", "localpass")
        .map(|d| d.data_dir().to_path_buf())
        .ok_or_else(|| {
            "could not determine the platform data directory; set LOCALPASS_PROFILE".to_string()
        })
}

/// The profile path as the daemon expects it on the wire (a display string).
///
/// # Errors
///
/// Propagates [`resolve_profile`]'s error.
pub fn profile_string() -> Result<String, String> {
    Ok(resolve_profile()?.display().to_string())
}

/// Send one request to the daemon and return the response.
///
/// Opens a fresh connection (connections are cheap; the daemon serves them
/// concurrently), sends `request`, reads one response, and drops the connection.
///
/// # Errors
///
/// [`DaemonError::NotRunning`] if no daemon is listening; otherwise
/// [`DaemonError::Transport`] on a transport/protocol failure.
pub fn call(request: &Request) -> Result<Response, DaemonError> {
    let mut client = match Client::connect() {
        Ok(c) => c,
        Err(lp_daemon::Error::NotRunning) => return Err(DaemonError::NotRunning),
        Err(e) => return Err(DaemonError::Transport(e.to_string())),
    };
    match client.call(request) {
        Ok(resp) => Ok(resp),
        Err(lp_daemon::Error::NotRunning | lp_daemon::Error::Closed) => {
            Err(DaemonError::NotRunning)
        }
        Err(e) => Err(DaemonError::Transport(e.to_string())),
    }
}
