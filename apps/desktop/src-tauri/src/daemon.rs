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
use std::time::Duration;

use lp_daemon::client::{self, Client};
use lp_daemon::protocol::{Request, Response};
use lp_daemon::spawn::{self, DaemonExe};

/// Idle auto-lock the GUI-started daemon uses (seconds). Mirrors the CLI's
/// `daemon start` default (10 minutes); the daemon zeroizes keys on timeout.
const DEFAULT_AUTOLOCK_SECS: u64 = 600;

/// How long to wait for a freshly-spawned daemon to answer a Ping.
const READY_TIMEOUT: Duration = Duration::from_secs(8);

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

/// Ensure a daemon is running for this profile, spawning one if needed.
///
/// This is what lets the GUI "just work" for a first-time user: the desktop app
/// is a daemon *client* and cannot hold keys itself, so if no daemon is up it
/// starts one detached — exactly as `localpass unlock` does on the CLI
/// (`crates/lp-cli` `daemonctl`). Idempotent: if a daemon is already listening
/// this is a cheap probe and returns immediately.
///
/// The daemon executable is located next to the app (a bundled release ships
/// `localpass-daemon` beside the GUI binary), falling back to `localpass-daemon`
/// on `PATH` (a `cargo install`ed dev setup) — see [`DaemonExe::Auto`].
///
/// # Errors
///
/// A human-readable, secret-free message if the service binary cannot be found
/// or does not become ready in time. The caller surfaces it as UI guidance.
pub fn ensure_running() -> Result<(), String> {
    // Already listening? (A different-profile daemon is handled later by the
    // per-request `WrongProfile` response, not here.)
    if client::probe().unwrap_or(false) {
        return Ok(());
    }
    let profile = resolve_profile()?;
    spawn::spawn_detached(
        &DaemonExe::Auto,
        &profile,
        DEFAULT_AUTOLOCK_SECS,
        false,
        READY_TIMEOUT,
    )
    .map_err(|e| match e {
        lp_daemon::Error::NotRunning => {
            "the LocalPass service was started but did not become ready in time — try again"
                .to_string()
        }
        other => format!(
            "could not start the LocalPass service ({other}). \
             Ensure `localpass-daemon` is installed (it ships beside the app, \
             or run `cargo install --path crates/lp-daemon`)."
        ),
    })
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
