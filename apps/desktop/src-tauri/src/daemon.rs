// SPDX-License-Identifier: MPL-2.0
// This file is part of the LocalPass desktop GUI. See apps/desktop/LICENSE.

//! The backend seam: profile resolution + the `call(&Request) -> Response`
//! entry every `#[tauri::command]` goes through. There are **two**
//! implementations, chosen at compile time, and the command layer above is
//! identical for both:
//!
//! - **Desktop** (default): a **daemon client**, exactly like the CLI and the
//!   native-messaging host (PRD §7.1). It opens a short-lived
//!   [`lp_daemon::client::Client`] per request over the same-user-only IPC
//!   channel and forwards the request; it holds no `Session`.
//! - **Mobile** (`cfg(mobile)`, or `--features inprocess` to test on desktop):
//!   there is no background daemon or IPC on Android, so the app process **is**
//!   the vault. `call` runs the **same** [`lp_daemon::engine::handle`] the daemon
//!   uses against a [`lp_daemon::engine::State`] held in-process — no separate
//!   process, no pipe, and **zero duplicated logic** (masking, unlock, vault ops,
//!   audit all come from the shared engine). The mobile `setup()` hook points
//!   `LOCALPASS_PROFILE` at the Android app-private dir so [`resolve_profile`]
//!   stays the single source of truth for both backends.
//!
//! In every case the helpers return a typed error the command layer maps to a
//! [`crate::model::SessionState`] the UI switches on — never a hang, never a
//! crash (PRD §4.7 "never blocks").

use std::path::PathBuf;

// ===========================================================================
// Android: the `AppHandle` hand-off (SAF sync).
// ===========================================================================
//
// The in-process engine state below is a lazy static built on first request, so
// it has no `AppHandle` of its own — but the SAF channel backend needs one (the
// plugin is reached through `AppHandle`). `lib.rs`'s `setup()` hook is the first
// place a handle exists, and it runs before any command can fire, so it stashes
// the handle here and the state initializer reads it back. This one-cell
// hand-off is the whole coupling; nothing else in the app needs it.

/// The `AppHandle` stashed by `lib.rs`'s `setup()` hook, so the lazily-built
/// engine state can reach the SAF plugin. Android-only.
#[cfg(target_os = "android")]
static APP_HANDLE: std::sync::OnceLock<tauri::AppHandle> = std::sync::OnceLock::new();

/// Record the app handle for the SAF channel backend. Called exactly once, from
/// `lib.rs`'s `setup()` hook, before any command runs; later calls are ignored.
#[cfg(target_os = "android")]
pub fn set_app_handle(app: tauri::AppHandle) {
    let _ = APP_HANDLE.set(app);
}

/// The stashed app handle, or `None` if `setup()` has not run yet.
#[cfg(target_os = "android")]
#[must_use]
pub fn app_handle() -> Option<tauri::AppHandle> {
    APP_HANDLE.get().cloned()
}

/// A backend-call failure the command layer can map to a UI state.
#[derive(Debug)]
pub enum DaemonError {
    /// No daemon is reachable — the UI shows "start the daemon" guidance.
    /// (Never produced by the in-process backend, which is always available.)
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
/// A `LOCALPASS_PROFILE` env override wins (the mobile `setup()` hook sets it to
/// the Android app-private data dir); otherwise the platform data directory via
/// `directories::ProjectDirs` (`%APPDATA%\localpass`, `~/Library/Application
/// Support/localpass`, `~/.local/share/localpass`) — the same path the CLI and
/// daemon default to, so the desktop GUI unlocks the same account store.
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

/// The profile path as the backend expects it on the wire (a display string).
///
/// # Errors
///
/// Propagates [`resolve_profile`]'s error.
pub fn profile_string() -> Result<String, String> {
    Ok(resolve_profile()?.display().to_string())
}

/// The account-store file name within a profile directory. Mirrors
/// `lp_vault::account::ACCOUNT_FILE`; kept as a literal so the GUI backend does
/// not take a direct `lp-vault` dependency (it reaches the core through
/// `lp-daemon`).
const ACCOUNT_FILE: &str = "account.localpass";

/// Whether an account store already exists in the resolved profile.
///
/// Distinguishes "locked, show unlock" from "no account yet, show onboarding".
/// A cheap filesystem check on `<profile>/account.localpass` — the same file the
/// create/unlock paths key on, so it is correct for both backends.
///
/// # Errors
///
/// Propagates [`resolve_profile`]'s error if the profile cannot be determined.
pub fn account_exists() -> Result<bool, String> {
    Ok(resolve_profile()?.join(ACCOUNT_FILE).exists())
}

// ===========================================================================
// Desktop backend: a daemon client over same-user-only IPC.
// ===========================================================================

#[cfg(not(any(mobile, feature = "inprocess")))]
mod backend {
    use std::time::Duration;

    use lp_daemon::client::{self, Client};
    use lp_daemon::protocol::{Request, Response};
    use lp_daemon::spawn::{self, DaemonExe};

    use super::{DaemonError, resolve_profile};

    /// Idle auto-lock the GUI-started daemon uses (seconds); mirrors the CLI's
    /// `daemon start` default (10 minutes).
    const DEFAULT_AUTOLOCK_SECS: u64 = 600;
    /// How long to wait for a freshly-spawned daemon to answer a Ping.
    const READY_TIMEOUT: Duration = Duration::from_secs(8);

    /// Ensure a daemon is running for this profile, spawning one if needed.
    ///
    /// # Errors
    ///
    /// A secret-free message if the service binary cannot be found or does not
    /// become ready in time.
    pub fn ensure_running() -> Result<(), String> {
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
}

// ===========================================================================
// Mobile / test backend: the daemon engine, in-process (no IPC, no daemon).
// ===========================================================================

#[cfg(any(mobile, feature = "inprocess"))]
mod backend {
    use std::sync::{Mutex, OnceLock, PoisonError};
    use std::time::Duration;

    use lp_daemon::engine::{self, State};
    use lp_daemon::protocol::{Request, Response};

    use super::{DaemonError, resolve_profile};

    /// Idle auto-lock for the in-process backend. On mobile the app process is
    /// the vault, so the engine's own idle timer stands in for the daemon's;
    /// a lifecycle hook can also lock on app-background (future).
    const AUTOLOCK: Duration = Duration::from_secs(300);

    /// The single in-process engine state — the vault lives in this process.
    static STATE: OnceLock<Mutex<State>> = OnceLock::new();

    fn state() -> &'static Mutex<State> {
        STATE.get_or_init(|| {
            // `resolve_profile` is the single source of truth; on mobile the
            // `setup()` hook has already pointed `LOCALPASS_PROFILE` at the
            // Android app-private dir before the first request.
            let profile = resolve_profile().unwrap_or_else(|_| std::path::PathBuf::from("."));

            // On Android the user's sync root is a SAF `content://` tree URI,
            // which `std::fs` cannot open — so the engine gets the app's own
            // `StoreFactory` (SAF for `content://`, filesystem otherwise)
            // through the core's injection seam. `setup()` has already stashed
            // the handle (see `super::set_app_handle`); if it somehow has not,
            // fall back to the plain filesystem state rather than panicking —
            // sync then simply refuses a `content://` root, and the rest of the
            // vault keeps working.
            #[cfg(target_os = "android")]
            if let Some(app) = super::app_handle() {
                return Mutex::new(State::new_with_store_factory(
                    profile,
                    AUTOLOCK,
                    std::sync::Arc::new(crate::safstore::AppStoreFactory::new(app)),
                ));
            }

            // Desktop (and the `inprocess` test feature): the core's default
            // filesystem channel, exactly as before.
            Mutex::new(State::new(profile, AUTOLOCK))
        })
    }

    /// The in-process backend is always available.
    #[allow(clippy::unnecessary_wraps)]
    pub fn ensure_running() -> Result<(), String> {
        Ok(())
    }

    /// Dispatch a request against the in-process engine — the SAME
    /// `lp_daemon::engine::handle` the daemon uses. No IPC, no separate process,
    /// no duplicated logic. Never fails at the transport level.
    pub fn call(request: &Request) -> Result<Response, DaemonError> {
        let mut guard = state().lock().unwrap_or_else(PoisonError::into_inner);
        guard.maybe_autolock();
        Ok(engine::handle(&mut guard, request.clone()).response)
    }
}

pub use backend::{call, ensure_running};

#[cfg(all(test, feature = "inprocess"))]
mod inprocess_tests {
    use super::*;
    use lp_daemon::protocol::{Request, Response};

    /// End-to-end proof that the mobile in-process backend works on desktop:
    /// create an account, unlock, and list vaults — all through `call`, the same
    /// path the Tauri commands use, with no daemon.
    #[test]
    fn create_unlock_and_list_run_in_process() {
        let dir = tempfile::tempdir().unwrap();
        // Point the whole backend (state init + account_exists) at an isolated
        // profile. SAFETY: single-threaded test setup, before any request.
        unsafe { std::env::set_var("LOCALPASS_PROFILE", dir.path()) };
        let profile = dir.path().display().to_string();
        let pw = "correct horse battery".to_string();

        assert!(!account_exists().unwrap(), "no account before create");

        let resp = call(&Request::CreateAccount {
            profile: profile.clone(),
            password: pw.clone(),
        })
        .unwrap();
        assert!(
            matches!(resp, Response::AccountCreated { .. }),
            "got {}",
            resp.kind()
        );
        assert!(account_exists().unwrap(), "account exists after create");

        let resp = call(&Request::Unlock {
            profile: profile.clone(),
            password: pw,
            secret_key: None,
            autolock_secs: None,
        })
        .unwrap();
        assert!(
            matches!(resp, Response::Ok { .. }),
            "unlock ok: {}",
            resp.kind()
        );

        let resp = call(&Request::ListVaults { profile }).unwrap();
        match resp {
            Response::Vaults { vaults } => assert!(
                vaults.iter().any(|(_, name)| name == "personal"),
                "default personal vault present: {vaults:?}"
            ),
            other => panic!("expected Vaults, got {}", other.kind()),
        }
    }
}
