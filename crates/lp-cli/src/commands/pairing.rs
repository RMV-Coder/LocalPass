//! `localpass pairing enable|disable|status` — the pairing-mode window
//! (`device-pairing.md` §4).
//!
//! Pairing mode is a per-device, **time-boxed (3-minute)** window that gates
//! trusting a **new** device. It lives in the daemon's in-memory unlocked
//! session, so this command **routes through the daemon** (`Route::Proxy` →
//! [`Request::SetPairingMode`] for enable/disable; [`Request::Status`] for
//! status). Without it, a CLI-with-daemon user could never trust a device once
//! the engine gate exists: the daemon's `TrustDevice` refuses while the window
//! is closed.
//!
//! # The direct (`--no-daemon`) path is not gated — and that is fine
//!
//! Pairing mode is a *daemon-session* concept. When no unlocked daemon is
//! serving this profile (`--no-daemon`, no daemon running, or a locked daemon),
//! [`crate::daemonctl::route`] returns [`Route::Direct`] and there is nothing to
//! toggle. The direct trust path (`localpass device trust`) is **intentionally**
//! not gated — only the engine enforces the window. So the Direct case prints a
//! clear note rather than failing.

use std::path::Path;

use anyhow::Result;
use serde_json::json;

use crate::cli::PairingCommand;
use crate::daemonctl::{self, Route};

use lp_daemon::protocol::{Request, Response};

/// Run a `localpass pairing ...` subcommand.
///
/// # Errors
///
/// Propagates a daemon transport failure, or a daemon-side usage/lock error
/// mapped to the right exit code (via [`crate::daemonctl::check_error`]).
pub fn run(profile_dir: &Path, no_daemon: bool, command: &PairingCommand) -> Result<()> {
    match command {
        PairingCommand::Enable => set(profile_dir, no_daemon, true),
        PairingCommand::Disable => set(profile_dir, no_daemon, false),
        PairingCommand::Status { json } => status(profile_dir, no_daemon, *json),
    }
}

/// `pairing enable` / `pairing disable` — open or close the window on the daemon.
fn set(profile_dir: &Path, no_daemon: bool, enabled: bool) -> Result<()> {
    match daemonctl::route(profile_dir, no_daemon) {
        Route::Proxy(mut client) => {
            let resp = daemonctl::call(
                &mut client,
                &Request::SetPairingMode {
                    profile: profile_dir.display().to_string(),
                    enabled,
                },
            )?;
            daemonctl::check_error(&resp)?;
            if enabled {
                println!(
                    "Pairing mode is ON for 3 minutes — trust a new device now \
                     (`localpass device trust …`)."
                );
            } else {
                println!("Pairing mode is OFF.");
            }
            Ok(())
        }
        Route::Direct => {
            print_direct_note();
            Ok(())
        }
    }
}

/// `pairing status` — report whether pairing mode is on and the seconds left.
fn status(profile_dir: &Path, no_daemon: bool, json_out: bool) -> Result<()> {
    match daemonctl::route(profile_dir, no_daemon) {
        Route::Proxy(mut client) => {
            let resp = daemonctl::call(
                &mut client,
                &Request::Status {
                    profile: profile_dir.display().to_string(),
                },
            )?;
            if let Response::Status {
                pairing_mode_secs, ..
            } = resp
            {
                emit_status(json_out, true, pairing_mode_secs);
            } else {
                daemonctl::check_error(&resp)?;
            }
            Ok(())
        }
        Route::Direct => {
            if json_out {
                emit_status(true, false, None);
            } else {
                print_direct_note();
            }
            Ok(())
        }
    }
}

/// Emit the pairing-mode status in human or JSON form. `daemon` records whether
/// an unlocked daemon answered; `remaining` is the seconds left (`Some` ⇒ ON).
fn emit_status(json_out: bool, daemon: bool, remaining: Option<u64>) {
    let on = remaining.is_some();
    if json_out {
        let obj = json!({
            "daemon": daemon,
            "pairing_mode": on,
            "remaining_secs": remaining,
        });
        println!("{}", serde_json::to_string_pretty(&obj).unwrap_or_default());
    } else if let Some(secs) = remaining {
        println!("Pairing mode: ON ({secs}s remaining)");
    } else {
        println!("Pairing mode: OFF");
    }
}

/// Print the note shown when no unlocked daemon is serving this profile: pairing
/// mode is a daemon-session control, and the direct trust path is not gated.
fn print_direct_note() {
    println!(
        "Pairing mode is a daemon-session control (device-pairing.md §4): it gates \
         trusting a NEW device through the daemon."
    );
    println!(
        "No unlocked daemon is running for this profile, so there is nothing to \
         toggle — and the direct `localpass device trust` path is intentionally NOT \
         gated by pairing mode."
    );
    println!("To use pairing mode, unlock the daemon first: `localpass unlock`.");
}
