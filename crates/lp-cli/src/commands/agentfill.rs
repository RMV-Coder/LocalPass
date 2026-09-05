//! `localpass agent-fill arm|disable|status` — the agent-fill arm window
//! (`docs/specs/agent-fill.md` §7).
//!
//! Agent-fill mode is a per-device, **time-boxed (3-minute)**, **per-item**
//! window that lets an AI agent trigger a browser autofill through the
//! `fill_login` MCP tool. It is the compensating consent for the one thing this
//! feature removes: the user's click in the extension popup (§4).
//!
//! Like pairing mode, it lives in the running daemon's in-memory unlocked
//! session, so this command **routes through the daemon** (`Route::Proxy` →
//! [`Request::SetAgentFillMode`] to arm/disable, [`Request::Status`] to report).
//! It exists so arming never requires the desktop GUI — a CLI-and-daemon user
//! must be able to arm a fill from a terminal.
//!
//! # Why arming names items
//!
//! There is no "arm everything". §7 scopes the window to the specific items the
//! user chose, and an item outside that set is refused (`item_not_armed`) even
//! while the window is open. `arm` therefore requires at least one `--item`; the
//! daemon refuses an empty set rather than silently widening the scope.
//!
//! # The direct (`--no-daemon`) path has nothing to arm
//!
//! Agent fill is a daemon-session concept end to end: the browser extension
//! reaches the vault through the native host, which is a daemon client. With no
//! unlocked daemon there is no window to open and no extension to serve, so the
//! Direct case prints a note rather than pretending to arm something.

use std::path::Path;

use anyhow::Result;
use serde_json::json;

use crate::cli::AgentFillCommand;
use crate::daemonctl::{self, Route};

use lp_daemon::protocol::{Request, Response};

/// Run a `localpass agent-fill ...` subcommand.
///
/// # Errors
///
/// Propagates a daemon transport failure, or a daemon-side usage/lock error
/// mapped to the right exit code (via [`crate::daemonctl::check_error`]).
pub fn run(profile_dir: &Path, no_daemon: bool, command: &AgentFillCommand) -> Result<()> {
    match command {
        AgentFillCommand::Arm { item, vault } => {
            arm(profile_dir, no_daemon, item, vault.as_deref())
        }
        AgentFillCommand::Disable => disable(profile_dir, no_daemon),
        AgentFillCommand::Status { json } => status(profile_dir, no_daemon, *json),
    }
}

/// `agent-fill arm --item <ITEM> [--item <ITEM> …]` — open the window over
/// exactly those items.
fn arm(profile_dir: &Path, no_daemon: bool, items: &[String], vault: Option<&str>) -> Result<()> {
    match daemonctl::route(profile_dir, no_daemon) {
        Route::Proxy(mut client) => {
            let resp = daemonctl::call(
                &mut client,
                &Request::SetAgentFillMode {
                    profile: profile_dir.display().to_string(),
                    on: true,
                    item_ids: items.to_vec(),
                    vault: vault.map(ToString::to_string),
                },
            )?;
            daemonctl::check_error(&resp)?;
            // A refusal here is a bad item reference; render its §10 token.
            if let Response::FillRefused { reason } = resp {
                return Err(crate::error::CliError::usage(format!(
                    "could not arm agent fill: {}",
                    reason.token()
                ))
                .into());
            }
            let n = items.len();
            let plural = if n == 1 { "item" } else { "items" };
            println!(
                "Agent fill is ARMED for 3 minutes, for {n} {plural}. An AI agent may now call \
                 the `fill_login` MCP tool for {} — and for nothing else.",
                if n == 1 { "that item" } else { "those items" }
            );
            println!(
                "Every fill raises a notification and is written to the audit log. \
                 `localpass agent-fill disable` closes the window early."
            );
            Ok(())
        }
        Route::Direct => {
            print_direct_note();
            Ok(())
        }
    }
}

/// `agent-fill disable` — close the window now (and drop any pending intent).
fn disable(profile_dir: &Path, no_daemon: bool) -> Result<()> {
    match daemonctl::route(profile_dir, no_daemon) {
        Route::Proxy(mut client) => {
            let resp = daemonctl::call(
                &mut client,
                &Request::SetAgentFillMode {
                    profile: profile_dir.display().to_string(),
                    on: false,
                    item_ids: Vec::new(),
                    vault: None,
                },
            )?;
            daemonctl::check_error(&resp)?;
            println!("Agent fill is OFF.");
            Ok(())
        }
        Route::Direct => {
            print_direct_note();
            Ok(())
        }
    }
}

/// `agent-fill status` — report whether the window is open and the seconds left.
fn status(profile_dir: &Path, no_daemon: bool, json_out: bool) -> Result<()> {
    // Observing only — this reports a countdown, so neither the route probe nor
    // the Status below may restart it.
    match daemonctl::route_observing(profile_dir, no_daemon) {
        Route::Proxy(mut client) => {
            let resp = daemonctl::call(
                &mut client,
                &Request::Status {
                    profile: profile_dir.display().to_string(),
                    keepalive: false,
                },
            )?;
            if let Response::Status {
                agent_fill_secs, ..
            } = resp
            {
                emit_status(json_out, true, agent_fill_secs);
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

/// Emit the agent-fill status in human or JSON form. `daemon` records whether an
/// unlocked daemon answered; `remaining` is the seconds left (`Some` ⇒ armed).
///
/// The armed **item set** is deliberately absent: item titles are ciphertext
/// everywhere else, and a status line is not the place to start printing them.
fn emit_status(json_out: bool, daemon: bool, remaining: Option<u64>) {
    let on = remaining.is_some();
    if json_out {
        let obj = json!({
            "daemon": daemon,
            "agent_fill": on,
            "remaining_secs": remaining,
        });
        println!("{}", serde_json::to_string_pretty(&obj).unwrap_or_default());
    } else if let Some(secs) = remaining {
        println!("Agent fill: ARMED ({secs}s remaining)");
    } else {
        println!("Agent fill: OFF");
    }
}

/// Print the note shown when no unlocked daemon is serving this profile.
fn print_direct_note() {
    println!(
        "Agent fill is a daemon-session control (agent-fill.md §7): it opens a \
         time-boxed, per-item window in the running daemon."
    );
    println!(
        "No unlocked daemon is running for this profile, so there is nothing to arm — \
         and with no daemon the browser extension cannot reach the vault either."
    );
    println!("Unlock the daemon first: `localpass unlock`.");
}
