//! `localpass daemon start|stop|status`, plus the top-level `unlock` / `lock`
//! commands.
//!
//! These are the user-facing controls for the background agent (PRD §4.4). The
//! daemon itself is a separate process (`localpass-daemon`); `start` spawns it
//! detached and waits for it to answer a Ping, `stop` signals a clean shutdown,
//! and `status` reports whether it's running and its lock state.
//!
//! `unlock` prompts locally and sends the password to the daemon (starting it
//! first if needed); `lock` drops the daemon's keys.

use std::path::Path;

use anyhow::{Result, anyhow};
use serde_json::json;

use crate::cli::DaemonCommand;
use crate::daemonctl;
use crate::error::CliError;
use crate::unlock::{self, PasswordSource};

use lp_daemon::client::Client;
use lp_daemon::protocol::{LockState, Request, Response};
use lp_daemon::{AUTOLOCK_ENV, DEFAULT_AUTOLOCK_SECS};

/// Run a `localpass daemon ...` subcommand.
///
/// # Errors
///
/// Propagates spawn / transport failures with the documented exit codes.
pub fn run(profile_dir: &Path, command: &DaemonCommand) -> Result<()> {
    match command {
        DaemonCommand::Start { autolock, verbose } => start(profile_dir, *autolock, *verbose),
        DaemonCommand::Stop => stop(),
        DaemonCommand::Status { json } => status(profile_dir, *json),
    }
}

/// Resolve the effective auto-lock seconds: explicit flag → env var → default.
fn resolve_autolock(explicit: Option<u64>) -> u64 {
    if let Some(secs) = explicit {
        return secs;
    }
    if let Ok(v) = std::env::var(AUTOLOCK_ENV)
        && let Ok(secs) = v.trim().parse::<u64>()
    {
        return secs;
    }
    DEFAULT_AUTOLOCK_SECS
}

/// `localpass daemon start` — spawn detached if not already running.
fn start(profile_dir: &Path, autolock: Option<u64>, verbose: bool) -> Result<()> {
    let autolock_secs = resolve_autolock(autolock);
    let started = daemonctl::ensure_started(profile_dir, autolock_secs, verbose)?;
    if started {
        let never = if autolock_secs == 0 {
            " (auto-lock disabled)".to_string()
        } else {
            format!(" (auto-lock after {autolock_secs}s idle)")
        };
        println!("daemon started{never}");
    } else {
        // Friendly no-op: already running.
        println!("daemon already running");
    }
    Ok(())
}

/// `localpass daemon stop` — clean shutdown; no-op if not running.
fn stop() -> Result<()> {
    if daemonctl::shutdown()? {
        println!("daemon stopped");
    } else {
        println!("no daemon running");
    }
    Ok(())
}

/// `localpass daemon status` — running? locked/unlocked?
fn status(profile_dir: &Path, json_out: bool) -> Result<()> {
    let profile = profile_dir.display().to_string();
    match Client::connect() {
        Ok(mut client) => {
            // A daemon that is exiting can accept a connection but close before
            // answering (a shutdown race). Treat a transport-closed/EOF as "not
            // running" rather than an internal error.
            let resp = match client.call(&Request::Status {
                profile: profile.clone(),
            }) {
                Ok(r) => r,
                Err(lp_daemon::Error::Closed | lp_daemon::Error::NotRunning) => {
                    print_status(
                        json_out, false, None, &profile, None, None, None, None, None,
                    );
                    return Ok(());
                }
                Err(e) => {
                    return Err(
                        CliError::internal(anyhow!("daemon communication failed: {e}")).into(),
                    );
                }
            };
            match resp {
                Response::Status {
                    state,
                    profile: served,
                    vault_count,
                    autolock_secs,
                    idle_remaining_secs,
                    ssh_agent_endpoint,
                    ssh_identity_count,
                } => print_status(
                    json_out,
                    true,
                    Some(state),
                    &served,
                    vault_count,
                    Some(autolock_secs),
                    idle_remaining_secs,
                    ssh_agent_endpoint,
                    Some(ssh_identity_count),
                ),
                Response::WrongProfile { expected } => print_status(
                    json_out, true, None, &expected, None, None, None, None, None,
                ),
                other => {
                    return Err(CliError::internal(anyhow!(
                        "unexpected daemon response: {}",
                        other.kind()
                    ))
                    .into());
                }
            }
        }
        Err(lp_daemon::Error::NotRunning) => {
            print_status(
                json_out, false, None, &profile, None, None, None, None, None,
            );
        }
        Err(e) => {
            return Err(CliError::internal(anyhow!("failed to reach daemon: {e}")).into());
        }
    }
    Ok(())
}

/// Print the daemon status in human or JSON form.
#[allow(clippy::fn_params_excessive_bools, clippy::too_many_arguments)]
fn print_status(
    json_out: bool,
    running: bool,
    state: Option<LockState>,
    profile: &str,
    vault_count: Option<usize>,
    autolock_secs: Option<u64>,
    idle_remaining_secs: Option<u64>,
    ssh_agent_endpoint: Option<String>,
    ssh_identity_count: Option<usize>,
) {
    let state_str = match state {
        Some(LockState::Unlocked) => "unlocked",
        Some(LockState::Locked) => "locked",
        None => "n/a",
    };
    if json_out {
        let obj = json!({
            "running": running,
            "state": state_str,
            "profile": profile,
            "vault_count": vault_count,
            "autolock_secs": autolock_secs,
            "idle_remaining_secs": idle_remaining_secs,
            "ssh_agent_endpoint": ssh_agent_endpoint,
            "ssh_identity_count": ssh_identity_count,
        });
        println!("{}", serde_json::to_string_pretty(&obj).unwrap_or_default());
    } else {
        println!(
            "Daemon:  {}",
            if running { "running" } else { "not running" }
        );
        if running {
            println!("State:   {state_str}");
            println!("Profile: {profile}");
            if let Some(n) = vault_count {
                println!("Vaults:  {n}");
            }
            if let Some(secs) = autolock_secs {
                if secs == 0 {
                    println!("Autolock: disabled");
                } else {
                    match idle_remaining_secs {
                        Some(rem) => println!("Autolock: {secs}s idle ({rem}s remaining)"),
                        None => println!("Autolock: {secs}s idle"),
                    }
                }
            }
            match &ssh_agent_endpoint {
                Some(ep) => {
                    let n = ssh_identity_count.unwrap_or(0);
                    println!("SSH agent: {ep} ({n} identities)");
                }
                None => println!("SSH agent: disabled"),
            }
        }
    }
}

/// `localpass unlock` — prompt locally, start the daemon if needed, send Unlock.
///
/// # Errors
///
/// - [`CliError::Auth`] (exit 2) on a wrong password / Secret Key.
/// - [`CliError::Usage`] / [`CliError::Internal`] on other failures.
pub fn run_unlock(profile_dir: &Path, src: PasswordSource) -> Result<()> {
    // Refuse early if there's no account (clean message, no daemon spun up).
    if !crate::profile::account_exists(profile_dir) {
        return Err(CliError::usage(format!(
            "no account at {} — run `localpass init` first",
            profile_dir.display()
        ))
        .into());
    }

    // Ensure the daemon is up (start detached if needed) with the default/env
    // auto-lock; `unlock` does not take an --autolock flag, so it uses the same
    // resolution as `daemon start` with no explicit override. If the daemon was
    // ALREADY running (e.g. started by `daemon start --autolock N`), we must NOT
    // clobber its configured timeout — so we only send an autolock in the Unlock
    // when this call is the one that started the daemon.
    let autolock_secs = resolve_autolock(None);
    let started = daemonctl::ensure_started(profile_dir, autolock_secs, false)?;
    let unlock_autolock = if started { Some(autolock_secs) } else { None };

    // Prompt for the password locally (honours env/stdin/no-input), then send it
    // to the daemon over the same-user-only channel.
    let password = unlock::acquire_password(src, "Master password: ")?;

    let mut client =
        Client::connect().map_err(|e| CliError::internal(anyhow!("daemon not reachable: {e}")))?;
    let resp = daemonctl::call(
        &mut client,
        &Request::Unlock {
            profile: profile_dir.display().to_string(),
            password,
            // The daemon reads <profile>/secret-key itself (MVP keychain
            // stand-in); we do not ship the Secret Key over the wire when the
            // daemon can read it locally.
            secret_key: None,
            autolock_secs: unlock_autolock,
        },
    )?;
    daemonctl::check_error(&resp)?;
    match resp {
        Response::Ok { .. } => {
            println!("unlocked (daemon will hold keys until idle-lock or `localpass lock`)");
            Ok(())
        }
        other => Err(CliError::internal(anyhow!(
            "unexpected daemon response to unlock: {}",
            other.kind()
        ))
        .into()),
    }
}

/// `localpass lock` — drop the daemon's keys. No-op (exit 0) if not running.
///
/// # Errors
///
/// [`CliError::Internal`] on an unexpected transport failure.
pub fn run_lock(_profile_dir: &Path) -> Result<()> {
    match Client::connect() {
        Ok(mut client) => {
            let resp = daemonctl::call(&mut client, &Request::Lock)?;
            daemonctl::check_error(&resp)?;
            println!("locked");
            Ok(())
        }
        Err(lp_daemon::Error::NotRunning) => {
            println!("no daemon running (nothing to lock)");
            Ok(())
        }
        Err(e) => Err(CliError::internal(anyhow!("failed to reach daemon: {e}")).into()),
    }
}
