//! CLI-side daemon control and the daemon-first / direct-fallback decision.
//!
//! # The behaviour matrix (PRD §4.4)
//!
//! Every vault-touching command calls [`route`] to decide how to run:
//!
//! | `--no-daemon` | daemon running? | daemon unlocked (this profile)? | outcome |
//! |---------------|-----------------|--------------------------------|---------|
//! | yes           | —               | —                              | **Direct** (unchanged pre-daemon path) |
//! | no            | no              | —                              | **Direct** (regression-safe: behaves exactly as before) |
//! | no            | yes             | no (locked / wrong profile)    | **Direct** (the daemon can't help; unlock locally) |
//! | no            | yes             | yes                            | **Proxy** through the daemon (no re-prompt) |
//!
//! So a command *never fails just because a daemon is present* — the daemon is a
//! fast path, and its absence or locked state is transparent. `--no-daemon`
//! forces Direct even when a daemon is unlocked.
//!
//! The daemon is a **separate process** (`localpass-daemon`); the CLI is only a
//! client and the launcher. Proxied item rendering uses the daemon's wire types,
//! which mirror the CLI's own display model, so output is identical either way.

use std::path::Path;
use std::sync::OnceLock;
use std::time::Duration;

use anyhow::{Result, anyhow, bail};
use lp_daemon::client::{self, Client};
use lp_daemon::protocol::{Request, Response, WireItem, WireItemSummary};
use lp_daemon::spawn::{self, DaemonExe};
use serde_json::json;
use zeroize::Zeroize;

use crate::error::CliError;
use crate::unlock::{self, PasswordSource};

/// How this invocation may ask for the master password, recorded once by
/// `main` so a proxied call can confirm presence (`mcp-server.md` §7) without
/// every command threading the source through.
static PASSWORD_SOURCE: OnceLock<PasswordSource> = OnceLock::new();

/// Record this invocation's password source. Later calls are ignored.
pub fn set_password_source(src: PasswordSource) {
    let _ = PASSWORD_SOURCE.set(src);
}

/// How long to wait for a freshly-spawned daemon to answer a Ping.
const READY_TIMEOUT: Duration = Duration::from_secs(10);

/// The routing decision for a vault-touching command.
pub enum Route {
    /// Proxy through the daemon over this (already-connected) client. The daemon
    /// is running and unlocked for the requested profile.
    Proxy(Box<Client>),
    /// Fall back to a direct unlock (daemon absent, locked, wrong profile, or
    /// `--no-daemon`).
    Direct,
}

/// Decide whether to proxy through the daemon or unlock directly for `profile`.
///
/// This performs a single fast probe (`Status`). It never fails the command: any
/// daemon-side trouble degrades to [`Route::Direct`].
///
/// # Idle auto-lock
///
/// The probe is sent as a **keep-alive** — a command only routes because it is
/// about to do real work, which makes it a present user, so the daemon resets
/// its idle timer. This is what keeps the vault unlocked across a long
/// `localpass run …` or MCP session while a GUI sits idle, and it is load-bearing
/// for a command that then goes *Direct*: the daemon sees only this probe.
///
/// A command that merely *reports* daemon state must use
/// [`route_observing`] instead, so it does not restart the countdown it prints.
#[must_use]
pub fn route(profile: &Path, no_daemon: bool) -> Route {
    route_inner(profile, no_daemon, /* keepalive = */ true)
}

/// [`route`], but for a command that only **observes** the daemon
/// (`localpass status`, `pairing status`): the probe is passive and does not
/// reset the idle auto-lock timer, so printing the countdown never extends it.
#[must_use]
pub fn route_observing(profile: &Path, no_daemon: bool) -> Route {
    route_inner(profile, no_daemon, /* keepalive = */ false)
}

/// The shared probe body for [`route`] / [`route_observing`].
fn route_inner(profile: &Path, no_daemon: bool, keepalive: bool) -> Route {
    if no_daemon {
        return Route::Direct;
    }
    let Ok(mut client) = Client::connect() else {
        return Route::Direct;
    };
    // Ask the daemon its status for this profile. If it's unlocked and serving
    // this profile, proxy; otherwise go direct.
    //
    let req = Request::Status {
        profile: profile.display().to_string(),
        keepalive,
    };
    match client.call(&req) {
        Ok(Response::Status {
            state: lp_daemon::protocol::LockState::Unlocked,
            ..
        }) => Route::Proxy(Box::new(client)),
        // Locked, wrong profile, or any other answer: unlock directly.
        _ => Route::Direct,
    }
}

/// Send `request` and return the response, mapping transport failures to a clean
/// internal error.
///
/// If the daemon answers [`Response::PresenceRequired`] (an AI agent is
/// connected and this is a consent or change request), ask for the master
/// password, confirm presence, and send the request once more. The password
/// comes from the same sources as an unlock (`LOCALPASS_PASSWORD`,
/// `--password-stdin`, or a hidden prompt), none of which a process started by
/// the agent has: LocalPass strips the variable from its children, and their
/// stdin is not a terminal.
///
/// # Errors
///
/// [`CliError::Internal`] on a transport failure; [`CliError::Auth`] on a wrong
/// password; [`CliError::Usage`] when no password can be asked for.
pub fn call(client: &mut Client, request: &Request) -> Result<Response> {
    let response = send(client, request)?;
    let Response::PresenceRequired { action } = &response else {
        return Ok(response);
    };
    let Some(profile) = request.profile() else {
        return Ok(response);
    };
    confirm_presence(client, profile, action)?;
    send(client, request)
}

/// One round trip, with transport failures mapped to an internal error.
fn send(client: &mut Client, request: &Request) -> Result<Response> {
    client
        .call(request)
        .map_err(|e| CliError::internal(anyhow!("daemon communication failed: {e}")).into())
}

/// Ask for the master password and trade it for a presence grant, which then
/// rides on every later request from this process.
fn confirm_presence(client: &mut Client, profile: &str, action: &str) -> Result<()> {
    let src = PASSWORD_SOURCE.get().copied().unwrap_or(PasswordSource {
        no_input: true,
        stdin: false,
    });
    eprintln!(
        "An AI agent is connected to LocalPass, so {} needs your master password.",
        describe_action(action)
    );
    let mut password = unlock::acquire_password(src, "Master password: ").map_err(|e| {
        CliError::usage(format!(
            "an AI agent is connected, so this change needs your master password, and none \
             could be read: {e:#}"
        ))
    })?;
    let result = lp_daemon::presence::confirm(client, profile, &password);
    password.zeroize();
    let response =
        result.map_err(|e| CliError::internal(anyhow!("daemon communication failed: {e}")))?;
    match response {
        Response::PresenceGrant { .. } => Ok(()),
        other => {
            check_error(&other)?;
            Err(CliError::internal(anyhow!(
                "unexpected daemon response to a presence check: {}",
                other.kind()
            ))
            .into())
        }
    }
}

/// A short phrase for the refused request, for the prompt.
fn describe_action(action: &str) -> &'static str {
    match action {
        "CreateItem" => "creating an item",
        "UpdateItem" => "editing an item",
        "DeleteItem" => "deleting an item",
        "RestoreVersion" => "restoring an item version",
        "UntrashItem" => "restoring an item from the trash",
        "CreateVault" => "creating a vault",
        "DeleteVault" => "deleting a vault",
        "AddAttachment" => "adding an attachment",
        "DeleteAttachment" => "deleting an attachment",
        "SetAgentFillMode" => "turning on agent fill",
        "SetPairingMode" => "turning on pairing mode",
        "TrustDevice" => "trusting a device",
        "ShareVaultToDevice" => "sharing a vault to a device",
        "SyncSetup" => "setting up sync",
        _ => "this change",
    }
}

/// Map a [`Response::Error`] / [`Response::Locked`] / [`Response::WrongProfile`]
/// to the appropriate [`CliError`]. Any other response is returned to the caller
/// to handle. Used by proxying commands so daemon-side errors carry the right
/// exit code (auth = 2, usage = 1).
///
/// # Errors
///
/// The mapped [`CliError`] when `response` is an error-shaped variant.
pub fn check_error(response: &Response) -> Result<()> {
    match response {
        Response::Error { auth, message } => {
            if *auth {
                Err(CliError::auth(message.clone()).into())
            } else {
                Err(CliError::usage(message.clone()).into())
            }
        }
        Response::Locked => {
            // The daemon locked between our Status probe and this request.
            Err(CliError::usage("daemon is locked; run `localpass unlock` first").into())
        }
        Response::WrongProfile { expected } => Err(CliError::usage(format!(
            "the running daemon serves a different profile ({expected}); \
             stop it or pass --no-daemon"
        ))
        .into()),
        Response::PresenceRequired { action } => Err(CliError::auth(format!(
            "an AI agent is connected to LocalPass, so {} needs a person to confirm it \
             with the master password",
            describe_action(action)
        ))
        .into()),
        _ => Ok(()),
    }
}

/// Probe whether a daemon is running (fast). Returns `false` on any error.
#[must_use]
pub fn is_running() -> bool {
    client::probe().unwrap_or(false)
}

/// Ensure a daemon is running for `profile`, starting it detached if needed.
///
/// Returns `true` if it started a new daemon, `false` if one was already
/// running (the friendly no-op case).
///
/// # Errors
///
/// [`CliError::Internal`] if the daemon binary cannot be spawned or does not
/// come up within the readiness timeout.
pub fn ensure_started(profile: &Path, autolock_secs: u64, verbose: bool) -> Result<bool> {
    if is_running() {
        return Ok(false);
    }
    spawn::spawn_detached(
        &DaemonExe::Auto,
        profile,
        autolock_secs,
        verbose,
        READY_TIMEOUT,
    )
    .map_err(|e| CliError::internal(anyhow!("could not start the daemon: {e}")))?;
    Ok(true)
}

/// Send a `Shutdown` to a running daemon, if any. A no-op if none is running.
///
/// The daemon tears itself down the moment it handles `Shutdown`, so the
/// response can race with the endpoint closing: the client may get a clean `Ok`,
/// or a truncated read / EOF as the daemon exits. **Both mean success** — we
/// asked it to die and it did. Only a genuine "no daemon there" is reported as
/// `Ok(false)`.
///
/// # Errors
///
/// [`CliError::Internal`] only on an unexpected transport failure that is
/// neither a clean close nor a not-running endpoint.
pub fn shutdown() -> Result<bool> {
    match Client::connect() {
        Ok(mut client) => match client.call(&Request::Shutdown) {
            // A clean Ok, or the daemon closing mid-response — both are success.
            Ok(_) | Err(lp_daemon::Error::Closed) => Ok(true),
            Err(lp_daemon::Error::Io(e))
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::UnexpectedEof | std::io::ErrorKind::BrokenPipe
                ) =>
            {
                // Truncated read as the daemon exited — the shutdown took effect.
                Ok(true)
            }
            Err(e) => bail!(CliError::internal(anyhow!(
                "failed to signal daemon shutdown: {e}"
            ))),
        },
        Err(lp_daemon::Error::NotRunning) => Ok(false),
        Err(e) => bail!(CliError::internal(anyhow!(
            "failed to reach daemon for shutdown: {e}"
        ))),
    }
}

// --- Rendering proxied responses (matches the direct-path output exactly) ---

/// Print a single [`WireItem`] the way `item get` prints a direct-unlock item.
/// `reveal` controls the trailing "secrets masked" hint; the values themselves
/// arrive already masked or revealed from the daemon per the request.
pub fn print_item_human(item: &WireItem, reveal: bool) {
    println!("Title:   {}", item.title);
    println!("Type:    {}", item.type_str);
    println!("Id:      {}", item.id);
    println!("Version: {}", item.version);
    if !item.tags.is_empty() {
        println!("Tags:    {}", item.tags.join(", "));
    }
    if !item.notes.is_empty() {
        println!("Notes:   {}", item.notes);
    }
    if item.fields.is_empty() {
        println!("(no fields)");
    } else {
        println!("Fields:");
        for f in &item.fields {
            let marker = if f.secret { " (secret)" } else { "" };
            println!("  {}{}: {}", f.name, marker, f.value);
        }
    }
    if !reveal && item.fields.iter().any(|f| f.secret) {
        eprintln!("(secrets masked; pass --reveal to show, or --field <name> for one value)");
    }
}

/// Build the `item get --json` object for a [`WireItem`], matching
/// [`crate::output::item_to_json`]'s shape. Field values are exactly what the
/// daemon sent (already masked unless `--reveal`).
#[must_use]
pub fn item_to_json(item: &WireItem) -> serde_json::Value {
    let fields: Vec<serde_json::Value> = item
        .fields
        .iter()
        .map(|f| json!({ "name": f.name, "secret": f.secret, "value": f.value }))
        .collect();
    json!({
        "id": item.id,
        "title": item.title,
        "type": item.type_str,
        "version": item.version,
        "created_at": item.created_at,
        "updated_at": item.updated_at,
        "tags": item.tags,
        "favorite": item.favorite,
        "notes": item.notes,
        "fields": fields,
    })
}

/// Find one field's value in a [`WireItem`] for `item get --field NAME` (case-
/// sensitive first, then case-insensitive). Matches [`crate::output::find_field`].
#[must_use]
pub fn wire_field<'a>(item: &'a WireItem, name: &str) -> Option<&'a str> {
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

/// The compact `list`/`search` JSON summary for a [`WireItemSummary`], matching
/// [`crate::output::item_summary_json`].
#[must_use]
pub fn summary_to_json(s: &WireItemSummary) -> serde_json::Value {
    json!({
        "id": s.id,
        "title": s.title,
        "type": s.type_str,
        "updated_at": s.updated_at,
        "tags": s.tags,
    })
}

/// Print a `title  type  updated` table for `list`/`search`, matching
/// [`crate::commands::item::print_item_table`].
pub fn print_summary_table(items: &[WireItemSummary]) {
    let width = items
        .iter()
        .map(|i| i.title.chars().count())
        .max()
        .unwrap_or(5)
        .clamp(5, 40);
    println!("{:<width$}  {:<8}  UPDATED", "TITLE", "TYPE", width = width);
    for it in items {
        println!(
            "{:<width$}  {:<8}  {}",
            truncate(&it.title, width),
            it.type_str,
            crate::timestamp::format_millis_utc(it.updated_at),
            width = width
        );
    }
}

/// Truncate a title to `max` chars with an ellipsis (table display only).
fn truncate(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        s.to_string()
    } else {
        let head: String = s.chars().take(max.saturating_sub(1)).collect();
        format!("{head}…")
    }
}
