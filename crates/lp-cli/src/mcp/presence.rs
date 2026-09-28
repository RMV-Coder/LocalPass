//! Registering the MCP server with the daemon as an **AI-agent session**
//! (`mcp-server.md` §7).
//!
//! While an agent session is open, the daemon refuses every consent or change
//! request (turning on agent fill or pairing, trusting or sharing to a device,
//! any edit to vault contents) until a person re-enters the master password.
//! That is what stops a process the agent started — which can reach the
//! daemon exactly as any same-user process can — from widening its own reach.
//!
//! The session is bound to a daemon **connection**, so it ends by itself when
//! this process exits, and nothing else can end it. Two connections hold one:
//!
//! - on the Proxy route, the connection every tool call already uses, so the
//!   agent's own requests are marked as the agent's;
//! - in every route, a **sentinel** connection on a background thread. It
//!   covers the Direct route (where the tools never touch a daemon, but a
//!   daemon started or unlocked later could still serve the agent's children)
//!   and a daemon restart on the Proxy route. It re-registers within
//!   [`SENTINEL_INTERVAL`] of a daemon appearing, and a new daemon starts
//!   locked, so there is no usable gap.

use std::time::Duration;

use anyhow::Result;
use lp_daemon::client::Client;
use lp_daemon::protocol::{Request, Response};

use crate::error::CliError;

/// How often the sentinel checks its connection, and retries when there is no
/// daemon to register with.
pub const SENTINEL_INTERVAL: Duration = Duration::from_secs(1);

/// Register `client`'s connection as an agent session for `profile`.
///
/// # Errors
///
/// [`CliError::Usage`] if the daemon refused or does not know the request (a
/// daemon older than this build, which has no presence check and must be
/// restarted), or [`CliError::Internal`] on a transport failure.
pub fn register(client: &mut Client, profile: &str) -> Result<()> {
    let response = client
        .call(&Request::BeginAgentSession {
            profile: profile.to_string(),
        })
        .map_err(|e| CliError::internal(anyhow::anyhow!("daemon communication failed: {e}")))?;
    interpret(&response)
}

/// Map the daemon's answer to a registration.
fn interpret(response: &Response) -> Result<()> {
    match response {
        Response::Ok { .. } => Ok(()),
        Response::WrongProfile { expected } => Err(CliError::usage(format!(
            "the running LocalPass service serves a different profile ({expected})"
        ))
        .into()),
        Response::Error { message, .. } => Err(CliError::usage(format!(
            "the running LocalPass service could not register this agent session: {message}"
        ))
        .into()),
        other => Err(CliError::usage(format!(
            "the running LocalPass service answered an agent-session registration with {}",
            other.kind()
        ))
        .into()),
    }
}

/// Start the sentinel thread for `profile`. It runs for the life of the
/// process: holds a registered connection while a daemon is up, and retries
/// every [`SENTINEL_INTERVAL`] while none is. It only ever logs kinds of
/// failure, never a value.
pub fn spawn_sentinel(profile: String, log: fn(&str)) {
    std::thread::spawn(move || {
        let mut held: Option<Client> = None;
        loop {
            if let Some(client) = held.as_mut() {
                // A cheap liveness check: Ping never touches the idle timer.
                if !matches!(client.call(&Request::Ping), Ok(Response::Pong)) {
                    held = None;
                }
            }
            if held.is_none()
                && let Ok(mut client) = Client::connect()
            {
                // The connection is held whether or not the daemon accepted it,
                // so a daemon that refuses (another profile, an older build) is
                // asked once per appearance, not every second: a wrong-profile
                // refusal is audited, and the log must not fill with them.
                if let Err(e) = register(&mut client, &profile) {
                    log(&format!("agent-session registration failed: {e:#}"));
                }
                held = Some(client);
            }
            std::thread::sleep(SENTINEL_INTERVAL);
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_an_ok_counts_as_registered() {
        assert!(interpret(&Response::Ok { message: None }).is_ok());
        for refused in [
            Response::WrongProfile {
                expected: "/other".into(),
            },
            Response::Error {
                auth: false,
                message: "this request is not understood".into(),
            },
            Response::Locked,
        ] {
            let err = interpret(&refused).unwrap_err().to_string();
            assert!(err.contains("LocalPass service"), "{err}");
        }
    }
}
