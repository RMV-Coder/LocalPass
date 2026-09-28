#![forbid(unsafe_code)]
//! The client side of the human-presence check (`mcp-server.md` §7).
//!
//! While an AI agent holds a session with the daemon, the daemon answers a
//! consent or change request with [`Response::PresenceRequired`]. The client
//! asks the person for the master password, sends
//! [`Request::ConfirmPresence`], and gets back a short-lived grant token. This
//! module keeps that token for the rest of the process, and
//! [`crate::frame::write_request`] attaches it to every request until it
//! expires.
//!
//! The token lives only in this process's memory. That is the point: a process
//! an agent started cannot read it, and cannot mint its own without the
//! password.

use std::sync::Mutex;
use std::time::{Duration, Instant};

use zeroize::Zeroize;

use crate::client::Client;
use crate::error::Result;
use crate::protocol::{Request, Response};

/// The grant this process holds, with the instant it stops being useful.
static GRANT: Mutex<Option<(String, Instant)>> = Mutex::new(None);

/// Serializes the tests that use the process-wide slot, which would otherwise
/// race under the parallel test runner.
#[cfg(test)]
pub(crate) static TEST_SLOT: Mutex<()> = Mutex::new(());

/// Keep `token` for `ttl`, replacing any grant already held.
pub fn set_grant(token: String, ttl: Duration) {
    let mut slot = GRANT
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    if let Some((old, _)) = slot.as_mut() {
        old.zeroize();
    }
    *slot = Some((token, Instant::now() + ttl));
}

/// The held grant token, or `None` when there is none or it has expired. An
/// expired grant is forgotten here.
#[must_use]
pub fn current_grant() -> Option<String> {
    let mut slot = GRANT
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    match slot.as_ref() {
        Some((token, until)) if Instant::now() < *until => Some(token.clone()),
        Some(_) => {
            if let Some((old, _)) = slot.as_mut() {
                old.zeroize();
            }
            *slot = None;
            None
        }
        None => None,
    }
}

/// Forget the held grant (on lock, or when the daemon refused it).
pub fn clear_grant() {
    let mut slot = GRANT
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    if let Some((old, _)) = slot.as_mut() {
        old.zeroize();
    }
    *slot = None;
}

/// Send [`Request::ConfirmPresence`] for `profile` with `password`, and keep the
/// grant if the daemon issued one. Returns the daemon's answer:
/// [`Response::PresenceGrant`] on success, otherwise the refusal (a wrong
/// password is `Error { auth: true, .. }`).
///
/// # Errors
///
/// A transport or protocol failure.
pub fn confirm(client: &mut Client, profile: &str, password: &str) -> Result<Response> {
    let mut request = Request::ConfirmPresence {
        profile: profile.to_string(),
        password: password.to_string(),
    };
    let result = client.call(&request);
    request.zeroize_secrets();
    let response = result?;
    if let Response::PresenceGrant {
        token,
        expires_in_secs,
    } = &response
    {
        set_grant(token.clone(), Duration::from_secs(*expires_in_secs));
    }
    Ok(response)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn grant_is_held_until_it_expires_or_is_cleared() {
        let _slot = TEST_SLOT
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        clear_grant();
        assert_eq!(current_grant(), None);

        set_grant("aa".repeat(32), Duration::from_secs(60));
        assert_eq!(current_grant(), Some("aa".repeat(32)));

        set_grant("bb".repeat(32), Duration::from_secs(60));
        assert_eq!(
            current_grant(),
            Some("bb".repeat(32)),
            "a new grant replaces the old"
        );

        clear_grant();
        assert_eq!(current_grant(), None);

        set_grant("cc".repeat(32), Duration::ZERO);
        assert_eq!(current_grant(), None, "an expired grant is not attached");
    }
}
