#![forbid(unsafe_code)]
//! The host↔daemon bridge: turn a browser [`HostRequest`](crate::protocol::HostRequest)
//! into a fill-scoped [`lp_daemon`] request, over the daemon's existing
//! same-user-only IPC.
//!
//! # Fill-scoped by construction
//!
//! The host is a daemon **client**, exactly like the CLI, but it issues **only**
//! three request kinds — [`Request::Status`], [`Request::MatchLogins`], and
//! [`Request::FillLogin`]. It never sends `Unlock`, `GetItem`, `ResolveField`,
//! `Export`, or any mutation: the browser side literally cannot ask for anything
//! beyond "which logins match this origin" and "fill this one item". The daemon
//! enforces the same-user-only channel and does the vault access; the host holds
//! **no keys** and cannot unlock (PRD §5.1 least privilege, §6.7, §7.3).
//!
//! # Profile alignment
//!
//! The daemon serves exactly one profile. The host does not know it a priori, so
//! it sends its best-guess profile with each request and, on a
//! [`Response::WrongProfile`], **adopts the daemon's reported profile** and
//! retries once. This keeps the host aligned with whatever profile the running
//! daemon serves without the host needing to resolve the platform data directory
//! itself. An explicit profile (from the binary's `--profile`/`LOCALPASS_PROFILE`)
//! seeds the first guess.
//!
//! # Never blocks the browser
//!
//! Every call degrades gracefully: if no daemon is running, or the connection
//! fails, `status` reports `unavailable`+`locked` and the credential/fill paths
//! report `locked` — the host answers immediately rather than hanging the
//! extension (PRD §4.7 "never blocks the browser").

use std::sync::Mutex;

use lp_daemon::client::Client;
use lp_daemon::protocol::{LockState, Request, Response};

use crate::protocol::{Candidate, HostResponse};

/// The bridge to the daemon. Holds the current best-guess profile string, which
/// self-corrects on a `WrongProfile` reply.
pub struct Bridge {
    /// The profile string sent with each vault-touching request. Seeded from the
    /// host's `--profile`/env (or empty), self-corrected on `WrongProfile`.
    profile: Mutex<String>,
}

impl Bridge {
    /// A bridge seeded with an optional explicit profile (from the host binary's
    /// `--profile` flag or `LOCALPASS_PROFILE` env). An empty string is a fine
    /// seed — the first `WrongProfile` reply supplies the real one.
    #[must_use]
    pub fn new(profile: impl Into<String>) -> Self {
        Self {
            profile: Mutex::new(profile.into()),
        }
    }

    /// The current profile guess.
    fn profile(&self) -> String {
        self.profile.lock().expect("profile mutex").clone()
    }

    /// Adopt `expected` as the profile for subsequent requests.
    fn adopt_profile(&self, expected: String) {
        *self.profile.lock().expect("profile mutex") = expected;
    }

    /// Open a fresh daemon connection (one per request, like the CLI). Returns
    /// `None` if no daemon is running / the connection fails — the caller then
    /// reports unavailable/locked rather than blocking.
    fn connect(&self) -> Option<Client> {
        Client::connect().ok()
    }

    /// Send one request, transparently retrying once if the daemon reports a
    /// different profile (adopting it). Returns `None` on any transport failure
    /// (so the caller degrades to unavailable/locked).
    fn call(&self, make: impl Fn(String) -> Request) -> Option<Response> {
        let mut client = self.connect()?;
        let req = make(self.profile());
        match client.call(&req).ok()? {
            Response::WrongProfile { expected } => {
                // Adopt the daemon's real profile and retry once on a fresh conn.
                self.adopt_profile(expected);
                let mut client = self.connect()?;
                let req = make(self.profile());
                client.call(&req).ok()
            }
            other => Some(other),
        }
    }

    /// Handle `status`: report `{locked, available, vaults}`. Never blocks; if the
    /// daemon is unreachable it reports unavailable + locked.
    #[must_use]
    pub fn status(&self) -> HostResponse {
        let Some(resp) = self.call(|profile| Request::Status { profile }) else {
            return HostResponse::Status {
                locked: true,
                available: false,
                vaults: 0,
            };
        };
        match resp {
            Response::Status {
                state, vault_count, ..
            } => HostResponse::Status {
                locked: state == LockState::Locked,
                available: true,
                vaults: vault_count.unwrap_or(0),
            },
            // Any other reply (shouldn't happen for Status) is treated as
            // reachable-but-locked, never a hang.
            _ => HostResponse::Status {
                locked: true,
                available: true,
                vaults: 0,
            },
        }
    }

    /// Handle `credentials_for`: return non-secret login candidates matching
    /// `origin`. Only `kind == "login"` (or unset) is served; other kinds yield
    /// an empty list. A locked/unavailable daemon yields [`HostResponse::Locked`].
    #[must_use]
    pub fn credentials_for(&self, origin: &str, kind: Option<&str>) -> HostResponse {
        // Only login credentials are supported for autofill.
        if let Some(k) = kind
            && !k.eq_ignore_ascii_case("login")
        {
            return HostResponse::Credentials {
                candidates: Vec::new(),
            };
        }
        let origin = origin.to_string();
        let Some(resp) = self.call(move |profile| Request::MatchLogins {
            profile,
            origin: origin.clone(),
        }) else {
            return HostResponse::Locked;
        };
        match resp {
            Response::LoginCandidates { candidates } => HostResponse::Credentials {
                candidates: candidates
                    .into_iter()
                    .map(|c| Candidate {
                        item_id: c.item_id,
                        title: c.title,
                        username: c.username,
                        vault: c.vault,
                    })
                    .collect(),
            },
            Response::Locked => HostResponse::Locked,
            Response::Error { message, .. } => HostResponse::Error {
                error: "daemon_error".into(),
                message,
            },
            _ => HostResponse::Locked,
        }
    }

    /// Handle `fill`: return `{username, password}` for exactly `item_id`, only if
    /// the daemon re-validates the item's URL against `origin`. A mismatch is an
    /// `origin_mismatch` error, never the secret. A locked/unavailable daemon
    /// yields [`HostResponse::Locked`].
    #[must_use]
    pub fn fill(&self, item_id: &str, origin: &str) -> HostResponse {
        let item_id = item_id.to_string();
        let origin = origin.to_string();
        let Some(resp) = self.call(move |profile| Request::FillLogin {
            profile,
            item_id: item_id.clone(),
            origin: origin.clone(),
        }) else {
            return HostResponse::Locked;
        };
        match resp {
            Response::Fill { username, password } => HostResponse::Fill { username, password },
            Response::Locked => HostResponse::Locked,
            // A refused fill (origin mismatch / wrong item / not a login) comes
            // back as a usage Error; surface it as origin_mismatch WITHOUT the
            // secret. The daemon's message is already secret-free.
            Response::Error { message, .. } => HostResponse::Error {
                error: "origin_mismatch".into(),
                message,
            },
            _ => HostResponse::Locked,
        }
    }
}
