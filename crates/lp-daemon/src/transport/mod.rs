// NOTE: no module-level `forbid(unsafe_code)` here — this module is the parent
// of the platform transport modules (`windows`/`unix`), which must opt back into
// `unsafe`. A `forbid` here would propagate into them and could not be overridden
// (unlike the crate-level `deny`). This file itself contains no `unsafe`.
//! Platform transport: a same-user-only local IPC endpoint.
//!
//! LocalPass never uses a localhost TCP port (that whole class of
//! local-port-hijack bugs is out, PRD §4.7 / §8 T8). Instead:
//!
//! - **Windows:** a named pipe `\\.\pipe\localpass-<sanitized-username>` whose
//!   security descriptor's DACL grants access to the **current user's SID
//!   only** — no `Everyone`, no `NT AUTHORITY\NETWORK`. The DACL *is* the
//!   authentication: a process running as another user simply cannot open the
//!   pipe (PRD §7.3, §8 T8). See the `windows` submodule.
//! - **Unix:** a `SOCK_STREAM` domain socket at
//!   `$XDG_RUNTIME_DIR/localpass/daemon.sock` (fallback
//!   `~/.localpass-run/daemon.sock`). The directory is `0700` and the socket is
//!   `0600`, and **every** accepted connection's peer uid is checked against our
//!   euid via `SO_PEERCRED` — a mismatch is rejected. Permissions plus the peer
//!   check are the authentication. See the `unix` submodule.
//!
//! Both platforms expose the same three things through this module:
//!
//! - [`Listener`] — binds the endpoint and yields [`Connection`]s. `accept`
//!   already performed the platform access-control check, so a yielded
//!   connection is trusted as same-user.
//! - [`Connection`] — a bidirectional byte stream (`Read + Write`), the substrate
//!   [`crate::frame`] speaks over.
//! - [`connect`] — the client side: open the endpoint or return
//!   [`crate::error::Error::NotRunning`] if nothing is listening.
//!
//! The [`endpoint_label`] helper renders the human-facing endpoint string for
//! diagnostics (`localpass status` prints it); it is not a filesystem path on
//! Windows.

use crate::error::Result;

#[cfg(unix)]
pub mod unix;
#[cfg(windows)]
pub mod windows;

#[cfg(unix)]
use unix as imp;
#[cfg(windows)]
use windows as imp;

/// A bound listener that yields same-user connections.
///
/// Dropping the listener releases the endpoint. On Unix the socket file is
/// unlinked on drop; on Windows the pipe instance is closed (the OS reclaims the
/// name when the last handle closes).
pub struct Listener(imp::Listener);

/// One accepted client connection: a bidirectional byte stream.
pub struct Connection(imp::Connection);

impl Listener {
    /// Bind the endpoint for `username`'s daemon, applying the platform access
    /// control (Windows DACL / Unix dir+socket perms).
    ///
    /// # Errors
    ///
    /// [`crate::error::Error::Endpoint`] / [`crate::error::Error::Platform`] on a
    /// bind or access-control failure, including when another daemon already
    /// owns the endpoint.
    pub fn bind(username: &str) -> Result<Self> {
        Ok(Self(imp::Listener::bind(username)?))
    }

    /// Block until the next same-user client connects, returning the accepted
    /// [`Connection`]. The platform peer/DACL check has already passed.
    ///
    /// Takes `&mut self` because the Windows backend rolls a fresh pipe instance
    /// into place on each accept (the Unix backend simply re-uses the listener).
    ///
    /// # Errors
    ///
    /// [`crate::error::Error::PeerRejected`] if a Unix peer uid did not match
    /// our euid (the connection is dropped and this returns the error so the
    /// server can log and continue); other transport failures as their variants.
    pub fn accept(&mut self) -> Result<Connection> {
        Ok(Connection(self.0.accept()?))
    }

    /// The human-facing endpoint label for diagnostics.
    #[must_use]
    pub fn endpoint_label(&self) -> String {
        self.0.endpoint_label()
    }
}

impl std::io::Read for Connection {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.0.read(buf)
    }
}

impl std::io::Write for Connection {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.write(buf)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        self.0.flush()
    }
}

/// Connect to a running daemon for `username`.
///
/// # Errors
///
/// [`crate::error::Error::NotRunning`] if no daemon is listening (the client
/// then falls back to a direct unlock); other transport failures as their
/// variants.
pub fn connect(username: &str) -> Result<Connection> {
    Ok(Connection(imp::connect(username)?))
}

/// The human-facing endpoint label for `username` (pipe name on Windows, socket
/// path on Unix). Used in diagnostics and `status` output.
#[must_use]
pub fn endpoint_label(username: &str) -> String {
    imp::endpoint_label(username)
}

/// Spawn `program` with `args` as a fully detached daemon that inherits no
/// handles from the launcher.
///
/// On **Windows** this uses `CreateProcessW` with `bInheritHandles = FALSE`
/// (in the `windows` submodule) — critical so the daemon does not inherit the
/// launcher's stdio pipes and block a piped `daemon start` (e.g. under
/// `assert_cmd`). On **Unix** this uses `std::process::Command` with a new
/// process group and stdio redirected to `/dev/null`.
///
/// # Errors
///
/// [`crate::error::Error::Platform`] / [`crate::error::Error::Io`] on a spawn
/// failure.
pub fn spawn_detached(program: &std::path::Path, args: &[String]) -> Result<()> {
    imp::spawn_detached(program, args)
}

/// Sanitize a username into the `[A-Za-z0-9._-]` charset used in the endpoint
/// name, lowercasing and collapsing anything else to `_`. Shared by both
/// platforms so the pipe/socket-dir naming is identical in spirit.
///
/// An empty or fully-stripped username falls back to `"user"` so the endpoint is
/// always well-formed.
#[must_use]
pub fn sanitize_username(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len());
    for ch in raw.chars() {
        if ch.is_ascii_alphanumeric() || matches!(ch, '.' | '_' | '-') {
            out.push(ch.to_ascii_lowercase());
        } else {
            out.push('_');
        }
    }
    // Bound the length so the Windows pipe name stays well within limits.
    out.truncate(64);
    if out.chars().all(|c| c == '_') || out.is_empty() {
        return "user".to_string();
    }
    out
}

/// Best-effort current username, from the platform's environment variable
/// (`USERNAME` on Windows, `USER`/`LOGNAME` on Unix), sanitized. Falls back to
/// `"user"`. The daemon and CLI must agree on this so they name the same
/// endpoint; both call here.
#[must_use]
pub fn current_username() -> String {
    #[cfg(windows)]
    let raw = std::env::var("USERNAME").ok();
    #[cfg(unix)]
    let raw = std::env::var("USER")
        .ok()
        .or_else(|| std::env::var("LOGNAME").ok());
    sanitize_username(raw.as_deref().unwrap_or("user").trim())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sanitize_lowercases_and_replaces() {
        assert_eq!(sanitize_username("Alice"), "alice");
        assert_eq!(sanitize_username("dom\\admin"), "dom_admin");
        assert_eq!(sanitize_username("a b*c"), "a_b_c");
        assert_eq!(sanitize_username("ok.name-1_2"), "ok.name-1_2");
    }

    #[test]
    fn sanitize_handles_empty_and_all_separators() {
        assert_eq!(sanitize_username(""), "user");
        assert_eq!(sanitize_username("***"), "user");
    }

    #[test]
    fn current_username_is_nonempty() {
        assert!(!current_username().is_empty());
    }
}
