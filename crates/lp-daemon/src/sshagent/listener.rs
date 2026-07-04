// NOTE: no module-level `forbid(unsafe_code)` here — the Windows submodule must
// opt back into `unsafe` for the Win32 named-pipe APIs (as `transport::windows`
// does). This file itself contains no `unsafe`.
//! The SSH agent endpoint: a second same-user-only listener the daemon serves
//! alongside its control pipe/socket.
//!
//! # Endpoints
//!
//! - **Windows:** the named pipe `\\.\pipe\openssh-ssh-agent` — the **fixed**
//!   name Windows OpenSSH's `ssh.exe` / `ssh-add.exe` use by default, so no
//!   `SSH_AUTH_SOCK` configuration is needed. It is created with the **same
//!   current-user-only DACL + `FIRST_PIPE_INSTANCE`** pattern as the control
//!   pipe (reusing [`crate::transport`]'s security-descriptor code): the DACL is
//!   the authentication (PRD §8 T8). Because the name is fixed and system-wide,
//!   **Microsoft's own `ssh-agent` service must be stopped** for the name to be
//!   free — if it holds the name, [`AgentListener::bind`] fails with a clear
//!   message naming the conflict.
//! - **Unix:** `$XDG_RUNTIME_DIR/localpass/ssh-agent.sock` (fallback
//!   `~/.localpass-run/ssh-agent.sock`), with the dir `0700` and the socket
//!   `0600`, plus a `SO_PEERCRED` euid check on every connection — identical to
//!   the control socket. The CLI prints `export SSH_AUTH_SOCK=<path>` guidance.
//!
//! # Request loop
//!
//! [`serve`] runs the accept loop on its own thread (spawned by
//! [`crate::server`]). Each accepted connection is handed to a worker that reads
//! agent messages ([`crate::sshagent::protocol`]), takes the daemon state mutex
//! **briefly** to handle each one via [`crate::sshagent::service::handle_request`]
//! (passing the current session, or `None` when locked), releases the lock, and
//! writes the reply. Client IO never happens under the lock — the same
//! hung-client immunity as the control protocol.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use crate::engine::State;
use crate::error::Result;
use crate::sshagent::protocol;
use crate::sshagent::service;

#[cfg(unix)]
mod unix;
#[cfg(windows)]
mod windows;

#[cfg(unix)]
use unix as imp;
#[cfg(windows)]
use windows as imp;

/// A bound SSH agent listener that yields same-user connections.
pub struct AgentListener(imp::Listener);

/// One accepted agent client connection (a bidirectional byte stream).
pub struct AgentConnection(imp::Connection);

impl AgentListener {
    /// Bind the agent endpoint, applying the platform access control (the same
    /// current-user-only DACL on Windows / `0700`+`0600`+peer-uid on Unix as the
    /// control endpoint).
    ///
    /// # Errors
    ///
    /// [`crate::error::Error::Endpoint`] / [`crate::error::Error::Platform`] on a
    /// bind failure — notably, on Windows, when the fixed pipe name is already
    /// owned (e.g. by Microsoft's `ssh-agent` service). The message names the
    /// conflict.
    pub fn bind() -> Result<Self> {
        Ok(Self(imp::Listener::bind()?))
    }

    /// Block until the next same-user client connects.
    ///
    /// # Errors
    ///
    /// [`crate::error::Error::PeerRejected`] if a Unix peer uid mismatched (the
    /// connection is dropped and the error returned so the loop can log and keep
    /// serving); other transport failures as their variants.
    pub fn accept(&mut self) -> Result<AgentConnection> {
        Ok(AgentConnection(self.0.accept()?))
    }

    /// The human-facing endpoint label (pipe name / socket path) for diagnostics
    /// and the `status`/CLI guidance.
    #[must_use]
    pub fn endpoint_label(&self) -> String {
        self.0.endpoint_label()
    }
}

impl std::io::Read for AgentConnection {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.0.read(buf)
    }
}

impl std::io::Write for AgentConnection {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.write(buf)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        self.0.flush()
    }
}

/// The human-facing endpoint label without binding (for CLI guidance / status).
#[must_use]
pub fn endpoint_label() -> String {
    imp::endpoint_label()
}

/// Connect to the running agent endpoint as a client (the SSH-client side).
///
/// Used by the integration tests to drive the agent with hand-built protocol
/// messages, and available to any in-process caller that wants to talk to the
/// agent the daemon is serving.
///
/// # Errors
///
/// [`crate::error::Error::NotRunning`] if no agent is listening; other transport
/// failures as their variants.
pub fn connect() -> Result<AgentConnection> {
    Ok(AgentConnection(imp::connect()?))
}

/// Run the SSH agent accept loop until `running` is cleared.
///
/// `state` is the **shared** daemon state (the same `Mutex<State>` the control
/// server guards), so identity listing and signing see the live unlocked
/// session and lock/auto-lock take effect immediately. `running` is the server's
/// shared shutdown flag. `verbose` gates request-kind logging.
///
/// Returns after the loop observes `running == false`. Because `accept()`
/// blocks, the caller wakes it at shutdown by connecting once to the endpoint
/// (see [`wake`]).
pub fn serve(
    listener: &mut AgentListener,
    state: &Arc<Mutex<State>>,
    running: &Arc<AtomicBool>,
    verbose: bool,
) {
    let mut workers: Vec<std::thread::JoinHandle<()>> = Vec::new();
    while running.load(Ordering::Acquire) {
        match listener.accept() {
            Ok(conn) => {
                workers.retain(|w| !w.is_finished());
                let state = Arc::clone(state);
                let running = Arc::clone(running);
                workers.push(std::thread::spawn(move || {
                    serve_connection(conn, &state, &running, verbose);
                }));
            }
            Err(crate::error::Error::PeerRejected(msg)) => {
                if verbose {
                    log(&format!("rejected agent peer: {msg}"));
                }
            }
            Err(e) => {
                if !running.load(Ordering::Acquire) {
                    break;
                }
                if verbose {
                    log(&format!("agent accept error: {e}"));
                }
            }
        }
    }
    for w in workers {
        if w.is_finished() {
            let _ = w.join();
        }
    }
}

/// Serve one agent connection: read requests, handle each under the state mutex,
/// write replies. A malformed message or IO error ends this connection only.
fn serve_connection(
    mut conn: AgentConnection,
    state: &Arc<Mutex<State>>,
    running: &Arc<AtomicBool>,
    verbose: bool,
) {
    loop {
        if !running.load(Ordering::Acquire) {
            return;
        }
        // Read one agent request — NO lock held (a slow client can't block the
        // mutex, matching the control server's hung-client immunity).
        let request = match protocol::read_request(&mut conn) {
            Ok(Some(req)) => req,
            Ok(None) => return, // clean EOF between messages
            Err(_) => return,   // malformed / IO error: drop the connection
        };

        // Handle under the lock (brief; no client IO inside). The session is
        // passed as Some(&session) when unlocked, None when locked.
        let reply = {
            let guard = state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let session = guard.session_ref();
            service::handle_request(session, &request, verbose)
        };

        // Write the reply outside the lock. A write failure ends the connection.
        if std::io::Write::write_all(&mut conn, &reply).is_err() {
            return;
        }
    }
}

/// Wake a blocked agent `accept()` at shutdown by connecting once to the
/// endpoint. Best-effort — we only need `accept()` to return so the loop
/// re-checks `running`.
pub fn wake() {
    imp::wake();
}

/// Log one line to stderr, prefixed. Never a secret or key bytes.
fn log(msg: &str) {
    eprintln!("[localpass-daemon ssh-agent] {msg}");
}
