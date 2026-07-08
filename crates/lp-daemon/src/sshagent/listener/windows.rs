#![cfg(windows)]
// This module contains no Win32 calls of its own — it delegates every unsafe
// operation to the audited `transport::windows` helpers — but it needs one
// `unsafe impl Send` for `Listener` (which holds a raw security-descriptor
// pointer via `SecurityDescriptor`), exactly as `transport::windows::Listener`
// does. `deny(unsafe_code)` (crate-wide) permits this local opt-in; the single
// unsafe impl documents its contract inline.
#![allow(unsafe_code)]
//! Windows SSH agent named pipe: `\\.\pipe\openssh-ssh-agent`.
//!
//! This is the **fixed** pipe name Windows OpenSSH (`ssh.exe`, `ssh-add.exe`)
//! opens by default, so no `SSH_AUTH_SOCK` is needed. We create it with the
//! **same current-user-only DACL + `FIRST_PIPE_INSTANCE`** as the control pipe,
//! reusing [`crate::transport::windows`]'s security-descriptor and pipe-instance
//! helpers — the DACL is the authentication (PRD §8 T8).
//!
//! # Conflict with Microsoft's ssh-agent service
//!
//! Because the name is fixed and system-wide, only one process can own it.
//! Windows ships an `ssh-agent` **service** that, when running, holds this exact
//! name. In that case `CreateNamedPipeW` with `FIRST_PIPE_INSTANCE` fails and
//! [`Listener::bind`] returns a clear [`Error::Endpoint`] telling the user to
//! stop that service (`Stop-Service ssh-agent`). We do **not** stop it ourselves
//! — that is a system service the user controls.
//!
//! This module contains no `unsafe` of its own: it delegates the Win32 calls to
//! the (already-audited) `transport::windows` helpers.

use std::io::{self, Read, Write};

use crate::error::{Error, Result};
use crate::transport::windows::{
    Connection as PipeConnection, SecurityDescriptor, accept_on_instance, create_instance,
    pipe_name_wide_raw,
};

/// The pipe name Windows OpenSSH's `ssh.exe` opens by default. Production always
/// uses this so the agent is drop-in compatible (no `SSH_AUTH_SOCK` needed).
const DEFAULT_AGENT_PIPE_NAME: &str = r"\\.\pipe\openssh-ssh-agent";

/// The agent pipe name, honoring the `LOCALPASS_SSH_AGENT_PIPE` override.
///
/// The default ([`DEFAULT_AGENT_PIPE_NAME`]) is a **fixed, machine-global** name,
/// so only one agent can own it — which makes integration tests collide with any
/// running daemon. Tests set this env var to a unique pipe so each binds its own
/// isolated endpoint; production leaves it unset for OpenSSH compatibility. Both
/// the bind (daemon) and connect (client) sides read it, so they always agree.
fn agent_pipe_name() -> String {
    std::env::var("LOCALPASS_SSH_AGENT_PIPE")
        .ok()
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| DEFAULT_AGENT_PIPE_NAME.to_string())
}

/// A named-pipe agent listener holding one pending instance ready to accept.
pub struct Listener {
    name: Vec<u16>,
    /// The resolved pipe name this listener bound (for `endpoint_label`).
    label: String,
    sd: SecurityDescriptor,
    pending: Option<std::os::windows::io::OwnedHandle>,
}

// SAFETY: the pending pipe handle is safe to move across threads (only one
// instance is used from one thread at a time — accept creates a fresh instance
// handed to a worker), and the SecurityDescriptor's raw pointer is only read to
// build SECURITY_ATTRIBUTES. Mirrors `transport::windows::Listener`'s identical
// `unsafe impl Send`.
unsafe impl Send for Listener {}

impl Listener {
    /// Bind: build the current-user-only DACL and create the first pipe
    /// instance. Fails with a clear message when Microsoft's `ssh-agent` service
    /// (or any process) already owns the name.
    pub fn bind() -> Result<Self> {
        let label = agent_pipe_name();
        let name = pipe_name_wide_raw(&label);
        let sd = SecurityDescriptor::current_user_only()?;
        let sa = sd.attributes();
        let pending = create_instance(&name, &sa, true).map_err(|e| {
            Error::Endpoint(format!(
                "could not create the SSH agent pipe {label}: {e}. \
                 If Windows' own OpenSSH agent service holds this name, stop it first: \
                 `Stop-Service ssh-agent` (and optionally `Set-Service ssh-agent -StartupType Disabled`)."
            ))
        })?;
        Ok(Self {
            name,
            label,
            sd,
            pending: Some(pending),
        })
    }

    /// Wait for a client to connect to the pending instance, then roll a fresh
    /// instance into place and return the connected one.
    pub fn accept(&mut self) -> Result<Connection> {
        let instance = self
            .pending
            .take()
            .ok_or_else(|| Error::Platform("agent listener has no pending pipe instance".into()))?;
        // Re-arm a replacement BEFORE handing off, so the endpoint stays
        // continuously connectable. If connect fails we still re-arm below.
        let conn = accept_on_instance(instance);
        let sa = self.sd.attributes();
        self.pending = Some(create_instance(&self.name, &sa, false)?);
        Ok(Connection(conn?))
    }

    /// The pipe name label.
    pub fn endpoint_label(&self) -> String {
        self.label.clone()
    }
}

/// A connected agent pipe instance (thin wrapper over the transport connection).
pub struct Connection(PipeConnection);

impl Read for Connection {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.0.read(buf)
    }
}

impl Write for Connection {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0.write(buf)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.0.flush()
    }
}

/// The pipe name label without binding.
pub fn endpoint_label() -> String {
    agent_pipe_name()
}

/// Wake a blocked `accept()` at shutdown by connecting once to the agent pipe.
pub fn wake() {
    use crate::transport::windows::connect_pipe_by_name;
    let _ = connect_pipe_by_name(&agent_pipe_name());
}

/// Connect to the agent pipe as a client (SSH-client side).
pub fn connect() -> Result<Connection> {
    use crate::transport::windows::connect_pipe_by_name;
    Ok(Connection(connect_pipe_by_name(&agent_pipe_name())?))
}
