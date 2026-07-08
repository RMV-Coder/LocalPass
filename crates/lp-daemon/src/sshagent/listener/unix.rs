#![cfg(unix)]
#![forbid(unsafe_code)]
//! Unix SSH agent socket: `$XDG_RUNTIME_DIR/localpass/ssh-agent.sock`.
//!
//! Same access control as the control socket ([`crate::transport::unix`]): a
//! `0700` parent dir, a `0600` socket, and a `SO_PEERCRED` euid check on every
//! accepted connection. The socket path is what the CLI prints for
//! `export SSH_AUTH_SOCK=…`.

use std::io::{self, Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::PathBuf;

use crate::error::{Error, Result};
use crate::transport::unix::{ensure_dir_0700, our_euid, peer_uid};

/// Directory (under the runtime dir or `$HOME`) holding the agent socket.
const RUNTIME_SUBDIR: &str = "localpass";
/// The agent socket file name.
const SOCKET_FILE: &str = "ssh-agent.sock";
/// Fallback runtime directory under `$HOME` when `XDG_RUNTIME_DIR` is unset.
const HOME_FALLBACK_DIR: &str = ".localpass-run";

/// Resolve the agent socket path and its parent directory.
///
/// `LOCALPASS_SSH_AGENT_SOCK` overrides the full socket path (its parent is used
/// as the `0700` directory). The default location is fixed per user, so parallel
/// integration tests would collide on it; each test points this at a unique path
/// to bind an isolated socket. Both the bind (daemon) and connect (client) sides
/// call this, so they always agree. Production leaves it unset.
fn socket_paths() -> Result<(PathBuf, PathBuf)> {
    if let Some(sock) = std::env::var_os("LOCALPASS_SSH_AGENT_SOCK").filter(|v| !v.is_empty()) {
        let sock = PathBuf::from(sock);
        let dir = sock
            .parent()
            .map(PathBuf::from)
            .ok_or_else(|| Error::Endpoint("LOCALPASS_SSH_AGENT_SOCK has no parent dir".into()))?;
        return Ok((dir, sock));
    }
    let (base, sub): (PathBuf, &str) =
        if let Some(rt) = std::env::var_os("XDG_RUNTIME_DIR").filter(|v| !v.is_empty()) {
            (PathBuf::from(rt), RUNTIME_SUBDIR)
        } else if let Some(home) = std::env::var_os("HOME").filter(|v| !v.is_empty()) {
            (PathBuf::from(home), HOME_FALLBACK_DIR)
        } else {
            return Err(Error::Endpoint(
                "neither XDG_RUNTIME_DIR nor HOME is set; cannot place the SSH agent socket".into(),
            ));
        };
    let dir = base.join(sub);
    let sock = dir.join(SOCKET_FILE);
    Ok((dir, sock))
}

/// A bound agent-socket listener that unlinks the socket on drop.
pub struct Listener {
    inner: UnixListener,
    path: PathBuf,
    euid: u32,
}

impl Listener {
    /// Bind the agent socket, creating a `0700` dir and a `0600` socket. A stale
    /// socket from a previous run (no live listener) is removed first.
    pub fn bind() -> Result<Self> {
        let (dir, path) = socket_paths()?;
        ensure_dir_0700(&dir)?;
        if path.exists() {
            if UnixStream::connect(&path).is_ok() {
                return Err(Error::Endpoint(format!(
                    "an SSH agent is already listening at {}",
                    path.display()
                )));
            }
            let _ = std::fs::remove_file(&path);
        }
        let inner = UnixListener::bind(&path)
            .map_err(|e| Error::Endpoint(format!("binding {}: {e}", path.display())))?;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
        Ok(Self {
            inner,
            path,
            euid: our_euid(),
        })
    }

    /// Accept the next connection, enforcing the peer-uid check.
    pub fn accept(&mut self) -> Result<Connection> {
        let (stream, _addr) = self.inner.accept()?;
        let uid = peer_uid(&stream)?;
        if uid != self.euid {
            return Err(Error::PeerRejected(format!(
                "agent peer uid {uid} != our euid {}",
                self.euid
            )));
        }
        Ok(Connection { stream })
    }

    /// The socket path label.
    pub fn endpoint_label(&self) -> String {
        self.path.display().to_string()
    }
}

impl Drop for Listener {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

/// A connected agent Unix stream.
pub struct Connection {
    stream: UnixStream,
}

impl Read for Connection {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.stream.read(buf)
    }
}

impl Write for Connection {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.stream.write(buf)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.stream.flush()
    }
}

/// The socket path label without binding.
pub fn endpoint_label() -> String {
    match socket_paths() {
        Ok((_dir, path)) => path.display().to_string(),
        Err(_) => "<unresolved ssh-agent socket>".to_string(),
    }
}

/// Wake a blocked `accept()` at shutdown by connecting once.
pub fn wake() {
    if let Ok((_dir, path)) = socket_paths() {
        let _ = UnixStream::connect(&path);
    }
}

/// Connect to the agent socket as a client (SSH-client side).
pub fn connect() -> Result<Connection> {
    let (_dir, path) = socket_paths()?;
    match UnixStream::connect(&path) {
        Ok(stream) => Ok(Connection { stream }),
        Err(e)
            if matches!(
                e.kind(),
                io::ErrorKind::NotFound | io::ErrorKind::ConnectionRefused
            ) =>
        {
            Err(Error::NotRunning)
        }
        Err(e) => Err(Error::Io(e)),
    }
}
