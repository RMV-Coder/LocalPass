//! Unix domain socket transport with `SO_PEERCRED` peer-uid enforcement.
//!
//! # Endpoint
//!
//! The socket lives at `$XDG_RUNTIME_DIR/localpass/daemon.sock`. When
//! `XDG_RUNTIME_DIR` is unset (some minimal environments), we fall back to
//! `~/.localpass-run/daemon.sock`. The containing directory is created `0700`
//! and the socket is `chmod 0600` immediately after bind — so at the filesystem
//! level only the owner can reach it.
//!
//! # Access control (defense in depth)
//!
//! File permissions alone are the first line, but a same-uid-but-different
//! intent process on a misconfigured system could still connect, and on some
//! platforms socket-file permissions are not enforced. So **every accepted
//! connection's peer uid is read via `SO_PEERCRED` and compared to our
//! `geteuid()`** — a mismatch is rejected and the connection dropped
//! (PRD §7.3 OS peer credentials, §8 T8). The secret-bearing channel is trusted
//! only because both the permission gate and the peer check agree the far end is
//! us.
//!
//! # `username` on Unix
//!
//! Unlike Windows (where the pipe name embeds the sanitized username), the Unix
//! socket path is already per-user via `$XDG_RUNTIME_DIR` / `$HOME`. The
//! `username` argument is accepted for interface symmetry but not used to build
//! the path; per-user isolation comes from the runtime dir and the `0700`
//! parent.

#![cfg(unix)]
// This module calls `getsockopt(SO_PEERCRED)` and `geteuid` for the peer-uid
// access-control check; `deny(unsafe_code)` (crate-wide) permits this local
// opt-in. Every unsafe block documents its safety contract.
#![allow(unsafe_code)]

use std::io::{self, Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::io::AsRawFd;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};

use crate::error::{Error, Result};

/// Directory (under the runtime dir or `$HOME`) holding the daemon socket.
const RUNTIME_SUBDIR: &str = "localpass";
/// The socket file name.
const SOCKET_FILE: &str = "daemon.sock";
/// Fallback runtime directory under `$HOME` when `XDG_RUNTIME_DIR` is unset.
const HOME_FALLBACK_DIR: &str = ".localpass-run";

/// Resolve the socket path and its parent directory.
///
/// `$XDG_RUNTIME_DIR/localpass/daemon.sock`, else `~/.localpass-run/daemon.sock`.
fn socket_paths() -> Result<(PathBuf, PathBuf)> {
    let (base, sub): (PathBuf, &str) =
        if let Some(rt) = std::env::var_os("XDG_RUNTIME_DIR").filter(|v| !v.is_empty()) {
            (PathBuf::from(rt), RUNTIME_SUBDIR)
        } else if let Some(home) = std::env::var_os("HOME").filter(|v| !v.is_empty()) {
            (PathBuf::from(home), HOME_FALLBACK_DIR)
        } else {
            return Err(Error::Endpoint(
                "neither XDG_RUNTIME_DIR nor HOME is set; cannot place the daemon socket".into(),
            ));
        };
    let dir = base.join(sub);
    let sock = dir.join(SOCKET_FILE);
    Ok((dir, sock))
}

/// Create the socket directory `0700` if absent, and tighten it if it exists.
fn ensure_dir_0700(dir: &Path) -> Result<()> {
    if !dir.exists() {
        std::fs::create_dir_all(dir)?;
    }
    std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))?;
    Ok(())
}

/// Our effective uid.
fn our_euid() -> u32 {
    // SAFETY: geteuid() is always safe; it takes no arguments and cannot fail.
    unsafe { libc::geteuid() }
}

/// Read the peer's uid from a connected stream via `SO_PEERCRED`.
fn peer_uid(stream: &UnixStream) -> Result<u32> {
    let fd = stream.as_raw_fd();
    let mut cred = libc::ucred {
        pid: 0,
        uid: 0,
        gid: 0,
    };
    let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    // SAFETY: `fd` is a valid connected socket fd for the stream's lifetime;
    // `cred`/`len` are correctly sized out-params for SO_PEERCRED.
    let rc = unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            std::ptr::addr_of_mut!(cred).cast::<libc::c_void>(),
            &mut len,
        )
    };
    if rc != 0 {
        return Err(Error::Platform(format!(
            "getsockopt(SO_PEERCRED) failed: {}",
            io::Error::last_os_error()
        )));
    }
    Ok(cred.uid)
}

/// A bound Unix-socket listener that unlinks the socket on drop.
pub struct Listener {
    inner: UnixListener,
    path: PathBuf,
    euid: u32,
}

impl Listener {
    /// Bind the daemon socket, creating a `0700` directory and a `0600` socket.
    ///
    /// A stale socket file from a previous run is unlinked first (if binding
    /// fails with `AddrInUse` we surface it — a live daemon owns the endpoint).
    pub fn bind(_username: &str) -> Result<Self> {
        let (dir, path) = socket_paths()?;
        ensure_dir_0700(&dir)?;

        // Remove a stale socket file. A live peer would still hold the endpoint;
        // we detect that by attempting a connect first.
        if path.exists() {
            if connect_path(&path).is_ok() {
                return Err(Error::Endpoint(format!(
                    "a daemon is already listening at {}",
                    path.display()
                )));
            }
            // Stale file (no live listener): remove it so bind can proceed.
            let _ = std::fs::remove_file(&path);
        }

        let inner = UnixListener::bind(&path)
            .map_err(|e| Error::Endpoint(format!("binding {}: {e}", path.display())))?;
        // Tighten the socket to owner-only.
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;

        Ok(Self {
            inner,
            path,
            euid: our_euid(),
        })
    }

    /// Accept the next connection, enforcing the peer-uid check.
    ///
    /// Takes `&mut self` for interface symmetry with the Windows backend (which
    /// must roll a fresh pipe instance per accept); the Unix listener itself is
    /// unchanged across accepts.
    pub fn accept(&mut self) -> Result<Connection> {
        let (stream, _addr) = self.inner.accept()?;
        let uid = peer_uid(&stream)?;
        if uid != self.euid {
            // Drop the stream (closing it) and report — the server logs and
            // continues serving; this is a rejected impostor, not a fatal error.
            return Err(Error::PeerRejected(format!(
                "peer uid {uid} != our euid {}",
                self.euid
            )));
        }
        Ok(Connection { stream })
    }

    /// The socket path, for diagnostics.
    pub fn endpoint_label(&self) -> String {
        self.path.display().to_string()
    }
}

impl Drop for Listener {
    fn drop(&mut self) {
        // Best-effort unlink so a future bind is clean.
        let _ = std::fs::remove_file(&self.path);
    }
}

/// A connected Unix stream.
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

/// Connect to the daemon socket, mapping "nothing listening" to
/// [`Error::NotRunning`].
fn connect_path(path: &Path) -> Result<UnixStream> {
    match UnixStream::connect(path) {
        Ok(s) => Ok(s),
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

/// Client connect.
pub fn connect(_username: &str) -> Result<Connection> {
    let (_dir, path) = socket_paths()?;
    let stream = connect_path(&path)?;
    Ok(Connection { stream })
}

/// The socket path label for diagnostics.
pub fn endpoint_label(_username: &str) -> String {
    match socket_paths() {
        Ok((_dir, path)) => path.display().to_string(),
        Err(_) => "<unresolved unix socket>".to_string(),
    }
}

/// Spawn `program` with `args` detached: a new process group (so a terminal
/// signal to the launcher's group does not reach it) with stdio redirected to
/// `/dev/null` (so it never holds the launcher's pipes open). `process_group`
/// is a safe, stable std API — no `pre_exec`/`unsafe` needed for this level of
/// detachment.
pub fn spawn_detached(program: &Path, args: &[String]) -> Result<()> {
    use std::os::unix::process::CommandExt;
    use std::process::{Command, Stdio};
    Command::new(program)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .process_group(0)
        .spawn()
        .map(|_child| ())
        .map_err(Error::Io)
}
