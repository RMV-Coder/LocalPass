//! Unix domain socket transport with peer-uid enforcement (`SO_PEERCRED` on
//! Linux, `getpeereid` on macOS/BSD).
//!
//! # Endpoint
//!
//! The socket lives at `$XDG_RUNTIME_DIR/localpass/daemon-<username>.sock`. When
//! `XDG_RUNTIME_DIR` is unset (some minimal environments), we fall back to
//! `~/.localpass-run/daemon-<username>.sock`. The containing directory is created
//! `0700` and the socket is `chmod 0600` immediately after bind — so at the
//! filesystem level only the owner can reach it.
//!
//! # Access control (defense in depth)
//!
//! File permissions alone are the first line, but a same-uid-but-different
//! intent process on a misconfigured system could still connect, and on some
//! platforms socket-file permissions are not enforced. So **every accepted
//! connection's peer uid is read via the platform peer-credential call
//! (`SO_PEERCRED` / `getpeereid`) and compared to our `geteuid()`** — a mismatch
//! is rejected and the connection dropped
//! (PRD §7.3 OS peer credentials, §8 T8). The secret-bearing channel is trusted
//! only because both the permission gate and the peer check agree the far end is
//! us.
//!
//! # `username` on Unix
//!
//! The runtime dir (`$XDG_RUNTIME_DIR`, else `$HOME`) already scopes the socket
//! to the real user. The socket **file name** additionally embeds the sanitized
//! `username` (mirroring the Windows pipe name), so a single real user can run
//! independent daemons under distinct logical usernames — which is exactly how
//! the integration tests isolate: each overrides `USER`/`USERNAME` and gets its
//! own `daemon-<username>.sock`. Without this, parallel tests sharing one real
//! uid (and thus one runtime dir) would collide on a single socket.

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
/// Fallback runtime directory under `$HOME` when `XDG_RUNTIME_DIR` is unset.
const HOME_FALLBACK_DIR: &str = ".localpass-run";

/// Resolve the socket path and its parent directory for `username`.
///
/// `$XDG_RUNTIME_DIR/localpass/daemon-<username>.sock`, else
/// `~/.localpass-run/daemon-<username>.sock`. `username` is already sanitized to
/// `[a-z0-9._-]` by [`super::sanitize_username`], so it is a safe single path
/// component.
fn socket_paths(username: &str) -> Result<(PathBuf, PathBuf)> {
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
    let sock = dir.join(format!("daemon-{username}.sock"));
    Ok((dir, sock))
}

/// Create the socket directory `0700` if absent, and tighten it if it exists.
///
/// `pub(crate)` so the SSH agent listener can place its socket dir with the same
/// owner-only permissions.
pub(crate) fn ensure_dir_0700(dir: &Path) -> Result<()> {
    if !dir.exists() {
        std::fs::create_dir_all(dir)?;
    }
    std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))?;
    Ok(())
}

/// Our effective uid.
///
/// `pub(crate)` so the SSH agent listener ([`crate::sshagent::listener`]) can
/// enforce the same peer-uid == euid check on its own socket.
pub(crate) fn our_euid() -> u32 {
    // SAFETY: geteuid() is always safe; it takes no arguments and cannot fail.
    unsafe { libc::geteuid() }
}

/// Read the peer's effective uid from a connected stream.
///
/// Linux/Android expose it through `getsockopt(SO_PEERCRED)` (a `ucred` struct);
/// macOS and the BSDs use `getpeereid(2)`. Both return the connected peer's
/// effective uid, which the caller compares to our euid.
///
/// `pub(crate)` for reuse by the SSH agent listener's per-connection check.
#[cfg(any(target_os = "linux", target_os = "android"))]
pub(crate) fn peer_uid(stream: &UnixStream) -> Result<u32> {
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

/// macOS/BSD peer-uid via `getpeereid` (Linux's `SO_PEERCRED` is absent there).
///
/// `pub(crate)` for reuse by the SSH agent listener's per-connection check.
#[cfg(not(any(target_os = "linux", target_os = "android")))]
pub(crate) fn peer_uid(stream: &UnixStream) -> Result<u32> {
    let fd = stream.as_raw_fd();
    let mut uid: libc::uid_t = 0;
    let mut gid: libc::gid_t = 0;
    // SAFETY: `fd` is a valid connected socket fd for the stream's lifetime;
    // `uid`/`gid` are valid, correctly typed out-params for getpeereid.
    let rc =
        unsafe { libc::getpeereid(fd, std::ptr::addr_of_mut!(uid), std::ptr::addr_of_mut!(gid)) };
    if rc != 0 {
        return Err(Error::Platform(format!(
            "getpeereid failed: {}",
            io::Error::last_os_error()
        )));
    }
    Ok(uid)
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
    pub fn bind(username: &str) -> Result<Self> {
        let (dir, path) = socket_paths(username)?;
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
pub fn connect(username: &str) -> Result<Connection> {
    let (_dir, path) = socket_paths(username)?;
    let stream = connect_path(&path)?;
    Ok(Connection { stream })
}

/// The socket path label for diagnostics.
pub fn endpoint_label(username: &str) -> String {
    match socket_paths(username) {
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
