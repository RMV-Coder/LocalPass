//! Windows named-pipe transport whose DACL is the authentication.
//!
//! # Endpoint
//!
//! `\\.\pipe\localpass-<sanitized-username>`. The username is sanitized to
//! `[a-z0-9._-]` (see [`crate::transport::sanitize_username`]) so the pipe name
//! is always well-formed.
//!
//! # Access control — the DACL *is* the authentication (PRD §7.3, §8 T8)
//!
//! The pipe is created with an explicit `SECURITY_DESCRIPTOR` whose DACL
//! contains exactly **one** access-allowed ACE granting the **current user's
//! SID** full pipe access. There is **no** ACE for `Everyone`, `Authenticated
//! Users`, or `NT AUTHORITY\NETWORK`, and — because the DACL is present but
//! non-null — Windows denies everyone not named in it. Concretely:
//!
//! - A process running as **another user** cannot open the pipe: `CreateFileW`
//!   returns `ERROR_ACCESS_DENIED`. There is no password check on the wire
//!   because there cannot *be* another user on the far end.
//! - The pipe is created with `PIPE_REJECT_REMOTE_CLIENTS`, so even if a share
//!   or misconfiguration exposed the pipe namespace, a **remote** open is
//!   refused at the OS level (no `NETWORK` access).
//!
//! This mirrors the Unix side's "permissions + peer-uid check": there, the OS
//! tells us the peer uid and we compare; here, the OS enforces the DACL for us,
//! so a connection that is accepted is already same-user by construction. We
//! therefore do **not** additionally call `GetNamedPipeClientProcessId` for an
//! auth decision — the DACL already made it. (That API is available for future
//! per-client audit logging.)
//!
//! # Concurrency
//!
//! Each pipe *instance* serves one client at a time. The server keeps the
//! endpoint continuously available by creating the **next** instance before
//! handing the just-connected one to a worker thread (the standard overlapped-
//! free named-pipe server loop): [`Listener::accept`] connects the current
//! instance, then rolls a fresh instance into place for the next `accept`.

#![cfg(windows)]
// This module calls the Win32 named-pipe and security APIs to build the
// current-user-only DACL and do blocking pipe IO; `deny(unsafe_code)`
// (crate-wide) permits this local opt-in. Every unsafe block documents its
// safety contract inline.
#![allow(unsafe_code)]

use std::io::{self, Read, Write};
use std::os::windows::io::{FromRawHandle, IntoRawHandle, OwnedHandle};
use std::ptr;

use windows_sys::Win32::Foundation::{
    CloseHandle, ERROR_ACCESS_DENIED, ERROR_FILE_NOT_FOUND, ERROR_PIPE_BUSY, GENERIC_READ,
    GENERIC_WRITE, HANDLE, INVALID_HANDLE_VALUE, LocalFree, WAIT_TIMEOUT,
};
use windows_sys::Win32::Security::Authorization::{
    ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
};
use windows_sys::Win32::Security::{
    GetTokenInformation, SECURITY_ATTRIBUTES, TOKEN_QUERY, TOKEN_USER, TokenUser,
};
use windows_sys::Win32::Storage::FileSystem::{
    CreateFileW, FILE_FLAG_FIRST_PIPE_INSTANCE, OPEN_EXISTING, PIPE_ACCESS_DUPLEX,
};
use windows_sys::Win32::System::Pipes::{
    ConnectNamedPipe, CreateNamedPipeW, PIPE_READMODE_BYTE, PIPE_REJECT_REMOTE_CLIENTS,
    PIPE_TYPE_BYTE, PIPE_UNLIMITED_INSTANCES, PIPE_WAIT, WaitNamedPipeW,
};
use windows_sys::Win32::System::Threading::{
    CREATE_NEW_PROCESS_GROUP, CREATE_NO_WINDOW, CreateProcessW, DETACHED_PROCESS,
    GetCurrentProcess, OpenProcessToken, PROCESS_INFORMATION, STARTUPINFOW,
};

use crate::error::{Error, Result};
use crate::transport::sanitize_username;

/// Read/write buffer size hint for each pipe instance.
const PIPE_BUFFER: u32 = 64 * 1024;

/// Build the `\\.\pipe\localpass-<user>` name as a NUL-terminated UTF-16 vector.
fn pipe_name_wide(username: &str) -> Vec<u16> {
    let name = format!(r"\\.\pipe\localpass-{}", sanitize_username(username));
    name.encode_utf16().chain(std::iter::once(0)).collect()
}

/// The human-facing pipe name (no trailing NUL), for diagnostics.
pub fn endpoint_label(username: &str) -> String {
    format!(r"\\.\pipe\localpass-{}", sanitize_username(username))
}

/// Encode an arbitrary pipe name (e.g. `\\.\pipe\openssh-ssh-agent`) as a
/// NUL-terminated UTF-16 vector. Used by the SSH agent listener, which serves a
/// **fixed** pipe name (the one Windows OpenSSH expects) rather than a
/// per-user-derived one.
#[must_use]
pub fn pipe_name_wide_raw(name: &str) -> Vec<u16> {
    name.encode_utf16().chain(std::iter::once(0)).collect()
}

/// Fetch the current process token's user SID as an SDDL string (e.g.
/// `S-1-5-21-…`). Used to build a DACL that names exactly this user.
fn current_user_sid_string() -> Result<String> {
    // 1) Open our process token for query.
    let mut token: HANDLE = ptr::null_mut();
    // SAFETY: GetCurrentProcess returns a pseudo-handle; OpenProcessToken fills
    // `token` on success. We check the return and close the token below.
    let ok = unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) };
    if ok == 0 {
        return Err(Error::Platform(format!(
            "OpenProcessToken failed: {}",
            io::Error::last_os_error()
        )));
    }
    // Ensure the token handle is always closed.
    let _token_guard = HandleGuard(token);

    // 2) Query the required buffer size for TokenUser.
    let mut needed: u32 = 0;
    // SAFETY: first call with a null buffer just reports the needed size.
    unsafe {
        GetTokenInformation(token, TokenUser, ptr::null_mut(), 0, &mut needed);
    }
    if needed == 0 {
        return Err(Error::Platform(
            "GetTokenInformation reported size 0".into(),
        ));
    }
    let mut buf = vec![0u8; needed as usize];
    // SAFETY: `buf` is `needed` bytes; on success it holds a TOKEN_USER whose
    // `User.Sid` points inside `buf`.
    let ok = unsafe {
        GetTokenInformation(
            token,
            TokenUser,
            buf.as_mut_ptr().cast(),
            needed,
            &mut needed,
        )
    };
    if ok == 0 {
        return Err(Error::Platform(format!(
            "GetTokenInformation(TokenUser) failed: {}",
            io::Error::last_os_error()
        )));
    }

    // 3) Convert the SID to its string form.
    // SAFETY: `buf` holds a valid TOKEN_USER; read the Sid pointer from it.
    let token_user = unsafe { &*(buf.as_ptr() as *const TOKEN_USER) };
    let sid = token_user.User.Sid;
    if sid.is_null() {
        return Err(Error::Platform("token user SID was null".into()));
    }
    let sid_str = sid_to_string(sid)?;
    Ok(sid_str)
}

/// Convert a SID pointer to its `S-1-…` string form via `ConvertSidToStringSidW`.
fn sid_to_string(sid: *mut core::ffi::c_void) -> Result<String> {
    use windows_sys::Win32::Security::Authorization::ConvertSidToStringSidW;
    let mut out: *mut u16 = ptr::null_mut();
    // SAFETY: `sid` is a valid SID for the call's duration; `out` receives a
    // LocalAlloc'd string we free with LocalFree below.
    let ok = unsafe { ConvertSidToStringSidW(sid, &mut out) };
    if ok == 0 || out.is_null() {
        return Err(Error::Platform(format!(
            "ConvertSidToStringSidW failed: {}",
            io::Error::last_os_error()
        )));
    }
    let s = wide_ptr_to_string(out);
    // SAFETY: `out` was allocated by the API with LocalAlloc; free it once.
    unsafe {
        LocalFree(out.cast());
    }
    Ok(s)
}

/// Read a NUL-terminated UTF-16 string from a raw pointer into a `String`.
fn wide_ptr_to_string(mut p: *const u16) -> String {
    let mut units = Vec::new();
    // SAFETY: `p` points at a NUL-terminated UTF-16 buffer owned by the caller.
    unsafe {
        while *p != 0 {
            units.push(*p);
            p = p.add(1);
        }
    }
    String::from_utf16_lossy(&units)
}

/// A security descriptor built for the current-user-only DACL, freed on drop.
///
/// `pub(crate)` so the SSH agent listener ([`crate::sshagent::listener`]) can
/// reuse the exact same current-user-only DACL for its own (differently named)
/// pipe — the DACL is the authentication for both endpoints (PRD §8 T8).
pub(crate) struct SecurityDescriptor {
    psd: *mut core::ffi::c_void,
}

impl SecurityDescriptor {
    /// Build a self-relative security descriptor whose DACL grants the current
    /// user's SID full access to the pipe, denies remote/other users implicitly
    /// (present, non-null DACL), via an SDDL string.
    ///
    /// The SDDL is `D:(A;;GA;;;<user-sid>)`:
    /// - `D:` — the DACL section.
    /// - `(A;;GA;;;SID)` — one **A**llow ACE granting **G**eneric **A**ll to the
    ///   named SID and to nobody else. No `Everyone` (`WD`), no `NETWORK` (`NU`).
    pub(crate) fn current_user_only() -> Result<Self> {
        let sid = current_user_sid_string()?;
        let sddl = format!("D:(A;;GA;;;{sid})");
        let wide: Vec<u16> = sddl.encode_utf16().chain(std::iter::once(0)).collect();

        let mut psd: *mut core::ffi::c_void = ptr::null_mut();
        // SAFETY: `wide` is a valid NUL-terminated SDDL string; on success `psd`
        // receives a LocalAlloc'd self-relative security descriptor we free in
        // Drop. `SDDL_REVISION_1` is the required revision constant.
        let ok = unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                wide.as_ptr(),
                SDDL_REVISION_1,
                &mut psd,
                ptr::null_mut(),
            )
        };
        if ok == 0 || psd.is_null() {
            return Err(Error::Platform(format!(
                "ConvertStringSecurityDescriptorToSecurityDescriptorW failed: {}",
                io::Error::last_os_error()
            )));
        }
        Ok(Self { psd })
    }

    /// A `SECURITY_ATTRIBUTES` referencing this descriptor (non-inheritable).
    pub(crate) fn attributes(&self) -> SECURITY_ATTRIBUTES {
        SECURITY_ATTRIBUTES {
            nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: self.psd,
            bInheritHandle: 0,
        }
    }
}

impl Drop for SecurityDescriptor {
    fn drop(&mut self) {
        if !self.psd.is_null() {
            // SAFETY: `psd` was LocalAlloc'd by the conversion API; free once.
            unsafe {
                LocalFree(self.psd.cast());
            }
            self.psd = ptr::null_mut();
        }
    }
}

/// RAII wrapper closing a raw `HANDLE` on drop (for the token handle).
struct HandleGuard(HANDLE);
impl Drop for HandleGuard {
    fn drop(&mut self) {
        if !self.0.is_null() && self.0 != INVALID_HANDLE_VALUE {
            // SAFETY: we own this handle for the guard's lifetime.
            unsafe {
                CloseHandle(self.0);
            }
        }
    }
}

/// Create one blocking, byte-mode, duplex pipe instance protected by the DACL.
///
/// `pub(crate)` so the SSH agent listener can create instances of its own
/// (fixed-name) pipe with the same DACL + `FIRST_PIPE_INSTANCE` semantics.
pub(crate) fn create_instance(
    name: &[u16],
    sa: &SECURITY_ATTRIBUTES,
    first: bool,
) -> Result<OwnedHandle> {
    // FILE_FLAG_FIRST_PIPE_INSTANCE on the first instance guarantees we are the
    // sole owner of the name (a second daemon fails to create the first
    // instance). Both PIPE_ACCESS_DUPLEX and FILE_FLAG_FIRST_PIPE_INSTANCE are
    // FILE_FLAGS_AND_ATTRIBUTES (u32) under Storage::FileSystem.
    let mut open_mode = PIPE_ACCESS_DUPLEX;
    if first {
        open_mode |= FILE_FLAG_FIRST_PIPE_INSTANCE;
    }
    let pipe_mode = PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS;

    // SAFETY: `name` is a valid NUL-terminated wide string; `sa` is a valid
    // SECURITY_ATTRIBUTES pointing at our current-user-only descriptor. On
    // success we own the returned handle.
    let handle = unsafe {
        CreateNamedPipeW(
            name.as_ptr(),
            open_mode,
            pipe_mode,
            PIPE_UNLIMITED_INSTANCES,
            PIPE_BUFFER,
            PIPE_BUFFER,
            0,
            sa as *const SECURITY_ATTRIBUTES,
        )
    };
    if handle == INVALID_HANDLE_VALUE {
        let err = io::Error::last_os_error();
        // A first-instance failure with ACCESS_DENIED/ALREADY_EXISTS means
        // another daemon owns the name.
        return Err(Error::Endpoint(format!(
            "CreateNamedPipeW failed (name may already be owned by a running daemon): {err}"
        )));
    }
    // SAFETY: `handle` is a valid, owned pipe handle we just created.
    Ok(unsafe { OwnedHandle::from_raw_handle(handle as *mut _) })
}

/// A named-pipe server listener holding one *pending* instance ready to accept.
pub struct Listener {
    name: Vec<u16>,
    label: String,
    // The DACL descriptor is kept alive for the listener's lifetime so every
    // freshly-created instance can reference the same SECURITY_ATTRIBUTES.
    sd: SecurityDescriptor,
    // The next instance waiting to be connected. `accept` connects this one and
    // then creates a replacement so the endpoint is never momentarily absent.
    pending: Option<OwnedHandle>,
}

// The raw pipe handle is safe to move across threads; we only ever use one
// instance from one thread at a time (accept creates a fresh instance handed
// off to a worker). The descriptor pointer is only read to build SAs.
unsafe impl Send for Listener {}

impl Listener {
    /// Bind: build the DACL and create the first pipe instance.
    pub fn bind(username: &str) -> Result<Self> {
        let name = pipe_name_wide(username);
        let label = endpoint_label(username);
        let sd = SecurityDescriptor::current_user_only()?;
        let sa = sd.attributes();
        let pending = create_instance(&name, &sa, true)?;
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
            .ok_or_else(|| Error::Platform("listener has no pending pipe instance".into()))?;
        let raw = instance.into_raw_handle() as HANDLE;

        // Block until a client connects. ERROR_PIPE_CONNECTED means a client
        // connected between CreateNamedPipe and ConnectNamedPipe — also success.
        // SAFETY: `raw` is our valid pipe instance handle.
        let ok = unsafe { ConnectNamedPipe(raw, ptr::null_mut()) };
        if ok == 0 {
            let err = io::Error::last_os_error();
            // ERROR_PIPE_CONNECTED (535) is a success signal.
            const ERROR_PIPE_CONNECTED: i32 = 535;
            if err.raw_os_error() != Some(ERROR_PIPE_CONNECTED) {
                // SAFETY: close the handle we failed to connect.
                unsafe {
                    CloseHandle(raw);
                }
                // Re-arm a pending instance so the listener stays usable.
                let sa = self.sd.attributes();
                self.pending = Some(create_instance(&self.name, &sa, false)?);
                return Err(Error::Io(err));
            }
        }

        // Create the replacement instance BEFORE handing off this one, so the
        // endpoint is continuously connectable.
        let sa = self.sd.attributes();
        self.pending = Some(create_instance(&self.name, &sa, false)?);

        Ok(Connection { handle: raw })
    }

    /// The pipe name label.
    pub fn endpoint_label(&self) -> String {
        self.label.clone()
    }
}

/// A connected named-pipe instance — used for both the server-accepted side and
/// the client side. Byte IO goes through `ReadFile`/`WriteFile`; the handle is
/// closed on drop.
pub struct Connection {
    handle: HANDLE,
}

// A single connection is used from a single worker thread at a time.
unsafe impl Send for Connection {}

/// Wait for a client to connect on a freshly-created pipe instance `handle`,
/// then wrap it in a [`Connection`]. Shared by the daemon control listener and
/// the SSH agent listener. On a connect failure the handle is closed and the
/// error returned; the caller re-arms a fresh instance.
///
/// # Errors
///
/// [`Error::Io`] if `ConnectNamedPipe` fails for a reason other than the
/// already-connected race.
pub(crate) fn accept_on_instance(instance: OwnedHandle) -> Result<Connection> {
    let raw = instance.into_raw_handle() as HANDLE;
    // SAFETY: `raw` is our valid pipe instance handle.
    let ok = unsafe { ConnectNamedPipe(raw, ptr::null_mut()) };
    if ok == 0 {
        let err = io::Error::last_os_error();
        const ERROR_PIPE_CONNECTED: i32 = 535;
        if err.raw_os_error() != Some(ERROR_PIPE_CONNECTED) {
            // SAFETY: close the handle we failed to connect.
            unsafe {
                CloseHandle(raw);
            }
            return Err(Error::Io(err));
        }
    }
    Ok(Connection { handle: raw })
}

impl Read for Connection {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        use windows_sys::Win32::Storage::FileSystem::ReadFile;
        let mut read: u32 = 0;
        let to_read = u32::try_from(buf.len()).unwrap_or(u32::MAX);
        // SAFETY: `handle` is a valid pipe handle; `buf`/`read` are valid
        // out-params for `to_read` bytes.
        let ok = unsafe {
            ReadFile(
                self.handle,
                buf.as_mut_ptr(),
                to_read,
                &mut read,
                ptr::null_mut(),
            )
        };
        if ok == 0 {
            let err = io::Error::last_os_error();
            // A closed pipe surfaces as BROKEN_PIPE / PIPE_NOT_CONNECTED; map to
            // a clean EOF (0 bytes) so the framing layer sees end-of-stream.
            const ERROR_BROKEN_PIPE: i32 = 109;
            const ERROR_PIPE_NOT_CONNECTED: i32 = 233;
            if matches!(
                err.raw_os_error(),
                Some(ERROR_BROKEN_PIPE) | Some(ERROR_PIPE_NOT_CONNECTED)
            ) {
                return Ok(0);
            }
            return Err(err);
        }
        Ok(read as usize)
    }
}

impl Write for Connection {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        use windows_sys::Win32::Storage::FileSystem::WriteFile;
        let mut written: u32 = 0;
        let to_write = u32::try_from(buf.len()).unwrap_or(u32::MAX);
        // SAFETY: `handle` is a valid pipe handle; `buf`/`written` are valid.
        let ok = unsafe {
            WriteFile(
                self.handle,
                buf.as_ptr(),
                to_write,
                &mut written,
                ptr::null_mut(),
            )
        };
        if ok == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(written as usize)
    }
    fn flush(&mut self) -> io::Result<()> {
        // Named pipes are not buffered on our side beyond the OS; nothing to do.
        Ok(())
    }
}

impl Drop for Connection {
    fn drop(&mut self) {
        if !self.handle.is_null() && self.handle != INVALID_HANDLE_VALUE {
            // Just close the handle. We deliberately do NOT call
            // DisconnectNamedPipe first: on the server side that would discard
            // any response bytes the client has not yet read (the shutdown-race
            // failure mode). Closing lets the OS deliver already-written data,
            // then the client's read returns EOF. Each accept makes a fresh
            // instance, so we never need to reuse this one.
            // SAFETY: we own this handle.
            unsafe {
                CloseHandle(self.handle);
            }
            self.handle = INVALID_HANDLE_VALUE;
        }
    }
}

/// Connect to the daemon's pipe. Maps "no such pipe" to [`Error::NotRunning`]
/// and transiently handles `ERROR_PIPE_BUSY` (all instances momentarily busy)
/// by waiting briefly.
pub fn connect(username: &str) -> Result<Connection> {
    connect_pipe_by_name(&endpoint_label(username))
}

/// Connect to an arbitrary named pipe (e.g. the fixed SSH agent pipe). Shares
/// the control-pipe client logic: maps "no such pipe" / access-denied to
/// [`Error::NotRunning`] and retries transient `ERROR_PIPE_BUSY`.
///
/// `pub(crate)` so the SSH agent listener's `wake` path (and agent-pipe tests)
/// can open the fixed agent pipe by name.
///
/// # Errors
///
/// [`Error::NotRunning`] if nothing is listening at `name` (or the DACL denied
/// us); [`Error::Io`] on other failures.
pub(crate) fn connect_pipe_by_name(name: &str) -> Result<Connection> {
    let name = pipe_name_wide_raw(name);
    // Retry a bounded number of times on ERROR_PIPE_BUSY.
    for _ in 0..20 {
        // SAFETY: `name` is a NUL-terminated wide pipe name; on success we own
        // the returned handle.
        let handle = unsafe {
            CreateFileW(
                name.as_ptr(),
                GENERIC_READ | GENERIC_WRITE,
                0,
                ptr::null(),
                OPEN_EXISTING,
                // No overlapped: we do blocking IO from a dedicated thread.
                0,
                ptr::null_mut(),
            )
        };
        if handle != INVALID_HANDLE_VALUE {
            return Ok(Connection { handle });
        }
        let err = io::Error::last_os_error();
        match err.raw_os_error() {
            Some(code) if code == ERROR_FILE_NOT_FOUND as i32 => return Err(Error::NotRunning),
            Some(code) if code == ERROR_ACCESS_DENIED as i32 => {
                // The DACL denied us — a different user owns the pipe. Treat as
                // "not our daemon" so we fall back to a direct unlock.
                return Err(Error::NotRunning);
            }
            Some(code) if code == ERROR_PIPE_BUSY as i32 => {
                // All instances busy; wait up to 250ms for one to free, then
                // retry. WaitNamedPipeW returns 0 on timeout.
                // SAFETY: `name` is a valid NUL-terminated pipe name.
                let waited = unsafe { WaitNamedPipeW(name.as_ptr(), 250) };
                if waited == 0 {
                    let werr = io::Error::last_os_error();
                    if werr.raw_os_error() == Some(WAIT_TIMEOUT as i32) {
                        continue;
                    }
                }
                continue;
            }
            _ => return Err(Error::Io(err)),
        }
    }
    Err(Error::NotRunning)
}

/// Spawn `program` with `args` as a fully detached daemon that inherits **no**
/// handles from us.
///
/// This is the Windows-correct daemon launch. `std::process::Command` spawns
/// with `bInheritHandles = TRUE`, so a detached daemon would inherit the
/// launcher's stdio pipes — and when the launcher's own stdout is a pipe (as
/// under `assert_cmd`, or `$(localpass daemon start)`), the daemon holding a
/// copy of that pipe's write end means the reader never sees EOF and blocks
/// until the daemon exits. Passing `bInheritHandles = FALSE` here breaks that:
/// the daemon inherits nothing, so the launcher's pipe closes normally. The
/// daemon has no console (`DETACHED_PROCESS | CREATE_NO_WINDOW`) and its own
/// process group (`CREATE_NEW_PROCESS_GROUP`); it writes no stdout and only
/// optional `--verbose` stderr, which simply goes nowhere when detached.
///
/// # Errors
///
/// [`Error::Platform`] if `CreateProcessW` fails.
pub fn spawn_detached(program: &std::path::Path, args: &[String]) -> Result<()> {
    // Build a properly quoted command line: "program" arg1 arg2 ...
    let mut cmdline = String::new();
    push_quoted(&mut cmdline, &program.display().to_string());
    for a in args {
        cmdline.push(' ');
        push_quoted(&mut cmdline, a);
    }
    // CreateProcessW may modify the command-line buffer in place, so it must be
    // a writable NUL-terminated UTF-16 buffer.
    let mut cmdline_w: Vec<u16> = cmdline.encode_utf16().chain(std::iter::once(0)).collect();

    let mut si: STARTUPINFOW = unsafe { std::mem::zeroed() };
    si.cb = std::mem::size_of::<STARTUPINFOW>() as u32;
    let mut pi: PROCESS_INFORMATION = unsafe { std::mem::zeroed() };

    let flags = DETACHED_PROCESS | CREATE_NO_WINDOW | CREATE_NEW_PROCESS_GROUP;

    // SAFETY: `cmdline_w` is a writable NUL-terminated UTF-16 buffer of the
    // correct length; `si`/`pi` are properly sized/zeroed out-params. We pass
    // null for application name (the exe is the first cmdline token), null
    // attributes, FALSE inherit-handles (the whole point), null environment
    // (inherit ours), and null current dir (inherit ours).
    let ok = unsafe {
        CreateProcessW(
            ptr::null(),
            cmdline_w.as_mut_ptr(),
            ptr::null(),
            ptr::null(),
            0, // bInheritHandles = FALSE — daemon inherits no handles from us
            flags,
            ptr::null(),
            ptr::null(),
            &si,
            &mut pi,
        )
    };
    if ok == 0 {
        return Err(Error::Platform(format!(
            "CreateProcessW failed: {}",
            io::Error::last_os_error()
        )));
    }
    // We do not wait on the daemon; close the handles we were handed so we don't
    // leak them (the process keeps running).
    // SAFETY: both handles were just returned to us by CreateProcessW.
    unsafe {
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
    }
    Ok(())
}

/// Append `arg` to a Windows command line, quoting per the CommandLineToArgvW
/// rules (wrap in quotes if it contains spaces/tabs/quotes; backslash-escape
/// embedded quotes and the run of backslashes before a quote).
fn push_quoted(out: &mut String, arg: &str) {
    let needs_quotes = arg.is_empty() || arg.chars().any(|c| c == ' ' || c == '\t' || c == '"');
    if !needs_quotes {
        out.push_str(arg);
        return;
    }
    out.push('"');
    let mut backslashes = 0usize;
    for ch in arg.chars() {
        match ch {
            '\\' => {
                backslashes += 1;
            }
            '"' => {
                // Escape all pending backslashes (they precede a quote) and the
                // quote itself.
                for _ in 0..=backslashes {
                    out.push('\\');
                }
                out.push('"');
                backslashes = 0;
            }
            other => {
                for _ in 0..backslashes {
                    out.push('\\');
                }
                backslashes = 0;
                out.push(other);
            }
        }
    }
    // Escape trailing backslashes so they don't escape the closing quote.
    for _ in 0..(backslashes * 2) {
        out.push('\\');
    }
    out.push('"');
}
