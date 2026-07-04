#![forbid(unsafe_code)]
//! Launching the `localpass-daemon` binary as a detached background process.
//!
//! Used by `localpass daemon start`. The daemon must outlive the launching CLI
//! invocation, must not be tied to its console, and — critically — must inherit
//! **none** of the launcher's handles, so a piped `daemon start` (as under
//! `assert_cmd`) does not block waiting for the daemon to close an inherited
//! pipe. The platform-specific spawn lives in [`crate::transport`]:
//!
//! - **Windows:** `CreateProcessW` with `bInheritHandles = FALSE` and
//!   `DETACHED_PROCESS | CREATE_NO_WINDOW | CREATE_NEW_PROCESS_GROUP`. The
//!   `FALSE` is the load-bearing part — `std::process::Command` always spawns
//!   with `TRUE`, which leaks the launcher's stdio pipes into the daemon.
//! - **Unix:** `std::process::Command` with a new process group and stdio to
//!   `/dev/null` (so it neither receives the launcher's terminal signals nor
//!   holds its pipes open). A full double-fork/`setsid` daemonize is a later
//!   refinement; new-process-group + null stdio is sufficient for the MVP.
//!
//! The spawned daemon inherits the profile via `--profile` and the auto-lock via
//! `--autolock` (or, absent the flag, the `LOCALPASS_AUTOLOCK_SECS` env var).

use std::path::Path;
use std::time::Duration;

use crate::client;
use crate::error::Result;
use crate::transport;

/// How the `localpass-daemon` executable is located.
pub enum DaemonExe<'a> {
    /// An explicit path to the `localpass-daemon` binary.
    Path(&'a Path),
    /// Look it up next to the current executable (installed side-by-side), then
    /// fall back to `localpass-daemon` on `PATH`.
    Auto,
}

/// Resolve the daemon executable path.
fn resolve_exe(exe: &DaemonExe<'_>) -> std::path::PathBuf {
    match exe {
        DaemonExe::Path(p) => p.to_path_buf(),
        DaemonExe::Auto => {
            // Prefer a sibling of the current exe so a dev/CI build finds the
            // freshly-built daemon in the same target dir.
            if let Ok(mut cur) = std::env::current_exe() {
                cur.pop();
                #[cfg(windows)]
                let name = "localpass-daemon.exe";
                #[cfg(not(windows))]
                let name = "localpass-daemon";
                let sibling = cur.join(name);
                if sibling.exists() {
                    return sibling;
                }
            }
            // Fall back to PATH lookup by bare name.
            std::path::PathBuf::from("localpass-daemon")
        }
    }
}

/// Spawn the daemon detached for `profile`, with `autolock` seconds (`0` =
/// never), then wait up to `ready_timeout` for it to answer a Ping.
///
/// A no-op-friendly caller checks [`client::probe`] first; this function does
/// not (it always spawns), so callers implement the "friendly no-op if already
/// running" behavior.
///
/// # Errors
///
/// [`crate::Error::Io`] / [`crate::Error::Platform`] if the process cannot be
/// spawned, or [`crate::Error::NotRunning`] if it did not answer a Ping within
/// `ready_timeout`.
pub fn spawn_detached(
    exe: &DaemonExe<'_>,
    profile: &Path,
    autolock_secs: u64,
    verbose: bool,
    ready_timeout: Duration,
) -> Result<()> {
    let program = resolve_exe(exe);
    let mut args = vec![
        "--profile".to_string(),
        profile.display().to_string(),
        "--autolock".to_string(),
        autolock_secs.to_string(),
    ];
    if verbose {
        args.push("--verbose".to_string());
    }

    // Spawn fully detached with no inherited handles (see the module docs and
    // `transport::spawn_detached`). We do not hold a `Child` — the daemon is
    // independent of this process.
    transport::spawn_detached(&program, &args)?;

    // Wait for readiness so `daemon start` only returns once the endpoint is up.
    client::wait_until_ready(ready_timeout)
}
