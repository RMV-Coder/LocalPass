//! The `localpass-daemon` binary: the per-user background agent.
//!
//! Normally launched detached by `localpass daemon start`, but can be run in the
//! foreground for debugging (`localpass-daemon --profile <dir> --verbose`).
//!
//! # Arguments
//!
//! ```text
//!   --profile <DIR>     the single profile directory to serve (required)
//!   --autolock <SECS>   idle auto-lock timeout in seconds (0 = never)
//!   --verbose           log request kinds + timings to stderr (never secrets)
//! ```
//!
//! When `--autolock` is absent, the `LOCALPASS_AUTOLOCK_SECS` env var is used;
//! when that is absent too, the default ([`lp_daemon::DEFAULT_AUTOLOCK_SECS`]).
//!
//! The daemon writes **no secret** to stdout/stderr ever. `--verbose` logs only
//! request/response *kinds* and timings.

use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Duration;

use lp_daemon::server::{self, Config};
use lp_daemon::transport;
use lp_daemon::{AUTOLOCK_ENV, DEFAULT_AUTOLOCK_SECS};

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(msg) => {
            eprintln!("localpass-daemon: {msg}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<(), String> {
    let args = parse_args()?;

    let profile = args
        .profile
        .ok_or_else(|| "missing required --profile <DIR>".to_string())?;

    let autolock_secs = match args.autolock {
        Some(secs) => secs,
        None => match std::env::var(AUTOLOCK_ENV) {
            Ok(v) => v
                .trim()
                .parse::<u64>()
                .map_err(|_| format!("{AUTOLOCK_ENV} must be a non-negative integer"))?,
            Err(_) => DEFAULT_AUTOLOCK_SECS,
        },
    };

    let username = transport::current_username();

    let config = Config {
        profile,
        autolock: Duration::from_secs(autolock_secs),
        username,
        verbose: args.verbose,
    };

    server::run(config).map_err(|e| e.to_string())
}

/// Parsed daemon arguments.
struct Args {
    profile: Option<PathBuf>,
    autolock: Option<u64>,
    verbose: bool,
}

/// A tiny hand-rolled argument parser (the daemon has three flags; pulling in
/// clap for the binary would duplicate the CLI's dependency for no gain).
fn parse_args() -> Result<Args, String> {
    let mut profile = None;
    let mut autolock = None;
    let mut verbose = false;

    let mut it = std::env::args().skip(1);
    while let Some(arg) = it.next() {
        match arg.as_str() {
            "--profile" => {
                let v = it
                    .next()
                    .ok_or_else(|| "--profile requires a directory argument".to_string())?;
                profile = Some(PathBuf::from(v));
            }
            "--autolock" => {
                let v = it
                    .next()
                    .ok_or_else(|| "--autolock requires a seconds argument".to_string())?;
                autolock = Some(
                    v.parse::<u64>()
                        .map_err(|_| "--autolock must be a non-negative integer".to_string())?,
                );
            }
            "--verbose" => verbose = true,
            other => return Err(format!("unknown argument {other:?}")),
        }
    }

    Ok(Args {
        profile,
        autolock,
        verbose,
    })
}
