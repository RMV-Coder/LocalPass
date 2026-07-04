//! The `localpass-native-host` binary: the browser native-messaging host.
//!
//! The browser launches this process (per its native-messaging manifest) and
//! pipes messages over the process's stdin/stdout. It is **not** meant to be run
//! interactively; when a human runs it in a terminal it just waits for framed
//! input on stdin and answers on stdout (stderr carries logs).
//!
//! # Arguments (browsers pass none; these are for manual/testing use)
//!
//! ```text
//!   --profile <DIR>   seed the daemon profile guess (usually unnecessary — the
//!                     host adopts the running daemon's profile automatically).
//!   --quiet           suppress the stderr log lines (types only; never secrets).
//! ```
//!
//! When `--profile` is absent, `LOCALPASS_PROFILE` is used if set; otherwise the
//! host starts with an empty guess and adopts the daemon's profile on the first
//! `WrongProfile` reply (see [`lp_native_host::bridge`]).
//!
//! Browsers may append extra arguments (Chrome passes the calling extension's
//! origin; Firefox passes the extension id and, on some platforms, a window
//! handle). We ignore any unrecognized argument rather than erroring, so a
//! browser-appended argument never prevents startup.

#![deny(unsafe_code)]

use std::io::{self, Write};
use std::process::ExitCode;

use lp_native_host::bridge::Bridge;
use lp_native_host::host;

fn main() -> ExitCode {
    let args = parse_args();

    // The profile seed: --profile, else LOCALPASS_PROFILE, else empty (adopted
    // from the daemon on first contact).
    let profile = args
        .profile
        .or_else(|| std::env::var("LOCALPASS_PROFILE").ok())
        .unwrap_or_default();
    let bridge = Bridge::new(profile);

    // Lock stdin/stdout for the whole session. Native messaging is binary-framed,
    // so we must not let any other code interleave on these handles.
    let stdin = io::stdin();
    let stdout = io::stdout();
    let mut reader = stdin.lock();
    let mut writer = stdout.lock();

    let quiet = args.quiet;
    let log = |line: &str| {
        if !quiet {
            // stderr only — never stdout (that is the wire). Best-effort.
            let _ = writeln!(io::stderr(), "localpass-native-host: {line}");
        }
    };

    match host::run(&mut reader, &mut writer, &bridge, log) {
        Ok(()) => ExitCode::SUCCESS,
        // A framing/IO failure ended the stream. The browser relaunches the host
        // on the next message, so a non-zero exit is the right signal.
        Err(_) => ExitCode::FAILURE,
    }
}

/// Parsed host arguments.
struct Args {
    profile: Option<String>,
    quiet: bool,
}

/// A minimal argument parser. Unknown arguments (including any a browser appends)
/// are ignored so startup never fails on an unexpected argument.
fn parse_args() -> Args {
    let mut profile = None;
    let mut quiet = false;
    let mut it = std::env::args().skip(1);
    while let Some(arg) = it.next() {
        match arg.as_str() {
            "--profile" => profile = it.next(),
            "--quiet" => quiet = true,
            // Ignore anything else (browser-appended origin/extension-id/etc.).
            _ => {}
        }
    }
    Args { profile, quiet }
}
