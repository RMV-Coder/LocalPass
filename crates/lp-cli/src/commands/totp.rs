//! `localpass totp <title-or-id>` — print the current TOTP code (PRD §4.1/§4.4).
//!
//! The target must be a `TypeData::Totp` item. LocalPass decodes the stored
//! base32 secret, computes the RFC 6238 code with [`lp_crypto::totp`], and
//! **zeroizes the decoded secret** immediately. The bare CODE goes to STDOUT;
//! the `expires in Ns` hint goes to STDERR, so `localpass totp X | clip`
//! captures only the digits.
//!
//! # Daemon proxy (secret stays off the pipe)
//!
//! When the daemon is unlocked for this profile the command sends a
//! [`Request::Totp`]; the daemon computes the code from the secret it already
//! holds and returns only the finished digits + metadata ([`Response::Totp`]).
//! The base32 secret never crosses the IPC channel — only the 6-8 digit code
//! does. Otherwise the command unlocks directly and computes locally.
//!
//! # `--watch`
//!
//! Reprints the code whenever the period rolls over. It is a poll loop: it sleeps
//! in short increments and reprints when the window's remaining-seconds jumps
//! back up (a new period began). Ctrl-C ends it. We deliberately poll (rather
//! than sleep exactly `seconds_remaining`) so a machine resume / clock jump can
//! never leave a stale code on screen for a whole period.

use std::io::Write;
use std::path::Path;
use std::time::Duration;

use anyhow::{Result, bail};
use lp_vault::payload::TypeData;
use serde_json::json;
use zeroize::Zeroize;

use crate::cli::TotpArgs;
use crate::daemonctl::{self, Route};
use crate::error::CliError;
use crate::resolve;
use crate::unlock::{self, PasswordSource};

use lp_daemon::client::Client;
use lp_daemon::protocol::{Request, Response};

/// The computed TOTP code plus its (non-secret) display metadata. Shared shape
/// for the direct and proxied paths so output is identical.
struct Computed {
    code: String,
    seconds_remaining: u32,
    period: u32,
    digits: u32,
    algo: String,
}

/// The poll interval for `--watch` (short, so a clock jump can't leave a stale
/// code on screen for long).
const WATCH_POLL: Duration = Duration::from_millis(500);

/// Run `localpass totp`.
///
/// # Errors
///
/// Propagates unlock, resolution, wrong-type, and computation failures with the
/// documented exit codes (usage = 1, auth = 2).
pub fn run(
    profile_dir: &Path,
    src: PasswordSource,
    no_daemon: bool,
    args: &TotpArgs,
) -> Result<()> {
    if let Route::Proxy(mut client) = daemonctl::route(profile_dir, no_daemon) {
        return run_proxied(profile_dir, &mut client, args);
    }
    run_direct(profile_dir, src, args)
}

// --- direct path ---------------------------------------------------------

fn run_direct(profile_dir: &Path, src: PasswordSource, args: &TotpArgs) -> Result<()> {
    let (session, _sk) = unlock::unlock(profile_dir, src)?;
    if args.watch {
        return watch(|| compute_direct(&session, &args.vault, &args.target));
    }
    let computed = compute_direct(&session, &args.vault, &args.target)?;
    emit(&computed, args.json);
    Ok(())
}

/// Resolve the item, verify it is a totp item, decode the secret, compute the
/// code, and zeroize the secret. The base32 secret exists only inside this
/// function and is wiped before it returns.
fn compute_direct(session: &lp_vault::Session, vault_ref: &str, target: &str) -> Result<Computed> {
    let vault = resolve::open_vault(session, vault_ref)?;
    let item = resolve::find_item(&vault, target)?;

    let TypeData::Totp {
        secret_b32,
        algo,
        digits,
        period,
        ..
    } = &item.payload.type_data
    else {
        bail!(CliError::usage(format!(
            "item {target:?} is not a totp item (its type is {}); \
             use `item add --type totp --otpauth-uri ...` to create one",
            item.payload.type_data.type_str()
        )));
    };

    // RFC 6238 defaults for legacy/empty stored fields.
    let digits = if *digits == 0 { 6 } else { *digits };
    let period = if *period == 0 { 30 } else { *period };
    let algo = lp_crypto::TotpAlgo::parse(algo)
        .map_err(|_| CliError::usage("item has an unknown TOTP algorithm"))?;
    let digits_u8 =
        u8::try_from(digits).map_err(|_| CliError::usage("item TOTP digits out of range"))?;

    let mut secret = lp_crypto::decode_base32(secret_b32.trim())
        .map_err(|_| CliError::usage("item TOTP secret is not valid base32"))?;
    let result = lp_crypto::totp::code_now(&secret, algo, digits_u8, period);
    // Wipe the decoded secret before doing anything else with the outcome.
    secret.zeroize();
    let (code, seconds_remaining) =
        result.map_err(|_| CliError::usage("could not compute TOTP code (bad parameters)"))?;

    // Computing a TOTP code discloses a value derived from the secret: audit it as
    // a secret read of the totp field (PRD §4.9). Best-effort. (The proxied path is
    // audited in the daemon, which holds the session — no double-logging.)
    vault.record_secret_read(&item.item_id, Some("totp")).ok();

    Ok(Computed {
        code,
        seconds_remaining,
        period,
        digits,
        algo: algo.as_str().to_string(),
    })
}

// --- proxied path (daemon computes; secret never crosses the pipe) -------

fn run_proxied(profile_dir: &Path, client: &mut Client, args: &TotpArgs) -> Result<()> {
    let profile = profile_dir.display().to_string();
    if args.watch {
        return watch(|| compute_proxied(&profile, client, &args.vault, &args.target));
    }
    let computed = compute_proxied(&profile, client, &args.vault, &args.target)?;
    emit(&computed, args.json);
    Ok(())
}

fn compute_proxied(
    profile: &str,
    client: &mut Client,
    vault_ref: &str,
    target: &str,
) -> Result<Computed> {
    let resp = daemonctl::call(
        client,
        &Request::Totp {
            profile: profile.to_string(),
            vault: vault_ref.to_string(),
            target: target.to_string(),
        },
    )?;
    daemonctl::check_error(&resp)?;
    let Response::Totp {
        code,
        seconds_remaining,
        period,
        digits,
        algo,
    } = resp
    else {
        bail!(CliError::internal(anyhow::anyhow!(
            "unexpected daemon response: {}",
            resp.kind()
        )));
    };
    Ok(Computed {
        code,
        seconds_remaining,
        period,
        digits,
        algo,
    })
}

// --- output --------------------------------------------------------------

/// Print one computed code: the CODE to stdout, the `expires in Ns` hint to
/// stderr (so a pipe gets only the code), or the `--json` object to stdout.
fn emit(c: &Computed, json_out: bool) {
    if json_out {
        let obj = json!({
            "code": c.code,
            "seconds_remaining": c.seconds_remaining,
            "period": c.period,
            "digits": c.digits,
            "algo": c.algo,
        });
        println!("{obj}");
    } else {
        println!("{}", c.code);
        eprintln!("expires in {}s", c.seconds_remaining);
    }
}

/// `--watch`: reprint the code each time a new period begins, until interrupted.
///
/// Prints the current code, then polls on [`WATCH_POLL`]. When the recomputed
/// `seconds_remaining` is greater than the last value we saw, the window rolled
/// over, so a fresh code is printed. Ctrl-C ends the loop (the process is
/// terminated by the signal; there is no other clean exit — documented).
fn watch<F>(mut compute: F) -> Result<()>
where
    F: FnMut() -> Result<Computed>,
{
    let mut last_code = String::new();
    let mut last_remaining = u32::MAX;
    loop {
        let c = compute()?;
        // Print on the first iteration and whenever the code changes (a new
        // period began — detectable as remaining jumping back up, or the code
        // simply differing).
        if c.code != last_code || c.seconds_remaining > last_remaining {
            // stdout: the code; stderr: the countdown hint (piped consumers get
            // a clean stream of codes, one per line).
            println!("{}", c.code);
            let _ = std::io::stdout().flush();
            eprintln!("expires in {}s (Ctrl-C to stop)", c.seconds_remaining);
            last_code = c.code.clone();
        }
        last_remaining = c.seconds_remaining;
        std::thread::sleep(WATCH_POLL);
    }
}
