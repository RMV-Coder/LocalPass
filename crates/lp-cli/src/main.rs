//! `localpass` — the LocalPass command-line interface.
//!
//! A fully local, offline password & secrets manager CLI. Each vault-touching
//! command tries the background daemon first (a fast Ping/Status probe); if the
//! daemon is running and unlocked for this profile, the command **proxies**
//! through it so no master-password re-prompt is needed. Otherwise — no daemon,
//! a locked daemon, or `--no-daemon` — the command falls back to unlocking
//! **directly** against the `lp-vault` storage core, exactly as it did before
//! the daemon existed. See [`daemonctl`] for the full routing matrix.
//!
//! # Module map
//!
//! - [`cli`] — the `clap` command tree (the documented interface).
//! - [`commands`] — one module per command; each returns `anyhow::Result<()>`.
//! - [`daemonctl`] — the daemon-first / direct-fallback routing and daemon
//!   lifecycle (start/stop/unlock/lock proxying).
//! - [`unlock`] — the shared Secret-Key-load + password + unlock flow.
//! - [`profile`] — profile-dir resolution and on-device Secret Key storage.
//! - [`content`] / [`output`] / [`resolve`] — payload building, masked
//!   rendering, and name/id resolution.
//! - [`generate`] / [`wordlist`] — CSPRNG password / EFF-passphrase generation.
//! - [`error`] — the [`error::CliError`] taxonomy and the exit-code contract.
//!
//! # Exit codes (PRD §4.4)
//!
//! `0` ok · `1` user error · `2` authentication failure · `3` internal error.
//! On any error, one clean line is printed to stderr — never a `Debug` dump and
//! never a secret value.

#![forbid(unsafe_code)]

mod cli;
mod commands;
mod content;
mod daemonctl;
mod dotenv;
mod envmap;
mod error;
mod generate;
mod otpauth;
mod output;
mod profile;
mod reference;
mod resolve;
mod timestamp;
mod unlock;
mod wordlist;

use std::process::ExitCode;

use clap::Parser;

use cli::{Cli, Command};
use error::CliError;
use unlock::PasswordSource;

fn main() -> ExitCode {
    let cli = Cli::parse();
    match run(cli) {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            // Downcast to CliError for the exit code; anything else is internal.
            let code = err
                .downcast_ref::<CliError>()
                .map_or(3, CliError::exit_code);
            // One clean line to stderr. `{:#}` renders anyhow's context chain
            // compactly (": " separated) without a Debug dump or backtrace.
            eprintln!("error: {err:#}");
            ExitCode::from(u8::try_from(code).unwrap_or(3))
        }
    }
}

/// Resolve the profile, build the password source, and dispatch to a command.
fn run(cli: Cli) -> anyhow::Result<()> {
    let profile_dir = profile::resolve(cli.profile.as_deref())?;
    let src = PasswordSource {
        no_input: cli.no_input,
        stdin: cli.password_stdin,
    };
    let no_daemon = cli.no_daemon;

    match &cli.command {
        Command::Init(args) => commands::init::run(&profile_dir, src, args),
        Command::Status { json } => commands::status::run(&profile_dir, src, no_daemon, *json),
        Command::Vault { command } => commands::vault::run(&profile_dir, src, no_daemon, command),
        Command::Item { command } => commands::item::run(&profile_dir, src, no_daemon, command),
        Command::Attach { command } => commands::attach::run(&profile_dir, src, command),
        Command::Search {
            query,
            item_type,
            vault,
            json,
        } => commands::search::run(
            &profile_dir,
            src,
            no_daemon,
            query,
            *item_type,
            vault,
            *json,
        ),
        Command::Generate(args) => commands::generate::run(args),
        Command::Health { vault, json } => {
            commands::health::run(&profile_dir, src, no_daemon, vault, *json)
        }
        Command::Password { command } => commands::password::run(&profile_dir, src, command),
        Command::Run(args) => commands::run::run(&profile_dir, src, no_daemon, args),
        Command::Env { command } => commands::env::run(&profile_dir, src, no_daemon, command),
        Command::Import(args) => commands::import::run(&profile_dir, src, no_daemon, args),
        Command::Export(args) => commands::export::run(&profile_dir, src, no_daemon, args),
        Command::Unlock => commands::daemon::run_unlock(&profile_dir, src),
        Command::Lock => commands::daemon::run_lock(&profile_dir),
        Command::Daemon { command } => commands::daemon::run(&profile_dir, command),
        Command::Backup { command } => commands::backup::run(&profile_dir, src, no_daemon, command),
        Command::Kit(args) => commands::kit::run(&profile_dir, src, args),
        Command::Sync { command } => commands::sync::run(&profile_dir, src, command),
        Command::Device { command } => commands::device::run(&profile_dir, src, command),
        Command::Ssh { command } => commands::ssh::run(&profile_dir, src, no_daemon, command),
        Command::Totp(args) => commands::totp::run(&profile_dir, src, no_daemon, args),
        Command::Audit(args) => commands::audit::run(&profile_dir, src, args),
        Command::Browser { command } => commands::browser::run(command),
    }
}
