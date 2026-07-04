//! `localpass` — the LocalPass command-line interface.
//!
//! A fully local, offline password & secrets manager CLI. This binary talks
//! **directly** to the `lp-vault` storage core: there is no daemon yet (the
//! per-user agent that caches unlocked keys is a later wave), so every command
//! that touches a vault performs its own unlock.
//!
//! # Module map
//!
//! - [`cli`] — the `clap` command tree (the documented interface).
//! - [`commands`] — one module per command; each returns `anyhow::Result<()>`.
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
mod error;
mod generate;
mod output;
mod profile;
mod resolve;
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

    match &cli.command {
        Command::Init => commands::init::run(&profile_dir, src),
        Command::Status { json } => commands::status::run(&profile_dir, src, *json),
        Command::Vault { command } => commands::vault::run(&profile_dir, src, command),
        Command::Item { command } => commands::item::run(&profile_dir, src, command),
        Command::Search {
            query,
            item_type,
            vault,
            json,
        } => commands::search::run(&profile_dir, src, query, *item_type, vault, *json),
        Command::Generate(args) => commands::generate::run(args),
        Command::Password { command } => commands::password::run(&profile_dir, src, command),
    }
}
