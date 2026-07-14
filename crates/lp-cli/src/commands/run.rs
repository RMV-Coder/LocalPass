//! `localpass run [flags] -- <command> [args...]` — the flagship secret
//! injection command (PRD §4.8, §7.2).
//!
//! Unlocks, composes the child environment from layered sources (env-sets <
//! env-files < `-e`), resolves every reference **once**, then spawns the child
//! with that environment. Plaintext secrets exist only in this process's memory
//! and the child's environment — never on disk, never in the child's argv.
//!
//! # Spawn behaviour per OS
//!
//! - **Unix:** `exec()` replaces this process with the child (via
//!   `std::os::unix::process::CommandExt::exec`, not an intra-doc link because
//!   that path does not exist on the Windows doc build); LocalPass vanishes from
//!   the process tree and the child's exit status is what the shell sees.
//! - **Windows:** there is no `exec`. LocalPass spawns the child with inherited
//!   stdio, waits for it, and exits with the child's exit code.

use std::path::Path;
use std::process::Command;

use anyhow::Result;
use lp_vault::Session;
use lp_vault::payload::TypeData;

use crate::cli::RunArgs;
use crate::daemonctl::{self, Route};
use crate::envmap::{OrderedEnv, base_env};
use crate::error::CliError;
use crate::reference;
use crate::resolve;
use crate::unlock::{self, PasswordSource};

use lp_daemon::client::Client;
use lp_daemon::protocol::{Request, Response};

/// Run `localpass run`.
///
/// # Errors
///
/// - [`CliError::Auth`] (exit 2) on a wrong password / Secret Key.
/// - [`CliError::Usage`] (exit 1) on an unresolvable reference, an unknown
///   env-set / vault, or a spawn failure. The message names the failing KEY and
///   reference, never a resolved value.
pub fn run(profile_dir: &Path, src: PasswordSource, no_daemon: bool, args: &RunArgs) -> Result<()> {
    // `command` is guaranteed non-empty by clap (`required = true`).
    let (program, program_args) = args
        .command
        .split_first()
        .expect("clap guarantees a non-empty command");

    // Compose the resolved variables (layering + precedence) via the daemon if
    // it's unlocked, else via a direct unlock. Done before we touch the base
    // environment so a resolution failure aborts cleanly.
    let resolved = match daemonctl::route(profile_dir, no_daemon) {
        Route::Proxy(mut client) => compose_resolved_proxied(profile_dir, &mut client, args)?,
        Route::Direct => {
            let (session, _sk) = unlock::unlock(profile_dir, src)?;
            compose_resolved(&session, args)?
        }
    };

    // Base = full parent env (default) or the minimal passthrough (--no-inherit).
    let mut child_env = base_env(!args.no_inherit);
    for (k, v) in resolved.iter() {
        child_env.set(k, v); // resolved vars override inherited ones
    }

    spawn(program, program_args, &child_env)
}

/// Compose the resolved variable set by proxying through the daemon: env-sets
/// via `GetRawPayload`, references via `ResolveField`. Same precedence as the
/// direct path (env-set < env-file < `-e`).
fn compose_resolved_proxied(
    profile_dir: &Path,
    client: &mut Client,
    args: &RunArgs,
) -> Result<OrderedEnv> {
    let profile = profile_dir.display().to_string();
    let mut env = OrderedEnv::new();

    // 1) --env-set: pull every entry of each env-set item.
    for set_ref in &args.env_sets {
        for (k, v) in load_env_set_proxied(&profile, client, &args.vault, set_ref)? {
            env.set(k, v);
        }
    }

    // 2) --env-file: dotenv values may be references (resolved) or literals.
    for path in &args.env_files {
        for entry in crate::dotenv::parse_file(path)? {
            let value = if reference::is_reference(&entry.value) {
                resolve_reference_proxied(&profile, client, &entry.key, &entry.value)?
            } else {
                entry.value
            };
            env.set(entry.key, value);
        }
    }

    // 3) -e KEY=<reference>: highest precedence.
    for mapping in &args.env {
        let (key, reference) = split_mapping(mapping)?;
        let value = resolve_reference_proxied(&profile, client, key, reference)?;
        env.set(key.to_string(), value);
    }

    Ok(env)
}

/// Load an env-set's entries through the daemon (`GetRawPayload`).
fn load_env_set_proxied(
    profile: &str,
    client: &mut Client,
    vault_ref: &str,
    set_ref: &str,
) -> Result<Vec<(String, String)>> {
    let resp = daemonctl::call(
        client,
        &Request::GetRawPayload {
            profile: profile.to_string(),
            vault: vault_ref.to_string(),
            target: set_ref.to_string(),
        },
    )?;
    daemonctl::check_error(&resp)?;
    let Response::RawPayload { payload, .. } = resp else {
        return Err(CliError::internal(anyhow::anyhow!(
            "unexpected daemon response: {}",
            resp.kind()
        ))
        .into());
    };
    let payload: lp_vault::ItemPayload = serde_json::from_value(payload)
        .map_err(|e| CliError::internal(anyhow::anyhow!("parsing env-set: {e}")))?;
    match payload.type_data {
        TypeData::EnvSet { entries } => Ok(entries.into_iter().map(|e| (e.key, e.value)).collect()),
        other => Err(CliError::usage(format!(
            "--env-set {set_ref:?} is a {} item, not an env-set",
            other.type_str()
        ))
        .into()),
    }
}

/// Resolve a `localpass://`/`op://` reference through the daemon
/// (`ResolveField`), naming the failing KEY on error without leaking a value.
/// A reference always carries its own vault (unlike a bare `--env-set` name),
/// so no default-vault argument is needed here.
fn resolve_reference_proxied(
    profile: &str,
    client: &mut Client,
    key: &str,
    reference: &str,
) -> Result<String> {
    let parsed = reference::parse(reference)?;
    let resp = daemonctl::call(
        client,
        &Request::ResolveField {
            profile: profile.to_string(),
            vault: parsed.vault.clone(),
            item: parsed.item.clone(),
            field: parsed.field.clone(),
        },
    )?;
    match &resp {
        Response::Field { value } => Ok(value.clone()),
        Response::Error { message, .. } => {
            Err(CliError::usage(format!("could not resolve {key}={reference}: {message}")).into())
        }
        _ => {
            daemonctl::check_error(&resp)?;
            Err(CliError::internal(anyhow::anyhow!(
                "unexpected daemon response: {}",
                resp.kind()
            ))
            .into())
        }
    }
}

/// Compose the fully-resolved variable set from all sources, applying the
/// precedence env-set < env-file < `-e`.
fn compose_resolved(session: &Session, args: &RunArgs) -> Result<OrderedEnv> {
    let mut env = OrderedEnv::new();

    // 1) --env-set: pull every entry of each env-set item. Later sets override.
    for set_ref in &args.env_sets {
        let entries = load_env_set(session, &args.vault, set_ref)?;
        for (k, v) in entries {
            env.set(k, v);
        }
    }

    // 2) --env-file: dotenv values may be references (resolved) or literals.
    for path in &args.env_files {
        for entry in crate::dotenv::parse_file(path)? {
            let value = if reference::is_reference(&entry.value) {
                resolve_named(session, &entry.key, &entry.value)?
            } else {
                entry.value
            };
            env.set(entry.key, value);
        }
    }

    // 3) -e KEY=<reference>: highest precedence. The RHS is a reference.
    for mapping in &args.env {
        let (key, reference) = split_mapping(mapping)?;
        let value = resolve_named(session, key, reference)?;
        env.set(key.to_string(), value);
    }

    Ok(env)
}

/// Load all entries of an env-set item as `(key, value)` pairs.
fn load_env_set(
    session: &Session,
    vault_ref: &str,
    set_ref: &str,
) -> Result<Vec<(String, String)>> {
    let vault = resolve::open_vault(session, vault_ref)?;
    let item = resolve::find_item(&vault, set_ref)?;
    match &item.payload.type_data {
        TypeData::EnvSet { entries } => Ok(entries
            .iter()
            .map(|e| (e.key.clone(), e.value.clone()))
            .collect()),
        other => Err(CliError::usage(format!(
            "--env-set {set_ref:?} is a {} item, not an env-set",
            other.type_str()
        ))
        .into()),
    }
}

/// Split a `KEY=<reference>` mapping without ever putting the reference in a
/// generic error (the reference is not itself secret, but keeping the shape
/// consistent avoids surprises).
fn split_mapping(mapping: &str) -> Result<(&str, &str)> {
    match mapping.split_once('=') {
        Some((k, v)) if !k.is_empty() && !v.is_empty() => Ok((k, v)),
        _ => Err(CliError::usage(format!(
            "malformed -e mapping (expected KEY=reference with non-empty parts): {mapping:?}"
        ))
        .into()),
    }
}

/// Resolve a reference, attaching the KEY to any error so the user knows which
/// variable failed — **without** leaking the resolved value (there is none on
/// the failure path; on success the value is returned, never logged).
fn resolve_named(session: &Session, key: &str, reference: &str) -> Result<String> {
    reference::resolve_str(session, reference).map_err(|e| {
        // Re-wrap as a Usage error naming the KEY and the (non-secret)
        // reference. The underlying message already avoids any secret value.
        CliError::usage(format!(
            "could not resolve {key}={reference}: {}",
            root_message(&e)
        ))
        .into()
    })
}

/// Extract the leaf human message from an error chain (avoids a `Debug` dump).
fn root_message(e: &anyhow::Error) -> String {
    format!("{e:#}")
}

/// Spawn the child with the composed environment.
///
/// Unix: exec-replace (never returns on success). Windows: spawn + wait +
/// propagate the exit code.
fn spawn(program: &str, args: &[String], env: &OrderedEnv) -> Result<()> {
    // On Windows, resolve the program through PATH + PATHEXT ourselves so that
    // batch-file launchers like `npm` (which is `npm.cmd`), `npx`, `yarn`, and
    // `pnpm` are found — `Command::new("npm")` only tries `npm` and `npm.exe`,
    // never the `.cmd`, so it fails with "program not found" even though the
    // shell finds it. Once the resolved name carries the `.cmd`/`.bat`
    // extension, std routes it through `cmd.exe` with CVE-2024-24576-safe
    // argument escaping. On Unix the loader/`exec` handles PATH lookup itself.
    #[cfg(windows)]
    let mut cmd = Command::new(resolve_program(program, env_path(env)));
    #[cfg(not(windows))]
    let mut cmd = Command::new(program);
    cmd.args(args);
    // Start from an empty environment and set exactly our composed map, so
    // --no-inherit genuinely means "only these" and inheritance is explicit.
    cmd.env_clear();
    for (k, v) in env.iter() {
        cmd.env(k, v);
    }

    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        // exec() only returns on failure; on success this process is replaced.
        let err = cmd.exec();
        Err(CliError::usage(format!("failed to exec {program:?}: {err}")).into())
    }

    #[cfg(not(unix))]
    {
        spawn_and_wait(cmd, program)
    }
}

/// Windows (and any non-Unix) path: spawn, inherit stdio, wait, and exit with
/// the child's code. Split out so it is unit-testable without `#[cfg]` noise.
#[cfg(not(unix))]
fn spawn_and_wait(mut cmd: Command, program: &str) -> Result<()> {
    let status = cmd
        .status()
        .map_err(|e| CliError::usage(format!("failed to spawn {program:?}: {e}")))?;
    // Propagate the child's exit code. `process::exit` skips destructors, but at
    // this point the only sensitive data is the child's own environment (which
    // the OS owns now); this process holds no unzeroized key material of its own
    // beyond what Session drops, and we are terminating anyway.
    let code = status.code().unwrap_or(1);
    std::process::exit(code);
}

/// The child's effective `PATH` (case-insensitively), for program resolution.
#[cfg(windows)]
fn env_path(env: &OrderedEnv) -> Option<String> {
    env.iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("PATH"))
        .map(|(_, v)| v.to_string())
}

/// Resolve a program name to a concrete file on Windows using `PATH` + `PATHEXT`,
/// exactly like the shell — so `npm` finds `npm.cmd`, `yarn` finds `yarn.cmd`,
/// etc. `Command::new` alone only tries the bare name and `.exe`, so a batch-file
/// launcher is otherwise "program not found".
///
/// A name that already has an extension or a path separator is returned as-is
/// (the caller meant that exact thing). A name that cannot be resolved is also
/// returned as-is, so `Command` still produces the same clear "not found" error.
#[cfg(windows)]
fn resolve_program(program: &str, path_var: Option<String>) -> std::ffi::OsString {
    use std::path::Path;

    if Path::new(program).extension().is_some() || program.contains('\\') || program.contains('/') {
        return program.into();
    }

    let path = path_var
        .or_else(|| std::env::var("PATH").ok())
        .unwrap_or_default();
    let pathext = std::env::var("PATHEXT").unwrap_or_else(|_| ".COM;.EXE;.BAT;.CMD".to_string());

    for dir in std::env::split_paths(&path) {
        for ext in pathext.split(';').filter(|e| !e.is_empty()) {
            let candidate = dir.join(format!("{program}{ext}"));
            if candidate.is_file() {
                return candidate.into_os_string();
            }
        }
    }
    program.into()
}

#[cfg(all(test, windows))]
mod windows_resolve_tests {
    use super::resolve_program;
    use std::fs;

    #[test]
    fn resolves_a_cmd_launcher_via_pathext() {
        let dir = tempfile::tempdir().unwrap();
        // A batch-file launcher like `npm.cmd` — no bare `foo` / `foo.exe`.
        fs::write(dir.path().join("foo.cmd"), "@echo off\n").unwrap();
        let path = dir.path().display().to_string();

        let resolved = resolve_program("foo", Some(path));
        // Compare case-insensitively: PATHEXT's `.CMD` and the on-disk `.cmd`
        // are the same file on Windows, and std matches the extension for batch
        // routing case-insensitively too.
        let got = resolved.to_string_lossy().to_ascii_lowercase();
        let want = dir
            .path()
            .join("foo.cmd")
            .to_string_lossy()
            .to_ascii_lowercase();
        assert_eq!(
            got, want,
            "bare `foo` should resolve to foo.cmd via PATHEXT"
        );
    }

    #[test]
    fn passes_through_names_with_extension_or_path() {
        // Already has an extension → unchanged.
        assert_eq!(resolve_program("node.exe", None), "node.exe");
        // Has a path separator → unchanged (an explicit target).
        assert_eq!(resolve_program(r"C:\tools\thing", None), r"C:\tools\thing");
    }

    #[test]
    fn unresolvable_name_is_returned_unchanged() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().display().to_string();
        // Nothing named `nope*` exists → the bare name is returned so Command
        // yields the same clear "not found" error.
        assert_eq!(resolve_program("nope", Some(path)), "nope");
    }
}
