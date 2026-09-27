//! Keeping `run_with_secrets` children from driving LocalPass itself.
//!
//! `run_with_secrets` runs an agent-chosen program as the same user. While the
//! daemon is unlocked, a child that is itself a LocalPass client is an
//! ordinary same-user daemon caller: `localpass item get <x> --field password`
//! would print a value the tool never injected (so the redactor never looks
//! for it) straight into the transcript, and `localpass agent-fill arm` would
//! open the consent window the spec reserves for the user.
//!
//! Two guards, both cheap and both documented as **defence in depth, not a
//! boundary** (docs/specs/mcp-server.md §7):
//!
//! 1. [`is_localpass_program`] — the server refuses to spawn a LocalPass
//!    binary directly.
//! 2. [`MCP_CHILD_ENV`] — every child (and, by inheritance, every grandchild)
//!    runs with this marker set, and the CLI refuses all but the harmless
//!    commands while it is present ([`allowed_in_mcp_child`]). That catches the
//!    indirect case: a script or package hook that calls `localpass`.
//!
//! A determined child can still unset the variable or speak the daemon's IPC
//! protocol itself — `run_with_secrets` is arbitrary same-user code execution.
//! The spec says so plainly rather than overclaiming.

use std::path::Path;

use crate::cli::Command;

/// Set to `1` in every `run_with_secrets` child's environment.
pub const MCP_CHILD_ENV: &str = "LOCALPASS_MCP_CHILD";

/// LocalPass executables a `run_with_secrets` child must not be.
const LOCALPASS_BINARIES: &[&str] = &["localpass", "localpass-daemon", "localpass-native-host"];

/// Whether `program` (as the agent wrote it: a bare name or a path) names a
/// LocalPass executable. Compares the base name without its extension,
/// case-insensitively, so `localpass`, `LocalPass.exe` and
/// `C:\bin\localpass.exe` all match; also matches the running executable by
/// canonical path, which catches a renamed copy invoked by path.
#[must_use]
pub fn is_localpass_program(program: &str) -> bool {
    if LOCALPASS_BINARIES.contains(&program_stem(program).as_str()) {
        return true;
    }
    same_file(Path::new(program), std::env::current_exe().ok().as_deref())
}

/// The lower-cased base name of `program` without its extension. Splits on
/// BOTH `/` and `\` on every platform: `std::path` treats `\` as a separator
/// only on Windows, but an agent may write either style anywhere.
fn program_stem(program: &str) -> String {
    let name = program.rsplit(['/', '\\']).next().unwrap_or(program);
    let stem = match name.rsplit_once('.') {
        Some((stem, _ext)) if !stem.is_empty() => stem,
        _ => name,
    };
    stem.to_ascii_lowercase()
}

fn same_file(candidate: &Path, current: Option<&Path>) -> bool {
    let (Some(current), Ok(candidate)) = (current, candidate.canonicalize()) else {
        return false;
    };
    current.canonicalize().is_ok_and(|c| c == candidate)
}

/// Whether the marker is set to a non-empty value.
#[must_use]
pub fn marker_set(value: Option<&str>) -> bool {
    value.is_some_and(|v| !v.is_empty())
}

/// The commands a LocalPass CLI may run inside a `run_with_secrets` child.
/// Only those that read no vault content and grant no consent: `status`
/// (lock state and counts) and `generate` (fresh random output, never stored).
#[must_use]
pub fn allowed_in_mcp_child(command: &Command) -> bool {
    matches!(command, Command::Status { .. } | Command::Generate(_))
}

/// The error a refused command prints.
#[must_use]
pub fn refusal_message() -> String {
    format!(
        "refusing to run inside an MCP `run_with_secrets` child ({MCP_CHILD_ENV} is set): \
         a child process must not read secrets or grant consent through LocalPass. \
         Only `status` and `generate` are available here."
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    fn parse(args: &[&str]) -> Command {
        crate::cli::Cli::parse_from(std::iter::once("localpass").chain(args.iter().copied()))
            .command
    }

    #[test]
    fn localpass_binaries_are_recognised_by_name_and_path() {
        for p in [
            "localpass",
            "localpass.exe",
            "LocalPass.EXE",
            "localpass-daemon",
            "localpass-native-host.exe",
            "/usr/local/bin/localpass",
            r"C:\Users\me\.cargo\bin\localpass.exe",
        ] {
            assert!(is_localpass_program(p), "{p} must be refused");
        }
    }

    #[test]
    fn stems_are_taken_across_both_separator_styles_on_every_platform() {
        assert_eq!(
            program_stem(r"C:\Users\me\.cargo\bin\localpass.exe"),
            "localpass"
        );
        assert_eq!(program_stem("/usr/local/bin/localpass"), "localpass");
        assert_eq!(
            program_stem(r"bin/sub\LocalPass-Daemon.EXE"),
            "localpass-daemon"
        );
        assert_eq!(program_stem("localpass"), "localpass");
        assert_eq!(program_stem(".hidden"), ".hidden");
    }

    #[test]
    fn ordinary_programs_are_allowed() {
        for p in [
            "npm",
            "node",
            "psql",
            "cargo",
            "sh",
            "cmd",
            "localpassword-checker",
            "my-localpass-wrapper",
        ] {
            assert!(!is_localpass_program(p), "{p} must be allowed");
        }
    }

    #[test]
    fn the_running_executable_is_recognised_even_when_renamed() {
        let exe = std::env::current_exe().expect("current exe");
        assert!(is_localpass_program(exe.to_str().expect("utf-8 path")));
    }

    #[test]
    fn marker_needs_a_non_empty_value() {
        assert!(marker_set(Some("1")));
        assert!(marker_set(Some("yes")));
        assert!(!marker_set(Some("")));
        assert!(!marker_set(None));
    }

    #[test]
    fn only_status_and_generate_are_allowed_in_a_child() {
        assert!(allowed_in_mcp_child(&parse(&["status"])));
        assert!(allowed_in_mcp_child(&parse(&["generate"])));
        for args in [
            &["item", "get", "Prod DB", "--field", "password"][..],
            &["item", "list"],
            &["agent-fill", "arm", "--item", "Prod DB"],
            &["item", "get", "Prod DB", "--reveal"],
            &["env", "export", "myapp-dev"],
            &["run", "--env-set", "myapp-dev", "--", "env"],
            &["export", "csv", "out.csv"],
            &["totp", "ACME 2FA"],
            &["unlock"],
            &["mcp"],
        ] {
            assert!(
                !allowed_in_mcp_child(&parse(args)),
                "{args:?} must be refused"
            );
        }
    }

    #[test]
    fn refusal_names_the_marker() {
        assert!(refusal_message().contains(MCP_CHILD_ENV));
    }
}
