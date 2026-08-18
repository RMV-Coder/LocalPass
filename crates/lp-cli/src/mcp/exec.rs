//! Spawning `run_with_secrets`' child process: capture, not inherit.
//!
//! `localpass run` hands the child LocalPass's own stdio (and on Unix `exec()`s
//! into it). The MCP server cannot: its stdout is the protocol channel, so a
//! child writing to it would corrupt the JSON-RPC stream. Here the child gets
//! **piped** stdout/stderr, a closed stdin, and a wall-clock timeout; the
//! captured bytes go back through [`super::redact`] before anyone sees them.
//!
//! Environment composition is `localpass run`'s: `env_clear()` plus the exact
//! composed map, so what the caller sees is what the child got. Program
//! resolution on Windows reuses `run`'s `PATH` × `PATHEXT` walk, so `npm` finds
//! `npm.cmd` here for the same reason it does there (see `LESSONS.md`).

use std::io::Read;
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use anyhow::Result;

use crate::envmap::OrderedEnv;
use crate::error::CliError;

/// How often the wait loop checks whether the child has exited.
const POLL: Duration = Duration::from_millis(25);

/// What a finished (or killed) child produced.
pub struct Captured {
    /// The child's exit code, or `None` if it was killed / died by signal.
    pub exit_code: Option<i32>,
    /// Whether the child was killed because it outlived its timeout.
    pub timed_out: bool,
    /// Captured stdout, lossily decoded as UTF-8. **Not yet redacted.**
    pub stdout: String,
    /// Captured stderr, lossily decoded as UTF-8. **Not yet redacted.**
    pub stderr: String,
}

/// Spawn `program` with `args` and `env`, capture both streams, and wait up to
/// `timeout`.
///
/// stdin is `/dev/null`: an MCP tool call is non-interactive, and a child that
/// blocked on a read would just burn the timeout.
///
/// # Errors
///
/// [`CliError::Usage`] if the program cannot be spawned (not found, `cwd`
/// missing, …) — the message names the program, never an environment value.
pub fn run_capture(
    program: &str,
    args: &[String],
    env: &OrderedEnv,
    cwd: Option<&Path>,
    timeout: Duration,
) -> Result<Captured> {
    #[cfg(windows)]
    let mut cmd = Command::new(crate::commands::run::resolve_program(
        program,
        crate::commands::run::env_path(env),
    ));
    #[cfg(not(windows))]
    let mut cmd = Command::new(program);

    cmd.args(args);
    cmd.env_clear();
    for (k, v) in env.iter() {
        cmd.env(k, v);
    }
    if let Some(dir) = cwd {
        cmd.current_dir(dir);
    }
    cmd.stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    let mut child = cmd
        .spawn()
        .map_err(|e| CliError::usage(format!("failed to spawn {program:?}: {e}")))?;

    // Drain both pipes on their own threads: a child that fills one pipe's
    // buffer would otherwise deadlock against our wait loop.
    let out_handle = child.stdout.take().map(drain);
    let err_handle = child.stderr.take().map(drain);

    let started = Instant::now();
    let mut timed_out = false;
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break Some(status),
            Ok(None) => {}
            Err(e) => {
                return Err(CliError::internal(anyhow::anyhow!(
                    "waiting for {program:?} failed: {e}"
                ))
                .into());
            }
        }
        if started.elapsed() >= timeout {
            timed_out = true;
            // Best-effort kill, then reap so the reader threads see EOF.
            let _ = child.kill();
            break child.wait().ok();
        }
        std::thread::sleep(POLL);
    };

    let stdout = out_handle.map(join).unwrap_or_default();
    let stderr = err_handle.map(join).unwrap_or_default();

    Ok(Captured {
        exit_code: status.and_then(|s| s.code()),
        timed_out,
        stdout,
        stderr,
    })
}

/// Read a pipe to EOF on a worker thread.
fn drain<R: Read + Send + 'static>(mut r: R) -> std::thread::JoinHandle<Vec<u8>> {
    std::thread::spawn(move || {
        let mut buf = Vec::new();
        let _ = r.read_to_end(&mut buf);
        buf
    })
}

/// Join a drain thread and decode its bytes lossily. A panicked reader yields
/// empty output rather than taking the server down.
fn join(h: std::thread::JoinHandle<Vec<u8>>) -> String {
    h.join()
        .map(|b| String::from_utf8_lossy(&b).into_owned())
        .unwrap_or_default()
}

/// Split a command **string** into a program and its arguments, honouring
/// single and double quotes.
///
/// Backslash is **not** an escape character: on Windows it is a path separator,
/// and treating `C:\tools\x.exe` as escapes would be actively wrong. Quote a
/// literal quote by switching quote style (`"it's"`, `'say "hi"'`).
///
/// A caller that needs full control should pass `command` as a JSON **array**
/// instead — the MCP tool accepts both and skips this function entirely for the
/// array form.
///
/// # Errors
///
/// [`CliError::Usage`] if a quote is left open or the string is empty.
pub fn tokenize(command: &str) -> Result<Vec<String>> {
    let mut out: Vec<String> = Vec::new();
    let mut cur = String::new();
    let mut started = false;
    let mut quote: Option<char> = None;

    for ch in command.chars() {
        match quote {
            Some(q) if ch == q => quote = None,
            Some(_) => cur.push(ch),
            None if ch == '\'' || ch == '"' => {
                quote = Some(ch);
                started = true;
            }
            None if ch.is_whitespace() => {
                if started {
                    out.push(std::mem::take(&mut cur));
                    started = false;
                }
            }
            None => {
                cur.push(ch);
                started = true;
            }
        }
    }
    if quote.is_some() {
        return Err(CliError::usage("command has an unterminated quote").into());
    }
    if started {
        out.push(cur);
    }
    if out.is_empty() {
        return Err(CliError::usage("command is empty").into());
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn splits_on_whitespace() {
        assert_eq!(
            tokenize("echo hello world").unwrap(),
            ["echo", "hello", "world"]
        );
    }

    #[test]
    fn keeps_quoted_groups_together() {
        assert_eq!(
            tokenize("sh -c 'echo $VAR'").unwrap(),
            ["sh", "-c", "echo $VAR"]
        );
        assert_eq!(
            tokenize(r#"say "hello there""#).unwrap(),
            ["say", "hello there"]
        );
    }

    #[test]
    fn backslashes_are_literal_not_escapes() {
        assert_eq!(
            tokenize(r"C:\tools\thing.exe --flag").unwrap(),
            [r"C:\tools\thing.exe", "--flag"]
        );
    }

    #[test]
    fn an_empty_quoted_argument_is_preserved() {
        assert_eq!(tokenize("prog '' x").unwrap(), ["prog", "", "x"]);
    }

    #[test]
    fn unterminated_quote_and_empty_command_are_usage_errors() {
        assert!(tokenize("sh -c 'oops").is_err());
        assert!(tokenize("   ").is_err());
    }
}
