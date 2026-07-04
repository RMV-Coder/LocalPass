//! Shared helpers for the `localpass` CLI integration tests.
//!
//! Every test drives the built binary via `assert_cmd`, points `--profile` at a
//! fresh `tempfile::TempDir`, and supplies the master password through the
//! `LOCALPASS_PASSWORD` environment variable (the documented script path). The
//! account KDF is Argon2id at recommended cost (~1s per unlock), so tests that
//! unlock are kept deliberately lean and, where practical, a single initialized
//! profile is reused across assertions within one test.

#![allow(dead_code)]

use std::path::Path;

use assert_cmd::Command;
use tempfile::TempDir;

/// The master password used across the integration tests.
pub const TEST_PASSWORD: &str = "correct-horse-battery";

/// A throwaway profile directory plus the password to unlock it.
pub struct TestProfile {
    /// The temp dir backing the profile (kept alive for the test's duration).
    pub dir: TempDir,
}

impl TestProfile {
    /// Create an empty (uninitialized) profile.
    pub fn empty() -> Self {
        Self {
            dir: tempfile::tempdir().expect("create tempdir"),
        }
    }

    /// Create a profile and run `init` on it, returning the initialized profile.
    pub fn initialized() -> Self {
        let p = Self::empty();
        p.cmd().arg("init").assert().success();
        p
    }

    /// The profile path.
    pub fn path(&self) -> &Path {
        self.dir.path()
    }

    /// A `localpass` command pre-wired with `--profile` and the password env
    /// var (but no subcommand yet).
    pub fn cmd(&self) -> Command {
        let mut cmd = Command::cargo_bin("localpass").expect("built binary");
        cmd.env("LOCALPASS_PASSWORD", TEST_PASSWORD)
            .arg("--profile")
            .arg(self.dir.path());
        cmd
    }

    /// A `localpass` command with an explicit (wrong) password, for auth tests.
    pub fn cmd_with_password(&self, password: &str) -> Command {
        let mut cmd = Command::cargo_bin("localpass").expect("built binary");
        cmd.env("LOCALPASS_PASSWORD", password)
            .arg("--profile")
            .arg(self.dir.path());
        cmd
    }
}
