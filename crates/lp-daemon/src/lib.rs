// `unsafe` is denied crate-wide and forbidden per-module in every safe module
// (see each module's `#![forbid(unsafe_code)]`). Only `transport::windows` opts
// back in — it must call Win32 pipe/security APIs — via a local
// `#![allow(unsafe_code)]`, which `deny` (unlike `forbid`) permits. Every unsafe
// block there documents its safety contract inline.
#![deny(unsafe_code)]
#![warn(missing_docs)]
//! # LocalPass daemon (`lp-daemon`)
//!
//! A per-user background process that holds one **unlocked** vault session in
//! memory so repeated `localpass` CLI calls don't re-prompt for the master
//! password (PRD §4.4 "Agent/daemon"). It speaks a small, versioned,
//! length-prefixed JSON protocol over a **same-user-only** local IPC channel and
//! auto-locks on idle. This crate is both a **library** (consumed by `lp-cli`)
//! and the `localpass-daemon` **binary**.
//!
//! ## Transport & access control (the security core — PRD §7.3, §8 T8)
//!
//! No localhost TCP is ever used (that class of local-port-hijack bugs is out of
//! scope, PRD §4.7). Instead:
//!
//! - **Windows:** a named pipe `\\.\pipe\localpass-<sanitized-username>` created
//!   with a security descriptor whose DACL grants access to the **current user's
//!   SID only** (and `PIPE_REJECT_REMOTE_CLIENTS`). **The DACL is the
//!   authentication** — a process running as another user, or a remote client,
//!   cannot open the pipe at all.
//! - **Unix:** a `SOCK_STREAM` domain socket at
//!   `$XDG_RUNTIME_DIR/localpass/daemon.sock` (fallback
//!   `~/.localpass-run/daemon.sock`), with the directory `0700`, the socket
//!   `0600`, **and** a `SO_PEERCRED` check on every connection requiring the peer
//!   uid to equal our euid. Permissions plus the peer check are the
//!   authentication.
//!
//! The master password (during [`protocol::Request::Unlock`]) and revealed
//! secret values ([`protocol::Response::Field`], and [`protocol::Response::Item`]
//! with `reveal`) cross the channel in the clear **only because the channel is
//! same-user-only** by construction. See [`protocol`] for the full wire spec
//! (destined for `docs/specs/daemon-ipc.md`).
//!
//! ## Auto-lock & concurrency
//!
//! One [`std::sync::Mutex`] guards the held session (`lp_vault::Session` is not
//! thread-safe, so vault access is serialized behind it — fine at CLI scale). A
//! reaper thread drops the session after a configurable idle timeout (default
//! 600 s; `0` = never; overridable per [`protocol::Request::Unlock`] or the
//! `LOCALPASS_AUTOLOCK_SECS` env var). Every successful request resets the timer.
//! Client IO never happens under the lock, so a hung client can never block a
//! `Lock`, an auto-lock, or another client. See [`server`].
//!
//! ## Module map
//!
//! - [`protocol`] — the versioned, length-prefixed JSON wire types (the spec).
//! - [`origin`] — registrable-domain (eTLD+1) matching for browser autofill;
//!   the daemon-side authority for the `MatchLogins`/`FillLogin` requests the
//!   browser native-messaging host proxies (PRD §4.7 / §8 T7).
//! - [`frame`] — length-prefixed read/write over any byte stream.
//! - [`transport`] — the platform endpoint + access control.
//! - [`engine`] — request → `lp_vault` operations → response.
//! - [`render`] — `lp_vault` items → wire types, with secret masking.
//! - [`server`] — the accept loop, workers, and reaper (`localpass-daemon`).
//! - [`client`] — the connection API the CLI drives, plus [`client::probe`].
//! - [`spawn`] — launch the `localpass-daemon` binary detached (`daemon start`).
//! - [`sshagent`] — the SSH agent protocol served on a **second** same-user-only
//!   endpoint by the same process (vault-backed SSH keys, PRD §4.8).
//! - [`error`] — the transport/lifecycle error type.
//!
//! `unsafe` is confined to the two platform transport modules (the Windows
//! backend for Win32 pipe/security APIs; the Unix backend for
//! `getsockopt(SO_PEERCRED)` + `geteuid`) — see [`transport`]. Those modules are
//! `#[cfg]`-gated, so only the current platform's one is compiled. Every unsafe
//! block is audited inline with a documented safety contract; every other module
//! is `unsafe`-free (each carries a module-level `#![forbid(unsafe_code)]`).

pub mod client;
pub mod engine;
pub mod error;
pub mod frame;
pub mod origin;
pub mod protocol;
pub mod render;
pub mod server;
pub mod spawn;
pub mod sshagent;
pub mod sync;
pub mod transport;

pub use error::{Error, Result};

/// The default idle auto-lock timeout in seconds (PRD §4.3 default 10 min).
pub const DEFAULT_AUTOLOCK_SECS: u64 = 600;

/// The environment variable overriding the idle auto-lock timeout (seconds;
/// `0` = never). Read by the daemon binary at startup.
pub const AUTOLOCK_ENV: &str = "LOCALPASS_AUTOLOCK_SECS";
