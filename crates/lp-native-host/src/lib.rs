// `unsafe` is denied crate-wide and forbidden per-module in every safe module.
// Only `winreg` (Windows only) opts back in — it must call Win32 registry APIs —
// via a local `#![allow(unsafe_code)]`, which `deny` (unlike `forbid`) permits.
// Every unsafe block there documents its safety contract inline.
#![deny(unsafe_code)]
#![warn(missing_docs)]
//! # LocalPass browser native-messaging host (`lp-native-host`)
//!
//! The `localpass-native-host` binary the browser launches for the LocalPass
//! extension (Chrome/Chromium family, Firefox). It speaks the browser
//! **native-messaging** protocol on stdin/stdout ([`framing`], [`protocol`]) and
//! bridges to the LocalPass daemon over the daemon's existing **same-user-only**
//! IPC ([`bridge`]) — with a strictly **fill-scoped** capability.
//!
//! ## Why native messaging, not a localhost port (PRD §4.7 / §8 T8)
//!
//! LocalPass never opens a localhost HTTP port for the browser — that is the
//! class of local-port-hijack bugs the design explicitly avoids. Native messaging
//! is browser-brokered: the browser launches this host as a child process and
//! pipes messages over its stdio, and the OS + the browser's manifest allowlist
//! (`allowed_origins`/`allowed_extensions`) decide which extension may talk to it.
//!
//! ## The security posture (PRD §5.1, §6.7, §7.3, §8 T3/T7)
//!
//! - **Holds no keys.** The host cannot unlock and never sees key material. All
//!   secret access goes through the daemon, which holds the unlocked session.
//! - **Fill-scoped only.** The host issues just three daemon requests —
//!   `Status`, `MatchLogins`, `FillLogin` — never a raw item read, export, or any
//!   mutation. The browser side literally cannot ask for more.
//! - **No password in candidate lists.** `credentials_for` returns only
//!   `{item_id, title, username, vault}` — never a password (§8 T7). The password
//!   crosses only in a `fill` response, for one user-selected item.
//! - **Server-side origin re-validation.** For a `fill`, the **daemon**
//!   re-checks that the item's stored URL matches the requested origin's
//!   registrable domain ([`lp_daemon::origin`]) — the host's/extension's claim is
//!   not trusted. A mismatch returns an error, never the secret (§8 T7).
//! - **Registrable-domain matching, no cross-origin over-match.** A lookalike
//!   domain (`evil-example.com`, `example.com.evil.com`) never matches
//!   `example.com`; a bare public suffix (`com`, `co.uk`) is refused.
//! - **Locked ≠ hang.** A locked or unreachable daemon yields a `locked` /
//!   `unavailable` response so the extension can prompt the user to unlock via the
//!   CLI/daemon — the browser is never blocked (PRD §4.7).
//! - **Bounded input.** A 1 MiB inbound cap (Chrome's limit) and a length-checked
//!   frame reader mean a corrupt or hostile prefix cannot exhaust memory or panic.
//! - **Secret-free logs.** stderr logs message *types* only; a `fill` password is
//!   never logged.
//!
//! The hard autofill rules from PRD §4.7 that live in the **extension** (fill only
//! on an explicit user gesture, never auto-submit, never fill a cross-origin
//! iframe) are the extension's responsibility; this host provides the trustworthy
//! primitive underneath: *only* non-secret candidates for a matching registrable
//! domain, and a single-item, daemon-re-validated fill.
//!
//! ## Module map
//!
//! - [`framing`] — native-messaging stdio framing (native-endian length prefix,
//!   1 MiB inbound cap, truncation handled without panic).
//! - [`protocol`] — the versioned `{"v":1,...}` extension↔host JSON schema.
//! - [`bridge`] — the fill-scoped host↔daemon translation over `lp_daemon`'s IPC.
//! - [`host`] — the read→dispatch→write loop (parameterized over any `Read`/`Write`).
//! - [`register`] — writing/removing the browser native-messaging **manifests**
//!   and (Windows) the registry keys that point browsers at this binary.
//! - [`error`] — the crate error type (transport-free, secret-free messages).
//! - `winreg` (Windows only) — a tiny `HKCU` registry helper for `register`; the
//!   sole module permitted `unsafe` (Win32 registry calls).

pub mod bridge;
pub mod error;
pub mod framing;
pub mod host;
pub mod protocol;
pub mod register;
#[cfg(windows)]
pub mod winreg;
