// NOTE: no module-level `forbid(unsafe_code)` here — this is the parent of the
// platform listener modules (`listener::windows` needs the Win32 pipe APIs via
// `transport::windows`). A `forbid` here would propagate and could not be
// overridden. This file itself contains no `unsafe`; each safe submodule carries
// its own `#![forbid(unsafe_code)]`.
//! # SSH agent service (`sshagent`)
//!
//! A vault-backed SSH agent (PRD §4.8: "`localpass ssh-agent` implements the SSH
//! agent protocol backed by vault-stored keys — keys never touch disk"). It is
//! served by the **same daemon process** as the control protocol, on a **second**
//! same-user-only endpoint, so `ssh`/`ssh-add` can use vault keys with no key
//! material ever written to disk.
//!
//! ## Design (mirrors the control protocol's transport & access control)
//!
//! - **Endpoint** ([`listener`]): Windows named pipe `\\.\pipe\openssh-ssh-agent`
//!   (the fixed name Windows OpenSSH uses) created with the **same
//!   current-user-only DACL + `FIRST_PIPE_INSTANCE`** as the control pipe;
//!   Unix `$XDG_RUNTIME_DIR/localpass/ssh-agent.sock` (`0700`/`0600` +
//!   `SO_PEERCRED`). The security-descriptor / pipe-instance code is **reused**
//!   from [`crate::transport`] — the DACL is the authentication (PRD §8 T8).
//! - **Protocol** ([`protocol`]): the draft-miller SSH agent wire format
//!   (big-endian length-framed messages, SSH-string fields). We handle
//!   `REQUEST_IDENTITIES` and `SIGN_REQUEST`; every other request →
//!   `SSH_AGENT_FAILURE`.
//! - **Keys** ([`keys`]): OpenSSH-format key parsing + signing via the `ssh-key`
//!   crate — the **foreign-format crypto boundary**. `lp-crypto` gains no
//!   SSH-specific code (LESSONS.md). Ed25519 + RSA supported (ECDSA not).
//! - **Service** ([`service`]): turns a request into a reply against the daemon's
//!   held [`lp_vault::Session`] — listing every `ssh_key` item across unlocked
//!   vaults, and signing with the item's current private key (read at request
//!   time, so a rotated key is picked up immediately; no long-lived cache).
//!
//! ## Lock behavior
//!
//! A **locked** daemon serves an **empty** identity list and answers every
//! `SIGN_REQUEST` with `SSH_AGENT_FAILURE` — never an error that kills the
//! connection. The listener passes `None` for the session while locked; unlock /
//! auto-lock take effect immediately because the agent shares the daemon's one
//! `Mutex<State>`.

pub mod keys;
pub mod listener;
pub mod protocol;
pub mod service;
