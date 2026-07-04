//! Command implementations, one module per top-level command.
//!
//! Each `run` takes the resolved profile directory, the [`PasswordSource`], and
//! its parsed arguments, and returns `anyhow::Result<()>`; `main` maps the
//! error to an exit code (see [`crate::error`]).
//!
//! [`PasswordSource`]: crate::unlock::PasswordSource

pub mod backup;
pub mod daemon;
pub mod device;
pub mod env;
pub mod export;
pub mod generate;
pub mod import;
pub mod init;
pub mod item;
pub mod kit;
pub mod password;
pub mod run;
pub mod search;
pub mod ssh;
pub mod status;
pub mod sync;
pub mod totp;
pub mod vault;
