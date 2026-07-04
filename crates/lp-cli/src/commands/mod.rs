//! Command implementations, one module per top-level command.
//!
//! Each `run` takes the resolved profile directory, the [`PasswordSource`], and
//! its parsed arguments, and returns `anyhow::Result<()>`; `main` maps the
//! error to an exit code (see [`crate::error`]).
//!
//! [`PasswordSource`]: crate::unlock::PasswordSource

pub mod generate;
pub mod init;
pub mod item;
pub mod password;
pub mod search;
pub mod status;
pub mod vault;
