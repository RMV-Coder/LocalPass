#![forbid(unsafe_code)]
//! The `lp-native-host` error type.
//!
//! Covers only **registration** and manifest I/O failures — the native-messaging
//! run loop uses [`crate::framing::FramingError`] instead. No variant carries a
//! secret; every message is safe to print (registration is non-sensitive config).

use thiserror::Error;

/// A registration / manifest error.
#[derive(Debug, Error)]
pub enum Error {
    /// A filesystem failure writing or removing a manifest.
    #[error("io error: {0}")]
    Io(#[source] std::io::Error),

    /// A JSON serialization failure building a manifest (never in practice).
    #[error("manifest serialization error: {0}")]
    Serde(#[source] serde_json::Error),

    /// The platform config/home directory could not be resolved (no
    /// `APPDATA`/`HOME`), so we cannot locate the manifest directory.
    #[error("could not resolve the platform config directory (no APPDATA/HOME)")]
    NoConfigDir,

    /// A Windows registry operation failed, carrying the OS error for diagnosis.
    #[error("registry error: {0}")]
    Registry(String),
}

/// The registration result alias.
pub type Result<T> = std::result::Result<T, Error>;
