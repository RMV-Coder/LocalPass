#![forbid(unsafe_code)]
//! The daemon crate's error type.
//!
//! One enum for both the server and the client. No variant carries a secret
//! value; messages are safe to log. Authentication failures (wrong password /
//! Secret Key) are represented on the wire by [`crate::protocol::Response::Error`]
//! with `auth = true`, not by this type — this type covers transport, framing,
//! and daemon-lifecycle failures.

use std::io;

/// A daemon transport / lifecycle error.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// An IO failure on the socket/pipe or a profile file.
    #[error("io error: {0}")]
    Io(#[from] io::Error),

    /// A JSON (de)serialization failure on a frame body.
    #[error("protocol serialization error: {0}")]
    Serde(#[from] serde_json::Error),

    /// A declared frame length exceeded [`crate::protocol::MAX_FRAME_LEN`].
    #[error("frame too large: {0} bytes")]
    FrameTooLarge(u64),

    /// The peer used a protocol version this build does not understand.
    #[error("unsupported protocol version: {0}")]
    UnsupportedVersion(u32),

    /// The peer closed the connection before answering.
    #[error("connection closed by peer")]
    Closed,

    /// No daemon is listening at the expected endpoint (used by the client to
    /// decide it must fall back to a direct unlock).
    #[error("no daemon is running")]
    NotRunning,

    /// The peer-credential / access-control check rejected the connection
    /// (Unix uid mismatch). On Windows the DACL prevents the connection from
    /// ever being accepted, so this is Unix-specific.
    #[error("peer credential check failed: {0}")]
    PeerRejected(String),

    /// The daemon could not resolve or create its runtime endpoint (socket
    /// directory, pipe name, …).
    #[error("endpoint setup failed: {0}")]
    Endpoint(String),

    /// A platform / OS API failure (Windows security-descriptor construction,
    /// Unix getsockopt, …), carrying the OS error code for diagnosis.
    #[error("platform error: {0}")]
    Platform(String),
}

/// The daemon crate result alias.
pub type Result<T> = std::result::Result<T, Error>;
