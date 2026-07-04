#![forbid(unsafe_code)]
//! The client API the CLI uses to talk to a running daemon.
//!
//! A [`Client`] is one connection; it sends a single [`Request`] and reads the
//! [`Response`]. The CLI opens one per request (connections are cheap and the
//! daemon serves them concurrently). [`probe`] is the fast liveness check the
//! CLI runs before deciding whether to proxy or fall back to a direct unlock.

use std::time::{Duration, Instant};

use crate::error::{Error, Result};
use crate::frame;
use crate::protocol::{Request, Response};
use crate::transport;

/// A single client connection to the daemon.
pub struct Client {
    conn: transport::Connection,
}

impl Client {
    /// Connect to the daemon serving the current user.
    ///
    /// # Errors
    ///
    /// [`Error::NotRunning`] if no daemon is listening (the CLI then falls back
    /// to a direct unlock).
    pub fn connect() -> Result<Self> {
        let username = transport::current_username();
        let conn = transport::connect(&username)?;
        Ok(Self { conn })
    }

    /// Send `request` and read the response (one round-trip).
    ///
    /// # Errors
    ///
    /// [`Error::Io`] / [`Error::Serde`] / [`Error::Closed`] on a transport or
    /// protocol failure.
    pub fn call(&mut self, request: &Request) -> Result<Response> {
        frame::write_request(&mut self.conn, request)?;
        frame::read_response(&mut self.conn)
    }
}

/// Fast liveness probe: connect and `Ping`. Returns `Ok(true)` if a daemon
/// answered, `Ok(false)` if none is running, and an error only on an unexpected
/// transport failure.
///
/// # Errors
///
/// A transport error other than "not running".
pub fn probe() -> Result<bool> {
    match Client::connect() {
        Ok(mut c) => match c.call(&Request::Ping) {
            Ok(Response::Pong) => Ok(true),
            Ok(_) => Ok(true), // any answer means a daemon is there
            Err(Error::NotRunning) | Err(Error::Closed) => Ok(false),
            Err(e) => Err(e),
        },
        Err(Error::NotRunning) => Ok(false),
        Err(e) => Err(e),
    }
}

/// Poll [`probe`] until it succeeds or `timeout` elapses (used by
/// `daemon start` after spawning the detached process).
///
/// # Errors
///
/// [`Error::NotRunning`] if the daemon did not come up within `timeout`.
pub fn wait_until_ready(timeout: Duration) -> Result<()> {
    let deadline = Instant::now() + timeout;
    loop {
        if probe().unwrap_or(false) {
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err(Error::NotRunning);
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}
