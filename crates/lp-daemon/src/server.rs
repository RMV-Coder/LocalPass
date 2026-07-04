#![forbid(unsafe_code)]
//! The daemon server: accept loop, per-connection workers, and the auto-lock
//! reaper.
//!
//! # Concurrency model (dependency-light, threaded std — no tokio)
//!
//! - One **accept loop** on the main thread binds the endpoint and blocks in
//!   `accept()`. Each accepted connection is handed to a **worker thread**.
//! - Each worker reads a request off the wire, then briefly takes the shared
//!   `Mutex<State>` to handle it (via [`crate::engine::handle`]), then releases
//!   the mutex and writes the response. Because client IO happens **outside**
//!   the locked section, a hung client stalls only its own worker — never the
//!   mutex, so `Lock`/auto-lock/other clients are never blocked (the PRD's
//!   hung-client immunity requirement).
//! - One **reaper thread** wakes on a short fixed interval and, holding the
//!   mutex for a few microseconds, drops the session if the idle timeout
//!   elapsed. It performs no IO under the lock.
//!
//! Why threaded std over tokio: the workload is a handful of sequential CLI
//! requests, `lp-vault`'s `Session` is synchronous and `!Sync` (so it must be
//! serialized behind a mutex regardless), and a blocking accept + thread-per-
//! connection keeps the whole daemon auditable with no async runtime in the
//! dependency graph. tokio would add a large surface for zero real benefit here.
//!
//! # Shutdown
//!
//! A `Shutdown` request (or SIGINT-style termination of the process) flips the
//! shared `running` flag. The reaper observes it and returns; the accept loop
//! observes it after its current `accept()` returns. Because `accept()` blocks,
//! the shutdown path also *self-connects* once to unblock it, then the endpoint
//! is released on `Listener` drop (Unix unlinks the socket; Windows closes the
//! pipe), leaving no stale endpoint behind.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use crate::engine::{self, State};
use crate::error::{Error, Result};
use crate::frame;
use crate::transport::{self, Listener};

/// How often the reaper checks the idle timer.
const REAP_INTERVAL: Duration = Duration::from_millis(200);

/// Options for [`run`].
pub struct Config {
    /// The single profile directory this daemon serves (absolute).
    pub profile: std::path::PathBuf,
    /// The idle auto-lock timeout (`Duration::ZERO` = never).
    pub autolock: Duration,
    /// The sanitized username used to name the endpoint.
    pub username: String,
    /// Whether to log request kinds + timings to stderr (never secrets).
    pub verbose: bool,
}

/// Shared server state: the guarded vault state plus a running flag.
struct Shared {
    state: Mutex<State>,
    running: AtomicBool,
    verbose: bool,
    username: String,
}

/// Run the daemon until a `Shutdown` request arrives (blocking).
///
/// Binds the endpoint (applying the platform access control), spawns the reaper,
/// and serves connections until shutdown. Returns after the endpoint is
/// released.
///
/// # Errors
///
/// [`Error::Endpoint`] / [`Error::Platform`] if the endpoint cannot be bound
/// (e.g. another daemon already owns it).
pub fn run(config: Config) -> Result<()> {
    let mut listener = Listener::bind(&config.username)?;
    let label = listener.endpoint_label();
    if config.verbose {
        log(&format!(
            "listening on {label} (profile {}, autolock {}s)",
            config.profile.display(),
            config.autolock.as_secs()
        ));
    }

    let shared = Arc::new(Shared {
        state: Mutex::new(State::new(config.profile.clone(), config.autolock)),
        running: AtomicBool::new(true),
        verbose: config.verbose,
        username: config.username.clone(),
    });

    // Reaper thread: idle auto-lock.
    let reaper = {
        let shared = Arc::clone(&shared);
        std::thread::spawn(move || reaper_loop(&shared))
    };

    // Accept loop.
    let mut workers = Vec::new();
    while shared.running.load(Ordering::Acquire) {
        match listener.accept() {
            Ok(conn) => {
                // Prune finished worker handles so the vec doesn't grow without
                // bound over a long-lived daemon's many short connections.
                workers.retain(|w: &std::thread::JoinHandle<()>| !w.is_finished());
                let shared = Arc::clone(&shared);
                workers.push(std::thread::spawn(move || {
                    if let Err(e) = serve_connection(&shared, conn)
                        && shared.verbose
                    {
                        log(&format!("connection error: {e}"));
                    }
                }));
            }
            Err(Error::PeerRejected(msg)) => {
                // Unix: an impostor uid. Log and keep serving.
                if shared.verbose {
                    log(&format!("rejected peer: {msg}"));
                }
            }
            Err(e) => {
                // A transient accept error: if we're shutting down, break;
                // otherwise log and continue (do not kill the daemon on one
                // bad accept).
                if !shared.running.load(Ordering::Acquire) {
                    break;
                }
                if shared.verbose {
                    log(&format!("accept error: {e}"));
                }
            }
        }
    }

    // Signal reaper to stop and join it. Detach any still-running workers: their
    // clients are hung; we do not wait on client IO during shutdown.
    shared.running.store(false, Ordering::Release);
    let _ = reaper.join();
    // Best-effort join of workers that are already finishing; don't block on
    // hung ones (they hold no lock and will be reaped by process exit).
    for w in workers {
        if w.is_finished() {
            let _ = w.join();
        }
    }

    // Drop the listener to release the endpoint (unlink socket / close pipe).
    drop(listener);
    if shared.verbose {
        log("stopped; endpoint released");
    }
    Ok(())
}

/// Serve one connection: read requests, handle them, write responses, until the
/// client closes or a `Shutdown` is handled.
fn serve_connection(shared: &Arc<Shared>, mut conn: transport::Connection) -> Result<()> {
    loop {
        // 1) Read the full request off the wire — NO lock held here, so a slow
        //    client cannot block the mutex.
        let request = match frame::read_request(&mut conn)? {
            Some(req) => req,
            None => return Ok(()), // client closed cleanly between messages
        };
        let kind = request.kind();
        let started = std::time::Instant::now();

        // 2) Handle under the lock (brief; no client IO inside).
        let handled = {
            let mut state = shared
                .state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            engine::handle(&mut state, request)
        };

        if shared.verbose {
            log(&format!(
                "{kind} -> {} ({} us)",
                handled.response.kind(),
                started.elapsed().as_micros()
            ));
        }

        // 3) Write the response — again outside the lock.
        frame::write_response(&mut conn, &handled.response)?;

        if handled.shutdown {
            // Flip running and unblock the accept loop by self-connecting.
            shared.running.store(false, Ordering::Release);
            wake_acceptor(&shared.username);
            return Ok(());
        }
    }
}

/// The idle auto-lock loop. Wakes periodically and drops the session if idle.
fn reaper_loop(shared: &Arc<Shared>) {
    while shared.running.load(Ordering::Acquire) {
        std::thread::sleep(REAP_INTERVAL);
        if !shared.running.load(Ordering::Acquire) {
            break;
        }
        let locked_now = {
            let mut state = shared
                .state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            state.maybe_autolock()
        };
        if locked_now && shared.verbose {
            log("auto-locked (idle timeout)");
        }
    }
}

/// Unblock the accept loop's blocking `accept()` by making one throwaway
/// connection to our own endpoint. The accept returns, the loop re-checks
/// `running` (now false), and exits.
fn wake_acceptor(username: &str) {
    if let Ok(mut conn) = transport::connect(username) {
        // Send a Ping so the just-accepted worker has something to read and
        // exits cleanly; ignore any error (we only need accept() to return).
        let _ = frame::write_request(&mut conn, &crate::protocol::Request::Ping);
    }
}

/// Log one line to stderr, prefixed. Never called with a secret (callers pass
/// request/response *kinds* and timings only).
fn log(msg: &str) {
    eprintln!("[localpass-daemon] {msg}");
}
