//! In-process server lifecycle tests: run the real server loop in a thread and
//! drive it via the client, checking Ping, Status, Shutdown, and that shutdown
//! actually terminates the loop (no hang).
//!
//! These drive the client via `Client::connect()`, which reads the endpoint
//! username from the process-global `USERNAME`/`USER` env. To keep that safe
//! under cargo's default parallelism, every test holds [`ENV_LOCK`] for its
//! whole body, serializing the two tests in this binary.

use std::sync::Mutex;
use std::time::Duration;

use lp_daemon::client::Client;
use lp_daemon::protocol::{LockState, Request, Response};
use lp_daemon::server::{self, Config};

/// Serializes the tests in this binary (they mutate the process-global
/// `USERNAME`/`USER` env that `Client::connect` reads).
static ENV_LOCK: Mutex<()> = Mutex::new(());

fn unique_user(tag: &str) -> String {
    format!("lpsrv-{tag}-{}", std::process::id())
}

/// The server answers Ping/Status and a Shutdown request terminates `run()`.
#[test]
fn shutdown_terminates_run() {
    let _env = ENV_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let username = unique_user("shutdown");
    let tmp = tempfile::tempdir().unwrap();
    let cfg = Config {
        profile: tmp.path().to_path_buf(),
        autolock: Duration::from_secs(600),
        username: username.clone(),
        verbose: false,
    };

    // Run the server loop in a thread.
    let handle = std::thread::spawn(move || server::run(cfg));

    // Wait for it to come up.
    let user_for_wait = username.clone();
    let ready = wait_ready(&user_for_wait, Duration::from_secs(5));
    assert!(ready, "server did not come up");

    // Ping.
    {
        let mut c = connect(&username);
        assert!(matches!(c.call(&Request::Ping).unwrap(), Response::Pong));
    }
    // Status: locked, correct profile.
    {
        let mut c = connect(&username);
        let resp = c
            .call(&Request::Status {
                profile: tmp.path().display().to_string(),
            })
            .unwrap();
        match resp {
            Response::Status { state, .. } => assert_eq!(state, LockState::Locked),
            other => panic!("expected Status, got {}", other.kind()),
        }
    }
    // Shutdown.
    {
        let mut c = connect(&username);
        let resp = c.call(&Request::Shutdown).unwrap();
        assert!(matches!(resp, Response::Ok { .. }), "shutdown ack");
    }

    // The run() thread must terminate promptly (no hang). Join with a bound.
    let joined = join_timeout(handle, Duration::from_secs(5));
    assert!(joined, "server run() did not terminate after Shutdown");

    // After shutdown, the endpoint is gone: a fresh probe reports not running.
    assert!(
        !wait_ready(&username, Duration::from_millis(500)),
        "endpoint should be released after shutdown"
    );
}

/// A wrong-profile request is answered with WrongProfile, and Lock is idempotent.
#[test]
fn wrong_profile_and_lock_idempotent() {
    let _env = ENV_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let username = unique_user("profile");
    let tmp = tempfile::tempdir().unwrap();
    let cfg = Config {
        profile: tmp.path().to_path_buf(),
        autolock: Duration::from_secs(600),
        username: username.clone(),
        verbose: false,
    };
    let handle = std::thread::spawn(move || server::run(cfg));
    assert!(wait_ready(&username, Duration::from_secs(5)));

    {
        let mut c = connect(&username);
        let resp = c
            .call(&Request::ListVaults {
                profile: "/some/other/profile".into(),
            })
            .unwrap();
        assert!(
            matches!(resp, Response::WrongProfile { .. }),
            "expected WrongProfile"
        );
    }
    // Lock twice (idempotent, both Ok).
    {
        let mut c = connect(&username);
        assert!(matches!(
            c.call(&Request::Lock).unwrap(),
            Response::Ok { .. }
        ));
    }
    {
        let mut c = connect(&username);
        assert!(matches!(
            c.call(&Request::Lock).unwrap(),
            Response::Ok { .. }
        ));
    }

    // Clean up.
    {
        let mut c = connect(&username);
        let _ = c.call(&Request::Shutdown);
    }
    let _ = join_timeout(handle, Duration::from_secs(5));
}

fn connect(username: &str) -> Client {
    // The Client uses current_username(); override the env so it targets ours.
    // Both USERNAME (Windows) and USER (Unix) are set for consistency.
    unsafe {
        std::env::set_var("USERNAME", username);
        std::env::set_var("USER", username);
    }
    Client::connect().expect("connect to test server")
}

fn wait_ready(username: &str, timeout: Duration) -> bool {
    unsafe {
        std::env::set_var("USERNAME", username);
        std::env::set_var("USER", username);
    }
    let deadline = std::time::Instant::now() + timeout;
    loop {
        if lp_daemon::client::probe().unwrap_or(false) {
            return true;
        }
        if std::time::Instant::now() >= deadline {
            return false;
        }
        std::thread::sleep(Duration::from_millis(25));
    }
}

/// Join a thread with a timeout by polling `is_finished`.
fn join_timeout(handle: std::thread::JoinHandle<lp_daemon::Result<()>>, timeout: Duration) -> bool {
    let deadline = std::time::Instant::now() + timeout;
    while std::time::Instant::now() < deadline {
        if handle.is_finished() {
            let _ = handle.join();
            return true;
        }
        std::thread::sleep(Duration::from_millis(25));
    }
    false
}
