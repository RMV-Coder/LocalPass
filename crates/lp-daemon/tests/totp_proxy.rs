//! Daemon-proxy TOTP test: run the real server loop, unlock it, seed a `totp`
//! item, then send a [`Request::Totp`] and confirm the daemon returns a code
//! that matches `lp_crypto::totp` computed for the same unix second.
//!
//! # What this proves
//!
//! - The daemon computes the code **itself** from the secret it already holds:
//!   the [`Response::Totp`] carries only the digits + metadata, never the base32
//!   secret (the wire type has no secret field — that is the "secret stays off
//!   the pipe" guarantee, enforced structurally).
//! - The daemon's code equals the crypto core's code at the same second, with a
//!   documented retry on a 30-second period-boundary straddle.
//! - A non-`totp` target is answered with a usage error, not a crash.
//!
//! Like the other in-process server tests, this holds [`ENV_LOCK`] for its whole
//! body (it mutates the process-global `USERNAME`/`USER` env `Client::connect`
//! reads) and binds a unique endpoint so parallel test binaries never collide.

use std::sync::Mutex;
use std::time::{Duration, Instant};

use lp_daemon::client::Client;
use lp_daemon::protocol::{Request, Response};
use lp_daemon::server::{self, Config};

/// Serializes this binary's tests (process-global endpoint env).
static ENV_LOCK: Mutex<()> = Mutex::new(());

/// The RFC 6238 SHA-1 seed "12345678901234567890" in base32.
const RFC_SEED_B32: &str = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
/// The same seed as raw bytes, for the independent `lp_crypto` computation.
const RFC_SEED: &[u8] = b"12345678901234567890";
const TEST_PASSWORD: &str = "correct-horse-battery";

fn unique_user(tag: &str) -> String {
    format!("lptotp-{tag}-{}", std::process::id())
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

/// Create an account with a `totp` item seeded with the RFC secret, plus the
/// on-device Secret Key file the daemon reads at unlock. Returns the tempdir.
fn make_profile_with_totp() -> tempfile::TempDir {
    use lp_vault::AccountStore;
    use lp_vault::payload::{ItemPayload, TypeData};

    let tmp = tempfile::tempdir().unwrap();
    let (session, secret_key) = AccountStore::create(tmp.path(), TEST_PASSWORD).unwrap();
    std::fs::write(
        tmp.path().join("secret-key"),
        secret_key.to_display_string(),
    )
    .unwrap();

    let vid = session.create_vault("personal").unwrap();
    let vault = session.open_vault(vid).unwrap();
    // A totp item (8 digits, period 30, SHA1) and a plain note (wrong-type case).
    vault
        .create_item(&ItemPayload::new(
            TypeData::Totp {
                secret_b32: RFC_SEED_B32.to_string(),
                algo: "SHA1".into(),
                digits: 8,
                period: 30,
                issuer: "ACME".into(),
                account: "alice".into(),
            },
            "RFC",
        ))
        .unwrap();
    vault
        .create_item(&ItemPayload::new(TypeData::Note {}, "JustANote"))
        .unwrap();
    drop(vault);
    session.lock();
    tmp
}

fn set_user(username: &str) {
    unsafe {
        std::env::set_var("USERNAME", username);
        std::env::set_var("USER", username);
    }
}

fn wait_ready(username: &str, timeout: Duration) -> bool {
    set_user(username);
    let deadline = Instant::now() + timeout;
    loop {
        if lp_daemon::client::probe().unwrap_or(false) {
            return true;
        }
        if Instant::now() >= deadline {
            return false;
        }
        std::thread::sleep(Duration::from_millis(25));
    }
}

fn connect(username: &str) -> Client {
    set_user(username);
    Client::connect().expect("connect to test server")
}

#[test]
fn daemon_totp_matches_crypto_core_and_rejects_wrong_type() {
    let _env = ENV_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let username = unique_user("proxy");
    let tmp = make_profile_with_totp();
    let profile = tmp.path().display().to_string();

    let cfg = Config {
        profile: tmp.path().to_path_buf(),
        autolock: Duration::from_secs(600),
        username: username.clone(),
        verbose: false,
        no_ssh_agent: true,
    };
    let handle = std::thread::spawn(move || server::run(cfg));
    assert!(wait_ready(&username, Duration::from_secs(5)), "server up");

    // Unlock the daemon (it reads the secret-key file from the profile).
    {
        let mut c = connect(&username);
        let resp = c
            .call(&Request::Unlock {
                profile: profile.clone(),
                password: TEST_PASSWORD.into(),
                secret_key: None,
                autolock_secs: None,
            })
            .unwrap();
        assert!(matches!(resp, Response::Ok { .. }), "unlock ok");
    }

    // Totp request: retry once on a period-boundary straddle.
    let mut matched = false;
    for _ in 0..3 {
        let before = now_secs();
        let resp = {
            let mut c = connect(&username);
            c.call(&Request::Totp {
                profile: profile.clone(),
                vault: "personal".into(),
                target: "RFC".into(),
            })
            .unwrap()
        };
        let after = now_secs();

        let Response::Totp {
            code,
            seconds_remaining,
            period,
            digits,
            algo,
        } = resp
        else {
            panic!("expected Totp response, got {}", resp.kind());
        };
        assert_eq!(period, 30);
        assert_eq!(digits, 8);
        assert_eq!(algo, "SHA1");
        assert_eq!(code.len(), 8);
        assert!((1..=30).contains(&seconds_remaining));

        if before / 30 == after / 30 {
            let expected =
                lp_crypto::totp::code(RFC_SEED, lp_crypto::TotpAlgo::Sha1, 8, 30, before).unwrap();
            assert_eq!(
                code, expected,
                "daemon code must match lp_crypto at second {before}"
            );
            matched = true;
            break;
        }
    }
    assert!(
        matched,
        "could not land inside a single period after retries"
    );

    // A non-totp target is a usage error (auth = false), not a crash.
    {
        let mut c = connect(&username);
        let resp = c
            .call(&Request::Totp {
                profile: profile.clone(),
                vault: "personal".into(),
                target: "JustANote".into(),
            })
            .unwrap();
        match resp {
            Response::Error { auth, message } => {
                assert!(!auth, "wrong-type is a usage error, not auth");
                assert!(message.contains("not a totp item"), "message: {message}");
            }
            other => panic!("expected Error, got {}", other.kind()),
        }
    }

    // Shut the daemon down.
    {
        let mut c = connect(&username);
        let _ = c.call(&Request::Shutdown);
    }
    let deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < deadline && !handle.is_finished() {
        std::thread::sleep(Duration::from_millis(25));
    }
    if handle.is_finished() {
        let _ = handle.join();
    }
}
