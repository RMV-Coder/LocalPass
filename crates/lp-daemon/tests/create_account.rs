//! Integration tests for the `CreateAccount` onboarding request (PRD §4.11).
//!
//! These drive the daemon [`engine::handle`] directly against a fresh tempdir
//! profile — no CLI binary and no live endpoint needed, since account creation
//! is a pure state transition on the held [`engine::State`]. They prove:
//!
//! - a create produces an account file, a Secret Key file, and an unlocked
//!   session holding the default `personal` vault;
//! - the written `secret-key` file lets a subsequent `Unlock` (with no supplied
//!   key) succeed — i.e. the daemon writes exactly the file the unlock path
//!   reads;
//! - a second `CreateAccount` is refused with an "already exists" error;
//! - neither the request nor the response ever renders the secret in `Debug`.

use std::time::Duration;

use lp_daemon::engine::{self, State};
use lp_daemon::protocol::{Request, Response};

const TEST_PASSWORD: &str = "correct-horse-battery-onboard";

/// A create → (account exists, secret-key written, unlocked) → unlock-from-file
/// round trip.
#[test]
fn create_account_then_unlock_from_written_secret_key() {
    let tmp = tempfile::tempdir().unwrap();
    let profile = tmp.path().to_path_buf();
    let mut state = State::new(profile.clone(), Duration::from_secs(600));

    // Create the account.
    let handled = engine::handle(
        &mut state,
        Request::CreateAccount {
            profile: profile.display().to_string(),
            password: TEST_PASSWORD.into(),
        },
    );

    let secret_key = match handled.response {
        Response::AccountCreated {
            secret_key,
            profile: p,
            vault_count,
        } => {
            assert_eq!(vault_count, 1, "the default personal vault was created");
            assert_eq!(p, profile.display().to_string());
            assert!(
                secret_key.starts_with("LP1"),
                "a Secret Key display string was returned"
            );
            secret_key
        }
        other => panic!("expected AccountCreated, got {}", other.kind()),
    };

    // The on-disk files exist: the account store and the owner-only secret-key.
    assert!(
        profile.join("account.localpass").exists(),
        "account store was written"
    );
    let sk_path = profile.join("secret-key");
    assert!(sk_path.exists(), "secret-key file was written");
    let sk_contents = std::fs::read_to_string(&sk_path).unwrap();
    // Byte-for-byte: the display string followed by a single newline (matches
    // lp-cli's store_secret_key, which the unlock path reads).
    assert_eq!(sk_contents, format!("{secret_key}\n"));

    // The session is held unlocked right after creation.
    let status = engine::handle(
        &mut state,
        Request::Status {
            profile: profile.display().to_string(),
        },
    );
    match status.response {
        Response::Status {
            vault_count,
            state: st,
            ..
        } => {
            assert_eq!(st, lp_daemon::protocol::LockState::Unlocked);
            assert_eq!(vault_count, Some(1));
        }
        other => panic!("expected Status, got {}", other.kind()),
    }

    // Lock, then unlock with NO supplied Secret Key: the daemon must read the
    // `secret-key` file it wrote at creation. Success proves the write/read pair
    // agree on the file.
    engine::handle(&mut state, Request::Lock);
    let unlocked = engine::handle(
        &mut state,
        Request::Unlock {
            profile: profile.display().to_string(),
            password: TEST_PASSWORD.into(),
            secret_key: None,
            autolock_secs: None,
        },
    );
    match unlocked.response {
        Response::Ok { .. } => {}
        other => panic!("expected Ok on unlock, got {}", other.kind()),
    }
}

/// A second `CreateAccount` on the same profile is refused (never overwrites).
#[test]
fn create_account_twice_is_refused() {
    let tmp = tempfile::tempdir().unwrap();
    let profile = tmp.path().to_path_buf();
    let mut state = State::new(profile.clone(), Duration::from_secs(600));

    let first = engine::handle(
        &mut state,
        Request::CreateAccount {
            profile: profile.display().to_string(),
            password: TEST_PASSWORD.into(),
        },
    );
    assert!(
        matches!(first.response, Response::AccountCreated { .. }),
        "first create succeeds"
    );

    let second = engine::handle(
        &mut state,
        Request::CreateAccount {
            profile: profile.display().to_string(),
            password: "another-password-entirely".into(),
        },
    );
    match second.response {
        Response::Error { auth, message } => {
            assert!(!auth, "an already-exists error is not an auth failure");
            assert!(
                message.contains("already exists"),
                "clear already-exists message: {message}"
            );
        }
        other => panic!("expected Error on second create, got {}", other.kind()),
    }
}

/// The secret never appears in a `Debug` render of the request or response —
/// the same kind-only redaction the `Unlock`/`Field` paths use (PRD §7.3).
#[test]
fn create_account_debug_never_leaks_secret() {
    let tmp = tempfile::tempdir().unwrap();
    let profile = tmp.path().to_path_buf();
    let mut state = State::new(profile.clone(), Duration::from_secs(600));

    let req = Request::CreateAccount {
        profile: profile.display().to_string(),
        password: "super-secret-onboarding-pw".into(),
    };
    let req_dbg = format!("{req:?}");
    assert!(!req_dbg.contains("super-secret-onboarding-pw"));
    assert!(req_dbg.contains("CreateAccount"));

    let handled = engine::handle(&mut state, req);
    let resp_dbg = format!("{:?}", handled.response);
    // Whatever Secret Key was minted, its display string must not be in Debug.
    if let Response::AccountCreated { secret_key, .. } = &handled.response {
        assert!(
            !resp_dbg.contains(secret_key.as_str()),
            "the response Debug leaked the Secret Key"
        );
    } else {
        panic!("expected AccountCreated");
    }
    assert!(resp_dbg.contains("AccountCreated"));
}
