//! Integration tests for the `CreateVault` request (GUI "New vault").
//!
//! Drives the daemon [`engine::handle`] directly against a fresh tempdir
//! profile (like `create_account.rs`). Proves that, on an unlocked session, a
//! `CreateVault` adds a vault visible to `ListVaults`, and that it requires an
//! unlocked session.

use std::time::Duration;

use lp_daemon::engine::{self, State};
use lp_daemon::protocol::{Request, Response};

const TEST_PASSWORD: &str = "correct-horse-battery-vault";

fn create_account(state: &mut State, profile: &std::path::Path) {
    let handled = engine::handle(
        state,
        Request::CreateAccount {
            profile: profile.display().to_string(),
            password: TEST_PASSWORD.into(),
        },
    );
    assert!(
        matches!(handled.response, Response::AccountCreated { .. }),
        "account creation should succeed"
    );
}

fn vault_names(state: &mut State, profile: &std::path::Path) -> Vec<String> {
    let listed = engine::handle(
        state,
        Request::ListVaults {
            profile: profile.display().to_string(),
        },
    );
    match listed.response {
        Response::Vaults { vaults } => vaults.into_iter().map(|(_, name)| name).collect(),
        other => panic!("expected Vaults, got {}", other.kind()),
    }
}

#[test]
fn create_vault_adds_a_named_vault() {
    let tmp = tempfile::tempdir().unwrap();
    let profile = tmp.path().to_path_buf();
    let mut state = State::new(profile.clone(), Duration::from_secs(600));
    create_account(&mut state, &profile); // makes the default `personal` vault

    // A new vault by name returns its id.
    let handled = engine::handle(
        &mut state,
        Request::CreateVault {
            profile: profile.display().to_string(),
            name: "work".into(),
        },
    );
    match handled.response {
        Response::Ok { message } => {
            let id = message.expect("the new vault id");
            assert_eq!(id.len(), 36, "a hyphenated UUID id is returned");
        }
        other => panic!("expected Ok, got {}", other.kind()),
    }

    // Both vaults are now listed.
    let names = vault_names(&mut state, &profile);
    assert!(
        names.contains(&"personal".to_string()),
        "default vault kept"
    );
    assert!(names.contains(&"work".to_string()), "new vault present");
    assert_eq!(names.len(), 2);
}

#[test]
fn create_vault_requires_an_unlocked_session() {
    let tmp = tempfile::tempdir().unwrap();
    let profile = tmp.path().to_path_buf();
    let mut state = State::new(profile.clone(), Duration::from_secs(600));
    create_account(&mut state, &profile);

    // Lock, then attempt to create a vault → refused with Locked.
    engine::handle(&mut state, Request::Lock);
    let handled = engine::handle(
        &mut state,
        Request::CreateVault {
            profile: profile.display().to_string(),
            name: "work".into(),
        },
    );
    assert!(
        matches!(handled.response, Response::Locked),
        "creating a vault while locked must be refused"
    );
}
