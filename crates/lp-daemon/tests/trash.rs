//! Integration tests for the trash requests (`ListTrash` / `UntrashItem`) —
//! the "recoverable for 30 days" promise made by the delete flow.
//!
//! Drives the daemon [`engine::handle`] directly against a fresh tempdir
//! profile (like `attachments.rs`). Properties under test: a deleted item shows
//! up in the trash listing with its decrypted title (and no field values on the
//! wire), untrash revives it (by title or id, resolved among trashed items
//! only), and a live or unknown target is refused with a usage error.

use std::time::Duration;

use lp_daemon::engine::{self, State};
use lp_daemon::protocol::{Request, Response, WireTrashEntry};

const TEST_PASSWORD: &str = "correct-horse-battery-trash";

fn p(path: &std::path::Path) -> String {
    path.display().to_string()
}

fn create_account(state: &mut State, profile: &std::path::Path) {
    let handled = engine::handle(
        state,
        Request::CreateAccount {
            profile: p(profile),
            password: TEST_PASSWORD.into(),
        },
    );
    assert!(
        matches!(handled.response, Response::AccountCreated { .. }),
        "account creation should succeed"
    );
}

fn create_note(state: &mut State, profile: &std::path::Path, title: &str) {
    let payload = serde_json::json!({
        "v": 1,
        "type": "note",
        "title": title,
    });
    let handled = engine::handle(
        state,
        Request::CreateItem {
            profile: p(profile),
            vault: "personal".into(),
            payload,
        },
    );
    assert!(
        matches!(handled.response, Response::Ok { .. }),
        "creating a note should succeed"
    );
}

fn delete_item(state: &mut State, profile: &std::path::Path, target: &str) {
    let handled = engine::handle(
        state,
        Request::DeleteItem {
            profile: p(profile),
            vault: "personal".into(),
            target: target.into(),
        },
    );
    assert!(
        matches!(handled.response, Response::Ok { .. }),
        "deleting {target:?} should succeed"
    );
}

fn list_trash(state: &mut State, profile: &std::path::Path) -> Vec<WireTrashEntry> {
    let handled = engine::handle(
        state,
        Request::ListTrash {
            profile: p(profile),
            vault: "personal".into(),
        },
    );
    match handled.response {
        Response::TrashEntries { entries } => entries,
        other => panic!("expected TrashEntries, got {}", other.kind()),
    }
}

fn count_live_items(state: &mut State, profile: &std::path::Path) -> usize {
    let handled = engine::handle(
        state,
        Request::ListItems {
            profile: p(profile),
            vault: "personal".into(),
        },
    );
    match handled.response {
        Response::Items { items } => items.len(),
        other => panic!("expected Items, got {}", other.kind()),
    }
}

fn untrash(state: &mut State, profile: &std::path::Path, target: &str) -> Response {
    engine::handle(
        state,
        Request::UntrashItem {
            profile: p(profile),
            vault: "personal".into(),
            target: target.into(),
        },
    )
    .response
}

#[test]
fn delete_list_untrash_roundtrip_by_title_and_id() {
    let tmp = tempfile::tempdir().unwrap();
    let profile = tmp.path().to_path_buf();
    let mut state = State::new(profile.clone(), Duration::from_secs(600));
    create_account(&mut state, &profile);
    create_note(&mut state, &profile, "Alpha");
    create_note(&mut state, &profile, "Beta");
    assert_eq!(count_live_items(&mut state, &profile), 2);

    // Delete Alpha → it appears in the trash with its decrypted title.
    delete_item(&mut state, &profile, "Alpha");
    assert_eq!(count_live_items(&mut state, &profile), 1);
    let trash = list_trash(&mut state, &profile);
    assert_eq!(trash.len(), 1);
    assert_eq!(trash[0].title, "Alpha");
    assert_eq!(trash[0].type_str, "note");
    assert!(trash[0].deleted_at > 0);
    assert!(
        trash[0].purge_after > trash[0].deleted_at,
        "purge window lies after the deletion"
    );

    // Untrash by TITLE → revived as a new version; trash is empty again.
    match untrash(&mut state, &profile, "Alpha") {
        Response::Ok { message } => {
            assert_eq!(message.as_deref(), Some("version 2"));
        }
        other => panic!("expected Ok, got {}", other.kind()),
    }
    assert_eq!(count_live_items(&mut state, &profile), 2);
    assert!(list_trash(&mut state, &profile).is_empty());

    // Delete Beta and untrash it by ID (the trash entry carries the id).
    delete_item(&mut state, &profile, "Beta");
    let trash = list_trash(&mut state, &profile);
    assert_eq!(trash.len(), 1);
    let beta_id = trash[0].id.clone();
    assert!(
        matches!(untrash(&mut state, &profile, &beta_id), Response::Ok { .. }),
        "untrash by id should succeed"
    );
    assert_eq!(count_live_items(&mut state, &profile), 2);
    assert!(list_trash(&mut state, &profile).is_empty());
}

#[test]
fn untrash_refuses_live_and_unknown_targets() {
    let tmp = tempfile::tempdir().unwrap();
    let profile = tmp.path().to_path_buf();
    let mut state = State::new(profile.clone(), Duration::from_secs(600));
    create_account(&mut state, &profile);
    create_note(&mut state, &profile, "Live");

    // A live item does not resolve among trashed items.
    match untrash(&mut state, &profile, "Live") {
        Response::Error { auth, message } => {
            assert!(!auth);
            assert!(
                message.contains("no trashed item"),
                "live target should miss the trash: {message}"
            );
        }
        other => panic!("expected Error, got {}", other.kind()),
    }

    // An unknown title is a usage error too.
    assert!(
        matches!(
            untrash(&mut state, &profile, "Never Existed"),
            Response::Error { auth: false, .. }
        ),
        "unknown target should be a usage error"
    );
}
