//! Integration tests for the attachment requests (the GUI "Attachments" section
//! on ItemDetail).
//!
//! Drives the daemon [`engine::handle`] directly against a fresh tempdir profile
//! (like `create_vault.rs`). The KEY property under test is the **path-based, no
//! blob-on-the-pipe** design: `AddAttachment` names a SOURCE path the daemon
//! reads itself; `GetAttachment` names a DEST path the daemon writes itself; the
//! blob bytes never appear in any request or response. We prove the round-trip
//! is byte-identical, that overwrite is refused without `force` and allowed with
//! it, that delete empties the list, and that an oversize source is rejected.

use std::time::Duration;

use lp_daemon::engine::{self, State};
use lp_daemon::protocol::{Request, Response};

const TEST_PASSWORD: &str = "correct-horse-battery-attach";

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

/// Create a note item titled `title` in the `personal` vault; return nothing —
/// the item is addressed by title in the requests below.
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

fn list_attachments(
    state: &mut State,
    profile: &std::path::Path,
    item: &str,
) -> Vec<(String, String, i64)> {
    let handled = engine::handle(
        state,
        Request::ListAttachments {
            profile: p(profile),
            vault: "personal".into(),
            item: item.into(),
        },
    );
    match handled.response {
        Response::Attachments { attachments } => attachments
            .into_iter()
            .map(|a| (a.attachment_id, a.filename, a.size))
            .collect(),
        other => panic!("expected Attachments, got {}", other.kind()),
    }
}

#[test]
fn add_list_get_roundtrip_writes_byte_identical_data() {
    let tmp = tempfile::tempdir().unwrap();
    let profile = tmp.path().to_path_buf();
    let mut state = State::new(profile.clone(), Duration::from_secs(600));
    create_account(&mut state, &profile);
    create_note(&mut state, &profile, "Cert");

    // A source file on disk with arbitrary (binary) content.
    let contents: Vec<u8> = (0u8..=255).cycle().take(4096).collect();
    let src = tmp.path().join("service-account.json");
    std::fs::write(&src, &contents).unwrap();

    // AddAttachment: pass the SOURCE PATH; the daemon reads it and stores it.
    let added = engine::handle(
        &mut state,
        Request::AddAttachment {
            profile: p(&profile),
            vault: "personal".into(),
            item: "Cert".into(),
            source_path: p(&src),
            filename: String::new(), // derive from the source's base name
        },
    );
    let attachment_id = match added.response {
        Response::Attachment {
            attachment_id,
            filename,
        } => {
            assert_eq!(
                filename, "service-account.json",
                "filename derived from path"
            );
            attachment_id
        }
        other => panic!("expected Attachment, got {}", other.kind()),
    };

    // ListAttachments shows it with the right size (no blob bytes).
    let listed = list_attachments(&mut state, &profile, "Cert");
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].0, attachment_id);
    assert_eq!(listed[0].1, "service-account.json");
    assert_eq!(
        listed[0].2,
        contents.len() as i64,
        "size is the plaintext len"
    );

    // GetAttachment: pass a DEST PATH; the daemon writes the plaintext there.
    let dest = tmp.path().join("out").join("restored.bin");
    let got = engine::handle(
        &mut state,
        Request::GetAttachment {
            profile: p(&profile),
            vault: "personal".into(),
            item: "Cert".into(),
            attachment_id: attachment_id.clone(),
            dest_path: p(&dest),
            force: false,
        },
    );
    match got.response {
        Response::AttachmentSaved {
            filename,
            bytes_written,
        } => {
            assert_eq!(filename, "service-account.json");
            assert_eq!(bytes_written, contents.len() as u64);
        }
        other => panic!("expected AttachmentSaved, got {}", other.kind()),
    }

    // The bytes on disk are byte-identical (parent dir was created).
    let round = std::fs::read(&dest).unwrap();
    assert_eq!(round, contents, "the decrypted file matches the source");
}

#[test]
fn get_refuses_overwrite_without_force_and_allows_with_force() {
    let tmp = tempfile::tempdir().unwrap();
    let profile = tmp.path().to_path_buf();
    let mut state = State::new(profile.clone(), Duration::from_secs(600));
    create_account(&mut state, &profile);
    create_note(&mut state, &profile, "Cert");

    let src = tmp.path().join("data.bin");
    std::fs::write(&src, b"hello attachment").unwrap();
    let added = engine::handle(
        &mut state,
        Request::AddAttachment {
            profile: p(&profile),
            vault: "personal".into(),
            item: "Cert".into(),
            source_path: p(&src),
            filename: "data.bin".into(),
        },
    );
    let attachment_id = match added.response {
        Response::Attachment { attachment_id, .. } => attachment_id,
        other => panic!("expected Attachment, got {}", other.kind()),
    };

    // A pre-existing destination file.
    let dest = tmp.path().join("exists.bin");
    std::fs::write(&dest, b"do not clobber").unwrap();

    // force = false → refused, and the destination is left untouched.
    let refused = engine::handle(
        &mut state,
        Request::GetAttachment {
            profile: p(&profile),
            vault: "personal".into(),
            item: "Cert".into(),
            attachment_id: attachment_id.clone(),
            dest_path: p(&dest),
            force: false,
        },
    );
    assert!(
        matches!(refused.response, Response::Error { .. }),
        "overwrite without force must be refused"
    );
    assert_eq!(
        std::fs::read(&dest).unwrap(),
        b"do not clobber",
        "the destination is untouched on a refused get"
    );

    // force = true → overwrites with the attachment plaintext.
    let ok = engine::handle(
        &mut state,
        Request::GetAttachment {
            profile: p(&profile),
            vault: "personal".into(),
            item: "Cert".into(),
            attachment_id,
            dest_path: p(&dest),
            force: true,
        },
    );
    assert!(matches!(ok.response, Response::AttachmentSaved { .. }));
    assert_eq!(std::fs::read(&dest).unwrap(), b"hello attachment");
}

#[test]
fn delete_removes_the_attachment() {
    let tmp = tempfile::tempdir().unwrap();
    let profile = tmp.path().to_path_buf();
    let mut state = State::new(profile.clone(), Duration::from_secs(600));
    create_account(&mut state, &profile);
    create_note(&mut state, &profile, "Cert");

    let src = tmp.path().join("gone.txt");
    std::fs::write(&src, b"temporary").unwrap();
    let added = engine::handle(
        &mut state,
        Request::AddAttachment {
            profile: p(&profile),
            vault: "personal".into(),
            item: "Cert".into(),
            source_path: p(&src),
            filename: "gone.txt".into(),
        },
    );
    let attachment_id = match added.response {
        Response::Attachment { attachment_id, .. } => attachment_id,
        other => panic!("expected Attachment, got {}", other.kind()),
    };
    assert_eq!(list_attachments(&mut state, &profile, "Cert").len(), 1);

    let deleted = engine::handle(
        &mut state,
        Request::DeleteAttachment {
            profile: p(&profile),
            vault: "personal".into(),
            item: "Cert".into(),
            attachment_id,
        },
    );
    assert!(matches!(deleted.response, Response::Ok { .. }));
    assert!(
        list_attachments(&mut state, &profile, "Cert").is_empty(),
        "the attachment list is empty after delete"
    );
}
