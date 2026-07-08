//! The oversize-source rejection path for `AddAttachment`, isolated in its own
//! test binary.
//!
//! This lives apart from `attachments.rs` on purpose: it uses the debug-only
//! `LP_MAX_ATTACHMENT_BYTES` env override to lower the cap so the reject path
//! can be exercised without materializing a 50 MiB file — and a process env var
//! is shared across the tests in a single binary, so keeping this the ONLY test
//! in its binary means the lowered cap can never leak into the byte-identical
//! round-trip test (which would then spuriously fail).

use std::time::Duration;

use lp_daemon::engine::{self, State};
use lp_daemon::protocol::{Request, Response};

const TEST_PASSWORD: &str = "correct-horse-battery-attach-oversize";

fn p(path: &std::path::Path) -> String {
    path.display().to_string()
}

#[test]
fn oversize_source_is_rejected() {
    let tmp = tempfile::tempdir().unwrap();
    let profile = tmp.path().to_path_buf();
    let mut state = State::new(profile.clone(), Duration::from_secs(600));

    // Account + a note item to attach to.
    let created = engine::handle(
        &mut state,
        Request::CreateAccount {
            profile: p(&profile),
            password: TEST_PASSWORD.into(),
        },
    );
    assert!(matches!(created.response, Response::AccountCreated { .. }));
    let note = engine::handle(
        &mut state,
        Request::CreateItem {
            profile: p(&profile),
            vault: "personal".into(),
            payload: serde_json::json!({ "v": 1, "type": "note", "title": "Cert" }),
        },
    );
    assert!(matches!(note.response, Response::Ok { .. }));

    // Lower the cap (debug-only, cannot raise the 50 MiB const; compiled out of
    // release). This is the only test in this binary, so the override is scoped
    // to it. SAFETY: single-threaded, no other test reads the env concurrently.
    unsafe {
        std::env::set_var("LP_MAX_ATTACHMENT_BYTES", "16");
    }

    let src = tmp.path().join("too-big.bin");
    std::fs::write(&src, vec![0u8; 64]).unwrap();

    let handled = engine::handle(
        &mut state,
        Request::AddAttachment {
            profile: p(&profile),
            vault: "personal".into(),
            item: "Cert".into(),
            source_path: p(&src),
            filename: "too-big.bin".into(),
        },
    );
    assert!(
        matches!(handled.response, Response::Error { .. }),
        "an oversize source must be rejected"
    );

    // No attachment row was created for the rejected source.
    let listed = engine::handle(
        &mut state,
        Request::ListAttachments {
            profile: p(&profile),
            vault: "personal".into(),
            item: "Cert".into(),
        },
    );
    match listed.response {
        Response::Attachments { attachments } => {
            assert!(attachments.is_empty(), "no row for a rejected oversize add");
        }
        other => panic!("expected Attachments, got {}", other.kind()),
    }

    unsafe {
        std::env::remove_var("LP_MAX_ATTACHMENT_BYTES");
    }
}
