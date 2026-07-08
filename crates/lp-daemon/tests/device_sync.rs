//! Integration tests for the device-pairing + vault-sync requests (the GUI
//! "Devices & Sync" screen).
//!
//! Drives the daemon [`engine::handle`] directly against fresh tempdir profiles
//! (like `create_vault.rs`). Covers:
//!
//! - `ExportIdentity` returns a parseable `LPDEV1-…` string + its fingerprint.
//! - `TrustDevice` with a MATCHING fingerprint succeeds and appears in
//!   `ListPeers`; with a WRONG fingerprint is refused; with an empty
//!   confirmation is refused; a garbage identity string errors.
//! - A full two-device sync round-trip through two daemon `State`s sharing one
//!   temp sync dir: A shares a vault to B, B adopts + reads A's item, B edits,
//!   A pulls the edit back — all via daemon requests (mirrors
//!   `lp-sync/tests/two_device.rs` at the daemon layer).

use std::time::Duration;

use lp_daemon::engine::{self, State};
use lp_daemon::protocol::{Request, Response};
use lp_sync::identity::DeviceIdentity;

const PW: &str = "correct-horse-battery-device";

fn profile_str(p: &std::path::Path) -> String {
    p.display().to_string()
}

fn create_account(state: &mut State, profile: &std::path::Path) {
    let handled = engine::handle(
        state,
        Request::CreateAccount {
            profile: profile_str(profile),
            password: PW.into(),
        },
    );
    assert!(
        matches!(handled.response, Response::AccountCreated { .. }),
        "account creation should succeed"
    );
}

/// Export this device's `(device_id, identity_string, fingerprint)`.
fn export_identity(state: &mut State, profile: &std::path::Path) -> (String, String, String) {
    let handled = engine::handle(
        state,
        Request::ExportIdentity {
            profile: profile_str(profile),
        },
    );
    match handled.response {
        Response::DeviceIdentity {
            device_id,
            identity_string,
            fingerprint,
        } => (device_id, identity_string, fingerprint),
        other => panic!("expected DeviceIdentity, got {}", other.kind()),
    }
}

#[test]
fn export_identity_returns_a_parseable_lpdev1_string() {
    let tmp = tempfile::tempdir().unwrap();
    let profile = tmp.path().to_path_buf();
    let mut state = State::new(profile.clone(), Duration::from_secs(600));
    create_account(&mut state, &profile);

    let (device_id, identity_string, fingerprint) = export_identity(&mut state, &profile);
    assert_eq!(device_id.len(), 36, "hyphenated UUID device id");
    assert!(identity_string.starts_with("LPDEV1-"));

    // The string parses back and its fingerprint matches what the daemon reported.
    let parsed = DeviceIdentity::from_export_string(&identity_string).unwrap();
    assert_eq!(parsed.fingerprint(), fingerprint);
    assert_eq!(parsed.device_id.to_hyphenated(), device_id);
}

#[test]
fn trust_with_matching_fingerprint_succeeds_and_lists() {
    // Two independent accounts (two devices).
    let tmp_a = tempfile::tempdir().unwrap();
    let tmp_b = tempfile::tempdir().unwrap();
    let (profile_a, profile_b) = (tmp_a.path().to_path_buf(), tmp_b.path().to_path_buf());
    let mut a = State::new(profile_a.clone(), Duration::from_secs(600));
    let mut b = State::new(profile_b.clone(), Duration::from_secs(600));
    create_account(&mut a, &profile_a);
    create_account(&mut b, &profile_b);

    // B's identity is what A trusts.
    let (b_id, b_identity, b_fp) = export_identity(&mut b, &profile_b);

    // A trusts B with the correct fingerprint → PeerTrusted.
    let handled = engine::handle(
        &mut a,
        Request::TrustDevice {
            profile: profile_str(&profile_a),
            identity_string: b_identity.clone(),
            expected_fingerprint: b_fp.clone(),
            label: Some("laptop".into()),
        },
    );
    match handled.response {
        Response::PeerTrusted {
            device_id,
            fingerprint,
            label,
        } => {
            assert_eq!(device_id, b_id);
            assert_eq!(fingerprint, b_fp);
            assert_eq!(label.as_deref(), Some("laptop"));
        }
        other => panic!("expected PeerTrusted, got {}", other.kind()),
    }

    // B now appears in A's trusted-devices list, with the same fingerprint.
    let listed = engine::handle(
        &mut a,
        Request::ListPeers {
            profile: profile_str(&profile_a),
        },
    );
    match listed.response {
        Response::Peers { peers } => {
            assert_eq!(peers.len(), 1);
            assert_eq!(peers[0].device_id, b_id);
            assert_eq!(peers[0].fingerprint, b_fp);
            assert_eq!(peers[0].label.as_deref(), Some("laptop"));
        }
        other => panic!("expected Peers, got {}", other.kind()),
    }
}

#[test]
fn trust_with_wrong_fingerprint_is_refused() {
    let tmp_a = tempfile::tempdir().unwrap();
    let tmp_b = tempfile::tempdir().unwrap();
    let (profile_a, profile_b) = (tmp_a.path().to_path_buf(), tmp_b.path().to_path_buf());
    let mut a = State::new(profile_a.clone(), Duration::from_secs(600));
    let mut b = State::new(profile_b.clone(), Duration::from_secs(600));
    create_account(&mut a, &profile_a);
    create_account(&mut b, &profile_b);

    let (_b_id, b_identity, _b_fp) = export_identity(&mut b, &profile_b);

    // A wrong (but well-formed) fingerprint → refused, and nothing is trusted.
    let handled = engine::handle(
        &mut a,
        Request::TrustDevice {
            profile: profile_str(&profile_a),
            identity_string: b_identity.clone(),
            expected_fingerprint: "0000-0000-0000-0000".into(),
            label: None,
        },
    );
    assert!(
        matches!(handled.response, Response::Error { .. }),
        "a fingerprint mismatch must refuse the trust"
    );

    // An EMPTY confirmation is also refused (never auto-trust).
    let handled = engine::handle(
        &mut a,
        Request::TrustDevice {
            profile: profile_str(&profile_a),
            identity_string: b_identity,
            expected_fingerprint: String::new(),
            label: None,
        },
    );
    assert!(
        matches!(handled.response, Response::Error { .. }),
        "an empty fingerprint confirmation must refuse the trust"
    );

    // No peer was recorded.
    let listed = engine::handle(
        &mut a,
        Request::ListPeers {
            profile: profile_str(&profile_a),
        },
    );
    match listed.response {
        Response::Peers { peers } => assert!(peers.is_empty(), "no device should be trusted"),
        other => panic!("expected Peers, got {}", other.kind()),
    }
}

#[test]
fn trust_with_garbage_identity_string_errors() {
    let tmp = tempfile::tempdir().unwrap();
    let profile = tmp.path().to_path_buf();
    let mut state = State::new(profile.clone(), Duration::from_secs(600));
    create_account(&mut state, &profile);

    let handled = engine::handle(
        &mut state,
        Request::TrustDevice {
            profile: profile_str(&profile),
            identity_string: "NOT-A-REAL-IDENTITY".into(),
            expected_fingerprint: "0000-0000-0000-0000".into(),
            label: None,
        },
    );
    assert!(
        matches!(handled.response, Response::Error { .. }),
        "a garbage identity string must error"
    );
}

/// A vault name/id resolution + item titles are shared by helper below.
fn create_login(state: &mut State, profile: &std::path::Path, vault: &str, title: &str, pw: &str) {
    let payload = serde_json::json!({
        "v": 1,
        "type": "login",
        "title": title,
        "fields": [{ "name": "password", "kind": "hidden", "value": pw }],
    });
    let handled = engine::handle(
        state,
        Request::CreateItem {
            profile: profile_str(profile),
            vault: vault.into(),
            payload,
        },
    );
    assert!(
        matches!(handled.response, Response::Ok { .. }),
        "creating a login should succeed"
    );
}

#[test]
fn two_device_share_adopt_and_bidirectional_sync_through_daemons() {
    // Device A + B, each with its own account (and default `personal` vault).
    let tmp_a = tempfile::tempdir().unwrap();
    let tmp_b = tempfile::tempdir().unwrap();
    let sync_root = tempfile::tempdir().unwrap();
    let (profile_a, profile_b) = (tmp_a.path().to_path_buf(), tmp_b.path().to_path_buf());
    let root = sync_root.path().display().to_string();
    let mut a = State::new(profile_a.clone(), Duration::from_secs(600));
    let mut b = State::new(profile_b.clone(), Duration::from_secs(600));
    create_account(&mut a, &profile_a);
    create_account(&mut b, &profile_b);

    // A creates a login in its `personal` vault.
    create_login(&mut a, &profile_a, "personal", "GitHub", "hunter2");

    // Mutual trust (both directions confirmed by fingerprint).
    let (a_id, a_identity, a_fp) = export_identity(&mut a, &profile_a);
    let (b_id, b_identity, b_fp) = export_identity(&mut b, &profile_b);
    for (state, profile, identity, fp, id) in [
        (&mut a, &profile_a, &b_identity, &b_fp, &b_id),
        (&mut b, &profile_b, &a_identity, &a_fp, &a_id),
    ] {
        let handled = engine::handle(
            state,
            Request::TrustDevice {
                profile: profile_str(profile),
                identity_string: identity.clone(),
                expected_fingerprint: fp.clone(),
                label: None,
            },
        );
        assert!(
            matches!(handled.response, Response::PeerTrusted { .. }),
            "mutual trust should succeed for {id}"
        );
    }

    // A enrolls + pushes, then shares the vault to B.
    let setup = engine::handle(
        &mut a,
        Request::SyncSetup {
            profile: profile_str(&profile_a),
            vault: "personal".into(),
            dir: root.clone(),
        },
    );
    assert!(matches!(setup.response, Response::Ok { .. }));

    let push = engine::handle(
        &mut a,
        Request::SyncPush {
            profile: profile_str(&profile_a),
            vault: "personal".into(),
        },
    );
    match push.response {
        Response::SyncPushed {
            segments_written, ..
        } => assert!(segments_written >= 1, "A wrote at least one segment"),
        other => panic!("expected SyncPushed, got {}", other.kind()),
    }

    let share = engine::handle(
        &mut a,
        Request::ShareVaultToDevice {
            profile: profile_str(&profile_a),
            vault: "personal".into(),
            device_id: b_id.clone(),
        },
    );
    assert!(
        matches!(share.response, Response::Ok { .. }),
        "sharing the vault to B should succeed"
    );

    // B adopts the shared vault from the root — its items materialize.
    let adopt = engine::handle(
        &mut b,
        Request::SyncAdopt {
            profile: profile_str(&profile_b),
            dir: root.clone(),
        },
    );
    let adopted_vault_id = match adopt.response {
        Response::SyncAdopted {
            adopted,
            applied_total,
            alarms,
        } => {
            assert_eq!(adopted.len(), 1, "B adopted exactly one vault");
            assert!(applied_total >= 1, "B applied A's op(s)");
            assert!(alarms.is_empty(), "no alarms on a clean adopt");
            adopted[0].vault_id.clone()
        }
        other => panic!("expected SyncAdopted, got {}", other.kind()),
    };

    // B can read A's item (secret included) via a normal GetItem reveal.
    let got = engine::handle(
        &mut b,
        Request::GetItem {
            profile: profile_str(&profile_b),
            vault: adopted_vault_id.clone(),
            target: "GitHub".into(),
            version: None,
            reveal: true,
        },
    );
    match got.response {
        Response::Item { item } => {
            assert_eq!(item.title, "GitHub");
            let pw = item.fields.iter().find(|f| f.name == "password").unwrap();
            assert_eq!(pw.value, "hunter2", "B reads A's shared secret");
        }
        other => panic!("expected Item, got {}", other.kind()),
    }

    // B edits the item and pushes; A pulls the edit back.
    let update = engine::handle(
        &mut b,
        Request::UpdateItem {
            profile: profile_str(&profile_b),
            vault: adopted_vault_id.clone(),
            target: "GitHub".into(),
            payload: serde_json::json!({
                "v": 1,
                "type": "login",
                "title": "GitHub",
                "fields": [{ "name": "password", "kind": "hidden", "value": "rotated-9911" }],
            }),
        },
    );
    assert!(matches!(update.response, Response::Ok { .. }));

    let push_b = engine::handle(
        &mut b,
        Request::SyncPush {
            profile: profile_str(&profile_b),
            vault: adopted_vault_id.clone(),
        },
    );
    assert!(matches!(push_b.response, Response::SyncPushed { .. }));

    let pull_a = engine::handle(
        &mut a,
        Request::SyncPull {
            profile: profile_str(&profile_a),
            vault: "personal".into(),
        },
    );
    match pull_a.response {
        Response::SyncPulled {
            applied, alarms, ..
        } => {
            assert_eq!(applied, 1, "A applied B's edit");
            assert!(alarms.is_empty(), "no alarms on a clean pull");
        }
        other => panic!("expected SyncPulled, got {}", other.kind()),
    }

    // A now sees B's rotated password.
    let seen = engine::handle(
        &mut a,
        Request::GetItem {
            profile: profile_str(&profile_a),
            vault: "personal".into(),
            target: "GitHub".into(),
            version: None,
            reveal: true,
        },
    );
    match seen.response {
        Response::Item { item } => {
            let pw = item.fields.iter().find(|f| f.name == "password").unwrap();
            assert_eq!(pw.value, "rotated-9911", "A sees B's edit");
        }
        other => panic!("expected Item, got {}", other.kind()),
    }
}
