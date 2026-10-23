//! The daemon's "Sync by QR code" requests (`qr-transport.md` §10.2), driven
//! against two in-process daemon `State`s: a bundle moves between them by path,
//! exactly as the GUI hands it over after the camera rebuilt it.

use std::time::Duration;

use lp_daemon::engine::{self, RequestContext, State};
use lp_daemon::protocol::{Request, Response};

const PW: &str = "correct-horse-battery-qr";

struct Dev {
    state: State,
    profile: String,
    _dir: tempfile::TempDir,
}

fn call(state: &mut State, req: Request) -> Response {
    engine::handle(state, req).response
}

fn device() -> Dev {
    let dir = tempfile::tempdir().unwrap();
    let profile = dir.path().display().to_string();
    let mut dev = Dev {
        state: State::new(dir.path().to_path_buf(), Duration::ZERO),
        profile,
        _dir: dir,
    };
    let r = call(
        &mut dev.state,
        Request::CreateAccount {
            profile: dev.profile.clone(),
            password: PW.into(),
        },
    );
    assert!(matches!(r, Response::AccountCreated { .. }), "{}", r.kind());
    dev
}

fn identity(dev: &mut Dev) -> (String, String, String) {
    match call(
        &mut dev.state,
        Request::ExportIdentity {
            profile: dev.profile.clone(),
        },
    ) {
        Response::DeviceIdentity {
            device_id,
            identity_string,
            fingerprint,
        } => (device_id, identity_string, fingerprint),
        other => panic!("{}", other.kind()),
    }
}

fn trust(a: &mut Dev, b: &mut Dev) {
    let (_, identity_string, fingerprint) = identity(b);
    let profile = a.profile.clone();
    assert!(matches!(
        call(
            &mut a.state,
            Request::SetPairingMode {
                profile: profile.clone(),
                enabled: true,
            }
        ),
        Response::Ok { .. }
    ));
    let r = call(
        &mut a.state,
        Request::TrustDevice {
            profile,
            identity_string,
            expected_fingerprint: fingerprint,
            label: Some("peer".into()),
        },
    );
    assert!(matches!(r, Response::PeerTrusted { .. }), "{}", r.kind());
}

fn add_item(dev: &mut Dev, vault: &str, title: &str) {
    let r = call(
        &mut dev.state,
        Request::CreateItem {
            profile: dev.profile.clone(),
            vault: vault.into(),
            payload: serde_json::json!({
                "v": 1, "type": "login", "urls": [], "title": title, "notes": "",
                "tags": [], "favorite": false,
                "fields": [{ "name": "password", "kind": "hidden", "value": "pw" }],
            }),
        },
    );
    assert!(matches!(r, Response::Ok { .. }), "{}", r.kind());
}

fn export(
    dev: &mut Dev,
    out: &std::path::Path,
    have: Option<String>,
    peer: Option<String>,
    share: Vec<String>,
) -> Response {
    call(
        &mut dev.state,
        Request::QrExport {
            profile: dev.profile.clone(),
            out_path: out.display().to_string(),
            vaults: Vec::new(),
            have,
            peer,
            share,
            attachments: false,
            force: false,
        },
    )
}

fn import(dev: &mut Dev, path: &std::path::Path, transfer_id: Option<String>) -> Response {
    call(
        &mut dev.state,
        Request::QrImport {
            profile: dev.profile.clone(),
            path: path.display().to_string(),
            transfer_id,
        },
    )
}

#[test]
fn a_share_then_a_delta_travel_by_path() {
    let mut a = device();
    let mut b = device();
    trust(&mut a, &mut b);
    trust(&mut b, &mut a);
    let (b_id, _, _) = identity(&mut b);
    add_item(&mut a, "personal", "GitHub");
    let dir = tempfile::tempdir().unwrap();
    let first = dir.path().join("first.lpqr");

    let summary = match export(
        &mut a,
        &first,
        None,
        Some(b_id.clone()),
        vec!["personal".into()],
    ) {
        Response::QrExported { summary } => summary,
        Response::Error { message, .. } => panic!("{message}"),
        other => panic!("{}", other.kind()),
    };
    assert_eq!(summary.vaults[0].ops, 1);
    assert_eq!(summary.recipient.as_deref(), Some(b_id.as_str()));
    assert_eq!(summary.recipient_label.as_deref(), Some("peer"));
    assert_eq!(summary.transfer_id.len(), 16);
    let shared = summary.shared[0].clone();

    // Refuses to overwrite.
    assert!(matches!(
        export(&mut a, &first, None, None, Vec::new()),
        Response::Error { .. }
    ));

    // The transfer id the frames carried must match the bundle.
    let wrong = import(&mut b, &first, Some("0000000000000000".into()));
    assert!(
        matches!(wrong, Response::Error { ref message, .. } if message.contains("do not belong"))
    );
    let report = match import(&mut b, &first, Some(summary.transfer_id.clone())) {
        Response::QrImported { report } => report,
        Response::Error { message, .. } => panic!("{message}"),
        other => panic!("{}", other.kind()),
    };
    assert!(report.sender_trusted);
    assert!(!report.for_another_device);
    assert_eq!(report.adopted[0].vault_id, shared);
    assert_eq!(report.vaults[0].applied, 1);
    assert!(report.alarms.is_empty());

    // A delta with B's "what I have" code.
    add_item(&mut a, &shared, "AWS");
    let code = match call(
        &mut b.state,
        Request::QrHaveCode {
            profile: b.profile.clone(),
            vaults: Vec::new(),
        },
    ) {
        Response::QrHaveCode { code, vaults } => {
            assert_eq!(vaults, 2, "B's own vault and the shared one");
            code
        }
        other => panic!("{}", other.kind()),
    };
    let second = dir.path().join("second.lpqr");
    let summary = match export(&mut a, &second, Some(code), None, Vec::new()) {
        Response::QrExported { summary } => summary,
        Response::Error { message, .. } => panic!("{message}"),
        other => panic!("{}", other.kind()),
    };
    assert_eq!(summary.vaults.len(), 1);
    assert_eq!(summary.vaults[0].ops, 1);
    match import(&mut b, &second, None) {
        Response::QrImported { report } => assert_eq!(report.vaults[0].applied, 1),
        other => panic!("{}", other.kind()),
    }
}

#[test]
fn bad_files_and_codes_are_refused_with_plain_messages() {
    let mut a = device();
    let dir = tempfile::tempdir().unwrap();
    // A missing file.
    assert!(matches!(
        import(&mut a, &dir.path().join("nope.lpqr"), None),
        Response::Error { ref message, .. } if message.contains("could not read")
    ));
    // A file larger than any bundle is refused before it is read.
    let big = dir.path().join("big.lpqr");
    let f = std::fs::File::create(&big).unwrap();
    f.set_len(9 * 1024 * 1024).unwrap();
    drop(f);
    assert!(matches!(
        import(&mut a, &big, None),
        Response::Error { ref message, .. } if message.contains("larger than")
    ));
    // A malformed "what I have" code.
    assert!(matches!(
        export(
            &mut a,
            &dir.path().join("x.lpqr"),
            Some("LPHAVE1-00".into()),
            None,
            Vec::new()
        ),
        Response::Error { .. }
    ));
    // Sharing without naming the device.
    assert!(matches!(
        export(&mut a, &dir.path().join("y.lpqr"), None, None, vec!["personal".into()]),
        Response::Error { ref message, .. } if message.contains("needs the device")
    ));
}

#[test]
fn sharing_by_qr_needs_a_person_present_while_an_agent_is_connected() {
    let mut a = device();
    let mut b = device();
    trust(&mut a, &mut b);
    let (b_id, _, _) = identity(&mut b);
    // Something to send (before the agent connects: adding an item would then
    // need presence too).
    add_item(&mut a, "personal", "GitHub");
    let begun = engine::handle_with(
        &mut a.state,
        Request::BeginAgentSession {
            profile: a.profile.clone(),
        },
        &RequestContext::default(),
    );
    assert!(begun.began_agent_session);
    let dir = tempfile::tempdir().unwrap();

    // A plain export is a folder push: no password.
    let plain = export(
        &mut a,
        &dir.path().join("plain.lpqr"),
        None,
        None,
        Vec::new(),
    );
    assert!(
        matches!(plain, Response::QrExported { .. }),
        "{}",
        plain.kind()
    );

    // An export that carries a vault key is a share: refused without presence,
    // and nothing is written.
    let out = dir.path().join("share.lpqr");
    let shared = export(&mut a, &out, None, Some(b_id), vec!["personal".into()]);
    assert!(
        matches!(shared, Response::PresenceRequired { ref action } if action == "QrExport"),
        "{}",
        shared.kind()
    );
    assert!(!out.exists());
}
