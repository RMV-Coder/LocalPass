//! The daemon's "Sync with a nearby device" requests (`lan-transport.md` §9.1),
//! driven against two in-process daemon `State`s the way the server drives
//! them: handle under the mutex, then run the deferred network job with the
//! mutex released.

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use lp_daemon::engine::{self, RequestContext, State};
use lp_daemon::nearby;
use lp_daemon::protocol::{Request, Response, WireNearbyOutcome};
use lp_vault::payload::{ItemPayload, TypeData};

const PW: &str = "correct-horse-battery-nearby";

struct Dev {
    state: Arc<Mutex<State>>,
    profile: String,
    _dir: tempfile::TempDir,
}

/// Handle `req` like the server does: under the lock, then any deferred job
/// with the lock released.
fn call_with(dev: &Dev, req: Request, ctx: &RequestContext) -> Response {
    let handled = {
        let mut st = dev.state.lock().unwrap();
        engine::handle_with(&mut st, req, ctx)
    };
    match handled.deferred {
        Some(job) => nearby::run_deferred(Arc::clone(&dev.state), job).unwrap_or(handled.response),
        None => handled.response,
    }
}

fn call(dev: &Dev, req: Request) -> Response {
    call_with(dev, req, &RequestContext::default())
}

fn device() -> Dev {
    let dir = tempfile::tempdir().unwrap();
    let profile = dir.path().display().to_string();
    let dev = Dev {
        state: Arc::new(Mutex::new(State::new(
            dir.path().to_path_buf(),
            Duration::ZERO,
        ))),
        profile,
        _dir: dir,
    };
    let r = call(
        &dev,
        Request::CreateAccount {
            profile: dev.profile.clone(),
            password: PW.into(),
        },
    );
    assert!(matches!(r, Response::AccountCreated { .. }), "{}", r.kind());
    dev
}

fn identity(dev: &Dev) -> (String, String, String) {
    match call(
        dev,
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

/// `a` trusts `b` through the real pairing-mode + fingerprint ceremony.
fn trust(a: &Dev, b: &Dev) {
    let (_, identity_string, fingerprint) = identity(b);
    assert!(matches!(
        call(
            a,
            Request::SetPairingMode {
                profile: a.profile.clone(),
                enabled: true,
            }
        ),
        Response::Ok { .. }
    ));
    let r = call(
        a,
        Request::TrustDevice {
            profile: a.profile.clone(),
            identity_string,
            expected_fingerprint: fingerprint,
            label: Some("peer".into()),
        },
    );
    assert!(matches!(r, Response::PeerTrusted { .. }), "{}", r.kind());
}

fn listen(dev: &Dev, peer: Option<String>, share: Vec<String>, timeout_secs: u64) -> u16 {
    match call(
        dev,
        Request::NearbyListen {
            profile: dev.profile.clone(),
            bind: Some("127.0.0.1".into()),
            port: Some(0),
            timeout_secs: Some(timeout_secs),
            peer,
            share,
        },
    ) {
        Response::NearbyListening {
            port, addresses, ..
        } => {
            assert_eq!(addresses, vec![format!("127.0.0.1:{port}")]);
            port
        }
        Response::Error { message, .. } => panic!("{message}"),
        other => panic!("{}", other.kind()),
    }
}

fn status(dev: &Dev) -> (bool, Option<WireNearbyOutcome>) {
    match call(
        dev,
        Request::NearbyStatus {
            profile: dev.profile.clone(),
        },
    ) {
        Response::NearbyStatus {
            listening, last, ..
        } => (listening, last),
        other => panic!("{}", other.kind()),
    }
}

/// Wait until the listener reports a finished window.
fn wait_for_outcome(dev: &Dev) -> WireNearbyOutcome {
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        if let (false, Some(last)) = status(dev) {
            return last;
        }
        assert!(Instant::now() < deadline, "the listen window never closed");
        std::thread::sleep(Duration::from_millis(50));
    }
}

fn audit_kinds(dev: &Dev) -> Vec<String> {
    match call(
        dev,
        Request::AuditList {
            profile: dev.profile.clone(),
            limit: None,
            since: None,
        },
    ) {
        Response::AuditRecords { records } => records.into_iter().map(|r| r.kind).collect(),
        other => panic!("{}", other.kind()),
    }
}

#[test]
fn listen_then_connect_shares_and_syncs_a_vault() {
    let a = device();
    let b = device();
    trust(&a, &b);
    trust(&b, &a);
    let (b_id, _, _) = identity(&b);

    // A's vault with one item.
    let vault_id = {
        let st = a.state.lock().unwrap();
        let s = st.session_ref().unwrap();
        let v = s.create_vault("shared").unwrap();
        let mut p = ItemPayload::new(TypeData::Login { urls: vec![] }, "GitHub");
        p.fields.push(lp_vault::Field {
            name: "password".into(),
            kind: lp_vault::FieldKind::Hidden,
            value: "hunter2".into(),
        });
        s.open_vault(v).unwrap().create_item(&p).unwrap();
        v
    };

    // B opens the window; it reports itself listening.
    let port = listen(&b, None, Vec::new(), 30);
    assert!(status(&b).0);

    // A dials with a share for B. The request blocks until the session ends.
    let r = call(
        &a,
        Request::NearbyConnect {
            profile: a.profile.clone(),
            addr: format!("127.0.0.1:{port}"),
            peer: Some(b_id.clone()),
            share: vec!["shared".into()],
        },
    );
    let Response::NearbySynced { report } = r else {
        panic!("{}", r.kind())
    };
    assert_eq!(report.peer_device_id, b_id);
    assert_eq!(report.shared, vec![vault_id.to_hyphenated()]);
    assert!(report.alarms.is_empty(), "{:?}", report.alarms);
    assert_eq!(report.vaults.len(), 1);
    assert_eq!(report.vaults[0].ops_sent, 1);

    // B's window closed after its one session, with a report.
    let outcome = wait_for_outcome(&b);
    assert_eq!(outcome.result, "synced", "{:?}", outcome.error);
    let rb = outcome.report.unwrap();
    assert_eq!(rb.adopted.len(), 1);
    assert_eq!(rb.vaults[0].applied, 1);
    {
        let st = b.state.lock().unwrap();
        let s = st.session_ref().unwrap();
        let items = s.open_vault(vault_id).unwrap().list_items().unwrap();
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].payload.title, "GitHub");
    }

    // Audited on both sides.
    let kinds_b = audit_kinds(&b);
    for k in [
        "nearby_listen_enabled",
        "nearby_sync",
        "nearby_listen_disabled",
    ] {
        assert!(
            kinds_b.iter().any(|x| x == k),
            "{k} missing from {kinds_b:?}"
        );
    }
    let kinds_a = audit_kinds(&a);
    assert!(kinds_a.iter().any(|x| x == "nearby_sync"));
    assert!(kinds_a.iter().any(|x| x == "vault_share"));
}

#[test]
fn stop_and_lock_close_the_window() {
    let a = device();
    listen(&a, None, Vec::new(), 60);
    assert!(status(&a).0);
    assert!(matches!(
        call(
            &a,
            Request::NearbyStop {
                profile: a.profile.clone()
            }
        ),
        Response::Ok { .. }
    ));
    assert_eq!(wait_for_outcome(&a).result, "stopped");

    // A second window, then the vault locks: the window closes with it.
    let port = listen(&a, None, Vec::new(), 60);
    a.state.lock().unwrap().lock();
    let deadline = Instant::now() + Duration::from_secs(10);
    // The listener releases the port once it notices.
    loop {
        if std::net::TcpListener::bind(("127.0.0.1", port)).is_ok() {
            break;
        }
        assert!(Instant::now() < deadline, "the listener outlived the lock");
        std::thread::sleep(Duration::from_millis(50));
    }
    assert!(matches!(
        call(
            &a,
            Request::NearbyStatus {
                profile: a.profile.clone()
            }
        ),
        Response::Locked
    ));
}

#[test]
fn requests_are_validated_before_anything_touches_the_network() {
    let a = device();
    let usage = |r: Response| match r {
        Response::Error {
            auth: false,
            message,
        } => message,
        other => panic!("expected a usage error, got {}", other.kind()),
    };
    // A public address is refused before dialing; so is a host name.
    let m = usage(call(
        &a,
        Request::NearbyConnect {
            profile: a.profile.clone(),
            addr: "8.8.8.8:47823".into(),
            peer: None,
            share: Vec::new(),
        },
    ));
    assert!(m.contains("not a local-network address"), "{m}");
    let m = usage(call(
        &a,
        Request::NearbyConnect {
            profile: a.profile.clone(),
            addr: "laptop.example.com".into(),
            peer: None,
            share: Vec::new(),
        },
    ));
    assert!(m.contains("not an IP address"), "{m}");
    // Sharing needs a named, trusted peer.
    {
        let st = a.state.lock().unwrap();
        st.session_ref().unwrap().create_vault("v").unwrap();
    }
    let m = usage(call(
        &a,
        Request::NearbyListen {
            profile: a.profile.clone(),
            bind: Some("127.0.0.1".into()),
            port: Some(0),
            timeout_secs: None,
            peer: None,
            share: vec!["v".into()],
        },
    ));
    assert!(m.contains("needs the device it is for"), "{m}");
    let m = usage(call(
        &a,
        Request::NearbyListen {
            profile: a.profile.clone(),
            bind: Some("127.0.0.1".into()),
            port: Some(0),
            timeout_secs: None,
            peer: Some(lp_vault::Id::new().to_hyphenated()),
            share: Vec::new(),
        },
    ));
    assert!(m.contains("not trusted"), "{m}");
    // Binding a public interface is refused.
    let m = usage(call(
        &a,
        Request::NearbyListen {
            profile: a.profile.clone(),
            bind: Some("8.8.8.8".into()),
            port: Some(0),
            timeout_secs: None,
            peer: None,
            share: Vec::new(),
        },
    ));
    assert!(m.contains("local-network address"), "{m}");
    // Nothing is listening after all that.
    assert!(!status(&a).0);
}

#[test]
fn an_ai_agent_cannot_open_the_window_without_a_person() {
    let a = device();
    let agent = RequestContext {
        agent_connection: true,
        presence_grant: None,
    };
    assert!(matches!(
        call_with(
            &a,
            Request::BeginAgentSession {
                profile: a.profile.clone()
            },
            &RequestContext::default()
        ),
        Response::Ok { .. }
    ));
    let r = call_with(
        &a,
        Request::NearbyListen {
            profile: a.profile.clone(),
            bind: Some("127.0.0.1".into()),
            port: Some(0),
            timeout_secs: None,
            peer: None,
            share: Vec::new(),
        },
        &agent,
    );
    assert!(
        matches!(r, Response::PresenceRequired { .. }),
        "{}",
        r.kind()
    );
    assert!(!status(&a).0);
}

#[test]
fn old_clients_frames_still_decode_with_defaults() {
    // A minimal NearbyListen frame (no optional fields) decodes with every
    // default in place — the serde-default compatibility promise.
    let req: Request = serde_json::from_str(r#"{"kind":"NearbyListen","profile":"/p"}"#).unwrap();
    match req {
        Request::NearbyListen {
            bind,
            port,
            timeout_secs,
            peer,
            share,
            ..
        } => {
            assert!(bind.is_none() && port.is_none() && timeout_secs.is_none());
            assert!(peer.is_none() && share.is_empty());
        }
        _ => panic!("wrong variant"),
    }
    let resp: Response =
        serde_json::from_str(r#"{"kind":"NearbyStatus","listening":false}"#).unwrap();
    assert!(matches!(
        resp,
        Response::NearbyStatus {
            listening: false,
            last: None,
            ..
        }
    ));
}
