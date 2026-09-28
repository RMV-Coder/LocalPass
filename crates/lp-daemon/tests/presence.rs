//! Integration tests for the **human-presence check** (`mcp-server.md` §7).
//!
//! While an AI agent holds a session with the daemon, consent and change
//! requests need a person to have re-entered the master password. Most tests
//! drive [`engine::handle_with`] directly, passing the per-connection context
//! the server would; the last one runs the real server loop to show that the
//! session is bound to the agent's connection and ends when it closes.

use std::sync::Mutex;
use std::time::Duration;

use lp_daemon::client::Client;
use lp_daemon::engine::{self, RequestContext, State};
use lp_daemon::protocol::{MAX_PRESENCE_FAILURES, PRESENCE_GRANT_SECS, Request, Response};
use lp_daemon::server::{self, Config};

const PW: &str = "correct-horse-battery-presence";

fn profile_str(p: &std::path::Path) -> String {
    p.display().to_string()
}

/// A fresh unlocked daemon state with one login item titled `Seed`.
fn fixture() -> (State, tempfile::TempDir, String) {
    let tmp = tempfile::tempdir().unwrap();
    let profile = profile_str(tmp.path());
    let mut state = State::new(tmp.path().to_path_buf(), Duration::from_secs(600));
    let created = engine::handle(
        &mut state,
        Request::CreateAccount {
            profile: profile.clone(),
            password: PW.into(),
        },
    );
    assert!(matches!(created.response, Response::AccountCreated { .. }));
    let seeded = engine::handle(&mut state, create_item(&profile, "Seed"));
    assert!(matches!(seeded.response, Response::Ok { .. }));
    (state, tmp, profile)
}

fn create_item(profile: &str, title: &str) -> Request {
    Request::CreateItem {
        profile: profile.into(),
        vault: "personal".into(),
        payload: serde_json::json!({
            "v": 1,
            "type": "login",
            "urls": [],
            "title": title,
            "notes": "",
            "tags": [],
            "favorite": false,
            "fields": [
                { "name": "username", "kind": "text",   "value": "alice" },
                { "name": "password", "kind": "hidden", "value": "pw-value-123" },
            ],
        }),
    }
}

/// What the server passes for a request from an ordinary (non-agent)
/// connection, optionally carrying a grant.
fn person(grant: Option<&str>) -> RequestContext {
    RequestContext {
        agent_connection: false,
        presence_grant: grant.map(str::to_string),
    }
}

/// What the server passes for a request on the agent's own connection.
fn agent_conn(grant: Option<&str>) -> RequestContext {
    RequestContext {
        agent_connection: true,
        presence_grant: grant.map(str::to_string),
    }
}

/// Open an agent session the way the MCP server does.
fn begin_agent(state: &mut State, profile: &str) {
    let h = engine::handle_with(
        state,
        Request::BeginAgentSession {
            profile: profile.into(),
        },
        &person(None),
    );
    assert!(h.began_agent_session);
    assert!(matches!(h.response, Response::Ok { .. }));
}

fn confirm(state: &mut State, profile: &str, password: &str) -> Response {
    engine::handle_with(
        state,
        Request::ConfirmPresence {
            profile: profile.into(),
            password: password.into(),
        },
        &person(None),
    )
    .response
}

fn grant_token(response: Response) -> String {
    match response {
        Response::PresenceGrant {
            token,
            expires_in_secs,
        } => {
            assert_eq!(expires_in_secs, PRESENCE_GRANT_SECS);
            assert_eq!(token.len(), 64);
            token
        }
        other => panic!("expected a PresenceGrant, got {}", other.kind()),
    }
}

fn item_count(state: &mut State, profile: &str) -> usize {
    match engine::handle(
        state,
        Request::ListItems {
            profile: profile.into(),
            vault: "personal".into(),
        },
    )
    .response
    {
        Response::Items { items } => items.len(),
        other => panic!("expected Items, got {}", other.kind()),
    }
}

fn deny_reasons(state: &mut State, profile: &str) -> Vec<String> {
    match engine::handle(
        state,
        Request::AuditList {
            profile: profile.into(),
            limit: Some(500),
            since: None,
        },
    )
    .response
    {
        Response::AuditRecords { records } => {
            records.into_iter().filter_map(|r| r.deny_reason).collect()
        }
        other => panic!("expected AuditRecords, got {}", other.kind()),
    }
}

fn is_presence_required(response: &Response, action: &str) -> bool {
    matches!(response, Response::PresenceRequired { action: a } if a == action)
}

// --- no agent session: nothing changes ------------------------------------

#[test]
fn without_an_agent_session_changes_need_no_password() {
    let (mut state, _tmp, profile) = fixture();
    let h = engine::handle_with(&mut state, create_item(&profile, "Free"), &person(None));
    assert!(matches!(h.response, Response::Ok { .. }));
    assert_eq!(item_count(&mut state, &profile), 2);
}

// --- with an agent session ------------------------------------------------

#[test]
fn a_change_needs_presence_is_refused_audited_and_changes_nothing() {
    let (mut state, _tmp, profile) = fixture();
    begin_agent(&mut state, &profile);

    let h = engine::handle_with(&mut state, create_item(&profile, "Blocked"), &person(None));
    assert!(is_presence_required(&h.response, "CreateItem"));
    assert_eq!(item_count(&mut state, &profile), 1, "nothing was created");
    assert!(deny_reasons(&mut state, &profile).contains(&"presence_required".to_string()));

    for request in [
        Request::DeleteItem {
            profile: profile.clone(),
            vault: "personal".into(),
            target: "Seed".into(),
        },
        Request::DeleteVault {
            profile: profile.clone(),
            vault: "personal".into(),
        },
        Request::CreateVault {
            profile: profile.clone(),
            name: "work".into(),
        },
        Request::SetPairingMode {
            profile: profile.clone(),
            enabled: true,
        },
    ] {
        let kind = request.kind();
        let h = engine::handle_with(&mut state, request, &person(None));
        assert!(
            is_presence_required(&h.response, kind),
            "{kind} must need presence"
        );
    }
}

#[test]
fn reads_and_switching_consent_off_stay_open_during_an_agent_session() {
    let (mut state, _tmp, profile) = fixture();
    begin_agent(&mut state, &profile);

    assert_eq!(item_count(&mut state, &profile), 1);
    let got = engine::handle_with(
        &mut state,
        Request::GetItem {
            profile: profile.clone(),
            vault: "personal".into(),
            target: "Seed".into(),
            version: None,
            reveal: false,
        },
        &agent_conn(None),
    );
    assert!(matches!(got.response, Response::Item { .. }));

    for request in [
        Request::SetPairingMode {
            profile: profile.clone(),
            enabled: false,
        },
        Request::SetAgentFillMode {
            profile: profile.clone(),
            on: false,
            item_ids: vec![],
            vault: None,
        },
    ] {
        let h = engine::handle_with(&mut state, request, &agent_conn(None));
        assert!(
            matches!(h.response, Response::Ok { .. }),
            "narrowing must never need a password, got {}",
            h.response.kind()
        );
    }
}

#[test]
fn a_confirmed_person_gets_a_grant_that_lets_the_change_through() {
    let (mut state, _tmp, profile) = fixture();
    begin_agent(&mut state, &profile);

    let token = grant_token(confirm(&mut state, &profile, PW));
    let h = engine::handle_with(
        &mut state,
        create_item(&profile, "Approved"),
        &person(Some(&token)),
    );
    assert!(
        matches!(h.response, Response::Ok { .. }),
        "{}",
        h.response.kind()
    );
    assert_eq!(item_count(&mut state, &profile), 2);

    // The grant is reusable until it expires, not single-use.
    let again = engine::handle_with(
        &mut state,
        create_item(&profile, "Approved2"),
        &person(Some(&token)),
    );
    assert!(matches!(again.response, Response::Ok { .. }));
}

#[test]
fn a_wrong_or_forged_grant_is_refused() {
    let (mut state, _tmp, profile) = fixture();
    begin_agent(&mut state, &profile);
    let real = grant_token(confirm(&mut state, &profile, PW));

    let mut flipped = real.clone().into_bytes();
    flipped[0] = if flipped[0] == b'0' { b'1' } else { b'0' };
    let flipped = String::from_utf8(flipped).unwrap();
    for forged in ["", "not-hex", &"0".repeat(64), &flipped, &real[..62]] {
        let h = engine::handle_with(
            &mut state,
            create_item(&profile, "Forged"),
            &person(Some(forged)),
        );
        assert!(
            is_presence_required(&h.response, "CreateItem"),
            "{forged:?}"
        );
    }
    assert_eq!(item_count(&mut state, &profile), 1);
}

#[test]
fn the_agent_connection_can_neither_confirm_nor_use_a_grant() {
    let (mut state, _tmp, profile) = fixture();
    begin_agent(&mut state, &profile);

    let from_agent = engine::handle_with(
        &mut state,
        Request::ConfirmPresence {
            profile: profile.clone(),
            password: PW.into(),
        },
        &agent_conn(None),
    );
    assert!(matches!(
        from_agent.response,
        Response::Error { auth: false, .. }
    ));

    // Even a real grant, obtained by a person elsewhere, does not help a
    // request that arrives on the agent's own connection.
    let token = grant_token(confirm(&mut state, &profile, PW));
    let h = engine::handle_with(
        &mut state,
        create_item(&profile, "ViaAgent"),
        &agent_conn(Some(&token)),
    );
    assert!(is_presence_required(&h.response, "CreateItem"));
}

#[test]
fn wrong_passwords_are_refused_and_too_many_lock_the_vault() {
    let (mut state, _tmp, profile) = fixture();
    begin_agent(&mut state, &profile);

    for attempt in 1..MAX_PRESENCE_FAILURES {
        let r = confirm(&mut state, &profile, "wrong");
        assert!(
            matches!(r, Response::Error { auth: true, .. }),
            "attempt {attempt}"
        );
        assert!(state.is_unlocked(), "still unlocked after {attempt} misses");
    }
    // A right answer resets the count...
    grant_token(confirm(&mut state, &profile, PW));
    for _ in 1..MAX_PRESENCE_FAILURES {
        confirm(&mut state, &profile, "wrong");
    }
    assert!(state.is_unlocked());
    // ...and the last allowed miss locks.
    let last = confirm(&mut state, &profile, "wrong");
    assert!(matches!(last, Response::Error { auth: true, .. }));
    assert!(!state.is_unlocked(), "the vault must lock");
    assert!(
        deny_reasons_after_unlock(&mut state, &profile)
            .iter()
            .filter(|r| *r == "not_authorized")
            .count()
            >= usize::try_from(MAX_PRESENCE_FAILURES).unwrap(),
        "every wrong password is audited"
    );
}

fn deny_reasons_after_unlock(state: &mut State, profile: &str) -> Vec<String> {
    let h = engine::handle(
        state,
        Request::Unlock {
            profile: profile.into(),
            password: PW.into(),
            secret_key: None,
            autolock_secs: None,
        },
    );
    assert!(matches!(h.response, Response::Ok { .. }));
    deny_reasons(state, profile)
}

#[test]
fn a_grant_expires_and_does_not_survive_a_lock() {
    let (mut state, _tmp, profile) = fixture();
    begin_agent(&mut state, &profile);

    state.set_presence_ttl(Duration::from_millis(50));
    let short = match confirm(&mut state, &profile, PW) {
        Response::PresenceGrant { token, .. } => token,
        other => panic!("expected a grant, got {}", other.kind()),
    };
    std::thread::sleep(Duration::from_millis(120));
    let h = engine::handle_with(
        &mut state,
        create_item(&profile, "Late"),
        &person(Some(&short)),
    );
    assert!(
        is_presence_required(&h.response, "CreateItem"),
        "an expired grant must not count"
    );

    state.set_presence_ttl(Duration::from_secs(PRESENCE_GRANT_SECS));
    let token = grant_token(confirm(&mut state, &profile, PW));
    engine::handle(&mut state, Request::Lock);
    deny_reasons_after_unlock(&mut state, &profile);
    let h = engine::handle_with(
        &mut state,
        create_item(&profile, "AfterLock"),
        &person(Some(&token)),
    );
    assert!(
        is_presence_required(&h.response, "CreateItem"),
        "a grant is for one unlock only"
    );
}

#[test]
fn a_locked_daemon_answers_locked_not_presence_required() {
    let (mut state, _tmp, profile) = fixture();
    begin_agent(&mut state, &profile);
    engine::handle(&mut state, Request::Lock);
    let h = engine::handle_with(&mut state, create_item(&profile, "X"), &person(None));
    assert!(matches!(h.response, Response::Locked));
    assert!(matches!(
        confirm(&mut state, &profile, PW),
        Response::Locked
    ));
}

#[test]
fn status_reports_the_session_and_ending_it_lifts_the_check() {
    let (mut state, _tmp, profile) = fixture();
    let status = |state: &mut State| match engine::handle(
        state,
        Request::Status {
            profile: profile.clone(),
            keepalive: false,
        },
    )
    .response
    {
        Response::Status { agent_session, .. } => agent_session,
        other => panic!("expected Status, got {}", other.kind()),
    };
    assert!(!status(&mut state));

    begin_agent(&mut state, &profile);
    // A repeat on the SAME connection (the server passes agent_connection =
    // true once registered) must not add a second count.
    let repeat = engine::handle_with(
        &mut state,
        Request::BeginAgentSession {
            profile: profile.clone(),
        },
        &agent_conn(None),
    );
    assert!(repeat.began_agent_session);
    assert!(status(&mut state));

    state.end_agent_session();
    assert!(!status(&mut state), "one connection, one count");
    let h = engine::handle_with(&mut state, create_item(&profile, "Free"), &person(None));
    assert!(matches!(h.response, Response::Ok { .. }));
}

// --- the real server: the session is bound to the agent's connection -----

/// Serializes the server test's process-global env and presence-grant use.
static ENV_LOCK: Mutex<()> = Mutex::new(());

fn point_client_at(username: &str) {
    // `Client::connect` resolves the endpoint from the current username.
    unsafe {
        std::env::set_var("USERNAME", username);
        std::env::set_var("USER", username);
    }
}

#[test]
fn closing_the_agent_connection_ends_the_session() {
    let _env = ENV_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let username = format!("lpsrv-presence-{}", std::process::id());
    let tmp = tempfile::tempdir().unwrap();
    let profile = profile_str(tmp.path());
    let cfg = Config {
        profile: tmp.path().to_path_buf(),
        autolock: Duration::from_secs(600),
        username: username.clone(),
        verbose: false,
        no_ssh_agent: true,
    };
    let server_thread = std::thread::spawn(move || server::run(cfg));
    point_client_at(&username);
    lp_daemon::client::wait_until_ready(Duration::from_secs(5)).expect("server up");

    let call = |request: &Request| Client::connect().unwrap().call(request).unwrap();
    let agent_active = || match call(&Request::Status {
        profile: profile.clone(),
        keepalive: false,
    }) {
        Response::Status { agent_session, .. } => agent_session,
        other => panic!("expected Status, got {}", other.kind()),
    };

    assert!(matches!(
        call(&Request::CreateAccount {
            profile: profile.clone(),
            password: PW.into(),
        }),
        Response::AccountCreated { .. }
    ));

    // The agent's long-lived connection.
    let mut agent = Client::connect().unwrap();
    assert!(matches!(
        agent
            .call(&Request::BeginAgentSession {
                profile: profile.clone(),
            })
            .unwrap(),
        Response::Ok { .. }
    ));
    assert!(agent_active());
    assert!(is_presence_required(
        &call(&create_item(&profile, "Blocked")),
        "CreateItem"
    ));

    // A person confirms on their own connection; the grant rides on later
    // requests from this process automatically.
    let mut person = Client::connect().unwrap();
    let r = lp_daemon::presence::confirm(&mut person, &profile, PW).unwrap();
    assert!(matches!(r, Response::PresenceGrant { .. }));
    assert!(matches!(
        call(&create_item(&profile, "Approved")),
        Response::Ok { .. }
    ));
    lp_daemon::presence::clear_grant();
    assert!(is_presence_required(
        &call(&create_item(&profile, "Blocked2")),
        "CreateItem"
    ));

    // The agent goes away: its session ends with its connection.
    drop(agent);
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    while agent_active() {
        assert!(
            std::time::Instant::now() < deadline,
            "the session never ended"
        );
        std::thread::sleep(Duration::from_millis(20));
    }
    assert!(matches!(
        call(&create_item(&profile, "Free")),
        Response::Ok { .. }
    ));

    call(&Request::Shutdown);
    server_thread.join().unwrap().unwrap();
}
