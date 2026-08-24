//! Integration tests for **agent-triggered autofill** (`docs/specs/agent-fill.md`)
//! at the daemon layer.
//!
//! Drives [`engine::handle`] directly against fresh tempdir profiles, the same
//! way `device_sync.rs` does. What is under test is the half of the feature the
//! daemon owns:
//!
//! - the arm window (§7), including its **per-item scope** and its lapsing;
//! - the single-use fill intent and its independent 30-second TTL (§7);
//! - every refusal in the §10 taxonomy the daemon can produce, as a distinct
//!   code rather than one generic failure;
//! - the audit trail (§9), and the invariant that no planted secret value and no
//!   planted item title ever appears in it.
//!
//! The browser-side half (`tab_not_found`, `ambiguous_tab`, `origin_changed`,
//! `field_not_empty`, `no_login_form`) is the extension's to enforce; here it is
//! only checked that a reported failure reaches the audit log as an
//! `AccessDenied` with the right reason.

use std::time::Duration;

use lp_daemon::engine::{self, State};
use lp_daemon::protocol::{
    FieldState, FieldStates, FillField, FillRefusal, FillReport, FillStatus, Request, Response,
};

const PW: &str = "correct-horse-battery-agent-fill";
/// Planted on the login item; long and distinctive so a substring search over a
/// whole audit rendering is meaningful.
const PLANTED_PASSWORD: &str = "planted-agent-fill-password-7c1e94";
/// The item's title — also a secret as far as the plaintext audit log is
/// concerned (names are ciphertext everywhere else).
const ITEM_TITLE: &str = "PlantedAgentFillTitle";
const ORIGIN: &str = "https://example.com";

fn profile_str(p: &std::path::Path) -> String {
    p.display().to_string()
}

/// A fresh unlocked daemon state with one `login` item for `example.com`.
/// Returns the state, the profile dir (kept alive by the returned `TempDir`),
/// and the item's canonical hyphenated id.
fn fixture() -> (State, tempfile::TempDir, std::path::PathBuf, String) {
    let tmp = tempfile::tempdir().unwrap();
    let profile = tmp.path().to_path_buf();
    let mut state = State::new(profile.clone(), Duration::from_secs(600));
    let handled = engine::handle(
        &mut state,
        Request::CreateAccount {
            profile: profile_str(&profile),
            password: PW.into(),
        },
    );
    assert!(matches!(handled.response, Response::AccountCreated { .. }));

    let item_id = add_login(&mut state, &profile, ITEM_TITLE, ORIGIN, PLANTED_PASSWORD);
    (state, tmp, profile, item_id)
}

/// Create a `login` item and return its hyphenated id.
fn add_login(
    state: &mut State,
    profile: &std::path::Path,
    title: &str,
    url: &str,
    password: &str,
) -> String {
    let payload = serde_json::json!({
        "v": 1,
        "type": "login",
        "urls": [],
        "title": title,
        "notes": "",
        "tags": [],
        "favorite": false,
        "fields": [
            { "name": "username", "kind": "text",   "value": "alice" },
            { "name": "password", "kind": "hidden", "value": password },
            { "name": "url",      "kind": "url",    "value": url },
        ],
    });
    let handled = engine::handle(
        state,
        Request::CreateItem {
            profile: profile_str(profile),
            vault: "personal".into(),
            payload,
        },
    );
    match handled.response {
        Response::Ok { message: Some(id) } => id,
        other => panic!("expected the new item id, got {}", other.kind()),
    }
}

/// `SetAgentFillMode { on, item_ids }`.
fn set_mode(state: &mut State, profile: &std::path::Path, on: bool, items: &[&str]) -> Response {
    engine::handle(
        state,
        Request::SetAgentFillMode {
            profile: profile_str(profile),
            on,
            item_ids: items.iter().map(|s| (*s).to_string()).collect(),
        },
    )
    .response
}

/// `ArmFillIntent` for `item` on [`ORIGIN`].
fn arm(state: &mut State, profile: &std::path::Path, item: &str) -> Response {
    arm_on(state, profile, item, ORIGIN)
}

fn arm_on(state: &mut State, profile: &std::path::Path, item: &str, origin: &str) -> Response {
    engine::handle(
        state,
        Request::ArmFillIntent {
            profile: profile_str(profile),
            item_id: item.into(),
            tab_id: Some(42),
            origin: origin.into(),
            overwrite: false,
        },
    )
    .response
}

fn take(state: &mut State, profile: &std::path::Path) -> Response {
    engine::handle(
        state,
        Request::TakeFillIntent {
            profile: profile_str(profile),
        },
    )
    .response
}

fn poll(state: &mut State, profile: &std::path::Path) -> Response {
    engine::handle(
        state,
        Request::PollFillOutcome {
            profile: profile_str(profile),
        },
    )
    .response
}

/// The §10 code a refusal carries, or a panic naming what came back instead.
#[track_caller]
fn refusal(resp: &Response) -> FillRefusal {
    match resp {
        Response::FillRefused { reason } => *reason,
        other => panic!("expected a FillRefused, got {}", other.kind()),
    }
}

/// Every audit record on this device, rendered as one JSON string (the same
/// shape the Dev tab and `localpass audit --json` show).
fn audit_json(state: &mut State, profile: &std::path::Path) -> String {
    let handled = engine::handle(
        state,
        Request::AuditList {
            profile: profile_str(profile),
            limit: Some(500),
            since: None,
        },
    );
    match handled.response {
        Response::AuditRecords { records } => serde_json::to_string(&records).unwrap(),
        other => panic!("expected AuditRecords, got {}", other.kind()),
    }
}

/// The labels of every audit record, newest first.
fn audit_labels(state: &mut State, profile: &std::path::Path) -> Vec<String> {
    let json: serde_json::Value = serde_json::from_str(&audit_json(state, profile)).unwrap();
    json.as_array()
        .unwrap()
        .iter()
        .map(|r| r["kind"].as_str().unwrap().to_string())
        .collect()
}

// --- §10: refusals the daemon produces -----------------------------------

#[test]
fn arming_an_intent_without_an_armed_window_is_refused() {
    let (mut state, _tmp, profile, item_id) = fixture();
    assert_eq!(
        refusal(&arm(&mut state, &profile, &item_id)),
        FillRefusal::AgentFillNotArmed
    );
}

#[test]
fn an_item_outside_the_armed_set_is_refused_inside_an_open_window() {
    let (mut state, _tmp, profile, armed_id) = fixture();
    // A SECOND login item, on the same origin, deliberately left out of scope.
    let other_id = add_login(
        &mut state,
        &profile,
        "OtherSite",
        ORIGIN,
        "other-password-value",
    );
    assert!(matches!(
        set_mode(&mut state, &profile, true, &[&armed_id]),
        Response::Ok { .. }
    ));
    // The armed item works…
    assert!(matches!(
        arm(&mut state, &profile, &armed_id),
        Response::FillIntentArmed { .. }
    ));
    // …its neighbour does not, even though the window is wide open.
    assert_eq!(
        refusal(&arm(&mut state, &profile, &other_id)),
        FillRefusal::ItemNotArmed
    );
}

#[test]
fn an_unknown_item_and_an_ambiguous_title_get_distinct_codes() {
    let (mut state, _tmp, profile, item_id) = fixture();
    assert!(matches!(
        set_mode(&mut state, &profile, true, &[&item_id]),
        Response::Ok { .. }
    ));
    assert_eq!(
        refusal(&arm(&mut state, &profile, "no-such-item")),
        FillRefusal::ItemNotFound
    );

    // Two items sharing a title make the title ambiguous.
    add_login(&mut state, &profile, "Twin", ORIGIN, "twin-one-password");
    add_login(&mut state, &profile, "Twin", ORIGIN, "twin-two-password");
    assert_eq!(
        refusal(&arm(&mut state, &profile, "Twin")),
        FillRefusal::AmbiguousItem
    );
}

#[test]
fn an_origin_that_does_not_match_the_items_url_is_refused() {
    let (mut state, _tmp, profile, item_id) = fixture();
    assert!(matches!(
        set_mode(&mut state, &profile, true, &[&item_id]),
        Response::Ok { .. }
    ));
    // A different registrable domain…
    assert_eq!(
        refusal(&arm_on(
            &mut state,
            &profile,
            &item_id,
            "https://evil-example.com"
        )),
        FillRefusal::OriginMismatch
    );
    // …and an origin with no registrable domain at all.
    assert_eq!(
        refusal(&arm_on(&mut state, &profile, &item_id, "http://localhost")),
        FillRefusal::OriginMismatch
    );
}

#[test]
fn a_locked_daemon_refuses_every_agent_fill_request() {
    let (mut state, _tmp, profile, item_id) = fixture();
    assert!(matches!(
        set_mode(&mut state, &profile, true, &[&item_id]),
        Response::Ok { .. }
    ));
    engine::handle(&mut state, Request::Lock);

    for resp in [
        set_mode(&mut state, &profile, true, &[&item_id]),
        arm(&mut state, &profile, &item_id),
        take(&mut state, &profile),
        poll(&mut state, &profile),
    ] {
        assert!(
            matches!(resp, Response::Locked),
            "a locked daemon must refuse, got {}",
            resp.kind()
        );
    }

    // And locking dropped the window itself: unlocking again does not resurrect
    // it (the state is in memory and tied to the session).
    assert!(!state.agent_fill_active());
}

// --- §7: single use, TTL, window lapse ------------------------------------

#[test]
fn taking_an_intent_twice_fails_the_second_time() {
    let (mut state, _tmp, profile, item_id) = fixture();
    set_mode(&mut state, &profile, true, &[&item_id]);
    assert!(matches!(
        arm(&mut state, &profile, &item_id),
        Response::FillIntentArmed { .. }
    ));

    match take(&mut state, &profile) {
        Response::FillIntent {
            item_id: got,
            tab_id,
            origin,
            overwrite,
            ..
        } => {
            assert_eq!(got, item_id, "the intent names the canonical item id");
            assert_eq!(tab_id, Some(42));
            assert_eq!(origin, ORIGIN);
            assert!(!overwrite);
        }
        other => panic!("expected FillIntent, got {}", other.kind()),
    }
    assert!(
        matches!(take(&mut state, &profile), Response::NoFillIntent),
        "an intent is single use: the second take gets nothing"
    );
}

#[test]
fn arming_replaces_the_previous_unredeemed_intent() {
    let (mut state, _tmp, profile, first) = fixture();
    let second = add_login(&mut state, &profile, "Second", ORIGIN, "second-password");
    set_mode(&mut state, &profile, true, &[&first, &second]);
    arm(&mut state, &profile, &first);
    arm(&mut state, &profile, &second);
    match take(&mut state, &profile) {
        Response::FillIntent { item_id, .. } => {
            assert_eq!(item_id, second, "the newer arm replaced the older one");
        }
        other => panic!("expected FillIntent, got {}", other.kind()),
    }
    assert!(matches!(take(&mut state, &profile), Response::NoFillIntent));
}

#[test]
fn an_intent_lapses_on_its_own_ttl_inside_an_open_window() {
    let (mut state, _tmp, profile, item_id) = fixture();
    // A long window with a very short intent TTL isolates the two timers.
    state.set_agent_fill_timings(Duration::from_secs(300), Duration::from_millis(20));
    set_mode(&mut state, &profile, true, &[&item_id]);
    arm(&mut state, &profile, &item_id);

    std::thread::sleep(Duration::from_millis(60));

    assert!(
        state.agent_fill_active(),
        "the arm window is still wide open"
    );
    assert!(
        matches!(take(&mut state, &profile), Response::NoFillIntent),
        "a lapsed intent is not redeemable"
    );
    match poll(&mut state, &profile) {
        Response::FillOutcome { status, .. } => assert_eq!(status, FillStatus::Expired),
        other => panic!("expected FillOutcome, got {}", other.kind()),
    }
}

#[test]
fn the_arm_window_lapses_on_its_own_and_is_recorded() {
    let (mut state, _tmp, profile, item_id) = fixture();
    state.set_agent_fill_timings(Duration::from_millis(20), Duration::from_secs(30));
    set_mode(&mut state, &profile, true, &[&item_id]);
    assert!(state.agent_fill_active());

    std::thread::sleep(Duration::from_millis(60));
    assert!(!state.agent_fill_active());

    // A new intent inside the lapsed window is refused as "not armed"…
    assert_eq!(
        refusal(&arm(&mut state, &profile, &item_id)),
        FillRefusal::AgentFillNotArmed
    );
    // …and the lapse itself left a disarm record, so the log shows the window
    // closing as well as opening.
    let labels = audit_labels(&mut state, &profile);
    assert!(
        labels.iter().any(|l| l == "agent_fill_mode_disabled"),
        "the lapse must be recorded: {labels:?}"
    );
    assert!(labels.iter().any(|l| l == "agent_fill_mode_enabled"));
}

#[test]
fn status_reports_the_remaining_window() {
    let (mut state, _tmp, profile, item_id) = fixture();
    let status = |state: &mut State| match engine::handle(
        state,
        Request::Status {
            profile: profile_str(&profile),
            keepalive: false,
        },
    )
    .response
    {
        Response::Status {
            agent_fill_secs, ..
        } => agent_fill_secs,
        other => panic!("expected Status, got {}", other.kind()),
    };
    assert_eq!(status(&mut state), None, "off by default");
    set_mode(&mut state, &profile, true, &[&item_id]);
    let secs = status(&mut state).expect("armed");
    assert!(secs <= 180 && secs > 150, "a ~3 minute window, got {secs}");
    set_mode(&mut state, &profile, false, &[]);
    assert_eq!(status(&mut state), None, "off again");
}

#[test]
fn disarming_drops_an_unredeemed_intent() {
    let (mut state, _tmp, profile, item_id) = fixture();
    set_mode(&mut state, &profile, true, &[&item_id]);
    arm(&mut state, &profile, &item_id);
    set_mode(&mut state, &profile, false, &[]);
    assert!(matches!(take(&mut state, &profile), Response::NoFillIntent));
}

#[test]
fn arming_the_window_with_no_items_is_refused() {
    let (mut state, _tmp, profile, _item_id) = fixture();
    match set_mode(&mut state, &profile, true, &[]) {
        Response::Error { auth, message } => {
            assert!(!auth);
            assert!(message.contains("at least one item"), "{message}");
        }
        other => panic!("expected a usage error, got {}", other.kind()),
    }
    assert!(!state.agent_fill_active());
}

// --- §3/§9: the outcome round trip ---------------------------------------

#[test]
fn the_outcome_round_trip_carries_booleans_and_nothing_else() {
    let (mut state, _tmp, profile, item_id) = fixture();
    set_mode(&mut state, &profile, true, &[&item_id]);
    arm(&mut state, &profile, &item_id);
    assert!(matches!(
        poll(&mut state, &profile),
        Response::FillOutcome {
            status: FillStatus::Pending,
            ..
        }
    ));
    take(&mut state, &profile);
    assert!(matches!(
        poll(&mut state, &profile),
        Response::FillOutcome {
            status: FillStatus::Taken,
            ..
        }
    ));

    let report = FillReport {
        filled: true,
        fields: vec![FillField::Username, FillField::Password],
        before: FieldStates {
            username: Some(FieldState::Empty),
            password: Some(FieldState::Empty),
        },
        after: FieldStates {
            username: Some(FieldState::Filled),
            password: Some(FieldState::Filled),
        },
        reason: None,
    };
    let resp = engine::handle(
        &mut state,
        Request::ReportFillOutcome {
            profile: profile_str(&profile),
            item_id: item_id.clone(),
            outcome: report.clone(),
        },
    )
    .response;
    assert!(matches!(resp, Response::Ok { .. }));

    match poll(&mut state, &profile) {
        Response::FillOutcome {
            status,
            item_id: got,
            tab_id,
            origin,
            report: back,
        } => {
            assert_eq!(status, FillStatus::Reported);
            assert_eq!(got.as_deref(), Some(item_id.as_str()));
            // The tab and origin are echoed from the intent the DAEMON armed,
            // never from the extension's report.
            assert_eq!(tab_id, Some(42));
            assert_eq!(origin.as_deref(), Some(ORIGIN));
            assert_eq!(back, Some(report));
        }
        other => panic!("expected FillOutcome, got {}", other.kind()),
    }
}

#[test]
fn an_outcome_for_an_untaken_or_unknown_intent_is_rejected() {
    let (mut state, _tmp, profile, item_id) = fixture();
    set_mode(&mut state, &profile, true, &[&item_id]);
    arm(&mut state, &profile, &item_id);
    let report = FillReport {
        filled: true,
        fields: vec![FillField::Password],
        before: FieldStates::default(),
        after: FieldStates::default(),
        reason: None,
    };
    // Not taken yet.
    let resp = engine::handle(
        &mut state,
        Request::ReportFillOutcome {
            profile: profile_str(&profile),
            item_id: item_id.clone(),
            outcome: report.clone(),
        },
    )
    .response;
    assert!(matches!(resp, Response::Error { auth: false, .. }));

    // Taken, but the report names a different item.
    take(&mut state, &profile);
    let resp = engine::handle(
        &mut state,
        Request::ReportFillOutcome {
            profile: profile_str(&profile),
            item_id: "00000000-0000-0000-0000-000000000000".into(),
            outcome: report,
        },
    )
    .response;
    assert!(matches!(resp, Response::Error { auth: false, .. }));
}

#[test]
fn an_extension_side_failure_reaches_the_audit_log_as_its_own_reason() {
    let (mut state, _tmp, profile, item_id) = fixture();
    set_mode(&mut state, &profile, true, &[&item_id]);
    arm(&mut state, &profile, &item_id);
    take(&mut state, &profile);
    engine::handle(
        &mut state,
        Request::ReportFillOutcome {
            profile: profile_str(&profile),
            item_id: item_id.clone(),
            outcome: FillReport {
                filled: false,
                fields: vec![FillField::Password],
                before: FieldStates {
                    username: Some(FieldState::Empty),
                    password: Some(FieldState::Filled),
                },
                after: FieldStates {
                    username: Some(FieldState::Empty),
                    password: Some(FieldState::Filled),
                },
                reason: Some(FillRefusal::FieldNotEmpty),
            },
        },
    );
    let json = audit_json(&mut state, &profile);
    assert!(
        json.contains("field_not_empty"),
        "the extension's refusal reason must reach the log: {json}"
    );
}

// --- §9: the audit trail, and what must never be in it --------------------

#[test]
fn arming_and_refusals_are_audited_without_a_value_or_a_title() {
    let (mut state, _tmp, profile, item_id) = fixture();

    // A refusal before the window is open…
    arm(&mut state, &profile, &item_id);
    // …then a real arm, a take, and a couple more refusals.
    set_mode(&mut state, &profile, true, &[&item_id]);
    arm(&mut state, &profile, &item_id);
    take(&mut state, &profile);
    arm_on(&mut state, &profile, &item_id, "https://evil-example.com");
    set_mode(&mut state, &profile, false, &[]);

    let labels = audit_labels(&mut state, &profile);
    assert!(labels.iter().any(|l| l == "agent_fill_mode_enabled"));
    assert!(labels.iter().any(|l| l == "agent_fill_mode_disabled"));
    assert!(
        labels.iter().filter(|l| *l == "access_denied").count() >= 2,
        "both refusals are audited: {labels:?}"
    );

    let json = audit_json(&mut state, &profile);
    assert!(json.contains("agent_fill_not_armed"), "{json}");
    assert!(json.contains("origin_mismatch"), "{json}");

    // THE invariant: the plaintext audit log never carries a secret VALUE, and
    // never an item TITLE (titles are ciphertext everywhere else).
    assert!(
        !json.contains(PLANTED_PASSWORD),
        "a secret value reached the audit log"
    );
    assert!(
        !json.contains(ITEM_TITLE),
        "an item title reached the audit log"
    );
}

#[test]
fn the_human_fill_path_is_untouched_by_the_arm_window() {
    let (mut state, _tmp, profile, item_id) = fixture();
    // Agent fill is OFF. The popup path — MatchLogins then FillLogin, both
    // behind the user's click — must work exactly as before (§12 non-goal: no
    // change to the human flow).
    assert!(!state.agent_fill_active());
    let resp = engine::handle(
        &mut state,
        Request::MatchLogins {
            profile: profile_str(&profile),
            origin: ORIGIN.into(),
        },
    )
    .response;
    match resp {
        Response::LoginCandidates { candidates } => {
            assert!(candidates.iter().any(|c| c.item_id == item_id));
        }
        other => panic!("expected LoginCandidates, got {}", other.kind()),
    }
    let resp = engine::handle(
        &mut state,
        Request::FillLogin {
            profile: profile_str(&profile),
            item_id: item_id.clone(),
            origin: ORIGIN.into(),
        },
    )
    .response;
    match resp {
        Response::Fill { password, .. } => assert_eq!(password, PLANTED_PASSWORD),
        other => panic!("expected Fill, got {}", other.kind()),
    }
}
