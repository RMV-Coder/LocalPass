//! Daemon-proxy audit test (PRD §4.9): drive the real server loop and prove that
//! proxied actions record their audit events **exactly once** — the daemon holds
//! the session, so the daemon records; the client does not (no double-logging).
//!
//! We unlock the daemon, then over the IPC channel: reveal an item (`GetItem`
//! with `reveal = true`), resolve a field (`ResolveField`), and compute a TOTP
//! (`Totp`). Then we read the account store's plaintext `audit_log` table
//! directly and assert exactly one record per action (plus the single
//! `UnlockSuccess`), and that no secret value landed in the log.
//!
//! Like the sibling in-process server tests, this holds [`ENV_LOCK`] for its
//! whole body (it mutates the process-global `USERNAME`/`USER` env that
//! `Client::connect` reads) and binds a unique endpoint.

use std::sync::Mutex;
use std::time::{Duration, Instant};

use lp_daemon::client::Client;
use lp_daemon::protocol::{Request, Response};
use lp_daemon::server::{self, Config};

/// Serializes this binary's tests (process-global endpoint env).
static ENV_LOCK: Mutex<()> = Mutex::new(());

const TEST_PASSWORD: &str = "correct-horse-battery";
const RFC_SEED_B32: &str = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
const SECRET_PW: &str = "sup3r-s3cr3t-proxy-pw";

fn unique_user(tag: &str) -> String {
    format!("lpaudit-{tag}-{}", std::process::id())
}

/// Kind codes mirror `lp_vault::audit::AuditKind::code()`.
const KIND_UNLOCK_SUCCESS: i64 = 1;
const KIND_ITEM_SECRET_READ: i64 = 3;

/// Create an account with a login (with a secret password) and a totp item, plus
/// the on-device Secret Key file the daemon reads at unlock. Returns the tempdir.
fn make_profile() -> tempfile::TempDir {
    use lp_vault::AccountStore;
    use lp_vault::payload::{Field, FieldKind, ItemPayload, TypeData};
    use serde_json::json;

    let tmp = tempfile::tempdir().unwrap();
    let (session, secret_key) = AccountStore::create(tmp.path(), TEST_PASSWORD).unwrap();
    std::fs::write(
        tmp.path().join("secret-key"),
        secret_key.to_display_string(),
    )
    .unwrap();

    let vid = session.create_vault("personal").unwrap();
    let vault = session.open_vault(vid).unwrap();
    let mut login = ItemPayload::new(TypeData::Login { urls: vec![] }, "Login");
    login.fields = vec![
        Field {
            name: "username".into(),
            kind: FieldKind::Text,
            value: json!("alice"),
        },
        Field {
            name: "password".into(),
            kind: FieldKind::Hidden,
            value: json!(SECRET_PW),
        },
    ];
    vault.create_item(&login).unwrap();
    vault
        .create_item(&ItemPayload::new(
            TypeData::Totp {
                secret_b32: RFC_SEED_B32.to_string(),
                algo: "SHA1".into(),
                digits: 6,
                period: 30,
                issuer: "ACME".into(),
                account: "alice".into(),
            },
            "RFC",
        ))
        .unwrap();
    drop(vault);
    session.lock();
    tmp
}

fn set_user(username: &str) {
    unsafe {
        std::env::set_var("USERNAME", username);
        std::env::set_var("USER", username);
    }
}

fn wait_ready(username: &str, timeout: Duration) -> bool {
    set_user(username);
    let deadline = Instant::now() + timeout;
    loop {
        if lp_daemon::client::probe().unwrap_or(false) {
            return true;
        }
        if Instant::now() >= deadline {
            return false;
        }
        std::thread::sleep(Duration::from_millis(25));
    }
}

fn connect(username: &str) -> Client {
    set_user(username);
    Client::connect().expect("connect to test server")
}

/// Count `audit_log` rows of a given kind code in the profile's account store.
fn count_kind(profile: &std::path::Path, kind: i64) -> i64 {
    let conn = rusqlite::Connection::open(profile.join("account.localpass")).unwrap();
    conn.query_row(
        "SELECT COUNT(*) FROM audit_log WHERE kind = ?1",
        rusqlite::params![kind],
        |r| r.get(0),
    )
    .unwrap()
}

/// Concatenate every text/blob column of `audit_log` into one string (for a
/// secret-leak assertion).
fn dump(profile: &std::path::Path) -> String {
    let conn = rusqlite::Connection::open(profile.join("account.localpass")).unwrap();
    let mut stmt = conn
        .prepare("SELECT hex(item_id), field, format, detail FROM audit_log")
        .unwrap();
    let rows = stmt
        .query_map([], |r| {
            Ok(format!(
                "{:?}{:?}{:?}{:?}",
                r.get::<_, Option<String>>(0)?,
                r.get::<_, Option<String>>(1)?,
                r.get::<_, Option<String>>(2)?,
                r.get::<_, Option<String>>(3)?,
            ))
        })
        .unwrap();
    rows.map(Result::unwrap).collect::<Vec<_>>().join("")
}

#[test]
fn proxied_actions_record_audit_events_exactly_once() {
    let _env = ENV_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let username = unique_user("once");
    let tmp = make_profile();
    let profile = tmp.path().display().to_string();
    let profile_path = tmp.path().to_path_buf();

    let cfg = Config {
        profile: tmp.path().to_path_buf(),
        autolock: Duration::from_secs(600),
        username: username.clone(),
        verbose: false,
        no_ssh_agent: true,
    };
    let handle = std::thread::spawn(move || server::run(cfg));
    assert!(wait_ready(&username, Duration::from_secs(5)), "server up");

    // 1) Unlock over IPC → exactly one UnlockSuccess (recorded in lp-vault's
    //    AccountStore::unlock, which the daemon calls).
    {
        let mut c = connect(&username);
        let resp = c
            .call(&Request::Unlock {
                profile: profile.clone(),
                password: TEST_PASSWORD.into(),
                secret_key: None,
                autolock_secs: None,
            })
            .unwrap();
        assert!(matches!(resp, Response::Ok { .. }), "unlock ok");
    }
    assert_eq!(
        count_kind(&profile_path, KIND_UNLOCK_SUCCESS),
        1,
        "exactly one UnlockSuccess for one proxied unlock"
    );

    // 2) A masked GetItem must NOT record a secret read.
    {
        let mut c = connect(&username);
        let resp = c
            .call(&Request::GetItem {
                profile: profile.clone(),
                vault: "personal".into(),
                target: "Login".into(),
                version: None,
                reveal: false,
            })
            .unwrap();
        assert!(matches!(resp, Response::Item { .. }), "masked get ok");
    }
    assert_eq!(
        count_kind(&profile_path, KIND_ITEM_SECRET_READ),
        0,
        "a masked GetItem is not a secret read"
    );

    // 3) A revealed GetItem records exactly one secret read.
    {
        let mut c = connect(&username);
        c.call(&Request::GetItem {
            profile: profile.clone(),
            vault: "personal".into(),
            target: "Login".into(),
            version: None,
            reveal: true,
        })
        .unwrap();
    }
    assert_eq!(
        count_kind(&profile_path, KIND_ITEM_SECRET_READ),
        1,
        "one revealed GetItem → one secret read (recorded once, by the daemon)"
    );

    // 4) A ResolveField records another secret read.
    {
        let mut c = connect(&username);
        let resp = c
            .call(&Request::ResolveField {
                profile: profile.clone(),
                vault: "personal".into(),
                item: "Login".into(),
                field: "password".into(),
            })
            .unwrap();
        assert!(matches!(resp, Response::Field { .. }), "resolve ok");
    }
    assert_eq!(
        count_kind(&profile_path, KIND_ITEM_SECRET_READ),
        2,
        "revealed get + resolve field → two secret reads"
    );

    // 5) A proxied TOTP records another secret read (the code is a disclosure).
    {
        let mut c = connect(&username);
        let resp = c
            .call(&Request::Totp {
                profile: profile.clone(),
                vault: "personal".into(),
                target: "RFC".into(),
            })
            .unwrap();
        assert!(matches!(resp, Response::Totp { .. }), "totp ok");
    }
    assert_eq!(
        count_kind(&profile_path, KIND_ITEM_SECRET_READ),
        3,
        "revealed get + resolve + totp → three secret reads, each recorded once"
    );

    // The secret password value must never have been written to the audit log.
    assert!(
        !dump(&profile_path).contains(SECRET_PW),
        "the audit log must never contain a secret value"
    );

    // Shut the daemon down.
    {
        let mut c = connect(&username);
        let _ = c.call(&Request::Shutdown);
    }
    let deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < deadline && !handle.is_finished() {
        std::thread::sleep(Duration::from_millis(25));
    }
    if handle.is_finished() {
        let _ = handle.join();
    }
}

/// Kind code for `AuditKind::AccessDenied`.
const KIND_ACCESS_DENIED: i64 = 13;

/// End-to-end over the real IPC channel: caller attribution reaches the log, a
/// keep-alive `Status` resets the idle timer while a passive one does not, a
/// refused request is audited and does NOT reset the timer, and `AuditList`
/// hands the records back without ever carrying a title or a secret.
#[test]
fn attribution_keepalive_and_refusals_over_ipc() {
    let _env = ENV_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let username = unique_user("attrib");
    let tmp = make_profile();
    let profile = tmp.path().display().to_string();
    let profile_path = tmp.path().to_path_buf();
    let autolock_secs = 600u64;

    let cfg = Config {
        profile: tmp.path().to_path_buf(),
        autolock: Duration::from_secs(autolock_secs),
        username: username.clone(),
        verbose: false,
        no_ssh_agent: true,
    };
    let handle = std::thread::spawn(move || server::run(cfg));
    assert!(wait_ready(&username, Duration::from_secs(5)), "server up");

    // This test process speaks as an MCP server, so every frame it sends carries
    // that attribution and everything the daemon audits for it says `mcp`.
    lp_vault::audit::set_process_origin(lp_vault::AuditOrigin::sanitized(
        lp_vault::AuditSource::Mcp,
        Some("localpass-mcp-test"),
        Some(std::process::id()),
    ));

    // --- A refusal while LOCKED is audited, keylessly ----------------------
    {
        let mut c = connect(&username);
        let resp = c
            .call(&Request::ListVaults {
                profile: profile.clone(),
            })
            .unwrap();
        assert!(matches!(resp, Response::Locked), "locked refusal");
    }
    assert_eq!(
        count_kind(&profile_path, KIND_ACCESS_DENIED),
        1,
        "a locked refusal is audited even with no session and no keys"
    );

    // --- Unlock, then a revealed read attributed to us ---------------------
    {
        let mut c = connect(&username);
        c.call(&Request::Unlock {
            profile: profile.clone(),
            password: TEST_PASSWORD.into(),
            secret_key: None,
            autolock_secs: None,
        })
        .unwrap();
        c.call(&Request::GetItem {
            profile: profile.clone(),
            vault: "personal".into(),
            target: "Login".into(),
            version: None,
            reveal: true,
        })
        .unwrap();
    }

    // --- Idle timer: passive Status observes, keep-alive Status refreshes ---
    let remaining = |c: &mut Client, keepalive: bool| -> u64 {
        let resp = c
            .call(&Request::Status {
                profile: profile.clone(),
                keepalive,
            })
            .unwrap();
        match resp {
            Response::Status {
                idle_remaining_secs,
                ..
            } => idle_remaining_secs.expect("unlocked"),
            other => panic!("expected Status, got {other:?}"),
        }
    };
    let mut c = connect(&username);
    std::thread::sleep(Duration::from_millis(1100));
    let after_passive = remaining(&mut c, false);
    assert!(
        after_passive < autolock_secs,
        "a passive Status must not reset the idle timer (remaining {after_passive})"
    );
    // The keep-alive's OWN answer reports the timer as it was when the request
    // arrived, so read it back with a second passive poll.
    let _ = remaining(&mut c, true);
    let after_keepalive = remaining(&mut c, false);
    assert!(
        after_keepalive > after_passive,
        "a keepalive Status must reset the idle timer ({after_passive} -> {after_keepalive})"
    );

    // A refused request must not reset it either.
    std::thread::sleep(Duration::from_millis(1100));
    let before_refusal = remaining(&mut c, false);
    let resp = c
        .call(&Request::ListVaults {
            profile: "/not/this/profile".into(),
        })
        .unwrap();
    assert!(matches!(resp, Response::WrongProfile { .. }));
    let after_refusal = remaining(&mut c, false);
    assert!(
        after_refusal <= before_refusal,
        "a refused request must not reset the idle timer \
         ({before_refusal} -> {after_refusal})"
    );
    assert_eq!(
        count_kind(&profile_path, KIND_ACCESS_DENIED),
        2,
        "the wrong-profile refusal is audited too"
    );

    // --- AuditList: attributed, metadata-only, no title, no secret ---------
    let resp = c
        .call(&Request::AuditList {
            profile: profile.clone(),
            limit: Some(50),
            since: None,
        })
        .unwrap();
    let Response::AuditRecords { records } = resp else {
        panic!("expected AuditRecords");
    };
    assert!(!records.is_empty(), "records came back");
    // Newest first.
    assert!(
        records.windows(2).all(|w| w[0].seq >= w[1].seq),
        "AuditList returns newest first"
    );
    let read = records
        .iter()
        .find(|r| r.kind == "item_secret_read")
        .expect("the revealed read is in the log");
    assert_eq!(
        read.source.as_deref(),
        Some("mcp"),
        "attributed to the MCP client"
    );
    assert_eq!(read.process.as_deref(), Some("localpass-mcp-test"));
    assert!(read.pid.is_some());
    assert!(read.item_id.is_some(), "the read names its item id");
    assert!(
        records
            .iter()
            .any(|r| r.kind == "access_denied" && r.deny_reason.as_deref() == Some("locked")),
        "the locked refusal is visible to a client"
    );

    // The whole response must carry no secret and no item TITLE — the log holds
    // neither, and this is the boundary where a leak would show up.
    let serialized = serde_json::to_string(&records).expect("serialize records");
    assert!(
        !serialized.contains(SECRET_PW),
        "AuditList leaked a secret: {serialized}"
    );
    for title in ["Login", "RFC", "personal"] {
        assert!(
            !serialized.contains(title),
            "AuditList leaked the {title:?} name: {serialized}"
        );
    }

    // Reset the process-global attribution for any test that follows.
    lp_vault::audit::set_process_origin(lp_vault::AuditOrigin::default());

    {
        let mut c = connect(&username);
        let _ = c.call(&Request::Shutdown);
    }
    let deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < deadline && !handle.is_finished() {
        std::thread::sleep(Duration::from_millis(25));
    }
    if handle.is_finished() {
        let _ = handle.join();
    }
}
