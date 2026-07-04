//! SSH agent integration test: run the real daemon server loop (which serves the
//! SSH agent endpoint alongside the control endpoint), unlock it, connect to the
//! **agent** endpoint as a client, and drive the raw draft-miller protocol —
//! REQUEST_IDENTITIES, SIGN_REQUEST, verify the signature — then lock and confirm
//! the identity list goes empty.
//!
//! # Endpoint sharing note
//!
//! The agent endpoint is a **fixed, system-wide** name (the Windows pipe
//! `\\.\pipe\openssh-ssh-agent`, and on Unix a per-user runtime socket). Only one
//! process/daemon can own it, so this test:
//!   - holds [`AGENT_LOCK`] for its whole body (serializing the tests here), and
//!   - **skips gracefully** (prints a note, returns) if the agent endpoint could
//!     not be bound — e.g. Microsoft's own ssh-agent service already owns the
//!     Windows pipe. That is an environmental conflict, not a code failure.

use std::sync::Mutex;
use std::time::{Duration, Instant};

use lp_daemon::client::Client;
use lp_daemon::protocol::{Request, Response};
use lp_daemon::server::{self, Config};
use lp_daemon::sshagent::keys::{self, GenAlgorithm};
use lp_daemon::sshagent::listener;
use lp_daemon::sshagent::protocol as agent;

/// Serializes the tests in this binary: they share the fixed agent endpoint and
/// the process-global `USERNAME`/`USER` env `Client::connect` reads.
static AGENT_LOCK: Mutex<()> = Mutex::new(());

fn unique_user(tag: &str) -> String {
    format!("lpssh-{tag}-{}", std::process::id())
}

/// Create a test account with two ed25519 ssh_key items and a Secret Key file, so
/// the daemon can unlock and serve them. Returns the tempdir (kept alive) and the
/// list of `(title, public_blob)` for assertions.
fn make_profile_with_keys() -> (tempfile::TempDir, Vec<(String, Vec<u8>)>) {
    use lp_vault::AccountStore;
    use lp_vault::payload::{ItemPayload, TypeData};

    let tmp = tempfile::tempdir().unwrap();
    let (session, secret_key) = AccountStore::create(tmp.path(), "correct horse battery").unwrap();
    // Persist the Secret Key file so the daemon can load it at unlock (the CLI's
    // MVP keychain stand-in the daemon reads from <profile>/secret-key).
    std::fs::write(
        tmp.path().join("secret-key"),
        secret_key.to_display_string(),
    )
    .unwrap();

    let vid = session.create_vault("personal").unwrap();
    let vault = session.open_vault(vid).unwrap();
    let mut blobs = Vec::new();
    for title in ["laptop key", "server key"] {
        let key = keys::generate(GenAlgorithm::Ed25519, title).unwrap();
        // Derive the public blob for later matching.
        let parsed = keys::parse_private_key(&key.private_pem, title).unwrap();
        blobs.push((title.to_string(), parsed.public_blob().unwrap()));
        let payload = ItemPayload::new(
            TypeData::SshKey {
                algo: key.algo,
                private_pem: key.private_pem,
                public_openssh: key.public_openssh,
                fingerprint: key.fingerprint,
            },
            title,
        );
        vault.create_item(&payload).unwrap();
    }
    drop(vault);
    session.lock();
    (tmp, blobs)
}

/// Set the endpoint username env so `Client::connect` targets this test's daemon.
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

/// Read one agent message off a connection into `(type, payload)`.
fn read_agent<R: std::io::Read>(r: &mut R) -> (u8, Vec<u8>) {
    agent::read_message(r).unwrap().unwrap()
}

/// Send REQUEST_IDENTITIES and return the parsed `(blob, comment)` list.
fn request_identities(conn: &mut listener::AgentConnection) -> Vec<(Vec<u8>, String)> {
    agent::write_message(conn, agent::SSH_AGENTC_REQUEST_IDENTITIES, &[]).unwrap();
    let (ty, payload) = read_agent(conn);
    assert_eq!(ty, agent::SSH_AGENT_IDENTITIES_ANSWER);
    let mut pc = std::io::Cursor::new(payload);
    let mut count_buf = [0u8; 4];
    std::io::Read::read_exact(&mut pc, &mut count_buf).unwrap();
    let count = u32::from_be_bytes(count_buf);
    let mut out = Vec::new();
    for _ in 0..count {
        let blob = agent::read_string(&mut pc).unwrap();
        let comment = String::from_utf8(agent::read_string(&mut pc).unwrap()).unwrap();
        out.push((blob, comment));
    }
    out
}

/// The end-to-end agent test: unlock, list identities over the agent pipe, sign,
/// verify, then lock and confirm the list is empty.
#[test]
fn agent_lists_and_signs_and_locks() {
    let _guard = AGENT_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);

    let (tmp, blobs) = make_profile_with_keys();
    let username = unique_user("e2e");

    let cfg = Config {
        profile: tmp.path().to_path_buf(),
        autolock: Duration::from_secs(600),
        username: username.clone(),
        verbose: false,
        no_ssh_agent: false,
    };
    let running = std::thread::spawn(move || server::run(cfg));

    assert!(
        wait_ready(&username, Duration::from_secs(5)),
        "daemon did not come up"
    );

    // If the agent endpoint could not be bound (e.g. Microsoft's ssh-agent owns
    // the Windows pipe), skip gracefully — this is environmental, not a bug.
    let mut agent_conn = match listener::connect() {
        Ok(c) => c,
        Err(_) => {
            eprintln!(
                "SKIP: SSH agent endpoint not available (likely owned by another agent); \
                 stop it to run this test end to end."
            );
            shutdown(&username, running);
            return;
        }
    };

    // 1) While LOCKED: identities list is empty, sign fails.
    let ids = request_identities(&mut agent_conn);
    assert_eq!(ids.len(), 0, "locked daemon serves no identities");

    // Sign against a known blob → FAILURE while locked.
    {
        let mut payload = Vec::new();
        agent::write_string(&mut payload, &blobs[0].1).unwrap();
        agent::write_string(&mut payload, b"data").unwrap();
        payload.extend_from_slice(&0u32.to_be_bytes());
        agent::write_message(&mut agent_conn, agent::SSH_AGENTC_SIGN_REQUEST, &payload).unwrap();
        let (ty, _) = read_agent(&mut agent_conn);
        assert_eq!(ty, agent::SSH_AGENT_FAILURE, "locked sign is failure");
    }
    drop(agent_conn);

    // 2) UNLOCK via the control channel.
    {
        set_user(&username);
        let mut c = Client::connect().unwrap();
        let resp = c
            .call(&Request::Unlock {
                profile: tmp.path().display().to_string(),
                password: "correct horse battery".into(),
                secret_key: None,
                autolock_secs: None,
            })
            .unwrap();
        assert!(matches!(resp, Response::Ok { .. }), "unlock ok");
    }

    // 3) UNLOCKED: identities list has both keys.
    let mut agent_conn = listener::connect().unwrap();
    let ids = request_identities(&mut agent_conn);
    assert_eq!(ids.len(), 2, "two ssh keys served when unlocked");
    let comments: Vec<&str> = ids.iter().map(|(_, c)| c.as_str()).collect();
    assert!(comments.contains(&"laptop key"));
    assert!(comments.contains(&"server key"));
    // Every served blob matches one we created.
    for (blob, _) in &ids {
        assert!(blobs.iter().any(|(_, b)| b == blob), "served blob is known");
    }

    // 4) SIGN_REQUEST against the first key; verify the signature.
    let target_blob = ids[0].0.clone();
    let data = b"the SSH transport session data to sign";
    {
        let mut payload = Vec::new();
        agent::write_string(&mut payload, &target_blob).unwrap();
        agent::write_string(&mut payload, data).unwrap();
        payload.extend_from_slice(&0u32.to_be_bytes());
        agent::write_message(&mut agent_conn, agent::SSH_AGENTC_SIGN_REQUEST, &payload).unwrap();
        let (ty, resp_payload) = read_agent(&mut agent_conn);
        assert_eq!(ty, agent::SSH_AGENT_SIGN_RESPONSE, "sign response");
        let mut pc = std::io::Cursor::new(resp_payload);
        let sig_blob = agent::read_string(&mut pc).unwrap();

        // Verify: decode the signature and check it against the public key blob.
        use signature::Verifier;
        let sig = ssh_key::Signature::try_from(sig_blob.as_slice()).unwrap();
        // Reconstruct the public key from the served blob via ssh-encoding.
        let key_data = decode_public_blob(&target_blob);
        key_data
            .verify(data, &sig)
            .expect("agent signature verifies");
    }

    // 5) An unknown key → FAILURE.
    {
        let mut payload = Vec::new();
        agent::write_string(&mut payload, b"not a key blob at all").unwrap();
        agent::write_string(&mut payload, data).unwrap();
        payload.extend_from_slice(&0u32.to_be_bytes());
        agent::write_message(&mut agent_conn, agent::SSH_AGENTC_SIGN_REQUEST, &payload).unwrap();
        let (ty, _) = read_agent(&mut agent_conn);
        assert_eq!(ty, agent::SSH_AGENT_FAILURE, "unknown key sign fails");
    }
    drop(agent_conn);

    // 6) LOCK via the control channel; identities go empty again.
    {
        set_user(&username);
        let mut c = Client::connect().unwrap();
        assert!(matches!(
            c.call(&Request::Lock).unwrap(),
            Response::Ok { .. }
        ));
    }
    let mut agent_conn = listener::connect().unwrap();
    let ids = request_identities(&mut agent_conn);
    assert_eq!(ids.len(), 0, "locked again → empty identity list");
    drop(agent_conn);

    shutdown(&username, running);
}

/// The daemon status reports the agent endpoint and identity count.
#[test]
fn status_reports_agent_endpoint_and_count() {
    let _guard = AGENT_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);

    let (tmp, _blobs) = make_profile_with_keys();
    let username = unique_user("status");
    let cfg = Config {
        profile: tmp.path().to_path_buf(),
        autolock: Duration::from_secs(600),
        username: username.clone(),
        verbose: false,
        no_ssh_agent: false,
    };
    let running = std::thread::spawn(move || server::run(cfg));
    assert!(wait_ready(&username, Duration::from_secs(5)));

    // Unlock so the agent has identities to count.
    set_user(&username);
    {
        let mut c = Client::connect().unwrap();
        c.call(&Request::Unlock {
            profile: tmp.path().display().to_string(),
            password: "correct horse battery".into(),
            secret_key: None,
            autolock_secs: None,
        })
        .unwrap();
    }

    set_user(&username);
    let mut c = Client::connect().unwrap();
    let resp = c
        .call(&Request::Status {
            profile: tmp.path().display().to_string(),
        })
        .unwrap();
    if let Response::Status {
        ssh_agent_endpoint,
        ssh_identity_count,
        ..
    } = resp
    {
        // If the agent bound (endpoint Some), it must serve 2 identities.
        if let Some(ep) = ssh_agent_endpoint {
            assert!(!ep.is_empty());
            assert_eq!(ssh_identity_count, 2, "two ssh keys counted");
        } else {
            eprintln!("SKIP count assert: agent endpoint not bound in this environment");
        }
    } else {
        panic!("expected Status");
    }

    shutdown(&username, running);
}

/// Decode an SSH public-key blob back into `KeyData` for verification.
fn decode_public_blob(blob: &[u8]) -> ssh_key::public::KeyData {
    use ssh_encoding::Decode;
    // ssh-encoding's `Reader` is implemented for `&[u8]` (which advances as it
    // reads), not for `Cursor`.
    let mut reader: &[u8] = blob;
    ssh_key::public::KeyData::decode(&mut reader).unwrap()
}

/// Shut the daemon down and join its thread.
fn shutdown(username: &str, running: std::thread::JoinHandle<lp_daemon::Result<()>>) {
    set_user(username);
    if let Ok(mut c) = Client::connect() {
        let _ = c.call(&Request::Shutdown);
    }
    let deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < deadline {
        if running.is_finished() {
            let _ = running.join();
            return;
        }
        std::thread::sleep(Duration::from_millis(25));
    }
    // If it didn't stop, still drop the handle (process exit reaps it).
    let _ = running;
}
