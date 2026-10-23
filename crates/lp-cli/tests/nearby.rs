//! `localpass sync nearby` end to end: two real `localpass` processes on
//! loopback, one listening and one connecting (`lan-transport.md` §9.2).

mod common;

use std::io::{BufRead, BufReader};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use common::{TEST_PASSWORD, TestProfile};
use predicates::str::contains;

/// `(device_id, identity, fingerprint)` from `device export-identity --json`.
fn identity(p: &TestProfile) -> (String, String, String) {
    let out = p
        .cmd()
        .args(["device", "export-identity", "--json"])
        .output()
        .unwrap();
    assert!(out.status.success());
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    (
        v["device_id"].as_str().unwrap().to_string(),
        v["identity"].as_str().unwrap().to_string(),
        v["fingerprint"].as_str().unwrap().to_string(),
    )
}

fn trust(on: &TestProfile, other: &TestProfile, label: &str) {
    let (_, id, fp) = identity(other);
    on.cmd()
        .args([
            "device",
            "trust",
            &id,
            "--fingerprint",
            &fp,
            "--label",
            label,
        ])
        .assert()
        .success();
}

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

#[test]
fn listen_and_connect_share_a_vault_between_two_processes() {
    let a = TestProfile::initialized();
    let b = TestProfile::initialized();
    a.cmd()
        .args(["item", "add", "--title", "Server", "--username", "root"])
        .assert()
        .success();
    trust(&a, &b, "b");
    trust(&b, &a, "a");
    let (a_id, _, _) = identity(&a);
    let (b_id, _, _) = identity(&b);
    let port = free_port();

    // B listens in its own process.
    let mut listener = Command::new(assert_cmd::cargo::cargo_bin("localpass"))
        .env("LOCALPASS_PASSWORD", TEST_PASSWORD)
        .arg("--profile")
        .arg(b.path())
        .args([
            "sync",
            "nearby",
            "--listen",
            "--bind",
            "127.0.0.1",
            "--port",
            &port.to_string(),
            "--timeout",
            "60",
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    // Wait until it says it is listening (it unlocks first: ~1 s of KDF).
    let stdout = listener.stdout.take().unwrap();
    let (tx, rx) = std::sync::mpsc::channel::<String>();
    let reader = std::thread::spawn(move || {
        for line in BufReader::new(stdout).lines().map_while(Result::ok) {
            let _ = tx.send(line);
        }
    });
    let deadline = Instant::now() + Duration::from_secs(60);
    let mut seen = Vec::new();
    loop {
        let line = rx
            .recv_timeout(deadline.saturating_duration_since(Instant::now()))
            .expect("the listener never reported it was waiting");
        let ready = line.starts_with("Waiting");
        seen.push(line);
        if ready {
            break;
        }
    }

    // A connects and shares its default vault with B.
    let out = a
        .cmd()
        .args([
            "sync",
            "nearby",
            "--connect",
            &format!("127.0.0.1:{port}"),
            "--peer",
            &b_id,
            "--share",
            "personal",
            "--json",
        ])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "connect failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let report: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(report["peer_device_id"], b_id.as_str());
    assert_eq!(report["peer_label"], "b");
    let shared = report["shared"][0].as_str().unwrap().to_string();
    assert_eq!(report["vaults"][0]["ops_sent"], 1);
    assert!(report["alarms"].as_array().unwrap().is_empty());

    // B's process finishes its one session and exits cleanly.
    let status = listener.wait().unwrap();
    reader.join().unwrap();
    seen.extend(rx.try_iter());
    let text = seen.join("\n");
    assert!(status.success(), "listener failed:\n{text}");
    assert!(
        text.contains(&format!("Synced with device {a_id} (a)")),
        "{text}"
    );
    assert!(text.contains("adopted vault"), "{text}");

    // The shared vault and its item are now on B.
    b.cmd()
        .args(["item", "list", "--vault", &shared])
        .assert()
        .success()
        .stdout(contains("Server"));
}

#[test]
fn connect_refuses_non_local_addresses_and_host_names_without_dialing() {
    let a = TestProfile::initialized();
    a.cmd()
        .args(["sync", "nearby", "--connect", "8.8.8.8"])
        .assert()
        .failure()
        .stderr(contains("not a local-network address"));
    a.cmd()
        .args(["sync", "nearby", "--connect", "my-laptop.local"])
        .assert()
        .failure()
        .stderr(contains("not an IP address"));
    a.cmd()
        .args([
            "sync",
            "nearby",
            "--connect",
            "127.0.0.1",
            "--share",
            "personal",
        ])
        .assert()
        .failure()
        .stderr(contains("--share needs --peer"));
}
