//! A real-endpoint transport round-trip: bind a listener, connect a client, and
//! exchange one framed Ping/Pong. This exercises the platform access-control
//! path (Windows DACL / Unix peer-uid) end to end without spawning a process.

use lp_daemon::frame;
use lp_daemon::protocol::{Request, Response};
use lp_daemon::transport::{self, Listener};

/// Bind, accept in a thread, connect, send Ping, expect Pong.
#[test]
fn ping_pong_over_real_endpoint() {
    // Use a distinctive username so this test's endpoint doesn't collide with a
    // real running daemon (Windows pipe name; Unix ignores the username but the
    // socket path is per-user runtime dir — fine for a single test process).
    let username = format!("lp-test-{}", std::process::id());

    let mut listener = Listener::bind(&username).expect("bind listener");

    let server = std::thread::spawn(move || {
        let mut conn = listener.accept().expect("accept");
        // Read one request, answer Pong.
        let req = frame::read_request(&mut conn).expect("read").expect("some");
        assert!(matches!(req, Request::Ping));
        frame::write_response(&mut conn, &Response::Pong).expect("write");
        // Keep the listener alive until we've answered.
        drop(conn);
    });

    // Give the acceptor a moment to be ready, then connect and round-trip.
    // Retry connect briefly to avoid a race with bind/accept setup.
    let mut client = None;
    for _ in 0..40 {
        match transport::connect(&username) {
            Ok(c) => {
                client = Some(c);
                break;
            }
            Err(_) => std::thread::sleep(std::time::Duration::from_millis(25)),
        }
    }
    let mut client = client.expect("connect to test endpoint");

    frame::write_request(&mut client, &Request::Ping).expect("client write");
    let resp = frame::read_response(&mut client).expect("client read");
    assert!(matches!(resp, Response::Pong), "expected Pong");

    server.join().expect("server thread");

    // Sanity: the endpoint label is well-formed.
    let label = transport::endpoint_label(&username);
    assert!(!label.is_empty());
}

/// A second bind for the same endpoint while one is live must fail (single
/// owner), proving the "already running" detection the CLI relies on.
#[test]
fn second_bind_same_user_fails_while_first_is_live() {
    let username = format!("lp-test-dup-{}", std::process::id());
    let _first = Listener::bind(&username).expect("first bind");
    // A second bind of the same endpoint must be refused while the first lives.
    let second = Listener::bind(&username);
    assert!(
        second.is_err(),
        "second bind should fail while first is live"
    );
}

/// The frame layer works over an in-memory pipe (transport-agnostic framing).
#[test]
fn framing_is_transport_agnostic() {
    // A pair of connected byte buffers via std::io — just confirm the framing
    // helpers are not platform-coupled.
    let mut buf: Vec<u8> = Vec::new();
    frame::write_request(&mut buf, &Request::Lock).expect("write");
    let mut cur = std::io::Cursor::new(buf);
    let got = frame::read_request(&mut cur).expect("read").expect("some");
    assert!(matches!(got, Request::Lock));
}
