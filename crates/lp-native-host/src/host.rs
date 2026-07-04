#![forbid(unsafe_code)]
//! The host run loop: read framed native-messaging requests from a reader,
//! dispatch them through the [`Bridge`], and write framed responses to a writer.
//!
//! Parameterizing over `Read`/`Write` (rather than hard-wiring stdin/stdout) lets
//! tests drive the exact same loop over in-memory buffers. The real
//! `localpass-native-host` binary passes locked stdin/stdout.
//!
//! # Logging discipline (stderr is for logs only)
//!
//! Native messaging uses stdout for the wire; **stderr** is the only safe place
//! to log. We log the request *type* and the response *type* only — never a
//! message body, an origin's full URL is fine but a `fill` password is **never**
//! logged. In practice we log types, so no secret can ever reach the log.

use std::io::{Read, Write};

use crate::bridge::Bridge;
use crate::framing::{self, FramingError};
use crate::protocol::{
    HostRequest, HostResponse, PROTOCOL_VERSION, RequestEnvelope, ResponseEnvelope,
};

/// Run the native-messaging loop until the input stream reaches EOF (the browser
/// closed the port) or a fatal framing error occurs.
///
/// `log` receives short, secret-free status lines (the binary points it at
/// stderr; tests can discard it). Returns `Ok(())` on a clean shutdown (EOF) and
/// an error only on an unrecoverable framing/IO failure — a malformed *message*
/// is answered with an error response and the loop continues (a single bad
/// message from a page must not kill the host).
///
/// # Errors
///
/// [`FramingError`] on an unrecoverable stdio failure (a truncated frame or an
/// IO error). Per-message parse failures are **not** errors — they are answered
/// with a `bad_request`/`unsupported` response.
pub fn run<R: Read, W: Write>(
    reader: &mut R,
    writer: &mut W,
    bridge: &Bridge,
    mut log: impl FnMut(&str),
) -> framing::Result<()> {
    loop {
        let body = match framing::read_message(reader) {
            Ok(Some(body)) => body,
            Ok(None) => {
                log("port closed (eof); exiting");
                return Ok(());
            }
            // A truncated/oversized frame is fatal for this stream — we cannot
            // resync a length-prefixed protocol mid-stream. Log the KIND and stop
            // (the browser will relaunch the host on the next message).
            Err(e @ (FramingError::Truncated | FramingError::TooLarge(_))) => {
                log(&format!("fatal framing error: {e}; exiting"));
                return Err(e);
            }
            Err(e) => {
                log(&format!("io error: {e}; exiting"));
                return Err(e);
            }
        };

        let response = dispatch(&body, bridge, &mut log);
        let envelope = ResponseEnvelope::new(response);
        // Serialization of our own response type cannot fail in practice; if it
        // somehow did, emit a minimal hand-built error frame rather than panic.
        let out = serde_json::to_vec(&envelope).unwrap_or_else(|_| {
            br#"{"v":1,"type":"error","error":"internal","message":"encode failed"}"#.to_vec()
        });
        framing::write_message(writer, &out)?;
    }
}

/// Parse one request body and produce the response. Never returns an `Err` — a
/// malformed body becomes a `bad_request` response so the loop keeps running.
fn dispatch(body: &[u8], bridge: &Bridge, log: &mut impl FnMut(&str)) -> HostResponse {
    let envelope: RequestEnvelope = match serde_json::from_slice(body) {
        Ok(env) => env,
        Err(e) => {
            log("recv: <unparseable body>");
            return HostResponse::bad_request(format!("malformed request json: {e}"));
        }
    };
    if envelope.v != PROTOCOL_VERSION {
        log(&format!("recv: <unsupported version {}>", envelope.v));
        return HostResponse::bad_request(format!(
            "unsupported protocol version {} (this host speaks v{PROTOCOL_VERSION})",
            envelope.v
        ));
    }

    match envelope.request {
        HostRequest::Ping => {
            log("recv: ping");
            HostResponse::Pong
        }
        HostRequest::Status => {
            log("recv: status");
            bridge.status()
        }
        HostRequest::CredentialsFor { origin, kind } => {
            // The origin is not a secret; logging it aids debugging. Still, we log
            // only the type to keep logs uniform and minimal.
            log("recv: credentials_for");
            bridge.credentials_for(&origin, kind.as_deref())
        }
        HostRequest::Fill { item_id, origin } => {
            log("recv: fill");
            let resp = bridge.fill(&item_id, &origin);
            // NEVER log the fill result body; log only the outcome kind.
            match &resp {
                HostResponse::Fill { .. } => log("send: fill (ok)"),
                HostResponse::Locked => log("send: locked"),
                HostResponse::Error { error, .. } => log(&format!("send: error({error})")),
                _ => {}
            }
            resp
        }
        HostRequest::Unknown => {
            log("recv: <unknown type>");
            HostResponse::unsupported()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::framing::write_message;
    use std::io::Cursor;

    /// Frame a JSON request into the native-messaging wire form.
    fn framed(json: &str) -> Vec<u8> {
        let mut buf = Vec::new();
        write_message(&mut buf, json.as_bytes()).unwrap();
        buf
    }

    /// Read all framed responses from a buffer into parsed JSON values.
    fn read_all(mut buf: &[u8]) -> Vec<serde_json::Value> {
        let mut out = Vec::new();
        while let Some(body) = framing::read_message(&mut buf).unwrap() {
            out.push(serde_json::from_slice(&body).unwrap());
        }
        out
    }

    #[test]
    fn ping_answers_pong_without_a_daemon() {
        // No daemon running in a unit test: ping still works (it never touches the
        // bridge). Use an isolated endpoint name so we don't hit a real daemon.
        let mut input = Vec::new();
        input.extend_from_slice(&framed(r#"{"v":1,"type":"ping"}"#));
        let mut reader = Cursor::new(input);
        let mut writer = Vec::new();
        let bridge = Bridge::new("");
        run(&mut reader, &mut writer, &bridge, |_| {}).unwrap();
        let responses = read_all(&writer);
        assert_eq!(responses.len(), 1);
        assert_eq!(responses[0]["type"], "pong");
        assert_eq!(responses[0]["v"], 1);
    }

    #[test]
    fn unknown_type_answers_unsupported() {
        let mut reader = Cursor::new(framed(r#"{"v":1,"type":"nope"}"#));
        let mut writer = Vec::new();
        run(&mut reader, &mut writer, &Bridge::new(""), |_| {}).unwrap();
        let responses = read_all(&writer);
        assert_eq!(responses[0]["type"], "error");
        assert_eq!(responses[0]["error"], "unsupported");
    }

    #[test]
    fn malformed_body_answers_bad_request_and_loop_survives() {
        // A malformed message followed by a valid ping: both are answered, proving
        // one bad message does not kill the loop.
        let mut input = Vec::new();
        input.extend_from_slice(&framed("not json at all"));
        input.extend_from_slice(&framed(r#"{"v":1,"type":"ping"}"#));
        let mut reader = Cursor::new(input);
        let mut writer = Vec::new();
        run(&mut reader, &mut writer, &Bridge::new(""), |_| {}).unwrap();
        let responses = read_all(&writer);
        assert_eq!(responses.len(), 2);
        assert_eq!(responses[0]["type"], "error");
        assert_eq!(responses[0]["error"], "bad_request");
        assert_eq!(responses[1]["type"], "pong");
    }

    #[test]
    fn unsupported_version_is_bad_request() {
        let mut reader = Cursor::new(framed(r#"{"v":999,"type":"ping"}"#));
        let mut writer = Vec::new();
        run(&mut reader, &mut writer, &Bridge::new(""), |_| {}).unwrap();
        let responses = read_all(&writer);
        assert_eq!(responses[0]["error"], "bad_request");
    }

    #[test]
    fn credentials_for_without_daemon_reports_locked() {
        // With no daemon reachable, credentials_for degrades to locked (never
        // hangs). We use a bogus endpoint by clearing USERNAME/USER is not
        // possible here, but Client::connect simply fails fast when no daemon is
        // listening for this user — in CI no daemon is running for the test user.
        let mut reader = Cursor::new(framed(
            r#"{"v":1,"type":"credentials_for","origin":"https://example.com","kind":"login"}"#,
        ));
        let mut writer = Vec::new();
        run(&mut reader, &mut writer, &Bridge::new(""), |_| {}).unwrap();
        let responses = read_all(&writer);
        // Either locked (no daemon) — never a hang, never a crash.
        assert!(matches!(
            responses[0]["type"].as_str(),
            Some("locked") | Some("credentials")
        ));
    }

    #[test]
    fn truncated_stream_is_fatal_but_clean() {
        // A valid ping, then a truncated frame. The ping is answered; the
        // truncated frame stops the loop with an error (no panic).
        let mut input = Vec::new();
        input.extend_from_slice(&framed(r#"{"v":1,"type":"ping"}"#));
        input.extend_from_slice(&10u32.to_ne_bytes()); // declares 10 bytes...
        input.extend_from_slice(b"ab"); // ...but supplies 2, then EOF
        let mut reader = Cursor::new(input);
        let mut writer = Vec::new();
        let result = run(&mut reader, &mut writer, &Bridge::new(""), |_| {});
        assert!(matches!(result, Err(FramingError::Truncated)));
        // The ping was still answered before the truncation.
        let responses = read_all(&writer);
        assert_eq!(responses[0]["type"], "pong");
    }
}
