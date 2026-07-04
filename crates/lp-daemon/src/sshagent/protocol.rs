#![forbid(unsafe_code)]
//! The SSH agent wire protocol (draft-miller-ssh-agent).
//!
//! This module is the **canonical spec** for the agent framing the daemon
//! speaks. It is deliberately separate from the daemon's own JSON IPC
//! ([`crate::protocol`]): that channel is LocalPass's private control protocol,
//! while this one is the *standard* SSH agent protocol that `ssh`/`ssh-add`
//! speak. The daemon serves both, on two different endpoints, from the one
//! process.
//!
//! # Message framing
//!
//! Every agent message is length-prefixed:
//!
//! ```text
//!   u32 length (BIG-endian)  ||  byte message_type  ||  <length-1> bytes payload
//! ```
//!
//! Note the endianness: the SSH agent protocol is **big-endian**, unlike the
//! daemon's little-endian JSON framing. The `length` counts the type byte plus
//! the payload. A message whose declared length exceeds [`MAX_MESSAGE_LEN`] is
//! refused **before** any allocation.
//!
//! # SSH strings
//!
//! Within a payload, a "string" is a `u32` big-endian length followed by that
//! many bytes ([`read_string`] / [`write_string`]). Public-key blobs, signature
//! blobs, and key comments are all encoded this way.
//!
//! # Message types we handle (draft-miller §5.1)
//!
//! | Constant | Value | Direction |
//! |----------|-------|-----------|
//! | [`SSH_AGENTC_REQUEST_IDENTITIES`] | 11 | client → agent |
//! | [`SSH_AGENT_IDENTITIES_ANSWER`]   | 12 | agent → client |
//! | [`SSH_AGENTC_SIGN_REQUEST`]       | 13 | client → agent |
//! | [`SSH_AGENT_SIGN_RESPONSE`]       | 14 | agent → client |
//! | [`SSH_AGENT_FAILURE`]             | 5  | agent → client |
//! | [`SSH_AGENT_SUCCESS`]            | 6  | agent → client |
//!
//! Every other request type (add/remove/lock/…) is answered with
//! [`SSH_AGENT_FAILURE`] — LocalPass is a *read-only, vault-backed* agent: keys
//! live in the vault, not in the agent, so `ssh-add`-style mutation is not
//! supported (and would be meaningless).
//!
//! # Signature flags (draft-miller §5.3)
//!
//! [`SSH_AGENTC_SIGN_REQUEST`] carries a `u32` flags word. For RSA keys the
//! client may set [`SSH_AGENT_RSA_SHA2_256`] or [`SSH_AGENT_RSA_SHA2_512`] to
//! request the modern `rsa-sha2-256` / `rsa-sha2-512` signature algorithms
//! instead of legacy SHA-1 `ssh-rsa`. We honor these (and default to
//! SHA-512 — never SHA-1 — when neither is set).

use std::io::{self, Read, Write};

/// `SSH_AGENTC_REQUEST_IDENTITIES` — list the identities the agent holds.
pub const SSH_AGENTC_REQUEST_IDENTITIES: u8 = 11;
/// `SSH_AGENT_IDENTITIES_ANSWER` — the identity list reply.
pub const SSH_AGENT_IDENTITIES_ANSWER: u8 = 12;
/// `SSH_AGENTC_SIGN_REQUEST` — sign a challenge with a held key.
pub const SSH_AGENTC_SIGN_REQUEST: u8 = 13;
/// `SSH_AGENT_SIGN_RESPONSE` — the signature reply.
pub const SSH_AGENT_SIGN_RESPONSE: u8 = 14;
/// `SSH_AGENT_FAILURE` — generic failure (also the answer to unsupported ops).
pub const SSH_AGENT_FAILURE: u8 = 5;
/// `SSH_AGENT_SUCCESS` — generic success (unused by our read-only agent, but
/// defined for completeness of the protocol surface).
pub const SSH_AGENT_SUCCESS: u8 = 6;

/// Sign-request flag: produce an `rsa-sha2-256` signature (RSA keys only).
pub const SSH_AGENT_RSA_SHA2_256: u32 = 0x02;
/// Sign-request flag: produce an `rsa-sha2-512` signature (RSA keys only).
pub const SSH_AGENT_RSA_SHA2_512: u32 = 0x04;

/// Maximum accepted agent message length (256 KiB). Generous for any realistic
/// identity list or sign request, but a hard ceiling so a hostile or corrupt
/// length prefix cannot force an unbounded allocation. Applied on read.
pub const MAX_MESSAGE_LEN: u32 = 256 * 1024;

/// A parsed agent request (only the message types we act on; everything else is
/// mapped to [`Request::Unsupported`] carrying its type byte).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Request {
    /// `SSH_AGENTC_REQUEST_IDENTITIES`: no payload.
    RequestIdentities,
    /// `SSH_AGENTC_SIGN_REQUEST`: `string key_blob || string data || u32 flags`.
    SignRequest {
        /// The public-key blob identifying which held key to sign with.
        key_blob: Vec<u8>,
        /// The data to sign (the SSH transport's signed session data).
        data: Vec<u8>,
        /// The signature flags ([`SSH_AGENT_RSA_SHA2_256`] / `_512`).
        flags: u32,
    },
    /// Any other request type (add/remove/lock/…): unsupported, answered with
    /// [`SSH_AGENT_FAILURE`]. Carries the original type byte for diagnostics.
    Unsupported(u8),
}

impl Request {
    /// A short, non-secret label for `--verbose` logging.
    #[must_use]
    pub fn kind(&self) -> &'static str {
        match self {
            Request::RequestIdentities => "RequestIdentities",
            Request::SignRequest { .. } => "SignRequest",
            Request::Unsupported(_) => "Unsupported",
        }
    }
}

/// One identity in an `SSH_AGENT_IDENTITIES_ANSWER`: a public-key blob and a
/// human comment (LocalPass uses the item title as the comment).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Identity {
    /// The public-key blob (`string` payload in the answer).
    pub key_blob: Vec<u8>,
    /// The key comment (the vault item title).
    pub comment: String,
}

/// Read one big-endian `u32`.
fn read_u32<R: Read>(r: &mut R) -> io::Result<u32> {
    let mut b = [0u8; 4];
    r.read_exact(&mut b)?;
    Ok(u32::from_be_bytes(b))
}

/// Read an SSH `string`: a big-endian `u32` length then that many bytes.
///
/// The length is bounded by [`MAX_MESSAGE_LEN`] so a corrupt inner length cannot
/// drive an unbounded allocation even within an already-read message body.
///
/// # Errors
///
/// [`io::Error`] on a short read or an over-long declared length.
pub fn read_string<R: Read>(r: &mut R) -> io::Result<Vec<u8>> {
    let len = read_u32(r)?;
    if len > MAX_MESSAGE_LEN {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "ssh string length exceeds maximum",
        ));
    }
    let mut buf = vec![0u8; len as usize];
    r.read_exact(&mut buf)?;
    Ok(buf)
}

/// Write an SSH `string`: a big-endian `u32` length then the bytes.
///
/// # Errors
///
/// [`io::Error`] on a write failure.
pub fn write_string<W: Write>(w: &mut W, bytes: &[u8]) -> io::Result<()> {
    let len = u32::try_from(bytes.len())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "ssh string too long"))?;
    w.write_all(&len.to_be_bytes())?;
    w.write_all(bytes)?;
    Ok(())
}

/// Read one framed agent message off `r`, returning its type byte and payload.
///
/// Returns `Ok(None)` on a clean EOF at the message boundary (the client closed
/// the connection between messages).
///
/// # Errors
///
/// [`io::Error`] on a read failure, an over-long declared length, or a truncated
/// frame.
pub fn read_message<R: Read>(r: &mut R) -> io::Result<Option<(u8, Vec<u8>)>> {
    let mut len_buf = [0u8; 4];
    // Tolerate a clean EOF before the first byte of the length prefix.
    match read_full_or_eof(r, &mut len_buf)? {
        FillOutcome::Eof => return Ok(None),
        FillOutcome::Filled => {}
    }
    let len = u32::from_be_bytes(len_buf);
    if len == 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "ssh agent message length is zero",
        ));
    }
    if len > MAX_MESSAGE_LEN {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "ssh agent message length exceeds maximum",
        ));
    }
    // length counts the type byte + payload.
    let mut body = vec![0u8; len as usize];
    r.read_exact(&mut body)?;
    let msg_type = body[0];
    let payload = body[1..].to_vec();
    Ok(Some((msg_type, payload)))
}

/// Parse a `(type, payload)` pair into a [`Request`].
///
/// A malformed [`SSH_AGENTC_SIGN_REQUEST`] payload (truncated fields) is reported
/// as an error so the caller answers with [`SSH_AGENT_FAILURE`] rather than
/// mis-signing.
///
/// # Errors
///
/// [`io::Error`] if a sign request's payload is malformed.
pub fn parse_request(msg_type: u8, payload: &[u8]) -> io::Result<Request> {
    match msg_type {
        SSH_AGENTC_REQUEST_IDENTITIES => Ok(Request::RequestIdentities),
        SSH_AGENTC_SIGN_REQUEST => {
            let mut cur = io::Cursor::new(payload);
            let key_blob = read_string(&mut cur)?;
            let data = read_string(&mut cur)?;
            let flags = read_u32(&mut cur)?;
            Ok(Request::SignRequest {
                key_blob,
                data,
                flags,
            })
        }
        other => Ok(Request::Unsupported(other)),
    }
}

/// Read one message and parse it in a single call.
///
/// Returns `Ok(None)` on a clean EOF at the boundary.
///
/// # Errors
///
/// [`io::Error`] on a read or parse failure.
pub fn read_request<R: Read>(r: &mut R) -> io::Result<Option<Request>> {
    match read_message(r)? {
        None => Ok(None),
        Some((msg_type, payload)) => Ok(Some(parse_request(msg_type, &payload)?)),
    }
}

/// Frame and write one agent message: `u32 len || type || payload`.
///
/// # Errors
///
/// [`io::Error`] on a write failure or an over-long payload.
pub fn write_message<W: Write>(w: &mut W, msg_type: u8, payload: &[u8]) -> io::Result<()> {
    let len = u32::try_from(payload.len() + 1)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "agent message too long"))?;
    w.write_all(&len.to_be_bytes())?;
    w.write_all(&[msg_type])?;
    w.write_all(payload)?;
    w.flush()?;
    Ok(())
}

/// Write an `SSH_AGENT_IDENTITIES_ANSWER`: `u32 count || (string blob || string
/// comment)*`.
///
/// # Errors
///
/// [`io::Error`] on a write failure.
pub fn write_identities_answer<W: Write>(w: &mut W, identities: &[Identity]) -> io::Result<()> {
    let mut payload = Vec::new();
    let count = u32::try_from(identities.len())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "too many identities"))?;
    payload.extend_from_slice(&count.to_be_bytes());
    for id in identities {
        write_string(&mut payload, &id.key_blob)?;
        write_string(&mut payload, id.comment.as_bytes())?;
    }
    write_message(w, SSH_AGENT_IDENTITIES_ANSWER, &payload)
}

/// Write an `SSH_AGENT_SIGN_RESPONSE`: `string signature`.
///
/// The `signature` blob is itself the OpenSSH signature encoding
/// (`string algorithm || string signature-data`), produced by [`crate::sshagent::keys`].
///
/// # Errors
///
/// [`io::Error`] on a write failure.
pub fn write_sign_response<W: Write>(w: &mut W, signature: &[u8]) -> io::Result<()> {
    let mut payload = Vec::new();
    write_string(&mut payload, signature)?;
    write_message(w, SSH_AGENT_SIGN_RESPONSE, &payload)
}

/// Write a bare `SSH_AGENT_FAILURE` (empty payload).
///
/// # Errors
///
/// [`io::Error`] on a write failure.
pub fn write_failure<W: Write>(w: &mut W) -> io::Result<()> {
    write_message(w, SSH_AGENT_FAILURE, &[])
}

/// The outcome of a best-effort exact read that permits EOF only before the
/// first byte.
enum FillOutcome {
    Filled,
    Eof,
}

/// Fill `buf` exactly, mapping a clean EOF *before the first byte* to
/// [`FillOutcome::Eof`]; an EOF partway through is a truncated frame.
fn read_full_or_eof<R: Read>(r: &mut R, buf: &mut [u8]) -> io::Result<FillOutcome> {
    let mut read = 0;
    while read < buf.len() {
        match r.read(&mut buf[read..]) {
            Ok(0) => {
                if read == 0 {
                    return Ok(FillOutcome::Eof);
                }
                return Err(io::Error::from(io::ErrorKind::UnexpectedEof));
            }
            Ok(n) => read += n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }
    Ok(FillOutcome::Filled)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn string_roundtrips() {
        let mut buf = Vec::new();
        write_string(&mut buf, b"ssh-ed25519").unwrap();
        let mut cur = Cursor::new(buf);
        assert_eq!(read_string(&mut cur).unwrap(), b"ssh-ed25519");
    }

    #[test]
    fn request_identities_roundtrips() {
        let mut buf = Vec::new();
        write_message(&mut buf, SSH_AGENTC_REQUEST_IDENTITIES, &[]).unwrap();
        let mut cur = Cursor::new(buf);
        let req = read_request(&mut cur).unwrap().unwrap();
        assert_eq!(req, Request::RequestIdentities);
    }

    #[test]
    fn sign_request_roundtrips() {
        // Build a sign-request payload by hand: string blob || string data || u32 flags.
        let mut payload = Vec::new();
        write_string(&mut payload, b"the-key-blob").unwrap();
        write_string(&mut payload, b"data-to-sign").unwrap();
        payload.extend_from_slice(&SSH_AGENT_RSA_SHA2_256.to_be_bytes());
        let mut framed = Vec::new();
        write_message(&mut framed, SSH_AGENTC_SIGN_REQUEST, &payload).unwrap();

        let mut cur = Cursor::new(framed);
        let req = read_request(&mut cur).unwrap().unwrap();
        assert_eq!(
            req,
            Request::SignRequest {
                key_blob: b"the-key-blob".to_vec(),
                data: b"data-to-sign".to_vec(),
                flags: SSH_AGENT_RSA_SHA2_256,
            }
        );
    }

    #[test]
    fn unknown_type_is_unsupported() {
        let mut buf = Vec::new();
        write_message(&mut buf, 99, &[1, 2, 3]).unwrap();
        let mut cur = Cursor::new(buf);
        let req = read_request(&mut cur).unwrap().unwrap();
        assert_eq!(req, Request::Unsupported(99));
    }

    #[test]
    fn identities_answer_roundtrips() {
        let ids = vec![
            Identity {
                key_blob: b"blobA".to_vec(),
                comment: "my ed25519".into(),
            },
            Identity {
                key_blob: b"blobB".to_vec(),
                comment: "work rsa".into(),
            },
        ];
        let mut buf = Vec::new();
        write_identities_answer(&mut buf, &ids).unwrap();

        // Parse it back: message type + count + entries.
        let mut cur = Cursor::new(buf);
        let (ty, payload) = read_message(&mut cur).unwrap().unwrap();
        assert_eq!(ty, SSH_AGENT_IDENTITIES_ANSWER);
        let mut pc = Cursor::new(payload);
        let count = read_u32(&mut pc).unwrap();
        assert_eq!(count, 2);
        let b0 = read_string(&mut pc).unwrap();
        let c0 = String::from_utf8(read_string(&mut pc).unwrap()).unwrap();
        assert_eq!(b0, b"blobA");
        assert_eq!(c0, "my ed25519");
        let b1 = read_string(&mut pc).unwrap();
        let c1 = String::from_utf8(read_string(&mut pc).unwrap()).unwrap();
        assert_eq!(b1, b"blobB");
        assert_eq!(c1, "work rsa");
    }

    #[test]
    fn empty_identities_answer_is_count_zero() {
        let mut buf = Vec::new();
        write_identities_answer(&mut buf, &[]).unwrap();
        let mut cur = Cursor::new(buf);
        let (ty, payload) = read_message(&mut cur).unwrap().unwrap();
        assert_eq!(ty, SSH_AGENT_IDENTITIES_ANSWER);
        assert_eq!(payload, 0u32.to_be_bytes());
    }

    #[test]
    fn clean_eof_at_boundary_is_none() {
        let empty: Vec<u8> = Vec::new();
        let mut cur = Cursor::new(empty);
        assert!(read_request(&mut cur).unwrap().is_none());
    }

    #[test]
    fn oversized_length_is_refused() {
        let mut buf = Vec::new();
        buf.extend_from_slice(&(MAX_MESSAGE_LEN + 1).to_be_bytes());
        let mut cur = Cursor::new(buf);
        let err = read_message(&mut cur).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn zero_length_is_refused() {
        let mut buf = Vec::new();
        buf.extend_from_slice(&0u32.to_be_bytes());
        let mut cur = Cursor::new(buf);
        let err = read_message(&mut cur).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn failure_message_is_wellformed() {
        let mut buf = Vec::new();
        write_failure(&mut buf).unwrap();
        let mut cur = Cursor::new(buf);
        let (ty, payload) = read_message(&mut cur).unwrap().unwrap();
        assert_eq!(ty, SSH_AGENT_FAILURE);
        assert!(payload.is_empty());
    }

    #[test]
    fn truncated_sign_request_is_error() {
        // A sign request whose payload is too short to hold even the first string.
        let payload = vec![0u8, 0u8, 0u8, 10u8]; // claims 10 bytes but none follow
        let err = parse_request(SSH_AGENTC_SIGN_REQUEST, &payload).unwrap_err();
        assert!(matches!(
            err.kind(),
            io::ErrorKind::UnexpectedEof | io::ErrorKind::InvalidData
        ));
    }
}
