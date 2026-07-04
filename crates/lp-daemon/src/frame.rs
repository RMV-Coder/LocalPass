#![forbid(unsafe_code)]
//! Length-prefixed framing over any byte stream.
//!
//! Both ends speak the same frame: a little-endian `u32` byte length followed
//! by exactly that many bytes of UTF-8 JSON (see [`crate::protocol`]). This
//! module is transport-agnostic — it works over a Unix socket, a Windows named
//! pipe, or an in-memory pipe in tests — because it only needs [`Read`] /
//! [`Write`].
//!
//! A frame whose declared length exceeds [`MAX_FRAME_LEN`] is refused **before**
//! any allocation, so a corrupt or hostile length prefix cannot drive an
//! unbounded allocation.

use std::io::{self, Read, Write};

use crate::error::{Error, Result};
use crate::protocol::{
    MAX_FRAME_LEN, PROTOCOL_VERSION, Request, RequestEnvelope, Response, ResponseEnvelope,
};

/// Write a length-prefixed JSON frame carrying `bytes`.
///
/// # Errors
///
/// [`Error::Io`] on a write failure, or [`Error::FrameTooLarge`] if the body
/// exceeds [`MAX_FRAME_LEN`].
fn write_frame<W: Write>(w: &mut W, bytes: &[u8]) -> Result<()> {
    let len = u32::try_from(bytes.len()).map_err(|_| Error::FrameTooLarge(u64::MAX))?;
    if len > MAX_FRAME_LEN {
        return Err(Error::FrameTooLarge(u64::from(len)));
    }
    w.write_all(&len.to_le_bytes())?;
    w.write_all(bytes)?;
    w.flush()?;
    Ok(())
}

/// Read one length-prefixed JSON frame into a `Vec<u8>`.
///
/// Returns `Ok(None)` on a clean EOF at the frame boundary (the peer closed the
/// connection between messages), which the server treats as "client done".
///
/// # Errors
///
/// [`Error::Io`] on a read failure, [`Error::FrameTooLarge`] if the declared
/// length exceeds [`MAX_FRAME_LEN`], or [`Error::Io`] wrapping an unexpected EOF
/// mid-frame.
fn read_frame<R: Read>(r: &mut R) -> Result<Option<Vec<u8>>> {
    let mut len_buf = [0u8; 4];
    // Read the length prefix, tolerating a clean EOF before any byte arrives.
    match read_exact_or_eof(r, &mut len_buf)? {
        ReadOutcome::Eof => return Ok(None),
        ReadOutcome::Filled => {}
    }
    let len = u32::from_le_bytes(len_buf);
    if len > MAX_FRAME_LEN {
        return Err(Error::FrameTooLarge(u64::from(len)));
    }
    let mut body = vec![0u8; len as usize];
    r.read_exact(&mut body)?;
    Ok(Some(body))
}

/// Outcome of a best-effort exact read that permits EOF only before the first
/// byte.
enum ReadOutcome {
    /// The buffer was filled completely.
    Filled,
    /// A clean EOF occurred before any byte was read.
    Eof,
}

/// Fill `buf` exactly, but map a clean EOF *before the first byte* to
/// [`ReadOutcome::Eof`]. An EOF partway through a prefix is a truncated frame
/// and surfaces as an [`io::ErrorKind::UnexpectedEof`].
fn read_exact_or_eof<R: Read>(r: &mut R, buf: &mut [u8]) -> Result<ReadOutcome> {
    let mut read = 0;
    while read < buf.len() {
        match r.read(&mut buf[read..]) {
            Ok(0) => {
                if read == 0 {
                    return Ok(ReadOutcome::Eof);
                }
                return Err(Error::Io(io::Error::from(io::ErrorKind::UnexpectedEof)));
            }
            Ok(n) => read += n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return Err(Error::Io(e)),
        }
    }
    Ok(ReadOutcome::Filled)
}

/// Write a [`Request`] as a versioned, length-prefixed frame.
///
/// # Errors
///
/// [`Error::Io`], [`Error::Serde`], or [`Error::FrameTooLarge`].
pub fn write_request<W: Write>(w: &mut W, request: &Request) -> Result<()> {
    let env = RequestEnvelope {
        v: PROTOCOL_VERSION,
        // Borrowing would require lifetimes on the envelope; a clone of a
        // small request is fine and keeps the type simple.
        request: request.clone(),
    };
    let bytes = serde_json::to_vec(&env)?;
    write_frame(w, &bytes)
}

/// Read a versioned [`Request`] frame, validating the protocol version.
///
/// Returns `Ok(None)` on a clean EOF at the frame boundary.
///
/// # Errors
///
/// [`Error::Io`], [`Error::Serde`], [`Error::FrameTooLarge`], or
/// [`Error::UnsupportedVersion`] if the envelope `v` is not [`PROTOCOL_VERSION`].
pub fn read_request<R: Read>(r: &mut R) -> Result<Option<Request>> {
    let Some(body) = read_frame(r)? else {
        return Ok(None);
    };
    let env: RequestEnvelope = serde_json::from_slice(&body)?;
    if env.v != PROTOCOL_VERSION {
        return Err(Error::UnsupportedVersion(env.v));
    }
    Ok(Some(env.request))
}

/// Write a [`Response`] as a versioned, length-prefixed frame.
///
/// # Errors
///
/// [`Error::Io`], [`Error::Serde`], or [`Error::FrameTooLarge`].
pub fn write_response<W: Write>(w: &mut W, response: &Response) -> Result<()> {
    let env = ResponseEnvelope {
        v: PROTOCOL_VERSION,
        response: response.clone(),
    };
    let bytes = serde_json::to_vec(&env)?;
    write_frame(w, &bytes)
}

/// Read a versioned [`Response`] frame, validating the protocol version.
///
/// # Errors
///
/// [`Error::Io`], [`Error::Serde`], [`Error::FrameTooLarge`],
/// [`Error::UnsupportedVersion`], or [`Error::Closed`] if the peer closed
/// before sending a response.
pub fn read_response<R: Read>(r: &mut R) -> Result<Response> {
    let Some(body) = read_frame(r)? else {
        return Err(Error::Closed);
    };
    let env: ResponseEnvelope = serde_json::from_slice(&body)?;
    if env.v != PROTOCOL_VERSION {
        return Err(Error::UnsupportedVersion(env.v));
    }
    Ok(env.response)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn request_roundtrips_over_a_buffer() {
        let mut buf = Vec::new();
        write_request(&mut buf, &Request::Ping).unwrap();
        let mut cur = Cursor::new(buf);
        let got = read_request(&mut cur).unwrap().unwrap();
        assert!(matches!(got, Request::Ping));
    }

    #[test]
    fn response_roundtrips_over_a_buffer() {
        let mut buf = Vec::new();
        write_response(&mut buf, &Response::Pong).unwrap();
        let mut cur = Cursor::new(buf);
        let got = read_response(&mut cur).unwrap();
        assert!(matches!(got, Response::Pong));
    }

    #[test]
    fn clean_eof_at_boundary_is_none() {
        let empty: Vec<u8> = Vec::new();
        let mut cur = Cursor::new(empty);
        assert!(read_request(&mut cur).unwrap().is_none());
    }

    #[test]
    fn oversized_length_is_refused_before_allocation() {
        // A length prefix of MAX+1 with no body must be rejected as too large.
        let mut buf = Vec::new();
        buf.extend_from_slice(&(MAX_FRAME_LEN + 1).to_le_bytes());
        let mut cur = Cursor::new(buf);
        match read_request(&mut cur) {
            Err(Error::FrameTooLarge(_)) => {}
            other => panic!("expected FrameTooLarge, got {other:?}"),
        }
    }

    #[test]
    fn truncated_prefix_is_unexpected_eof() {
        // Two bytes of a four-byte prefix, then EOF.
        let mut cur = Cursor::new(vec![1u8, 0u8]);
        match read_request(&mut cur) {
            Err(Error::Io(e)) => assert_eq!(e.kind(), io::ErrorKind::UnexpectedEof),
            other => panic!("expected UnexpectedEof, got {other:?}"),
        }
    }
}
