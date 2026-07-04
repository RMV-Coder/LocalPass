#![forbid(unsafe_code)]
//! Chrome/Firefox **native-messaging** stdio framing.
//!
//! The browser and the native host exchange messages over the host process's
//! stdin/stdout. Each message is:
//!
//! ```text
//!   u32 length prefix (NATIVE byte order)  ||  <length> bytes of UTF-8 JSON
//! ```
//!
//! # Byte order (the subtle part)
//!
//! The native-messaging protocol specifies the length prefix is in the **native
//! byte order of the host machine** — not a fixed endianness like the daemon IPC
//! ([`lp_daemon::frame`], which is little-endian). Chromium reads/writes the
//! prefix with the platform's native `uint32`, and Firefox matches it. We honor
//! that here with [`u32::to_ne_bytes`] / [`u32::from_ne_bytes`]. On the
//! little-endian x86/ARM targets LocalPass ships, native order *is* little-endian,
//! but we use the native accessors so a big-endian target would still be correct
//! by construction and to match the spec verbatim.
//!
//! # Size cap (Chrome limit)
//!
//! Chrome caps a single message the extension sends to the host at **1 MiB**
//! ([`MAX_INBOUND_LEN`]). A larger declared length is refused **before**
//! allocation — a corrupt or hostile prefix cannot drive an unbounded allocation.
//! (Chrome also caps host→browser messages at 1 MiB; our responses are tiny
//! credential descriptors, far under that, so we do not cap the write side, but a
//! response is small by construction.)
//!
//! # EOF handling
//!
//! A clean EOF at a message boundary (the browser closed the port / the extension
//! was unloaded) is reported as `Ok(None)` from [`read_message`], which the host
//! loop treats as "exit cleanly". An EOF partway through a prefix or body is a
//! truncated frame and surfaces as [`FramingError::Truncated`] — handled without
//! a panic.

use std::io::{self, Read, Write};

use thiserror::Error;

/// The maximum length (bytes) of a single message the extension may send to the
/// host: **1 MiB**, matching Chrome's native-messaging inbound cap. A declared
/// length above this is rejected before any allocation.
pub const MAX_INBOUND_LEN: u32 = 1024 * 1024;

/// A native-messaging framing error. No variant carries message contents (a body
/// may contain an origin or item id; never a secret at the framing layer — but we
/// keep messages content-free regardless so logs are always safe).
#[derive(Debug, Error)]
pub enum FramingError {
    /// An IO failure reading or writing the stdio stream.
    #[error("native-messaging io error: {0}")]
    Io(#[from] io::Error),

    /// The declared inbound length exceeded [`MAX_INBOUND_LEN`].
    #[error("native-messaging frame too large: {0} bytes (cap {MAX_INBOUND_LEN})")]
    TooLarge(u32),

    /// EOF arrived partway through a length prefix or body (a truncated frame).
    #[error("native-messaging frame truncated")]
    Truncated,
}

/// The framing result alias.
pub type Result<T> = std::result::Result<T, FramingError>;

/// Read one native-messaging message body (the raw JSON bytes) from `r`.
///
/// Returns `Ok(None)` on a clean EOF at the message boundary (the port closed).
///
/// # Errors
///
/// [`FramingError::TooLarge`] if the declared length exceeds [`MAX_INBOUND_LEN`],
/// [`FramingError::Truncated`] on a mid-frame EOF, or [`FramingError::Io`] on any
/// other read failure.
pub fn read_message<R: Read>(r: &mut R) -> Result<Option<Vec<u8>>> {
    let mut len_buf = [0u8; 4];
    match read_exact_or_eof(r, &mut len_buf)? {
        // Clean EOF at the boundary: the port closed. Exit cleanly.
        ReadOutcome::Eof => return Ok(None),
        // EOF partway through the 4-byte prefix: a truncated frame.
        ReadOutcome::PartialEof => return Err(FramingError::Truncated),
        ReadOutcome::Filled => {}
    }
    // NATIVE byte order per the native-messaging spec.
    let len = u32::from_ne_bytes(len_buf);
    if len > MAX_INBOUND_LEN {
        return Err(FramingError::TooLarge(len));
    }
    if len == 0 {
        return Ok(Some(Vec::new()));
    }
    let mut body = vec![0u8; len as usize];
    match read_exact_or_eof(r, &mut body)? {
        ReadOutcome::Filled => Ok(Some(body)),
        // Any EOF before the declared body is fully read is a truncated frame.
        ReadOutcome::Eof | ReadOutcome::PartialEof => Err(FramingError::Truncated),
    }
}

/// Write one native-messaging message body to `w` with its native-endian length
/// prefix, then flush.
///
/// # Errors
///
/// [`FramingError::TooLarge`] if `body` is longer than `u32::MAX` (never in
/// practice), or [`FramingError::Io`] on a write failure.
pub fn write_message<W: Write>(w: &mut W, body: &[u8]) -> Result<()> {
    let len = u32::try_from(body.len()).map_err(|_| FramingError::TooLarge(u32::MAX))?;
    // NATIVE byte order per the native-messaging spec.
    w.write_all(&len.to_ne_bytes())?;
    w.write_all(body)?;
    w.flush()?;
    Ok(())
}

/// The outcome of a best-effort exact read.
enum ReadOutcome {
    /// The buffer was filled completely.
    Filled,
    /// A clean EOF occurred **before any byte** of this buffer was read.
    Eof,
    /// EOF occurred **after** at least one byte but before the buffer was full
    /// (a truncated frame).
    PartialEof,
}

/// Fill `buf` exactly, distinguishing a clean EOF before the first byte
/// ([`ReadOutcome::Eof`]) from a mid-buffer EOF ([`ReadOutcome::PartialEof`]) so
/// the caller can tell a closed port from a truncated frame. Never panics.
fn read_exact_or_eof<R: Read>(r: &mut R, buf: &mut [u8]) -> Result<ReadOutcome> {
    let mut read = 0;
    while read < buf.len() {
        match r.read(&mut buf[read..]) {
            Ok(0) => {
                return Ok(if read == 0 {
                    ReadOutcome::Eof
                } else {
                    ReadOutcome::PartialEof
                });
            }
            Ok(n) => read += n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return Err(FramingError::Io(e)),
        }
    }
    Ok(ReadOutcome::Filled)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    /// Frame a body the way the browser would (native-endian length + bytes).
    fn framed(body: &[u8]) -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(&(body.len() as u32).to_ne_bytes());
        v.extend_from_slice(body);
        v
    }

    #[test]
    fn roundtrip_native_endian() {
        let body = br#"{"v":1,"type":"ping"}"#;
        let mut out = Vec::new();
        write_message(&mut out, body).unwrap();
        // The prefix is native-endian.
        assert_eq!(&out[..4], &(body.len() as u32).to_ne_bytes());
        let mut cur = Cursor::new(out);
        let got = read_message(&mut cur).unwrap().unwrap();
        assert_eq!(got, body);
    }

    #[test]
    fn clean_eof_at_boundary_is_none() {
        let mut cur = Cursor::new(Vec::<u8>::new());
        assert!(read_message(&mut cur).unwrap().is_none());
    }

    #[test]
    fn oversized_is_refused_before_allocation() {
        let mut buf = Vec::new();
        buf.extend_from_slice(&(MAX_INBOUND_LEN + 1).to_ne_bytes());
        // No body bytes at all — must reject on the length alone.
        let mut cur = Cursor::new(buf);
        match read_message(&mut cur) {
            Err(FramingError::TooLarge(n)) => assert_eq!(n, MAX_INBOUND_LEN + 1),
            other => panic!("expected TooLarge, got {other:?}"),
        }
    }

    #[test]
    fn exactly_at_cap_is_allowed() {
        // A body exactly MAX_INBOUND_LEN is accepted (cap is inclusive).
        let body = vec![b'x'; MAX_INBOUND_LEN as usize];
        let mut cur = Cursor::new(framed(&body));
        let got = read_message(&mut cur).unwrap().unwrap();
        assert_eq!(got.len(), MAX_INBOUND_LEN as usize);
    }

    #[test]
    fn truncated_prefix_is_truncated_error() {
        // Two of four prefix bytes, then EOF.
        let mut cur = Cursor::new(vec![1u8, 0u8]);
        match read_message(&mut cur) {
            Err(FramingError::Truncated) => {}
            other => panic!("expected Truncated, got {other:?}"),
        }
    }

    #[test]
    fn truncated_body_is_truncated_error() {
        // Declares 10 bytes but only supplies 3.
        let mut buf = Vec::new();
        buf.extend_from_slice(&10u32.to_ne_bytes());
        buf.extend_from_slice(b"abc");
        let mut cur = Cursor::new(buf);
        match read_message(&mut cur) {
            Err(FramingError::Truncated) => {}
            other => panic!("expected Truncated, got {other:?}"),
        }
    }

    #[test]
    fn zero_length_body_is_ok() {
        let mut cur = Cursor::new(0u32.to_ne_bytes().to_vec());
        let got = read_message(&mut cur).unwrap().unwrap();
        assert!(got.is_empty());
    }
}
