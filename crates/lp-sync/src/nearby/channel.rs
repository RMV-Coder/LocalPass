//! The authenticated channel: stream framing with deadlines, the Noise XX
//! handshake with identity proofs, and the record layer
//! (`lan-transport.md` §3–§5).

use std::io::ErrorKind;
use std::time::{Duration, Instant};

use lp_crypto::noise::{
    HANDSHAKE_HASH_LEN, MAX_NOISE_MESSAGE_LEN, MAX_TRANSPORT_PLAINTEXT_LEN, NOISE_STATIC_KEY_LEN,
};
use lp_crypto::sign::CONTEXT_LAN_HANDSHAKE;
use lp_crypto::{NoiseHandshake, NoiseTransport, VerifyingKey};
use lp_vault::ids::{DeviceId, Id};
use lp_vault::{PeerDevice, Session};

use super::message::{self, MESSAGE_HEADER_LEN};
use super::{Limits, Local, MAX_HANDSHAKE_MESSAGE, Role, Stream};
use crate::error::{Error, Refusal, Result};

/// The Noise prologue: both sides must use the same bytes, so it carries the
/// protocol version (`lan-transport.md` §4.1).
pub const PROLOGUE: &[u8] = b"localpass/v1/lan-sync/1";

/// The identity proof carried in handshake messages 2 and 3:
/// `device_id (16) || signature (64)`.
const PROOF_LEN: usize = 16 + 64;

/// The role byte signed into an initiator's proof.
const ROLE_INITIATOR: u8 = 0x01;
/// The role byte signed into a responder's proof.
const ROLE_RESPONDER: u8 = 0x02;

/// The finest granularity a deadline is checked at while a read or write is
/// blocked.
const POLL: Duration = Duration::from_millis(250);

/// A local `lp-crypto` failure (RNG, Noise state misuse) — never a peer's
/// doing, so it surfaces like any other crypto error from the storage layer.
fn crypto(e: lp_crypto::Error) -> Error {
    Error::Vault(lp_vault::Error::Crypto(e))
}

// --- Stream I/O under a deadline --------------------------------------------

/// Time left before `deadline`, or a timeout error.
fn remaining(deadline: Instant, what: &'static str) -> Result<Duration> {
    let left = deadline.saturating_duration_since(Instant::now());
    if left.is_zero() {
        return Err(Error::Timeout(what));
    }
    Ok(left)
}

/// Fill `buf` before `deadline`. `Ok(false)` means the stream ended before the
/// first byte (a clean close at a frame boundary); a close after it is an
/// error.
fn read_exact_by<S: Stream>(
    stream: &mut S,
    buf: &mut [u8],
    deadline: Instant,
    what: &'static str,
) -> Result<bool> {
    let mut filled = 0;
    while filled < buf.len() {
        let wait = remaining(deadline, what)?.min(POLL);
        stream.set_read_timeout(Some(wait))?;
        match stream.read(&mut buf[filled..]) {
            Ok(0) if filled == 0 => return Ok(false),
            Ok(0) => return Err(Error::Protocol("the stream ended inside a frame")),
            Ok(n) => filled += n,
            Err(e)
                if matches!(
                    e.kind(),
                    ErrorKind::WouldBlock | ErrorKind::TimedOut | ErrorKind::Interrupted
                ) => {}
            Err(e)
                if filled == 0
                    && matches!(
                        e.kind(),
                        ErrorKind::ConnectionReset
                            | ErrorKind::ConnectionAborted
                            | ErrorKind::UnexpectedEof
                    ) =>
            {
                return Ok(false);
            }
            Err(e) => return Err(Error::Io(e)),
        }
    }
    Ok(true)
}

/// Write all of `buf` before `deadline`.
fn write_all_by<S: Stream>(
    stream: &mut S,
    buf: &[u8],
    deadline: Instant,
    what: &'static str,
) -> Result<()> {
    let mut sent = 0;
    while sent < buf.len() {
        let wait = remaining(deadline, what)?.min(POLL);
        stream.set_write_timeout(Some(wait))?;
        match stream.write(&buf[sent..]) {
            Ok(0) => return Err(Error::Protocol("the peer stopped reading")),
            Ok(n) => sent += n,
            Err(e)
                if matches!(
                    e.kind(),
                    ErrorKind::WouldBlock | ErrorKind::TimedOut | ErrorKind::Interrupted
                ) => {}
            Err(e) => return Err(Error::Io(e)),
        }
    }
    loop {
        match stream.flush() {
            Ok(()) => return Ok(()),
            Err(e) if e.kind() == ErrorKind::Interrupted => {}
            Err(e) => return Err(Error::Io(e)),
        }
    }
}

/// Read one `u16 BE length || noise message` frame of at most `cap` bytes.
/// `Ok(None)` is a clean close before the frame. The length is checked before
/// the body is read or allocated.
pub(super) fn read_noise_frame<S: Stream>(
    stream: &mut S,
    cap: usize,
    deadline: Instant,
    what: &'static str,
) -> Result<Option<Vec<u8>>> {
    let mut len = [0u8; 2];
    if !read_exact_by(stream, &mut len, deadline, what)? {
        return Ok(None);
    }
    let len = usize::from(u16::from_be_bytes(len));
    if len == 0 {
        return Err(Error::Protocol("empty noise frame"));
    }
    if len > cap {
        return Err(Error::Protocol("noise frame exceeds its size limit"));
    }
    let mut body = vec![0u8; len];
    if !read_exact_by(stream, &mut body, deadline, what)? {
        return Err(Error::Protocol("the stream ended inside a frame"));
    }
    Ok(Some(body))
}

/// Write one `u16 BE length || noise message` frame.
pub(super) fn write_noise_frame<S: Stream>(
    stream: &mut S,
    message: &[u8],
    deadline: Instant,
    what: &'static str,
) -> Result<()> {
    let len = u16::try_from(message.len())
        .map_err(|_| Error::Protocol("noise message too long for one frame"))?;
    let mut frame = Vec::with_capacity(2 + message.len());
    frame.extend_from_slice(&len.to_be_bytes());
    frame.extend_from_slice(message);
    write_all_by(stream, &frame, deadline, what)
}

// --- Identity proofs (§3.1, §4.3) -------------------------------------------

/// The signed proof body: `role || h || s`.
fn proof_message(
    role: u8,
    h: &[u8; HANDSHAKE_HASH_LEN],
    noise_static: &[u8; NOISE_STATIC_KEY_LEN],
) -> Vec<u8> {
    let mut m = Vec::with_capacity(1 + HANDSHAKE_HASH_LEN + NOISE_STATIC_KEY_LEN);
    m.push(role);
    m.extend_from_slice(h);
    m.extend_from_slice(noise_static);
    m
}

/// Build this device's proof for its next handshake message.
fn make_proof(
    session: &Session,
    role: u8,
    h: &[u8; HANDSHAKE_HASH_LEN],
    noise_static: &[u8; NOISE_STATIC_KEY_LEN],
) -> Result<Vec<u8>> {
    let signature = session.sign_lan_handshake(&proof_message(role, h, noise_static))?;
    let mut proof = Vec::with_capacity(PROOF_LEN);
    proof.extend_from_slice(session.device_id().as_bytes());
    proof.extend_from_slice(&signature);
    Ok(proof)
}

/// Check a peer's proof (`lan-transport.md` §4.4 steps 2–5) and return the
/// pinned peer it authenticates.
fn verify_proof(
    session: &Session,
    payload: &[u8],
    role: u8,
    h: &[u8; HANDSHAKE_HASH_LEN],
    noise_static: &[u8; NOISE_STATIC_KEY_LEN],
    expected_peer: Option<DeviceId>,
) -> Result<PeerDevice> {
    if payload.len() != PROOF_LEN {
        return Err(Error::Refused(Refusal::BadProof));
    }
    let device_id: DeviceId = Id::from_bytes(payload[..16].try_into().expect("16 bytes"));
    let signature: [u8; 64] = payload[16..].try_into().expect("64 bytes");
    if device_id == session.device_id() {
        return Err(Error::Refused(Refusal::OwnIdentity));
    }
    let Some(peer) = session.peer_device(&device_id)? else {
        return Err(Error::Refused(Refusal::UntrustedPeer));
    };
    if expected_peer.is_some_and(|e| e != device_id) {
        return Err(Error::Refused(Refusal::UnexpectedPeer));
    }
    let key = VerifyingKey::from_bytes(&peer.ed25519_pub)
        .map_err(|_| Error::Refused(Refusal::BadProof))?;
    key.verify(
        CONTEXT_LAN_HANDSHAKE,
        &proof_message(role, h, noise_static),
        &signature,
    )
    .map_err(|_| Error::Refused(Refusal::BadProof))?;
    Ok(peer)
}

/// Read the next handshake message; a close or a failed decrypt is a refusal.
fn read_handshake<S: Stream>(
    stream: &mut S,
    hs: &mut NoiseHandshake,
    deadline: Instant,
) -> Result<Vec<u8>> {
    let frame = read_noise_frame(stream, MAX_HANDSHAKE_MESSAGE, deadline, "handshake")?
        .ok_or(Error::Refused(Refusal::PeerClosed))?;
    hs.read_message(&frame)
        .map_err(|_| Error::Refused(Refusal::HandshakeFailed))
}

/// Write the next handshake message.
fn write_handshake<S: Stream>(
    stream: &mut S,
    hs: &mut NoiseHandshake,
    payload: &[u8],
    deadline: Instant,
) -> Result<()> {
    let message = hs
        .write_message(payload)
        .map_err(|_| Error::Refused(Refusal::HandshakeFailed))?;
    write_noise_frame(stream, &message, deadline, "handshake")
}

/// Run the Noise XX handshake as `role` and authenticate the peer against
/// `peer_devices` (`lan-transport.md` §4). Returns the transport and the
/// pinned peer; nothing past the handshake has been read.
pub(super) fn handshake<S: Stream, L: Local>(
    stream: &mut S,
    role: Role,
    local: &L,
    expected_peer: Option<DeviceId>,
    limits: &Limits,
) -> Result<(NoiseTransport, PeerDevice)> {
    let deadline = Instant::now() + limits.handshake_timeout;
    match role {
        Role::Initiator => {
            let mut hs = NoiseHandshake::initiator(PROLOGUE).map_err(crypto)?;
            // -> e
            write_handshake(stream, &mut hs, &[], deadline)?;
            let h1 = hs.handshake_hash();
            // <- e, ee, s, es + responder proof
            let proof = read_handshake(stream, &mut hs, deadline)?;
            let rs = hs
                .remote_static_public()
                .ok_or(Error::Refused(Refusal::HandshakeFailed))?;
            let peer = local.with_session(|s| {
                verify_proof(s, &proof, ROLE_RESPONDER, &h1, &rs, expected_peer)
            })?;
            // The responder is authenticated; only now reveal this device.
            let h2 = hs.handshake_hash();
            let me = hs.local_static_public();
            let mine = local.with_session(|s| make_proof(s, ROLE_INITIATOR, &h2, &me))?;
            // -> s, se + initiator proof
            write_handshake(stream, &mut hs, &mine, deadline)?;
            Ok((hs.into_transport().map_err(crypto)?, peer))
        }
        Role::Responder => {
            let mut hs = NoiseHandshake::responder(PROLOGUE).map_err(crypto)?;
            // -> e (payload must be empty)
            let payload = read_handshake(stream, &mut hs, deadline)?;
            if !payload.is_empty() {
                return Err(Error::Refused(Refusal::HandshakeFailed));
            }
            let h1 = hs.handshake_hash();
            let me = hs.local_static_public();
            let mine = local.with_session(|s| make_proof(s, ROLE_RESPONDER, &h1, &me))?;
            // <- e, ee, s, es + responder proof
            write_handshake(stream, &mut hs, &mine, deadline)?;
            let h2 = hs.handshake_hash();
            // -> s, se + initiator proof
            let proof = read_handshake(stream, &mut hs, deadline)?;
            let rs = hs
                .remote_static_public()
                .ok_or(Error::Refused(Refusal::HandshakeFailed))?;
            let peer = local.with_session(|s| {
                verify_proof(s, &proof, ROLE_INITIATOR, &h2, &rs, expected_peer)
            })?;
            Ok((hs.into_transport().map_err(crypto)?, peer))
        }
    }
}

// --- Record layer (§5.2) -----------------------------------------------------

/// An authenticated link: the stream plus the Noise transport.
pub(super) struct SecureChannel<S> {
    stream: S,
    transport: NoiseTransport,
    record_timeout: Duration,
}

impl<S: Stream> SecureChannel<S> {
    pub(super) fn new(stream: S, transport: NoiseTransport, limits: &Limits) -> Self {
        Self {
            stream,
            transport,
            record_timeout: limits.record_timeout,
        }
    }

    fn deadline(&self) -> Instant {
        Instant::now() + self.record_timeout
    }

    /// Encrypt and write one record.
    fn send_record(&mut self, plaintext: &[u8]) -> Result<()> {
        let record = self.transport.encrypt(plaintext).map_err(crypto)?;
        let deadline = self.deadline();
        write_noise_frame(&mut self.stream, &record, deadline, "sending to the peer")
    }

    /// Read and decrypt one record; `Ok(None)` on a clean close.
    fn recv_record(&mut self) -> Result<Option<Vec<u8>>> {
        let deadline = self.deadline();
        let Some(frame) = read_noise_frame(
            &mut self.stream,
            MAX_NOISE_MESSAGE_LEN,
            deadline,
            "waiting for the peer",
        )?
        else {
            return Ok(None);
        };
        self.transport
            .decrypt(&frame)
            .map(Some)
            .map_err(|_| Error::Protocol("a record failed to authenticate"))
    }

    /// Send one application message, split into records (`type || len`
    /// header first).
    pub(super) fn send(&mut self, kind: u8, body: &[u8]) -> Result<()> {
        let len = u32::try_from(body.len()).map_err(|_| Error::Protocol("message too long"))?;
        if message::cap_for(kind).is_none_or(|cap| body.len() > cap) {
            return Err(Error::Protocol("message exceeds its size limit"));
        }
        let first_take = body
            .len()
            .min(MAX_TRANSPORT_PLAINTEXT_LEN - MESSAGE_HEADER_LEN);
        let mut first = Vec::with_capacity(MESSAGE_HEADER_LEN + first_take);
        first.push(kind);
        first.extend_from_slice(&len.to_le_bytes());
        first.extend_from_slice(&body[..first_take]);
        self.send_record(&first)?;
        for chunk in body[first_take..].chunks(MAX_TRANSPORT_PLAINTEXT_LEN) {
            self.send_record(chunk)?;
        }
        Ok(())
    }

    /// Receive one application message. `Ok(None)` is a clean close between
    /// messages. The declared length is checked against the type's cap
    /// before anything is allocated.
    pub(super) fn recv(&mut self) -> Result<Option<(u8, Vec<u8>)>> {
        let Some(first) = self.recv_record()? else {
            return Ok(None);
        };
        if first.len() < MESSAGE_HEADER_LEN {
            return Err(Error::Protocol("short message header"));
        }
        let kind = first[0];
        let len = u32::from_le_bytes(first[1..5].try_into().expect("4 bytes")) as usize;
        let cap = message::cap_for(kind).ok_or(Error::Protocol("unknown message type"))?;
        if len > cap {
            return Err(Error::Protocol("message exceeds its size limit"));
        }
        // Grow with the data actually received rather than trusting the
        // declared length for an up-front allocation.
        let mut body = Vec::with_capacity(len.min(MAX_TRANSPORT_PLAINTEXT_LEN));
        let head = &first[MESSAGE_HEADER_LEN..];
        if head.len() > len {
            return Err(Error::Protocol("a record overruns its message"));
        }
        body.extend_from_slice(head);
        while body.len() < len {
            let record = self
                .recv_record()?
                .ok_or(Error::Protocol("the stream ended inside a message"))?;
            if body.len() + record.len() > len {
                return Err(Error::Protocol("a record overruns its message"));
            }
            body.extend_from_slice(&record);
        }
        Ok(Some((kind, body)))
    }

    /// Receive one message that must be of `kind`.
    pub(super) fn expect(&mut self, kind: u8) -> Result<Vec<u8>> {
        match self.recv()? {
            Some((k, body)) if k == kind => Ok(body),
            Some(_) => Err(Error::Protocol("unexpected message")),
            None => Err(Error::Protocol(
                "the peer closed the connection before the session finished",
            )),
        }
    }

    /// Test hook: write a raw record plaintext (lets a test send a header that
    /// lies about its length).
    #[cfg(test)]
    pub(super) fn send_raw_record(&mut self, plaintext: &[u8]) -> Result<()> {
        self.send_record(plaintext)
    }
}

#[cfg(test)]
mod tests {
    use std::net::{TcpListener, TcpStream};
    use std::thread;

    use super::*;
    use crate::nearby::message::{MSG_BLOB, MSG_DONE, MSG_HELLO};

    fn account() -> (tempfile::TempDir, Session) {
        let dir = tempfile::tempdir().unwrap();
        let (session, _sk) =
            lp_vault::AccountStore::create(dir.path(), "correct horse battery").unwrap();
        (dir, session)
    }

    fn pin(a: &Session, b: &Session) {
        let id = b.device_public_identity();
        a.trust_peer_device(&id.device_id, &id.ed25519_pub, &id.x25519_pub, Some("peer"))
            .unwrap();
    }

    fn pair() -> (TcpStream, TcpStream) {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = l.local_addr().unwrap();
        let c = TcpStream::connect(addr).unwrap();
        let (s, _) = l.accept().unwrap();
        (c, s)
    }

    fn fast() -> Limits {
        Limits {
            handshake_timeout: Duration::from_millis(1500),
            record_timeout: Duration::from_millis(1500),
        }
    }

    /// Two mutually pinned devices: an established channel pair.
    fn channels() -> (SecureChannel<TcpStream>, SecureChannel<TcpStream>) {
        let (_da, a) = account();
        let (_db, b) = account();
        pin(&a, &b);
        pin(&b, &a);
        let (mut c, mut s) = pair();
        let limits = fast();
        let l2 = limits.clone();
        let server = thread::spawn(move || {
            let (t, peer) = handshake(&mut s, Role::Responder, &b, None, &l2).unwrap();
            drop(b);
            drop(_db);
            (SecureChannel::new(s, t, &l2), peer.device_id)
        });
        let (t, peer) = handshake(&mut c, Role::Initiator, &a, None, &limits).unwrap();
        let (sc, server_saw) = server.join().unwrap();
        assert_eq!(server_saw, a.device_id());
        assert_ne!(peer.device_id, a.device_id());
        drop(a);
        drop(_da);
        (SecureChannel::new(c, t, &limits), sc)
    }

    #[test]
    fn messages_round_trip_across_many_records() {
        let (mut c, mut s) = channels();
        let big: Vec<u8> = (0..200_000u32).map(|i| (i % 251) as u8).collect();
        let body = big.clone();
        let t = thread::spawn(move || {
            c.send(MSG_BLOB, &body).unwrap();
            c.send(MSG_DONE, &[]).unwrap();
        });
        let (k, got) = s.recv().unwrap().unwrap();
        assert_eq!(k, MSG_BLOB);
        assert_eq!(got, big);
        assert_eq!(s.expect(MSG_DONE).unwrap(), Vec::<u8>::new());
        t.join().unwrap();
    }

    #[test]
    fn a_header_declaring_an_oversize_message_is_refused_before_allocation() {
        let (mut c, mut s) = channels();
        let t = thread::spawn(move || {
            // A HELLO header claiming 4 GiB - 1.
            let mut header = vec![MSG_HELLO];
            header.extend_from_slice(&u32::MAX.to_le_bytes());
            c.send_raw_record(&header).unwrap();
            c
        });
        assert!(matches!(
            s.recv(),
            Err(Error::Protocol("message exceeds its size limit"))
        ));
        drop(t.join().unwrap());
    }

    #[test]
    fn an_unknown_message_type_is_refused() {
        let (mut c, mut s) = channels();
        let t = thread::spawn(move || {
            c.send_raw_record(&[0x7f, 0, 0, 0, 0]).unwrap();
            c
        });
        assert!(matches!(
            s.recv(),
            Err(Error::Protocol("unknown message type"))
        ));
        drop(t.join().unwrap());
    }

    #[test]
    fn a_stream_that_ends_inside_a_message_is_an_error() {
        let (mut c, mut s) = channels();
        let t = thread::spawn(move || {
            // Declare 100 000 bytes, send one record's worth, then close.
            let mut header = vec![MSG_BLOB];
            header.extend_from_slice(&100_000u32.to_le_bytes());
            header.extend_from_slice(&[7u8; 1000]);
            c.send_raw_record(&header).unwrap();
            drop(c);
        });
        assert!(matches!(
            s.recv(),
            Err(Error::Protocol("the stream ended inside a message"))
        ));
        t.join().unwrap();
    }

    #[test]
    fn a_tampered_record_fails_to_authenticate() {
        // A MITM between the two ends that flips one byte of the first
        // post-handshake record.
        let (_da, a) = account();
        let (_db, b) = account();
        pin(&a, &b);
        pin(&b, &a);
        let front = TcpListener::bind("127.0.0.1:0").unwrap();
        let back = TcpListener::bind("127.0.0.1:0").unwrap();
        let front_addr = front.local_addr().unwrap();
        let back_addr = back.local_addr().unwrap();
        let limits = fast();

        let l2 = limits.clone();
        let server = thread::spawn(move || {
            let (mut s, _) = back.accept().unwrap();
            let (t, _) = handshake(&mut s, Role::Responder, &b, None, &l2).unwrap();
            let mut ch = SecureChannel::new(s, t, &l2);
            ch.recv()
        });
        let proxy = thread::spawn(move || {
            let (mut down, _) = front.accept().unwrap();
            let mut up = TcpStream::connect(back_addr).unwrap();
            let deadline = Instant::now() + Duration::from_secs(5);
            // Relay msg 1 (I->R), msg 2 (R->I) and msg 3 (I->R) untouched, then
            // flip one bit of the initiator's first transport record.
            for (i, to_responder) in [true, false, true, true].into_iter().enumerate() {
                let (from, to) = if to_responder {
                    (&mut down, &mut up)
                } else {
                    (&mut up, &mut down)
                };
                let mut frame = read_noise_frame(from, MAX_NOISE_MESSAGE_LEN, deadline, "proxy")
                    .unwrap()
                    .unwrap();
                if i == 3 {
                    frame[0] ^= 0x01;
                }
                write_noise_frame(to, &frame, deadline, "proxy").unwrap();
            }
            (down, up)
        });
        let mut c = TcpStream::connect(front_addr).unwrap();
        let (t, _) = handshake(&mut c, Role::Initiator, &a, None, &limits).unwrap();
        let mut ch = SecureChannel::new(c, t, &limits);
        ch.send(MSG_DONE, &[]).unwrap();
        let got = server.join().unwrap();
        assert!(matches!(
            got,
            Err(Error::Protocol("a record failed to authenticate"))
        ));
        drop(proxy.join().unwrap());
    }

    #[test]
    fn an_oversize_handshake_frame_is_refused_before_reading_it() {
        let (_db, b) = account();
        let (mut c, mut s) = pair();
        let limits = fast();
        let server =
            thread::spawn(move || handshake(&mut s, Role::Responder, &b, None, &limits).err());
        // A length prefix of 65535 for message 1.
        std::io::Write::write_all(&mut c, &u16::MAX.to_be_bytes()).unwrap();
        let err = server.join().unwrap().expect("refused");
        assert!(matches!(
            err,
            Error::Protocol("noise frame exceeds its size limit")
        ));
    }

    #[test]
    fn a_silent_client_times_out_the_handshake() {
        let (_db, b) = account();
        let (_c, mut s) = pair();
        let limits = Limits {
            handshake_timeout: Duration::from_millis(600),
            record_timeout: Duration::from_secs(5),
        };
        let started = Instant::now();
        let err = handshake(&mut s, Role::Responder, &b, None, &limits).unwrap_err();
        assert!(matches!(err, Error::Timeout(_)), "{err:?}");
        assert!(started.elapsed() < Duration::from_secs(3));
    }

    #[test]
    fn a_byte_trickling_client_cannot_extend_the_handshake() {
        let (_db, b) = account();
        let (mut c, mut s) = pair();
        let limits = Limits {
            handshake_timeout: Duration::from_millis(800),
            record_timeout: Duration::from_secs(5),
        };
        let trickle = thread::spawn(move || {
            // Claim a 32-byte message 1 and send one byte every 150 ms: each
            // read succeeds, but the deadline is over the whole handshake.
            let _ = std::io::Write::write_all(&mut c, &32u16.to_be_bytes());
            for _ in 0..32 {
                thread::sleep(Duration::from_millis(150));
                if std::io::Write::write_all(&mut c, &[0u8]).is_err() {
                    break;
                }
            }
        });
        let started = Instant::now();
        let err = handshake(&mut s, Role::Responder, &b, None, &limits).unwrap_err();
        assert!(matches!(err, Error::Timeout(_)), "{err:?}");
        assert!(started.elapsed() < Duration::from_millis(2500));
        drop(s);
        trickle.join().unwrap();
    }

    #[test]
    fn a_proof_for_another_role_or_transcript_does_not_verify() {
        let (_da, a) = account();
        let (_db, b) = account();
        pin(&b, &a);
        let h = [3u8; HANDSHAKE_HASH_LEN];
        let s = [4u8; NOISE_STATIC_KEY_LEN];
        let proof = make_proof(&a, ROLE_RESPONDER, &h, &s).unwrap();
        assert!(verify_proof(&b, &proof, ROLE_RESPONDER, &h, &s, None).is_ok());
        // Reflected as the other role.
        assert!(matches!(
            verify_proof(&b, &proof, ROLE_INITIATOR, &h, &s, None),
            Err(Error::Refused(Refusal::BadProof))
        ));
        // Another session's transcript.
        assert!(matches!(
            verify_proof(&b, &proof, ROLE_RESPONDER, &[5u8; 32], &s, None),
            Err(Error::Refused(Refusal::BadProof))
        ));
        // Another Noise static key.
        assert!(matches!(
            verify_proof(&b, &proof, ROLE_RESPONDER, &h, &[6u8; 32], None),
            Err(Error::Refused(Refusal::BadProof))
        ));
        // A trusted device, but not the one asked for.
        assert!(matches!(
            verify_proof(&b, &proof, ROLE_RESPONDER, &h, &s, Some(Id::new())),
            Err(Error::Refused(Refusal::UnexpectedPeer))
        ));
        // An untrusted device (a never pinned b).
        let proof_b = make_proof(&b, ROLE_RESPONDER, &h, &s).unwrap();
        assert!(matches!(
            verify_proof(&a, &proof_b, ROLE_RESPONDER, &h, &s, None),
            Err(Error::Refused(Refusal::UntrustedPeer))
        ));
        // This device's own identity.
        assert!(matches!(
            verify_proof(
                &a,
                &make_proof(&a, ROLE_RESPONDER, &h, &s).unwrap(),
                ROLE_RESPONDER,
                &h,
                &s,
                None
            ),
            Err(Error::Refused(Refusal::OwnIdentity))
        ));
    }
}
