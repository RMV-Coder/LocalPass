#![forbid(unsafe_code)]
//! "Sync with a nearby device": the LAN listener and dialer
//! (`docs/specs/lan-transport.md` §7, §9).
//!
//! The protocol — handshake, record layer, exchange — is
//! [`lp_sync::nearby`] and runs over any stream. This module owns everything
//! that touches the network:
//!
//! - the **address policy** ([`is_local_address`]): both ends refuse anything
//!   outside loopback, RFC 1918, link-local, CGNAT `100.64.0.0/10`
//!   (Tailscale) and IPv6 unique-local / link-local — checked before a byte
//!   is read or a connection is attempted;
//! - the **dialer** ([`dial`]): IP literals only, so no host name is ever sent
//!   to a DNS server;
//! - the **listener** ([`bind`], [`serve`]): one connection at a time, inside a
//!   window that closes on expiry, after one session, after
//!   [`MAX_FAILED_HANDSHAKES`] failed handshakes, or when told to stop;
//! - the **daemon glue**: the `Nearby*` requests are validated by the engine
//!   under the state mutex, which hands back a [`Deferred`] job. The server runs
//!   that job *after* releasing the mutex ([`run_deferred`]), and the session
//!   borrows the session back through [`SharedLocal`] one local step at a time.
//!   A slow or hostile peer therefore never holds the mutex, so other clients,
//!   `Lock` and the auto-lock are never blocked.
//!
//! # Not a control channel
//!
//! This is the daemon's only TCP socket, and it is not an IPC endpoint: it
//! accepts nothing but the Noise handshake, refuses every device that is not
//! pinned before reading anything else, and then speaks only the sync exchange.
//! The control channel stays the same-user-only pipe / socket (PRD §8 T8).

use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::ops::Deref;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

use lp_sync::nearby::{self, Local, Role, SessionOptions, SessionReport};
use lp_vault::Session;

use crate::engine::State;
use crate::protocol::{
    Response, WireAdoptedVault, WireNearbyOutcome, WireNearbyReport, WireNearbyVault,
};

/// The default listen port (`lan-transport.md` §7.2).
pub const DEFAULT_PORT: u16 = 47823;

/// How long a listen window stays open by default.
pub const DEFAULT_LISTEN_SECS: u64 = 180;

/// The longest listen window a caller may ask for.
pub const MAX_LISTEN_SECS: u64 = 600;

/// Failed handshakes (or address-policy rejects) that close a window early.
pub const MAX_FAILED_HANDSHAKES: u32 = 8;

/// How long the dialer waits for the TCP connection.
pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// How often the listener re-checks its stop flag and deadline.
const ACCEPT_POLL: Duration = Duration::from_millis(100);

// --- Address policy (§7.3) ---------------------------------------------------

/// Whether `ip` is on a network this transport may use: loopback, RFC 1918,
/// link-local, CGNAT `100.64.0.0/10` (Tailscale's IPv4 range), or IPv6
/// unique-local `fc00::/7` (Tailscale's IPv6 range) / link-local / loopback.
/// IPv4-mapped IPv6 addresses are judged as IPv4.
#[must_use]
pub fn is_local_address(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => is_local_v4(v4),
        IpAddr::V6(v6) => {
            if let Some(v4) = v6.to_ipv4_mapped() {
                return is_local_v4(v4);
            }
            let first = v6.segments()[0];
            v6.is_loopback() || (first & 0xfe00) == 0xfc00 || (first & 0xffc0) == 0xfe80
        }
    }
}

fn is_local_v4(ip: Ipv4Addr) -> bool {
    let o = ip.octets();
    ip.is_loopback()
        || ip.is_private()
        || ip.is_link_local()
        || (o[0] == 100 && (o[1] & 0xc0) == 64)
}

/// Parse a dial target: an IP literal with an optional port
/// (`192.168.1.20`, `192.168.1.20:47823`, `[fe80::1]:47823`, `fd7a::1`).
/// Host names are refused — resolving one would send it to a DNS server.
///
/// # Errors
///
/// A secret-free message for an unparseable, non-local, or port-0 address.
pub fn parse_peer_address(s: &str) -> Result<SocketAddr, String> {
    let s = s.trim();
    let addr = if let Ok(sa) = s.parse::<SocketAddr>() {
        sa
    } else if let Ok(ip) = s.trim_matches(['[', ']']).parse::<IpAddr>() {
        SocketAddr::new(ip, DEFAULT_PORT)
    } else {
        return Err(format!(
            "{s:?} is not an IP address; give the address the other device shows, \
             optionally with :PORT (host names are not looked up)"
        ));
    };
    if addr.port() == 0 {
        return Err("the port must not be 0".into());
    }
    if !is_local_address(addr.ip()) {
        return Err(format!(
            "{} is not a local-network address; nearby sync only connects within \
             your LAN or Tailscale network",
            addr.ip()
        ));
    }
    Ok(addr)
}

/// The address(es) to show the user for a listener bound to `bound`.
///
/// A specific bind address is shown as is. For an unspecified one
/// (`0.0.0.0` / `[::]`), ask the routing table which interface address it
/// would use for a private destination — a UDP socket "connected" to a
/// private address, which sends **nothing** — and show that.
#[must_use]
pub fn display_addresses(bound: SocketAddr) -> Vec<String> {
    if !bound.ip().is_unspecified() {
        return vec![bound.to_string()];
    }
    // Unicast addresses in each private range (not broadcast addresses, which
    // a UDP connect may refuse); nothing is ever sent to them.
    const PROBES: [&str; 3] = ["10.254.254.254:9", "192.168.254.254:9", "172.31.254.254:9"];
    for probe in PROBES {
        let Ok(sock) = UdpSocket::bind("0.0.0.0:0") else {
            continue;
        };
        if sock.connect(probe).is_err() {
            continue;
        }
        if let Ok(local) = sock.local_addr()
            && is_local_address(local.ip())
            && !local.ip().is_loopback()
            && !local.ip().is_unspecified()
        {
            return vec![SocketAddr::new(local.ip(), bound.port()).to_string()];
        }
    }
    Vec::new()
}

// --- Dialer and listener -----------------------------------------------------

/// Connect to `addr` and run a session as the initiator.
///
/// # Errors
///
/// [`lp_sync::Error::Invalid`] for a non-local address (checked before
/// connecting), [`lp_sync::Error::Io`] if the connection fails, and every
/// session error [`nearby::run`] documents.
pub fn dial<L: Local>(
    addr: SocketAddr,
    local: &L,
    options: &SessionOptions,
) -> lp_sync::Result<SessionReport> {
    if !is_local_address(addr.ip()) {
        return Err(lp_sync::Error::Invalid(
            "not a local-network address (nearby sync stays on the LAN / Tailscale)",
        ));
    }
    let stream = TcpStream::connect_timeout(&addr, CONNECT_TIMEOUT)?;
    stream.set_nodelay(true).ok();
    nearby::run(stream, Role::Initiator, local, options)
}

/// Bind a listen socket (non-blocking, for [`serve`]'s polling accept).
///
/// # Errors
///
/// The socket error (e.g. the port is in use).
pub fn bind(addr: SocketAddr) -> std::io::Result<TcpListener> {
    let listener = TcpListener::bind(addr)?;
    listener.set_nonblocking(true)?;
    Ok(listener)
}

/// How a listen window ended.
#[derive(Debug)]
pub enum ListenEnd {
    /// A pinned peer connected and the session completed.
    Synced(Box<SessionReport>),
    /// A pinned peer connected but the session failed after the handshake.
    Failed(String),
    /// Nobody (trusted) connected before the window closed.
    Expired,
    /// The window was closed by the user or by the vault locking.
    Stopped,
    /// Too many failed handshakes; the window closed early.
    TooManyFailures,
}

impl ListenEnd {
    /// A short, stable label.
    #[must_use]
    pub fn code(&self) -> &'static str {
        match self {
            ListenEnd::Synced(_) => "synced",
            ListenEnd::Failed(_) => "failed",
            ListenEnd::Expired => "expired",
            ListenEnd::Stopped => "stopped",
            ListenEnd::TooManyFailures => "too_many_failures",
        }
    }
}

/// Accept connections on `listener` until one session completes, the window
/// reaches `until`, `stop` is set, or [`MAX_FAILED_HANDSHAKES`] attempts fail.
///
/// Connections are served one at a time. A peer outside the address policy is
/// dropped before a byte is read; a peer that fails the handshake (untrusted,
/// wrong device, malformed, too slow) is dropped and counted; nothing past the
/// handshake is read from either. `on_refused` is told about each refusal (a
/// secret-free reason), for logging.
pub fn serve<L: Local>(
    listener: &TcpListener,
    local: &L,
    options: &SessionOptions,
    until: Instant,
    stop: &AtomicBool,
    mut on_refused: impl FnMut(&str),
) -> ListenEnd {
    let mut failures = 0u32;
    loop {
        if stop.load(Ordering::Acquire) {
            return ListenEnd::Stopped;
        }
        if Instant::now() >= until {
            return ListenEnd::Expired;
        }
        let (stream, peer) = match listener.accept() {
            Ok(conn) => conn,
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(ACCEPT_POLL);
                continue;
            }
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => return ListenEnd::Failed(format!("the listener failed: {e}")),
        };
        if !is_local_address(peer.ip()) {
            drop(stream);
            on_refused(&format!("{}: not a local-network address", peer.ip()));
            failures += 1;
        } else {
            match accept_one(stream, local, options) {
                Ok(report) => return ListenEnd::Synced(Box::new(report)),
                Err(Accepted::Authenticated(e)) => return ListenEnd::Failed(e.to_string()),
                Err(Accepted::NotAuthenticated(e)) => {
                    on_refused(&format!("{}: {e}", peer.ip()));
                    failures += 1;
                }
            }
        }
        if failures >= MAX_FAILED_HANDSHAKES {
            return ListenEnd::TooManyFailures;
        }
    }
}

/// Whether a failed connection got past the handshake.
enum Accepted {
    NotAuthenticated(lp_sync::Error),
    Authenticated(lp_sync::Error),
}

fn accept_one<L: Local>(
    stream: TcpStream,
    local: &L,
    options: &SessionOptions,
) -> Result<SessionReport, Accepted> {
    // Accepted sockets may inherit the listener's non-blocking mode (Windows);
    // the session wants blocking reads with timeouts.
    stream
        .set_nonblocking(false)
        .map_err(|e| Accepted::NotAuthenticated(e.into()))?;
    stream.set_nodelay(true).ok();
    let linked = nearby::handshake(stream, Role::Responder, local, options)
        .map_err(Accepted::NotAuthenticated)?;
    linked
        .exchange(local, options)
        .map_err(Accepted::Authenticated)
}

// --- Daemon glue ---------------------------------------------------------------

/// Lends the daemon's held session to a running nearby session, locking the
/// state mutex for each local step only.
pub struct SharedLocal<H>(pub H);

impl<H: Deref<Target = Mutex<State>>> Local for SharedLocal<H> {
    fn with_session<R>(
        &self,
        f: impl FnOnce(&Session) -> lp_sync::Result<R>,
    ) -> lp_sync::Result<R> {
        let state = self.0.lock().unwrap_or_else(PoisonError::into_inner);
        let session = state.session_ref().ok_or(lp_sync::Error::Invalid(
            "the vault locked during nearby sync",
        ))?;
        f(session)
    }
}

/// The nearby-sync part of the daemon's state: the open listen window, if any,
/// and the last outcome (kept across windows for `NearbyStatus`).
#[derive(Default)]
pub struct NearbyState {
    listen: Option<ListenHandle>,
    last: Arc<Mutex<Option<WireNearbyOutcome>>>,
}

/// An open listen window, as the state sees it.
struct ListenHandle {
    stop: Arc<AtomicBool>,
    running: Arc<AtomicBool>,
    port: u16,
    addresses: Vec<String>,
    until: Instant,
}

impl NearbyState {
    /// Whether a listen window is open and its listener is running.
    #[must_use]
    pub fn listening(&self) -> bool {
        self.listen.as_ref().is_some_and(|h| {
            h.running.load(Ordering::Acquire)
                && !h.stop.load(Ordering::Acquire)
                && Instant::now() < h.until
        })
    }

    /// Close the listen window, if one is open (the listener thread notices
    /// within a tenth of a second). Called on `NearbyStop` and on every lock.
    pub fn stop_listening(&mut self) {
        if let Some(h) = self.listen.take() {
            h.stop.store(true, Ordering::Release);
        }
    }

    /// Render the current status.
    #[must_use]
    pub fn status(&self) -> Response {
        let open = self.listening();
        let handle = self.listen.as_ref().filter(|_| open);
        Response::NearbyStatus {
            listening: open,
            addresses: handle.map(|h| h.addresses.clone()).unwrap_or_default(),
            port: handle.map(|h| h.port),
            expires_in_secs: handle
                .map(|h| h.until.saturating_duration_since(Instant::now()).as_secs()),
            last: self
                .last
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .clone(),
        }
    }

    /// Open a listen window on `listener` (already bound) and return the job
    /// the host must run. Fails if a window is already open.
    ///
    /// # Errors
    ///
    /// A secret-free message when a window is already open or the socket's
    /// address cannot be read.
    pub fn open(
        &mut self,
        listener: TcpListener,
        window: Duration,
        options: SessionOptions,
    ) -> Result<(Deferred, Response), String> {
        if self.listening() {
            return Err("already listening for a nearby device".into());
        }
        let bound = listener
            .local_addr()
            .map_err(|e| format!("could not read the listen address: {e}"))?;
        let addresses = display_addresses(bound);
        let until = Instant::now() + window;
        let stop = Arc::new(AtomicBool::new(false));
        let running = Arc::new(AtomicBool::new(true));
        self.listen = Some(ListenHandle {
            stop: Arc::clone(&stop),
            running: Arc::clone(&running),
            port: bound.port(),
            addresses: addresses.clone(),
            until,
        });
        let job = Deferred::Listen(ListenJob {
            listener,
            options,
            until,
            stop,
            running,
            last: Arc::clone(&self.last),
        });
        let response = Response::NearbyListening {
            addresses,
            port: bound.port(),
            expires_in_secs: window.as_secs(),
        };
        Ok((job, response))
    }

    /// A dial job for the host to run.
    #[must_use]
    pub fn connect(&self, addr: SocketAddr, options: SessionOptions) -> Deferred {
        Deferred::Connect(ConnectJob {
            addr,
            options,
            last: Arc::clone(&self.last),
        })
    }
}

/// Network work the engine validated but must not run under the state mutex.
/// The host runs it with [`run_deferred`] after releasing the lock.
pub enum Deferred {
    /// Serve an open listen window on its own thread.
    Listen(ListenJob),
    /// Dial a peer and run a session on the requesting connection's thread.
    Connect(ConnectJob),
}

/// A listen window to serve.
pub struct ListenJob {
    listener: TcpListener,
    options: SessionOptions,
    until: Instant,
    stop: Arc<AtomicBool>,
    running: Arc<AtomicBool>,
    last: Arc<Mutex<Option<WireNearbyOutcome>>>,
}

impl Drop for ListenJob {
    /// However the job ends — served, or dropped by a host that never ran it —
    /// the state stops reporting the window as open.
    fn drop(&mut self) {
        self.running.store(false, Ordering::Release);
    }
}

/// A dial to perform.
pub struct ConnectJob {
    addr: SocketAddr,
    options: SessionOptions,
    last: Arc<Mutex<Option<WireNearbyOutcome>>>,
}

/// Run a [`Deferred`] job with the state mutex **released**. Returns the
/// response that replaces the engine's provisional one (a dial's result), or
/// `None` to keep it (a listen window, whose session runs on its own thread
/// and reports through `NearbyStatus`).
pub fn run_deferred<H>(state: H, job: Deferred) -> Option<Response>
where
    H: Deref<Target = Mutex<State>> + Clone + Send + 'static,
{
    match job {
        Deferred::Listen(job) => {
            std::thread::spawn(move || listen_thread(state, job));
            None
        }
        Deferred::Connect(job) => Some(connect_now(&state, job)),
    }
}

fn listen_thread<H>(state: H, job: ListenJob)
where
    H: Deref<Target = Mutex<State>> + Clone + Send + 'static,
{
    let local = SharedLocal(state.clone());
    let end = serve(
        &job.listener,
        &local,
        &job.options,
        job.until,
        &job.stop,
        |_reason| {},
    );
    let outcome = {
        let st = state.lock().unwrap_or_else(PoisonError::into_inner);
        let session = st.session_ref();
        if let Some(session) = session {
            session
                .record_audit(lp_vault::AuditKind::NearbyListenDisabled, None)
                .ok();
        }
        outcome_for("listen", end, session)
    };
    *job.last.lock().unwrap_or_else(PoisonError::into_inner) = Some(outcome);
    // `job` drops here: the listener closes and the state stops reporting it.
}

fn connect_now<H: Deref<Target = Mutex<State>>>(state: &H, job: ConnectJob) -> Response {
    let local = SharedLocal(&**state);
    let result = dial(job.addr, &local, &job.options);
    let st = state.lock().unwrap_or_else(PoisonError::into_inner);
    let session = st.session_ref();
    let (outcome, response) = match result {
        Ok(report) => {
            let wire = render_report(&report, session);
            (
                WireNearbyOutcome {
                    role: "connect".into(),
                    result: "synced".into(),
                    error: None,
                    report: Some(wire.clone()),
                },
                Response::NearbySynced { report: wire },
            )
        }
        Err(e) => {
            let message = format!("nearby sync failed: {e}");
            (
                WireNearbyOutcome {
                    role: "connect".into(),
                    result: "failed".into(),
                    error: Some(message.clone()),
                    report: None,
                },
                Response::Error {
                    auth: false,
                    message,
                },
            )
        }
    };
    *job.last.lock().unwrap_or_else(PoisonError::into_inner) = Some(outcome);
    response
}

/// Render a finished window for `NearbyStatus`.
fn outcome_for(role: &str, end: ListenEnd, session: Option<&Session>) -> WireNearbyOutcome {
    let result = end.code().to_string();
    match end {
        ListenEnd::Synced(report) => WireNearbyOutcome {
            role: role.into(),
            result,
            error: None,
            report: Some(render_report(&report, session)),
        },
        ListenEnd::Failed(e) => WireNearbyOutcome {
            role: role.into(),
            result,
            error: Some(e),
            report: None,
        },
        ListenEnd::Expired | ListenEnd::Stopped | ListenEnd::TooManyFailures => WireNearbyOutcome {
            role: role.into(),
            result,
            error: None,
            report: None,
        },
    }
}

/// Render a session report for the wire, naming vaults when the session is
/// available. Secret-free: ids, names (vault metadata, same-user channel only),
/// counts and alarm descriptions.
#[must_use]
pub fn render_report(report: &SessionReport, session: Option<&Session>) -> WireNearbyReport {
    let names = session
        .and_then(|s| s.list_vaults().ok())
        .unwrap_or_default();
    let name_of = |id: &lp_vault::VaultId| {
        names
            .iter()
            .find(|(v, _)| v == id)
            .map_or_else(String::new, |(_, n)| n.clone())
    };
    let mut alarms: Vec<String> = report
        .shares_rejected
        .iter()
        .map(|(v, why)| format!("refused a vault-key share for {}: {why}", v.to_hyphenated()))
        .collect();
    for v in &report.vaults {
        for q in &v.quarantines {
            alarms.push(format!(
                "device {} quarantined at seq {} — {}",
                q.device_id.to_hyphenated(),
                q.seq,
                q.alarm
            ));
        }
        for h in &v.blobs_tampered {
            alarms.push(format!("attachment blob {h} failed its content check"));
        }
    }
    WireNearbyReport {
        peer_device_id: report.peer.to_hyphenated(),
        peer_label: report.peer_label.clone(),
        vaults: report
            .vaults
            .iter()
            .map(|v| WireNearbyVault {
                vault_id: v.vault_id.to_hyphenated(),
                name: name_of(&v.vault_id),
                ops_sent: v.ops_sent,
                applied: v.applied,
                pending: v.pending,
                blobs_sent: v.blobs_sent,
                blobs_fetched: v.blobs_fetched,
                blobs_pending: v.blobs_pending,
            })
            .collect(),
        shared: report
            .shares_sent
            .iter()
            .map(lp_vault::Id::to_hyphenated)
            .collect(),
        adopted: report
            .shares_adopted
            .iter()
            .map(|v| WireAdoptedVault {
                vault_id: v.to_hyphenated(),
                name: name_of(v),
            })
            .collect(),
        alarms,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn local_ranges_are_allowed() {
        for a in [
            "127.0.0.1",
            "10.1.2.3",
            "172.16.0.1",
            "172.31.255.254",
            "192.168.1.20",
            "169.254.10.10",
            "100.64.0.1",
            "100.127.255.254",
            "::1",
            "fd7a:115c:a1e0::1",
            "fe80::1",
            "::ffff:192.168.1.5",
        ] {
            assert!(is_local_address(ip(a)), "{a}");
        }
    }

    #[test]
    fn everything_else_is_refused() {
        for a in [
            "8.8.8.8",
            "1.1.1.1",
            "172.32.0.1",
            "100.128.0.1",
            "100.63.255.255",
            "192.169.0.1",
            "2001:4860:4860::8888",
            "::ffff:8.8.8.8",
            "0.0.0.0",
            "255.255.255.255",
        ] {
            assert!(!is_local_address(ip(a)), "{a}");
        }
    }

    #[test]
    fn dial_targets_must_be_local_ip_literals() {
        assert_eq!(
            parse_peer_address("192.168.1.20").unwrap(),
            "192.168.1.20:47823".parse().unwrap()
        );
        assert_eq!(
            parse_peer_address(" 100.101.102.103:5000 ").unwrap().port(),
            5000
        );
        assert_eq!(parse_peer_address("[fe80::1]:9").unwrap().port(), 9);
        assert_eq!(parse_peer_address("fd7a::1").unwrap().port(), DEFAULT_PORT);
        assert!(parse_peer_address("laptop.local").is_err());
        assert!(parse_peer_address("8.8.8.8:47823").is_err());
        assert!(parse_peer_address("192.168.1.20:0").is_err());
    }

    #[test]
    fn a_specific_bind_address_is_shown_as_is() {
        let a: SocketAddr = "192.168.7.7:47823".parse().unwrap();
        assert_eq!(display_addresses(a), vec!["192.168.7.7:47823".to_string()]);
    }

    #[test]
    fn a_window_expires_and_a_stop_flag_stops_it() {
        let dir = tempfile::tempdir().unwrap();
        let (session, _sk) = lp_vault::AccountStore::create(dir.path(), "pw").unwrap();
        let listener = bind("127.0.0.1:0".parse().unwrap()).unwrap();
        let stop = AtomicBool::new(false);
        let until = Instant::now() + Duration::from_millis(300);
        let end = serve(
            &listener,
            &session,
            &SessionOptions::default(),
            until,
            &stop,
            |_| {},
        );
        assert!(matches!(end, ListenEnd::Expired));

        stop.store(true, Ordering::Release);
        let until = Instant::now() + Duration::from_secs(30);
        let end = serve(
            &listener,
            &session,
            &SessionOptions::default(),
            until,
            &stop,
            |_| {},
        );
        assert!(matches!(end, ListenEnd::Stopped));
    }

    #[test]
    fn repeated_failed_handshakes_close_the_window() {
        let dir = tempfile::tempdir().unwrap();
        let (session, _sk) = lp_vault::AccountStore::create(dir.path(), "pw").unwrap();
        let listener = bind("127.0.0.1:0".parse().unwrap()).unwrap();
        let addr = listener.local_addr().unwrap();
        let stop = AtomicBool::new(false);
        let options = SessionOptions {
            limits: lp_sync::nearby::Limits {
                handshake_timeout: Duration::from_millis(500),
                record_timeout: Duration::from_secs(5),
            },
            ..SessionOptions::default()
        };
        // Clients that connect and send garbage instead of a Noise message.
        let spammer = std::thread::spawn(move || {
            for _ in 0..MAX_FAILED_HANDSHAKES + 2 {
                if let Ok(mut c) = TcpStream::connect(addr) {
                    let _ = std::io::Write::write_all(&mut c, &[0, 32]);
                    let _ = std::io::Write::write_all(&mut c, &[0xAB; 32]);
                    std::thread::sleep(Duration::from_millis(50));
                }
            }
        });
        let mut refused = 0;
        let until = Instant::now() + Duration::from_secs(60);
        let end = serve(&listener, &session, &options, until, &stop, |_| {
            refused += 1
        });
        assert!(matches!(end, ListenEnd::TooManyFailures), "{end:?}");
        assert_eq!(refused, MAX_FAILED_HANDSHAKES);
        spammer.join().unwrap();
    }
}
