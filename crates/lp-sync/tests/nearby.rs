//! Nearby (LAN) sync between REAL devices over loopback TCP
//! (`docs/specs/lan-transport.md` §13).
//!
//! Each device is a separate account (`AccountStore::create`, real Argon2id),
//! pinned to the other exactly as `device trust` would. One side listens, one
//! dials, and both run `lp_sync::nearby::run` on their end of a real
//! `TcpStream`.

use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::thread;
use std::time::Duration;

use lp_sync::engine;
use lp_sync::nearby::{self, Limits, Local, Role, SessionOptions, SessionReport};
use lp_sync::store::FsStoreFactory;
use lp_sync::{Error, Refusal};
use lp_vault::payload::{ItemPayload, TypeData};
use lp_vault::{AccountStore, Session, VaultId};

struct Device {
    session: Session,
    _dir: tempfile::TempDir,
}

fn device(pw: &str) -> Device {
    let dir = tempfile::tempdir().unwrap();
    let (session, _sk) = AccountStore::create(dir.path(), pw).unwrap();
    Device { session, _dir: dir }
}

/// `a` pins `b` (one direction of a pairing).
fn pin(a: &Session, b: &Session, label: &str) {
    let id = b.device_public_identity();
    a.trust_peer_device(&id.device_id, &id.ed25519_pub, &id.x25519_pub, Some(label))
        .unwrap();
}

fn login(title: &str, password: &str) -> ItemPayload {
    let mut p = ItemPayload::new(TypeData::Login { urls: vec![] }, title);
    p.fields.push(lp_vault::Field {
        name: "password".into(),
        kind: lp_vault::FieldKind::Hidden,
        value: password.into(),
    });
    p
}

fn options() -> SessionOptions {
    SessionOptions {
        limits: Limits {
            handshake_timeout: Duration::from_secs(10),
            record_timeout: Duration::from_secs(30),
        },
        ..SessionOptions::default()
    }
}

/// Counts the local steps a side took, to prove a refused peer got none.
struct Counting {
    device: Device,
    calls: AtomicUsize,
}

impl Local for Counting {
    fn with_session<R>(
        &self,
        f: impl FnOnce(&Session) -> lp_sync::Result<R>,
    ) -> lp_sync::Result<R> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        f(&self.device.session)
    }
}

/// Run one session: `listener` accepts on loopback, `dialer` connects. Returns
/// both results and both devices back.
#[allow(clippy::type_complexity)]
fn session(
    listener: Device,
    listener_opts: SessionOptions,
    dialer: Device,
    dialer_opts: SessionOptions,
) -> (
    (lp_sync::Result<SessionReport>, Counting),
    (lp_sync::Result<SessionReport>, Counting),
) {
    let socket = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = socket.local_addr().unwrap();
    let l = thread::spawn(move || {
        let local = Counting {
            device: listener,
            calls: AtomicUsize::new(0),
        };
        let (stream, _) = socket.accept().unwrap();
        let r = nearby::run(stream, Role::Responder, &local, &listener_opts);
        (r, local)
    });
    let d = thread::spawn(move || {
        let local = Counting {
            device: dialer,
            calls: AtomicUsize::new(0),
        };
        let stream = TcpStream::connect(addr).unwrap();
        let r = nearby::run(stream, Role::Initiator, &local, &dialer_opts);
        (r, local)
    });
    (l.join().unwrap(), d.join().unwrap())
}

/// Per item: hyphenated id, current version, `(version, canonical payload)`s.
type Snapshot = Vec<(String, i64, Vec<(i64, Vec<u8>)>)>;

/// The device-independent materialized state of a vault: per item (by id),
/// its current version number, current payload, and every version's payload.
fn snapshot(session: &Session, vault_id: VaultId) -> Snapshot {
    let vault = session.open_vault(vault_id).unwrap();
    let mut out: Vec<_> = vault
        .list_items()
        .unwrap()
        .into_iter()
        .map(|item| {
            let history = vault
                .history(item.item_id)
                .unwrap()
                .into_iter()
                .map(|v| (v.version, v.payload.to_canonical().unwrap()))
                .collect();
            (item.item_id.to_hyphenated(), item.current_version, history)
        })
        .collect();
    out.sort();
    out
}

fn vault_ids(session: &Session) -> Vec<VaultId> {
    session
        .list_vaults()
        .unwrap()
        .into_iter()
        .map(|(id, _)| id)
        .collect()
}

#[test]
fn share_then_converge_and_a_file_sync_afterwards_finds_nothing_new() {
    let a = device("pw-a");
    let b = device("pw-b");
    pin(&a.session, &b.session, "b");
    pin(&b.session, &a.session, "a");
    let b_id = b.session.device_id();

    // A has a vault with two items; B has never seen it.
    let vault_id = a.session.create_vault("shared").unwrap();
    let (github, aws) = {
        let v = a.session.open_vault(vault_id).unwrap();
        (
            v.create_item(&login("GitHub", "hunter2")).unwrap(),
            v.create_item(&login("AWS", "s3cr3t")).unwrap(),
        )
    };

    // Session 1: B listens; A dials and shares the vault to B. One session
    // hands the key over AND fills the vault.
    let mut share = options();
    share.expected_peer = Some(b_id);
    share.share = vec![vault_id];
    let ((rb, b), (ra, a)) = session(b, options(), a, share);
    let rb = rb.expect("listener session");
    let ra = ra.expect("dialer session");
    assert_eq!(ra.shares_sent, vec![vault_id]);
    assert_eq!(rb.shares_adopted, vec![vault_id]);
    assert!(!ra.has_alarms() && !rb.has_alarms());
    assert_eq!(rb.peer_label.as_deref(), Some("a"));
    let vb = rb.vaults.iter().find(|v| v.vault_id == vault_id).unwrap();
    assert_eq!(vb.applied, 2, "both create ops arrive in the same session");
    assert_eq!(
        snapshot(&a.device.session, vault_id),
        snapshot(&b.device.session, vault_id)
    );
    // Only the vault both hold is exchanged: each side's own default vault
    // (none here) never crosses.
    assert_eq!(ra.vaults.len(), 1);

    // Edits on both sides: different items, plus a concurrent edit of the same
    // field (the loser must be preserved as a version on both).
    {
        let v = a.device.session.open_vault(vault_id).unwrap();
        v.update_item(github, &login("GitHub", "from-a")).unwrap();
        v.update_item(aws, &login("AWS", "a-wins-or-loses"))
            .unwrap();
    }
    {
        let v = b.device.session.open_vault(vault_id).unwrap();
        v.update_item(aws, &login("AWS", "b-wins-or-loses"))
            .unwrap();
        v.create_item(&login("Fastmail", "from-b")).unwrap();
    }

    // Session 2: roles swapped — A listens, B dials. No share this time.
    let ((ra2, a), (rb2, b)) = session(a.device, options(), b.device, options());
    let ra2 = ra2.unwrap();
    let rb2 = rb2.unwrap();
    assert!(!ra2.has_alarms() && !rb2.has_alarms());
    assert_eq!(ra2.vaults[0].applied, 2, "B's update + create");
    assert_eq!(rb2.vaults[0].applied, 2, "A's two updates");
    let snap_a = snapshot(&a.device.session, vault_id);
    assert_eq!(snap_a, snapshot(&b.device.session, vault_id));
    let aws_versions = snap_a
        .iter()
        .find(|(id, _, _)| *id == aws.to_hyphenated())
        .unwrap()
        .2
        .len();
    assert!(aws_versions >= 3, "the losing concurrent edit is kept");

    // A third session finds nothing to do.
    let ((ra3, a), (rb3, b)) = session(a.device, options(), b.device, options());
    let (ra3, rb3) = (ra3.unwrap(), rb3.unwrap());
    assert_eq!((ra3.vaults[0].ops_sent, ra3.vaults[0].applied), (0, 0));
    assert_eq!((rb3.vaults[0].ops_sent, rb3.vaults[0].applied), (0, 0));

    // The LAN produced exactly the file-sync state: pushing both devices' logs
    // through a shared folder and pulling gives each side nothing new.
    let root = tempfile::tempdir().unwrap();
    let root_s = root.path().to_string_lossy().into_owned();
    for s in [&a.device.session, &b.device.session] {
        engine::setup(s, vault_id, &root_s, &FsStoreFactory).unwrap();
        let v = s.open_vault(vault_id).unwrap();
        engine::push(s, &v, &FsStoreFactory).unwrap();
    }
    for s in [&a.device.session, &b.device.session] {
        let v = s.open_vault(vault_id).unwrap();
        let pulled = engine::pull(s, &v, &FsStoreFactory).unwrap();
        assert_eq!(pulled.applied, 0, "file sync found an op the LAN missed");
        assert!(!pulled.has_alarms());
    }
    assert_eq!(
        snapshot(&a.device.session, vault_id),
        snapshot(&b.device.session, vault_id)
    );
}

#[test]
fn a_third_devices_ops_are_forwarded() {
    let a = device("pw-a");
    let b = device("pw-b");
    let c = device("pw-c");
    for (x, y) in [(&a, &b), (&b, &a), (&a, &c), (&c, &a), (&b, &c)] {
        pin(&x.session, &y.session, "peer");
    }
    // A owns the vault and has shared it to B and C through the file channel
    // in the past; C's edits reached A that way. B was offline.
    let vault_id = a.session.create_vault("family").unwrap();
    let root = tempfile::tempdir().unwrap();
    let root_s = root.path().to_string_lossy().into_owned();
    engine::setup(&a.session, vault_id, &root_s, &FsStoreFactory).unwrap();
    {
        let v = a.session.open_vault(vault_id).unwrap();
        v.create_item(&login("Router", "admin")).unwrap();
        engine::push(&a.session, &v, &FsStoreFactory).unwrap();
    }
    engine::share_vault_to_device(
        &a.session,
        vault_id,
        &c.session.device_id(),
        &FsStoreFactory,
    )
    .unwrap();
    assert_eq!(
        engine::adopt(&c.session, &root_s, &FsStoreFactory).unwrap(),
        vec![vault_id]
    );
    {
        let v = c.session.open_vault(vault_id).unwrap();
        engine::pull(&c.session, &v, &FsStoreFactory).unwrap();
        v.create_item(&login("Printer", "from-c")).unwrap();
        engine::push(&c.session, &v, &FsStoreFactory).unwrap();
    }
    {
        let v = a.session.open_vault(vault_id).unwrap();
        assert_eq!(
            engine::pull(&a.session, &v, &FsStoreFactory)
                .unwrap()
                .applied,
            1
        );
    }

    // Now B meets A on the LAN: it gets the vault, A's op AND C's op.
    let mut share = options();
    share.expected_peer = Some(b.session.device_id());
    share.share = vec![vault_id];
    let ((rb, b), (ra, a)) = session(b, options(), a, share);
    let rb = rb.unwrap();
    ra.unwrap();
    assert!(!rb.has_alarms(), "C is pinned on B, so its op verifies");
    assert_eq!(rb.vaults[0].applied, 2);
    assert_eq!(
        snapshot(&a.device.session, vault_id),
        snapshot(&b.device.session, vault_id)
    );
    drop(c);
}

#[test]
fn an_untrusted_dialer_is_refused_before_any_data_is_read() {
    let listener = device("pw-l");
    let stranger = device("pw-s");
    // The stranger pinned the listener (it has the listener's public identity
    // string), but the listener never pinned the stranger.
    pin(&stranger.session, &listener.session, "listener");
    let stranger_vault = stranger.session.create_vault("bait").unwrap();
    let before = vault_ids(&listener.session);

    let mut bait = options();
    bait.expected_peer = Some(listener.session.device_id());
    bait.share = vec![stranger_vault];
    let ((rl, l), (rs, _s)) = session(listener, options(), stranger, bait);

    assert!(
        matches!(rl, Err(Error::Refused(Refusal::UntrustedPeer))),
        "{rl:?}"
    );
    // The listener did exactly two local steps — sign its own proof, check the
    // stranger's — and nothing after: no inventory, no share import, no ingest.
    assert_eq!(l.calls.load(Ordering::SeqCst), 2);
    assert_eq!(vault_ids(&l.device.session), before);
    assert!(rs.is_err(), "the stranger's session must fail too");
}

#[test]
fn an_untrusted_listener_never_learns_who_dialed() {
    let listener = device("pw-l");
    let dialer = device("pw-d");
    // The listener pinned the dialer; the dialer never pinned the listener.
    pin(&listener.session, &dialer.session, "dialer");

    let ((rl, l), (rd, d)) = session(listener, options(), dialer, options());
    assert!(
        matches!(rd, Err(Error::Refused(Refusal::UntrustedPeer))),
        "{rd:?}"
    );
    // The dialer checked the listener's proof (one local step) and stopped
    // before signing its own: message 3 was never sent.
    assert_eq!(d.calls.load(Ordering::SeqCst), 1);
    assert!(
        matches!(rl, Err(Error::Refused(Refusal::PeerClosed))),
        "{rl:?}"
    );
    // The listener signed its proof and then saw the connection close.
    assert_eq!(l.calls.load(Ordering::SeqCst), 1);
}

#[test]
fn a_trusted_but_unexpected_peer_is_refused() {
    let listener = device("pw-l");
    let dialer = device("pw-d");
    let other = device("pw-o");
    pin(&listener.session, &dialer.session, "dialer");
    pin(&listener.session, &other.session, "other");
    pin(&dialer.session, &listener.session, "listener");

    let mut only_other = options();
    only_other.expected_peer = Some(other.session.device_id());
    let ((rl, _), (rd, _)) = session(listener, only_other, dialer, options());
    assert!(
        matches!(rl, Err(Error::Refused(Refusal::UnexpectedPeer))),
        "{rl:?}"
    );
    assert!(rd.is_err());
}

#[test]
fn sharing_without_naming_the_peer_is_refused_up_front() {
    let a = device("pw-a");
    let v = a.session.create_vault("x").unwrap();
    let mut opts = options();
    opts.share = vec![v];
    let (s, _c) = {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let c = TcpStream::connect(l.local_addr().unwrap()).unwrap();
        (l.accept().unwrap().0, c)
    };
    assert!(matches!(
        nearby::run(s, Role::Responder, &a.session, &opts),
        Err(Error::Invalid(_))
    ));
}

#[test]
fn attachment_blobs_cross_the_link_and_are_re_hashed() {
    let a = device("pw-a");
    let b = device("pw-b");
    pin(&a.session, &b.session, "b");
    pin(&b.session, &a.session, "a");
    let vault_id = a.session.create_vault("docs").unwrap();
    let body: Vec<u8> = (0..300_000u32).map(|i| (i * 7 % 256) as u8).collect();
    {
        let v = a.session.open_vault(vault_id).unwrap();
        let item = v.create_item(&login("Passport", "-")).unwrap();
        v.add_attachment(item, "passport.pdf", &body).unwrap();
    }
    let mut share = options();
    share.expected_peer = Some(b.session.device_id());
    share.share = vec![vault_id];
    let ((rb, b), (ra, _a)) = session(b, options(), a, share);
    let rb = rb.unwrap();
    let ra = ra.unwrap();
    assert_eq!(ra.vaults[0].blobs_sent, 1);
    assert_eq!(rb.vaults[0].blobs_fetched, 1);
    assert_eq!(rb.vaults[0].blobs_pending, 0);
    assert!(!rb.has_alarms());

    let v = b.device.session.open_vault(vault_id).unwrap();
    let item = v.list_items().unwrap()[0].item_id;
    let atts = v.list_attachments(item).unwrap();
    assert_eq!(atts.len(), 1);
    let (name, bytes) = v.get_attachment(atts[0].attachment_id).unwrap();
    assert_eq!(name, "passport.pdf");
    assert_eq!(bytes, body);
}
