//! Sync by QR code between REAL devices (`docs/specs/qr-transport.md` §14).
//!
//! Each device is a separate account (real Argon2id), pinned to the others as
//! `device trust` would. A bundle goes through the frame encoder, a lossy
//! "camera" (30% of frames dropped, the rest shuffled and some duplicated),
//! the frame decoder, and the import — the whole channel minus the pixels.

use std::collections::BTreeMap;
use std::time::Instant;

use lp_sync::engine;
use lp_sync::qr::{self, ExportOptions, FrameDecoder, HaveCode, bundle};
use lp_sync::store::FsStoreFactory;
use lp_vault::ids::Id;
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
    p.notes = "x".repeat(400);
    p
}

/// A small deterministic PRNG (xorshift64*), so the lossy channel is the same
/// on every run.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_f491_4f6c_dd1d)
    }

    fn below(&mut self, n: u64) -> u64 {
        self.next() % n
    }
}

/// Play `bundle` through a lossy, reordering, duplicating camera and return
/// what the receiver rebuilt, with how many frames the sender had to show.
fn through_the_air(bundle: &[u8], symbol_size: u16, seed: u64) -> ([u8; 8], Vec<u8>, u32) {
    let enc = qr::encoder_for(bundle, symbol_size).unwrap();
    let mut rng = Rng(seed);
    let mut dec = FrameDecoder::new();
    let now = Instant::now();
    let mut shown = 0u32;
    // The player shows frames in ESI order, forever; the camera catches about
    // 70% of them, late and out of order, sometimes twice. Process the
    // "caught" frames in shuffled batches of 20, like the GUI's batches.
    let mut esi = 0u32;
    while !dec.progress().complete {
        assert!(shown < 20 * enc.source_symbols() + 100, "never completed");
        let mut batch: Vec<Vec<u8>> = Vec::new();
        for frame in enc.frames(esi, 20) {
            shown += 1;
            if rng.below(100) < 30 {
                continue; // lost
            }
            if rng.below(100) < 15 {
                batch.push(frame.clone()); // seen twice
            }
            batch.push(frame);
        }
        esi += 20;
        for i in (1..batch.len()).rev() {
            batch.swap(i, rng.below(i as u64 + 1) as usize);
        }
        for f in &batch {
            dec.push(f, now);
        }
        dec.decode(now);
        assert!(dec.progress().failed.is_none(), "{:?}", dec.progress());
    }
    let (id, data) = dec.take().unwrap();
    (id, data, shown)
}

type Snapshot = Vec<(String, i64, Vec<(i64, Vec<u8>)>)>;

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

fn holds(session: &Session, vault_id: VaultId) -> bool {
    session
        .list_vaults()
        .unwrap()
        .iter()
        .any(|(v, _)| *v == vault_id)
}

/// A shares a 40-item vault with B over a lossy QR stream; then both devices
/// push and pull through a folder, and the folder finds nothing new.
#[test]
fn a_lossy_shuffled_stream_shares_and_fills_a_vault_exactly_like_file_sync() {
    let a = device("pw-a");
    let b = device("pw-b");
    pin(&a.session, &b.session, "phone");
    pin(&b.session, &a.session, "laptop");
    let vault_id = a.session.create_vault("personal").unwrap();
    {
        let v = a.session.open_vault(vault_id).unwrap();
        for i in 0..40 {
            let id = v.create_item(&login(&format!("site-{i}"), "pw")).unwrap();
            if i % 4 == 0 {
                v.update_item(id, &login(&format!("site-{i}"), "rotated"))
                    .unwrap();
            }
        }
    }

    let (bytes, summary) = bundle::export(
        &a.session,
        &ExportOptions {
            share: vec![vault_id],
            peer: Some(b.session.device_id()),
            ..ExportOptions::default()
        },
    )
    .unwrap();
    assert_eq!(summary.vaults, vec![(vault_id, 50)]);
    assert_eq!(summary.shares, vec![vault_id]);
    assert_eq!(summary.recipient, Some(b.session.device_id()));
    assert!(summary.bytes > 20_000, "a real multi-frame transfer");

    let (transfer_id, received, shown) = through_the_air(&bytes, 600, 1);
    assert_eq!(received, bytes);
    assert_eq!(transfer_id, summary.transfer_id);
    let k = bytes.len().div_ceil(600) as u32;
    assert!(shown < 2 * k, "30% loss should cost well under 2× K frames");

    let report = bundle::import(&b.session, &received, Some(transfer_id)).unwrap();
    assert_eq!(report.shares_adopted, vec![vault_id]);
    assert!(!report.has_alarms(), "{report:?}");
    assert!(report.sender_trusted);
    assert_eq!(report.sender_label.as_deref(), Some("laptop"));
    assert_eq!(report.vaults.len(), 1);
    assert_eq!(report.vaults[0].applied, 50);
    assert_eq!(
        snapshot(&a.session, vault_id),
        snapshot(&b.session, vault_id)
    );

    // Receiving it again is idempotent.
    let again = bundle::import(&b.session, &received, None).unwrap();
    assert_eq!((again.vaults[0].applied, again.vaults[0].skipped), (0, 50));

    // The QR channel produced exactly the file-sync state.
    let root = tempfile::tempdir().unwrap();
    let root_s = root.path().to_string_lossy().into_owned();
    for s in [&a.session, &b.session] {
        engine::setup(s, vault_id, &root_s, &FsStoreFactory).unwrap();
        let v = s.open_vault(vault_id).unwrap();
        engine::push(s, &v, &FsStoreFactory).unwrap();
    }
    for s in [&a.session, &b.session] {
        let v = s.open_vault(vault_id).unwrap();
        let pulled = engine::pull(s, &v, &FsStoreFactory).unwrap();
        assert_eq!(
            pulled.applied, 0,
            "file sync found an op the QR stream missed"
        );
        assert!(!pulled.has_alarms());
    }
}

/// Edits on the receiver travel back, and the "what I have" code makes the
/// next bundle carry only what is missing.
#[test]
fn the_have_code_sends_only_what_is_missing_in_both_directions() {
    let a = device("pw-a");
    let b = device("pw-b");
    pin(&a.session, &b.session, "b");
    pin(&b.session, &a.session, "a");
    let vault_id = a.session.create_vault("work").unwrap();
    let item = {
        let v = a.session.open_vault(vault_id).unwrap();
        let first = v.create_item(&login("GitLab", "one")).unwrap();
        for i in 0..5 {
            v.create_item(&login(&format!("svc-{i}"), "pw")).unwrap();
        }
        first
    };
    let share = ExportOptions {
        share: vec![vault_id],
        peer: Some(b.session.device_id()),
        ..ExportOptions::default()
    };
    let (bytes, _) = bundle::export(&a.session, &share).unwrap();
    bundle::import(&b.session, &bytes, None).unwrap();

    // Both sides edit.
    a.session
        .open_vault(vault_id)
        .unwrap()
        .update_item(item, &login("GitLab", "two"))
        .unwrap();
    {
        let v = b.session.open_vault(vault_id).unwrap();
        v.create_item(&login("Fastmail", "from-b")).unwrap();
        v.create_item(&login("Proton", "from-b")).unwrap();
    }

    // B → A, with A's code: only B's two new ops travel.
    let code_a =
        HaveCode::from_text(&HaveCode::build(&a.session, &[]).unwrap().to_text().unwrap()).unwrap();
    let (bytes, summary) = bundle::export(
        &b.session,
        &ExportOptions {
            have: Some(code_a),
            ..ExportOptions::default()
        },
    )
    .unwrap();
    assert_eq!(summary.vaults, vec![(vault_id, 2)]);
    assert_eq!(summary.recipient, Some(a.session.device_id()));
    let r = bundle::import(&a.session, &through_the_air(&bytes, 400, 2).1, None).unwrap();
    assert_eq!((r.vaults[0].applied, r.vaults[0].skipped), (2, 0));

    // A → B with B's code: only A's update travels (B's own ops never do).
    let code_b = HaveCode::build(&b.session, &[]).unwrap();
    let (bytes, summary) = bundle::export(
        &a.session,
        &ExportOptions {
            have: Some(code_b),
            ..ExportOptions::default()
        },
    )
    .unwrap();
    assert_eq!(summary.vaults, vec![(vault_id, 1)]);
    let r = bundle::import(&b.session, &bytes, None).unwrap();
    assert_eq!(r.vaults[0].applied, 1);
    assert_eq!(
        snapshot(&a.session, vault_id),
        snapshot(&b.session, vault_id)
    );

    // Up to date: nothing to send, said plainly.
    let code_b = HaveCode::build(&b.session, &[]).unwrap();
    let err = bundle::export(
        &a.session,
        &ExportOptions {
            have: Some(code_b),
            ..ExportOptions::default()
        },
    )
    .unwrap_err();
    assert!(err.to_string().contains("nothing to send"), "{err}");

    // Without a code, everything travels and the receiver skips what it has.
    let (bytes, summary) = bundle::export(&a.session, &ExportOptions::default()).unwrap();
    assert_eq!(summary.vaults, vec![(vault_id, 9)]);
    let r = bundle::import(&b.session, &bytes, None).unwrap();
    // B skips everything except its own two ops, which ingest drops before
    // counting.
    assert_eq!((r.vaults[0].applied, r.vaults[0].skipped), (0, 7));
}

/// Per vault id, `(author device id, claimed head)` pairs.
type ForgedHeads = Vec<([u8; 16], Vec<([u8; 16], u64)>)>;

/// A forged "what I have" code can only change what the sender selects.
#[test]
fn a_hostile_have_code_only_changes_what_is_sent() {
    let a = device("pw-a");
    let b = device("pw-b");
    let mallory = device("pw-m");
    pin(&a.session, &b.session, "b");
    pin(&b.session, &a.session, "a");
    let shared = a.session.create_vault("shared").unwrap();
    let private = a.session.create_vault("private").unwrap();
    for v in [shared, private] {
        a.session
            .open_vault(v)
            .unwrap()
            .create_item(&login("x", "y"))
            .unwrap();
    }
    let (bytes, _) = bundle::export(
        &a.session,
        &ExportOptions {
            vaults: vec![shared],
            share: vec![shared],
            peer: Some(b.session.device_id()),
            ..ExportOptions::default()
        },
    )
    .unwrap();
    bundle::import(&b.session, &bytes, None).unwrap();

    let forge = |device: [u8; 16], heads: ForgedHeads| HaveCode {
        device_id: Id::from_bytes(device),
        heads: heads
            .into_iter()
            .map(|(v, h)| (v, h.into_iter().collect::<BTreeMap<_, _>>()))
            .collect(),
    };
    let a_dev = *a.session.device_id().as_bytes();

    // Heads claimed far too high: the sender omits the ops (nothing to send).
    let high = forge(
        *mallory.session.device_id().as_bytes(),
        vec![(*shared.as_bytes(), vec![(a_dev, u64::MAX)])],
    );
    let only_shared = ExportOptions {
        vaults: vec![shared],
        have: Some(high),
        ..ExportOptions::default()
    };
    assert!(bundle::export(&a.session, &only_shared).is_err());

    // A code listing the private vault cannot add it: the user picked
    // `shared` only.
    let greedy = forge(
        *mallory.session.device_id().as_bytes(),
        vec![(*private.as_bytes(), vec![]), (*shared.as_bytes(), vec![])],
    );
    let (bytes, summary) = bundle::export(
        &a.session,
        &ExportOptions {
            vaults: vec![shared],
            have: Some(greedy.clone()),
            ..ExportOptions::default()
        },
    )
    .unwrap();
    assert_eq!(summary.vaults, vec![(shared, 1)]);
    assert!(summary.shares.is_empty(), "a code never causes a share");
    let parsed = bundle::parse(&bytes).unwrap();
    assert!(parsed.shares.is_empty());
    assert!(parsed.ops.iter().all(|(v, _)| *v == shared));

    // A code from another device than the one being shared with is refused.
    let err = bundle::export(
        &a.session,
        &ExportOptions {
            vaults: vec![shared],
            have: Some(greedy),
            share: vec![shared],
            peer: Some(b.session.device_id()),
            ..ExportOptions::default()
        },
    )
    .unwrap_err();
    assert!(err.to_string().contains("different device"), "{err}");

    // A code claiming B has nothing: everything is sent, and B, which really
    // has it all, just skips it. Its state is unchanged.
    let before = snapshot(&b.session, shared);
    let zero = forge(
        *b.session.device_id().as_bytes(),
        vec![(*shared.as_bytes(), vec![])],
    );
    let (bytes, _) = bundle::export(
        &a.session,
        &ExportOptions {
            have: Some(zero),
            ..ExportOptions::default()
        },
    )
    .unwrap();
    let r = bundle::import(&b.session, &bytes, None).unwrap();
    assert_eq!((r.vaults[0].applied, r.vaults[0].skipped), (0, 1));
    assert!(!r.has_alarms());
    assert_eq!(snapshot(&b.session, shared), before);
    assert!(!holds(&b.session, private));
}

/// Offset of the last byte of the first op in a bundle (a signature byte).
fn first_op_signature_byte(bytes: &[u8]) -> usize {
    let n = usize::from(u16::from_le_bytes([bytes[38], bytes[39]]));
    let mut pos = 40 + 16 * n + 4 + 32; // body start
    let shares_len = u32::from_le_bytes(bytes[pos..pos + 4].try_into().unwrap()) as usize;
    pos += 4 + shares_len; // first OPS section
    pos += 4 + 16; // its length, its vault id
    let op_len = u32::from_le_bytes(bytes[pos..pos + 4].try_into().unwrap()) as usize;
    pos + 4 + op_len - 1
}

/// Recompute a bundle's hash after editing it, as an attacker would.
fn rehash(bytes: &mut [u8]) {
    let n = usize::from(u16::from_le_bytes([bytes[38], bytes[39]]));
    let hash_at = 40 + 16 * n + 4;
    let mut all = bytes[..hash_at].to_vec();
    all.extend_from_slice(&bytes[hash_at + 32..]);
    let h = lp_crypto::blake3_256(&all);
    bytes[hash_at..hash_at + 32].copy_from_slice(&h);
}

#[test]
fn a_tampered_bundle_is_refused_by_its_hash_and_then_by_the_verifier() {
    let a = device("pw-a");
    let b = device("pw-b");
    pin(&a.session, &b.session, "b");
    pin(&b.session, &a.session, "a");
    let vault_id = a.session.create_vault("v").unwrap();
    a.session
        .open_vault(vault_id)
        .unwrap()
        .create_item(&login("one", "1"))
        .unwrap();
    let share = ExportOptions {
        share: vec![vault_id],
        peer: Some(b.session.device_id()),
        ..ExportOptions::default()
    };
    let (bytes, _) = bundle::export(&a.session, &share).unwrap();
    bundle::import(&b.session, &bytes, None).unwrap();
    a.session
        .open_vault(vault_id)
        .unwrap()
        .create_item(&login("two", "2"))
        .unwrap();
    let (good, _) = bundle::export(
        &a.session,
        &ExportOptions {
            have: Some(HaveCode::build(&b.session, &[]).unwrap()),
            ..ExportOptions::default()
        },
    )
    .unwrap();
    let before = snapshot(&b.session, vault_id);

    // 1. A flipped signature byte without a new hash: refused whole.
    let at = first_op_signature_byte(&good);
    let mut damaged = good.clone();
    damaged[at] ^= 0x01;
    let err = bundle::import(&b.session, &damaged, None).unwrap_err();
    assert!(err.to_string().contains("hash"), "{err}");
    assert_eq!(snapshot(&b.session, vault_id), before);

    // 2. The same flip with the hash recomputed (a deliberate forgery): the
    //    bundle parses, and the §5 verifier quarantines the op.
    rehash(&mut damaged);
    let r = bundle::import(&b.session, &damaged, None).unwrap();
    assert!(r.has_alarms());
    assert_eq!(r.vaults[0].applied, 0);
    assert_eq!(
        r.vaults[0].quarantines[0].alarm,
        lp_sync::Alarm::SignatureInvalid
    );
    assert_eq!(snapshot(&b.session, vault_id), before);

    // 3. Frames that belong to another transfer id are refused at import.
    let err = bundle::import(&b.session, &good, Some([0; 8])).unwrap_err();
    assert!(err.to_string().contains("do not belong"), "{err}");

    // The genuine bundle still applies.
    assert_eq!(
        bundle::import(&b.session, &good, None).unwrap().vaults[0].applied,
        1
    );
}

/// A stranger B never pinned can neither hand B a vault nor inject ops; ops it
/// merely forwards from a pinned author still verify.
#[test]
fn an_untrusted_sender_is_refused_and_untrusted_authors_are_quarantined() {
    let a = device("pw-a");
    let b = device("pw-b");
    let s = device("pw-s");
    // A trusts B and S; B trusts A only. S trusts both.
    for (x, y) in [(&a, &b), (&b, &a), (&a, &s), (&s, &a), (&s, &b)] {
        pin(&x.session, &y.session, "peer");
    }

    // S shares its own vault with B: refused (B never pinned S).
    let bait = s.session.create_vault("bait").unwrap();
    let (bytes, _) = bundle::export(
        &s.session,
        &ExportOptions {
            share: vec![bait],
            peer: Some(b.session.device_id()),
            ..ExportOptions::default()
        },
    )
    .unwrap();
    let r = bundle::import(&b.session, &bytes, None).unwrap();
    assert!(!r.sender_trusted);
    assert_eq!(r.shares_rejected.len(), 1);
    assert!(r.shares_adopted.is_empty());
    assert!(!holds(&b.session, bait));

    // A shares a vault with both; S edits it and sends B a bundle carrying
    // A's op (forwarded) and S's own op.
    let vault_id = a.session.create_vault("family").unwrap();
    a.session
        .open_vault(vault_id)
        .unwrap()
        .create_item(&login("router", "admin"))
        .unwrap();
    for to in [&b, &s] {
        let (bytes, _) = bundle::export(
            &a.session,
            &ExportOptions {
                share: vec![vault_id],
                peer: Some(to.session.device_id()),
                ..ExportOptions::default()
            },
        )
        .unwrap();
        bundle::import(&to.session, &bytes, None).unwrap();
    }
    s.session
        .open_vault(vault_id)
        .unwrap()
        .create_item(&login("from-s", "evil"))
        .unwrap();
    a.session
        .open_vault(vault_id)
        .unwrap()
        .create_item(&login("from-a", "good"))
        .unwrap();
    // S has A's new op too, via another bundle from A.
    let (bytes, _) = bundle::export(
        &a.session,
        &ExportOptions {
            have: Some(HaveCode::build(&s.session, &[]).unwrap()),
            ..ExportOptions::default()
        },
    )
    .unwrap();
    bundle::import(&s.session, &bytes, None).unwrap();

    let (bytes, _) = bundle::export(
        &s.session,
        &ExportOptions {
            have: Some(HaveCode::build(&b.session, &[]).unwrap()),
            ..ExportOptions::default()
        },
    )
    .unwrap();
    let r = bundle::import(&b.session, &bytes, None).unwrap();
    let line = &r.vaults[0];
    assert_eq!(line.applied, 1, "A's forwarded op verifies");
    assert_eq!(line.quarantines.len(), 1);
    assert_eq!(line.quarantines[0].device_id, s.session.device_id());
    assert_eq!(line.quarantines[0].alarm, lp_sync::Alarm::UnknownDevice);
    let titles: Vec<String> = b
        .session
        .open_vault(vault_id)
        .unwrap()
        .list_items()
        .unwrap()
        .into_iter()
        .map(|i| i.payload.title)
        .collect();
    assert!(!titles.iter().any(|t| t == "from-s"), "{titles:?}");
    assert!(titles.iter().any(|t| t == "from-a"));
}

#[test]
fn attachments_stay_behind_unless_asked_for_and_are_re_hashed() {
    let a = device("pw-a");
    let b = device("pw-b");
    pin(&a.session, &b.session, "b");
    pin(&b.session, &a.session, "a");
    let vault_id = a.session.create_vault("docs").unwrap();
    let body: Vec<u8> = (0..20_000u32).map(|i| (i * 13 % 256) as u8).collect();
    {
        let v = a.session.open_vault(vault_id).unwrap();
        let item = v.create_item(&login("Passport", "-")).unwrap();
        v.add_attachment(item, "passport.pdf", &body).unwrap();
    }
    let share = ExportOptions {
        share: vec![vault_id],
        peer: Some(b.session.device_id()),
        ..ExportOptions::default()
    };
    let (bytes, summary) = bundle::export(&a.session, &share).unwrap();
    assert_eq!(summary.blobs, 0);
    let r = bundle::import(&b.session, &bytes, None).unwrap();
    assert_eq!(
        (r.vaults[0].blobs_stored, r.vaults[0].blobs_missing),
        (0, 1)
    );

    let (bytes, summary) = bundle::export(
        &a.session,
        &ExportOptions {
            attachments: true,
            ..ExportOptions::default()
        },
    )
    .unwrap();
    assert_eq!(summary.blobs, 1);
    let (_, received, _) = through_the_air(&bytes, 1000, 3);
    let r = bundle::import(&b.session, &received, None).unwrap();
    assert_eq!(
        (r.vaults[0].blobs_stored, r.vaults[0].blobs_missing),
        (1, 0)
    );
    assert!(!r.has_alarms());
    let v = b.session.open_vault(vault_id).unwrap();
    let item = v.list_items().unwrap()[0].item_id;
    let atts = v.list_attachments(item).unwrap();
    assert_eq!(v.get_attachment(atts[0].attachment_id).unwrap().1, body);

    // Receiving the same blobs again stores nothing new.
    let r = bundle::import(&b.session, &received, None).unwrap();
    assert_eq!(
        (r.vaults[0].blobs_stored, r.vaults[0].blobs_ignored),
        (0, 1)
    );
}

#[test]
fn a_stream_mixed_with_another_transfer_and_junk_still_completes() {
    let a = device("pw-a");
    let vault_id = a.session.create_vault("v").unwrap();
    {
        let v = a.session.open_vault(vault_id).unwrap();
        for i in 0..10 {
            v.create_item(&login(&format!("i{i}"), "p")).unwrap();
        }
    }
    let (one, _) = bundle::export(&a.session, &ExportOptions::default()).unwrap();
    a.session
        .open_vault(vault_id)
        .unwrap()
        .create_item(&login("later", "p"))
        .unwrap();
    let (two, _) = bundle::export(&a.session, &ExportOptions::default()).unwrap();
    let e1 = qr::encoder_for(&one, 500).unwrap();
    let e2 = qr::encoder_for(&two, 500).unwrap();
    assert_ne!(e1.transfer_id(), e2.transfer_id());

    let now = Instant::now();
    let mut dec = FrameDecoder::new();
    let k = e1.source_symbols();
    let mut esi = 0;
    while !dec.progress().complete {
        let f1 = e1.frames(esi, 1).remove(0);
        dec.push(&f1, now);
        dec.push(&e2.frames(esi, 1).remove(0), now);
        let mut corrupt = f1.clone();
        corrupt[30] ^= 0xFF;
        dec.push(&corrupt, now);
        dec.push(b"https://example.com/not-a-frame", now);
        dec.decode(now);
        esi += 1;
        assert!(esi < 3 * k);
    }
    let p = dec.progress().clone();
    assert_eq!(p.other_transfer, esi);
    assert_eq!(p.invalid, 2 * esi);
    assert_eq!(dec.take().unwrap().1, one);
}
