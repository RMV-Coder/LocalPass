//! The channel-backend injection seam (sync-protocol.md §7): the engine treats
//! a vault's sync root as an **opaque string** and opens it through the
//! caller-supplied `StoreFactory`, never by constructing a backend itself.
//!
//! These tests pin the two properties Stage 1 of the Android SAF port depends
//! on, both of which are invisible from the desktop call sites:
//!
//! 1. the root is persisted and returned **verbatim** — no path normalization,
//!    no `to_string_lossy` round-trip — so a `content://…` tree URI survives; and
//! 2. a factory defined **outside** `lp-sync` is what resolves it, so an app
//!    that cannot be a dependency of the core can still supply the backend.

mod common;

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use lp_sync::engine;
use lp_sync::store::{FsStore, FsStoreFactory, Store, StoreFactory};
use lp_sync::{Error, Result};

use common::new_vault;

/// A factory standing in for a host's own (e.g. SAF) backend: it records every
/// root string it is handed, claims only its own `lp-test://` scheme, and serves
/// the channel out of a temp dir the test controls.
struct SchemeFactory {
    /// Where the pretend non-filesystem channel actually lives.
    backing: std::path::PathBuf,
    /// The exact root strings the engine asked this factory to open.
    seen: Arc<std::sync::Mutex<Vec<String>>>,
    /// How many times the engine resolved a root through us.
    opens: Arc<AtomicUsize>,
}

impl StoreFactory for SchemeFactory {
    fn open(&self, root: &str) -> Result<Arc<dyn Store>> {
        self.seen.lock().unwrap().push(root.to_string());
        self.opens.fetch_add(1, Ordering::SeqCst);
        if !root.starts_with("lp-test://") {
            return Err(Error::Invalid("not an lp-test:// root"));
        }
        Ok(Arc::new(FsStore::new(&self.backing)))
    }
}

/// A root that is emphatically not a filesystem path must survive `setup` →
/// `enrolled_root` → `status` byte-for-byte, and be the exact string the
/// factory is asked to open.
#[test]
fn an_opaque_root_is_persisted_and_resolved_verbatim() {
    // Deliberately full of the characters a path round-trip would rewrite:
    // a scheme, percent-escapes, and forward slashes on a Windows-capable build.
    const ROOT: &str = "lp-test://tree/primary%3ASync%2FLocalPass/./x";

    let tv = new_vault();
    let backing = tempfile::tempdir().unwrap();
    let factory = SchemeFactory {
        backing: backing.path().to_path_buf(),
        seen: Arc::new(std::sync::Mutex::new(Vec::new())),
        opens: Arc::new(AtomicUsize::new(0)),
    };

    engine::setup(&tv.session, tv.vault_id, ROOT, &factory).unwrap();

    // Persisted verbatim.
    assert_eq!(
        engine::enrolled_root(&tv.session, tv.vault_id).unwrap(),
        Some(ROOT.to_string())
    );

    // `push`/`status` resolve that same string through the factory.
    let vault = tv.session.open_vault(tv.vault_id).unwrap();
    engine::push(&tv.session, &vault, &factory).unwrap();
    let st = engine::status(&tv.session, &vault, &factory).unwrap();
    assert!(st.enrolled);
    assert_eq!(st.root.as_deref(), Some(ROOT));

    // The §7.1 scaffold landed in the factory's backend, not in some path the
    // engine guessed from the root string.
    assert!(
        backing
            .path()
            .join(tv.vault_id.to_hyphenated())
            .join("ops")
            .is_dir()
    );

    // Every open saw the untouched root.
    let seen = factory.seen.lock().unwrap();
    assert!(!seen.is_empty());
    assert!(
        seen.iter().all(|s| s == ROOT),
        "root was rewritten: {seen:?}"
    );
    assert!(factory.opens.load(Ordering::SeqCst) >= 3); // setup + push + status
}

/// A factory that refuses a root it does not recognize surfaces as a normal
/// engine error — the engine has no fallback backend of its own.
#[test]
fn a_factory_may_refuse_a_root_it_does_not_recognize() {
    let tv = new_vault();
    let backing = tempfile::tempdir().unwrap();
    let factory = SchemeFactory {
        backing: backing.path().to_path_buf(),
        seen: Arc::new(std::sync::Mutex::new(Vec::new())),
        opens: Arc::new(AtomicUsize::new(0)),
    };
    let err = engine::setup(&tv.session, tv.vault_id, "/home/alice/Sync", &factory)
        .expect_err("a refused root must not enroll");
    assert!(matches!(err, Error::Invalid(_)));
    // Nothing was enrolled: a failed `setup` records no root.
    assert_eq!(
        engine::enrolled_root(&tv.session, tv.vault_id).unwrap(),
        None
    );
}

/// Desktop's regression guard: with [`FsStoreFactory`], the value stored under
/// `sync.root.<vault_id>` is exactly the string the caller passed — the same
/// bytes the engine wrote when it did the `Path` → `to_string_lossy` conversion
/// internally — so a profile enrolled before the injection refactor still
/// resolves afterwards.
#[test]
fn fs_roots_persist_exactly_as_the_caller_spelled_them() {
    let tv = new_vault();
    let dir = tempfile::tempdir().unwrap();
    // The CLI's conversion, performed at the boundary.
    let root = dir.path().to_string_lossy().into_owned();

    engine::setup(&tv.session, tv.vault_id, &root, &FsStoreFactory).unwrap();
    assert_eq!(
        engine::enrolled_root(&tv.session, tv.vault_id).unwrap(),
        Some(root.clone())
    );
    // …and it is still a path the filesystem backend opens, with the §7.1
    // scaffold under the dir the user actually named.
    assert!(
        dir.path()
            .join(tv.vault_id.to_hyphenated())
            .join("ops")
            .is_dir()
    );

    // A pre-existing enrollment (the value a pre-refactor `setup` wrote) is
    // read back and used without a re-`setup`.
    let vault = tv.session.open_vault(tv.vault_id).unwrap();
    let st = engine::status(&tv.session, &vault, &FsStoreFactory).unwrap();
    assert_eq!(st.root, Some(root));
}
