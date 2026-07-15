// SPDX-License-Identifier: MPL-2.0
// This file is part of the LocalPass desktop GUI. See apps/desktop/LICENSE.

//! **Android only.** The SAF (Storage Access Framework) channel backend: an
//! [`lp_sync::store::Store`] over a user-picked `content://` tree URI, plus the
//! [`AppStoreFactory`] that selects it, and the directory picker behind the
//! `pick_sync_dir` command.
//!
//! # Why this lives here and not in `lp-sync`
//!
//! Android scoped storage means a folder the user picked outside our app-private
//! directory is **not** a filesystem path — it is a `content://` tree URI that
//! [`std::fs`] can never open, and that must be walked through
//! `DocumentsContract` over JNI. So `lp_sync::store::FsStore` simply cannot work
//! there. But the AGPL core must never depend on Tauri (PRD §5.6), so the SAF
//! backend lives in this MPL GUI crate and is injected into the engine through
//! the core's [`lp_sync::store::StoreFactory`] seam (see `daemon.rs`). The §7.1
//! layout, the §5 verifier and the §4 merge above it are unchanged and unaware.
//!
//! # Security boundary
//!
//! Nothing secret crosses into the plugin. §7 segments and attachment blobs are
//! ciphertext on the channel and the manifest is advisory plaintext, exactly as
//! on desktop's [`lp_sync::store::FsStore`] — the channel is fully untrusted and
//! §5 verification is what protects the log. The plugin only ever sees those
//! already-encrypted bytes and the tree URI the user chose.
//!
//! Note also that the plugin's JS/IPC command layer is **compiled out**
//! (`default-features = false` in Cargo.toml): every call below reaches Kotlin
//! through `run_mobile_plugin`, which does not route through the Tauri ACL. The
//! webview therefore has no SAF reach whatsoever — consistent with the rest of
//! the app, where the webview renders and Rust does the I/O.
//!
//! # Error mapping
//!
//! The plugin's error type is opaque: its inner enum is private and it exposes
//! no `kind()` and no not-found discriminator, so a missing entry cannot be told
//! from a real failure by matching. Where the [`Store`] contract needs that
//! distinction we therefore synthesize it *structurally*, via the plugin's
//! `resolve_*_uri` methods, which are documented to "Error occurs, if the file
//! does not exist" — see [`SafStore::resolve_file`] / [`SafStore::resolve_dir`]
//! and the conflation caveat recorded there.

use std::io;
use std::path::{Component, Path, PathBuf};
use std::sync::Arc;

use lp_sync::error::{Error, Result};
use lp_sync::store::{DirEntry, FsStoreFactory, Store, StoreFactory, StorePath};
use tauri::AppHandle;
use tauri_plugin_android_fs::{AndroidFsExt, FsUri};

/// The URI scheme prefix that marks a channel root as a SAF tree rather than a
/// filesystem path. This is the *only* thing [`AppStoreFactory`] inspects.
const SAF_SCHEME: &str = "content://";

/// The MIME type every channel file is created with. The §7 layout's files are
/// opaque ciphertext (segments, blobs) or small JSON (the advisory manifest);
/// none of it is a media type Android should reason about, and a generic binary
/// type keeps the file provider from inferring anything.
const CHANNEL_MIME: &str = "application/octet-stream";

/// The suffix [`Store::write_atomic`] gives its temporary file before renaming
/// it onto the target. Deliberately **not** produced by the §7.1 layout (whose
/// names end in `.oplog`, `.blob`, `.json`), so a temp file can never collide
/// with, or be mistaken for, a real channel entry.
const TMP_SUFFIX: &str = ".lptmp";

/// Wrap a plugin/IO failure as the sync engine's [`Error::Io`]. The plugin's
/// error carries no `io::ErrorKind`, so this is always a generic "other" — the
/// not-found case is synthesized structurally instead (see the module docs).
fn io_err(context: &str, e: &impl std::fmt::Display) -> Error {
    Error::Io(io::Error::other(format!("SAF {context}: {e}")))
}

/// A not-found [`Error::Io`], the shape [`lp_sync::store::is_not_found`] tests.
fn not_found(what: &str) -> Error {
    Error::Io(io::Error::new(
        io::ErrorKind::NotFound,
        format!("SAF: no such entry: {what}"),
    ))
}

/// The [`lp_sync::store::StoreFactory`] the Android app injects into the engine.
///
/// It recognizes exactly one root shape of its own — a `content://` SAF tree URI
/// — and delegates everything else to the core's [`FsStoreFactory`], so an
/// Android build can still sync to a plain path (e.g. the app-private dir, or a
/// `/sdcard` path on an older device) with the core's own backend.
///
/// The root string is passed through **verbatim**, never normalized: it is the
/// exact string the user's enrollment persisted (`sync.root.<vault_id>`), and
/// for SAF it is an opaque URI whose every byte is significant.
///
/// Desktop does not compile this module at all — there the engine keeps the
/// core's default [`FsStoreFactory`], exactly as before (see `daemon.rs`).
pub struct AppStoreFactory {
    /// The handle every [`SafStore`] this factory opens reaches the plugin
    /// through. Stashed by `lib.rs`'s `setup()` hook (see `daemon::app_handle`).
    app: AppHandle,
}

impl AppStoreFactory {
    /// Bind a factory to the app handle its SAF stores will use.
    #[must_use]
    pub fn new(app: AppHandle) -> Self {
        Self { app }
    }
}

impl StoreFactory for AppStoreFactory {
    /// Open `root`: a SAF [`SafStore`] for a `content://` tree URI, else the
    /// core's [`lp_sync::store::FsStore`].
    ///
    /// # Errors
    ///
    /// [`Error::Io`] if a `content://` root cannot be bound — most importantly
    /// when this app no longer holds a persisted permission for that tree (the
    /// user revoked it, or Android evicted it); see [`SafStore::open`].
    fn open(&self, root: &str) -> Result<Arc<dyn Store>> {
        if root.starts_with(SAF_SCHEME) {
            return Ok(Arc::new(SafStore::open(self.app.clone(), root)?));
        }
        FsStoreFactory.open(root)
    }
}

/// An [`lp_sync::store::Store`] rooted at a user-picked SAF directory tree.
///
/// `Send + Sync` (as [`Store`] requires) because [`AppHandle`] is `Clone + Send
/// + Sync` and [`FsUri`] is plain data.
pub struct SafStore {
    /// The handle the plugin is reached through.
    app: AppHandle,
    /// The store root, as the **plugin's own** [`FsUri`] — see
    /// [`SafStore::open`] for why this may not be reconstructed by hand.
    root: FsUri,
}

impl SafStore {
    /// Bind a store to the SAF tree the root URI string names.
    ///
    /// # Why this is a lookup and not `FsUri::from_uri(root)`
    ///
    /// An [`FsUri`] for a picked directory is a **pair**, not a string: `uri` is
    /// a *document* URI (`…/tree/<id>/document/<id>`) while `document_top_tree_uri`
    /// is the *tree* URI (`…/tree/<id>`) it came from — two different strings.
    /// The plugin's Kotlin side dereferences the latter with a non-null assertion
    /// (`dirUri.documentTopTreeUri!!` in `DocumentFileController.readDir`), so an
    /// `FsUri::from_uri(root)` — which hard-codes that field to `None` — would
    /// not fail gracefully, it would raise a **NullPointerException** on the
    /// first directory listing.
    ///
    /// Rather than reconstruct the tree URI by string surgery, this asks the
    /// plugin for the authoritative pair: `get_all_persisted_uri_permissions`
    /// rebuilds both fields from the persisted grant exactly as the picker did,
    /// and we match on the `uri` field we persisted. That also means binding
    /// *checks the grant*: if the user revoked access to the folder, or Android
    /// evicted the grant (it caps how many a app may hold), we fail here with a
    /// clear, actionable message instead of deep inside a sync run.
    ///
    /// # Errors
    ///
    /// [`Error::Io`] if the persisted-permission list cannot be read, or if no
    /// persisted grant matches `root` (re-pick the folder to re-grant).
    pub fn open(app: AppHandle, root: &str) -> Result<Self> {
        let grants = app
            .android_fs()
            .picker()
            .get_all_persisted_uri_permissions()
            .map_err(|e| io_err("reading persisted folder permissions", &e))?;

        let uri = grants
            .into_iter()
            .map(tauri_plugin_android_fs::PersistedUriPermissionState::into_uri)
            .find(|u| u.uri == root)
            .ok_or_else(|| {
                Error::Io(io::Error::other(
                    "LocalPass no longer has permission for this sync folder \
                     (it was revoked, or Android released it). Choose the folder \
                     again to re-grant access.",
                ))
            })?;

        Ok(Self { app, root: uri })
    }

    /// The plugin's blocking file API.
    ///
    /// Blocking is correct here: [`Store`] is a synchronous trait, and every
    /// call runs on the Tauri command worker thread (via `daemon::call`), never
    /// on the Android main thread.
    fn fs(&self) -> &tauri_plugin_android_fs::api::api_sync::AndroidFs<tauri::Wry> {
        self.app.android_fs()
    }

    /// A [`StorePath`] as the plugin's relative path.
    ///
    /// The plugin's relative-path methods take a whole nested path and create
    /// missing parents themselves, so `ops/<device_id>/<name>.oplog` is **one**
    /// call — we never walk segments.
    fn rel(path: &StorePath) -> PathBuf {
        path.segments().iter().collect()
    }

    /// Normalize a relative path the plugin **handed back**, for comparison
    /// against the one we asked for.
    ///
    /// # Working around a plugin bug
    ///
    /// `create_new_file_and_return_relative_path` builds its result as
    /// `"{parent}/{name}"` with the parent trimmed of slashes — so for a file
    /// directly under the root the parent is empty and it returns a
    /// **leading-slash** path (`/manifest.json` for `manifest.json`). That is a
    /// bug in the plugin (its own `resolve_file_uri` then rejects the result:
    /// its validator refuses a root component), but we must not let it read as
    /// "the provider renamed our file" — that is the difference between a
    /// spurious hard failure and a correct write. Dropping the root component
    /// makes the comparison meaningful; it cannot mask a real rename, since a
    /// sanitized *name* still differs after normalization.
    fn normalize_returned(p: &Path) -> PathBuf {
        p.components()
            .filter(|c| !matches!(c, Component::RootDir))
            .collect()
    }

    /// Resolve `path` to an existing **file**, or `Ok(None)` if it is absent.
    ///
    /// # Caveat (documented conflation)
    ///
    /// `resolve_file_uri` is documented to error when the file does not exist,
    /// but the plugin's error type exposes no not-found discriminator, so a
    /// genuine failure (a dead provider, a revoked grant) is indistinguishable
    /// from absence and is also reported here as `Ok(None)`. This matches how
    /// the callers behave anyway — §7 readers treat a missing entry as empty —
    /// and the channel is untrusted, so a wrongly-empty read is a no-op, never a
    /// correctness or safety problem: it can only cause a retry on the next sync.
    ///
    /// # Errors
    ///
    /// Currently infallible, but returns [`Result`] so a future plugin release
    /// that *can* report not-found precisely can tighten this without churning
    /// every caller.
    fn resolve_file(&self, path: &StorePath) -> Result<Option<FsUri>> {
        if path.is_empty() {
            // The root is a directory, never a file.
            return Ok(None);
        }
        Ok(self.fs().resolve_file_uri(&self.root, Self::rel(path)).ok())
    }

    /// Resolve `path` to an existing **directory**.
    ///
    /// The empty path is the store root itself, which is the tree the user
    /// picked and therefore always exists.
    ///
    /// # Errors
    ///
    /// A not-found [`Error::Io`] if the directory does not exist — the shape
    /// [`lp_sync::store::is_not_found`] tests, which [`Store::list_dir`]'s
    /// contract requires so callers can tell "no such directory" from
    /// "unreadable". Subject to the same conflation caveat as
    /// [`SafStore::resolve_file`].
    fn resolve_dir(&self, path: &StorePath) -> Result<FsUri> {
        if path.is_empty() {
            return Ok(self.root.clone());
        }
        self.fs()
            .resolve_dir_uri(&self.root, Self::rel(path))
            .map_err(|_| not_found(&path.to_string()))
    }
}

impl Store for SafStore {
    /// Create `path` and every missing parent; an existing directory is not an
    /// error (the plugin's `create_dir_all` is idempotent and returns the
    /// existing URI).
    ///
    /// # Errors
    ///
    /// [`Error::Io`] if the directory cannot be created, or if the file provider
    /// **sanitized** the name into something other than what we asked for (see
    /// [`Store::write_atomic`]'s note on why an unverified name is corruption).
    fn create_dir_all(&self, path: &StorePath) -> Result<()> {
        if path.is_empty() {
            // The root is the picked tree; it exists by construction.
            return Ok(());
        }
        let want = Self::rel(path);
        let (_, got) = self
            .fs()
            .create_dir_all_and_return_relative_path(&self.root, &want)
            .map_err(|e| io_err(&format!("creating directory {path}"), &e))?;

        let got = Self::normalize_returned(&got);
        if got != want {
            return Err(io_err(
                "creating directory",
                &format!(
                    "the file provider stored {path} as {} — the channel layout \
                     requires exact names",
                    got.display()
                ),
            ));
        }
        Ok(())
    }

    /// Write `bytes` to `path` such that a concurrent reader never observes a
    /// partially written file.
    ///
    /// # How, without a POSIX rename
    ///
    /// SAF has no rename-that-overwrites: the plugin's `write` replaces contents
    /// **in place**, which a reader can catch half-done, and its `rename` refuses
    /// to clobber an existing target. So, mirroring [`lp_sync::store::FsStore`]'s
    /// temp-then-rename: create a uniquely-suffixed temp file beside the target,
    /// write it whole, remove any pre-existing target, then rename the temp onto
    /// the target name. A reader therefore sees *old → (briefly absent) → new*,
    /// and never a partial file — which is what the contract asks for.
    ///
    /// In practice the "pre-existing target" case is rare by design: §7 segments
    /// and blobs are immutable and uniquely named, so only the advisory
    /// `manifest.json` is ever overwritten, and it is advisory precisely because
    /// a reader may miss it.
    ///
    /// # Why the names are verified
    ///
    /// **Critical.** The file provider may append a sequential suffix (`(1)`) on
    /// a name collision instead of overwriting, and may sanitize names besides.
    /// A silently-renamed segment is channel corruption: the §7.1 layout is
    /// addressed *by name*, so a `x.oplog (1)` is simply lost, while its absence
    /// reads as a gap. Both the temp creation and the final rename therefore
    /// **verify that the resulting name is exactly the one requested** and fail
    /// loudly (cleaning up) if it is not — never silently.
    ///
    /// # Errors
    ///
    /// [`Error::Invalid`] if `path` is the store root (no file name);
    /// [`Error::Io`] on any write failure, or on a name the provider altered.
    fn write_atomic(&self, path: &StorePath, bytes: &[u8]) -> Result<()> {
        let name = path
            .file_name()
            .ok_or(Error::Invalid("cannot write to the store root itself"))?
            .to_owned();

        let target = Self::rel(path);
        let tmp_want = target.with_file_name(format!("{name}{TMP_SUFFIX}"));
        let fs = self.fs();

        // 1. Create the temp file exclusively, and verify the provider gave us
        //    the exact name we asked for.
        let (tmp_uri, tmp_got) = fs
            .create_new_file_and_return_relative_path(&self.root, &tmp_want, Some(CHANNEL_MIME))
            .map_err(|e| io_err(&format!("creating a temporary file for {path}"), &e))?;

        let tmp_got = Self::normalize_returned(&tmp_got);
        if tmp_got != tmp_want {
            let _ = fs.remove_file(&tmp_uri);
            return Err(io_err(
                "creating a temporary file",
                &format!(
                    "the file provider stored it as {} rather than {} — refusing \
                     to continue",
                    tmp_got.display(),
                    tmp_want.display()
                ),
            ));
        }

        // 2. Fill it. Nothing reads this name, so a partial temp is harmless.
        if let Err(e) = fs.write(&tmp_uri, bytes) {
            let _ = fs.remove_file(&tmp_uri);
            return Err(io_err(&format!("writing {path}"), &e));
        }

        // 3. Clear any pre-existing target: `rename` will not overwrite, it
        //    would suffix instead. This opens the brief "absent" window.
        if let Some(old) = self.resolve_file(path)?
            && let Err(e) = fs.remove_file(&old)
        {
            let _ = fs.remove_file(&tmp_uri);
            return Err(io_err(&format!("replacing {path}"), &e));
        }

        // 4. Rename the temp onto the target name, and verify the result really
        //    is that name (see "Why the names are verified" above).
        let new_uri = match fs.rename(&tmp_uri, &name) {
            Ok(u) => u,
            Err(e) => {
                let _ = fs.remove_file(&tmp_uri);
                return Err(io_err(&format!("publishing {path}"), &e));
            }
        };

        match fs.get_name(&new_uri) {
            Ok(got) if got == name => Ok(()),
            Ok(got) => {
                let _ = fs.remove_file(&new_uri);
                Err(io_err(
                    "publishing",
                    &format!(
                        "the file provider named the file {got} rather than \
                         {name} (a name collision it resolved by suffixing) — \
                         refusing to corrupt the channel layout"
                    ),
                ))
            }
            Err(e) => {
                let _ = fs.remove_file(&new_uri);
                Err(io_err(&format!("verifying the name of {path}"), &e))
            }
        }
    }

    /// Read `path` whole, or `Ok(None)` if it does not exist.
    ///
    /// # Errors
    ///
    /// [`Error::Io`] if the file resolves but cannot be read. A file that does
    /// not resolve is `Ok(None)` (see [`SafStore::resolve_file`]).
    fn read(&self, path: &StorePath) -> Result<Option<Vec<u8>>> {
        let Some(uri) = self.resolve_file(path)? else {
            return Ok(None);
        };
        self.fs()
            .read(&uri)
            .map(Some)
            .map_err(|e| io_err(&format!("reading {path}"), &e))
    }

    /// List the direct children of the directory `path`.
    ///
    /// # Errors
    ///
    /// [`Error::Io`] if the directory cannot be read, including a not-found for
    /// a directory that does not exist — callers distinguish that with
    /// [`lp_sync::store::is_not_found`] and treat it as empty.
    fn list_dir(&self, path: &StorePath) -> Result<Vec<DirEntry>> {
        let uri = self.resolve_dir(path)?;
        let entries = self
            .fs()
            .read_dir(&uri)
            .map_err(|e| io_err(&format!("listing {path}"), &e))?;

        Ok(entries
            .into_iter()
            .map(|e| DirEntry {
                name: e.name().to_owned(),
                is_dir: e.is_dir(),
            })
            .collect())
    }

    /// Whether an entry exists at `path`.
    ///
    /// The plugin has no `exists`, so this is synthesized from the `resolve_*`
    /// methods, which error when the entry is absent. Both are tried because a
    /// [`StorePath`] may name either a file or a directory.
    ///
    /// # Errors
    ///
    /// Does not currently fail: an unresolvable entry is reported as `false`.
    /// Per [`SafStore::resolve_file`]'s caveat, the plugin cannot distinguish
    /// "absent" from "failed", and `false` is the safe reading for both — the
    /// §7 callers use `exists` to decide whether to create something, and a
    /// spurious `false` leads to a create that then fails loudly on its own.
    fn exists(&self, path: &StorePath) -> Result<bool> {
        if path.is_empty() {
            return Ok(true);
        }
        if self.resolve_file(path)?.is_some() {
            return Ok(true);
        }
        let rel = Self::rel(path);
        Ok(self.fs().resolve_dir_uri(&self.root, rel).is_ok())
    }

    /// Remove the file at `path`. A missing file is a no-op — mirroring
    /// [`lp_sync::store::FsStore`], which absorbs `NotFound` from
    /// [`std::fs::remove_file`].
    ///
    /// # Errors
    ///
    /// [`Error::Io`] if the file resolves but cannot be removed.
    fn remove_file(&self, path: &StorePath) -> Result<()> {
        let Some(uri) = self.resolve_file(path)? else {
            return Ok(());
        };
        self.fs()
            .remove_file(&uri)
            .map_err(|e| io_err(&format!("removing {path}"), &e))
    }
}

/// Show the Android directory picker, take a **persistable** grant on what the
/// user chose, and return its URI string for `sync_setup` / `sync_adopt`.
///
/// The returned string is the plugin's own `uri` field, passed to the existing
/// `sync_setup(vault, dir)` unchanged — there is no protocol change, the engine
/// persists it verbatim in `sync.root.<vault_id>`, and [`AppStoreFactory`] later
/// recognizes it by its `content://` scheme. [`SafStore::open`] turns it back
/// into a full [`FsUri`] via the persisted-grant list.
///
/// # Why the grant is persisted
///
/// A picker result is valid only until the app is terminated. `sync.root` is
/// durable, so without `persist_uri_permission` every sync after a restart would
/// fail. Persisting requires no extra user confirmation — the pick *is* the
/// consent.
///
/// # Why `local_only`
///
/// `local_only: true` hides cloud DocumentsProviders from the picker. A remote
/// provider need not implement `rename`, and [`Store::write_atomic`] depends on
/// rename for its "a reader never sees a partial file" guarantee — so a folder
/// we could not write atomically is better refused at pick time than discovered
/// mid-sync. It also matches what the feature is *for*: a folder some other
/// tool (Syncthing, a USB stick) replicates, which is by definition local.
///
/// # Errors
///
/// A secret-free message if the picker or the permission grant fails. A
/// cancelled pick is `Ok(None)`.
pub async fn pick_sync_dir(app: &AppHandle) -> std::result::Result<Option<String>, String> {
    // The async API on purpose: the picker suspends on an Android activity
    // result, so this must not occupy a thread waiting for the UI.
    let api = app.android_fs_async();

    let picked = api
        .picker()
        .pick_dir(None, true)
        .await
        .map_err(|e| format!("could not open the folder picker: {e}"))?;

    let Some(uri) = picked else {
        return Ok(None); // The user cancelled.
    };

    api.picker()
        .persist_uri_permission(&uri)
        .await
        .map_err(|e| format!("could not keep access to that folder: {e}"))?;

    Ok(Some(uri.uri))
}
