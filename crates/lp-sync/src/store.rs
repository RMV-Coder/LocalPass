//! The channel storage seam (sync-protocol.md §7) — the [`Store`] trait and its
//! [`std::fs`] implementation, [`FsStore`].
//!
//! §7 log shipping deliberately assumes nothing about the channel beyond "a
//! folder someone else replicates". [`Store`] makes that assumption explicit:
//! it is the *whole* set of I/O primitives [`crate::shipping::SyncDir`] needs to
//! realize the §7.1 layout, and nothing else. The sync semantics — segment
//! immutability, the advisory manifest, chain heads, content-addressed blobs —
//! live entirely above it, in [`crate::shipping`].
//!
//! # Why a trait and not just `std::fs`
//!
//! On desktop the channel root is an ordinary directory and [`FsStore`] is the
//! only implementation. On other hosts the user-picked folder may not be a
//! filesystem path at all — Android's Storage Access Framework hands back a
//! `content://` tree URI that `std::fs` cannot open, and which must be walked
//! through a platform API instead. Keeping the channel's I/O behind one
//! object-safe trait means such a backend is a new `impl Store` selected at
//! runtime, with **zero** change to the §5 verifier, the §4 merge, or the §7
//! layout above it.
//!
//! # Addressing (`StorePath`, not `Path`)
//!
//! Entries are addressed by [`StorePath`] — a *relative* sequence of plain name
//! segments rooted at the store's own root — never by an absolute
//! [`std::path::Path`]. A `content://` tree URI is not a filesystem path, so an
//! absolute `PathBuf` is not expressible for every backend; a relative
//! `<vault_id>/ops/<device_id>/<name>.oplog` is. Resolving a [`StorePath`] onto
//! whatever the backend actually addresses is [`FsStore`]'s (or a future
//! backend's) private business.

use std::fmt;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use crate::error::{Error, Result};

/// A path **relative to a [`Store`]'s root**, as a sequence of plain name
/// segments (no separators, no `.`/`..` traversal).
///
/// This is the channel's addressing type. It is intentionally *not*
/// [`std::path::PathBuf`]: a store's root need not be a filesystem directory
/// (see the module docs), so only the relative path within it is portable. The
/// empty path is the store root itself ([`StorePath::root`]).
///
/// Segments are expected to be plain file/directory names — every name the §7.1
/// layout produces is ASCII (hyphenated UUIDs, hex hashes, fixed literals). A
/// segment containing a separator or a `..` component is a programming error and
/// its resolution is unspecified.
#[derive(Clone, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct StorePath {
    segments: Vec<String>,
}

impl StorePath {
    /// The store root itself (the empty relative path).
    #[must_use]
    pub fn root() -> Self {
        Self {
            segments: Vec::new(),
        }
    }

    /// This path with `segment` appended as one further name.
    #[must_use]
    pub fn join(&self, segment: impl Into<String>) -> Self {
        let mut segments = self.segments.clone();
        segments.push(segment.into());
        Self { segments }
    }

    /// The name segments, root-first.
    #[must_use]
    pub fn segments(&self) -> &[String] {
        &self.segments
    }

    /// Whether this is the store root (no segments).
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.segments.is_empty()
    }

    /// The last segment (the "file name"), or `None` at the root.
    #[must_use]
    pub fn file_name(&self) -> Option<&str> {
        self.segments.last().map(String::as_str)
    }

    /// The file name without its extension, mirroring
    /// [`std::path::Path::file_stem`] (a leading dot does not start an
    /// extension: `.oplog` stems to `.oplog`).
    #[must_use]
    pub fn file_stem(&self) -> Option<&str> {
        let name = self.file_name()?;
        match name.rsplit_once('.') {
            Some((stem, _)) if !stem.is_empty() => Some(stem),
            _ => Some(name),
        }
    }

    /// The file name's extension, mirroring [`std::path::Path::extension`]
    /// (`None` when there is no dot, or only a leading one).
    #[must_use]
    pub fn extension(&self) -> Option<&str> {
        let name = self.file_name()?;
        match name.rsplit_once('.') {
            Some((stem, ext)) if !stem.is_empty() => Some(ext),
            _ => None,
        }
    }
}

impl fmt::Display for StorePath {
    /// `/`-joined, for diagnostics only — never for addressing.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.segments.join("/"))
    }
}

/// One entry returned by [`Store::list_dir`].
///
/// Carries only what the §7 layout reader needs: the entry's own name (relative
/// to the listed directory) and whether it is a directory.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DirEntry {
    /// The entry's name within the listed directory.
    pub name: String,
    /// Whether the entry is a directory (symlinks are followed, matching
    /// [`std::path::Path::is_dir`]).
    pub is_dir: bool,
}

/// The set of channel I/O primitives §7 log shipping needs — create a
/// directory, write a file indivisibly, read a file, list a directory, test for
/// existence, remove a file.
///
/// Implementations are the *dumb channel*: they are fully untrusted (§5
/// verification is what protects the log) and carry no sync semantics of their
/// own. [`crate::shipping::SyncDir`] layers the §7.1 layout on top.
///
/// The trait is object-safe on purpose — a host picks its backend at runtime —
/// and `Send + Sync` so a [`crate::shipping::SyncDir`] can cross threads as it
/// does today.
///
/// # Error contract
///
/// Implementations report a missing entry as [`Error::Io`] carrying
/// [`std::io::ErrorKind::NotFound`] (see [`is_not_found`]); the read/remove
/// methods below absorb that case themselves, but [`Store::list_dir`] surfaces
/// it so callers can distinguish "no such directory" from "unreadable".
pub trait Store: Send + Sync {
    /// Create `path` and every missing parent; a directory that already exists
    /// is not an error.
    ///
    /// # Errors
    ///
    /// [`Error::Io`] if the directory cannot be created.
    fn create_dir_all(&self, path: &StorePath) -> Result<()>;

    /// Write `bytes` to `path` such that a concurrent reader never observes a
    /// partially written file: readers see either the previous contents or the
    /// complete new ones. Parent directories must already exist.
    ///
    /// # Errors
    ///
    /// [`Error::Io`] on a write failure.
    fn write_atomic(&self, path: &StorePath, bytes: &[u8]) -> Result<()>;

    /// Read `path` whole, or `Ok(None)` if it does not exist.
    ///
    /// # Errors
    ///
    /// [`Error::Io`] on a read failure other than not-found.
    fn read(&self, path: &StorePath) -> Result<Option<Vec<u8>>>;

    /// List the direct children of the directory `path`.
    ///
    /// The order is unspecified. An entry whose name is not valid UTF-8 is not
    /// addressable through a [`StorePath`] and is skipped — the §7.1 layout only
    /// ever produces ASCII names.
    ///
    /// # Errors
    ///
    /// [`Error::Io`] if the directory cannot be read, including
    /// [`std::io::ErrorKind::NotFound`] when it does not exist (callers that
    /// treat a missing directory as empty check for that with [`is_not_found`]).
    fn list_dir(&self, path: &StorePath) -> Result<Vec<DirEntry>>;

    /// Whether an entry exists at `path`.
    ///
    /// # Errors
    ///
    /// [`Error::Io`] if existence cannot be determined.
    fn exists(&self, path: &StorePath) -> Result<bool>;

    /// Remove the file at `path`. A missing file is a no-op.
    ///
    /// # Errors
    ///
    /// [`Error::Io`] on a removal failure other than not-found.
    fn remove_file(&self, path: &StorePath) -> Result<()>;
}

/// Whether an error is a not-found — the "this entry is simply absent" case
/// that §7 readers routinely treat as empty rather than as a failure.
#[must_use]
pub fn is_not_found(e: &Error) -> bool {
    matches!(e, Error::Io(io) if io.kind() == io::ErrorKind::NotFound)
}

/// The [`std::fs`] channel backend: a [`Store`] rooted at an ordinary local
/// directory (a Syncthing folder, a mounted share, a USB stick). This is the
/// only implementation on desktop.
#[derive(Clone, Debug)]
pub struct FsStore {
    root: PathBuf,
}

impl FsStore {
    /// Bind a store to the local directory `root`. The directory is not touched
    /// here — callers create what they need with [`Store::create_dir_all`].
    #[must_use]
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    /// The local directory this store is rooted at.
    ///
    /// Filesystem-specific by construction: this is what a non-filesystem
    /// backend (e.g. a SAF `content://` tree) cannot offer, which is why it
    /// lives on [`FsStore`] and not on [`Store`].
    #[must_use]
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Resolve a channel-relative [`StorePath`] onto the local filesystem.
    fn resolve(&self, path: &StorePath) -> PathBuf {
        let mut p = self.root.clone();
        for seg in path.segments() {
            p.push(seg);
        }
        p
    }
}

impl Store for FsStore {
    fn create_dir_all(&self, path: &StorePath) -> Result<()> {
        fs::create_dir_all(self.resolve(path))?;
        Ok(())
    }

    fn write_atomic(&self, path: &StorePath, bytes: &[u8]) -> Result<()> {
        // Write bytes durably-ish: to a temp sibling then rename into place, so
        // a reader never sees a half-written segment (segments are immutable
        // once named).
        let target = self.resolve(path);
        let tmp = target.with_extension("tmp");
        fs::write(&tmp, bytes)?;
        fs::rename(&tmp, &target)?;
        Ok(())
    }

    fn read(&self, path: &StorePath) -> Result<Option<Vec<u8>>> {
        match fs::read(self.resolve(path)) {
            Ok(bytes) => Ok(Some(bytes)),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(Error::Io(e)),
        }
    }

    fn list_dir(&self, path: &StorePath) -> Result<Vec<DirEntry>> {
        let mut out = Vec::new();
        for entry in fs::read_dir(self.resolve(path))? {
            let entry = entry?;
            // Not valid UTF-8 → not addressable as a `StorePath` segment.
            let Ok(name) = entry.file_name().into_string() else {
                continue;
            };
            // `Path::is_dir` semantics: follow symlinks, treat a stat failure as
            // "not a directory". `file_type()` alone would not follow.
            let is_dir = match entry.file_type() {
                Ok(ft) if !ft.is_symlink() => ft.is_dir(),
                _ => entry.path().is_dir(),
            };
            out.push(DirEntry { name, is_dir });
        }
        Ok(out)
    }

    fn exists(&self, path: &StorePath) -> Result<bool> {
        Ok(self.resolve(path).exists())
    }

    fn remove_file(&self, path: &StorePath) -> Result<()> {
        match fs::remove_file(self.resolve(path)) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(Error::Io(e)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn store_path_addresses_relatively() {
        let p = StorePath::root()
            .join("vault")
            .join("ops")
            .join("a-1-2.oplog");
        assert_eq!(p.to_string(), "vault/ops/a-1-2.oplog");
        assert_eq!(p.file_name(), Some("a-1-2.oplog"));
        assert_eq!(p.file_stem(), Some("a-1-2"));
        assert_eq!(p.extension(), Some("oplog"));
        assert!(StorePath::root().is_empty());
        assert_eq!(StorePath::root().file_name(), None);
    }

    #[test]
    fn store_path_stem_matches_std_path_semantics() {
        // A leading dot does not start an extension.
        let dot = StorePath::root().join(".oplog");
        assert_eq!(dot.file_stem(), Some(".oplog"));
        assert_eq!(dot.extension(), None);
        // Only the LAST dot separates the extension.
        let multi = StorePath::root().join("a.b.c");
        assert_eq!(multi.file_stem(), Some("a.b"));
        assert_eq!(multi.extension(), Some("c"));
        // No dot at all.
        let bare = StorePath::root().join("manifest");
        assert_eq!(bare.file_stem(), Some("manifest"));
        assert_eq!(bare.extension(), None);
    }

    #[test]
    fn fs_store_roundtrips_and_lists() {
        let tmp = tempfile::tempdir().unwrap();
        let store = FsStore::new(tmp.path());
        let dir = StorePath::root().join("a").join("b");
        store.create_dir_all(&dir).unwrap();

        let file = dir.join("x.blob");
        assert!(!store.exists(&file).unwrap());
        assert!(store.read(&file).unwrap().is_none());

        store.write_atomic(&file, b"hi").unwrap();
        assert!(store.exists(&file).unwrap());
        assert_eq!(store.read(&file).unwrap().as_deref(), Some(&b"hi"[..]));
        // The temp sibling must not survive the rename.
        assert!(!store.exists(&dir.join("x.tmp")).unwrap());

        let entries = store.list_dir(&dir).unwrap();
        assert_eq!(
            entries,
            vec![DirEntry {
                name: "x.blob".into(),
                is_dir: false
            }]
        );
        let top = store.list_dir(&StorePath::root()).unwrap();
        assert_eq!(
            top,
            vec![DirEntry {
                name: "a".into(),
                is_dir: true
            }]
        );

        store.remove_file(&file).unwrap();
        assert!(!store.exists(&file).unwrap());
        // Removing a missing file is a no-op.
        store.remove_file(&file).unwrap();
    }

    #[test]
    fn missing_dir_lists_as_not_found() {
        let tmp = tempfile::tempdir().unwrap();
        let store = FsStore::new(tmp.path());
        let err = store
            .list_dir(&StorePath::root().join("nope"))
            .expect_err("missing dir must surface as not-found");
        assert!(is_not_found(&err));
    }

    #[test]
    fn store_is_object_safe() {
        let tmp = tempfile::tempdir().unwrap();
        let store: Box<dyn Store> = Box::new(FsStore::new(tmp.path()));
        store.create_dir_all(&StorePath::root().join("d")).unwrap();
        assert!(store.exists(&StorePath::root().join("d")).unwrap());
    }
}
