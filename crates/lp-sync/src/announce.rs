//! Channel announce (`docs/specs/device-pairing.md` §5) — the typing-free
//! pairing path once two devices already share a sync folder.
//!
//! Once two devices point at the same sync root, no `LPDEV1-…` string needs to
//! move by hand: each device drops a small plaintext file advertising its own
//! public identity, and the others list them and surface the unknown ones as
//! **pending devices** (§5.3). This module is just that read/write — it makes
//! **no** trust decision.
//!
//! # Layout (§5.1)
//!
//! At the **sync root** (device-level, not per-vault — pairing is not a vault
//! property):
//!
//! ```text
//! <sync-root>/pairing/<device_id>.identity
//! ```
//!
//! Content (plaintext JSON):
//!
//! ```json
//! {
//!   "identity": "LPDEV1-…",
//!   "label": "Ray's phone",
//!   "announced_at": 1752537600000
//! }
//! ```
//!
//! The file name carries the announcing device's id purely as a hint; the
//! **authoritative** `device_id` is derived by parsing the `identity` string
//! (see [`list_announces`]), never trusted from the file name.
//!
//! # The channel is untrusted — deliberately (§5.2)
//!
//! `pairing/` has **exactly the posture of `manifest.json`** (sync-protocol.md
//! §7.2): a discovery hint, not an authority. The channel is untrusted, so
//! anyone who can write to the folder can drop a forged `.identity` file. That
//! is acceptable and needs no defence here, because:
//!
//! - an announce **never** causes a pin by itself — it only populates a pending
//!   list, and
//! - the user still confirms the **fingerprint against the other device's
//!   screen** before trusting (the §3.3 rule, unchanged).
//!
//! A forged announce therefore achieves at most a pending entry whose
//! fingerprint matches nothing the user is looking at → rejected. It cannot
//! inject state, exactly as a forged manifest cannot. Concretely, one bad or
//! forged file must **never** error the whole list: [`list_announces`] skips a
//! malformed entry silently (log-free, like a forged manifest is inert) and
//! returns the valid ones.

use lp_vault::ids::DeviceId;
use serde::{Deserialize, Serialize};

use crate::error::Result;
use crate::identity::DeviceIdentity;
use crate::store::{Store, StorePath, is_not_found};

/// The device-level pairing directory at the sync root (§5.1).
const PAIRING_DIR: &str = "pairing";

/// The extension for an announce file (`<device_id>.identity`).
const IDENTITY_EXT: &str = "identity";

/// A device's channel announce (`docs/specs/device-pairing.md` §5.1): its public
/// identity string, an optional label, and when it was announced.
///
/// The on-disk JSON carries only `identity`, `label`, and `announced_at`. The
/// `device_id` here is **derived** by parsing the `identity` string
/// ([`DeviceIdentity::from_export_string`]) — it is the authoritative id, and it
/// is **not** trusted from the file name (§5.2, the untrusted-channel posture).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Announce {
    /// The announcing device's id, **derived from the parsed `identity` string**
    /// (never the file name).
    pub device_id: DeviceId,
    /// The announcing device's public `LPDEV1-…` identity string (public key
    /// material only — no secret; sync-protocol.md §6).
    pub identity: String,
    /// An optional human label the announcing device chose ("Ray's phone").
    pub label: Option<String>,
    /// When this announce was (re)written, in unix milliseconds.
    pub announced_at: u64,
}

/// The on-disk JSON shape of a `<device_id>.identity` file (§5.1). The
/// authoritative `device_id` is not stored — it is derived from `identity` on
/// read — so this struct deliberately omits it.
#[derive(Clone, Debug, Serialize, Deserialize)]
struct AnnounceJson {
    /// The public `LPDEV1-…` identity string.
    identity: String,
    /// An optional human label.
    label: Option<String>,
    /// Unix-millis announce time.
    announced_at: u64,
}

/// Write (or refresh) this device's announce at `pairing/<device_id>.identity`
/// under the sync root (`docs/specs/device-pairing.md` §5.1).
///
/// Creates the `pairing/` directory if needed, then writes the JSON
/// (`identity` / `label` / `announced_at`) atomically. The file name uses
/// `identity.device_id.to_hyphenated()`; the body embeds the full public
/// identity string, from which a reader re-derives the authoritative id (§5.2).
///
/// The announce is advisory (§5.2): a caller that treats a write failure as
/// non-fatal is behaving correctly — pairing still works via QR/paste, and a
/// missing announce only means this device will not auto-surface as pending on a
/// peer.
///
/// # Errors
///
/// [`Error::Io`](crate::error::Error::Io) if the `pairing/` directory cannot be
/// created or the file cannot be written; a serialization failure surfaces as
/// the same error type.
pub fn write_announce(
    store: &dyn Store,
    identity: &DeviceIdentity,
    label: Option<&str>,
    announced_at: u64,
) -> Result<()> {
    let dir = StorePath::root().join(PAIRING_DIR);
    store.create_dir_all(&dir)?;

    let body = AnnounceJson {
        identity: identity.to_export_string(),
        label: label.map(str::to_string),
        announced_at,
    };
    let name = format!("{}.{IDENTITY_EXT}", identity.device_id.to_hyphenated());
    let path = dir.join(name);
    store.write_atomic(&path, serde_json::to_vec_pretty(&body)?.as_slice())?;
    Ok(())
}

/// List every valid announce in `pairing/` under the sync root
/// (`docs/specs/device-pairing.md` §5).
///
/// A missing `pairing/` directory is **not** an error — it means "nobody has
/// announced yet" and yields `Ok(vec![])` (mirroring
/// [`crate::shipping::SyncDir::list_segments`]). For each `*.identity` file the
/// reader reads it, parses the JSON, and **parses the embedded `identity` string
/// via [`DeviceIdentity::from_export_string`]** — both to validate it and to
/// derive the authoritative `device_id` (never the file name; §5.2).
///
/// Because the channel is untrusted (§5.2), a malformed, unreadable, or forged
/// entry is **skipped silently** — one bad file must never error the whole list.
/// Only the valid announces are returned.
///
/// # Errors
///
/// [`Error::Io`](crate::error::Error::Io) only if the `pairing/` directory
/// exists but cannot be listed (a genuine I/O failure, not a missing dir).
/// Per-file read/parse failures are swallowed as skips, not surfaced.
pub fn list_announces(store: &dyn Store) -> Result<Vec<Announce>> {
    let dir = StorePath::root().join(PAIRING_DIR);
    // A missing `pairing/` dir is simply "no announces yet" (mirrors
    // `SyncDir::list_segments` treating an absent `ops/` as empty).
    let entries = match store.list_dir(&dir) {
        Ok(e) => e,
        Err(e) if is_not_found(&e) => return Ok(Vec::new()),
        Err(e) => return Err(e),
    };

    let mut out = Vec::new();
    for entry in entries {
        let path = dir.join(entry.name);
        // Only `*.identity` files are announces; a dumb channel may drop others.
        if path.extension() != Some(IDENTITY_EXT) {
            continue;
        }
        // Read the file; a vanished/unreadable file is skipped (untrusted §5.2).
        let bytes = match store.read(&path) {
            Ok(Some(b)) => b,
            _ => continue,
        };
        // Parse the JSON; a malformed/forged file is skipped, not fatal (§5.2).
        let body: AnnounceJson = match serde_json::from_slice(&bytes) {
            Ok(b) => b,
            Err(_) => continue,
        };
        // Derive the AUTHORITATIVE device_id by parsing the identity string —
        // this both validates the string (CRC/prefix/length) and is what the id
        // is trusted from, never the file name (§5.2).
        let parsed = match DeviceIdentity::from_export_string(&body.identity) {
            Ok(id) => id,
            Err(_) => continue,
        };
        out.push(Announce {
            device_id: parsed.device_id,
            identity: body.identity,
            label: body.label,
            announced_at: body.announced_at,
        });
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::FsStore;
    use lp_vault::ids::Id;

    /// A distinct, valid identity whose keys (and thus fingerprint + id) vary
    /// with `seed`, so two announces are genuinely different devices.
    fn identity(seed: u8) -> DeviceIdentity {
        DeviceIdentity {
            device_id: Id::from_bytes([seed; 16]),
            ed25519_pub: [seed.wrapping_add(1); 32],
            x25519_pub: [seed.wrapping_add(2); 32],
        }
    }

    #[test]
    fn writes_and_lists_two_announces() {
        let tmp = tempfile::tempdir().unwrap();
        let store = FsStore::new(tmp.path());

        let a = identity(0x11);
        let b = identity(0x22);
        write_announce(&store, &a, Some("phone"), 1000).unwrap();
        write_announce(&store, &b, None, 2000).unwrap();

        let mut listed = list_announces(&store).unwrap();
        assert_eq!(listed.len(), 2);
        listed.sort_by_key(|x| *x.device_id.as_bytes());

        // The device_id is derived from the identity string, matching the source.
        assert_eq!(listed[0].device_id, a.device_id);
        assert_eq!(listed[0].identity, a.to_export_string());
        assert_eq!(listed[0].label.as_deref(), Some("phone"));
        assert_eq!(listed[0].announced_at, 1000);

        assert_eq!(listed[1].device_id, b.device_id);
        assert_eq!(listed[1].label, None);
        assert_eq!(listed[1].announced_at, 2000);
    }

    #[test]
    fn on_disk_layout_matches_the_spec() {
        let tmp = tempfile::tempdir().unwrap();
        let store = FsStore::new(tmp.path());
        let a = identity(0x11);
        write_announce(&store, &a, Some("phone"), 1000).unwrap();

        // The §5.1 path is `pairing/<device_id>.identity` at the sync root.
        let path = tmp
            .path()
            .join(PAIRING_DIR)
            .join(format!("{}.{IDENTITY_EXT}", a.device_id.to_hyphenated()));
        assert!(path.exists(), "expected §5.1 announce path");
        // The temp sibling from write_atomic never survives.
        assert!(
            !tmp.path()
                .join(PAIRING_DIR)
                .join(format!("{}.tmp", a.device_id.to_hyphenated()))
                .exists()
        );
    }

    #[test]
    fn re_announcing_refreshes_in_place() {
        let tmp = tempfile::tempdir().unwrap();
        let store = FsStore::new(tmp.path());
        let a = identity(0x11);
        write_announce(&store, &a, Some("old"), 1000).unwrap();
        write_announce(&store, &a, Some("new"), 5000).unwrap();

        let listed = list_announces(&store).unwrap();
        assert_eq!(listed.len(), 1, "re-announce overwrites, never duplicates");
        assert_eq!(listed[0].announced_at, 5000);
        assert_eq!(listed[0].label.as_deref(), Some("new"));
    }

    #[test]
    fn a_malformed_file_is_skipped_not_fatal() {
        let tmp = tempfile::tempdir().unwrap();
        let store = FsStore::new(tmp.path());

        // One good announce…
        let a = identity(0x11);
        write_announce(&store, &a, None, 1000).unwrap();

        let dir = StorePath::root().join(PAIRING_DIR);
        // …plus garbage that is not JSON at all…
        store
            .write_atomic(&dir.join("garbage.identity"), b"not json {{{")
            .unwrap();
        // …plus valid JSON whose identity string is forged/broken…
        store
            .write_atomic(
                &dir.join("forged.identity"),
                br#"{"identity":"LPDEV1-not-hex","label":null,"announced_at":3}"#,
            )
            .unwrap();
        // …plus an unrelated non-`.identity` file the dumb channel dropped in.
        store.write_atomic(&dir.join("README.txt"), b"hi").unwrap();

        // The whole list does not error; only the one valid announce survives.
        let listed = list_announces(&store).unwrap();
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].device_id, a.device_id);
    }

    #[test]
    fn missing_or_empty_pairing_dir_lists_empty() {
        let tmp = tempfile::tempdir().unwrap();
        let store = FsStore::new(tmp.path());
        // Missing dir → empty (not an error).
        assert!(list_announces(&store).unwrap().is_empty());

        // Empty (but present) dir → still empty.
        store
            .create_dir_all(&StorePath::root().join(PAIRING_DIR))
            .unwrap();
        assert!(list_announces(&store).unwrap().is_empty());
    }
}
