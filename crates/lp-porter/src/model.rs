//! Shared types: the import outcome and the documented age-archive JSON model.

use lp_vault::ItemPayload;
use serde::{Deserialize, Serialize};

/// The result of an import: the items that parsed, plus the entries that were
/// skipped (reported by **title only**, never by value).
///
/// A partial parse is normal and non-fatal: an importer imports every entry it
/// understands and records the rest in [`skipped`](ImportOutcome::skipped) so
/// the CLI can tell the user "imported N, skipped M" and name the skipped
/// titles. A skip never carries the reason's underlying value.
#[derive(Debug, Default)]
pub struct ImportOutcome {
    /// The successfully parsed items, ready for the caller to create in a vault.
    pub items: Vec<ItemPayload>,
    /// Entries that could not be imported, each identified by a non-secret
    /// title/label and a value-free reason.
    pub skipped: Vec<SkippedEntry>,
}

impl ImportOutcome {
    /// An empty outcome.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Push a parsed item.
    pub fn push(&mut self, item: ItemPayload) {
        self.items.push(item);
    }

    /// Record a skipped entry (title + value-free reason).
    pub fn skip(&mut self, title: impl Into<String>, reason: impl Into<String>) {
        self.skipped.push(SkippedEntry {
            title: title.into(),
            reason: reason.into(),
        });
    }

    /// Number of imported items.
    #[must_use]
    pub fn count(&self) -> usize {
        self.items.len()
    }
}

/// A single skipped entry: a non-secret title/label and a value-free reason.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SkippedEntry {
    /// The entry's title/label (a name, never a secret value).
    pub title: String,
    /// Why it was skipped (structural; no value).
    pub reason: String,
}

// --- The documented age-archive JSON model -------------------------------

/// The archive format version (`"format"` string in the JSON header).
///
/// This is a **public, documented** contract: a third-party tool that runs
/// `age -d archive.age | tar -x` gets a tar whose single entry `vault.json`
/// deserializes to [`Archive`]. Bumping this requires a spec note.
pub const ARCHIVE_FORMAT: &str = "localpass-archive-v1";

/// The tar entry name holding the JSON body inside the (decrypted) archive.
pub const ARCHIVE_ENTRY: &str = "vault.json";

/// The top-level archive document (serialized to `vault.json`, tarred, then
/// age-encrypted).
///
/// The shape is intentionally simple and self-describing so it is trivially
/// re-implementable by a recovery tool:
///
/// ```json
/// {
///   "format": "localpass-archive-v1",
///   "exported_at": 1751600000000,
///   "vaults": [
///     { "name": "personal", "items": [ <ItemPayload>, ... ] }
///   ]
/// }
/// ```
///
/// Each item is a verbatim [`ItemPayload`] — the same canonical model LocalPass
/// stores — so a re-import needs no translation. Secrets are present in full
/// (the archive's confidentiality comes entirely from the age layer around it).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Archive {
    /// Format tag; must equal [`ARCHIVE_FORMAT`] on import.
    pub format: String,
    /// Export time, unix millis (informational; not security-relevant).
    pub exported_at: i64,
    /// The exported vaults, each a named bundle of items.
    pub vaults: Vec<ArchiveVault>,
}

/// One vault's worth of items inside an [`Archive`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArchiveVault {
    /// The vault's name (informational; the importer may target a different
    /// vault).
    pub name: String,
    /// The items, as verbatim [`ItemPayload`]s.
    pub items: Vec<ItemPayload>,
}

impl Archive {
    /// Build an archive from named `(vault_name, items)` groups.
    #[must_use]
    pub fn new(exported_at: i64, vaults: Vec<ArchiveVault>) -> Self {
        Self {
            format: ARCHIVE_FORMAT.to_string(),
            exported_at,
            vaults,
        }
    }

    /// Every item across all vaults, flattened (for a simple re-import that
    /// drops into a single target vault).
    #[must_use]
    pub fn all_items(&self) -> Vec<ItemPayload> {
        self.vaults
            .iter()
            .flat_map(|v| v.items.iter().cloned())
            .collect()
    }
}
