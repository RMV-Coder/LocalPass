//! The device-local, append-only, tamper-evident **audit log** (PRD §4.9).
//!
//! A separate per-device hash chain — distinct from the sync op log
//! ([`crate::op`]) — that records *who did what, when* on this device: unlocks,
//! failed unlocks, reads that reveal a secret value, edits, exports, and shares.
//! It lives in the **account store** (`audit_log` table), not in any vault file,
//! because its events are device-local and cross-vault (an unlock is not
//! vault-scoped) and it is deliberately **not synced** — every device keeps its
//! own local record of what happened on it.
//!
//! # What it stores — and what it must never store
//!
//! The audit log is **plaintext metadata**: ids, kinds, and timestamps only. It
//! is integrity-protected by the hash chain, not confidential. This is a design
//! choice, not an oversight (PRD §4.9 "Log entries contain item IDs and
//! metadata, **never secret values**"):
//!
//! - **stored:** monotonic `seq`, `prev_hash`, unix-millis `timestamp`,
//!   `device_id`, an [`AuditKind`], and the ids it references (item id, vault id,
//!   peer device id) — all of which are already non-secret 16-byte UUIDs
//!   ([`crate::ids`]) or plaintext structural metadata elsewhere on disk.
//! - **never stored:** secret values (passwords, private keys, TOTP secrets,
//!   field values), master passwords, the Secret Key, **or vault/item names**
//!   (names are ciphertext everywhere else; the audit log is plaintext, so a
//!   name here would be a plaintext leak). An optional short `detail` string
//!   carries only non-secret context (e.g. an export format, a field *name* like
//!   `"password"`), never a value.
//!
//! ## What a log-file reader learns (threat note, cf. vault-format.md §12)
//!
//! Someone who reads `audit_log` — a locked-out user inspecting their own
//! device, or an attacker with the file — learns the *shape* of activity: that
//! item `<id>` in vault `<id>` had its secret revealed at a time, that an export
//! of N items happened, that unlocks succeeded or failed. They learn **no secret
//! value and no title**: ids are opaque UUIDs and names are never here. That a
//! locked-out user (or an auditor) can inspect this plaintext record *is the
//! point* — it answers "who read what, when" (PRD §4.9, §8 T3 per-item reveal
//! auditing) and stays useful even when the vault is locked and the keys are
//! gone.
//!
//! # The hash chain (mirrors [`crate::op`] / sync-protocol.md §5)
//!
//! Each record carries a per-device gapless `seq` (1-based) and a `prev_hash`
//! that is the BLAKE3-256 of the **canonical bytes of the previous record**
//! (including that record's own chain position). The genesis (first record)
//! `prev_hash` is
//! `blake3_256("localpass/v1/audit-genesis" || device_id(16))`, **raw-byte
//! framed** exactly like the op-log genesis (LESSONS 2026-07-04). Because each
//! link covers the whole previous record, an attacker cannot delete, reorder, or
//! alter a record without breaking every link after it —
//! [`crate::Session::verify_audit_chain`] re-derives the chain and detects any
//! such tamper, plus a `seq` gap.

use lp_crypto::blake3_256;

use crate::ids::{DeviceId, Id, ItemId, VaultId};

/// The raw-byte-framed genesis label for a device's first audit `prev_hash`
/// (LESSONS raw-framing rule; parallels [`crate::op`]'s chain genesis).
const AUDIT_GENESIS_LABEL: &[u8] = b"localpass/v1/audit-genesis";

/// The kind of an audited action (PRD §4.9). Only kinds that map to a **real**
/// action in this build are present; see the crate-level notes for the §4.9
/// events with no source yet (`TokenUse`).
///
/// Every variant carries only **non-secret** ids/metadata — never a value, and
/// never a vault/item name (names are ciphertext everywhere else).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AuditKind {
    /// A successful account unlock (a session was created).
    UnlockSuccess,
    /// A failed account unlock (wrong password or Secret Key). Recorded even
    /// though no session exists — see [`crate::AccountStore::record_unlock_failure`].
    UnlockFailure,
    /// A read that **revealed a secret value** of an item: `item get --reveal`,
    /// `item get --field`, a `localpass://` reference resolution, an autofill
    /// fill, a TOTP code, or a revealed version read. A *masked* read (plain
    /// `item get`, `list`, `search`) is **not** an `ItemSecretRead`.
    ItemSecretRead {
        /// The item whose secret was revealed.
        item_id: ItemId,
        /// The vault the item lives in.
        vault_id: VaultId,
        /// The specific field name revealed, if a single field (e.g.
        /// `"password"`) — a non-secret label, never a value. `None` for a
        /// whole-item reveal.
        field: Option<String>,
    },
    /// A new item was created.
    ItemCreate {
        /// The created item.
        item_id: ItemId,
        /// The vault it was created in.
        vault_id: VaultId,
    },
    /// An item was edited (a new version was written).
    ItemUpdate {
        /// The edited item.
        item_id: ItemId,
        /// The vault it lives in.
        vault_id: VaultId,
    },
    /// An item was moved to trash (tombstoned).
    ItemDelete {
        /// The deleted item.
        item_id: ItemId,
        /// The vault it lived in.
        vault_id: VaultId,
    },
    /// A prior version of an item was restored as a new version.
    ItemRestore {
        /// The restored item.
        item_id: ItemId,
        /// The vault it lives in.
        vault_id: VaultId,
    },
    /// Items were exported to a file (PRD §4.6/§4.9). Records the format and how
    /// many items left the vault — never their contents.
    Export {
        /// The export format token (e.g. `"age"`, `"json"`, `"csv"`, `"dotenv"`).
        format: String,
        /// The number of items exported.
        item_count: u64,
    },
    /// A vault's key was shared to a trusted peer device (PRD §4.5).
    VaultShare {
        /// The shared vault.
        vault_id: VaultId,
        /// The recipient peer device.
        peer_device_id: DeviceId,
    },
    /// A peer device was trusted (its keys pinned; sync-protocol.md §6).
    DeviceTrust {
        /// The now-trusted peer device.
        peer_device_id: DeviceId,
    },
}

impl AuditKind {
    /// The wire byte for this kind (stable; part of the canonical bytes the
    /// hash chain covers). Distinct values, never reused.
    #[must_use]
    pub fn code(&self) -> u8 {
        match self {
            AuditKind::UnlockSuccess => 1,
            AuditKind::UnlockFailure => 2,
            AuditKind::ItemSecretRead { .. } => 3,
            AuditKind::ItemCreate { .. } => 4,
            AuditKind::ItemUpdate { .. } => 5,
            AuditKind::ItemDelete { .. } => 6,
            AuditKind::ItemRestore { .. } => 7,
            AuditKind::Export { .. } => 8,
            AuditKind::VaultShare { .. } => 9,
            AuditKind::DeviceTrust { .. } => 10,
        }
    }

    /// A short, stable, non-secret label for display (`localpass audit`) and
    /// `--json`.
    #[must_use]
    pub fn label(&self) -> &'static str {
        match self {
            AuditKind::UnlockSuccess => "unlock_success",
            AuditKind::UnlockFailure => "unlock_failure",
            AuditKind::ItemSecretRead { .. } => "item_secret_read",
            AuditKind::ItemCreate { .. } => "item_create",
            AuditKind::ItemUpdate { .. } => "item_update",
            AuditKind::ItemDelete { .. } => "item_delete",
            AuditKind::ItemRestore { .. } => "item_restore",
            AuditKind::Export { .. } => "export",
            AuditKind::VaultShare { .. } => "vault_share",
            AuditKind::DeviceTrust { .. } => "device_trust",
        }
    }

    /// The item id this kind references, if any (for display/`--json`).
    #[must_use]
    pub fn item_id(&self) -> Option<&ItemId> {
        match self {
            AuditKind::ItemSecretRead { item_id, .. }
            | AuditKind::ItemCreate { item_id, .. }
            | AuditKind::ItemUpdate { item_id, .. }
            | AuditKind::ItemDelete { item_id, .. }
            | AuditKind::ItemRestore { item_id, .. } => Some(item_id),
            _ => None,
        }
    }

    /// The vault id this kind references, if any (for display/`--json`).
    #[must_use]
    pub fn vault_id(&self) -> Option<&VaultId> {
        match self {
            AuditKind::ItemSecretRead { vault_id, .. }
            | AuditKind::ItemCreate { vault_id, .. }
            | AuditKind::ItemUpdate { vault_id, .. }
            | AuditKind::ItemDelete { vault_id, .. }
            | AuditKind::ItemRestore { vault_id, .. }
            | AuditKind::VaultShare { vault_id, .. } => Some(vault_id),
            _ => None,
        }
    }

    /// The peer device id this kind references, if any (for display/`--json`).
    #[must_use]
    pub fn peer_device_id(&self) -> Option<&DeviceId> {
        match self {
            AuditKind::VaultShare { peer_device_id, .. }
            | AuditKind::DeviceTrust { peer_device_id } => Some(peer_device_id),
            _ => None,
        }
    }
}

/// One audit-log record: chain position + timestamp + device + kind + optional
/// non-secret detail. Read back by [`crate::Session::audit_iter`] /
/// [`crate::Session::audit_since`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuditRecord {
    /// Per-device gapless sequence (1-based).
    pub seq: u64,
    /// The chain link to this device's previous record (genesis for the first).
    pub prev_hash: [u8; 32],
    /// When the action happened (unix millis).
    pub timestamp: i64,
    /// The device the action happened on.
    pub device_id: DeviceId,
    /// What happened (and the non-secret ids it references).
    pub kind: AuditKind,
    /// An optional short, **non-secret** detail string (e.g. a field name, an
    /// export format note). Never a secret value.
    pub detail: Option<String>,
}

impl AuditRecord {
    /// Serialize this record to canonical, unambiguous bytes — exactly the byte
    /// string the *next* record's `prev_hash` is the BLAKE3-256 of, and the
    /// input the chain verifier reconstructs.
    ///
    /// Fixed-width integers are little-endian; variable-length components
    /// (`field`, `detail`) are `u32`-length-prefixed so the encoding is
    /// unambiguous without a separator that could collide with content.
    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(8 + 32 + 8 + 16 + 1 + 16 + 16 + 8 + 8 + 8);
        out.extend_from_slice(&self.seq.to_le_bytes());
        out.extend_from_slice(&self.prev_hash);
        out.extend_from_slice(&self.timestamp.to_le_bytes());
        out.extend_from_slice(self.device_id.as_bytes());
        out.push(self.kind.code());

        // Kind-specific ids/counters, each fixed-width where an id (16 bytes) or
        // an integer (u64 LE), and length-prefixed for the strings.
        match &self.kind {
            AuditKind::UnlockSuccess | AuditKind::UnlockFailure => {}
            AuditKind::ItemSecretRead {
                item_id,
                vault_id,
                field,
            } => {
                out.extend_from_slice(item_id.as_bytes());
                out.extend_from_slice(vault_id.as_bytes());
                push_opt_str(&mut out, field.as_deref());
            }
            AuditKind::ItemCreate { item_id, vault_id }
            | AuditKind::ItemUpdate { item_id, vault_id }
            | AuditKind::ItemDelete { item_id, vault_id }
            | AuditKind::ItemRestore { item_id, vault_id } => {
                out.extend_from_slice(item_id.as_bytes());
                out.extend_from_slice(vault_id.as_bytes());
            }
            AuditKind::Export { format, item_count } => {
                push_str(&mut out, format);
                out.extend_from_slice(&item_count.to_le_bytes());
            }
            AuditKind::VaultShare {
                vault_id,
                peer_device_id,
            } => {
                out.extend_from_slice(vault_id.as_bytes());
                out.extend_from_slice(peer_device_id.as_bytes());
            }
            AuditKind::DeviceTrust { peer_device_id } => {
                out.extend_from_slice(peer_device_id.as_bytes());
            }
        }

        // The optional free-form detail (never a secret), length-prefixed.
        push_opt_str(&mut out, self.detail.as_deref());
        out
    }

    /// The chain hash of this record (the next record's `prev_hash`).
    #[must_use]
    pub fn chain_hash(&self) -> [u8; 32] {
        blake3_256(&self.canonical_bytes())
    }
}

/// Push a `u32`-length-prefixed UTF-8 string.
fn push_str(out: &mut Vec<u8>, s: &str) {
    let bytes = s.as_bytes();
    let len = u32::try_from(bytes.len()).unwrap_or(u32::MAX);
    out.extend_from_slice(&len.to_le_bytes());
    out.extend_from_slice(&bytes[..len as usize]);
}

/// Push an optional string as `1 byte present-flag || (if present) length-prefixed
/// bytes`. The flag keeps `Some("")` distinct from `None`.
fn push_opt_str(out: &mut Vec<u8>, s: Option<&str>) {
    match s {
        None => out.push(0),
        Some(v) => {
            out.push(1);
            push_str(out, v);
        }
    }
}

/// The genesis `prev_hash` for a device's first audit record.
///
/// `blake3_256("localpass/v1/audit-genesis" || device_id(16))`, raw-byte framed
/// (LESSONS 2026-07-04) — the audit counterpart of [`crate::op::genesis_hash`].
/// Framing the device id at a fixed 16-byte width makes the input unambiguous
/// without a length prefix.
#[must_use]
pub fn genesis_hash(device_id: &DeviceId) -> [u8; 32] {
    let mut input = Vec::with_capacity(AUDIT_GENESIS_LABEL.len() + 16);
    input.extend_from_slice(AUDIT_GENESIS_LABEL);
    input.extend_from_slice(device_id.as_bytes());
    blake3_256(&input)
}

/// Decode a stored `kind` byte + its id/detail columns back into an
/// [`AuditKind`]. Used by the read/verify paths in [`crate::account`].
///
/// # Errors
///
/// [`crate::Error::Invalid`] if the code is unknown or a required id column is
/// missing/wrong-width for that kind.
pub(crate) fn kind_from_row(
    code: i64,
    item_id: Option<&[u8]>,
    vault_id: Option<&[u8]>,
    peer_device_id: Option<&[u8]>,
    field: Option<String>,
    item_count: i64,
    format: Option<String>,
) -> crate::Result<AuditKind> {
    // Helper: a required id column, erroring with a static, secret-free message.
    fn req_id(bytes: Option<&[u8]>, what: &'static str) -> crate::Result<Id> {
        match bytes {
            Some(b) => Id::from_slice(b),
            None => Err(crate::Error::Invalid(what)),
        }
    }
    let kind = match u8::try_from(code).ok() {
        Some(1) => AuditKind::UnlockSuccess,
        Some(2) => AuditKind::UnlockFailure,
        Some(3) => AuditKind::ItemSecretRead {
            item_id: req_id(item_id, "audit row missing item_id")?,
            vault_id: req_id(vault_id, "audit row missing vault_id")?,
            field,
        },
        Some(4) => AuditKind::ItemCreate {
            item_id: req_id(item_id, "audit row missing item_id")?,
            vault_id: req_id(vault_id, "audit row missing vault_id")?,
        },
        Some(5) => AuditKind::ItemUpdate {
            item_id: req_id(item_id, "audit row missing item_id")?,
            vault_id: req_id(vault_id, "audit row missing vault_id")?,
        },
        Some(6) => AuditKind::ItemDelete {
            item_id: req_id(item_id, "audit row missing item_id")?,
            vault_id: req_id(vault_id, "audit row missing vault_id")?,
        },
        Some(7) => AuditKind::ItemRestore {
            item_id: req_id(item_id, "audit row missing item_id")?,
            vault_id: req_id(vault_id, "audit row missing vault_id")?,
        },
        Some(8) => AuditKind::Export {
            format: format.ok_or(crate::Error::Invalid("audit row missing export format"))?,
            item_count: u64::try_from(item_count).unwrap_or(0),
        },
        Some(9) => AuditKind::VaultShare {
            vault_id: req_id(vault_id, "audit row missing vault_id")?,
            peer_device_id: req_id(peer_device_id, "audit row missing peer_device_id")?,
        },
        Some(10) => AuditKind::DeviceTrust {
            peer_device_id: req_id(peer_device_id, "audit row missing peer_device_id")?,
        },
        _ => return Err(crate::Error::Invalid("unknown audit kind")),
    };
    Ok(kind)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dev() -> DeviceId {
        Id::from_bytes([9u8; 16])
    }

    #[test]
    fn genesis_is_deterministic_and_binds_device() {
        let d = dev();
        assert_eq!(genesis_hash(&d), genesis_hash(&d));
        let d2 = Id::from_bytes([1u8; 16]);
        assert_ne!(genesis_hash(&d), genesis_hash(&d2));
    }

    #[test]
    fn canonical_bytes_change_with_every_field() {
        let base = AuditRecord {
            seq: 1,
            prev_hash: [0u8; 32],
            timestamp: 100,
            device_id: dev(),
            kind: AuditKind::ItemCreate {
                item_id: Id::from_bytes([2u8; 16]),
                vault_id: Id::from_bytes([3u8; 16]),
            },
            detail: None,
        };
        let h = base.chain_hash();

        // seq
        let mut a = base.clone();
        a.seq = 2;
        assert_ne!(a.chain_hash(), h);
        // prev_hash
        let mut b = base.clone();
        b.prev_hash = [1u8; 32];
        assert_ne!(b.chain_hash(), h);
        // timestamp
        let mut c = base.clone();
        c.timestamp = 101;
        assert_ne!(c.chain_hash(), h);
        // detail
        let mut e = base.clone();
        e.detail = Some("x".into());
        assert_ne!(e.chain_hash(), h);
        // kind (different item id)
        let mut f = base;
        f.kind = AuditKind::ItemUpdate {
            item_id: Id::from_bytes([2u8; 16]),
            vault_id: Id::from_bytes([3u8; 16]),
        };
        assert_ne!(f.chain_hash(), h);
    }

    #[test]
    fn opt_str_some_empty_differs_from_none() {
        let mut with_none = Vec::new();
        push_opt_str(&mut with_none, None);
        let mut with_empty = Vec::new();
        push_opt_str(&mut with_empty, Some(""));
        assert_ne!(with_none, with_empty);
    }

    #[test]
    fn kind_codes_are_distinct() {
        let kinds = [
            AuditKind::UnlockSuccess,
            AuditKind::UnlockFailure,
            AuditKind::ItemSecretRead {
                item_id: dev(),
                vault_id: dev(),
                field: None,
            },
            AuditKind::ItemCreate {
                item_id: dev(),
                vault_id: dev(),
            },
            AuditKind::ItemUpdate {
                item_id: dev(),
                vault_id: dev(),
            },
            AuditKind::ItemDelete {
                item_id: dev(),
                vault_id: dev(),
            },
            AuditKind::ItemRestore {
                item_id: dev(),
                vault_id: dev(),
            },
            AuditKind::Export {
                format: "age".into(),
                item_count: 3,
            },
            AuditKind::VaultShare {
                vault_id: dev(),
                peer_device_id: dev(),
            },
            AuditKind::DeviceTrust {
                peer_device_id: dev(),
            },
        ];
        let mut codes: Vec<u8> = kinds.iter().map(AuditKind::code).collect();
        codes.sort_unstable();
        codes.dedup();
        assert_eq!(codes.len(), kinds.len(), "kind codes must be distinct");
    }
}
