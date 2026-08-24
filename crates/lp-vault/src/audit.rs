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
//!
//! # Caller attribution ([`AuditOrigin`])
//!
//! A record also carries **who asked** — the surface ([`AuditSource`]: GUI, CLI,
//! MCP, the browser native-messaging host, the SSH agent) plus, where cheaply
//! available, the caller's short process name and pid (PRD §4.10's sketch of an
//! injection record: `{ts, op, item, requestor:"cli", pid}`). None of that is a
//! secret, and it deliberately **never includes a command line** — a command line
//! can carry a password typed as an argument.
//!
//! Attribution is *provenance, not authentication*: on the daemon route the
//! client self-reports it over the same-user-only IPC channel, which the daemon
//! already treats as itself (PRD §8 T8). It answers "which of my tools did this"
//! for an honest user, not "prove you are who you say" against same-user malware
//! — that adversary (T3) is already inside the trust boundary.
//!
//! ## Why the canonical bytes stay backward-compatible
//!
//! [`AuditRecord::canonical_bytes`] is the input to the tamper-evident hash
//! chain, so a format change would invalidate every existing log. The origin is
//! therefore appended **only when present**: a record with `origin: None` — which
//! is every record written by an earlier build — encodes to exactly the bytes it
//! always did, so pre-existing chains keep verifying unchanged. The encoding
//! stays injective because everything before the origin is fixed-width or
//! length-prefixed (self-delimiting), and appending a suffix to a self-delimiting
//! prefix cannot collide with a shorter encoding of a different record.

use std::cell::RefCell;
use std::sync::RwLock;

use lp_crypto::blake3_256;

use crate::ids::{DeviceId, Id, ItemId, VaultId};

/// The maximum stored length of an attributed process name, in **characters**.
/// A name is a base name (never a path) and is truncated here so a hostile or
/// merely absurd executable name cannot bloat the plaintext log.
pub const MAX_PROCESS_NAME_CHARS: usize = 32;

/// The raw-byte-framed genesis label for a device's first audit `prev_hash`
/// (LESSONS raw-framing rule; parallels [`crate::op`]'s chain genesis).
const AUDIT_GENESIS_LABEL: &[u8] = b"localpass/v1/audit-genesis";

/// Which LocalPass surface performed an audited action.
///
/// A small, closed set with stable wire codes — the plaintext log stores the
/// code, and [`label`](AuditSource::label) renders it. `Unknown` is the honest
/// answer for a caller that did not identify itself (an older peer, or an
/// embedder that never called [`set_process_origin`]); it is never guessed at.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum AuditSource {
    /// The surface did not identify itself (older peer, or unset).
    #[default]
    Unknown,
    /// The `localpass` command-line interface.
    Cli,
    /// The desktop GUI (a daemon client).
    Gui,
    /// The `localpass mcp` Model Context Protocol server.
    Mcp,
    /// The browser native-messaging host (`localpass-native-host`).
    NativeHost,
    /// The daemon's built-in SSH agent.
    SshAgent,
    /// The daemon itself, acting on its own behalf (e.g. an auto-lock).
    Daemon,
}

impl AuditSource {
    /// The stable wire byte for this source (part of the canonical bytes the
    /// hash chain covers). Distinct values, never reused.
    #[must_use]
    pub fn code(self) -> u8 {
        match self {
            AuditSource::Unknown => 0,
            AuditSource::Cli => 1,
            AuditSource::Gui => 2,
            AuditSource::Mcp => 3,
            AuditSource::NativeHost => 4,
            AuditSource::SshAgent => 5,
            AuditSource::Daemon => 6,
        }
    }

    /// A short, stable, non-secret label for display (`localpass audit`) and
    /// `--json`.
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            AuditSource::Unknown => "unknown",
            AuditSource::Cli => "cli",
            AuditSource::Gui => "gui",
            AuditSource::Mcp => "mcp",
            AuditSource::NativeHost => "native_host",
            AuditSource::SshAgent => "ssh_agent",
            AuditSource::Daemon => "daemon",
        }
    }

    /// The source for a stored wire byte. An unrecognized code decodes to
    /// [`AuditSource::Unknown`] rather than failing the read — a log written by a
    /// newer build must still be *readable* by an older one.
    #[must_use]
    pub fn from_code(code: u8) -> Self {
        match code {
            1 => AuditSource::Cli,
            2 => AuditSource::Gui,
            3 => AuditSource::Mcp,
            4 => AuditSource::NativeHost,
            5 => AuditSource::SshAgent,
            6 => AuditSource::Daemon,
            _ => AuditSource::Unknown,
        }
    }

    /// Parse a [`label`](AuditSource::label) back into a source; anything else is
    /// [`AuditSource::Unknown`]. Used to decode a self-reported label off the
    /// daemon wire.
    #[must_use]
    pub fn from_label(label: &str) -> Self {
        match label {
            "cli" => AuditSource::Cli,
            "gui" => AuditSource::Gui,
            "mcp" => AuditSource::Mcp,
            "native_host" => AuditSource::NativeHost,
            "ssh_agent" => AuditSource::SshAgent,
            "daemon" => AuditSource::Daemon,
            _ => AuditSource::Unknown,
        }
    }
}

/// Why an operation was refused, for [`AuditKind::AccessDenied`].
///
/// A closed set of non-secret reason tokens — the interesting half of an audit
/// log is the attempts that did *not* succeed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DenyReason {
    /// The vault was locked and the operation needs an unlocked session.
    Locked,
    /// The request named a profile this daemon does not serve.
    WrongProfile,
    /// The caller was authenticated but not permitted to do this.
    NotAuthorized,
}

impl DenyReason {
    /// The stable wire byte for this reason (covered by the hash chain).
    #[must_use]
    pub fn code(self) -> u8 {
        match self {
            DenyReason::Locked => 1,
            DenyReason::WrongProfile => 2,
            DenyReason::NotAuthorized => 3,
        }
    }

    /// A short, stable, non-secret label for display and `--json`.
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            DenyReason::Locked => "locked",
            DenyReason::WrongProfile => "wrong_profile",
            DenyReason::NotAuthorized => "not_authorized",
        }
    }

    /// Decode a stored wire byte, or `None` if it is not a known reason.
    #[must_use]
    pub fn from_code(code: u8) -> Option<Self> {
        match code {
            1 => Some(DenyReason::Locked),
            2 => Some(DenyReason::WrongProfile),
            3 => Some(DenyReason::NotAuthorized),
            _ => None,
        }
    }
}

/// Who performed an audited action: the surface, plus the caller's short process
/// name and pid where cheaply available.
///
/// # What is deliberately absent
///
/// **No command line, ever.** A command line routinely contains a secret (a
/// password typed as an argument), and the audit log is plaintext. Only the
/// executable's base name survives [`sanitized`](AuditOrigin::sanitized), and it
/// is truncated to [`MAX_PROCESS_NAME_CHARS`] characters.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct AuditOrigin {
    /// The surface that performed the action.
    pub source: AuditSource,
    /// The caller's executable base name (never a path, never a command line),
    /// truncated to [`MAX_PROCESS_NAME_CHARS`] characters. `None` when unknown.
    pub process: Option<String>,
    /// The caller's process id, when known.
    pub pid: Option<u32>,
}

impl AuditOrigin {
    /// An origin for `source` with the **current** process's base name and pid.
    ///
    /// This is what a binary records about itself at startup (see
    /// [`set_process_origin`]). A failure to read `current_exe` degrades to
    /// `process: None` — attribution is best-effort context, never a hard
    /// dependency.
    #[must_use]
    pub fn for_current_process(source: AuditSource) -> Self {
        let process = std::env::current_exe()
            .ok()
            .and_then(|p| p.file_name().map(|n| n.to_string_lossy().into_owned()));
        Self::sanitized(source, process.as_deref(), Some(std::process::id()))
    }

    /// Build an origin, sanitizing `process` to a truncated **base name**.
    ///
    /// Strips any directory component (a full path can leak a home directory or
    /// a checkout name into the plaintext log), trims whitespace, drops an empty
    /// result, and truncates to [`MAX_PROCESS_NAME_CHARS`] characters. A
    /// command line is never accepted here because only a name is ever passed —
    /// callers must not join arguments into this field.
    #[must_use]
    pub fn sanitized(source: AuditSource, process: Option<&str>, pid: Option<u32>) -> Self {
        let process = process.and_then(|raw| {
            // Base name only: split on both separators so a Windows path handed
            // to a Unix build (or vice versa) is still reduced.
            let base = raw.rsplit(['/', '\\']).next().unwrap_or(raw).trim();
            if base.is_empty() {
                return None;
            }
            Some(
                base.chars()
                    .take(MAX_PROCESS_NAME_CHARS)
                    .collect::<String>(),
            )
        });
        Self {
            source,
            process,
            pid,
        }
    }

    /// Whether this origin carries nothing worth recording (an unknown surface
    /// with no process context). Such an origin is stored as `NULL`, which keeps
    /// its canonical bytes byte-identical to a pre-attribution record.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.source == AuditSource::Unknown && self.process.is_none() && self.pid.is_none()
    }
}

/// The process-wide default origin, used when no scoped origin is active.
static PROCESS_ORIGIN: RwLock<Option<AuditOrigin>> = RwLock::new(None);

thread_local! {
    /// The origin in force for the current thread, if any — set by
    /// [`with_origin`] around one request's handling.
    static SCOPED_ORIGIN: RefCell<Option<AuditOrigin>> = const { RefCell::new(None) };
}

/// Declare, once at startup, which surface this process is.
///
/// Every audit record this process writes is attributed to `origin` unless a
/// narrower [`with_origin`] scope is active. A process that never calls this
/// records [`AuditSource::Unknown`] — honest, not guessed.
pub fn set_process_origin(origin: AuditOrigin) {
    if let Ok(mut slot) = PROCESS_ORIGIN.write() {
        *slot = Some(origin);
    }
}

/// Run `f` with `origin` in force **on this thread**, restoring the previous
/// scope afterwards (including on unwind).
///
/// This is how a *server* attributes work to its *client*: the daemon handles one
/// request per connection thread and wraps that handling in the origin the client
/// self-reported, so a record written deep inside a vault operation is attributed
/// to the CLI/GUI/MCP caller rather than to the daemon.
pub fn with_origin<T>(origin: AuditOrigin, f: impl FnOnce() -> T) -> T {
    /// Restores the previous scoped origin on drop, so an early return or a
    /// panic inside `f` cannot leave a stale attribution behind.
    struct Restore(Option<AuditOrigin>);
    impl Drop for Restore {
        fn drop(&mut self) {
            let prev = self.0.take();
            SCOPED_ORIGIN.with(|slot| *slot.borrow_mut() = prev);
        }
    }
    let prev = SCOPED_ORIGIN.with(|slot| slot.borrow_mut().replace(origin));
    let _restore = Restore(prev);
    f()
}

/// The origin currently in force: the [`with_origin`] scope if any, else the
/// process default, else an empty (`Unknown`) origin.
#[must_use]
pub fn current_origin() -> AuditOrigin {
    if let Some(scoped) = SCOPED_ORIGIN.with(|slot| slot.borrow().clone()) {
        return scoped;
    }
    PROCESS_ORIGIN
        .read()
        .ok()
        .and_then(|slot| slot.clone())
        .unwrap_or_default()
}

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
    /// **Pairing mode was turned on** — the time-boxed window that permits
    /// pinning a **new** device was opened (`device-pairing.md` §4). Like
    /// [`UnlockSuccess`](AuditKind::UnlockSuccess)/[`UnlockFailure`](AuditKind::UnlockFailure)
    /// this is a device-local on/off event that references no id.
    PairingModeEnabled,
    /// **Pairing mode was turned off** — the pairing window was closed by the
    /// user (`device-pairing.md` §4). The unit counterpart of
    /// [`PairingModeEnabled`](AuditKind::PairingModeEnabled); it carries no id.
    PairingModeDisabled,
    /// An operation was **refused** — the vault was locked, the caller named a
    /// profile this daemon does not serve, or the caller was not authorized.
    ///
    /// The denied attempts are the interesting half of an audit log: a probing
    /// process leaves a trail even though it got nothing. Carries only a closed
    /// [`DenyReason`] token; the *operation* it attempted is not recorded,
    /// because a refused request was never resolved against the vault and its
    /// arguments (a vault/item name) would be a plaintext leak.
    AccessDenied {
        /// Why the operation was refused.
        reason: DenyReason,
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
            AuditKind::PairingModeEnabled => 11,
            AuditKind::PairingModeDisabled => 12,
            AuditKind::AccessDenied { .. } => 13,
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
            AuditKind::PairingModeEnabled => "pairing_mode_enabled",
            AuditKind::PairingModeDisabled => "pairing_mode_disabled",
            AuditKind::AccessDenied { .. } => "access_denied",
        }
    }

    /// The refusal reason this kind carries, if any (for display/`--json`).
    #[must_use]
    pub fn deny_reason(&self) -> Option<DenyReason> {
        match self {
            AuditKind::AccessDenied { reason } => Some(*reason),
            _ => None,
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
    /// Who performed the action (surface + process name + pid), or `None` for a
    /// record written before attribution existed — see the module docs on why
    /// `None` keeps the canonical bytes byte-identical to the old format.
    pub origin: Option<AuditOrigin>,
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
            AuditKind::UnlockSuccess
            | AuditKind::UnlockFailure
            | AuditKind::PairingModeEnabled
            | AuditKind::PairingModeDisabled => {}
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
            AuditKind::AccessDenied { reason } => out.push(reason.code()),
        }

        // The optional free-form detail (never a secret), length-prefixed.
        push_opt_str(&mut out, self.detail.as_deref());

        // The caller attribution, appended ONLY when present. A record with no
        // origin — every record written before attribution existed — therefore
        // encodes exactly as it always did, so pre-existing hash chains still
        // verify (see the module docs).
        if let Some(origin) = &self.origin {
            out.push(1);
            out.push(origin.source.code());
            push_opt_str(&mut out, origin.process.as_deref());
            match origin.pid {
                None => out.push(0),
                Some(pid) => {
                    out.push(1);
                    out.extend_from_slice(&pid.to_le_bytes());
                }
            }
        }
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
// One parameter per `audit_log` column that feeds a kind. Bundling them into a
// struct would just re-spell the row tuple the single caller already destructures.
#[allow(clippy::too_many_arguments)]
pub(crate) fn kind_from_row(
    code: i64,
    item_id: Option<&[u8]>,
    vault_id: Option<&[u8]>,
    peer_device_id: Option<&[u8]>,
    field: Option<String>,
    item_count: i64,
    format: Option<String>,
    deny_reason: Option<i64>,
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
        Some(11) => AuditKind::PairingModeEnabled,
        Some(12) => AuditKind::PairingModeDisabled,
        Some(13) => AuditKind::AccessDenied {
            reason: deny_reason
                .and_then(|c| u8::try_from(c).ok())
                .and_then(DenyReason::from_code)
                .ok_or(crate::Error::Invalid("audit row missing deny reason"))?,
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
            origin: None,
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

    /// THE chain-compatibility property: attaching an origin must not change
    /// the bytes of a record that has none, so pre-existing logs keep verifying.
    #[test]
    fn an_origin_free_record_encodes_exactly_as_before() {
        let base = AuditRecord {
            seq: 7,
            prev_hash: [4u8; 32],
            timestamp: 1_700_000_000_000,
            device_id: dev(),
            kind: AuditKind::UnlockSuccess,
            detail: Some("x".into()),
            origin: None,
        };
        // Hand-built expectation of the pre-attribution encoding.
        let mut expect = Vec::new();
        expect.extend_from_slice(&7u64.to_le_bytes());
        expect.extend_from_slice(&[4u8; 32]);
        expect.extend_from_slice(&1_700_000_000_000i64.to_le_bytes());
        expect.extend_from_slice(dev().as_bytes());
        expect.push(1); // UnlockSuccess
        push_opt_str(&mut expect, Some("x"));
        assert_eq!(base.canonical_bytes(), expect);

        // Adding an origin changes the hash (it IS covered by the chain).
        let mut with_origin = base.clone();
        with_origin.origin = Some(AuditOrigin::sanitized(
            AuditSource::Cli,
            Some("localpass"),
            Some(42),
        ));
        assert_ne!(with_origin.chain_hash(), base.chain_hash());
        // And so does changing any part of it.
        let mut other = with_origin.clone();
        other.origin = Some(AuditOrigin::sanitized(
            AuditSource::Mcp,
            Some("localpass"),
            Some(42),
        ));
        assert_ne!(other.chain_hash(), with_origin.chain_hash());
    }

    #[test]
    fn sanitize_strips_paths_and_truncates() {
        let o = AuditOrigin::sanitized(AuditSource::Cli, Some(r"C:\tools\localpass.exe"), Some(1));
        assert_eq!(o.process.as_deref(), Some("localpass.exe"));
        let o = AuditOrigin::sanitized(AuditSource::Cli, Some("/usr/local/bin/localpass"), None);
        assert_eq!(o.process.as_deref(), Some("localpass"));
        let long = "x".repeat(200);
        let o = AuditOrigin::sanitized(AuditSource::Cli, Some(&long), None);
        assert_eq!(o.process.as_deref().unwrap().len(), MAX_PROCESS_NAME_CHARS);
        // Blank / whitespace-only names are dropped rather than stored empty.
        assert!(
            AuditOrigin::sanitized(AuditSource::Cli, Some("   "), None)
                .process
                .is_none()
        );
    }

    #[test]
    fn source_and_deny_codes_round_trip() {
        for s in [
            AuditSource::Unknown,
            AuditSource::Cli,
            AuditSource::Gui,
            AuditSource::Mcp,
            AuditSource::NativeHost,
            AuditSource::SshAgent,
            AuditSource::Daemon,
        ] {
            assert_eq!(AuditSource::from_code(s.code()), s);
            assert_eq!(AuditSource::from_label(s.label()), s);
        }
        // An unknown code from a newer build reads as Unknown, never an error.
        assert_eq!(AuditSource::from_code(200), AuditSource::Unknown);
        for r in [
            DenyReason::Locked,
            DenyReason::WrongProfile,
            DenyReason::NotAuthorized,
        ] {
            assert_eq!(DenyReason::from_code(r.code()), Some(r));
        }
        assert_eq!(DenyReason::from_code(0), None);
    }

    #[test]
    fn scoped_origin_wins_and_is_restored() {
        set_process_origin(AuditOrigin::sanitized(
            AuditSource::Daemon,
            Some("localpass-daemon"),
            Some(9),
        ));
        assert_eq!(current_origin().source, AuditSource::Daemon);
        let inner = with_origin(
            AuditOrigin::sanitized(AuditSource::Mcp, Some("agent"), Some(1)),
            current_origin,
        );
        assert_eq!(inner.source, AuditSource::Mcp);
        // Restored after the scope ends.
        assert_eq!(current_origin().source, AuditSource::Daemon);
        // …and after a panic inside the scope.
        let caught = std::panic::catch_unwind(|| {
            with_origin(AuditOrigin::sanitized(AuditSource::Cli, None, None), || {
                panic!("boom")
            })
        });
        assert!(caught.is_err());
        assert_eq!(current_origin().source, AuditSource::Daemon);
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
            AuditKind::PairingModeEnabled,
            AuditKind::PairingModeDisabled,
            AuditKind::AccessDenied {
                reason: DenyReason::Locked,
            },
        ];
        let mut codes: Vec<u8> = kinds.iter().map(AuditKind::code).collect();
        codes.sort_unstable();
        codes.dedup();
        assert_eq!(codes.len(), kinds.len(), "kind codes must be distinct");
    }
}
