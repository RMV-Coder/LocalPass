#![forbid(unsafe_code)]
//! The daemon IPC wire protocol: versioned, length-prefixed JSON.
//!
//! This module is the **canonical protocol spec** (destined for
//! `docs/specs/daemon-ipc.md`). It defines the framing, the versioned envelope,
//! and every request/response the [`crate::client`] sends and the
//! [`crate::server`] answers.
//!
//! # Framing
//!
//! Every message on the wire is:
//!
//! ```text
//!   u32 length (little-endian)  ||  <length> bytes of UTF-8 JSON
//! ```
//!
//! The length prefix counts only the JSON body. A message is refused before
//! allocation if its length exceeds [`MAX_FRAME_LEN`] — a hostile or corrupt
//! peer cannot make us allocate unbounded memory.
//!
//! # Envelope & versioning
//!
//! Both [`Request`] and [`Response`] carry a `"v"` field pinned to
//! [`PROTOCOL_VERSION`]. Crypto agility in LocalPass is by versioned headers,
//! never runtime negotiation (PRD §5.1); the IPC protocol follows the same rule.
//! A peer that sends a `v` we do not understand is rejected with
//! [`Response::Error`] rather than best-effort parsed.
//!
//! # Secret handling on the channel
//!
//! The master password (in [`Request::Unlock`]) and revealed secret values (in
//! [`Response::Item`] with `reveal = true`, [`Response::Field`], and
//! [`Response::Fill`]) cross this channel **in the clear**. That is safe **only
//! because the channel is same-user-only** by construction: on Windows the pipe's
//! DACL grants access to
//! the current user's SID alone; on Unix the socket lives in a `0700` directory,
//! is `0600`, and every connection's peer uid is checked against our euid
//! (PRD §7.3, §8 T8). No other process — not another user, not the network —
//! can open the endpoint. The daemon therefore treats the peer as itself.
//!
//! The request/response `Debug` impls are hand-written to render the request
//! *kind* only (never the password or a secret value), so `--verbose` logging
//! and any accidental `{:?}` cannot leak.
//!
//! # Activity vs. observation
//!
//! Handling a request may reset the daemon's idle auto-lock timer. Two rules
//! govern that, both enforced in [`crate::engine`]:
//!
//! 1. A **passive** request does not. [`Request::Status`] is the passive one: a
//!    client polls it to *discover* a lock, and an observation that postponed
//!    the auto-lock it observes would keep the vault awake forever. A client
//!    that is about to do real work says so with `keepalive: true`.
//! 2. A **refused** request does not, whatever it was. A `Locked`,
//!    `WrongProfile`, or auth-failure answer leaves the timer alone, so a
//!    probing process cannot hold the vault open by failing repeatedly.
//!
//! # Caller attribution
//!
//! Each request frame carries an optional [`WireOrigin`] naming the surface
//! (CLI, GUI, MCP, …) plus its process name and pid, which the daemon puts in
//! force while it handles that request so any audit record names the client
//! rather than the daemon. It is provenance over a same-user-only channel, not
//! authentication.

use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

/// The protocol version carried in every envelope (`"v"`). Bump on any
/// breaking wire change; a mismatch is a hard error, never negotiated.
pub const PROTOCOL_VERSION: u32 = 1;

/// Maximum accepted JSON body length (16 MiB). Generous for any realistic
/// item/env-set payload, but a hard ceiling so a bad length prefix cannot force
/// an unbounded allocation. Applied on both read directions.
pub const MAX_FRAME_LEN: u32 = 16 * 1024 * 1024;

/// A request from a client to the daemon.
///
/// Every vault-touching request carries `profile`: the absolute profile
/// directory the client is operating on. A single-profile daemon (the MVP)
/// refuses requests whose `profile` does not match the one it was started for
/// (see [`Response::WrongProfile`]).
#[derive(Clone, Serialize, Deserialize)]
#[serde(tag = "kind")]
pub enum Request {
    /// Liveness probe. Answered by [`Response::Pong`] whether locked or not.
    Ping,
    /// Report lock state, profile, and (when unlocked) the vault count.
    Status {
        /// The profile the caller expects this daemon to serve.
        profile: String,
        /// Whether this Status is a **client keep-alive** rather than a passive
        /// observation.
        ///
        /// - `false` (the default, and what a GUI/`localpass daemon status` poll
        ///   sends): a pure observation. It does **not** reset the idle
        ///   auto-lock timer — an observer must not postpone the auto-lock it is
        ///   observing, or a UI that polls to notice the lock would keep the
        ///   vault awake forever.
        /// - `true`: a tool is about to do real work and is probing which route
        ///   to take (`lp_cli::daemonctl::route`). That is a present user, so it
        ///   counts as activity and resets the timer — which is what keeps the
        ///   vault alive across a long CLI/MCP run even when the GUI is idle.
        ///
        /// `#[serde(default)]` so a frame from an older peer, which has no such
        /// field, still decodes — as the safe, passive `false`.
        #[serde(default)]
        keepalive: bool,
    },
    /// Unlock the session with a master password (and optionally the Secret Key
    /// display string; if omitted the daemon reads `<profile>/secret-key`).
    Unlock {
        /// The profile directory to unlock.
        profile: String,
        /// The master password (crosses the same-user-only channel; see module
        /// docs). Zeroized after use on both ends.
        password: String,
        /// Optional Secret Key display string (`LP1-…`). When `None`, the daemon
        /// loads it from `<profile>/secret-key` itself.
        secret_key: Option<String>,
        /// Optional idle auto-lock override, in seconds (`0` = never). When
        /// `None`, the daemon keeps its configured/default timeout.
        autolock_secs: Option<u64>,
    },
    /// Create a **brand-new account** in `profile` and hold it unlocked.
    ///
    /// The zero-terminal onboarding path (PRD §4.11) for the desktop GUI, which
    /// is a daemon client and cannot create the account itself. The daemon:
    /// creates the account store (`AccountStore::create`), writes the Secret Key
    /// display string to `<profile>/secret-key` (owner-only — the exact file the
    /// unlock path reads), creates the default `personal` vault, and holds the
    /// unlocked session (same as a successful [`Unlock`](Request::Unlock)).
    ///
    /// Refuses if an account already exists at `profile` (returns
    /// [`Response::Error`]). Answered by [`Response::AccountCreated`], which
    /// carries the Secret Key display string **once** so the GUI can show the
    /// Emergency Kit — it crosses the same-user-only channel exactly like a
    /// revealed secret does.
    CreateAccount {
        /// The profile directory to create the account in.
        profile: String,
        /// The master password (crosses the same-user-only channel; see module
        /// docs). Zeroized after use on both ends.
        password: String,
    },
    /// Drop the unlocked session now (zeroizing key material). Idempotent.
    Lock,
    /// List all vaults as `(id, name)` (requires an unlocked session).
    ListVaults {
        /// The profile directory being operated on.
        profile: String,
    },
    /// Create a new vault by name (requires an unlocked session). Answered by
    /// [`Response::Ok`] whose `message` is the new vault id.
    CreateVault {
        /// The profile directory being operated on.
        profile: String,
        /// The human-readable vault name.
        name: String,
    },
    /// Soft-delete a vault by name or id (requires an unlocked session). The
    /// vault file is left in place but becomes unlisted and unopenable
    /// (vault-format.md §5.1); the operation is a metadata flag, no secret
    /// crosses the wire. Answered by [`Response::Ok`].
    DeleteVault {
        /// The profile directory being operated on.
        profile: String,
        /// Vault name or id to delete.
        vault: String,
    },
    /// List all live items in a vault (metadata + non-secret fields only).
    ListItems {
        /// The profile directory being operated on.
        profile: String,
        /// Vault name or id.
        vault: String,
    },
    /// Analyze a vault's passwords for weak / short / common / reused secrets (the
    /// "Watchtower" check). Runs offline. Answered by [`Response::PasswordHealth`],
    /// which carries **metadata only — never a secret value**.
    PasswordHealth {
        /// The profile directory being operated on.
        profile: String,
        /// Vault name or id.
        vault: String,
    },
    /// Get one item. With `reveal = true` the response carries secret values.
    GetItem {
        /// The profile directory being operated on.
        profile: String,
        /// Vault name or id.
        vault: String,
        /// Item title or id.
        target: String,
        /// A specific version (default: current) — `None` = current.
        version: Option<i64>,
        /// Whether to include secret field values in the response.
        reveal: bool,
    },
    /// An item's version history (metadata per version; never secret values).
    History {
        /// The profile directory being operated on.
        profile: String,
        /// Vault name or id.
        vault: String,
        /// Item title or id.
        target: String,
    },
    /// Search a vault by title/tag/type; never returns secret values.
    Search {
        /// The profile directory being operated on.
        profile: String,
        /// Vault name or id.
        vault: String,
        /// The query text.
        query: String,
        /// Optional item-type filter (e.g. `"login"`).
        type_filter: Option<String>,
    },
    /// Compute the **current TOTP code** for a `totp` item (PRD §4.1 / §4.4).
    ///
    /// The daemon decodes the item's base32 secret and computes the code
    /// **inside the daemon**; the response ([`Response::Totp`]) carries only the
    /// finished digits and the (non-secret) metadata. **The secret never crosses
    /// this channel** — only the 6-8 digit code does. A non-`totp` target is a
    /// usage error.
    Totp {
        /// The profile directory being operated on.
        profile: String,
        /// Vault name or id.
        vault: String,
        /// Item title or id (must be a `totp` item).
        target: String,
    },
    /// Resolve one field of one item to its plaintext value (for `run`/`env`
    /// reference resolution). Returns [`Response::Field`].
    ResolveField {
        /// The profile directory being operated on.
        profile: String,
        /// Vault name or id.
        vault: String,
        /// Item title or id.
        item: String,
        /// Field name (or env-set entry key).
        field: String,
    },
    /// Fetch an item's **raw canonical payload** (the full `ItemPayload` JSON,
    /// including all secret values). Used by `item edit` proxying: the CLI
    /// overlays its edit flags onto the current payload locally (keeping that
    /// logic in one place) and sends it back via [`Request::UpdateItem`]. Same
    /// secret exposure as [`Request::GetItem`] with `reveal` — it crosses the
    /// same-user-only channel.
    GetRawPayload {
        /// The profile directory being operated on.
        profile: String,
        /// Vault name or id.
        vault: String,
        /// Item title or id.
        target: String,
    },
    /// Create an item from a canonical item payload (the JSON the CLI builds).
    CreateItem {
        /// The profile directory being operated on.
        profile: String,
        /// Vault name or id.
        vault: String,
        /// The full item payload as canonical JSON (mirrors `ItemPayload`).
        payload: serde_json::Value,
    },
    /// Update an item (creates a new version) from a canonical payload.
    UpdateItem {
        /// The profile directory being operated on.
        profile: String,
        /// Vault name or id.
        vault: String,
        /// Item title or id.
        target: String,
        /// The full replacement payload as canonical JSON.
        payload: serde_json::Value,
    },
    /// Move an item to the trash.
    DeleteItem {
        /// The profile directory being operated on.
        profile: String,
        /// Vault name or id.
        vault: String,
        /// Item title or id.
        target: String,
    },
    /// Restore a prior version as a new current version.
    RestoreVersion {
        /// The profile directory being operated on.
        profile: String,
        /// Vault name or id.
        vault: String,
        /// Item title or id.
        target: String,
        /// The version number to restore.
        version: i64,
    },
    /// List a vault's trashed (tombstoned) items — metadata + title only, never
    /// a secret value. Answered by [`Response::TrashEntries`].
    ListTrash {
        /// The profile directory being operated on.
        profile: String,
        /// Vault name or id.
        vault: String,
    },
    /// Restore a trashed item out of the trash (PRD §4.10 recover-within-window):
    /// the item's current version is forward-restored as a new version and the
    /// tombstone is dropped. `target` resolves among **trashed** items only.
    UntrashItem {
        /// The profile directory being operated on.
        profile: String,
        /// Vault name or id.
        vault: String,
        /// Item title or id (matched against the trash, not live items).
        target: String,
    },
    /// **Browser autofill (fill-scoped):** list the non-secret login candidates
    /// whose stored URLs match `origin`'s registrable domain (eTLD+1), across all
    /// vaults. Answered by [`Response::LoginCandidates`].
    ///
    /// This is the query behind the extension's `credentials_for` — it returns
    /// **only** `{item_id, title, username, vault}` per candidate and **never a
    /// password**. The daemon (not the extension) decides what matches, using
    /// [`crate::origin`]. A locked daemon answers [`Response::Locked`].
    MatchLogins {
        /// The profile directory being operated on.
        profile: String,
        /// The page origin (a full origin/URL or a bare host) to match against.
        origin: String,
    },
    /// **Browser autofill (fill-scoped):** reveal exactly one login item's
    /// `{username, password}` — and only if the item's stored URL still matches
    /// `origin`'s registrable domain, **re-checked here server-side**. Answered by
    /// [`Response::Fill`].
    ///
    /// This is the only browser-facing request that returns secret values, and
    /// only for a single, user-selected item. The origin re-validation is
    /// defense-in-depth against a hostile/compromised extension claiming a match
    /// it should not have (PRD §8 T7): a mismatch returns [`Response::Error`],
    /// never the secret. A locked daemon answers [`Response::Locked`].
    FillLogin {
        /// The profile directory being operated on.
        profile: String,
        /// The item id (hyphenated) or title to fill.
        item_id: String,
        /// The page origin the fill is for (re-validated against the item's URL).
        origin: String,
    },
    /// **Device pairing:** export this device's public identity (device id,
    /// identity string, fingerprint) for the user to hand to another device.
    /// Answered by [`Response::DeviceIdentity`]. Everything returned is
    /// **public** (public keys + a hash) — no secret crosses this request.
    ExportIdentity {
        /// The profile directory being operated on.
        profile: String,
    },
    /// **Device pairing:** list the trusted peer devices (their pinned public
    /// keys, rendered as fingerprints). Answered by [`Response::Peers`]. No
    /// secret; fingerprints are public.
    ListPeers {
        /// The profile directory being operated on.
        profile: String,
    },
    /// **Device pairing (security-critical):** trust a peer device from its
    /// exported identity string, **after** confirming its fingerprint.
    ///
    /// The daemon parses `identity_string`, computes its fingerprint, and — if
    /// `expected_fingerprint` is non-empty — **requires** it to equal the
    /// computed fingerprint (else refuses with a "fingerprint mismatch" error).
    /// This enforces the out-of-band fingerprint confirmation server-side; the
    /// GUI must never auto-trust. Answered by [`Response::PeerTrusted`]. The
    /// identity string / fingerprint are public — no secret crosses here.
    TrustDevice {
        /// The profile directory being operated on.
        profile: String,
        /// The peer's exported `LPDEV1-…` identity string.
        identity_string: String,
        /// The fingerprint the user confirmed matches the other device
        /// out-of-band. Empty means "not confirmed" → the daemon refuses.
        expected_fingerprint: String,
        /// An optional human label for the peer ("laptop").
        label: Option<String>,
    },
    /// **Device pairing:** open or close this device's **pairing-mode** window
    /// (`device-pairing.md` §4). While open (a time-boxed 3-minute window),
    /// [`TrustDevice`](Request::TrustDevice) may pin a **new** device; while off
    /// (the default) or expired, trusting a new device is refused. It gates
    /// **only** new trust — never anything an already-pinned peer needs (push,
    /// pull, op acceptance, key shares). Requires an unlocked session (the toggle
    /// is recorded in the audit log). Answered by [`Response::Ok`].
    SetPairingMode {
        /// The profile directory being operated on.
        profile: String,
        /// `true` opens the window; `false` closes it immediately.
        enabled: bool,
    },

    // --- Agent-triggered autofill (`agent-fill.md`) ------------------------
    /// **Agent fill:** open or close the **agent-fill arm window**
    /// (`agent-fill.md` §7) and set the per-item scope it covers.
    ///
    /// While the window is open, an agent may [`ArmFillIntent`](Request::ArmFillIntent)
    /// for one of `item_ids` and no other item. The window is time-boxed to
    /// three minutes and lives in memory only, exactly like
    /// [`SetPairingMode`](Request::SetPairingMode). Requires an unlocked session
    /// (the toggle is audited). Answered by [`Response::Ok`].
    SetAgentFillMode {
        /// The profile directory being operated on.
        profile: String,
        /// `true` opens a fresh window; `false` closes it (and drops any
        /// unredeemed intent) immediately.
        on: bool,
        /// The items the window covers — titles or hyphenated ids, resolved to
        /// canonical ids by the daemon. Ignored when `on` is `false`. An empty
        /// set with `on: true` is refused: arming must name what it covers.
        #[serde(default)]
        item_ids: Vec<String>,
        /// Resolve `item_ids` inside this vault only (name or id). `None` — the
        /// default — searches every vault, which is how the browser fill path
        /// has always resolved an item.
        #[serde(default)]
        vault: Option<String>,
    },
    /// **Agent fill:** arm the single, single-use **fill intent** an armed
    /// extension will pull (`agent-fill.md` §5/§7). Carries only ids, a tab id,
    /// and an origin — **never a secret**. Answered by
    /// [`Response::FillIntentArmed`], or [`Response::FillRefused`] with the §10
    /// reason.
    ///
    /// Arming replaces any unredeemed intent; there is no queue.
    ArmFillIntent {
        /// The profile directory being operated on.
        profile: String,
        /// The item to fill — a title or a hyphenated id. Resolved daemon-side
        /// to a canonical id, which is what the intent then carries. (The spec
        /// names this field `item_id`; it accepts either spelling of a
        /// reference, exactly as [`FillLogin`](Request::FillLogin) does.)
        item_id: String,
        /// The browser tab the fill targets, when the agent knows it. `None`
        /// falls back to origin-only targeting, which the extension refuses if
        /// several tabs match (`ambiguous_tab`).
        #[serde(default)]
        tab_id: Option<u64>,
        /// The page origin the fill is for, e.g. `https://github.com`.
        origin: String,
        /// Whether the extension may overwrite an already non-empty field
        /// (`agent-fill.md` §8). Defaults to `false`.
        #[serde(default)]
        overwrite: bool,
        /// Resolve `item_id` inside this vault only (name or id). `None` — the
        /// default — searches every vault, as the browser fill path does.
        #[serde(default)]
        vault: Option<String>,
    },
    /// **Agent fill:** take the pending fill intent, if any (`agent-fill.md`
    /// §5.1). Sent by the browser extension through the native host while the
    /// arm window is open. **Single use** — taking removes it. Answered by
    /// [`Response::FillIntent`] or [`Response::NoFillIntent`]. Non-secret.
    TakeFillIntent {
        /// The profile directory being operated on.
        profile: String,
    },
    /// **Agent fill:** report what the extension did with a taken intent
    /// (`agent-fill.md` §9). Non-secret by construction: [`FillReport`] can only
    /// carry booleans, `empty`/`filled` tokens, and a closed refusal code.
    /// Answered by [`Response::Ok`].
    ReportFillOutcome {
        /// The profile directory being operated on.
        profile: String,
        /// The item the outcome is about (hyphenated id, as handed out in the
        /// intent). A report naming a different item is refused.
        item_id: String,
        /// The non-secret outcome.
        outcome: FillReport,
    },
    /// **Agent fill:** read the state of the pending fill intent so a waiting
    /// caller can learn the outcome **without the daemon ever blocking**
    /// (`agent-fill.md` §5.1, and see [`crate::engine`] on the state mutex).
    ///
    /// This request is not in `agent-fill.md` §11: the spec defines how the
    /// outcome is *reported* but not how the MCP tool, which must answer the
    /// agent with the before/after booleans, *learns* it. Every daemon request
    /// runs under one state mutex, so a blocking wait inside the daemon would
    /// freeze the auto-lock; the MCP client therefore polls this cheap,
    /// non-secret, activity-neutral read between short sleeps. Answered by
    /// [`Response::FillOutcome`].
    PollFillOutcome {
        /// The profile directory being operated on.
        profile: String,
    },
    /// **Sync:** enroll a vault for file-based sync under a shared directory
    /// (`localpass sync setup`). Answered by [`Response::Ok`].
    SyncSetup {
        /// The profile directory being operated on.
        profile: String,
        /// Vault name or id.
        vault: String,
        /// The shared sync-root directory (both devices watch it).
        dir: String,
    },
    /// **Sync:** publish this device's ops to the channel (`localpass sync
    /// push`). Answered by [`Response::SyncPushed`]. No secret — ops are
    /// ciphertext on the channel.
    SyncPush {
        /// The profile directory being operated on.
        profile: String,
        /// Vault name or id.
        vault: String,
    },
    /// **Sync:** verify + merge peers' ops into this vault (`localpass sync
    /// pull`). Answered by [`Response::SyncPulled`], whose `alarms` surface any
    /// quarantine/tamper events (secret-free strings). No secret crosses here;
    /// a shared VaultKey is unsealed inside the engine, never on the wire.
    SyncPull {
        /// The profile directory being operated on.
        profile: String,
        /// Vault name or id.
        vault: String,
    },
    /// **Sync:** per-device seq marks + pending/quarantine counts (`localpass
    /// sync status`). Answered by [`Response::SyncStatus`]. Secret-free.
    SyncStatus {
        /// The profile directory being operated on.
        profile: String,
        /// Vault name or id.
        vault: String,
    },
    /// **Sync:** seal this vault's key to a trusted peer device and ship it via
    /// the channel (`localpass vault share-to-device`). Answered by
    /// [`Response::Ok`]. The sealed key never crosses this API as plaintext —
    /// the request names only a (public) device id; the seal happens inside the
    /// engine.
    ShareVaultToDevice {
        /// The profile directory being operated on.
        profile: String,
        /// Vault name or id.
        vault: String,
        /// The recipient peer's device id (hyphenated UUID).
        device_id: String,
    },
    /// **Sync:** adopt vaults shared to this device from a sync root, then pull
    /// each (`localpass sync adopt`). Answered by [`Response::SyncAdopted`].
    SyncAdopt {
        /// The profile directory being operated on.
        profile: String,
        /// The shared sync-root directory to scan.
        dir: String,
    },
    /// **Device pairing (channel announce, `device-pairing.md` §5):** list the
    /// devices that have announced themselves under `dir`'s `pairing/` folder
    /// but are **not yet trusted** (nor this device itself). Answered by
    /// [`Response::PendingDevices`].
    ///
    /// The announce channel is **untrusted** (§5.2): each returned entry is only
    /// a discovery hint, never a pin. The user still confirms the fingerprint
    /// out-of-band and trusts via [`TrustDevice`](Request::TrustDevice) exactly
    /// as for a pasted string — this request populates a list, nothing more. An
    /// empty/not-enrolled `dir` yields an empty list rather than an error (the
    /// GUI calls it whenever a folder is set). Requires an unlocked session.
    ListPendingDevices {
        /// The profile directory being operated on.
        profile: String,
        /// The shared sync-root directory whose `pairing/` folder to scan.
        dir: String,
    },
    /// **Attachments (path-based; no blob bytes cross this channel):** attach a
    /// file to an item. The caller passes a SOURCE file **path**; the daemon
    /// reads that file itself (it is the same user) and stores it encrypted via
    /// [`lp_vault::Vault::add_attachment`]. Answered by
    /// [`Response::Attachment`].
    ///
    /// The attachment plaintext is read daemon↔disk directly and **never
    /// traverses the pipe** — a strictly stronger boundary than
    /// [`GetItem`](Request::GetItem)/`reveal`, whose secret values do cross the
    /// channel. If `filename` is empty the daemon derives it from
    /// `source_path`'s file name. Oversize sources (> `MAX_ATTACHMENT_BYTES`)
    /// are rejected with a secret-free message.
    AddAttachment {
        /// The profile directory being operated on.
        profile: String,
        /// Vault name or id.
        vault: String,
        /// Item title or id the attachment binds to.
        item: String,
        /// The **source** file path the daemon reads (its bytes never cross the
        /// pipe).
        source_path: String,
        /// The stored filename. Empty ⇒ derived from `source_path`'s base name.
        filename: String,
    },
    /// **Attachments:** list an item's attachments as
    /// `{attachment_id, filename, size}`. Filenames are vault metadata (like
    /// item titles) and only cross the same-user pipe. Answered by
    /// [`Response::Attachments`].
    ListAttachments {
        /// The profile directory being operated on.
        profile: String,
        /// Vault name or id.
        vault: String,
        /// Item title or id.
        item: String,
    },
    /// **Attachments (path-based; no blob bytes cross this channel):** decrypt an
    /// attachment and write its plaintext to a **destination path** the daemon
    /// writes to itself. The decrypted bytes go daemon↔disk directly and **never
    /// enter the response** — a stronger boundary than
    /// [`GetItem`](Request::GetItem)/`reveal`. Answered by
    /// [`Response::AttachmentSaved`] carrying only the filename + byte count.
    ///
    /// Refuses to overwrite an existing `dest_path` unless `force` is set.
    GetAttachment {
        /// The profile directory being operated on.
        profile: String,
        /// Vault name or id.
        vault: String,
        /// Item title or id.
        item: String,
        /// The attachment id (hyphenated) to fetch.
        attachment_id: String,
        /// The **destination** file path the daemon writes the plaintext to (its
        /// bytes never cross the pipe).
        dest_path: String,
        /// Overwrite `dest_path` if it already exists (default refuse).
        force: bool,
    },
    /// **Attachments:** delete an attachment by id. Answered by
    /// [`Response::Ok`].
    DeleteAttachment {
        /// The profile directory being operated on.
        profile: String,
        /// Vault name or id.
        vault: String,
        /// Item title or id.
        item: String,
        /// The attachment id (hyphenated) to delete.
        attachment_id: String,
    },
    /// Read every `(key, value)` of an **env-set** item, in plaintext, for
    /// secret injection (`localpass run --env-set`, and the MCP
    /// `run_with_secrets` tool). Answered by [`Response::EnvEntries`].
    ///
    /// This exists as its own request rather than reusing
    /// [`GetRawPayload`](Request::GetRawPayload) because the two mean different
    /// things: a raw-payload fetch is the support call behind `item edit` and is
    /// deliberately **not** audited, whereas handing over every value of an
    /// env-set is a bulk secret disclosure that **is** — recorded as a
    /// whole-item secret read, exactly as the direct route records it. Splitting
    /// them is what keeps proxied and direct injection symmetric in the audit
    /// log. A non-env-set target is a usage error.
    GetEnvSet {
        /// The profile directory being operated on.
        profile: String,
        /// Vault name or id.
        vault: String,
        /// Item title or id (must be an `env_set` item).
        item: String,
    },
    /// **Audit:** read this device's recent audit records (PRD §4.9). Answered by
    /// [`Response::AuditRecords`].
    ///
    /// An authenticated, unlocked-session operation: the log lives in the account
    /// store, and a locked daemon answers [`Response::Locked`] rather than
    /// opening it. The response carries **metadata only** — ids, kind labels,
    /// timestamps, the caller attribution — and never an item *title*, because
    /// the audit log itself never stores one (a title in this plaintext log
    /// would be a leak; [`lp_vault::audit`]). A client that wants titles resolves
    /// the ids against the vault itself while unlocked.
    AuditList {
        /// The profile directory being operated on.
        profile: String,
        /// Return at most this many records, **most recent first**. `None` means
        /// no cap. The daemon additionally clamps to [`MAX_AUDIT_LIMIT`].
        limit: Option<u32>,
        /// Only records with `timestamp >= since` (unix millis). `None` = all.
        since: Option<i64>,
    },
    /// Terminate the daemon: drop the session and exit, removing the endpoint.
    Shutdown,
}

/// The hard cap on how many audit records one [`Request::AuditList`] returns.
/// A UI shows a recent window; an auditor uses `localpass audit`, which reads
/// the store directly and is not limited.
pub const MAX_AUDIT_LIMIT: u32 = 1000;

impl Request {
    /// A short, non-secret label for logging (`--verbose` logs request kinds
    /// and timings only, never arguments or secrets).
    #[must_use]
    pub fn kind(&self) -> &'static str {
        match self {
            Request::Ping => "Ping",
            Request::Status { .. } => "Status",
            Request::Unlock { .. } => "Unlock",
            Request::CreateAccount { .. } => "CreateAccount",
            Request::Lock => "Lock",
            Request::ListVaults { .. } => "ListVaults",
            Request::CreateVault { .. } => "CreateVault",
            Request::DeleteVault { .. } => "DeleteVault",
            Request::ListItems { .. } => "ListItems",
            Request::PasswordHealth { .. } => "PasswordHealth",
            Request::GetItem { .. } => "GetItem",
            Request::History { .. } => "History",
            Request::Search { .. } => "Search",
            Request::Totp { .. } => "Totp",
            Request::ResolveField { .. } => "ResolveField",
            Request::GetRawPayload { .. } => "GetRawPayload",
            Request::CreateItem { .. } => "CreateItem",
            Request::UpdateItem { .. } => "UpdateItem",
            Request::DeleteItem { .. } => "DeleteItem",
            Request::RestoreVersion { .. } => "RestoreVersion",
            Request::ListTrash { .. } => "ListTrash",
            Request::UntrashItem { .. } => "UntrashItem",
            Request::MatchLogins { .. } => "MatchLogins",
            Request::FillLogin { .. } => "FillLogin",
            Request::ExportIdentity { .. } => "ExportIdentity",
            Request::ListPeers { .. } => "ListPeers",
            Request::TrustDevice { .. } => "TrustDevice",
            Request::SetPairingMode { .. } => "SetPairingMode",
            Request::SetAgentFillMode { .. } => "SetAgentFillMode",
            Request::ArmFillIntent { .. } => "ArmFillIntent",
            Request::TakeFillIntent { .. } => "TakeFillIntent",
            Request::ReportFillOutcome { .. } => "ReportFillOutcome",
            Request::PollFillOutcome { .. } => "PollFillOutcome",
            Request::SyncSetup { .. } => "SyncSetup",
            Request::SyncPush { .. } => "SyncPush",
            Request::SyncPull { .. } => "SyncPull",
            Request::SyncStatus { .. } => "SyncStatus",
            Request::ShareVaultToDevice { .. } => "ShareVaultToDevice",
            Request::SyncAdopt { .. } => "SyncAdopt",
            Request::ListPendingDevices { .. } => "ListPendingDevices",
            Request::AddAttachment { .. } => "AddAttachment",
            Request::ListAttachments { .. } => "ListAttachments",
            Request::GetAttachment { .. } => "GetAttachment",
            Request::DeleteAttachment { .. } => "DeleteAttachment",
            Request::GetEnvSet { .. } => "GetEnvSet",
            Request::AuditList { .. } => "AuditList",
            Request::Shutdown => "Shutdown",
        }
    }

    /// Best-effort zeroize of the in-memory password after the request has been
    /// handled. Only [`Request::Unlock`] and [`Request::CreateAccount`] carry one.
    pub fn zeroize_secrets(&mut self) {
        match self {
            Request::Unlock {
                password,
                secret_key,
                ..
            } => {
                password.zeroize();
                if let Some(sk) = secret_key {
                    sk.zeroize();
                }
            }
            Request::CreateAccount { password, .. } => password.zeroize(),
            _ => {}
        }
    }
}

/// A `Debug` that never prints the password or secret payloads — only the kind.
impl core::fmt::Debug for Request {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Request")
            .field("kind", &self.kind())
            .finish()
    }
}

/// One field of an item as sent to the client. Secret values are already
/// masked by the server unless the request asked to reveal them, so the client
/// renders exactly what it receives.
#[derive(Clone, Serialize, Deserialize)]
pub struct WireField {
    /// The field name.
    pub name: String,
    /// The (possibly-masked) value.
    pub value: String,
    /// Whether the field is secret (masked when not revealed).
    pub secret: bool,
}

/// A single item rendered for the wire (metadata + flattened display fields).
///
/// This mirrors the CLI's own display model so the client can render items
/// identically whether it went through the daemon or unlocked directly.
#[derive(Clone, Serialize, Deserialize)]
pub struct WireItem {
    /// Hyphenated item id.
    pub id: String,
    /// The item title.
    pub title: String,
    /// The item type string (e.g. `"login"`).
    pub type_str: String,
    /// The current (or requested) version number.
    pub version: i64,
    /// Creation time (unix millis).
    pub created_at: i64,
    /// Last-update time (unix millis).
    pub updated_at: i64,
    /// Tags.
    pub tags: Vec<String>,
    /// Favorite flag.
    pub favorite: bool,
    /// Notes body.
    pub notes: String,
    /// Flattened display fields (already masked unless revealed).
    pub fields: Vec<WireField>,
}

/// One entry in an item's version history (metadata only; no field values).
#[derive(Clone, Serialize, Deserialize)]
pub struct WireVersion {
    /// The version number.
    pub version: i64,
    /// When this version was written (unix millis).
    pub created_at: i64,
    /// The title at this version.
    pub title: String,
    /// The item type string at this version.
    pub type_str: String,
}

/// A compact item summary for `list`/`search` (never carries field values).
#[derive(Clone, Serialize, Deserialize)]
pub struct WireItemSummary {
    /// Hyphenated item id.
    pub id: String,
    /// The item title.
    pub title: String,
    /// The item type string.
    pub type_str: String,
    /// Last-update time (unix millis).
    pub updated_at: i64,
    /// Tags.
    pub tags: Vec<String>,
}

/// One trash entry ([`Response::TrashEntries`]) — the tombstone metadata plus
/// the decrypted title/type for display. Never carries a field value.
#[derive(Clone, Serialize, Deserialize)]
pub struct WireTrashEntry {
    /// Hyphenated item id.
    pub id: String,
    /// The item title (at its current — trashed — version).
    pub title: String,
    /// The item type string.
    pub type_str: String,
    /// When the item was deleted (unix millis).
    pub deleted_at: i64,
    /// When it becomes eligible for permanent purge (unix millis).
    pub purge_after: i64,
}

/// One password-health verdict for the "Watchtower" check
/// ([`Response::PasswordHealth`]). Carries **no secret value** — only the
/// metadata needed to render a report.
#[derive(Clone, Serialize, Deserialize)]
pub struct WirePasswordHealth {
    /// Hyphenated item id.
    pub item_id: String,
    /// The item title.
    pub title: String,
    /// The secret field's name (e.g. `password`).
    pub field: String,
    /// The value's length in characters.
    pub length: usize,
    /// Estimated entropy in bits.
    pub entropy_bits: f64,
    /// Coarse strength bucket: `weak` / `fair` / `strong` / `excellent`.
    pub strength: String,
    /// Issue tokens: any of `short` / `weak` / `common` / `reused`.
    pub issues: Vec<String>,
    /// A group id shared by items reusing the same value; `None` if unique.
    pub reuse_group: Option<u32>,
    /// Days since the item was last updated, if known.
    pub age_days: Option<i64>,
}

/// A single non-secret login candidate for browser autofill
/// ([`Response::LoginCandidates`]).
///
/// This is the **only** shape the extension's `credentials_for` returns per
/// match, and it deliberately carries **no password** — just enough for the
/// extension to render a picker. The secret is fetched separately, per item, via
/// [`Request::FillLogin`] after the user chooses.
#[derive(Clone, Serialize, Deserialize)]
pub struct LoginCandidate {
    /// The item id (hyphenated) — the handle passed back to `FillLogin`.
    pub item_id: String,
    /// The item title (for display in the picker).
    pub title: String,
    /// The login username (non-secret; safe to show pre-fill). Empty if unset.
    pub username: String,
    /// The vault name the item lives in (for display / disambiguation).
    pub vault: String,
}

/// A trusted peer device rendered for the wire ([`Response::Peers`]). All
/// fields are **public** — the fingerprint is a hash of public keys, never a
/// secret.
#[derive(Clone, Serialize, Deserialize)]
pub struct WirePeer {
    /// The peer's device id (hyphenated UUID).
    pub device_id: String,
    /// The peer's out-of-band comparison fingerprint (`xxxx-xxxx-xxxx-xxxx`).
    pub fingerprint: String,
    /// An optional user label ("laptop").
    pub label: Option<String>,
    /// When this trust was recorded (unix millis).
    pub verified_at: i64,
}

/// Per-device sync marks rendered for the wire ([`Response::SyncStatus`]).
#[derive(Clone, Serialize, Deserialize)]
pub struct WireSyncDevice {
    /// The device id (hyphenated UUID).
    pub device_id: String,
    /// Whether this is the local (self) device.
    pub is_self: bool,
    /// Whether this device is a trusted peer (or self).
    pub trusted: bool,
    /// Highest `seq` applied locally for this device.
    pub local_seq: u64,
    /// Highest `seq` this device has published to the channel.
    pub channel_seq: u64,
}

/// One announced-but-untrusted device rendered for the wire
/// ([`Response::PendingDevices`], `device-pairing.md` §5). All fields are
/// **public** (public key material + a hash of it); the announce channel is
/// untrusted, so this is a discovery hint the user still confirms out-of-band
/// before trusting (§5.2) — it can populate a list, never pin.
#[derive(Clone, Serialize, Deserialize)]
pub struct WirePendingDevice {
    /// The announcing device's id (hyphenated UUID), derived from its parsed
    /// identity string — **never** trusted from the announce file name (§5.2).
    pub device_id: String,
    /// The announcing device's public `LPDEV1-…` identity string, ready to feed
    /// to [`Request::TrustDevice`] once the user confirms the fingerprint.
    pub identity_string: String,
    /// The out-of-band comparison fingerprint (`xxxx-xxxx-xxxx-xxxx`), derived
    /// from the identity string — the value the user compares to the other
    /// device's screen before trusting.
    pub fingerprint: String,
    /// An optional label the announcing device chose (advisory, untrusted).
    pub label: Option<String>,
    /// When the device announced itself (unix millis).
    pub announced_at: u64,
}

/// One adopted vault rendered for the wire ([`Response::SyncAdopted`]).
#[derive(Clone, Serialize, Deserialize)]
pub struct WireAdoptedVault {
    /// The adopted vault id (hyphenated UUID).
    pub vault_id: String,
    /// The vault name once known locally (may be empty until first pull).
    pub name: String,
}

/// One attachment listing entry rendered for the wire
/// ([`Response::Attachments`]). Carries **no blob bytes** — just the id, the
/// (vault-metadata) filename, and the plaintext size.
#[derive(Clone, Serialize, Deserialize)]
pub struct WireAttachment {
    /// The attachment id (hyphenated UUID) — the handle for get/delete.
    pub attachment_id: String,
    /// The decrypted filename (vault metadata, not a secret value per se).
    pub filename: String,
    /// The plaintext size in bytes.
    pub size: i64,
}

/// One audit record rendered for the wire ([`Response::AuditRecords`]).
///
/// Deliberately **metadata only**, mirroring what the log itself stores: ids as
/// hyphenated UUIDs, a stable kind label, a timestamp, and the caller
/// attribution. There is **no title field and never will be** — the plaintext
/// audit log stores no names ([`lp_vault::audit`]), and putting one here would
/// invent a leak the storage layer refuses to have. Clients resolve `item_id` to
/// a title themselves, against the unlocked vault.
#[derive(Clone, Serialize, Deserialize)]
pub struct WireAuditRecord {
    /// The per-device gapless sequence number (1-based).
    pub seq: u64,
    /// When the action happened (unix millis).
    pub timestamp: i64,
    /// The device the action happened on (hyphenated UUID).
    pub device_id: String,
    /// The stable kind label (e.g. `item_secret_read`, `access_denied`).
    pub kind: String,
    /// The item this record references, if any (hyphenated UUID).
    pub item_id: Option<String>,
    /// The vault this record references, if any (hyphenated UUID).
    pub vault_id: Option<String>,
    /// The peer device this record references, if any (hyphenated UUID).
    pub peer_device_id: Option<String>,
    /// The revealed field *name* for a secret read (never a value).
    pub field: Option<String>,
    /// The export format token, for an export record.
    pub export_format: Option<String>,
    /// The exported item count, for an export record.
    pub item_count: Option<u64>,
    /// Why an operation was refused, for an `access_denied` record.
    pub deny_reason: Option<String>,
    /// Which surface performed the action (`cli` / `gui` / `mcp` / …), or `None`
    /// for a record written before attribution existed.
    pub source: Option<String>,
    /// The caller's short process name (base name only, never a command line).
    pub process: Option<String>,
    /// The caller's process id, when known.
    pub pid: Option<u32>,
    /// The record's optional short non-secret detail string.
    pub detail: Option<String>,
}

/// The caller attribution a client self-reports on the request envelope.
///
/// Carried once per frame rather than per request variant, so adding it did not
/// touch a single request shape. The daemon decodes it into an
/// [`lp_vault::AuditOrigin`] and puts it in force for the duration of that
/// request's handling, so any audit record written on the client's behalf names
/// the client rather than the daemon.
///
/// **Provenance, not authentication:** the channel is same-user-only and the
/// daemon already treats its peer as itself (PRD §8 T8), so this answers "which
/// of my tools did this", not "prove who you are".
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct WireOrigin {
    /// The surface label (see [`lp_vault::AuditSource::label`]). An unknown
    /// label decodes to `unknown` rather than failing the frame.
    #[serde(default)]
    pub source: String,
    /// The caller's process base name. Sanitized again daemon-side.
    #[serde(default)]
    pub process: Option<String>,
    /// The caller's process id.
    #[serde(default)]
    pub pid: Option<u32>,
}

impl WireOrigin {
    /// Render an [`lp_vault::AuditOrigin`] for the wire.
    #[must_use]
    pub fn from_origin(origin: &lp_vault::AuditOrigin) -> Self {
        Self {
            source: origin.source.label().to_string(),
            process: origin.process.clone(),
            pid: origin.pid,
        }
    }

    /// Decode into an [`lp_vault::AuditOrigin`], **re-sanitizing** the process
    /// name daemon-side: the peer is same-user and therefore trusted, but a
    /// server never stores a peer-supplied string into a plaintext log without
    /// re-applying its own base-name/length rules.
    #[must_use]
    pub fn to_origin(&self) -> lp_vault::AuditOrigin {
        lp_vault::AuditOrigin::sanitized(
            lp_vault::AuditSource::from_label(&self.source),
            self.process.as_deref(),
            self.pid,
        )
    }
}

/// A login field an agent fill may target (`agent-fill.md` §3).
///
/// A **closed** set on purpose. The extension names the fields it touched, and
/// this type makes it structurally impossible for that name to be anything but
/// `username` or `password` — a free-form string here would be a channel a
/// hostile extension could smuggle a value down.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FillField {
    /// The username / email field.
    Username,
    /// The password field.
    Password,
}

/// Whether a field held anything, before or after a fill (`agent-fill.md` §3).
///
/// Derived from `value.length > 0` **inside the extension**. The length itself
/// is not reported, and no substring, prefix, or hash of the value ever crosses:
/// this two-valued type is the entire vocabulary.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FieldState {
    /// The field was empty.
    Empty,
    /// The field held something (what, nobody says).
    Filled,
}

/// The `empty`/`filled` state of each field, before or after a fill.
///
/// A struct rather than a map so the key space is closed too — see
/// [`FillField`].
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct FieldStates {
    /// The username field's state, or `None` if there was no such field.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub username: Option<FieldState>,
    /// The password field's state, or `None` if there was no such field.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub password: Option<FieldState>,
}

/// A refusal reason from the `agent-fill.md` §10 taxonomy.
///
/// The agent must be able to tell "you may not" from "it did not work", so these
/// are distinct closed tokens rather than one generic failure. Every variant is
/// a fixed token: a refusal can never carry a message that might contain a
/// value.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FillRefusal {
    /// The agent-fill window is not armed.
    AgentFillNotArmed,
    /// The item is outside the armed per-item set.
    ItemNotArmed,
    /// The daemon is locked.
    Locked,
    /// No item matches the reference.
    ItemNotFound,
    /// The title matches more than one item.
    AmbiguousItem,
    /// The item's stored URL does not match the origin.
    OriginMismatch,
    /// The tab the agent named is gone.
    TabNotFound,
    /// An origin-only arm matched several tabs.
    AmbiguousTab,
    /// The tab navigated after the intent was armed.
    OriginChanged,
    /// The intent lapsed before it was redeemed.
    IntentExpired,
    /// A target field was already non-empty and `overwrite` was not set.
    FieldNotEmpty,
    /// No extension is connected / no native host answered.
    ExtensionUnavailable,
    /// The page has no fillable password field.
    NoLoginForm,
}

impl FillRefusal {
    /// The short, stable token an agent sees (`agent_fill_not_armed`, …).
    #[must_use]
    pub fn token(self) -> &'static str {
        match self {
            FillRefusal::AgentFillNotArmed => "agent_fill_not_armed",
            FillRefusal::ItemNotArmed => "item_not_armed",
            FillRefusal::Locked => "locked",
            FillRefusal::ItemNotFound => "item_not_found",
            FillRefusal::AmbiguousItem => "ambiguous_item",
            FillRefusal::OriginMismatch => "origin_mismatch",
            FillRefusal::TabNotFound => "tab_not_found",
            FillRefusal::AmbiguousTab => "ambiguous_tab",
            FillRefusal::OriginChanged => "origin_changed",
            FillRefusal::IntentExpired => "intent_expired",
            FillRefusal::FieldNotEmpty => "field_not_empty",
            FillRefusal::ExtensionUnavailable => "extension_unavailable",
            FillRefusal::NoLoginForm => "no_login_form",
        }
    }

    /// The [`lp_vault::DenyReason`] this refusal is audited as, or `None` for
    /// the ones that are "it did not work" rather than "you may not" (an
    /// unmatched item reference was never resolved against the vault, so there
    /// is nothing to attribute) and for the client-side
    /// [`ExtensionUnavailable`](FillRefusal::ExtensionUnavailable), which the
    /// daemon never produces.
    #[must_use]
    pub fn deny_reason(self) -> Option<lp_vault::DenyReason> {
        use lp_vault::DenyReason as D;
        match self {
            FillRefusal::AgentFillNotArmed => Some(D::AgentFillNotArmed),
            FillRefusal::ItemNotArmed => Some(D::ItemNotArmed),
            FillRefusal::Locked => Some(D::Locked),
            FillRefusal::OriginMismatch => Some(D::OriginMismatch),
            FillRefusal::TabNotFound => Some(D::TabNotFound),
            FillRefusal::AmbiguousTab => Some(D::AmbiguousTab),
            FillRefusal::OriginChanged => Some(D::OriginChanged),
            FillRefusal::IntentExpired => Some(D::IntentExpired),
            FillRefusal::FieldNotEmpty => Some(D::FieldNotEmpty),
            FillRefusal::NoLoginForm => Some(D::NoLoginForm),
            FillRefusal::ItemNotFound
            | FillRefusal::AmbiguousItem
            | FillRefusal::ExtensionUnavailable => None,
        }
    }
}

/// What the extension did with a taken intent (`agent-fill.md` §3/§9).
///
/// **Structurally secret-free.** Every field is a boolean, a closed token, or a
/// list of closed tokens; there is no `String` anywhere in this type, so the
/// extension has no slot to put a value, a length, a prefix, or a hash in.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FillReport {
    /// Whether the fill landed.
    pub filled: bool,
    /// Which fields were touched.
    #[serde(default)]
    pub fields: Vec<FillField>,
    /// Each field's state before the fill.
    #[serde(default)]
    pub before: FieldStates,
    /// Each field's state after the fill.
    #[serde(default)]
    pub after: FieldStates,
    /// Why it did not land, when `filled` is `false`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<FillRefusal>,
}

/// Where a fill intent is in its short life (answer to
/// [`Request::PollFillOutcome`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FillStatus {
    /// There is no intent at all.
    None,
    /// An intent is armed and waiting for the extension to take it.
    Pending,
    /// The extension took the intent and has not reported back yet.
    Taken,
    /// The extension reported an outcome.
    Reported,
    /// The intent lapsed before it was taken or reported.
    Expired,
}

/// The unlock/lock state reported by [`Response::Status`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum LockState {
    /// A session is held (key material is in memory).
    Unlocked,
    /// No session is held.
    Locked,
}

/// A response from the daemon to the client.
#[derive(Clone, Serialize, Deserialize)]
#[serde(tag = "kind")]
pub enum Response {
    /// Answer to [`Request::Ping`].
    Pong,
    /// Answer to [`Request::Status`].
    Status {
        /// Current lock state.
        state: LockState,
        /// The profile this daemon serves (absolute path).
        profile: String,
        /// Vault count when unlocked; `None` when locked.
        vault_count: Option<usize>,
        /// The effective idle auto-lock timeout in seconds (`0` = never).
        autolock_secs: u64,
        /// Seconds remaining until idle auto-lock when unlocked (`None` when
        /// locked or when auto-lock is disabled).
        idle_remaining_secs: Option<u64>,
        /// The SSH agent endpoint label (pipe name / socket path) when the agent
        /// is enabled, else `None` (started with `--no-ssh-agent`).
        ssh_agent_endpoint: Option<String>,
        /// How many SSH identities the agent is currently serving (0 when locked
        /// or when the agent is disabled).
        ssh_identity_count: usize,
        /// Whole seconds remaining in the open **pairing-mode** window
        /// (`device-pairing.md` §4), or `None` when pairing mode is off/expired.
        /// The GUI/CLI render this as a live countdown; `None` means "off".
        pairing_mode_secs: Option<u64>,
        /// Whole seconds remaining in the open **agent-fill arm window**
        /// (`agent-fill.md` §7), or `None` when agent fill is off/expired.
        /// The browser extension polls `take_fill_intent` **only** while this is
        /// `Some`. `#[serde(default)]` so a `Status` frame from a peer that
        /// predates agent fill still decodes — as `None`, i.e. "off".
        #[serde(default)]
        agent_fill_secs: Option<u64>,
    },
    /// A generic "did it" acknowledgement (Unlock, Lock, mutations).
    Ok {
        /// An optional human message (e.g. `"unlocked"`, `"version 2"`), never
        /// a secret value.
        message: Option<String>,
    },
    /// The answer to a successful [`Request::CreateAccount`].
    ///
    /// Carries the freshly-generated Secret Key **display string** — the one
    /// place it crosses the same-user-only channel, so the GUI can render the
    /// Emergency Kit once (component-local, cleared on navigation). The `Debug`
    /// impl is kind-only (see below), so it is never logged.
    AccountCreated {
        /// The Secret Key display string (`LP1-…`), shown once by the client.
        secret_key: String,
        /// The profile the account was created in (absolute path, display only).
        profile: String,
        /// The number of vaults created (the default `personal` vault → `1`).
        vault_count: usize,
    },
    /// A list of vaults as `(id, name)`.
    Vaults {
        /// The vaults.
        vaults: Vec<(String, String)>,
    },
    /// A list of item summaries (list/search).
    Items {
        /// The summaries.
        items: Vec<WireItemSummary>,
    },
    /// A password-health report (the "Watchtower" check). **Carries no secret
    /// value** — only per-field metadata and issue flags.
    PasswordHealth {
        /// One verdict per analyzed secret field.
        entries: Vec<WirePasswordHealth>,
    },
    /// A vault's trash listing (answer to [`Request::ListTrash`]). Metadata +
    /// titles only — never a field value.
    TrashEntries {
        /// The trashed items, oldest deletion first.
        entries: Vec<WireTrashEntry>,
    },
    /// An item's version history (metadata per version).
    Versions {
        /// The item id (hyphenated).
        id: String,
        /// The versions, oldest first.
        versions: Vec<WireVersion>,
    },
    /// A single full item. Boxed so the [`Response`] enum stays small (a
    /// `WireItem` is the largest variant by far; boxing it keeps every
    /// `Result<_, Response>` in the engine cheap to move).
    Item {
        /// The item.
        item: Box<WireItem>,
    },
    /// The current TOTP code plus its (non-secret) metadata (answer to
    /// [`Request::Totp`]). **This carries no secret** — the base32 secret stayed
    /// inside the daemon; only the finished 6-8 digit `code` and the display
    /// metadata cross the channel.
    Totp {
        /// The current zero-padded code.
        code: String,
        /// Whole seconds remaining in the current time window.
        seconds_remaining: u32,
        /// The time step in seconds (e.g. 30).
        period: u32,
        /// The digit count (6-10).
        digits: u32,
        /// The algorithm token (`SHA1` / `SHA256` / `SHA512`).
        algo: String,
    },
    /// A single resolved field value (ResolveField). Carries a plaintext secret
    /// value — same exposure as the CLI's own `--field` / reference path.
    Field {
        /// The resolved value.
        value: String,
    },
    /// An item's raw canonical payload JSON (GetRawPayload). Carries every
    /// secret value in the clear — for `item edit` overlay on the client side.
    RawPayload {
        /// The item id (hyphenated), so the client can address the update.
        id: String,
        /// The full canonical `ItemPayload` as JSON.
        payload: serde_json::Value,
    },
    /// Non-secret login candidates matching an origin (answer to
    /// [`Request::MatchLogins`]). **Never carries a password** — see
    /// [`LoginCandidate`].
    LoginCandidates {
        /// The matching candidates (may be empty).
        candidates: Vec<LoginCandidate>,
    },
    /// The `{username, password}` for one user-selected login (answer to
    /// [`Request::FillLogin`]), returned **only after** the daemon re-validated
    /// that the item's URL matches the requested origin. This is the sole
    /// browser-facing response carrying a secret value; it carries nothing else.
    Fill {
        /// The login username.
        username: String,
        /// The login password (the secret).
        password: String,
    },
    /// This device's public identity (answer to [`Request::ExportIdentity`]).
    /// Everything here is **public** (public keys + a hash); no secret.
    DeviceIdentity {
        /// This device's id (hyphenated UUID).
        device_id: String,
        /// The compact, CRC-checked `LPDEV1-…` identity string to hand to a peer.
        identity_string: String,
        /// The out-of-band comparison fingerprint (`xxxx-xxxx-xxxx-xxxx`).
        fingerprint: String,
    },
    /// The trusted peer devices (answer to [`Request::ListPeers`]). Public.
    Peers {
        /// The peers (may be empty).
        peers: Vec<WirePeer>,
    },
    /// A peer was trusted (answer to [`Request::TrustDevice`]). Carries the
    /// trusted device's public id + fingerprint + label so the UI can confirm.
    PeerTrusted {
        /// The trusted device id (hyphenated UUID).
        device_id: String,
        /// The confirmed fingerprint (`xxxx-xxxx-xxxx-xxxx`).
        fingerprint: String,
        /// The label recorded for the peer, if any.
        label: Option<String>,
    },
    /// The outcome of a [`Request::SyncPush`]. No secret — ops are ciphertext.
    SyncPushed {
        /// Number of device chains published to the channel.
        published: usize,
        /// Number of segment files freshly written this push.
        segments_written: usize,
    },
    /// The outcome of a [`Request::SyncPull`]. `alarms` are secret-free
    /// descriptions of any quarantine/tamper events — surfaced prominently by
    /// the UI, never swallowed.
    SyncPulled {
        /// Number of foreign ops verified and applied.
        applied: usize,
        /// Number of ops held pending (an earlier op has not arrived yet).
        pending: usize,
        /// Whether a shared-VaultKey blob addressed to this device was imported.
        key_imported: bool,
        /// Secret-free alarm descriptions (empty when clean).
        alarms: Vec<String>,
    },
    /// The per-device sync status (answer to [`Request::SyncStatus`]).
    SyncStatus {
        /// Whether the vault is enrolled for sync.
        enrolled: bool,
        /// The enrolled sync-root (if any; a plain path, non-secret).
        root: Option<String>,
        /// Per-device seq marks.
        devices: Vec<WireSyncDevice>,
        /// Ops currently held pending across all peers.
        pending: usize,
        /// Secret-free alarm descriptions currently in effect.
        alarms: Vec<String>,
    },
    /// The outcome of a [`Request::SyncAdopt`].
    SyncAdopted {
        /// The vaults adopted from the shared folder (may be empty).
        adopted: Vec<WireAdoptedVault>,
        /// Total ops applied across all adopted vaults' initial pulls.
        applied_total: usize,
        /// Secret-free alarm descriptions raised during the adopt pulls.
        alarms: Vec<String>,
    },
    /// The announced-but-untrusted devices found under a sync root's `pairing/`
    /// folder (answer to [`Request::ListPendingDevices`], `device-pairing.md`
    /// §5). Everything here is **public**; the list is a discovery hint the user
    /// still confirms out-of-band before trusting (§5.2).
    PendingDevices {
        /// The pending devices (may be empty), each with its fingerprint.
        devices: Vec<WirePendingDevice>,
    },
    /// A file was attached (answer to [`Request::AddAttachment`]). Carries the
    /// new attachment's id + stored filename — **no blob bytes**.
    Attachment {
        /// The new attachment id (hyphenated UUID).
        attachment_id: String,
        /// The stored filename.
        filename: String,
    },
    /// An item's attachments (answer to [`Request::ListAttachments`]).
    Attachments {
        /// The attachments (may be empty). No blob bytes — see [`WireAttachment`].
        attachments: Vec<WireAttachment>,
    },
    /// An attachment's plaintext was written to disk by the daemon (answer to
    /// [`Request::GetAttachment`]). Carries only the filename + byte count — the
    /// **plaintext bytes are NOT in this response**; they went daemon↔disk.
    AttachmentSaved {
        /// The decrypted filename.
        filename: String,
        /// How many plaintext bytes were written to the destination path.
        bytes_written: u64,
    },
    /// Every entry of an env-set item (answer to [`Request::GetEnvSet`]).
    /// Carries plaintext secret values — the same exposure as
    /// [`Response::Field`], and audited as a whole-item secret read.
    EnvEntries {
        /// The `(key, value)` pairs, in the item's stored order.
        entries: Vec<(String, String)>,
    },
    /// This device's audit records (answer to [`Request::AuditList`]), **most
    /// recent first**. Metadata only — see [`WireAuditRecord`].
    AuditRecords {
        /// The records (may be empty), newest first.
        records: Vec<WireAuditRecord>,
    },
    /// **Agent fill:** a fill intent was armed (answer to
    /// [`Request::ArmFillIntent`]). Non-secret.
    FillIntentArmed {
        /// Whole seconds until the intent lapses (`agent-fill.md` §7: 30s).
        expires_in_secs: u64,
        /// The canonical hyphenated item id the intent was armed for (the
        /// daemon resolved the caller's title/id reference).
        item_id: String,
    },
    /// **Agent fill:** the pending intent, handed to the extension exactly once
    /// (answer to [`Request::TakeFillIntent`]). Ids, a tab id, and an origin —
    /// **never a secret**. The extension then makes the ordinary
    /// [`Request::FillLogin`] call for the credential, unchanged.
    FillIntent {
        /// The item to fill (canonical hyphenated id).
        item_id: String,
        /// The tab the intent targets, or `None` for origin-only targeting.
        tab_id: Option<u64>,
        /// The origin the intent is bound to.
        origin: String,
        /// Whole seconds left before the intent lapses.
        expires_in_secs: u64,
        /// Whether a non-empty field may be overwritten (`agent-fill.md` §8).
        overwrite: bool,
    },
    /// **Agent fill:** there is no intent to take (answer to
    /// [`Request::TakeFillIntent`]). The extension's poll loop sees this for
    /// almost every poll; it is deliberately empty and cheap.
    NoFillIntent,
    /// **Agent fill:** the current state of the pending intent (answer to
    /// [`Request::PollFillOutcome`]).
    FillOutcome {
        /// Where the intent is in its short life.
        status: FillStatus,
        /// The item the intent named (canonical hyphenated id), when there is
        /// one.
        item_id: Option<String>,
        /// The tab the intent targeted, echoed from the intent the daemon armed
        /// — never from the extension's report.
        tab_id: Option<u64>,
        /// The origin the intent was bound to, echoed from the intent the daemon
        /// armed — never from the extension's report.
        origin: Option<String>,
        /// The extension's non-secret report, once
        /// [`Request::ReportFillOutcome`] has arrived.
        report: Option<FillReport>,
    },
    /// **Agent fill:** the request was refused, with the closed `agent-fill.md`
    /// §10 reason code. Separate from [`Response::Error`] so the agent can tell
    /// "you may not" from "it did not work" without parsing a message.
    FillRefused {
        /// Why (a closed token, never a message that could carry a value).
        reason: FillRefusal,
    },
    /// The requested operation needs an unlocked session and none is held.
    Locked,
    /// This daemon serves a different profile than the request named.
    WrongProfile {
        /// The profile this daemon actually serves.
        expected: String,
    },
    /// A structured error. `auth = true` marks a wrong password / Secret Key
    /// (so the client can map it to the auth exit code); otherwise it is a
    /// usage/not-found style error. The message never contains a secret.
    Error {
        /// Whether this is an authentication failure (wrong password/Secret Key).
        auth: bool,
        /// A one-line, secret-free message.
        message: String,
    },
}

impl Response {
    /// A short, non-secret label for logging.
    #[must_use]
    pub fn kind(&self) -> &'static str {
        match self {
            Response::Pong => "Pong",
            Response::Status { .. } => "Status",
            Response::Ok { .. } => "Ok",
            Response::AccountCreated { .. } => "AccountCreated",
            Response::Vaults { .. } => "Vaults",
            Response::Items { .. } => "Items",
            Response::TrashEntries { .. } => "TrashEntries",
            Response::PasswordHealth { .. } => "PasswordHealth",
            Response::Versions { .. } => "Versions",
            Response::Item { .. } => "Item",
            Response::Totp { .. } => "Totp",
            Response::Field { .. } => "Field",
            Response::RawPayload { .. } => "RawPayload",
            Response::LoginCandidates { .. } => "LoginCandidates",
            Response::Fill { .. } => "Fill",
            Response::DeviceIdentity { .. } => "DeviceIdentity",
            Response::Peers { .. } => "Peers",
            Response::PeerTrusted { .. } => "PeerTrusted",
            Response::SyncPushed { .. } => "SyncPushed",
            Response::SyncPulled { .. } => "SyncPulled",
            Response::SyncStatus { .. } => "SyncStatus",
            Response::SyncAdopted { .. } => "SyncAdopted",
            Response::PendingDevices { .. } => "PendingDevices",
            Response::Attachment { .. } => "Attachment",
            Response::Attachments { .. } => "Attachments",
            Response::AttachmentSaved { .. } => "AttachmentSaved",
            Response::EnvEntries { .. } => "EnvEntries",
            Response::AuditRecords { .. } => "AuditRecords",
            Response::FillIntentArmed { .. } => "FillIntentArmed",
            Response::FillIntent { .. } => "FillIntent",
            Response::NoFillIntent => "NoFillIntent",
            Response::FillOutcome { .. } => "FillOutcome",
            Response::FillRefused { .. } => "FillRefused",
            Response::Locked => "Locked",
            Response::WrongProfile { .. } => "WrongProfile",
            Response::Error { .. } => "Error",
        }
    }
}

/// A `Debug` that renders the response kind only (a `Field`/`Item` response
/// carries plaintext secrets when revealed; never let `{:?}` print them).
impl core::fmt::Debug for Response {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Response")
            .field("kind", &self.kind())
            .finish()
    }
}

/// The versioned request envelope actually placed on the wire: `{"v":1, ...}`.
///
/// `caller` is the client's self-reported caller attribution (see
/// [`WireOrigin`]). It rides on the envelope rather than inside each request so
/// adding it touched no request shape, and it is `#[serde(default)]` so a frame
/// from a peer that predates attribution still decodes — as `None`, which the
/// daemon treats as an unattributed caller rather than guessing.
///
/// **The name is load-bearing.** `request` is `#[serde(flatten)]`ed into this
/// same JSON object, so an envelope field that shares a name with any request
/// field emits that key twice and fails to decode with `duplicate field`. This
/// field was called `origin` and collided with [`Request::MatchLogins`] /
/// [`Request::FillLogin`], whose `origin` is the browser origin — every autofill
/// request died on the wire. Keep this name distinct from every request field.
#[derive(Serialize, Deserialize)]
pub(crate) struct RequestEnvelope {
    pub(crate) v: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) caller: Option<WireOrigin>,
    #[serde(flatten)]
    pub(crate) request: Request,
}

/// The versioned response envelope actually placed on the wire.
#[derive(Serialize, Deserialize)]
pub(crate) struct ResponseEnvelope {
    pub(crate) v: u32,
    #[serde(flatten)]
    pub(crate) response: Response,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_debug_never_prints_password() {
        let req = Request::Unlock {
            profile: "/tmp/p".into(),
            password: "hunter2".into(),
            secret_key: Some("LP1-SECRET".into()),
            autolock_secs: Some(600),
        };
        let dbg = format!("{req:?}");
        assert!(!dbg.contains("hunter2"));
        assert!(!dbg.contains("LP1-SECRET"));
        assert!(dbg.contains("Unlock"));
    }

    #[test]
    fn response_debug_never_prints_field_value() {
        let resp = Response::Field {
            value: "s3cr3t-value".into(),
        };
        let dbg = format!("{resp:?}");
        assert!(!dbg.contains("s3cr3t-value"));
        assert!(dbg.contains("Field"));
    }

    #[test]
    fn response_debug_never_prints_fill_password() {
        let resp = Response::Fill {
            username: "octocat".into(),
            password: "s3cr3t-pw".into(),
        };
        let dbg = format!("{resp:?}");
        assert!(!dbg.contains("s3cr3t-pw"));
        // Username is non-secret but the kind-only Debug omits it anyway.
        assert!(!dbg.contains("octocat"));
        assert!(dbg.contains("Fill"));
    }

    #[test]
    fn request_debug_never_prints_create_account_password() {
        let req = Request::CreateAccount {
            profile: "/tmp/p".into(),
            password: "hunter2-onboard".into(),
        };
        let dbg = format!("{req:?}");
        assert!(!dbg.contains("hunter2-onboard"));
        assert!(dbg.contains("CreateAccount"));
    }

    #[test]
    fn response_debug_never_prints_account_created_secret_key() {
        let resp = Response::AccountCreated {
            secret_key: "LP1-SECRET-KIT-VALUE".into(),
            profile: "/tmp/p".into(),
            vault_count: 1,
        };
        let dbg = format!("{resp:?}");
        assert!(!dbg.contains("LP1-SECRET-KIT-VALUE"));
        assert!(dbg.contains("AccountCreated"));
    }

    #[test]
    fn zeroize_clears_create_account_password() {
        let mut req = Request::CreateAccount {
            profile: "/tmp/p".into(),
            password: "hunter2-onboard".into(),
        };
        req.zeroize_secrets();
        if let Request::CreateAccount { password, .. } = &req {
            assert!(password.is_empty());
        } else {
            panic!("still create account");
        }
    }

    #[test]
    fn zeroize_clears_unlock_password() {
        let mut req = Request::Unlock {
            profile: "/tmp/p".into(),
            password: "hunter2".into(),
            secret_key: Some("LP1-X".into()),
            autolock_secs: None,
        };
        req.zeroize_secrets();
        if let Request::Unlock {
            password,
            secret_key,
            ..
        } = &req
        {
            assert!(password.is_empty());
            assert_eq!(secret_key.as_deref(), Some(""));
        } else {
            panic!("still unlock");
        }
    }

    #[test]
    fn envelope_roundtrips_with_version() {
        let env = RequestEnvelope {
            v: PROTOCOL_VERSION,
            caller: None,
            request: Request::Ping,
        };
        let bytes = serde_json::to_vec(&env).unwrap();
        let s = String::from_utf8(bytes.clone()).unwrap();
        assert!(s.contains("\"v\":1"));
        assert!(s.contains("\"kind\":\"Ping\""));
        // An absent caller is omitted entirely, not sent as null.
        assert!(!s.contains("caller"), "{s}");
        let back: RequestEnvelope = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(back.v, PROTOCOL_VERSION);
        assert!(matches!(back.request, Request::Ping));
    }

    /// A request that has a field of its own named like an envelope field must
    /// still round-trip. `request` is `#[serde(flatten)]`ed beside the envelope's
    /// own fields, so a shared name emits the key twice and decoding dies with
    /// `duplicate field`. `MatchLogins.origin` (a browser origin) collided with
    /// an envelope field once called `origin`, which silently killed every
    /// autofill request on the wire; this pins the fix.
    #[test]
    fn envelope_roundtrips_a_request_whose_field_shadows_the_caller_slot() {
        let env = RequestEnvelope {
            v: PROTOCOL_VERSION,
            caller: Some(WireOrigin::from_origin(&lp_vault::AuditOrigin::sanitized(
                lp_vault::AuditSource::NativeHost,
                Some("host"),
                Some(11),
            ))),
            request: Request::MatchLogins {
                profile: "/p".into(),
                origin: "https://example.com/login".into(),
            },
        };
        let bytes = serde_json::to_vec(&env).expect("serialize");
        let back: RequestEnvelope = serde_json::from_slice(&bytes)
            .expect("an envelope field must never share a name with a request field");
        assert!(back.caller.is_some(), "attribution survived");
        match back.request {
            Request::MatchLogins { origin, .. } => {
                assert_eq!(origin, "https://example.com/login", "the URL is intact");
            }
            other => panic!("wrong request back: {other:?}"),
        }
    }

    /// Both additive wire fields must decode from a frame that predates them —
    /// an older peer's `Status` has no `keepalive`, and no envelope `caller`.
    #[test]
    fn an_older_peers_frame_still_decodes() {
        let body = br#"{"v":1,"kind":"Status","profile":"/p"}"#;
        let env: RequestEnvelope = serde_json::from_slice(body).unwrap();
        assert!(env.caller.is_none(), "no attribution claimed");
        match env.request {
            // Defaults to the SAFE, passive reading: an unlabelled Status must
            // not be mistaken for a keep-alive.
            Request::Status { keepalive, profile } => {
                assert!(!keepalive);
                assert_eq!(profile, "/p");
            }
            other => panic!("expected Status, got {other:?}"),
        }
    }

    /// The agent-fill requests add `origin` and `tab_id` as **request** fields,
    /// which is fine; what must never happen is a new *envelope* field sharing a
    /// name with any of them. This drives the exact shape through the wire so a
    /// future envelope field called `origin`, `tab_id`, `item_id`, or `overwrite`
    /// fails here instead of silently killing agent fill the way an envelope
    /// field called `origin` once killed all browser autofill.
    #[test]
    fn the_agent_fill_requests_round_trip_through_the_envelope() {
        let env = RequestEnvelope {
            v: PROTOCOL_VERSION,
            caller: Some(WireOrigin::from_origin(&lp_vault::AuditOrigin::sanitized(
                lp_vault::AuditSource::Mcp,
                Some("agent"),
                Some(7),
            ))),
            request: Request::ArmFillIntent {
                profile: "/p".into(),
                item_id: "the-item".into(),
                tab_id: Some(42),
                origin: "https://github.com".into(),
                overwrite: true,
                vault: None,
            },
        };
        let bytes = serde_json::to_vec(&env).expect("serialize");
        let back: RequestEnvelope = serde_json::from_slice(&bytes)
            .expect("an envelope field must never share a name with a request field");
        assert!(back.caller.is_some(), "attribution survived");
        match back.request {
            Request::ArmFillIntent {
                item_id,
                tab_id,
                origin,
                overwrite,
                ..
            } => {
                assert_eq!(item_id, "the-item");
                assert_eq!(tab_id, Some(42));
                assert_eq!(origin, "https://github.com");
                assert!(overwrite);
            }
            other => panic!("wrong request back: {other:?}"),
        }
    }

    /// The optional agent-fill request fields all default, so a frame from a
    /// peer that predates them still decodes — and decodes to the SAFE reading
    /// (no tab, no overwrite, an empty item scope).
    #[test]
    fn agent_fill_request_fields_default_for_an_older_peer() {
        let body = br#"{"v":1,"kind":"ArmFillIntent","profile":"/p","item_id":"i","origin":"https://x.test"}"#;
        let env: RequestEnvelope = serde_json::from_slice(body).unwrap();
        match env.request {
            Request::ArmFillIntent {
                tab_id, overwrite, ..
            } => {
                assert_eq!(tab_id, None);
                assert!(
                    !overwrite,
                    "overwriting a filled field is never the default"
                );
            }
            other => panic!("expected ArmFillIntent, got {other:?}"),
        }
        let body = br#"{"v":1,"kind":"SetAgentFillMode","profile":"/p","on":true}"#;
        let env: RequestEnvelope = serde_json::from_slice(body).unwrap();
        match env.request {
            Request::SetAgentFillMode { item_ids, .. } => assert!(item_ids.is_empty()),
            other => panic!("expected SetAgentFillMode, got {other:?}"),
        }
    }

    /// A [`FillReport`] is structurally incapable of carrying a value: every
    /// field is a boolean or a closed token. This pins that the serialized form
    /// really is just `empty`/`filled` tokens, and that a body trying to smuggle
    /// a value down `before`/`fields` fails to decode rather than passing it on.
    #[test]
    fn a_fill_report_can_only_say_empty_or_filled() {
        let report = FillReport {
            filled: true,
            fields: vec![FillField::Username, FillField::Password],
            before: FieldStates {
                username: Some(FieldState::Empty),
                password: Some(FieldState::Empty),
            },
            after: FieldStates {
                username: Some(FieldState::Filled),
                password: Some(FieldState::Filled),
            },
            reason: None,
        };
        let json = serde_json::to_string(&report).unwrap();
        assert_eq!(
            json,
            r#"{"filled":true,"fields":["username","password"],"before":{"username":"empty","password":"empty"},"after":{"username":"filled","password":"filled"}}"#
        );
        // A smuggled value is not a `FieldState`, so it does not decode at all.
        assert!(
            serde_json::from_str::<FillReport>(
                r#"{"filled":true,"before":{"password":"hunter2"}}"#
            )
            .is_err()
        );
        // …and neither is a smuggled field NAME.
        assert!(
            serde_json::from_str::<FillReport>(r#"{"filled":true,"fields":["hunter2"]}"#).is_err()
        );
    }

    /// Every §10 refusal has a distinct token, and the ones the daemon can
    /// produce map to a distinct [`lp_vault::DenyReason`] so the audit log can
    /// tell them apart.
    #[test]
    fn every_fill_refusal_has_a_distinct_token() {
        const ALL: [FillRefusal; 13] = [
            FillRefusal::AgentFillNotArmed,
            FillRefusal::ItemNotArmed,
            FillRefusal::Locked,
            FillRefusal::ItemNotFound,
            FillRefusal::AmbiguousItem,
            FillRefusal::OriginMismatch,
            FillRefusal::TabNotFound,
            FillRefusal::AmbiguousTab,
            FillRefusal::OriginChanged,
            FillRefusal::IntentExpired,
            FillRefusal::FieldNotEmpty,
            FillRefusal::ExtensionUnavailable,
            FillRefusal::NoLoginForm,
        ];
        let mut tokens: Vec<&str> = ALL.iter().map(|r| r.token()).collect();
        tokens.sort_unstable();
        tokens.dedup();
        assert_eq!(tokens.len(), ALL.len(), "tokens must be distinct");
        // The serde token and the display token are the same string, so an
        // agent reading either sees one vocabulary.
        for r in ALL {
            let json = serde_json::to_string(&r).unwrap();
            assert_eq!(json, format!("\"{}\"", r.token()));
        }
        let mut reasons: Vec<u8> = ALL
            .iter()
            .filter_map(|r| r.deny_reason())
            .map(lp_vault::DenyReason::code)
            .collect();
        reasons.sort_unstable();
        reasons.dedup();
        assert_eq!(reasons.len(), 10, "ten of the thirteen are audited");
    }

    #[test]
    fn origin_round_trips_and_is_resanitized_on_the_way_in() {
        let wire = WireOrigin {
            source: "mcp".into(),
            // A hostile peer sending a full path gets it reduced daemon-side.
            process: Some("/home/someone/secret-project/agent".into()),
            pid: Some(77),
        };
        let origin = wire.to_origin();
        assert_eq!(origin.source, lp_vault::AuditSource::Mcp);
        assert_eq!(origin.process.as_deref(), Some("agent"));
        assert_eq!(origin.pid, Some(77));
        // An unknown label degrades to `unknown` rather than failing the frame.
        assert_eq!(
            WireOrigin {
                source: "from-the-future".into(),
                process: None,
                pid: None,
            }
            .to_origin()
            .source,
            lp_vault::AuditSource::Unknown
        );
        // And the round trip preserves the label.
        assert_eq!(WireOrigin::from_origin(&origin).source, "mcp");
    }
}
