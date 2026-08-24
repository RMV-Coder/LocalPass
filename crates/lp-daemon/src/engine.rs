#![forbid(unsafe_code)]
//! The vault engine: turning a [`Request`] into vault operations against a held
//! [`lp_vault::Session`], and back into a [`Response`].
//!
//! # Session ownership & thread-safety
//!
//! `lp_vault::Session` is deliberately **not** thread-safe (its op-authoring
//! reads-then-writes are not internally serialized). The daemon therefore holds
//! the whole unlocked state behind one [`std::sync::Mutex`] and serializes all
//! vault access through it — acceptable at CLI request rates (PRD §5.3 targets a
//! handful of ops, not high concurrency). A `Vault<'s>` borrows the `Session`,
//! so every vault operation is scoped inside the same locked critical section.
//!
//! # Locking immunity to a hung client
//!
//! This module never performs client IO. The [`crate::server`] reads the full
//! request off the wire *before* it takes the state mutex, and writes the
//! response *after* it releases it. So a client that stalls mid-read holds only
//! its own worker thread — never the mutex — and can never block a `Lock`,
//! auto-lock, or another client (PRD requirement: "locking must be immune to a
//! hung client").

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use lp_crypto::SecretKey;
use lp_sync::store::{FsStoreFactory, StoreFactory};
use lp_vault::{AccountStore, Item, Session, Vault, VaultId};

use crate::protocol::{
    FillRefusal, FillReport, FillStatus, LockState, Request, Response, WireItem,
};
use crate::render;

/// How long **pairing mode** stays open once enabled (`device-pairing.md` §4):
/// a deliberate, time-boxed **3 minutes**. Trusting a new device is only
/// accepted inside this window; it lapses on its own so an accidentally-left-on
/// toggle cannot linger. Off by default, and turning it off never affects an
/// already-pinned peer (§4 "Does not gate").
const PAIRING_WINDOW: Duration = Duration::from_secs(180);

/// How long the **agent-fill arm window** stays open (`agent-fill.md` §7): a
/// deliberate, time-boxed **3 minutes**, matching pairing mode's precedent. It
/// lapses on its own, and it gates only *new* agent-triggered fills — the human
/// popup path keeps its user-click gate and is untouched by this window.
const AGENT_FILL_WINDOW: Duration = Duration::from_secs(180);

/// How long a single **fill intent** stays redeemable (`agent-fill.md` §7): 30
/// seconds, nested inside the arm window. Long enough for a page to settle,
/// short enough that a forgotten intent is not redeemable later.
const FILL_INTENT_TTL: Duration = Duration::from_secs(30);

/// The open agent-fill arm window and the per-item scope it covers.
///
/// In memory only, exactly like [`State::pairing_mode_until`] — never persisted,
/// and dropped whenever the session is dropped.
struct AgentFillWindow {
    /// When the window lapses.
    until: Instant,
    /// The canonical hyphenated item ids the window covers. An item outside this
    /// set is refused (`item_not_armed`) even inside an open window.
    items: BTreeSet<String>,
}

/// The single pending fill intent (`agent-fill.md` §7: one at a time, no queue).
struct PendingFill {
    /// The canonical hyphenated item id the intent names.
    item_id: String,
    /// The tab the intent targets, or `None` for origin-only targeting.
    tab_id: Option<u64>,
    /// The origin the intent is bound to.
    origin: String,
    /// Whether a non-empty field may be overwritten (`agent-fill.md` §8).
    overwrite: bool,
    /// When the intent lapses, independent of the arm window.
    expires_at: Instant,
    /// Whether the extension has already taken it (single use — taking it twice
    /// must fail).
    taken: bool,
    /// The extension's non-secret outcome report, once it has arrived.
    report: Option<FillReport>,
}

/// The daemon's unlocked-or-locked state, guarded by a mutex in the server.
pub struct State {
    /// The single profile directory this daemon serves.
    profile: PathBuf,
    /// The held session when unlocked; `None` when locked.
    session: Option<Session>,
    /// The idle auto-lock timeout. `Duration::ZERO` means "never".
    autolock: Duration,
    /// The instant of the last successful request (resets the idle timer).
    last_activity: Instant,
    /// The SSH agent endpoint label when the agent is enabled, else `None`
    /// (started with `--no-ssh-agent`). Reported in [`Response::Status`].
    ssh_agent_endpoint: Option<String>,
    /// The sync channel backend every `Sync*` request resolves its enrolled root
    /// through ([`lp_sync::engine`]). Defaults to [`FsStoreFactory`] — the
    /// filesystem channel the daemon has always used — and is replaced by a host
    /// whose user-picked sync root is not a filesystem path (Android's SAF tree
    /// URI), via [`set_store_factory`](Self::set_store_factory).
    store_factory: Arc<dyn StoreFactory>,
    /// When the current **pairing-mode** window expires, or `None` when pairing
    /// mode is off (the default). While `Some(t)` and `Instant::now() < t`,
    /// [`Request::TrustDevice`] may pin a **new** device; otherwise trust is
    /// refused (`device-pairing.md` §4). Held in memory only — a transient
    /// session control, never persisted — and it gates *only* new trust, never
    /// anything an already-pinned peer needs (push/pull, op acceptance, key
    /// shares, `Status`, `ExportIdentity`, `ListPeers`).
    pairing_mode_until: Option<Instant>,
    /// The open **agent-fill arm window** and its per-item scope, or `None` when
    /// agent fill is off (the default). In memory only, like
    /// [`pairing_mode_until`](Self::pairing_mode_until) — see `agent-fill.md`
    /// §7.
    agent_fill: Option<AgentFillWindow>,
    /// The single pending fill intent, or `None`. Replaced (never queued) by a
    /// new arm, removed by the take that redeems it, and dropped whenever the
    /// arm window closes or the session is locked.
    pending_fill: Option<PendingFill>,
    /// How long a fresh agent-fill window stays open. [`AGENT_FILL_WINDOW`] in
    /// production; a test shortens it with
    /// [`set_agent_fill_timings`](Self::set_agent_fill_timings) so lapsing can
    /// be observed without a three-minute wait.
    agent_fill_window: Duration,
    /// How long a fresh fill intent stays redeemable. [`FILL_INTENT_TTL`] in
    /// production; see [`agent_fill_window`](Self::agent_fill_window).
    fill_intent_ttl: Duration,
}

impl State {
    /// A fresh, locked state for `profile` with `autolock` idle timeout, the
    /// filesystem sync backend ([`FsStoreFactory`]), and no SSH agent endpoint
    /// recorded (set later via
    /// [`set_ssh_agent_endpoint`](Self::set_ssh_agent_endpoint) once the agent
    /// listener has bound).
    #[must_use]
    pub fn new(profile: PathBuf, autolock: Duration) -> Self {
        Self::new_with_store_factory(profile, autolock, Arc::new(FsStoreFactory))
    }

    /// [`new`](Self::new), but with the sync channel backend injected.
    ///
    /// This is the seam for a host that cannot be a dependency of the core: an
    /// Android SAF-backed [`lp_sync::store::Store`] lives in the app, and its
    /// factory is handed to the daemon state here. Everything else — the §7
    /// layout, the §5 verifier, the §4 merge — is unchanged.
    #[must_use]
    pub fn new_with_store_factory(
        profile: PathBuf,
        autolock: Duration,
        store_factory: Arc<dyn StoreFactory>,
    ) -> Self {
        Self {
            profile,
            session: None,
            autolock,
            last_activity: Instant::now(),
            ssh_agent_endpoint: None,
            store_factory,
            pairing_mode_until: None,
            agent_fill: None,
            pending_fill: None,
            agent_fill_window: AGENT_FILL_WINDOW,
            fill_intent_ttl: FILL_INTENT_TTL,
        }
    }

    /// Replace the sync channel backend on an existing state (the mutable
    /// counterpart of [`new_with_store_factory`](Self::new_with_store_factory),
    /// for a host that builds its state first and learns its backend later).
    pub fn set_store_factory(&mut self, store_factory: Arc<dyn StoreFactory>) {
        self.store_factory = store_factory;
    }

    /// The sync channel backend this state resolves enrolled roots through.
    ///
    /// Returns a cloned handle so a request handler can hold it across the
    /// `&Session` borrow `with_session` takes on the state.
    #[must_use]
    pub fn store_factory(&self) -> Arc<dyn StoreFactory> {
        Arc::clone(&self.store_factory)
    }

    /// Record the SSH agent endpoint label so `status` can report it. Called by
    /// the server after the agent listener binds (`None` disables reporting when
    /// the agent is off).
    pub fn set_ssh_agent_endpoint(&mut self, endpoint: Option<String>) {
        self.ssh_agent_endpoint = endpoint;
    }

    /// The profile this daemon serves.
    #[must_use]
    pub fn profile(&self) -> &Path {
        &self.profile
    }

    /// The configured auto-lock timeout.
    #[must_use]
    pub fn autolock(&self) -> Duration {
        self.autolock
    }

    /// Whether a session is currently held.
    #[must_use]
    pub fn is_unlocked(&self) -> bool {
        self.session.is_some()
    }

    /// Borrow the held session, or `None` when locked. Used by the SSH agent
    /// listener ([`crate::sshagent`]) to list identities / sign against the
    /// live unlocked session while holding the state mutex. A locked daemon
    /// (`None`) serves an empty agent identity list.
    #[must_use]
    pub fn session_ref(&self) -> Option<&Session> {
        self.session.as_ref()
    }

    /// The number of SSH-agent identities the daemon would currently serve
    /// (every parseable `ssh_key` item across all unlocked vaults), or `0` when
    /// locked. Reported by [`crate::protocol::Response::Status`]. Never fails —
    /// a storage error is reported as `0` (the agent itself degrades the same
    /// way), and per-item parse problems are skipped by
    /// [`crate::sshagent::service::collect_identities`].
    #[must_use]
    pub fn ssh_identity_count(&self) -> usize {
        match &self.session {
            Some(s) => crate::sshagent::service::collect_identities(s)
                .map(|v| v.len())
                .unwrap_or(0),
            None => 0,
        }
    }

    /// Drop the session now (zeroizing key material). Idempotent.
    ///
    /// Also drops the agent-fill window and any pending intent: `agent-fill.md`
    /// §7 says a locked daemon refuses, and the cheapest way to guarantee that
    /// is for the arm state not to survive the lock at all. (Pairing mode is
    /// left alone — it gates a ceremony that itself requires an unlock.)
    pub fn lock(&mut self) {
        // Taking the Option and dropping it runs Session::Drop, which zeroizes.
        if let Some(session) = self.session.take() {
            session.lock();
        }
        self.agent_fill = None;
        self.pending_fill = None;
    }

    /// If unlocked, auto-lock has a non-zero timeout, and the idle time has
    /// elapsed, drop the session and report `true`. Called by the reaper thread
    /// while holding the mutex; performs no IO.
    pub fn maybe_autolock(&mut self) -> bool {
        if self.session.is_some()
            && !self.autolock.is_zero()
            && self.last_activity.elapsed() >= self.autolock
        {
            self.lock();
            return true;
        }
        false
    }

    /// Seconds remaining until idle auto-lock, or `None` if locked or auto-lock
    /// is disabled.
    #[must_use]
    pub fn idle_remaining_secs(&self) -> Option<u64> {
        if self.session.is_none() || self.autolock.is_zero() {
            return None;
        }
        let elapsed = self.last_activity.elapsed();
        Some(self.autolock.saturating_sub(elapsed).as_secs())
    }

    /// Open or close the **pairing-mode** window (`device-pairing.md` §4).
    ///
    /// `on = true` opens a fresh `PAIRING_WINDOW` window
    /// (`Instant::now() + PAIRING_WINDOW`); `on = false` closes it immediately.
    /// While the window is open, [`Request::TrustDevice`] may pin a **new**
    /// device; closed, trust is refused. This only affects *new* trust — it
    /// never touches an already-pinned peer or any sync operation.
    pub fn set_pairing_mode(&mut self, on: bool) {
        self.pairing_mode_until = if on {
            Some(Instant::now() + PAIRING_WINDOW)
        } else {
            None
        };
    }

    /// Whether pairing mode is currently open: `true` iff a window is set and
    /// has not yet elapsed. Expiry is lazy — a window that has passed reads as
    /// closed without any explicit clear.
    #[must_use]
    pub fn pairing_mode_active(&self) -> bool {
        matches!(self.pairing_mode_until, Some(t) if Instant::now() < t)
    }

    /// Whole seconds remaining in the open pairing-mode window, or `None` when
    /// pairing mode is off or has expired. Reported by [`Response::Status`] so
    /// the UI can render a live countdown.
    #[must_use]
    pub fn pairing_mode_remaining_secs(&self) -> Option<u64> {
        match self.pairing_mode_until {
            Some(t) => {
                let now = Instant::now();
                if now < t {
                    Some(t.saturating_duration_since(now).as_secs())
                } else {
                    None
                }
            }
            None => None,
        }
    }

    /// Open or close the **agent-fill arm window** (`agent-fill.md` §7).
    ///
    /// `on = true` opens a fresh [`AGENT_FILL_WINDOW`] covering exactly `items`
    /// (canonical hyphenated item ids); `on = false` closes it now. Either way
    /// any unredeemed intent is dropped: re-arming replaces the scope, so an
    /// intent armed under the old scope must not survive it.
    fn set_agent_fill_mode(&mut self, on: bool, items: BTreeSet<String>) {
        let window = self.agent_fill_window;
        self.agent_fill = on.then(|| AgentFillWindow {
            until: Instant::now() + window,
            items,
        });
        self.pending_fill = None;
    }

    /// Whether the agent-fill window is currently open. Expiry is lazy, exactly
    /// like [`pairing_mode_active`](Self::pairing_mode_active).
    #[must_use]
    pub fn agent_fill_active(&self) -> bool {
        matches!(&self.agent_fill, Some(w) if Instant::now() < w.until)
    }

    /// Whole seconds remaining in the open agent-fill window, or `None` when it
    /// is off or has lapsed. Reported by [`Response::Status`] as
    /// `agent_fill_secs`; the extension polls for intents only while it is
    /// `Some`.
    #[must_use]
    pub fn agent_fill_remaining_secs(&self) -> Option<u64> {
        let w = self.agent_fill.as_ref()?;
        let now = Instant::now();
        (now < w.until).then(|| w.until.saturating_duration_since(now).as_secs())
    }

    /// Whether an **open** window covers `item_id` (a canonical hyphenated id).
    #[must_use]
    fn agent_fill_covers(&self, item_id: &str) -> bool {
        match &self.agent_fill {
            Some(w) if Instant::now() < w.until => w.items.contains(item_id),
            _ => false,
        }
    }

    /// Whether a window was set but has now lapsed — the one transition worth an
    /// audit record, swept by [`sweep_agent_fill`] on the next request.
    #[must_use]
    fn agent_fill_lapsed(&self) -> bool {
        matches!(&self.agent_fill, Some(w) if Instant::now() >= w.until)
    }

    /// Forget the window and any pending intent (used by the lapse sweep).
    fn clear_agent_fill(&mut self) {
        self.agent_fill = None;
        self.pending_fill = None;
    }

    /// Replace the pending intent with a fresh one for `item_id` (canonical id),
    /// and report its TTL in whole seconds.
    fn arm_fill_intent(
        &mut self,
        item_id: String,
        tab_id: Option<u64>,
        origin: String,
        overwrite: bool,
    ) -> u64 {
        self.pending_fill = Some(PendingFill {
            item_id,
            tab_id,
            origin,
            overwrite,
            expires_at: Instant::now() + self.fill_intent_ttl,
            taken: false,
            report: None,
        });
        self.fill_intent_ttl.as_secs()
    }

    /// Shorten (or lengthen) the agent-fill deadlines on this state.
    ///
    /// The production values are [`AGENT_FILL_WINDOW`] and [`FILL_INTENT_TTL`];
    /// nothing in the daemon calls this. It exists so a test can watch a window
    /// or an intent actually lapse — the alternative, fabricating an expired
    /// deadline directly, would test a state the daemon can never reach.
    #[doc(hidden)]
    pub fn set_agent_fill_timings(&mut self, window: Duration, intent_ttl: Duration) {
        self.agent_fill_window = window;
        self.fill_intent_ttl = intent_ttl;
    }

    /// Take the pending intent exactly once. Returns `None` when there is none,
    /// when it has already been taken, or when it has lapsed.
    ///
    /// The intent is **not** removed on take — the daemon keeps it so the
    /// extension's later outcome report has something to attach to, and so a
    /// waiting caller can observe the state. `taken` is what makes it single
    /// use: a second take sees `true` and gets nothing.
    fn take_fill_intent(&mut self) -> Option<(String, Option<u64>, String, u64, bool)> {
        let now = Instant::now();
        let intent = self.pending_fill.as_mut()?;
        if intent.taken || now >= intent.expires_at {
            return None;
        }
        intent.taken = true;
        Some((
            intent.item_id.clone(),
            intent.tab_id,
            intent.origin.clone(),
            intent.expires_at.saturating_duration_since(now).as_secs(),
            intent.overwrite,
        ))
    }

    /// Attach the extension's outcome report to the taken intent for `item_id`.
    /// Returns `false` when no taken intent matches (a stale or forged report).
    fn record_fill_report(&mut self, item_id: &str, report: FillReport) -> bool {
        match self.pending_fill.as_mut() {
            Some(intent) if intent.taken && intent.item_id == item_id => {
                intent.report = Some(report);
                true
            }
            _ => false,
        }
    }

    /// The current state of the pending intent, for a caller waiting on it.
    fn fill_outcome(
        &self,
    ) -> (
        FillStatus,
        Option<String>,
        Option<u64>,
        Option<String>,
        Option<FillReport>,
    ) {
        let Some(intent) = self.pending_fill.as_ref() else {
            return (FillStatus::None, None, None, None, None);
        };
        let status = if intent.report.is_some() {
            FillStatus::Reported
        } else if Instant::now() >= intent.expires_at {
            FillStatus::Expired
        } else if intent.taken {
            FillStatus::Taken
        } else {
            FillStatus::Pending
        };
        (
            status,
            Some(intent.item_id.clone()),
            intent.tab_id,
            Some(intent.origin.clone()),
            intent.report.clone(),
        )
    }

    /// Reset the idle timer (called after every handled request that
    /// [`counts_as_activity`] — i.e. everything except the passive `Status`).
    fn touch(&mut self) {
        self.last_activity = Instant::now();
    }
}

/// Whether `profile` matches the profile this state serves (canonicalized where
/// possible so `.`/trailing-slash spellings agree; falls back to a raw compare).
fn same_profile(state: &State, profile: &str) -> bool {
    let want = Path::new(profile);
    let have = state.profile();
    if want == have {
        return true;
    }
    // Best-effort canonicalization: both may point at the same dir via different
    // spellings. If either canonicalize fails (e.g. dir not yet created), fall
    // back to the raw comparison already done above.
    match (want.canonicalize(), have.canonicalize()) {
        (Ok(a), Ok(b)) => a == b,
        _ => false,
    }
}

/// Parse a hyphenated/simple UUID string into an `lp_vault` id, if it is one.
fn parse_id(s: &str) -> Option<lp_vault::Id> {
    // lp-vault ids are 16-byte UUIDs; reuse its `from_slice` after hex parse.
    // We avoid a uuid dependency here by parsing the canonical hyphenated form
    // by hand (32 hex nibbles, dashes ignored).
    let hex: String = s.chars().filter(|c| *c != '-').collect();
    if hex.len() != 32 || !hex.chars().all(|c| c.is_ascii_hexdigit()) {
        return None;
    }
    let mut bytes = [0u8; 16];
    for (i, b) in bytes.iter_mut().enumerate() {
        let byte = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).ok()?;
        *b = byte;
    }
    Some(lp_vault::Id::from_bytes(bytes))
}

/// Resolve a vault reference (name or id) and open it. Mirrors the CLI's
/// `resolve::open_vault`.
fn open_vault<'s>(session: &'s Session, reference: &str) -> Result<Vault<'s>, Response> {
    let id = resolve_vault_id(session, reference)?;
    session.open_vault(id).map_err(vault_err)
}

/// Resolve a vault reference (name or id) to its [`VaultId`] without opening it.
/// Shares [`open_vault`]'s matching rules (id wins; then unique name; ambiguous
/// names error). Used by operations like delete that act on the id directly.
fn resolve_vault_id(session: &Session, reference: &str) -> Result<VaultId, Response> {
    let vaults = session.list_vaults().map_err(vault_err)?;

    if let Some(id) = parse_id(reference)
        && vaults.iter().any(|(vid, _)| *vid == id)
    {
        return Ok(id);
    }

    let matches: Vec<VaultId> = vaults
        .iter()
        .filter(|(_, name)| name == reference)
        .map(|(vid, _)| *vid)
        .collect();
    match matches.as_slice() {
        [] => Err(usage(format!("no vault named or id {reference:?}"))),
        [only] => Ok(*only),
        _ => Err(usage(format!(
            "vault name {reference:?} is ambiguous ({} match); use the vault id",
            matches.len()
        ))),
    }
}

/// Resolve an item reference (title or id) to a live [`Item`]. Mirrors the CLI's
/// `resolve::find_item`.
fn find_item(vault: &Vault<'_>, reference: &str) -> Result<Item, Response> {
    if let Some(id) = parse_id(reference) {
        match vault.get_item(id) {
            Ok(item) => return Ok(item),
            Err(lp_vault::Error::NotFound(_)) => {}
            Err(e) => return Err(vault_err(e)),
        }
    }
    let items = vault.list_items().map_err(vault_err)?;
    let matches: Vec<&Item> = items
        .iter()
        .filter(|it| it.payload.title == reference)
        .collect();
    match matches.as_slice() {
        [] => Err(usage(format!("no item titled or id {reference:?}"))),
        [only] => vault.get_item(only.item_id).map_err(vault_err),
        _ => Err(usage(format!(
            "item title {reference:?} is ambiguous ({} match); use the item id",
            matches.len()
        ))),
    }
}

/// Resolve an item reference (title or id) among the vault's **trashed** items
/// only. The trash-side mirror of [`find_item`]: an id must be tombstoned to
/// match, and a title is matched against the decrypted titles of the trash
/// listing (unique, else ambiguous).
fn find_trashed_item(vault: &Vault<'_>, reference: &str) -> Result<lp_vault::ItemId, Response> {
    if let Some(id) = parse_id(reference) {
        match vault.get_trashed_item(id) {
            Ok(item) => return Ok(item.item_id),
            Err(lp_vault::Error::NotFound(_)) => {}
            Err(e) => return Err(vault_err(e)),
        }
    }
    let mut matches = Vec::new();
    for e in vault.list_trash().map_err(vault_err)? {
        let it = vault.get_trashed_item(e.item_id).map_err(vault_err)?;
        if it.payload.title == reference {
            matches.push(e.item_id);
        }
    }
    match matches.as_slice() {
        [] => Err(usage(format!("no trashed item titled or id {reference:?}"))),
        [only] => Ok(*only),
        _ => Err(usage(format!(
            "trashed item title {reference:?} is ambiguous ({} match); use the item id",
            matches.len()
        ))),
    }
}

/// Build a usage-style error response (never an auth error, never a secret).
fn usage(message: impl Into<String>) -> Response {
    Response::Error {
        auth: false,
        message: message.into(),
    }
}

/// Map an `lp_vault::Error` from *after* unlock to a response. A post-unlock
/// `DecryptionFailed` is internal (unlock already gated auth), never an auth
/// failure; NotFound/Invalid are usage errors. Mirrors the CLI's
/// `error::map_vault_error`.
fn vault_err(e: lp_vault::Error) -> Response {
    match e {
        lp_vault::Error::NotFound(what) => usage(format!("not found: {what}")),
        lp_vault::Error::Invalid(what) => usage(format!("invalid: {what}")),
        lp_vault::Error::UnsupportedFormat { found, supported } => usage(format!(
            "vault file format {found} is newer than this build supports ({supported}); upgrade LocalPass"
        )),
        other => usage(format!("storage error: {other}")),
    }
}

/// The outcome of handling one request: the response, plus a flag telling the
/// server whether to shut down after replying.
pub struct Handled {
    /// The response to send back.
    pub response: Response,
    /// If true, the server should exit after sending `response`.
    pub shutdown: bool,
}

impl Handled {
    fn reply(response: Response) -> Self {
        Self {
            response,
            shutdown: false,
        }
    }
}

/// Load the Secret Key for `profile`: from the request's display string if
/// supplied, else from `<profile>/secret-key` (the CLI's on-device stand-in).
fn load_secret_key(profile: &Path, supplied: Option<&str>) -> Result<SecretKey, Response> {
    if let Some(s) = supplied {
        return SecretKey::from_display_string(s.trim())
            .map_err(|_| usage("the supplied Secret Key is malformed"));
    }
    let path = profile.join("secret-key");
    let raw = std::fs::read_to_string(&path).map_err(|e| {
        if e.kind() == std::io::ErrorKind::NotFound {
            usage(format!(
                "no Secret Key on this device at {} — it is required to unlock",
                path.display()
            ))
        } else {
            usage(format!("reading Secret Key file: {e}"))
        }
    })?;
    SecretKey::from_display_string(raw.trim()).map_err(|_| {
        usage(format!(
            "the stored Secret Key at {} is malformed",
            path.display()
        ))
    })
}

/// Handle one request against `state` (the caller holds the state mutex).
///
/// Performs **no** client IO — it only reads/writes `state` and the vault files.
/// On success it resets the idle timer.
#[allow(clippy::too_many_lines)]
pub fn handle(state: &mut State, request: Request) -> Handled {
    // Ping and Shutdown are answered regardless of profile/lock.
    match &request {
        Request::Ping => return Handled::reply(Response::Pong),
        Request::Shutdown => {
            state.lock();
            return Handled {
                response: Response::Ok {
                    message: Some("shutting down".into()),
                },
                shutdown: true,
            };
        }
        _ => {}
    }

    // Every other request carries a profile (except Lock, which is global to
    // this single-profile daemon). Enforce the single-profile rule. A refused
    // request is audited and never touches the idle timer (see below).
    if let Some(profile) = request_profile(&request)
        && !same_profile(state, profile)
    {
        record_denied(state, &request, lp_vault::DenyReason::WrongProfile);
        return Handled::reply(Response::WrongProfile {
            expected: state.profile().display().to_string(),
        });
    }

    // Sweep a lapsed agent-fill window before answering, so the arm record has a
    // matching disarm record and a lapsed window can never gate anything.
    sweep_agent_fill(state);

    // Whether the REQUEST is an active one at all (see `counts_as_activity`);
    // the response gets a veto further down.
    let is_activity = counts_as_activity(&request);
    // Remembered for the denial-audit decision, which happens after `request`
    // has been consumed by the match below.
    let denial_worth_auditing = audits_denial(&request);

    let handled = match request {
        Request::Ping | Request::Shutdown => unreachable!("handled above"),

        Request::Status { .. } => {
            let vault_count = state
                .session
                .as_ref()
                .and_then(|s| s.list_vaults().ok())
                .map(|v| v.len());
            let ssh_identity_count = state.ssh_identity_count();
            Handled::reply(Response::Status {
                state: if state.is_unlocked() {
                    LockState::Unlocked
                } else {
                    LockState::Locked
                },
                profile: state.profile().display().to_string(),
                vault_count,
                autolock_secs: state.autolock().as_secs(),
                idle_remaining_secs: state.idle_remaining_secs(),
                ssh_agent_endpoint: state.ssh_agent_endpoint.clone(),
                ssh_identity_count,
                pairing_mode_secs: state.pairing_mode_remaining_secs(),
                agent_fill_secs: state.agent_fill_remaining_secs(),
            })
        }

        Request::Unlock {
            password,
            secret_key,
            autolock_secs,
            ..
        } => handle_unlock(state, &password, secret_key.as_deref(), autolock_secs),

        Request::CreateAccount { password, .. } => handle_create_account(state, &password),

        Request::Lock => {
            state.lock();
            Handled::reply(Response::Ok {
                message: Some("locked".into()),
            })
        }

        Request::ListVaults { .. } => with_session(state, |session| {
            let vaults = session.list_vaults().map_err(vault_err)?;
            Ok(Response::Vaults {
                vaults: vaults
                    .into_iter()
                    .map(|(id, name)| (id.to_hyphenated(), name))
                    .collect(),
            })
        }),

        Request::CreateVault { name, .. } => with_session(state, |session| {
            let id = session.create_vault(&name).map_err(vault_err)?;
            Ok(Response::Ok {
                message: Some(id.to_hyphenated()),
            })
        }),

        Request::DeleteVault { vault, .. } => with_session(state, |session| {
            // Resolve name/id, then soft-delete (metadata flag; the vault file
            // stays on disk but becomes unlisted and unopenable).
            let id = resolve_vault_id(session, &vault)?;
            session.soft_delete_vault(id).map_err(vault_err)?;
            Ok(Response::Ok { message: None })
        }),

        Request::ListItems { vault, .. } => with_session(state, |session| {
            let v = open_vault(session, &vault)?;
            let items = v.list_items().map_err(vault_err)?;
            Ok(Response::Items {
                items: items.iter().map(render::item_to_summary).collect(),
            })
        }),

        Request::PasswordHealth { vault, .. } => with_session(state, |session| {
            let v = open_vault(session, &vault)?;
            // The analysis reads secret values internally but returns metadata
            // only; `render::health_to_wire` carries no value across the wire.
            let report = v.password_health().map_err(vault_err)?;
            Ok(Response::PasswordHealth {
                entries: report.iter().map(render::health_to_wire).collect(),
            })
        }),

        Request::GetItem {
            vault,
            target,
            version,
            reveal,
            ..
        } => with_session(state, |session| {
            let v = open_vault(session, &vault)?;
            let item = find_item(&v, &target)?;
            let wire: WireItem = match version {
                Some(ver) => {
                    let vi = v.get_item_version(item.item_id, ver).map_err(vault_err)?;
                    render::version_to_wire(
                        item.item_id.to_hyphenated(),
                        vi.version,
                        vi.created_at,
                        &vi.payload,
                        reveal,
                    )
                }
                None => render::item_to_wire(&item, reveal),
            };
            // Audit (PRD §4.9): a revealed GetItem discloses secret values — record
            // a whole-item secret read when the item actually has a secret to
            // reveal. A masked GetItem (reveal == false, used by e.g. the delete
            // confirmation) discloses nothing and is NOT audited. The daemon holds
            // the session, so it records here (the CLI proxied path does not — no
            // double-logging). Best-effort.
            if reveal && wire.fields.iter().any(|f| f.secret) {
                v.record_secret_read(&item.item_id, None).ok();
            }
            Ok(Response::Item {
                item: Box::new(wire),
            })
        }),

        Request::History { vault, target, .. } => with_session(state, |session| {
            let v = open_vault(session, &vault)?;
            let it = find_item(&v, &target)?;
            let versions = v.history(it.item_id).map_err(vault_err)?;
            Ok(Response::Versions {
                id: it.item_id.to_hyphenated(),
                versions: versions
                    .into_iter()
                    .map(|ver| crate::protocol::WireVersion {
                        version: ver.version,
                        created_at: ver.created_at,
                        title: ver.payload.title.clone(),
                        type_str: ver.payload.type_data.type_str().to_string(),
                    })
                    .collect(),
            })
        }),

        Request::Search {
            vault,
            query,
            type_filter,
            ..
        } => with_session(state, |session| {
            let v = open_vault(session, &vault)?;
            let hits = v
                .search(&query, type_filter.as_deref())
                .map_err(vault_err)?;
            Ok(Response::Items {
                items: hits.iter().map(render::item_to_summary).collect(),
            })
        }),

        Request::Totp { vault, target, .. } => with_session(state, |session| {
            let v = open_vault(session, &vault)?;
            let it = find_item(&v, &target)?;
            match render::totp_code(&it.payload) {
                Ok(Some(t)) => {
                    // Audit (PRD §4.9): a TOTP code is a disclosure derived from the
                    // secret — record a secret read of the totp field. Best-effort.
                    v.record_secret_read(&it.item_id, Some("totp")).ok();
                    Ok(Response::Totp {
                        code: t.code,
                        seconds_remaining: t.seconds_remaining,
                        period: t.period,
                        digits: t.digits,
                        algo: t.algo,
                    })
                }
                Ok(None) => Err(usage(format!(
                    "item {target:?} is not a totp item (its type is {})",
                    it.payload.type_data.type_str()
                ))),
                Err(msg) => Err(usage(msg)),
            }
        }),

        Request::ResolveField {
            vault, item, field, ..
        } => with_session(state, |session| {
            let v = open_vault(session, &vault)?;
            let it = find_item(&v, &item)?;
            match render::resolve_field(&it.payload, &field) {
                Some(value) => {
                    // Audit (PRD §4.9): resolving a `localpass://` field discloses
                    // its plaintext value — record a secret read naming the field
                    // (never the value). Best-effort.
                    v.record_secret_read(&it.item_id, Some(&field)).ok();
                    Ok(Response::Field { value })
                }
                None => Err(usage(format!(
                    "item {item:?} in vault {vault:?} has no field {field:?}"
                ))),
            }
        }),

        Request::GetRawPayload { vault, target, .. } => with_session(state, |session| {
            let v = open_vault(session, &vault)?;
            let it = find_item(&v, &target)?;
            let payload = serde_json::to_value(&it.payload)
                .map_err(|e| usage(format!("could not serialize payload: {e}")))?;
            // NOT audited as a secret read: GetRawPayload is the daemon-internal
            // support call behind proxied `item edit` (fetch → overlay flags →
            // UpdateItem). The direct-mode `item edit` reads the payload the same
            // way without auditing a read (the ItemUpdate mutation is what gets
            // logged). Auditing here would make proxied edit log a phantom read
            // that direct edit does not — so we keep the two paths symmetric.
            Ok(Response::RawPayload {
                id: it.item_id.to_hyphenated(),
                payload,
            })
        }),

        Request::CreateItem { vault, payload, .. } => with_session(state, |session| {
            let v = open_vault(session, &vault)?;
            let payload = parse_payload(payload)?;
            let id = v.create_item(&payload).map_err(vault_err)?;
            Ok(Response::Ok {
                message: Some(id.to_hyphenated()),
            })
        }),

        Request::UpdateItem {
            vault,
            target,
            payload,
            ..
        } => with_session(state, |session| {
            let v = open_vault(session, &vault)?;
            let it = find_item(&v, &target)?;
            let payload = parse_payload(payload)?;
            let version = v.update_item(it.item_id, &payload).map_err(vault_err)?;
            Ok(Response::Ok {
                message: Some(format!("version {version}")),
            })
        }),

        Request::DeleteItem { vault, target, .. } => with_session(state, |session| {
            const TRASH_RETENTION_MS: i64 = 30 * 24 * 60 * 60 * 1000;
            let v = open_vault(session, &vault)?;
            let it = find_item(&v, &target)?;
            v.delete_item(it.item_id, TRASH_RETENTION_MS)
                .map_err(vault_err)?;
            Ok(Response::Ok {
                message: Some("deleted".into()),
            })
        }),

        Request::RestoreVersion {
            vault,
            target,
            version,
            ..
        } => with_session(state, |session| {
            let v = open_vault(session, &vault)?;
            let it = find_item(&v, &target)?;
            let new_version = v.restore_version(it.item_id, version).map_err(vault_err)?;
            Ok(Response::Ok {
                message: Some(format!("version {new_version}")),
            })
        }),

        Request::ListTrash { vault, .. } => with_session(state, |session| {
            let v = open_vault(session, &vault)?;
            let entries = v.list_trash().map_err(vault_err)?;
            let mut out = Vec::with_capacity(entries.len());
            for e in entries {
                // Decrypt the trashed item's current payload for its title/type
                // (metadata + title only — never a field value on the wire).
                let it = v.get_trashed_item(e.item_id).map_err(vault_err)?;
                out.push(crate::protocol::WireTrashEntry {
                    id: e.item_id.to_hyphenated(),
                    title: it.payload.title,
                    type_str: it.payload.type_data.type_str().to_string(),
                    deleted_at: e.deleted_at,
                    purge_after: e.purge_after,
                });
            }
            Ok(Response::TrashEntries { entries: out })
        }),

        Request::UntrashItem { vault, target, .. } => with_session(state, |session| {
            let v = open_vault(session, &vault)?;
            let item_id = find_trashed_item(&v, &target)?;
            let new_version = v.untrash_item(item_id).map_err(vault_err)?;
            Ok(Response::Ok {
                message: Some(format!("version {new_version}")),
            })
        }),

        Request::MatchLogins { origin, .. } => {
            with_session(state, |session| match_logins(session, &origin))
        }

        Request::FillLogin {
            item_id, origin, ..
        } => with_session(state, |session| fill_login(session, &item_id, &origin)),

        // --- Device pairing (sync-protocol.md §6) --------------------------
        Request::ExportIdentity { .. } => with_session(state, crate::sync::export_identity),

        Request::ListPeers { .. } => with_session(state, crate::sync::list_peers),

        // Pairing mode (`device-pairing.md` §4): open/close the time-boxed
        // window that gates NEW trust. Requires an unlocked session (the toggle
        // is audited). Grab the enabled flag, then in one `with_session` closure
        // flip the pairing window and record the audit through the session — but
        // `set_pairing_mode` needs `&mut state`, which `with_session` borrows, so
        // it is applied *after* the closure returns, driven by a small marker the
        // closure produces (see the match below).
        Request::SetPairingMode { enabled, .. } => handle_set_pairing_mode(state, enabled),

        // --- Agent-triggered autofill (`agent-fill.md`) -------------------
        Request::SetAgentFillMode {
            on,
            item_ids,
            vault,
            ..
        } => handle_set_agent_fill_mode(state, on, &item_ids, vault.as_deref()),

        Request::ArmFillIntent {
            item_id,
            tab_id,
            origin,
            overwrite,
            vault,
            ..
        } => handle_arm_fill_intent(
            state,
            &item_id,
            tab_id,
            &origin,
            overwrite,
            vault.as_deref(),
        ),

        Request::TakeFillIntent { .. } => handle_take_fill_intent(state),

        Request::ReportFillOutcome {
            item_id, outcome, ..
        } => handle_report_fill_outcome(state, &item_id, outcome),

        Request::PollFillOutcome { .. } => handle_poll_fill_outcome(state),

        Request::TrustDevice {
            identity_string,
            expected_fingerprint,
            label,
            ..
        } => {
            // Gate NEW trust on an open pairing-mode window (§4, the load-bearing
            // part). Off/expired → refuse before touching the trust logic; the
            // ceremony itself (fingerprint re-check + pin) is unchanged.
            if !state.pairing_mode_active() {
                Handled::reply(usage(
                    "Pairing mode is off. Turn it on in Devices & Sync to trust a new device.",
                ))
            } else {
                with_session(state, |session| {
                    crate::sync::trust_device(
                        session,
                        &identity_string,
                        &expected_fingerprint,
                        label.as_deref(),
                    )
                })
            }
        }

        // --- Vault sync (sync-protocol.md §5/§7) ---------------------------
        // Each arm takes its own handle on the injected channel backend before
        // `with_session` borrows the state, then resolves the enrolled root
        // through it (`lp_sync::engine` never constructs a backend itself).
        Request::SyncSetup { vault, dir, .. } => {
            let factory = state.store_factory();
            with_session(state, |session| {
                let v = open_vault(session, &vault)?;
                crate::sync::sync_setup(session, &v, &dir, factory.as_ref())
            })
        }

        Request::SyncPush { vault, .. } => {
            let factory = state.store_factory();
            with_session(state, |session| {
                let v = open_vault(session, &vault)?;
                crate::sync::sync_push(session, &v, factory.as_ref())
            })
        }

        Request::SyncPull { vault, .. } => {
            let factory = state.store_factory();
            with_session(state, |session| {
                let v = open_vault(session, &vault)?;
                crate::sync::sync_pull(session, &v, factory.as_ref())
            })
        }

        Request::SyncStatus { vault, .. } => {
            let factory = state.store_factory();
            with_session(state, |session| {
                let v = open_vault(session, &vault)?;
                crate::sync::sync_status(session, &v, factory.as_ref())
            })
        }

        Request::ShareVaultToDevice {
            vault, device_id, ..
        } => {
            let factory = state.store_factory();
            with_session(state, |session| {
                let v = open_vault(session, &vault)?;
                crate::sync::share_vault_to_device(session, &v, &device_id, factory.as_ref())
            })
        }

        Request::SyncAdopt { dir, .. } => {
            let factory = state.store_factory();
            with_session(state, |session| {
                crate::sync::sync_adopt(session, &dir, factory.as_ref())
            })
        }

        // Channel announce (`device-pairing.md` §5): list the announced-but-
        // untrusted devices under the folder's `pairing/` dir. Untrusted (§5.2):
        // it only populates a list — trusting still goes through TrustDevice.
        Request::ListPendingDevices { dir, .. } => {
            let factory = state.store_factory();
            with_session(state, |session| {
                crate::sync::list_pending_devices(session, &dir, factory.as_ref())
            })
        }

        // --- Attachments (path-based; no blob bytes cross the pipe) ---------
        Request::AddAttachment {
            vault,
            item,
            source_path,
            filename,
            ..
        } => with_session(state, |session| {
            add_attachment(session, &vault, &item, &source_path, &filename)
        }),

        Request::ListAttachments { vault, item, .. } => with_session(state, |session| {
            let v = open_vault(session, &vault)?;
            let it = find_item(&v, &item)?;
            let infos = v.list_attachments(it.item_id).map_err(vault_err)?;
            Ok(Response::Attachments {
                attachments: infos
                    .into_iter()
                    .map(|a| crate::protocol::WireAttachment {
                        attachment_id: a.attachment_id.to_hyphenated(),
                        filename: a.filename,
                        size: a.size_plain,
                    })
                    .collect(),
            })
        }),

        Request::GetAttachment {
            vault,
            item,
            attachment_id,
            dest_path,
            force,
            ..
        } => with_session(state, |session| {
            get_attachment(session, &vault, &item, &attachment_id, &dest_path, force)
        }),

        Request::DeleteAttachment {
            vault,
            item,
            attachment_id,
            ..
        } => with_session(state, |session| {
            let v = open_vault(session, &vault)?;
            let it = find_item(&v, &item)?;
            let att_id = resolve_attachment(&v, it.item_id, &attachment_id)?;
            v.delete_attachment(att_id).map_err(vault_err)?;
            Ok(Response::Ok {
                message: Some("removed".into()),
            })
        }),

        Request::GetEnvSet { vault, item, .. } => with_session(state, |session| {
            let v = open_vault(session, &vault)?;
            let it = find_item(&v, &item)?;
            let lp_vault::TypeData::EnvSet { entries } = &it.payload.type_data else {
                return Err(usage(format!(
                    "item {item:?} is a {} item, not an env-set",
                    it.payload.type_data.type_str()
                )));
            };
            // Audit (PRD §4.9): handing over every value of an env-set is a bulk
            // secret disclosure — record a whole-item secret read, matching what
            // the direct route records. Best-effort, and only after the type
            // check passed (a refused request disclosed nothing).
            v.record_secret_read(&it.item_id, None).ok();
            Ok(Response::EnvEntries {
                entries: entries
                    .iter()
                    .map(|e| (e.key.clone(), e.value.clone()))
                    .collect(),
            })
        }),

        Request::AuditList { limit, since, .. } => {
            with_session(state, |session| audit_list(session, limit, since))
        }
    };

    // A REFUSED request is audited (the denied attempts are the interesting
    // half of an audit log) and never resets the idle timer.
    if denial_worth_auditing && let Some(reason) = deny_reason_for(&handled.response) {
        record_denied_reason(state, reason);
    }

    // Reset the idle timer only for an active request that was actually served.
    // A locked/wrong-profile/auth-failure answer is explicitly NOT activity, so
    // a probing process cannot hold the vault open by failing over and over.
    if is_activity && response_counts_as_activity(&handled.response) {
        state.touch();
    }
    handled
}

/// Handle [`Request::AuditList`]: this device's records, **newest first**,
/// optionally floored at `since` and capped at `limit`.
///
/// Metadata only — see [`crate::protocol::WireAuditRecord`]; no item title ever
/// crosses here because the log stores none.
fn audit_list(
    session: &Session,
    limit: Option<u32>,
    since: Option<i64>,
) -> Result<Response, Response> {
    let records = match since {
        Some(floor) => session.audit_since(floor).map_err(vault_err)?,
        None => session.audit_iter().map_err(vault_err)?,
    };
    let cap = limit
        .unwrap_or(crate::protocol::MAX_AUDIT_LIMIT)
        .min(crate::protocol::MAX_AUDIT_LIMIT) as usize;
    // Stored ascending by seq; a client wants the recent window, so reverse and
    // then cap — taking the NEWEST `cap`, not the oldest.
    let out = records
        .iter()
        .rev()
        .take(cap)
        .map(render::audit_to_wire)
        .collect();
    Ok(Response::AuditRecords { records: out })
}

/// Whether a *denied* answer to this request is worth an audit record.
///
/// Only requests that would have touched the vault qualify, and only where no
/// better record already exists:
///
/// - `Status`/`Ping`/`Lock`/`Shutdown` are excluded because a GUI polls `Status`
///   every few seconds against a locked daemon, and auditing that would bury the
///   real refusals under screensaver noise (and grow the log without bound).
/// - `Unlock` is excluded because a failed unlock already writes the more
///   specific [`lp_vault::AuditKind::UnlockFailure`] inside
///   `AccountStore::unlock`. Adding a generic `AccessDenied` beside it would
///   double-count the same event.
fn audits_denial(request: &Request) -> bool {
    !matches!(
        request,
        Request::Ping
            | Request::Shutdown
            | Request::Status { .. }
            | Request::Lock
            | Request::Unlock { .. }
            // The two agent-fill polls are the `Status` argument again: the
            // extension polls `TakeFillIntent` about once a second while armed
            // and the MCP client polls `PollFillOutcome` while it waits, so
            // auditing their refusals would bury the real ones under poll noise
            // and grow the log without bound. The ArmFillIntent that starts the
            // whole exchange IS audited, which is the record that matters.
            | Request::TakeFillIntent { .. }
            | Request::PollFillOutcome { .. }
    )
}

/// The refusal reason a response represents, or `None` if it is not a refusal.
fn deny_reason_for(response: &Response) -> Option<lp_vault::DenyReason> {
    match response {
        Response::Locked => Some(lp_vault::DenyReason::Locked),
        Response::WrongProfile { .. } => Some(lp_vault::DenyReason::WrongProfile),
        Response::Error { auth: true, .. } => Some(lp_vault::DenyReason::NotAuthorized),
        _ => None,
    }
}

/// Record an [`lp_vault::AuditKind::AccessDenied`] for a request refused before
/// it was handled (the wrong-profile gate).
fn record_denied(state: &State, request: &Request, reason: lp_vault::DenyReason) {
    if audits_denial(request) {
        record_denied_reason(state, reason);
    }
}

/// Append the refusal record. **Best-effort and keyless**: a locked daemon holds
/// no session, so this goes through [`AccountStore::record_access_denied`],
/// which reads the device id from the account store's plaintext column and
/// needs no key material. A logging failure never changes the answer the client
/// gets — and a profile with no account store at all simply has nowhere to log.
fn record_denied_reason(state: &State, reason: lp_vault::DenyReason) {
    AccountStore::record_access_denied(state.profile(), reason).ok();
}

/// Whether a request counts as user activity for the idle auto-lock timer.
///
/// `Status` is the one request that can be passive: clients poll it to *observe*
/// lock state (the GUI schedules a refresh for the moment `idle_remaining_secs`
/// expires so it can fall back to the unlock screen), and **an observer must not
/// postpone the auto-lock it is observing**. So a plain `Status` is passive.
///
/// A `Status` with `keepalive: true` is a different thing entirely: it is the
/// route probe a tool sends *because it is about to do real work*
/// (`lp_cli::daemonctl::route`), which makes it evidence of a present user, not
/// an observation. That distinction is what keeps the vault alive through a long
/// CLI or MCP run while an idle GUI polling in the background still lets it lock.
///
/// `Ping`/`Shutdown` never reach the activity accounting at all. The *response*
/// gets a separate veto — see [`response_counts_as_activity`].
fn counts_as_activity(request: &Request) -> bool {
    match request {
        Request::Status { keepalive, .. } => *keepalive,
        // The agent-fill polls are observations, not work: the extension polls
        // `TakeFillIntent` roughly once a second for the whole arm window and
        // the MCP client polls `PollFillOutcome` while it waits for the
        // extension. Letting either reset the idle timer would mean an armed
        // browser tab kept the vault unlocked indefinitely — the same mistake a
        // keep-alive `Status` would be. The `ArmFillIntent` and
        // `ReportFillOutcome` around them are real work and do count.
        Request::TakeFillIntent { .. } | Request::PollFillOutcome { .. } => false,
        _ => true,
    }
}

/// Whether the ANSWER lets the request reset the idle timer.
///
/// A refused request must not: `Locked`, `WrongProfile`, and an authentication
/// failure all mean the caller got nothing, so letting them touch the timer
/// would let an unauthenticated process hold the vault open indefinitely just by
/// failing in a loop.
///
/// An ordinary usage error (`Error { auth: false }`) — a typo'd vault name, a
/// missing item — **does** count. The caller was authenticated and reached a
/// live session; a user fumbling a name is as present as a user getting it
/// right, and the alternative would auto-lock the vault out from under someone
/// who is actively (if clumsily) using it.
fn response_counts_as_activity(response: &Response) -> bool {
    !matches!(
        response,
        Response::Locked | Response::WrongProfile { .. } | Response::Error { auth: true, .. }
    )
}

/// The profile string carried by a request, if any.
fn request_profile(request: &Request) -> Option<&str> {
    match request {
        Request::Status { profile, .. }
        | Request::AuditList { profile, .. }
        | Request::GetEnvSet { profile, .. }
        | Request::Unlock { profile, .. }
        | Request::CreateAccount { profile, .. }
        | Request::ListVaults { profile }
        | Request::CreateVault { profile, .. }
        | Request::DeleteVault { profile, .. }
        | Request::ListItems { profile, .. }
        | Request::PasswordHealth { profile, .. }
        | Request::GetItem { profile, .. }
        | Request::History { profile, .. }
        | Request::Search { profile, .. }
        | Request::Totp { profile, .. }
        | Request::ResolveField { profile, .. }
        | Request::GetRawPayload { profile, .. }
        | Request::CreateItem { profile, .. }
        | Request::UpdateItem { profile, .. }
        | Request::DeleteItem { profile, .. }
        | Request::RestoreVersion { profile, .. }
        | Request::ListTrash { profile, .. }
        | Request::UntrashItem { profile, .. }
        | Request::MatchLogins { profile, .. }
        | Request::FillLogin { profile, .. }
        | Request::ExportIdentity { profile }
        | Request::ListPeers { profile }
        | Request::TrustDevice { profile, .. }
        | Request::SetPairingMode { profile, .. }
        | Request::SetAgentFillMode { profile, .. }
        | Request::ArmFillIntent { profile, .. }
        | Request::TakeFillIntent { profile }
        | Request::ReportFillOutcome { profile, .. }
        | Request::PollFillOutcome { profile }
        | Request::SyncSetup { profile, .. }
        | Request::SyncPush { profile, .. }
        | Request::SyncPull { profile, .. }
        | Request::SyncStatus { profile, .. }
        | Request::ShareVaultToDevice { profile, .. }
        | Request::SyncAdopt { profile, .. }
        | Request::ListPendingDevices { profile, .. }
        | Request::AddAttachment { profile, .. }
        | Request::ListAttachments { profile, .. }
        | Request::GetAttachment { profile, .. }
        | Request::DeleteAttachment { profile, .. } => Some(profile),
        Request::Ping | Request::Lock | Request::Shutdown => None,
    }
}

/// Run `f` against the held session, or return [`Response::Locked`] if locked.
fn with_session<F>(state: &mut State, f: F) -> Handled
where
    F: FnOnce(&Session) -> Result<Response, Response>,
{
    let Some(session) = state.session.as_ref() else {
        return Handled::reply(Response::Locked);
    };
    let resp = match f(session) {
        Ok(r) | Err(r) => r,
    };
    Handled::reply(resp)
}

/// Handle [`Request::SetPairingMode`]: flip the in-memory pairing-mode window
/// (`device-pairing.md` §4) and record the toggle in the audit log.
///
/// Requires an unlocked session: the audit log lives in the account store, and
/// recording the toggle (PRD §4.9) is precisely what makes opening the window a
/// deliberate, auditable act. A locked daemon answers [`Response::Locked`].
///
/// The audit write is **best-effort** — a logging failure must not stop the
/// toggle from taking effect, since the security gate is the in-memory window
/// itself, not the log line.
///
/// # Borrow discipline
///
/// [`State::set_pairing_mode`] needs `&mut state`, but the session is borrowed
/// *from* `state`. So the audit is recorded through the `&Session` first, inside
/// a block that ends that borrow; only then is `state` mutated. No overlap, no
/// `unsafe` — the same shape the `Sync*` handlers use to take what they need
/// before `with_session`.
fn handle_set_pairing_mode(state: &mut State, enabled: bool) -> Handled {
    // Record the toggle through the unlocked session, then let the borrow end.
    {
        let Some(session) = state.session_ref() else {
            return Handled::reply(Response::Locked);
        };
        let kind = if enabled {
            lp_vault::AuditKind::PairingModeEnabled
        } else {
            lp_vault::AuditKind::PairingModeDisabled
        };
        // Best-effort: a failed audit write never blocks the toggle.
        session.record_audit(kind, None).ok();
    }
    // The `&Session` borrow has ended — now flip the pairing-mode window.
    state.set_pairing_mode(enabled);
    Handled::reply(Response::Ok { message: None })
}

// --- Agent-triggered autofill (`agent-fill.md`) ---------------------------

/// Close a lapsed agent-fill window, recording the disarm exactly once.
///
/// Expiry elsewhere in the daemon is lazy (a passed window simply reads as
/// closed). Agent fill wants one thing more: `agent-fill.md` §9 asks for the
/// lapse to be *recorded*, so the audit log shows a window closing as well as
/// opening. This runs at the top of every handled request — the cheapest place
/// that is guaranteed to be reached soon after the window passes — and clears
/// the state so it can only fire once.
///
/// Best-effort: a locked daemon has no session to write through, and it has
/// already dropped the window in [`State::lock`], so there is nothing to sweep.
fn sweep_agent_fill(state: &mut State) {
    if !state.agent_fill_lapsed() {
        return;
    }
    if let Some(session) = state.session_ref() {
        session
            .record_audit(lp_vault::AuditKind::AgentFillModeDisabled, None)
            .ok();
    }
    state.clear_agent_fill();
}

/// Build a [`Response::FillRefused`], auditing it where the refusal is a "you
/// may not" with a [`lp_vault::DenyReason`] behind it.
///
/// The audit write is best-effort and goes through the held session; a locked
/// daemon never reaches here (it answers [`Response::Locked`], which the
/// existing denial machinery already audits).
fn refuse_fill(session: &Session, reason: FillRefusal) -> Response {
    if let Some(deny) = reason.deny_reason() {
        session
            .record_audit(lp_vault::AuditKind::AccessDenied { reason: deny }, None)
            .ok();
    }
    Response::FillRefused { reason }
}

/// The result of looking one item reference up across every vault.
enum Located {
    /// Exactly one live item matched.
    One(Box<lp_vault::Item>),
    /// Nothing matched.
    None,
    /// A title matched more than one item, across one or more vaults.
    Ambiguous,
}

/// Resolve an item reference (hyphenated id, or title) across **all** vaults,
/// distinguishing "no match" from "several matches".
///
/// The human fill path ([`fill_login`]) takes the first title match it finds and
/// is deliberately left alone; the agent path must be able to answer
/// `ambiguous_item` (`agent-fill.md` §10), so it scans every vault and counts.
fn locate_item(
    session: &Session,
    item_ref: &str,
    vault_ref: Option<&str>,
) -> Result<Located, Response> {
    // `None` searches every vault — the way the browser fill path has always
    // resolved an item. A named vault narrows the search to that one.
    let vaults = match vault_ref {
        Some(name) => vec![(resolve_vault_id(session, name)?, String::new())],
        None => session.list_vaults().map_err(vault_err)?,
    };
    let mut matches: Vec<lp_vault::Item> = Vec::new();
    for (vault_id, _name) in &vaults {
        let v = session.open_vault(*vault_id).map_err(vault_err)?;
        if let Some(id) = parse_id(item_ref) {
            match v.get_item(id) {
                // An id is unique by construction: found is found.
                Ok(item) => return Ok(Located::One(Box::new(item))),
                Err(lp_vault::Error::NotFound(_)) => {}
                Err(e) => return Err(vault_err(e)),
            }
        }
        for it in v.list_items().map_err(vault_err)? {
            if it.payload.title == item_ref {
                matches.push(v.get_item(it.item_id).map_err(vault_err)?);
            }
        }
    }
    match matches.len() {
        0 => Ok(Located::None),
        1 => Ok(Located::One(Box::new(matches.remove(0)))),
        _ => Ok(Located::Ambiguous),
    }
}

/// Resolve a reference to the canonical hyphenated id of the one **login** item
/// it names, or the §10 refusal that explains why not.
fn resolve_login_item(
    session: &Session,
    item_ref: &str,
    vault_ref: Option<&str>,
) -> Result<Result<lp_vault::Item, FillRefusal>, Response> {
    Ok(match locate_item(session, item_ref, vault_ref)? {
        Located::None => Err(FillRefusal::ItemNotFound),
        Located::Ambiguous => Err(FillRefusal::AmbiguousItem),
        // A non-login item is "there is no login item by that name", not a
        // separate code — §10 has no variant for a type mismatch.
        Located::One(item) => {
            if matches!(item.payload.type_data, lp_vault::TypeData::Login { .. }) {
                Ok(*item)
            } else {
                Err(FillRefusal::ItemNotFound)
            }
        }
    })
}

/// Handle [`Request::SetAgentFillMode`]: open or close the agent-fill arm window
/// and set the per-item scope (`agent-fill.md` §7).
///
/// Requires an unlocked session, like [`handle_set_pairing_mode`]: the toggle is
/// audited, and that is what makes arming a deliberate act. Opening the window
/// with an empty item list is refused — arming must name what it covers, or the
/// per-item scope would be a no-op.
///
/// # Borrow discipline
///
/// Same shape as [`handle_set_pairing_mode`]: resolve and audit through the
/// `&Session` inside a block, then mutate `state` once the borrow has ended.
fn handle_set_agent_fill_mode(
    state: &mut State,
    on: bool,
    item_ids: &[String],
    vault_ref: Option<&str>,
) -> Handled {
    let resolved: BTreeSet<String> = {
        let Some(session) = state.session_ref() else {
            return Handled::reply(Response::Locked);
        };
        let mut set = BTreeSet::new();
        if on {
            if item_ids.is_empty() {
                return Handled::reply(usage(
                    "arming agent fill needs at least one item; it is scoped per item, \
                     never to the whole vault",
                ));
            }
            for reference in item_ids {
                match resolve_login_item(session, reference, vault_ref) {
                    Err(resp) => return Handled::reply(resp),
                    Ok(Err(reason)) => return Handled::reply(refuse_fill(session, reason)),
                    Ok(Ok(item)) => {
                        set.insert(item.item_id.to_hyphenated());
                    }
                }
            }
        }
        let kind = if on {
            lp_vault::AuditKind::AgentFillModeEnabled
        } else {
            lp_vault::AuditKind::AgentFillModeDisabled
        };
        // Best-effort: a failed audit write never blocks the toggle.
        session.record_audit(kind, None).ok();
        set
    };
    // The `&Session` borrow has ended — now flip the window.
    state.set_agent_fill_mode(on, resolved);
    Handled::reply(Response::Ok { message: None })
}

/// Handle [`Request::ArmFillIntent`]: arm the single, single-use fill intent
/// (`agent-fill.md` §5/§7), after every gate in §10 the daemon can check.
///
/// The gates, in order: the daemon is unlocked; the arm window is open; the item
/// resolves to exactly one login item; that item is inside the armed set; and
/// the item's stored URL matches the requested origin by registrable domain
/// ([`crate::origin`]) — the same authoritative predicate the human fill path
/// re-checks, so a caller cannot lie its way past it.
///
/// **No secret is touched here.** The intent carries ids, a tab id, and an
/// origin; the credential itself only ever leaves through the existing
/// [`Request::FillLogin`], answering the extension exactly as it does today.
fn handle_arm_fill_intent(
    state: &mut State,
    item_ref: &str,
    tab_id: Option<u64>,
    origin: &str,
    overwrite: bool,
    vault_ref: Option<&str>,
) -> Handled {
    let armed: String = {
        let Some(session) = state.session_ref() else {
            return Handled::reply(Response::Locked);
        };
        if !state.agent_fill_active() {
            return Handled::reply(refuse_fill(session, FillRefusal::AgentFillNotArmed));
        }
        let item = match resolve_login_item(session, item_ref, vault_ref) {
            Err(resp) => return Handled::reply(resp),
            Ok(Err(reason)) => return Handled::reply(refuse_fill(session, reason)),
            Ok(Ok(item)) => item,
        };
        let item_id = item.item_id.to_hyphenated();
        if !state.agent_fill_covers(&item_id) {
            return Handled::reply(refuse_fill(session, FillRefusal::ItemNotArmed));
        }
        // The origin must have a registrable domain at all, and the item's URL
        // must match it (PRD §8 T7). Both are `origin_mismatch` to the agent.
        if crate::origin::registrable_domain(origin).is_none()
            || !payload_matches_origin(&item.payload, origin)
        {
            return Handled::reply(refuse_fill(session, FillRefusal::OriginMismatch));
        }
        item_id
    };
    let expires_in_secs =
        state.arm_fill_intent(armed.clone(), tab_id, origin.to_string(), overwrite);
    Handled::reply(Response::FillIntentArmed {
        expires_in_secs,
        item_id: armed,
    })
}

/// Handle [`Request::TakeFillIntent`]: hand the pending intent to the extension
/// **exactly once** (`agent-fill.md` §7 "single use").
///
/// A second take, a take after the 30-second TTL, or a take with nothing armed
/// all answer [`Response::NoFillIntent`] — the extension's poll loop sees that
/// for almost every poll and must treat it as unremarkable.
fn handle_take_fill_intent(state: &mut State) -> Handled {
    if !state.is_unlocked() {
        return Handled::reply(Response::Locked);
    }
    match state.take_fill_intent() {
        Some((item_id, tab_id, origin, expires_in_secs, overwrite)) => {
            Handled::reply(Response::FillIntent {
                item_id,
                tab_id,
                origin,
                expires_in_secs,
                overwrite,
            })
        }
        None => Handled::reply(Response::NoFillIntent),
    }
}

/// Handle [`Request::ReportFillOutcome`]: attach the extension's non-secret
/// report to the intent it took (`agent-fill.md` §9).
///
/// A report that names an item with no *taken* intent behind it is a usage
/// error, not a refusal: it is a stale or forged message, and nothing about the
/// vault was attempted. A report of a *failed* fill whose reason maps to a
/// [`lp_vault::DenyReason`] is audited as an `AccessDenied`, which is how the
/// extension-side halves of the §10 taxonomy (`field_not_empty`,
/// `origin_changed`, …) reach the log at all — the daemon cannot observe them
/// itself.
///
/// A *successful* fill is already in the log: the [`Request::FillLogin`] that
/// released the credential wrote the `ItemSecretRead`, so recording another one
/// here would double-count the same disclosure.
fn handle_report_fill_outcome(state: &mut State, item_id: &str, outcome: FillReport) -> Handled {
    {
        let Some(session) = state.session_ref() else {
            return Handled::reply(Response::Locked);
        };
        if !outcome.filled
            && let Some(deny) = outcome.reason.and_then(FillRefusal::deny_reason)
        {
            session
                .record_audit(lp_vault::AuditKind::AccessDenied { reason: deny }, None)
                .ok();
        }
    }
    if state.record_fill_report(item_id, outcome) {
        Handled::reply(Response::Ok { message: None })
    } else {
        Handled::reply(usage(
            "no taken fill intent matches this outcome report; ignoring it",
        ))
    }
}

/// Handle [`Request::PollFillOutcome`]: report where the pending intent is, so a
/// waiting caller can learn the outcome **without the daemon ever blocking**.
///
/// This is the whole answer to the concurrency problem the feature poses. Every
/// request runs under the one state mutex (see the module docs), so a `fill_login`
/// that waited *inside* the daemon for the extension would hold that mutex for
/// seconds and freeze everything behind it — including the auto-lock reaper. So
/// nothing waits in here: this handler reads three fields and returns. The
/// waiting happens in the MCP client, between separate requests, with the mutex
/// released the whole time.
fn handle_poll_fill_outcome(state: &mut State) -> Handled {
    if !state.is_unlocked() {
        return Handled::reply(Response::Locked);
    }
    let (status, item_id, tab_id, origin, report) = state.fill_outcome();
    Handled::reply(Response::FillOutcome {
        status,
        item_id,
        tab_id,
        origin,
        report,
    })
}

/// Perform an unlock: derive keys and stash the session, or report the failure.
fn handle_unlock(
    state: &mut State,
    password: &str,
    secret_key: Option<&str>,
    autolock_secs: Option<u64>,
) -> Handled {
    let profile = state.profile().to_path_buf();
    let secret_key = match load_secret_key(&profile, secret_key) {
        Ok(sk) => sk,
        Err(resp) => return Handled::reply(resp),
    };

    match AccountStore::unlock(&profile, password, &secret_key) {
        Ok(session) => {
            // Replace any existing session (re-unlock is idempotent-ish).
            state.lock();
            state.session = Some(session);
            if let Some(secs) = autolock_secs {
                state.autolock = Duration::from_secs(secs);
            }
            Handled::reply(Response::Ok {
                message: Some("unlocked".into()),
            })
        }
        Err(lp_vault::Error::DecryptionFailed) => Handled::reply(Response::Error {
            auth: true,
            message: "wrong master password or Secret Key".into(),
        }),
        Err(lp_vault::Error::NotFound(_)) => Handled::reply(usage(format!(
            "no account at {} — run `localpass init` first",
            profile.display()
        ))),
        Err(e) => Handled::reply(usage(format!("unlock failed: {e}"))),
    }
}

/// The default vault created at account creation. Mirrors the CLI's
/// `init::DEFAULT_VAULT` so a GUI-created account is indistinguishable from a
/// `localpass init`-created one.
const DEFAULT_VAULT: &str = "personal";

/// Create a brand-new account, write its Secret Key to `<profile>/secret-key`,
/// create the default `personal` vault, and hold the unlocked session.
///
/// Refuses if an account already exists at the profile. On success the daemon
/// holds the live [`Session`] exactly as a successful unlock does, and resets
/// the idle timer (via the shared [`State::touch`] on the way out of `handle`).
///
/// The returned [`Response::AccountCreated`] carries the Secret Key display
/// string once (for the Emergency Kit); the daemon keeps no copy of it beyond
/// the on-device `secret-key` file it must write for the unlock path to read.
fn handle_create_account(state: &mut State, password: &str) -> Handled {
    let profile = state.profile().to_path_buf();

    // Refuse if an account already exists (mirrors the CLI's `init` guard). The
    // `create` call below would also fail, but checking up front yields the
    // exact "already exists" message and never partially touches the store.
    if profile.join(lp_vault::account::ACCOUNT_FILE).exists() {
        return Handled::reply(usage(format!(
            "an account already exists at {} — refusing to overwrite",
            profile.display()
        )));
    }

    // Create the account. The Secret Key is returned exactly once here.
    let (session, secret_key) = match AccountStore::create(&profile, password) {
        Ok(pair) => pair,
        Err(lp_vault::Error::Invalid(_)) => {
            // `create` maps "already exists" to Invalid.
            return Handled::reply(usage(format!(
                "an account already exists at {}",
                profile.display()
            )));
        }
        Err(e) => return Handled::reply(usage(format!("could not create the account: {e}"))),
    };

    // Persist the Secret Key on-device at `<profile>/secret-key`, byte-for-byte
    // as the CLI's `init` does (the unlock path — `load_secret_key` above —
    // reads exactly this file). A failure here leaves an account with no local
    // Secret Key, which cannot be unlocked, so surface it as an error.
    let secret_key_display = secret_key.to_display_string();
    if let Err(e) = write_secret_key_file(&profile, &secret_key_display) {
        return Handled::reply(usage(format!(
            "account created, but writing the Secret Key file failed: {e}"
        )));
    }

    // Create the default vault (same name as the CLI's `init`).
    if let Err(e) = session.create_vault(DEFAULT_VAULT) {
        return Handled::reply(usage(format!(
            "account created, but creating the default vault failed: {e}"
        )));
    }

    let vault_count = session.list_vaults().map(|v| v.len()).unwrap_or(1);

    // Hold the unlocked session (same as a successful Unlock).
    state.lock();
    state.session = Some(session);

    Handled::reply(Response::AccountCreated {
        secret_key: secret_key_display,
        profile: profile.display().to_string(),
        vault_count,
    })
}

/// Write the Secret Key display string to `<profile>/secret-key`, owner-only.
///
/// This mirrors `lp-cli`'s `profile::store_secret_key` **byte-for-byte**: the
/// file is the display string followed by a single `\n`, created (or truncated)
/// with mode `0600` on Unix. The unlock path ([`load_secret_key`]) reads exactly
/// this file, so the two writers must agree on its contents.
fn write_secret_key_file(profile: &Path, secret_key_display: &str) -> std::io::Result<()> {
    use std::io::Write;
    std::fs::create_dir_all(profile)?;
    let path = profile.join("secret-key");
    // Newline-terminated so the file is a well-formed text line (matches lp-cli).
    let contents = format!("{secret_key_display}\n");
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut f = opts.open(&path)?;
    f.write_all(contents.as_bytes())?;
    // Re-assert 0600 in case the file pre-existed with looser perms.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
    }
    f.sync_all()?;
    Ok(())
}

/// Collect every URL a `login` item advertises for autofill matching: its
/// primary `url` field (kind `url`) plus any additional `TypeData::Login.urls`.
/// Non-login items yield an empty list. Blank URLs are dropped. This is the
/// exact set the registrable-domain check runs over (PRD §4.7).
fn login_urls(payload: &lp_vault::ItemPayload) -> Vec<String> {
    use lp_vault::payload::{FieldKind, TypeData};
    let mut urls = Vec::new();
    let TypeData::Login { urls: extra } = &payload.type_data else {
        return urls;
    };
    // The primary URL lives as a `url`-kind custom field (mirrors how the CLI
    // stores `--url`); accept any string-valued field named "url" too.
    for f in &payload.fields {
        let is_url = matches!(f.kind, FieldKind::Url) || f.name.eq_ignore_ascii_case("url");
        if is_url && let Some(s) = f.value.as_str() {
            let s = s.trim();
            if !s.is_empty() {
                urls.push(s.to_string());
            }
        }
    }
    for u in extra {
        let u = u.trim();
        if !u.is_empty() {
            urls.push(u.to_string());
        }
    }
    urls
}

/// The non-secret username of a login item (the `username` field, exact then
/// case-insensitive), or an empty string when unset.
fn login_username(payload: &lp_vault::ItemPayload) -> String {
    payload
        .fields
        .iter()
        .find(|f| f.name == "username")
        .or_else(|| {
            payload
                .fields
                .iter()
                .find(|f| f.name.eq_ignore_ascii_case("username"))
        })
        .and_then(|f| f.value.as_str())
        .unwrap_or("")
        .to_string()
}

/// The password of a login item (the `password` field, exact then
/// case-insensitive), or an empty string when unset. **Secret** — only ever put
/// in a [`Response::Fill`], never a candidate list.
fn login_password(payload: &lp_vault::ItemPayload) -> String {
    payload
        .fields
        .iter()
        .find(|f| f.name == "password")
        .or_else(|| {
            payload
                .fields
                .iter()
                .find(|f| f.name.eq_ignore_ascii_case("password"))
        })
        .and_then(|f| f.value.as_str())
        .unwrap_or("")
        .to_string()
}

/// Whether any of `payload`'s login URLs matches `origin` by registrable domain.
/// The single authoritative predicate ([`crate::origin`]) used by both the
/// candidate scan and the fill re-check.
fn payload_matches_origin(payload: &lp_vault::ItemPayload, origin: &str) -> bool {
    login_urls(payload)
        .iter()
        .any(|u| crate::origin::url_matches_origin(u, origin))
}

/// Handle [`Request::MatchLogins`]: scan every vault for `login` items whose
/// stored URLs match `origin` by registrable domain, returning **non-secret**
/// candidate descriptors (never a password).
fn match_logins(session: &Session, origin: &str) -> Result<Response, Response> {
    // Reject an origin with no registrable domain up front (a bare public suffix,
    // an IP, localhost) — there is nothing legitimate to match (PRD §8 T7).
    if crate::origin::registrable_domain(origin).is_none() {
        return Ok(Response::LoginCandidates {
            candidates: Vec::new(),
        });
    }
    let vaults = session.list_vaults().map_err(vault_err)?;
    let mut candidates = Vec::new();
    for (vault_id, vault_name) in &vaults {
        let v = session.open_vault(*vault_id).map_err(vault_err)?;
        let items = v.list_items().map_err(vault_err)?;
        for it in &items {
            if payload_matches_origin(&it.payload, origin) {
                candidates.push(crate::protocol::LoginCandidate {
                    item_id: it.item_id.to_hyphenated(),
                    title: it.payload.title.clone(),
                    username: login_username(&it.payload),
                    vault: vault_name.clone(),
                });
            }
        }
    }
    Ok(Response::LoginCandidates { candidates })
}

/// Handle [`Request::FillLogin`]: find the one item by id/title across all
/// vaults, **re-validate** its URL against `origin` server-side, and return
/// `{username, password}` only on a match. A mismatch is a usage error, never
/// the secret (defense in depth against a hostile extension — PRD §8 T7).
fn fill_login(session: &Session, item_ref: &str, origin: &str) -> Result<Response, Response> {
    // Re-validate the origin has a registrable domain at all before doing work.
    if crate::origin::registrable_domain(origin).is_none() {
        return Err(usage(
            "the requested origin has no registrable domain; refusing to fill",
        ));
    }
    let vaults = session.list_vaults().map_err(vault_err)?;
    // Locate the item across vaults (by id first, else by unique title). Track the
    // owning vault id so the fill can be audited against the right vault.
    let mut found: Option<(lp_vault::Item, lp_vault::VaultId)> = None;
    for (vault_id, _name) in &vaults {
        let v = session.open_vault(*vault_id).map_err(vault_err)?;
        // Try by id (`parse_id` yields an `lp_vault::Id`, which is `ItemId`).
        if let Some(id) = parse_id(item_ref) {
            match v.get_item(id) {
                Ok(item) => {
                    found = Some((item, *vault_id));
                    break;
                }
                Err(lp_vault::Error::NotFound(_)) => {}
                Err(e) => return Err(vault_err(e)),
            }
        }
        // Try by unique title within this vault.
        if found.is_none() {
            let items = v.list_items().map_err(vault_err)?;
            if let Some(it) = items.iter().find(|it| it.payload.title == item_ref) {
                found = Some((v.get_item(it.item_id).map_err(vault_err)?, *vault_id));
                break;
            }
        }
    }
    let (item, vault_id) =
        found.ok_or_else(|| usage(format!("no login item matching {item_ref:?}")))?;

    // Must be a login item.
    if !matches!(item.payload.type_data, lp_vault::TypeData::Login { .. }) {
        return Err(usage(
            "the requested item is not a login item; refusing to fill",
        ));
    }

    // THE server-side origin re-check (defense in depth). A mismatch never
    // returns the secret.
    if !payload_matches_origin(&item.payload, origin) {
        return Err(usage(
            "the item's URL does not match the requested origin; refusing to fill",
        ));
    }

    // Audit (PRD §4.9): a fill releases the password for autofill — a secret
    // disclosure. Record it as a secret read of the password field (never the
    // value), only after every check passed. Best-effort. A refused fill (bad
    // origin / wrong type / mismatch above) returns before here and is NOT logged
    // as a read — no secret left the vault.
    session
        .record_secret_read(&vault_id, &item.item_id, Some("password"))
        .ok();

    Ok(Response::Fill {
        username: login_username(&item.payload),
        password: login_password(&item.payload),
    })
}

/// Handle [`Request::AddAttachment`]: read the SOURCE file **from disk inside
/// the daemon** (same-user IPC) and store it encrypted. The blob bytes never
/// crossed the pipe — the caller passed a path, not the data.
///
/// The size cap is enforced twice: a friendly up-front check on the file's
/// metadata length (so an oversize file is rejected before it is read fully),
/// and again structurally inside [`lp_vault::Vault::add_attachment`] before any
/// blob is written. An empty `filename` is derived from the source's base name.
fn add_attachment(
    session: &Session,
    vault_ref: &str,
    item_ref: &str,
    source_path: &str,
    filename: &str,
) -> Result<Response, Response> {
    let v = open_vault(session, vault_ref)?;
    let it = find_item(&v, item_ref)?;

    let path = Path::new(source_path);

    // Derive the stored filename: the caller's, else the source's base name.
    let filename = if filename.trim().is_empty() {
        path.file_name()
            .and_then(|f| f.to_str())
            .map(str::to_string)
            .ok_or_else(|| usage("could not derive a filename from the source path"))?
    } else {
        filename.to_string()
    };

    // Reject an oversize file BEFORE reading it fully (cheap metadata check).
    // The vault re-checks the actual byte length before any blob write.
    if let Ok(meta) = std::fs::metadata(path)
        && meta.len() > lp_vault::MAX_ATTACHMENT_BYTES as u64
    {
        return Err(usage(format!(
            "the file is larger than the {} MiB attachment limit",
            lp_vault::MAX_ATTACHMENT_BYTES / (1024 * 1024)
        )));
    }

    // Read the source file inside the daemon (its bytes never cross the pipe).
    let data = std::fs::read(path).map_err(|e| {
        if e.kind() == std::io::ErrorKind::NotFound {
            usage("the source file does not exist")
        } else {
            usage(format!("could not read the source file: {e}"))
        }
    })?;

    let id = v
        .add_attachment(it.item_id, &filename, &data)
        .map_err(vault_err)?;
    Ok(Response::Attachment {
        attachment_id: id.to_hyphenated(),
        filename,
    })
}

/// Handle [`Request::GetAttachment`]: decrypt the attachment and write its
/// plaintext to `dest_path` **from inside the daemon**. The plaintext bytes go
/// daemon↔disk directly — they are NOT in the response (a stronger boundary
/// than a revealed field).
///
/// Refuses to overwrite an existing `dest_path` unless `force` is set. Creates
/// the destination's parent directories; the file is owner-only (0600) on Unix.
fn get_attachment(
    session: &Session,
    vault_ref: &str,
    item_ref: &str,
    attachment_ref: &str,
    dest_path: &str,
    force: bool,
) -> Result<Response, Response> {
    let v = open_vault(session, vault_ref)?;
    let it = find_item(&v, item_ref)?;
    let att_id = resolve_attachment(&v, it.item_id, attachment_ref)?;

    let dest = Path::new(dest_path);
    // Refuse to clobber an existing file unless forced.
    if dest.exists() && !force {
        return Err(usage(
            "the destination file already exists; pass force to overwrite",
        ));
    }

    let (filename, data) = v.get_attachment(att_id).map_err(vault_err)?;
    write_plaintext_0600(dest, &data)
        .map_err(|e| usage(format!("could not write the destination file: {e}")))?;
    let bytes_written = data.len() as u64;
    Ok(Response::AttachmentSaved {
        filename,
        bytes_written,
    })
}

/// Write `data` to `path`, creating parent dirs and the file owner-only (0600)
/// on Unix. On Windows the file inherits the parent directory's ACLs (mirrors
/// the CLI's `attach get` writer). The plaintext lands here because saving a
/// file inherently materializes it — it never crossed the IPC pipe.
fn write_plaintext_0600(path: &Path, data: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
    {
        std::fs::create_dir_all(parent)?;
    }
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut f = opts.open(path)?;
    f.write_all(data)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    }
    Ok(())
}

/// Resolve an attachment reference (its id or its decrypted filename) to an
/// [`lp_vault::AttachmentId`] within `item_id`. Mirrors the CLI's
/// `resolve_attachment`: id match first, then a unique-filename match.
fn resolve_attachment(
    vault: &Vault<'_>,
    item_id: lp_vault::ItemId,
    reference: &str,
) -> Result<lp_vault::AttachmentId, Response> {
    let attachments = vault.list_attachments(item_id).map_err(vault_err)?;

    if let Some(id) = parse_id(reference)
        && attachments.iter().any(|a| a.attachment_id == id)
    {
        return Ok(id);
    }

    let matches: Vec<lp_vault::AttachmentId> = attachments
        .iter()
        .filter(|a| a.filename == reference)
        .map(|a| a.attachment_id)
        .collect();
    match matches.as_slice() {
        [] => Err(usage(format!(
            "no attachment named or id {reference:?} on this item"
        ))),
        [only] => Ok(*only),
        _ => Err(usage(format!(
            "attachment name {reference:?} is ambiguous ({} match); use the attachment id",
            matches.len()
        ))),
    }
}

/// Parse a canonical item payload `Value` into an [`lp_vault::ItemPayload`].
fn parse_payload(value: serde_json::Value) -> Result<lp_vault::ItemPayload, Response> {
    // Serialize to canonical bytes then parse through lp-vault's own path so the
    // exact schema/validation applies (rejecting floats, bad shapes, etc.).
    let bytes = serde_json::to_vec(&value).map_err(|e| usage(format!("bad payload: {e}")))?;
    lp_vault::ItemPayload::from_canonical(&bytes)
        .map_err(|e| usage(format!("invalid item payload: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_id_accepts_hyphenated_and_rejects_names() {
        let id = lp_vault::Id::new();
        let s = id.to_hyphenated();
        assert_eq!(parse_id(&s), Some(id));
        assert!(parse_id("personal").is_none());
        assert!(parse_id("not-a-uuid").is_none());
    }

    #[test]
    fn locked_state_reports_no_remaining() {
        let st = State::new(PathBuf::from("/tmp/x"), Duration::from_secs(600));
        assert!(!st.is_unlocked());
        assert_eq!(st.idle_remaining_secs(), None);
    }

    #[test]
    fn status_is_passive_but_active_requests_reset_the_idle_timer() {
        use std::thread::sleep;
        let dir = tempfile::tempdir().expect("tempdir");
        let autolock = Duration::from_secs(600);
        let mut st = State::new(dir.path().to_path_buf(), autolock);
        // CreateAccount unlocks the session (one real Argon2 derivation).
        let created = handle(
            &mut st,
            Request::CreateAccount {
                profile: dir.path().display().to_string(),
                password: "test-password-123".into(),
            },
        );
        assert!(
            !matches!(created.response, Response::Error { .. }),
            "create failed: {:?}",
            created.response
        );
        assert!(st.is_unlocked());

        // Let some idle time accrue, then observe via Status: the remaining
        // time must have DECREASED (the poll did not reset the timer).
        sleep(Duration::from_millis(1100));
        let _ = handle(
            &mut st,
            Request::Status {
                profile: dir.path().display().to_string(),
                keepalive: false,
            },
        );
        let after_status = st.idle_remaining_secs().expect("unlocked");
        assert!(
            after_status < autolock.as_secs(),
            "a passive Status must not reset the idle timer (remaining: {after_status})"
        );

        // A KEEP-ALIVE Status — the route probe a tool sends before doing real
        // work — DOES reset it, even though it is the same request kind.
        let _ = handle(
            &mut st,
            Request::Status {
                profile: dir.path().display().to_string(),
                keepalive: true,
            },
        );
        let after_keepalive = st.idle_remaining_secs().expect("unlocked");
        assert!(
            after_keepalive >= autolock.as_secs() - 1,
            "a keepalive Status must reset the idle timer (remaining: {after_keepalive})"
        );
        assert!(after_keepalive > after_status);

        // An ordinary active request resets it back to the full window too.
        sleep(Duration::from_millis(1100));
        let _ = handle(
            &mut st,
            Request::ListVaults {
                profile: dir.path().display().to_string(),
            },
        );
        // `idle_remaining_secs` truncates the sub-second sliver that elapsed
        // since the reset, so "full window" reads as `autolock` or one below.
        let after_active = st.idle_remaining_secs().expect("unlocked");
        assert!(
            after_active >= autolock.as_secs() - 1,
            "ListVaults must reset the idle timer (remaining: {after_active})"
        );

        assert!(!counts_as_activity(&Request::Status {
            profile: String::new(),
            keepalive: false,
        }));
        assert!(counts_as_activity(&Request::Status {
            profile: String::new(),
            keepalive: true,
        }));
        assert!(counts_as_activity(&Request::ListVaults {
            profile: String::new()
        }));
    }

    /// A refused request must NOT reset the idle timer, so a probing process
    /// cannot hold the vault open by failing over and over — while an ordinary
    /// usage error from an authenticated caller still counts.
    #[test]
    fn refused_requests_do_not_reset_the_idle_timer() {
        use std::thread::sleep;
        let dir = tempfile::tempdir().expect("tempdir");
        let profile = dir.path().display().to_string();
        let autolock = Duration::from_secs(600);
        let mut st = State::new(dir.path().to_path_buf(), autolock);
        let created = handle(
            &mut st,
            Request::CreateAccount {
                profile: profile.clone(),
                password: "test-password-123".into(),
            },
        );
        assert!(!matches!(created.response, Response::Error { .. }));

        // Baseline: let the timer drop, then check each refusal leaves it there.
        for request in [
            // Wrong profile → refused before it is even handled.
            Request::ListVaults {
                profile: "/definitely/not/this/profile".into(),
            },
            // Authentication failure → refused by the unlock itself.
            Request::Unlock {
                profile: profile.clone(),
                password: "wrong-password".into(),
                secret_key: None,
                autolock_secs: None,
            },
        ] {
            sleep(Duration::from_millis(1100));
            let before = st.idle_remaining_secs().expect("unlocked");
            let handled = handle(&mut st, request);
            assert!(
                matches!(
                    handled.response,
                    Response::WrongProfile { .. } | Response::Error { auth: true, .. }
                ),
                "expected a refusal, got {:?}",
                handled.response
            );
            let after = st.idle_remaining_secs().expect("unlocked");
            assert!(
                after <= before,
                "a refused request must not reset the idle timer ({before} -> {after})"
            );
        }

        // A LOCKED refusal likewise leaves the timer alone.
        st.lock();
        let handled = handle(
            &mut st,
            Request::ListVaults {
                profile: profile.clone(),
            },
        );
        assert!(matches!(handled.response, Response::Locked));

        // Response-level rules, stated directly.
        assert!(!response_counts_as_activity(&Response::Locked));
        assert!(!response_counts_as_activity(&Response::WrongProfile {
            expected: String::new()
        }));
        assert!(!response_counts_as_activity(&Response::Error {
            auth: true,
            message: String::new()
        }));
        // An ordinary usage error from an authenticated caller DOES count.
        assert!(response_counts_as_activity(&Response::Error {
            auth: false,
            message: "no vault named \"nope\"".into()
        }));
        assert!(response_counts_as_activity(&Response::Ok { message: None }));
    }

    /// Every refusal above leaves an `access_denied` audit record, written
    /// **without keys** even while the daemon is locked.
    #[test]
    fn refusals_are_audited_even_when_locked() {
        let dir = tempfile::tempdir().expect("tempdir");
        let profile = dir.path().display().to_string();
        let mut st = State::new(dir.path().to_path_buf(), Duration::from_secs(600));
        let created = handle(
            &mut st,
            Request::CreateAccount {
                profile: profile.clone(),
                password: "test-password-123".into(),
            },
        );
        assert!(!matches!(created.response, Response::Error { .. }));
        st.lock(); // locked: no session, no keys

        let handled = handle(
            &mut st,
            Request::ListVaults {
                profile: profile.clone(),
            },
        );
        assert!(matches!(handled.response, Response::Locked));
        let handled = handle(
            &mut st,
            Request::ListVaults {
                profile: "/some/other/profile".into(),
            },
        );
        assert!(matches!(handled.response, Response::WrongProfile { .. }));

        // A passive Status against a locked daemon is NOT audited — a polling
        // GUI must not bury the real refusals in noise.
        let _ = handle(
            &mut st,
            Request::Status {
                profile: profile.clone(),
                keepalive: false,
            },
        );

        // A failed unlock is NOT double-counted: it already writes the more
        // specific UnlockFailure, so no generic AccessDenied joins it.
        let handled = handle(
            &mut st,
            Request::Unlock {
                profile: profile.clone(),
                password: "definitely-wrong".into(),
                secret_key: None,
                autolock_secs: None,
            },
        );
        assert!(matches!(
            handled.response,
            Response::Error { auth: true, .. }
        ));

        let conn = rusqlite::Connection::open(dir.path().join("account.localpass")).expect("open");
        let count = |kind: i64| -> i64 {
            conn.query_row(
                "SELECT COUNT(*) FROM audit_log WHERE kind = ?1",
                [kind],
                |r| r.get(0),
            )
            .expect("count")
        };
        // Kind code 13 = AccessDenied; exactly the two real refusals.
        assert_eq!(count(13), 2, "one Locked + one WrongProfile refusal");
        // Kind code 2 = UnlockFailure; the failed unlock, recorded once.
        assert_eq!(count(2), 1, "the failed unlock is recorded exactly once");
    }

    #[test]
    fn autolock_zero_never_expires() {
        let mut st = State::new(PathBuf::from("/tmp/x"), Duration::ZERO);
        // No session, so maybe_autolock is a no-op and returns false.
        assert!(!st.maybe_autolock());
        assert_eq!(st.idle_remaining_secs(), None);
    }

    fn login_with_url(url: &str) -> lp_vault::ItemPayload {
        use lp_vault::payload::{Field, FieldKind, TypeData};
        use serde_json::json;
        let mut p = lp_vault::ItemPayload::new(TypeData::Login { urls: vec![] }, "Site");
        p.fields = vec![
            Field {
                name: "username".into(),
                kind: FieldKind::Text,
                value: json!("alice"),
            },
            Field {
                name: "password".into(),
                kind: FieldKind::Hidden,
                value: json!("s3cr3t"),
            },
            Field {
                name: "url".into(),
                kind: FieldKind::Url,
                value: json!(url),
            },
        ];
        p
    }

    #[test]
    fn login_urls_collects_primary_and_extra() {
        use lp_vault::payload::TypeData;
        let mut p = login_with_url("https://example.com/login");
        if let TypeData::Login { urls } = &mut p.type_data {
            urls.push("https://alt.example.com".into());
            urls.push("   ".into()); // blank dropped
        }
        let urls = login_urls(&p);
        assert!(urls.contains(&"https://example.com/login".to_string()));
        assert!(urls.contains(&"https://alt.example.com".to_string()));
        assert_eq!(urls.len(), 2);
    }

    #[test]
    fn login_urls_empty_for_non_login() {
        let p = lp_vault::ItemPayload::new(lp_vault::TypeData::Note {}, "n");
        assert!(login_urls(&p).is_empty());
    }

    #[test]
    fn username_and_password_extracted() {
        let p = login_with_url("https://example.com");
        assert_eq!(login_username(&p), "alice");
        assert_eq!(login_password(&p), "s3cr3t");
    }

    #[test]
    fn payload_matches_by_registrable_domain() {
        let p = login_with_url("https://example.com/login");
        assert!(payload_matches_origin(&p, "https://www.example.com/"));
        assert!(payload_matches_origin(&p, "https://login.example.com/"));
        // Phishing lookalike never matches (T7).
        assert!(!payload_matches_origin(&p, "https://evil-example.com/"));
        assert!(!payload_matches_origin(&p, "https://example.com.evil.com/"));
    }

    #[test]
    fn blank_url_login_matches_nothing() {
        let p = login_with_url("");
        assert!(!payload_matches_origin(&p, "https://example.com/"));
    }
}
