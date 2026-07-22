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

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use lp_crypto::SecretKey;
use lp_sync::store::{FsStoreFactory, StoreFactory};
use lp_vault::{AccountStore, Item, Session, Vault, VaultId};

use crate::protocol::{LockState, Request, Response, WireItem};
use crate::render;

/// How long **pairing mode** stays open once enabled (`device-pairing.md` §4):
/// a deliberate, time-boxed **3 minutes**. Trusting a new device is only
/// accepted inside this window; it lapses on its own so an accidentally-left-on
/// toggle cannot linger. Off by default, and turning it off never affects an
/// already-pinned peer (§4 "Does not gate").
const PAIRING_WINDOW: Duration = Duration::from_secs(180);

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
    pub fn lock(&mut self) {
        // Taking the Option and dropping it runs Session::Drop, which zeroizes.
        if let Some(session) = self.session.take() {
            session.lock();
        }
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

    /// Reset the idle timer (called after every successful request).
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
    // this single-profile daemon). Enforce the single-profile rule.
    if let Some(profile) = request_profile(&request)
        && !same_profile(state, profile)
    {
        return Handled::reply(Response::WrongProfile {
            expected: state.profile().display().to_string(),
        });
    }

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
    };

    // Any successfully-handled request (even one returning a usage Error) counts
    // as activity and resets the idle timer — the user is clearly present.
    state.touch();
    handled
}

/// The profile string carried by a request, if any.
fn request_profile(request: &Request) -> Option<&str> {
    match request {
        Request::Status { profile }
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
        | Request::MatchLogins { profile, .. }
        | Request::FillLogin { profile, .. }
        | Request::ExportIdentity { profile }
        | Request::ListPeers { profile }
        | Request::TrustDevice { profile, .. }
        | Request::SetPairingMode { profile, .. }
        | Request::SyncSetup { profile, .. }
        | Request::SyncPush { profile, .. }
        | Request::SyncPull { profile, .. }
        | Request::SyncStatus { profile, .. }
        | Request::ShareVaultToDevice { profile, .. }
        | Request::SyncAdopt { profile, .. }
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
