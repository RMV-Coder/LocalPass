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
use std::time::{Duration, Instant};

use lp_crypto::SecretKey;
use lp_vault::{AccountStore, Item, Session, Vault, VaultId};

use crate::protocol::{LockState, Request, Response, WireItem};
use crate::render;

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
}

impl State {
    /// A fresh, locked state for `profile` with `autolock` idle timeout and no
    /// SSH agent endpoint recorded (set later via
    /// [`set_ssh_agent_endpoint`](Self::set_ssh_agent_endpoint) once the agent
    /// listener has bound).
    #[must_use]
    pub fn new(profile: PathBuf, autolock: Duration) -> Self {
        Self {
            profile,
            session: None,
            autolock,
            last_activity: Instant::now(),
            ssh_agent_endpoint: None,
        }
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
    let vaults = session.list_vaults().map_err(vault_err)?;

    if let Some(id) = parse_id(reference)
        && vaults.iter().any(|(vid, _)| *vid == id)
    {
        return session.open_vault(id).map_err(vault_err);
    }

    let matches: Vec<VaultId> = vaults
        .iter()
        .filter(|(_, name)| name == reference)
        .map(|(vid, _)| *vid)
        .collect();
    match matches.as_slice() {
        [] => Err(usage(format!("no vault named or id {reference:?}"))),
        [only] => session.open_vault(*only).map_err(vault_err),
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
            })
        }

        Request::Unlock {
            password,
            secret_key,
            autolock_secs,
            ..
        } => handle_unlock(state, &password, secret_key.as_deref(), autolock_secs),

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

        Request::ListItems { vault, .. } => with_session(state, |session| {
            let v = open_vault(session, &vault)?;
            let items = v.list_items().map_err(vault_err)?;
            Ok(Response::Items {
                items: items.iter().map(render::item_to_summary).collect(),
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
                Ok(Some(t)) => Ok(Response::Totp {
                    code: t.code,
                    seconds_remaining: t.seconds_remaining,
                    period: t.period,
                    digits: t.digits,
                    algo: t.algo,
                }),
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
                Some(value) => Ok(Response::Field { value }),
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
        | Request::ListVaults { profile }
        | Request::ListItems { profile, .. }
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
        | Request::FillLogin { profile, .. } => Some(profile),
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
    // Locate the item across vaults (by id first, else by unique title).
    let mut found: Option<lp_vault::Item> = None;
    for (vault_id, _name) in &vaults {
        let v = session.open_vault(*vault_id).map_err(vault_err)?;
        // Try by id (`parse_id` yields an `lp_vault::Id`, which is `ItemId`).
        if let Some(id) = parse_id(item_ref) {
            match v.get_item(id) {
                Ok(item) => {
                    found = Some(item);
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
                found = Some(v.get_item(it.item_id).map_err(vault_err)?);
                break;
            }
        }
    }
    let item = found.ok_or_else(|| usage(format!("no login item matching {item_ref:?}")))?;

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

    Ok(Response::Fill {
        username: login_username(&item.payload),
        password: login_password(&item.payload),
    })
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
