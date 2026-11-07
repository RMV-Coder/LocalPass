//! Vault access for the MCP server, over the CLI's existing two routes.
//!
//! The server picks a route at startup through [`crate::daemonctl::route`] —
//! exactly the routing matrix every other subcommand uses, and the same one
//! `localpass run` uses:
//!
//! - daemon running and unlocked for this profile → [`Backend::Proxy`], every
//!   read goes over the same-user-only IPC channel and the keys stay in the
//!   daemon;
//! - otherwise, with a password to hand (`LOCALPASS_PASSWORD`,
//!   `--password-stdin`, a terminal) or under `--no-daemon` →
//!   [`Backend::Direct`], the server unlocks itself and holds the
//!   `lp_vault::Session` in this process;
//! - otherwise → [`Backend::Detached`]. An agent host starts this server with
//!   none of those, usually while the vault is locked, and exiting there is what
//!   used to make the host report it as failed for good.
//!
//! Either way the *outputs* of this module are identical, so the tool layer
//! above never branches on the route.
//!
//! # Reconnecting
//!
//! [`Backend::prepare`] runs before every tool call and is what keeps a
//! long-lived server useful without a restart: it re-attaches to a daemon that
//! appeared or restarted, and turns "not running" and "locked" into a message an
//! agent can act on. It re-registers the agent session on every new connection,
//! so a reconnect never skips the presence check (`mcp-server.md` §7).
//!
//! # Idle auto-lock on the Direct route
//!
//! An MCP server is long-lived — an agent host starts it once and leaves it
//! running for hours. On the **Proxy** route that is safe: the keys live in the
//! daemon, which auto-locks on its own idle timer, and each tool call is a
//! request that resets it (so an *active* agent keeps the vault awake and an
//! idle one does not).
//!
//! On the **Direct** route there was no such timer at all: the process held an
//! unlocked `Session` from startup until stdin EOF, which meant a forgotten MCP
//! server kept the vault unlocked indefinitely — strictly weaker than every
//! other surface. [`DirectSession`] closes that: it mirrors the daemon's idle
//! timeout ([`lp_daemon::DEFAULT_AUTOLOCK_SECS`], overridable with the same
//! [`lp_daemon::AUTOLOCK_ENV`] variable), each vault-touching call resets it,
//! and once it lapses the session is dropped (zeroizing key material) and every
//! later call fails cleanly.
//!
//! It **never re-unlocks** on purpose: that would require keeping the master
//! password in memory for the process's lifetime, which is the very exposure the
//! timeout exists to end. A lapsed server moves to [`Backend::Detached`] and uses
//! the daemon from then on. Under `--no-daemon` there is no daemon to move to, so
//! every later call fails until the host restarts the server.
//!
//! # Secret exposure
//!
//! Only two methods here return plaintext: [`Backend::resolve_reference`] and
//! [`Backend::env_set_entries`]. Both feed `run_with_secrets`'s child
//! environment and nothing else — their values are never rendered into a tool
//! result. Item reads go out through [`super::mask`]; on the proxy route they
//! are additionally requested with `reveal = false`, so the daemon has already
//! masked them before they cross the pipe (defense in depth).

use std::path::Path;
use std::time::{Duration, Instant};

use anyhow::{Result, anyhow, bail};
use lp_daemon::client::Client;
use lp_daemon::protocol::{
    FillRefusal, FillReport, FillStatus, LockState, Request, Response, WireItem,
};
use lp_vault::Session;

use crate::commands::{run as run_cmd, totp as totp_cmd};
use crate::daemonctl::{self, Route};
use crate::error::CliError;
use crate::mcp::mask::{FieldView, ItemView};
use crate::profile;
use crate::reference;
use crate::resolve;
use crate::unlock::{self, PasswordSource};

/// A vault name/id pair for `list_vaults`.
pub struct VaultEntry {
    /// Hyphenated vault id.
    pub id: String,
    /// The vault name.
    pub name: String,
}

/// The acquired session, in whichever form the routing matrix produced.
pub enum Backend {
    /// Proxy every read through a running, unlocked daemon.
    Proxy {
        /// The connected client (held open for the server's lifetime).
        client: Box<Client>,
        /// The profile string every request carries.
        profile: String,
    },
    /// Hold an unlocked session in this process, under its own idle timeout.
    Direct(DirectSession),
    /// Attached to nothing: no daemon was reachable and there was no password
    /// to unlock with, or the connection or session was lost. [`Backend::prepare`]
    /// moves on from here as soon as a daemon answers.
    Detached {
        /// The profile string a later connection will use.
        profile: String,
    },
}

/// What a tool call reports while the vault is locked.
const LOCKED_MESSAGE: &str = "The LocalPass vault is locked. Ask the user to open LocalPass and \
     unlock it, then call this tool again. This server does not need to be restarted.";

/// What a tool call reports while no daemon is reachable.
const NOT_RUNNING_MESSAGE: &str = "The LocalPass service is not running. Ask the user to open \
     LocalPass and unlock it, then call this tool again. This server does not need to be \
     restarted.";

/// An in-process unlocked session with an idle auto-lock, for the Direct route.
///
/// The session is `Some` while unlocked and `None` once the idle window has
/// lapsed. Dropping it runs `Session`'s zeroizing teardown, so the key material
/// is gone the moment the timeout fires — not merely flagged as expired.
pub struct DirectSession {
    /// The unlocked session, or `None` once auto-locked.
    session: Option<Box<Session>>,
    /// The idle window. `Duration::ZERO` means "never auto-lock".
    autolock: Duration,
    /// When the last vault-touching call happened.
    last_activity: Instant,
    /// The profile string, for moving to the daemon once this lapses.
    profile: String,
    /// `--no-daemon`: never move to the daemon.
    no_daemon: bool,
}

impl DirectSession {
    /// Wrap `session` with the configured idle window.
    fn new(session: Session, profile: String, no_daemon: bool) -> Self {
        Self {
            session: Some(Box::new(session)),
            autolock: configured_autolock(),
            last_activity: Instant::now(),
            profile,
            no_daemon,
        }
    }

    /// Drop the session if the idle window has lapsed. Returns whether it is gone.
    fn lapse_if_idle(&mut self) -> bool {
        if self.session.is_some()
            && !self.autolock.is_zero()
            && self.last_activity.elapsed() >= self.autolock
        {
            // Dropping the session zeroizes its key material.
            if let Some(s) = self.session.take() {
                s.lock();
            }
        }
        self.session.is_none()
    }

    /// Borrow the session for one vault-touching call, enforcing the idle
    /// window first and resetting it on success.
    ///
    /// # Errors
    ///
    /// [`CliError::Usage`] once the window has lapsed — a clean, secret-free
    /// failure the agent sees as a tool error. It never re-unlocks: that would
    /// require holding the master password for the process's lifetime.
    fn session(&mut self) -> Result<&Session> {
        self.lapse_if_idle();
        let secs = self.autolock.as_secs();
        let session = self.session.as_deref().ok_or_else(|| {
            CliError::usage(format!(
                "the LocalPass session auto-locked after {secs}s idle; \
                 restart the MCP server to unlock again"
            ))
        })?;
        self.last_activity = Instant::now();
        Ok(session)
    }
}

/// The Direct-route idle window: [`lp_daemon::AUTOLOCK_ENV`] if it parses, else
/// [`lp_daemon::DEFAULT_AUTOLOCK_SECS`]. `0` disables auto-lock, exactly as it
/// does for the daemon — the two surfaces read the same knob so a user who sets
/// a policy once gets it everywhere.
fn configured_autolock() -> Duration {
    let secs = std::env::var(lp_daemon::AUTOLOCK_ENV)
        .ok()
        .and_then(|v| v.trim().parse::<u64>().ok())
        .unwrap_or(lp_daemon::DEFAULT_AUTOLOCK_SECS);
    Duration::from_secs(secs)
}

impl Backend {
    /// Pick the startup route for `profile_dir`, mirroring `localpass run`,
    /// except that a locked or absent daemon with no password to hand is not a
    /// failure: the server starts [`Backend::Detached`] and waits.
    ///
    /// # Errors
    ///
    /// [`CliError::Auth`] on a wrong master password / Secret Key, or
    /// [`CliError::Usage`] when there is no account at `profile_dir`.
    pub fn acquire(profile_dir: &Path, src: PasswordSource, no_daemon: bool) -> Result<Self> {
        let profile = profile_dir.display().to_string();
        match daemonctl::route(profile_dir, no_daemon) {
            Route::Proxy(mut client) => {
                // Mark this connection as the agent's, so the daemon asks a
                // person before any consent or change (mcp-server.md §7). A
                // daemon that cannot is refused rather than silently served:
                // the connection is dropped and every tool call says why.
                match super::presence::register(&mut client, &profile) {
                    Ok(()) => Ok(Backend::Proxy { client, profile }),
                    Err(e) => {
                        super::log(&format!("agent-session registration failed: {e:#}"));
                        Ok(Backend::Detached { profile })
                    }
                }
            }
            Route::Direct if !no_daemon && !unlock::password_available(src) => {
                if !profile::account_exists(profile_dir) {
                    bail!(CliError::usage(format!(
                        "no account at {} — run `localpass init` first",
                        profile_dir.display()
                    )));
                }
                Ok(Backend::Detached { profile })
            }
            Route::Direct => {
                let (session, _sk) = unlock::unlock(profile_dir, src)?;
                Ok(Backend::Direct(DirectSession::new(
                    session, profile, no_daemon,
                )))
            }
        }
    }

    /// Get ready for one tool call: move off a lapsed direct session, re-attach
    /// to the daemon if the connection is gone, and report a locked vault.
    ///
    /// Everything here is passive for the idle timer, so a server that keeps
    /// checking never holds the vault open. Only the tool's own request counts.
    ///
    /// # Errors
    ///
    /// [`CliError::Usage`] with a message the agent can act on when the service
    /// is not running, the vault is locked, or the daemon refused this agent.
    pub fn prepare(&mut self) -> Result<()> {
        if let Backend::Direct(direct) = self {
            if !direct.lapse_if_idle() || direct.no_daemon {
                return Ok(());
            }
            super::log("direct session auto-locked; using the daemon from now on");
            let profile = direct.profile.clone();
            *self = Backend::Detached { profile };
        }
        let (profile, answer) = match self {
            Backend::Proxy { client, profile } => {
                let answer = client.call(&status_request(profile)).ok();
                (profile.clone(), answer)
            }
            Backend::Detached { profile } => (profile.clone(), None),
            Backend::Direct(_) => return Ok(()),
        };
        let answer = match answer {
            Some(answer) => answer,
            None => {
                *self = Backend::Detached {
                    profile: profile.clone(),
                };
                let mut client = Client::connect()
                    .map_err(|_| CliError::usage(NOT_RUNNING_MESSAGE.to_string()))?;
                super::presence::register(&mut client, &profile)?;
                let answer = client
                    .call(&status_request(&profile))
                    .map_err(|_| CliError::usage(NOT_RUNNING_MESSAGE.to_string()))?;
                super::log("connected to the LocalPass service");
                *self = Backend::Proxy {
                    client: Box::new(client),
                    profile,
                };
                answer
            }
        };
        match answer {
            Response::Status {
                state: LockState::Locked,
                ..
            } => Err(CliError::usage(LOCKED_MESSAGE.to_string()).into()),
            Response::Status { .. } => Ok(()),
            other => {
                daemonctl::check_error(&other)?;
                bail!(unexpected(&other));
            }
        }
    }

    /// Record one finished tool call, for the activity the desktop app shows.
    /// Best-effort: a report that cannot be delivered changes nothing.
    pub fn note_tool_call(&mut self, tool: &str, ok: bool) {
        match self {
            Backend::Proxy { client, profile } => {
                let _ = client.call(&Request::AgentToolCall {
                    profile: profile.clone(),
                    tool: tool.to_string(),
                    ok,
                });
            }
            Backend::Direct(direct) => {
                if let Some(session) = direct.session.as_deref() {
                    let detail = if ok {
                        tool.to_string()
                    } else {
                        format!("{tool}:failed")
                    };
                    session
                        .record_audit(lp_vault::AuditKind::AgentToolCall, Some(&detail))
                        .ok();
                }
            }
            Backend::Detached { .. } => {}
        }
    }

    /// A short, non-secret label for the startup log line.
    #[must_use]
    pub fn route_label(&self) -> &'static str {
        match self {
            Backend::Proxy { .. } => "daemon",
            Backend::Direct(_) => "direct",
            Backend::Detached { .. } => "waiting",
        }
    }

    /// Every vault as `(id, name)`. Carries no secret.
    ///
    /// # Errors
    ///
    /// Propagates transport / storage failures.
    pub fn list_vaults(&mut self) -> Result<Vec<VaultEntry>> {
        match self {
            Backend::Proxy { client, profile } => {
                let resp = daemonctl::call(
                    client,
                    &Request::ListVaults {
                        profile: profile.clone(),
                    },
                )?;
                daemonctl::check_error(&resp)?;
                let Response::Vaults { vaults } = resp else {
                    bail!(unexpected(&resp));
                };
                Ok(vaults
                    .into_iter()
                    .map(|(id, name)| VaultEntry { id, name })
                    .collect())
            }
            Backend::Direct(direct) => Ok(direct
                .session()?
                .list_vaults()
                .map_err(crate::error::map_vault_error)?
                .into_iter()
                .map(|(id, name)| VaultEntry {
                    id: id.to_hyphenated(),
                    name,
                })
                .collect()),
            Backend::Detached { .. } => Err(detached()),
        }
    }

    /// Every live item in `vault`, as raw views.
    ///
    /// The caller must pass each one through [`super::mask::item_view_masked`]
    /// before it can be serialized — that is enforced by `ItemView` not being
    /// `Serialize`.
    ///
    /// # Errors
    ///
    /// [`CliError::Usage`] for an unknown vault; transport/storage failures
    /// otherwise.
    pub fn list_items(&mut self, vault: &str) -> Result<Vec<ItemView>> {
        match self {
            Backend::Proxy { client, profile } => {
                let resp = daemonctl::call(
                    client,
                    &Request::ListItems {
                        profile: profile.clone(),
                        vault: vault.to_string(),
                    },
                )?;
                daemonctl::check_error(&resp)?;
                let Response::Items { items } = resp else {
                    bail!(unexpected(&resp));
                };
                // The summary shape carries no fields, so fetch each item
                // masked (`reveal = false`) to learn its field NAMES. Vaults are
                // human-scale, so N small IPC round trips is fine.
                let mut out = Vec::with_capacity(items.len());
                for s in items {
                    out.push(get_item_proxied(client, profile, vault, &s.id)?);
                }
                Ok(out)
            }
            Backend::Direct(direct) => {
                let session = direct.session()?;
                let vault = resolve::open_vault(session, vault)?;
                let items = vault.list_items().map_err(crate::error::map_vault_error)?;
                Ok(items.iter().map(view_from_item).collect())
            }
            Backend::Detached { .. } => Err(detached()),
        }
    }

    /// One item by title or id, as a raw view (mask before serializing).
    ///
    /// # Errors
    ///
    /// [`CliError::Usage`] for an unknown vault/item.
    pub fn get_item(&mut self, vault: &str, item: &str) -> Result<ItemView> {
        match self {
            Backend::Proxy { client, profile } => get_item_proxied(client, profile, vault, item),
            Backend::Direct(direct) => {
                let session = direct.session()?;
                let vault = resolve::open_vault(session, vault)?;
                let item = resolve::find_item(&vault, item)?;
                Ok(view_from_item(&item))
            }
            Backend::Detached { .. } => Err(detached()),
        }
    }

    /// Resolve a `localpass://` / `op://` reference to its **plaintext** value.
    ///
    /// Only `run_with_secrets` calls this, and only to build a child
    /// environment. `key` names the variable being resolved so a failure can say
    /// which one broke without echoing a value.
    ///
    /// # Errors
    ///
    /// [`CliError::Usage`] when the reference is malformed or unresolvable.
    pub fn resolve_reference(&mut self, key: &str, reference: &str) -> Result<String> {
        match self {
            Backend::Proxy { client, profile } => {
                run_cmd::resolve_reference_proxied(profile, client, key, reference)
            }
            Backend::Direct(direct) => {
                let session = direct.session()?;
                reference::resolve_str(session, reference).map_err(|e| {
                    CliError::usage(format!("could not resolve {key}={reference}: {e:#}")).into()
                })
            }
            Backend::Detached { .. } => Err(detached()),
        }
    }

    /// Every `(key, value)` of an env-set item, in **plaintext**.
    ///
    /// Same exposure and same single consumer as [`Self::resolve_reference`].
    ///
    /// # Errors
    ///
    /// [`CliError::Usage`] when the target is missing or is not an env-set.
    pub fn env_set_entries(&mut self, vault: &str, item: &str) -> Result<Vec<(String, String)>> {
        match self {
            Backend::Proxy { client, profile } => {
                run_cmd::load_env_set_proxied(profile, client, vault, item)
            }
            Backend::Direct(direct) => run_cmd::load_env_set(direct.session()?, vault, item),
            Backend::Detached { .. } => Err(detached()),
        }
    }

    /// Arm an agent fill and **wait for the extension to report back**
    /// (`agent-fill.md` §3/§5.1).
    ///
    /// Returns `Ok(Ok(finished))` when the extension reported an outcome, and
    /// `Ok(Err(reason))` for any §10 refusal — including the two this layer
    /// decides itself:
    ///
    /// - `extension_unavailable` on the **Direct** route. Agent fill is a
    ///   daemon-mediated exchange with a browser: the extension pulls the intent
    ///   through the native host, which is a daemon client. With no daemon there
    ///   is nobody to pull it, so the honest answer is that no extension is
    ///   reachable — not a hang and not a bare error.
    /// - `intent_expired` when the intent's TTL lapses with nothing reported.
    ///
    /// # The wait, and why it is a client-side poll
    ///
    /// The daemon serializes **every** request behind one state mutex
    /// (`lp_daemon::engine`), so a wait that happened inside the daemon would
    /// hold that mutex for seconds and freeze everything behind it — including
    /// the idle auto-lock, which is a security control, not a convenience. So
    /// the wait lives here: separate `PollFillOutcome` requests every
    /// [`FILL_POLL_INTERVAL`], with the mutex released between them and the
    /// daemon answering everyone else normally the whole time. Each poll is
    /// deliberately activity-neutral daemon-side, so waiting does not postpone
    /// the auto-lock either.
    ///
    /// # The one re-arm
    ///
    /// The extension only polls for intents while the arm window is open, and it
    /// learns the window opened on a heartbeat that can lag the intent's 30s
    /// TTL. So an intent armed moments after the user arms the window can lapse
    /// before the extension ever looks. This re-arms **once** in exactly that
    /// case — the intent lapsed and was *never taken* — by which point the
    /// extension is polling. It never re-arms after a take: the extension may
    /// already have filled, and a second intent could fill twice.
    ///
    /// # Errors
    ///
    /// Transport failures only; every *refusal* comes back as `Ok(Err(reason))`.
    pub fn fill_login(
        &mut self,
        vault: Option<&str>,
        item: &str,
        tab_id: Option<u64>,
        origin: &str,
        overwrite: bool,
    ) -> Result<std::result::Result<FinishedFill, FillRefusal>> {
        let (client, profile) = match self {
            Backend::Proxy { client, profile } => (client, profile.clone()),
            Backend::Direct(_) | Backend::Detached { .. } => {
                return Ok(Err(FillRefusal::ExtensionUnavailable));
            }
        };
        // At most two attempts; see "The one re-arm" above.
        for attempt in 0..2u8 {
            let resp = daemonctl::call(
                client,
                &Request::ArmFillIntent {
                    profile: profile.clone(),
                    item_id: item.to_string(),
                    tab_id,
                    origin: origin.to_string(),
                    overwrite,
                    vault: vault.map(ToString::to_string),
                },
            )?;
            let ttl = match resp {
                Response::FillIntentArmed {
                    expires_in_secs, ..
                } => Duration::from_secs(expires_in_secs),
                Response::FillRefused { reason } => return Ok(Err(reason)),
                Response::Locked => return Ok(Err(FillRefusal::Locked)),
                other => {
                    daemonctl::check_error(&other)?;
                    bail!(unexpected(&other));
                }
            };

            let deadline = Instant::now() + ttl + FILL_POLL_GRACE;
            // Whether the extension ever picked this intent up. A lapse *after* a
            // take may mean the fill happened and the report was lost, so it must
            // never be retried.
            let mut saw_taken = false;
            loop {
                let resp = daemonctl::call(
                    client,
                    &Request::PollFillOutcome {
                        profile: profile.clone(),
                    },
                )?;
                match resp {
                    Response::FillOutcome {
                        status: FillStatus::Reported,
                        item_id,
                        tab_id,
                        origin,
                        report: Some(report),
                    } => {
                        return Ok(Ok(FinishedFill {
                            item_id: item_id.unwrap_or_default(),
                            tab_id,
                            origin: origin.unwrap_or_default(),
                            report,
                        }));
                    }
                    // The window was disarmed or the intent replaced underneath us:
                    // there is nothing left to wait for.
                    Response::FillOutcome {
                        status: FillStatus::None | FillStatus::Expired,
                        ..
                    } => {
                        if !saw_taken && attempt == 0 {
                            break; // re-arm once; the extension was not yet polling
                        }
                        return Ok(Err(FillRefusal::IntentExpired));
                    }
                    Response::FillOutcome {
                        status: FillStatus::Taken,
                        ..
                    } => saw_taken = true,
                    Response::FillOutcome { .. } => {}
                    Response::Locked => return Ok(Err(FillRefusal::Locked)),
                    other => {
                        daemonctl::check_error(&other)?;
                        bail!(unexpected(&other));
                    }
                }
                if Instant::now() >= deadline {
                    if !saw_taken && attempt == 0 {
                        break; // re-arm once, as above
                    }
                    return Ok(Err(FillRefusal::IntentExpired));
                }
                std::thread::sleep(FILL_POLL_INTERVAL);
            }
        }
        Ok(Err(FillRefusal::IntentExpired))
    }

    /// The current TOTP code for a `totp` item.
    ///
    /// A code is a short-lived value derived from the seed, not the seed: it is
    /// the one secret-adjacent thing an MCP tool result may carry, and the seed
    /// itself never leaves the vault (on the proxy route it never even leaves
    /// the daemon).
    ///
    /// # Errors
    ///
    /// [`CliError::Usage`] when the item is missing or is not a `totp` item.
    pub fn totp(&mut self, vault: &str, item: &str) -> Result<totp_cmd::Computed> {
        match self {
            Backend::Proxy { client, profile } => {
                totp_cmd::compute_proxied(profile, client, vault, item)
            }
            Backend::Direct(direct) => totp_cmd::compute_direct(direct.session()?, vault, item),
            Backend::Detached { .. } => Err(detached()),
        }
    }
}

/// A passive status probe: observing the lock state never resets the idle timer.
fn status_request(profile: &str) -> Request {
    Request::Status {
        profile: profile.to_string(),
        keepalive: false,
    }
}

/// A tool method reached without a session. [`Backend::prepare`] reports this
/// first, so it is only a backstop.
fn detached() -> anyhow::Error {
    CliError::usage(NOT_RUNNING_MESSAGE.to_string()).into()
}

/// Fetch one item over IPC with `reveal = false`, so the daemon masks before the
/// values ever cross the pipe.
fn get_item_proxied(
    client: &mut Client,
    profile: &str,
    vault: &str,
    target: &str,
) -> Result<ItemView> {
    let resp = daemonctl::call(
        client,
        &Request::GetItem {
            profile: profile.to_string(),
            vault: vault.to_string(),
            target: target.to_string(),
            version: None,
            reveal: false,
        },
    )?;
    daemonctl::check_error(&resp)?;
    let Response::Item { item } = resp else {
        bail!(unexpected(&resp));
    };
    Ok(view_from_wire(&item))
}

/// Build a raw view from a directly-decrypted item.
fn view_from_item(item: &lp_vault::Item) -> ItemView {
    ItemView {
        id: item.item_id.to_hyphenated(),
        title: item.payload.title.clone(),
        type_str: item.payload.type_data.type_str().to_string(),
        version: item.current_version,
        created_at: item.created_at,
        updated_at: item.updated_at,
        tags: item.payload.tags.clone(),
        favorite: item.payload.favorite,
        notes: item.payload.notes.clone(),
        fields: crate::output::display_fields(&item.payload)
            .into_iter()
            .map(|f| FieldView {
                name: f.name,
                value: f.value,
                secret: f.secret,
            })
            .collect(),
    }
}

/// Build a raw view from a wire item (already masked by the daemon; masking it
/// again through the choke point is idempotent and keeps one code path).
fn view_from_wire(w: &WireItem) -> ItemView {
    ItemView {
        id: w.id.clone(),
        title: w.title.clone(),
        type_str: w.type_str.clone(),
        version: w.version,
        created_at: w.created_at,
        updated_at: w.updated_at,
        tags: w.tags.clone(),
        favorite: w.favorite,
        notes: w.notes.clone(),
        fields: w
            .fields
            .iter()
            .map(|f| FieldView {
                name: f.name.clone(),
                value: f.value.clone(),
                secret: f.secret,
            })
            .collect(),
    }
}

/// How often the `fill_login` wait re-asks the daemon for the outcome.
///
/// Short enough that a fill that lands in half a second is reported promptly,
/// long enough that a 30-second wait is ~120 tiny requests rather than a spin.
const FILL_POLL_INTERVAL: Duration = Duration::from_millis(250);

/// Extra grace on top of the intent's own TTL before the wait gives up, so a
/// report that arrives just as the intent lapses is still collected.
const FILL_POLL_GRACE: Duration = Duration::from_secs(3);

/// A finished agent fill: the extension's non-secret report, plus the tab and
/// origin the daemon armed the intent against.
pub struct FinishedFill {
    /// The item the intent named (canonical hyphenated id).
    pub item_id: String,
    /// The tab the fill targeted, when the agent named one.
    pub tab_id: Option<u64>,
    /// The origin the intent was bound to.
    pub origin: String,
    /// What the extension did — booleans and closed tokens only.
    pub report: FillReport,
}

/// A uniform "the daemon answered something else" internal error.
fn unexpected(resp: &Response) -> CliError {
    CliError::internal(anyhow!("unexpected daemon response: {}", resp.kind()))
}
