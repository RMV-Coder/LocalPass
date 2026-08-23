//! Vault access for the MCP server, over the CLI's existing two routes.
//!
//! The server acquires a session **once at startup** through
//! [`crate::daemonctl::route`] — exactly the routing matrix every other
//! subcommand uses, and the same one `localpass run` uses:
//!
//! - daemon running and unlocked for this profile → [`Backend::Proxy`], every
//!   read goes over the same-user-only IPC channel and the keys stay in the
//!   daemon;
//! - otherwise (no daemon, locked daemon, `--no-daemon`) → [`Backend::Direct`],
//!   the server unlocks with the master password itself and holds the
//!   `lp_vault::Session` in this process.
//!
//! Either way the *outputs* of this module are identical, so the tool layer
//! above never branches on the route.
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
//! It **fails rather than re-unlocking** on purpose: re-unlocking would require
//! keeping the master password in memory for the process's lifetime, which is
//! the very exposure the timeout exists to end. The agent's host restarts the
//! server (and re-prompts) instead.
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
use lp_daemon::protocol::{Request, Response, WireItem};
use lp_vault::Session;

use crate::commands::{run as run_cmd, totp as totp_cmd};
use crate::daemonctl::{self, Route};
use crate::error::CliError;
use crate::mcp::mask::{FieldView, ItemView};
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
}

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
}

impl DirectSession {
    /// Wrap `session` with the configured idle window.
    fn new(session: Session) -> Self {
        Self {
            session: Some(Box::new(session)),
            autolock: configured_autolock(),
            last_activity: Instant::now(),
        }
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
        if self.session.is_some()
            && !self.autolock.is_zero()
            && self.last_activity.elapsed() >= self.autolock
        {
            // Dropping the session zeroizes its key material.
            if let Some(s) = self.session.take() {
                s.lock();
            }
        }
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
    /// Acquire a session for `profile_dir`, mirroring `localpass run`.
    ///
    /// # Errors
    ///
    /// [`CliError::Auth`] on a wrong master password / Secret Key, or
    /// [`CliError::Usage`] when there is no account at `profile_dir`.
    pub fn acquire(profile_dir: &Path, src: PasswordSource, no_daemon: bool) -> Result<Self> {
        match daemonctl::route(profile_dir, no_daemon) {
            Route::Proxy(client) => Ok(Backend::Proxy {
                client,
                profile: profile_dir.display().to_string(),
            }),
            Route::Direct => {
                let (session, _sk) = unlock::unlock(profile_dir, src)?;
                Ok(Backend::Direct(DirectSession::new(session)))
            }
        }
    }

    /// A short, non-secret label for the startup log line.
    #[must_use]
    pub fn route_label(&self) -> &'static str {
        match self {
            Backend::Proxy { .. } => "daemon",
            Backend::Direct(_) => "direct",
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
        }
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
        }
    }
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

/// A uniform "the daemon answered something else" internal error.
fn unexpected(resp: &Response) -> CliError {
    CliError::internal(anyhow!("unexpected daemon response: {}", resp.kind()))
}
