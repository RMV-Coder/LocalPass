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
//!   `lp_vault::Session` for its lifetime.
//!
//! Either way the *outputs* of this module are identical, so the tool layer
//! above never branches on the route.
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
    /// Hold an unlocked session in this process.
    Direct {
        /// The unlocked session.
        session: Box<Session>,
    },
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
                Ok(Backend::Direct {
                    session: Box::new(session),
                })
            }
        }
    }

    /// A short, non-secret label for the startup log line.
    #[must_use]
    pub fn route_label(&self) -> &'static str {
        match self {
            Backend::Proxy { .. } => "daemon",
            Backend::Direct { .. } => "direct",
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
            Backend::Direct { session } => Ok(session
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
            Backend::Direct { session } => {
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
            Backend::Direct { session } => {
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
            Backend::Direct { session } => {
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
            Backend::Direct { session } => run_cmd::load_env_set(session, vault, item),
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
            Backend::Direct { session } => totp_cmd::compute_direct(session, vault, item),
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
