//! `localpass ssh list | generate | public` — vault-backed SSH keys (PRD §4.8).
//!
//! - `list` shows the identities the daemon's SSH agent would serve (fingerprint,
//!   comment = item title, algo) across all vaults — without needing `ssh-add`.
//! - `generate` creates a keypair **in memory** (via `lp_daemon::sshagent::keys`,
//!   the foreign-format boundary) and stores it as an `ssh_key` item; only the
//!   public key is printed.
//! - `public` prints an item's public key for `authorized_keys`.
//!
//! Like the other vault-touching commands, each tries the daemon first (proxying
//! when it's unlocked for this profile) and otherwise unlocks directly. `list`
//! and `public` are read-only; `generate` creates an item (which the daemon
//! path proxies via `CreateItem`, so a rotated/new key is immediately servable).

use std::path::Path;

use anyhow::{Result, anyhow};
use lp_vault::payload::{ItemPayload, TypeData};
use lp_vault::{Session, Vault};
use serde_json::json;

use lp_daemon::client::Client;
use lp_daemon::protocol::{Request, Response};
use lp_daemon::sshagent::keys::{self, GenAlgorithm};

use crate::cli::{SshAlgo, SshCommand};
use crate::daemonctl::{self, Route};
use crate::error::{CliError, map_vault_error};
use crate::resolve;
use crate::unlock::{self, PasswordSource};

/// Run a `localpass ssh ...` subcommand.
///
/// # Errors
///
/// Propagates unlock, resolution, and storage failures with the documented exit
/// codes.
pub fn run(
    profile_dir: &Path,
    src: PasswordSource,
    no_daemon: bool,
    command: &SshCommand,
) -> Result<()> {
    if let Route::Proxy(mut client) = daemonctl::route(profile_dir, no_daemon) {
        return run_proxied(profile_dir, &mut client, command);
    }
    let (session, _sk) = unlock::unlock(profile_dir, src)?;
    run_direct(&session, command)
}

/// The direct (no-daemon) path: act on a locally-unlocked `Session`.
fn run_direct(session: &Session, command: &SshCommand) -> Result<()> {
    match command {
        SshCommand::List { json } => list_direct(session, *json),
        SshCommand::Generate {
            title,
            vault,
            algo,
            comment,
            json,
        } => {
            let vault = resolve::open_vault(session, vault)?;
            let key = build_key(*algo, title, comment.as_deref())?;
            store_key(&vault, title, &key)?;
            print_generated(&key, *json);
            Ok(())
        }
        SshCommand::Public { target, vault } => {
            let vault = resolve::open_vault(session, vault)?;
            let item = resolve::find_item(&vault, target)?;
            print_public(&item.payload, target)
        }
    }
}

/// The proxied path: the daemon holds the unlocked session.
fn run_proxied(profile_dir: &Path, client: &mut Client, command: &SshCommand) -> Result<()> {
    let profile = profile_dir.display().to_string();
    match command {
        SshCommand::List { json } => list_proxied(&profile, client, *json),
        SshCommand::Generate {
            title,
            vault,
            algo,
            comment,
            json,
        } => {
            let key = build_key(*algo, title, comment.as_deref())?;
            let payload = ssh_payload(title, &key);
            let value = serde_json::to_value(&payload)
                .map_err(|e| CliError::internal(anyhow!("serializing payload: {e}")))?;
            let resp = daemonctl::call(
                client,
                &Request::CreateItem {
                    profile,
                    vault: vault.clone(),
                    payload: value,
                },
            )?;
            daemonctl::check_error(&resp)?;
            print_generated(&key, *json);
            Ok(())
        }
        SshCommand::Public { target, vault } => {
            let resp = daemonctl::call(
                client,
                &Request::GetRawPayload {
                    profile,
                    vault: vault.clone(),
                    target: target.clone(),
                },
            )?;
            daemonctl::check_error(&resp)?;
            match resp {
                Response::RawPayload { payload, .. } => {
                    let parsed: ItemPayload = serde_json::from_value(payload)
                        .map_err(|e| CliError::internal(anyhow!("parsing item payload: {e}")))?;
                    print_public(&parsed, target)
                }
                other => Err(CliError::internal(anyhow!(
                    "unexpected daemon response: {}",
                    other.kind()
                ))
                .into()),
            }
        }
    }
}

// --- list ------------------------------------------------------------------

/// A displayed identity (fingerprint, comment, algo).
struct IdentityRow {
    fingerprint: String,
    comment: String,
    algo: String,
}

/// Collect servable identities directly from a session (all vaults).
fn list_direct(session: &Session, json_out: bool) -> Result<()> {
    let identities = lp_daemon::sshagent::service::collect_identities(session)
        .map_err(map_vault_error)?
        .into_iter()
        .map(|i| IdentityRow {
            fingerprint: i.fingerprint,
            comment: i.comment,
            algo: i.algo,
        })
        .collect::<Vec<_>>();
    print_identities(&identities, json_out);
    Ok(())
}

/// Collect servable identities through the daemon. The daemon has no dedicated
/// "list identities over IPC" request, so we drive its `Status` for the count
/// and fall back to walking items via the proxy. To keep the identity data
/// authoritative (derived from the private key), we list `ssh_key` items across
/// every vault and derive their public info locally from the item payloads.
fn list_proxied(profile: &str, client: &mut Client, json_out: bool) -> Result<()> {
    // Enumerate vaults, then list each vault's items, filtering to ssh_key.
    let vaults = match daemonctl::call(
        client,
        &Request::ListVaults {
            profile: profile.to_string(),
        },
    )? {
        Response::Vaults { vaults } => vaults,
        other => {
            return Err(CliError::internal(anyhow!(
                "unexpected daemon response: {}",
                other.kind()
            ))
            .into());
        }
    };

    let mut rows = Vec::new();
    for (vault_id, _name) in vaults {
        // For each ssh_key item, fetch its raw payload (carries the private key,
        // same-user-only channel) and derive the public info.
        let items = match daemonctl::call(
            client,
            &Request::ListItems {
                profile: profile.to_string(),
                vault: vault_id.clone(),
            },
        )? {
            Response::Items { items } => items,
            _ => continue,
        };
        for summary in items {
            if summary.type_str != "ssh_key" {
                continue;
            }
            let resp = daemonctl::call(
                client,
                &Request::GetRawPayload {
                    profile: profile.to_string(),
                    vault: vault_id.clone(),
                    target: summary.id.clone(),
                },
            )?;
            if let Response::RawPayload { payload, .. } = resp
                && let Ok(parsed) = serde_json::from_value::<ItemPayload>(payload)
                && let Some(row) = identity_from_payload(&parsed)
            {
                rows.push(row);
            }
        }
    }
    print_identities(&rows, json_out);
    Ok(())
}

/// Derive an identity row from a stored ssh_key payload by parsing its private
/// key (authoritative). Returns `None` for a non-ssh item or an unparseable key.
fn identity_from_payload(payload: &ItemPayload) -> Option<IdentityRow> {
    let TypeData::SshKey { private_pem, .. } = &payload.type_data else {
        return None;
    };
    let parsed = keys::parse_private_key(private_pem, &payload.title).ok()?;
    Some(IdentityRow {
        fingerprint: parsed.fingerprint(),
        comment: payload.title.clone(),
        algo: parsed.algorithm_str(),
    })
}

/// Print the identity list (human table or JSON).
fn print_identities(rows: &[IdentityRow], json_out: bool) {
    if json_out {
        let arr: Vec<serde_json::Value> = rows
            .iter()
            .map(|r| {
                json!({
                    "fingerprint": r.fingerprint,
                    "comment": r.comment,
                    "algo": r.algo,
                })
            })
            .collect();
        println!("{}", serde_json::to_string_pretty(&arr).unwrap_or_default());
        return;
    }
    if rows.is_empty() {
        println!("(no SSH keys in any vault)");
        return;
    }
    let algo_w = rows
        .iter()
        .map(|r| r.algo.len())
        .max()
        .unwrap_or(11)
        .clamp(11, 20);
    println!(
        "{:<algo_w$}  {:<50}  COMMENT",
        "ALGO",
        "FINGERPRINT",
        algo_w = algo_w
    );
    for r in rows {
        println!(
            "{:<algo_w$}  {:<50}  {}",
            r.algo,
            r.fingerprint,
            r.comment,
            algo_w = algo_w
        );
    }
}

// --- generate --------------------------------------------------------------

/// Build a keypair in memory for the chosen algorithm.
fn build_key(algo: SshAlgo, title: &str, comment: Option<&str>) -> Result<keys::GeneratedKey> {
    let gen_algo = match algo {
        SshAlgo::Ed25519 => GenAlgorithm::Ed25519,
        SshAlgo::Rsa4096 => GenAlgorithm::Rsa4096,
    };
    let comment = comment.unwrap_or(title);
    keys::generate(gen_algo, comment)
        .map_err(|e| CliError::internal(anyhow!("generating SSH key: {e}")).into())
}

/// Build the ssh_key item payload for a generated key.
fn ssh_payload(title: &str, key: &keys::GeneratedKey) -> ItemPayload {
    ItemPayload::new(
        TypeData::SshKey {
            algo: key.algo.clone(),
            private_pem: key.private_pem.clone(),
            public_openssh: key.public_openssh.clone(),
            fingerprint: key.fingerprint.clone(),
        },
        title,
    )
}

/// Store a generated key as an ssh_key item in `vault`.
fn store_key(vault: &Vault<'_>, title: &str, key: &keys::GeneratedKey) -> Result<()> {
    let payload = ssh_payload(title, key);
    vault.create_item(&payload).map_err(map_vault_error)?;
    Ok(())
}

/// Print the generated key's PUBLIC half only (never the private key).
fn print_generated(key: &keys::GeneratedKey, json_out: bool) {
    if json_out {
        let obj = json!({
            "public_openssh": key.public_openssh,
            "fingerprint": key.fingerprint,
            "algo": key.algo,
        });
        println!("{}", serde_json::to_string_pretty(&obj).unwrap_or_default());
    } else {
        // The public key line goes to stdout (for piping into authorized_keys);
        // the fingerprint hint goes to stderr so stdout stays a clean key line.
        println!("{}", key.public_openssh);
        eprintln!(
            "stored SSH key ({}); the private key never touched disk",
            key.fingerprint
        );
    }
}

// --- public ----------------------------------------------------------------

/// Print an ssh_key item's public key for authorized_keys.
fn print_public(payload: &ItemPayload, target: &str) -> Result<()> {
    match &payload.type_data {
        TypeData::SshKey {
            public_openssh,
            private_pem,
            ..
        } => {
            // Prefer the stored public key; if it is empty (older item), derive
            // it from the private key so `ssh public` still works.
            if !public_openssh.is_empty() {
                println!("{public_openssh}");
                return Ok(());
            }
            let parsed = keys::parse_private_key(private_pem, &payload.title)
                .map_err(|e| CliError::usage(format!("{e}")))?;
            let openssh = parsed
                .public_openssh()
                .map_err(|e| CliError::internal(anyhow!("deriving public key: {e}")))?;
            println!("{openssh}");
            Ok(())
        }
        _ => Err(CliError::usage(format!("item {target:?} is not an SSH key")).into()),
    }
}
