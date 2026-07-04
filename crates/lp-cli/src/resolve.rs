//! Resolving user-supplied vault and item references (a name/title *or* a
//! hyphenated UUID) to concrete ids.
//!
//! Ids are 16-byte UUIDv7 rendered hyphenated (e.g.
//! `018f...-...`). A reference is treated as an id **iff** it parses as a UUID;
//! otherwise it is matched against the decrypted name/title. `lp_vault` exposes
//! `Id` but no string parser, so we parse the canonical hyphenated form here
//! with the `uuid` crate (the same crate/version `lp-vault` uses).

use anyhow::Result;
use lp_vault::{Item, Session, Vault, VaultId};
use uuid::Uuid;

use crate::error::{CliError, map_vault_error};

/// Parse a hyphenated (or simple) UUID string into an `lp_vault` id, if it is
/// one. Returns `None` for anything that is not a UUID (treat as a name/title).
fn parse_id(s: &str) -> Option<lp_vault::Id> {
    Uuid::parse_str(s)
        .ok()
        .map(|u| lp_vault::Id::from_bytes(*u.as_bytes()))
}

/// Resolve a `--vault` reference (name or id) to a [`VaultId`] and open it.
///
/// # Errors
///
/// - [`CliError::Usage`] if no live vault matches, or the name is ambiguous
///   (more than one vault shares it).
pub fn open_vault<'s>(session: &'s Session, reference: &str) -> Result<Vault<'s>> {
    let vaults = session.list_vaults().map_err(map_vault_error)?;

    // If it looks like an id and matches a listed vault, use it directly.
    if let Some(id) = parse_id(reference)
        && vaults.iter().any(|(vid, _)| *vid == id)
    {
        return session
            .open_vault(id)
            .map_err(|e| map_vault_error(e).into());
    }

    // Otherwise match by name.
    let matches: Vec<VaultId> = vaults
        .iter()
        .filter(|(_, name)| name == reference)
        .map(|(vid, _)| *vid)
        .collect();
    match matches.as_slice() {
        [] => Err(CliError::usage(format!("no vault named or id {reference:?}")).into()),
        [only] => session
            .open_vault(*only)
            .map_err(|e| map_vault_error(e).into()),
        _ => Err(CliError::usage(format!(
            "vault name {reference:?} is ambiguous ({} match); use the vault id",
            matches.len()
        ))
        .into()),
    }
}

/// Resolve an item reference (title or id) to a live [`Item`] in `vault`.
///
/// # Errors
///
/// - [`CliError::Usage`] if no live item matches, or the title is ambiguous.
pub fn find_item(vault: &Vault<'_>, reference: &str) -> Result<Item> {
    // Id path: fetch directly (and give a clean not-found if it is a
    // well-formed id that simply is not present).
    if let Some(id) = parse_id(reference) {
        match vault.get_item(id) {
            Ok(item) => return Ok(item),
            Err(lp_vault::Error::NotFound(_)) => {
                // Fall through to a title match: a title could, in theory, be a
                // UUID string; but normally this is a genuine miss.
            }
            Err(e) => return Err(map_vault_error(e).into()),
        }
    }

    let items = vault.list_items().map_err(map_vault_error)?;
    let matches: Vec<&Item> = items
        .iter()
        .filter(|it| it.payload.title == reference)
        .collect();
    match matches.as_slice() {
        [] => Err(CliError::usage(format!("no item titled or id {reference:?}")).into()),
        [only] => {
            // Re-fetch by id to return an owned `Item` (list already decrypted
            // it, but returning a fresh owned value keeps the borrow simple).
            vault
                .get_item(only.item_id)
                .map_err(|e| map_vault_error(e).into())
        }
        _ => Err(CliError::usage(format!(
            "item title {reference:?} is ambiguous ({} match); use the item id",
            matches.len()
        ))
        .into()),
    }
}
