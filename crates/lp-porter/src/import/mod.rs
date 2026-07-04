//! Importers: parse a foreign export's bytes into an
//! [`ImportOutcome`](crate::model::ImportOutcome).
//!
//! Each importer is a free function taking the raw bytes (or a path, for the
//! ZIP/KDBX containers) and returning an
//! [`ImportOutcome`](crate::model::ImportOutcome) — the parsed
//! [`ItemPayload`]s plus a value-free skip list. None of
//! them touch a vault; the caller creates the items.
//!
//! ## Field mapping conventions
//!
//! LocalPass logins carry username/password/url in **custom fields** named
//! `username` (text), `password` (hidden), `url` (url) — matching how the CLI's
//! own `item add` builds a login (`content.rs`). Importers follow that
//! convention so imported logins render identically to natively-created ones.
//! Extra autofill URLs go in [`TypeData::Login::urls`](lp_vault::TypeData). TOTP
//! secrets attached to a login are added as a hidden `totp` field (LocalPass has
//! a dedicated `totp` item type, but 1Password/Bitwarden model TOTP as a login
//! sub-field; we preserve it losslessly on the login rather than splitting it).

pub mod bitwarden;
pub mod csv_generic;
pub mod dotenv;
pub mod kdbx;
pub mod lastpass;
pub mod onepux;

use lp_vault::{Field, FieldKind, ItemPayload};
use serde_json::json;

/// Insert or replace a custom field by name, preserving position on replace.
/// Shared across importers so field naming stays uniform with the CLI.
pub(crate) fn upsert_field(
    payload: &mut ItemPayload,
    name: &str,
    kind: FieldKind,
    value: impl Into<serde_json::Value>,
) {
    let value = value.into();
    if let Some(existing) = payload.fields.iter_mut().find(|f| f.name == name) {
        existing.kind = kind;
        existing.value = value;
    } else {
        payload.fields.push(Field {
            name: name.to_string(),
            kind,
            value,
        });
    }
}

/// Add a text field if the value is non-empty (skips blank foreign fields so we
/// don't clutter items with empty keys).
pub(crate) fn add_text(payload: &mut ItemPayload, name: &str, value: &str) {
    if !value.is_empty() {
        upsert_field(payload, name, FieldKind::Text, json!(value));
    }
}

/// Add a hidden (secret) field if the value is non-empty.
pub(crate) fn add_hidden(payload: &mut ItemPayload, name: &str, value: &str) {
    if !value.is_empty() {
        upsert_field(payload, name, FieldKind::Hidden, json!(value));
    }
}

/// Add a URL field if the value is non-empty.
pub(crate) fn add_url(payload: &mut ItemPayload, name: &str, value: &str) {
    if !value.is_empty() {
        upsert_field(payload, name, FieldKind::Url, json!(value));
    }
}
