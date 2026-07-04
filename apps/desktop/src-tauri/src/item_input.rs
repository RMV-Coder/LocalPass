// SPDX-License-Identifier: MPL-2.0
// This file is part of the LocalPass desktop GUI. See apps/desktop/LICENSE.

//! Typed item-form input from the webview, and the **pure** mapping into the
//! canonical `ItemPayload` JSON the daemon's `CreateItem`/`UpdateItem` requests
//! accept.
//!
//! # Why a `serde_json::Value`, not an `lp_vault::ItemPayload`
//!
//! The GUI backend is a daemon **client** and does not depend on `lp-vault`
//! directly (it reaches the core only through `lp-daemon`). The daemon's
//! create/update requests already take a canonical payload as
//! [`serde_json::Value`] and parse it through `lp_vault::ItemPayload::from_canonical`
//! server-side — so the exact schema/validation still applies. We therefore
//! build the payload JSON here to match the vault-format §4 shape (mirrored in
//! `lp_vault::payload`) and let the daemon validate it.
//!
//! # Secret hygiene
//!
//! Field values (passwords, api-key secrets, ssh private keys, totp secrets)
//! flow webview → here → daemon on an explicit submit, exactly like any payload.
//! They are **never** echoed back: `create_item` returns only the new id and
//! `update_item` returns `()`. The functions here are pure (no IO, no daemon),
//! so the mapping is unit-tested at the JSON boundary.

use serde::Deserialize;
use serde_json::{Value, json};

/// One custom field the form supplies (text or hidden/secret).
#[derive(Clone, Debug, Deserialize)]
pub struct CustomField {
    /// The field name.
    pub name: String,
    /// The field value.
    pub value: String,
    /// Whether the field is secret (rendered `hidden`/masked).
    #[serde(default)]
    pub secret: bool,
}

/// One `KEY=value` entry of an env-set item (order-significant).
#[derive(Clone, Debug, Deserialize)]
pub struct EnvEntryInput {
    /// The variable name.
    pub key: String,
    /// The variable value.
    pub value: String,
}

/// The typed payload the item form sends for a create or an edit.
///
/// Only the fields relevant to the chosen `type_str` are consulted; the rest are
/// ignored. Secret string fields use `Option<String>` so an edit can distinguish
/// "leave unchanged" (`None`) from "set to this new value" (`Some`) — see
/// [`build_payload`].
#[derive(Clone, Debug, Deserialize)]
pub struct NewItemInput {
    /// Item type string: `login` / `note` / `api_key` / `env_set` / `ssh_key` /
    /// `totp`.
    pub type_str: String,
    /// The item title (required, non-empty).
    pub title: String,
    /// Free-form notes body (Markdown for `note` items).
    #[serde(default)]
    pub notes: String,
    /// Tags.
    #[serde(default)]
    pub tags: Vec<String>,
    /// Favorite flag.
    #[serde(default)]
    pub favorite: bool,

    // --- login fields ---
    /// Login username (non-secret).
    #[serde(default)]
    pub username: Option<String>,
    /// Login/api-key password/secret. `None` on edit = keep the current value.
    #[serde(default)]
    pub password: Option<String>,
    /// Primary URL (login) / endpoint (api-key).
    #[serde(default)]
    pub url: Option<String>,

    // --- api-key fields ---
    /// The api-key identifier (non-secret).
    #[serde(default)]
    pub api_key: Option<String>,

    // --- env-set entries ---
    /// Ordered env entries (env-set items).
    #[serde(default)]
    pub env_entries: Vec<EnvEntryInput>,

    // --- ssh-key fields ---
    /// SSH algorithm (e.g. `ed25519`).
    #[serde(default)]
    pub ssh_algo: Option<String>,
    /// SSH private key PEM. `None` on edit = keep the current value.
    #[serde(default)]
    pub ssh_private_pem: Option<String>,
    /// SSH public key (OpenSSH form).
    #[serde(default)]
    pub ssh_public_openssh: Option<String>,
    /// SSH fingerprint.
    #[serde(default)]
    pub ssh_fingerprint: Option<String>,

    // --- totp fields ---
    /// TOTP base32 secret. `None` on edit = keep the current value.
    #[serde(default)]
    pub totp_secret_b32: Option<String>,
    /// TOTP algorithm token (`SHA1` / `SHA256` / `SHA512`).
    #[serde(default)]
    pub totp_algo: Option<String>,
    /// TOTP digit count.
    #[serde(default)]
    pub totp_digits: Option<u32>,
    /// TOTP period (seconds).
    #[serde(default)]
    pub totp_period: Option<u32>,
    /// TOTP issuer label.
    #[serde(default)]
    pub totp_issuer: Option<String>,
    /// TOTP account label.
    #[serde(default)]
    pub totp_account: Option<String>,

    // --- custom fields (all types) ---
    /// Extra custom fields (text or secret).
    #[serde(default)]
    pub custom_fields: Vec<CustomField>,
}

/// The payload-schema version (matches `lp_vault::payload::PAYLOAD_VERSION`).
const PAYLOAD_VERSION: u32 = 1;

/// Build a canonical `ItemPayload` JSON [`Value`] from `input`.
///
/// `current` is the item's existing raw payload when editing (from the daemon's
/// `GetRawPayload`), or `None` when creating. On edit, a secret string field
/// left `None` in the input **preserves** the current value rather than clearing
/// it — so an unedited/unrevealed secret is never lost (the form shows secret
/// fields as "•••• (unchanged)" with an optional new value). Non-secret fields
/// and structural data are taken from the input.
///
/// # Errors
///
/// Returns an error string if the `type_str` is unknown, the title is empty, or
/// (on edit) the current payload cannot be read for a preserved field.
pub fn build_payload(input: &NewItemInput, current: Option<&Value>) -> Result<Value, String> {
    if input.title.trim().is_empty() {
        return Err("a title is required".into());
    }

    let mut fields: Vec<Value> = Vec::new();
    let mut type_data: serde_json::Map<String, Value> = serde_json::Map::new();

    match input.type_str.as_str() {
        "login" => {
            // Preserve any additional autofill URLs already stored (the form
            // edits only the primary `url` field).
            let urls = current
                .and_then(|c| c.get("urls"))
                .cloned()
                .unwrap_or_else(|| json!([]));
            type_data.insert("urls".into(), urls);
            if let Some(u) = &input.username {
                push_field(&mut fields, "username", "text", json!(u));
            }
            push_secret_field(&mut fields, "password", input.password.as_deref(), current);
            if let Some(url) = &input.url {
                push_field(&mut fields, "url", "url", json!(url));
            }
        }
        "note" => {
            // No type-specific data.
        }
        "api_key" => {
            type_data.insert(
                "key".into(),
                json!(input.api_key.clone().unwrap_or_default()),
            );
            type_data.insert(
                "secret".into(),
                preserved_secret_scalar(input.password.as_deref(), current, "secret"),
            );
            type_data.insert(
                "endpoint".into(),
                json!(input.url.clone().unwrap_or_default()),
            );
            // Preserve expiry / rotate_after (not edited by the form).
            type_data.insert(
                "expiry".into(),
                current
                    .and_then(|c| c.get("expiry"))
                    .cloned()
                    .unwrap_or(Value::Null),
            );
            type_data.insert(
                "rotate_after".into(),
                current
                    .and_then(|c| c.get("rotate_after"))
                    .cloned()
                    .unwrap_or(Value::Null),
            );
        }
        "env_set" => {
            // On edit, an empty env-entries input preserves the current entries
            // (the ItemView the form seeds from does not surface env entries, so
            // "no entries supplied" must not clobber existing ones). A non-empty
            // input replaces them.
            if input.env_entries.is_empty() {
                let existing = current
                    .and_then(|c| c.get("entries"))
                    .cloned()
                    .unwrap_or_else(|| json!([]));
                type_data.insert("entries".into(), existing);
            } else {
                let entries: Vec<Value> = input
                    .env_entries
                    .iter()
                    .map(|e| json!({ "key": e.key, "value": e.value }))
                    .collect();
                type_data.insert("entries".into(), json!(entries));
            }
        }
        "ssh_key" => {
            type_data.insert(
                "algo".into(),
                json!(input.ssh_algo.clone().unwrap_or_default()),
            );
            type_data.insert(
                "private_pem".into(),
                preserved_secret_scalar(input.ssh_private_pem.as_deref(), current, "private_pem"),
            );
            type_data.insert(
                "public_openssh".into(),
                json!(input.ssh_public_openssh.clone().unwrap_or_default()),
            );
            type_data.insert(
                "fingerprint".into(),
                json!(input.ssh_fingerprint.clone().unwrap_or_default()),
            );
        }
        "totp" => {
            type_data.insert(
                "secret_b32".into(),
                preserved_secret_scalar(input.totp_secret_b32.as_deref(), current, "secret_b32"),
            );
            type_data.insert(
                "algo".into(),
                json!(input.totp_algo.clone().unwrap_or_default()),
            );
            type_data.insert("digits".into(), json!(input.totp_digits.unwrap_or(0)));
            type_data.insert("period".into(), json!(input.totp_period.unwrap_or(0)));
            type_data.insert(
                "issuer".into(),
                json!(input.totp_issuer.clone().unwrap_or_default()),
            );
            type_data.insert(
                "account".into(),
                json!(input.totp_account.clone().unwrap_or_default()),
            );
        }
        other => return Err(format!("unknown item type {other:?}")),
    }

    // Custom fields (all types). A secret custom field left blank on edit
    // preserves its current value.
    for cf in &input.custom_fields {
        if cf.name.trim().is_empty() {
            continue;
        }
        if cf.secret {
            push_secret_field(
                &mut fields,
                &cf.name,
                if cf.value.is_empty() {
                    None
                } else {
                    Some(cf.value.as_str())
                },
                current,
            );
        } else {
            push_field(&mut fields, &cf.name, "text", json!(cf.value));
        }
    }

    // Assemble the top-level object with the type tag flattened in.
    let mut obj = serde_json::Map::new();
    obj.insert("v".into(), json!(PAYLOAD_VERSION));
    obj.insert("type".into(), json!(input.type_str));
    for (k, v) in type_data {
        obj.insert(k, v);
    }
    obj.insert("title".into(), json!(input.title));
    obj.insert("notes".into(), json!(input.notes));
    obj.insert("tags".into(), json!(input.tags));
    obj.insert("favorite".into(), json!(input.favorite));
    // Preserve folder_id if the current item had one.
    obj.insert(
        "folder_id".into(),
        current
            .and_then(|c| c.get("folder_id"))
            .cloned()
            .unwrap_or(Value::Null),
    );
    obj.insert("fields".into(), json!(fields));

    Ok(Value::Object(obj))
}

/// Append a `{name, kind, value}` field.
fn push_field(fields: &mut Vec<Value>, name: &str, kind: &str, value: Value) {
    fields.push(json!({ "name": name, "kind": kind, "value": value }));
}

/// Append a `hidden` (secret) field named `name`. When `new_value` is `Some`,
/// that value is used. When `None`, the value is **preserved** from the
/// `current` payload's matching field (edit case); if there is no current value,
/// the field is omitted entirely (create case with an empty secret).
fn push_secret_field(
    fields: &mut Vec<Value>,
    name: &str,
    new_value: Option<&str>,
    current: Option<&Value>,
) {
    if let Some(v) = new_value {
        push_field(fields, name, "hidden", json!(v));
        return;
    }
    // Preserve the current value if one exists.
    if let Some(existing) = current_field_value(current, name) {
        push_field(fields, name, "hidden", existing);
    }
    // else: no current value and no new value → omit the field.
}

/// Preserve-or-set a *type-data scalar* secret (api-key `secret`, ssh
/// `private_pem`, totp `secret_b32`), which lives directly in the flattened
/// type object rather than in `fields`. `Some(new)` sets it; `None` keeps the
/// current value (or an empty string when creating).
fn preserved_secret_scalar(new_value: Option<&str>, current: Option<&Value>, key: &str) -> Value {
    if let Some(v) = new_value {
        return json!(v);
    }
    current
        .and_then(|c| c.get(key))
        .cloned()
        .unwrap_or_else(|| json!(""))
}

/// Look up the value of a `fields[]` entry by name in a current payload.
fn current_field_value(current: Option<&Value>, name: &str) -> Option<Value> {
    current?
        .get("fields")?
        .as_array()?
        .iter()
        .find(|f| f.get("name").and_then(Value::as_str) == Some(name))
        .and_then(|f| f.get("value").cloned())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base(type_str: &str) -> NewItemInput {
        NewItemInput {
            type_str: type_str.into(),
            title: "T".into(),
            notes: String::new(),
            tags: vec![],
            favorite: false,
            username: None,
            password: None,
            url: None,
            api_key: None,
            env_entries: vec![],
            ssh_algo: None,
            ssh_private_pem: None,
            ssh_public_openssh: None,
            ssh_fingerprint: None,
            totp_secret_b32: None,
            totp_algo: None,
            totp_digits: None,
            totp_period: None,
            totp_issuer: None,
            totp_account: None,
            custom_fields: vec![],
        }
    }

    #[test]
    fn empty_title_is_rejected() {
        let mut input = base("login");
        input.title = "   ".into();
        assert!(build_payload(&input, None).is_err());
    }

    #[test]
    fn login_create_maps_username_password_url() {
        let mut input = base("login");
        input.username = Some("alice".into());
        input.password = Some("s3cr3t".into());
        input.url = Some("https://example.com".into());
        let p = build_payload(&input, None).unwrap();
        assert_eq!(p["type"], "login");
        assert_eq!(p["title"], "T");
        let fields = p["fields"].as_array().unwrap();
        let find = |n: &str| fields.iter().find(|f| f["name"] == n).unwrap();
        assert_eq!(find("username")["value"], "alice");
        assert_eq!(find("password")["value"], "s3cr3t");
        assert_eq!(find("password")["kind"], "hidden");
        assert_eq!(find("url")["value"], "https://example.com");
        assert_eq!(find("url")["kind"], "url");
    }

    #[test]
    fn edit_preserves_unrevealed_password() {
        // Current payload has a password; the edit leaves password None.
        let current = json!({
            "v": 1, "type": "login", "urls": [], "title": "Old",
            "fields": [
                { "name": "username", "kind": "text", "value": "bob" },
                { "name": "password", "kind": "hidden", "value": "keepme" }
            ]
        });
        let mut input = base("login");
        input.title = "New".into();
        input.username = Some("bob".into());
        input.password = None; // unchanged
        let p = build_payload(&input, Some(&current)).unwrap();
        let fields = p["fields"].as_array().unwrap();
        let pw = fields.iter().find(|f| f["name"] == "password").unwrap();
        assert_eq!(pw["value"], "keepme", "unrevealed secret preserved");
        assert_eq!(p["title"], "New");
    }

    #[test]
    fn edit_replaces_password_when_given() {
        let current = json!({
            "v": 1, "type": "login", "urls": [], "title": "Old",
            "fields": [ { "name": "password", "kind": "hidden", "value": "old" } ]
        });
        let mut input = base("login");
        input.password = Some("brandnew".into());
        let p = build_payload(&input, Some(&current)).unwrap();
        let fields = p["fields"].as_array().unwrap();
        let pw = fields.iter().find(|f| f["name"] == "password").unwrap();
        assert_eq!(pw["value"], "brandnew");
    }

    #[test]
    fn login_edit_preserves_extra_urls() {
        let current = json!({
            "v": 1, "type": "login", "urls": ["https://alt.example"], "title": "Old",
            "fields": []
        });
        let input = base("login");
        let p = build_payload(&input, Some(&current)).unwrap();
        assert_eq!(p["urls"], json!(["https://alt.example"]));
    }

    #[test]
    fn env_set_preserves_order() {
        let mut input = base("env_set");
        input.env_entries = vec![
            EnvEntryInput {
                key: "Z".into(),
                value: "1".into(),
            },
            EnvEntryInput {
                key: "A".into(),
                value: "2".into(),
            },
        ];
        let p = build_payload(&input, None).unwrap();
        let entries = p["entries"].as_array().unwrap();
        assert_eq!(entries[0]["key"], "Z");
        assert_eq!(entries[1]["key"], "A");
    }

    #[test]
    fn env_set_edit_preserves_entries_when_empty_input() {
        let current = json!({
            "v": 1, "type": "env_set",
            "entries": [ { "key": "FOO", "value": "1" }, { "key": "BAR", "value": "2" } ],
            "title": "Old", "fields": []
        });
        let input = base("env_set"); // no env_entries supplied
        let p = build_payload(&input, Some(&current)).unwrap();
        let entries = p["entries"].as_array().unwrap();
        assert_eq!(entries.len(), 2, "existing entries preserved on empty edit");
        assert_eq!(entries[0]["key"], "FOO");
    }

    #[test]
    fn totp_edit_preserves_secret() {
        let current = json!({
            "v": 1, "type": "totp", "secret_b32": "JBSWY3DPEHPK3PXP",
            "algo": "SHA1", "digits": 6, "period": 30, "issuer": "", "account": "",
            "title": "Old", "fields": []
        });
        let mut input = base("totp");
        input.totp_secret_b32 = None; // unchanged
        input.totp_algo = Some("SHA1".into());
        input.totp_digits = Some(6);
        input.totp_period = Some(30);
        let p = build_payload(&input, Some(&current)).unwrap();
        assert_eq!(p["secret_b32"], "JBSWY3DPEHPK3PXP");
    }

    #[test]
    fn api_key_create_maps_key_secret_endpoint() {
        let mut input = base("api_key");
        input.api_key = Some("AKIA".into());
        input.password = Some("shh".into());
        input.url = Some("https://api".into());
        let p = build_payload(&input, None).unwrap();
        assert_eq!(p["key"], "AKIA");
        assert_eq!(p["secret"], "shh");
        assert_eq!(p["endpoint"], "https://api");
    }

    #[test]
    fn custom_secret_field_preserved_on_edit_when_blank() {
        let current = json!({
            "v": 1, "type": "note", "title": "Old",
            "fields": [ { "name": "api", "kind": "hidden", "value": "keep" } ]
        });
        let mut input = base("note");
        input.custom_fields = vec![CustomField {
            name: "api".into(),
            value: String::new(),
            secret: true,
        }];
        let p = build_payload(&input, Some(&current)).unwrap();
        let fields = p["fields"].as_array().unwrap();
        let f = fields.iter().find(|f| f["name"] == "api").unwrap();
        assert_eq!(f["value"], "keep");
    }

    #[test]
    fn unknown_type_is_rejected() {
        let mut input = base("bogus");
        input.title = "x".into();
        assert!(build_payload(&input, None).is_err());
    }
}
