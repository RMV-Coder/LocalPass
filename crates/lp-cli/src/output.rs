//! Rendering items for humans and for scripts — with secret masking as the
//! default.
//!
//! # Masking rule (PRD §4.4 / §4.10)
//!
//! Secret-adjacent values (the `password` field, any `hidden`-kind custom
//! field, and the secret halves of api-key / ssh-key / totp / env-set types)
//! are shown as `••••••` unless the caller passed `--reveal`. `list`, `history`
//! summaries, and `search` **never** reveal secrets regardless of flags.
//!
//! # Field model
//!
//! An item's "fields" for display purposes are a flattened view over both the
//! `type_data` (login username/password, api-key key/secret, …) and the payload
//! `fields` vec, each tagged secret or not. This gives `item get --field NAME`
//! and the masked table one consistent source.

use lp_vault::payload::{FieldKind, TypeData};
use lp_vault::{Item, ItemPayload};
use serde_json::{Value, json};

/// The mask shown in place of a secret value.
pub const MASK: &str = "••••••";

/// One displayable field: a name, a string value, and whether it is secret.
pub struct DisplayField {
    /// The field name (e.g. `username`, `password`, or a custom key).
    pub name: String,
    /// The field's value rendered as a string.
    pub value: String,
    /// Whether the value is secret (masked unless revealed).
    pub secret: bool,
}

impl DisplayField {
    fn new(name: impl Into<String>, value: impl Into<String>, secret: bool) -> Self {
        Self {
            name: name.into(),
            value: value.into(),
            secret,
        }
    }

    /// The value as shown given `reveal`: the raw value, or the mask if secret
    /// and not revealed. An empty value renders empty (nothing to mask).
    #[must_use]
    pub fn shown(&self, reveal: bool) -> String {
        if self.secret && !reveal && !self.value.is_empty() {
            MASK.to_string()
        } else {
            self.value.clone()
        }
    }
}

/// Render a `serde_json::Value` field value to a display string. Strings render
/// without quotes; numbers/bools/others via their JSON form.
fn value_to_string(v: &Value) -> String {
    match v {
        Value::String(s) => s.clone(),
        other => other.to_string(),
    }
}

/// Flatten an item payload into an ordered list of [`DisplayField`]s covering
/// the type-specific data and the custom fields.
///
/// The order is stable (type fields first, then custom fields in payload
/// order) so `--json` and the table are deterministic.
#[must_use]
pub fn display_fields(payload: &ItemPayload) -> Vec<DisplayField> {
    let mut out = Vec::new();
    match &payload.type_data {
        TypeData::Login { urls } => {
            if !urls.is_empty() {
                out.push(DisplayField::new("urls", urls.join(", "), false));
            }
        }
        TypeData::Note {} => {}
        TypeData::ApiKey {
            key,
            secret,
            endpoint,
            expiry,
            rotate_after,
        } => {
            out.push(DisplayField::new("key", key.clone(), false));
            out.push(DisplayField::new("secret", secret.clone(), true));
            if !endpoint.is_empty() {
                out.push(DisplayField::new("endpoint", endpoint.clone(), false));
            }
            if let Some(e) = expiry {
                out.push(DisplayField::new("expiry", e.to_string(), false));
            }
            if let Some(r) = rotate_after {
                out.push(DisplayField::new("rotate_after", r.to_string(), false));
            }
        }
        TypeData::EnvSet { entries } => {
            for e in entries {
                // env values are secret by default.
                out.push(DisplayField::new(e.key.clone(), e.value.clone(), true));
            }
        }
        TypeData::SshKey {
            algo,
            private_pem,
            public_openssh,
            fingerprint,
        } => {
            if !algo.is_empty() {
                out.push(DisplayField::new("algo", algo.clone(), false));
            }
            out.push(DisplayField::new("private_pem", private_pem.clone(), true));
            if !public_openssh.is_empty() {
                out.push(DisplayField::new(
                    "public_openssh",
                    public_openssh.clone(),
                    false,
                ));
            }
            if !fingerprint.is_empty() {
                out.push(DisplayField::new("fingerprint", fingerprint.clone(), false));
            }
        }
        TypeData::Totp {
            secret_b32,
            algo,
            digits,
            period,
            issuer,
            account,
        } => {
            out.push(DisplayField::new("secret_b32", secret_b32.clone(), true));
            if !algo.is_empty() {
                out.push(DisplayField::new("algo", algo.clone(), false));
            }
            if *digits != 0 {
                out.push(DisplayField::new("digits", digits.to_string(), false));
            }
            if *period != 0 {
                out.push(DisplayField::new("period", period.to_string(), false));
            }
            if !issuer.is_empty() {
                out.push(DisplayField::new("issuer", issuer.clone(), false));
            }
            if !account.is_empty() {
                out.push(DisplayField::new("account", account.clone(), false));
            }
        }
    }
    // Custom fields: `hidden` kind is secret; others are not.
    for f in &payload.fields {
        out.push(DisplayField::new(
            f.name.clone(),
            value_to_string(&f.value),
            matches!(f.kind, FieldKind::Hidden),
        ));
    }
    out
}

/// Find a single field's raw value by name (case-sensitive first, then
/// case-insensitive fallback). Returns the raw value regardless of secrecy —
/// `item get --field NAME` is an explicit reveal of exactly that field.
#[must_use]
pub fn find_field<'a>(fields: &'a [DisplayField], name: &str) -> Option<&'a DisplayField> {
    fields
        .iter()
        .find(|f| f.name == name)
        .or_else(|| fields.iter().find(|f| f.name.eq_ignore_ascii_case(name)))
}

/// Build the `--json` object for a single item.
///
/// Secret field values are included **only** when `reveal` is true; otherwise
/// they appear as the mask string, keeping the JSON shape stable either way.
#[must_use]
pub fn item_to_json(item: &Item, reveal: bool) -> Value {
    let fields: Vec<Value> = display_fields(&item.payload)
        .iter()
        .map(|f| {
            json!({
                "name": f.name,
                "secret": f.secret,
                "value": f.shown(reveal),
            })
        })
        .collect();
    json!({
        "id": item.item_id.to_hyphenated(),
        "title": item.payload.title,
        "type": item.payload.type_data.type_str(),
        "version": item.current_version,
        "created_at": item.created_at,
        "updated_at": item.updated_at,
        "tags": item.payload.tags,
        "favorite": item.payload.favorite,
        "notes": item.payload.notes,
        "fields": fields,
    })
}

/// Build a compact `--json` summary object for `list` / `search` (never
/// includes field values or secrets).
#[must_use]
pub fn item_summary_json(item: &Item) -> Value {
    json!({
        "id": item.item_id.to_hyphenated(),
        "title": item.payload.title,
        "type": item.payload.type_data.type_str(),
        "updated_at": item.updated_at,
        "tags": item.payload.tags,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use lp_vault::payload::{Field, ItemPayload};
    use serde_json::json as j;

    fn login_with_password() -> ItemPayload {
        let mut p = ItemPayload::new(TypeData::Login { urls: vec![] }, "Example");
        p.fields = vec![
            Field {
                name: "username".into(),
                kind: FieldKind::Text,
                value: j!("alice"),
            },
            Field {
                name: "password".into(),
                kind: FieldKind::Hidden,
                value: j!("hunter2"),
            },
        ];
        p
    }

    #[test]
    fn hidden_fields_mask_unless_revealed() {
        let p = login_with_password();
        let fields = display_fields(&p);
        let pw = find_field(&fields, "password").unwrap();
        assert!(pw.secret);
        assert_eq!(pw.shown(false), MASK);
        assert_eq!(pw.shown(true), "hunter2");
        let user = find_field(&fields, "username").unwrap();
        assert!(!user.secret);
        assert_eq!(user.shown(false), "alice");
    }

    #[test]
    fn env_values_are_secret() {
        let p = ItemPayload::new(
            TypeData::EnvSet {
                entries: vec![lp_vault::payload::EnvEntry {
                    key: "API_TOKEN".into(),
                    value: "sk_live_x".into(),
                }],
            },
            "env",
        );
        let fields = display_fields(&p);
        let f = find_field(&fields, "API_TOKEN").unwrap();
        assert!(f.secret);
        assert_eq!(f.shown(false), MASK);
        assert_eq!(f.shown(true), "sk_live_x");
    }

    #[test]
    fn find_field_is_case_insensitive_fallback() {
        let p = login_with_password();
        let fields = display_fields(&p);
        assert!(find_field(&fields, "PASSWORD").is_some());
        assert!(find_field(&fields, "nope").is_none());
    }
}
