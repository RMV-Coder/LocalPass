#![forbid(unsafe_code)]
//! Rendering `lp_vault` items into wire types, with secret masking.
//!
//! This mirrors the CLI's own display model (its `output` module) so an item
//! rendered by the daemon looks identical to one the CLI unlocked directly:
//! the same flattened field order, the same "env values are secret", the same
//! mask. Keeping the logic here (not shared with the CLI) preserves the crate
//! boundary — the daemon owns the session, so it owns the render — at the cost
//! of a small, well-tested duplication.

use lp_vault::health::PasswordHealth;
use lp_vault::payload::{FieldKind, TypeData};
use lp_vault::{Item, ItemPayload};

use crate::protocol::{WireField, WireItem, WireItemSummary, WirePasswordHealth};

/// The mask shown in place of a secret value (matches the CLI's `output::MASK`).
pub const MASK: &str = "••••••";

/// A flattened display field before masking.
struct Flat {
    name: String,
    value: String,
    secret: bool,
}

/// Render a `serde_json::Value` field value to a display string (strings without
/// quotes, everything else via its JSON form) — matching the CLI.
fn value_to_string(v: &serde_json::Value) -> String {
    match v {
        serde_json::Value::String(s) => s.clone(),
        other => other.to_string(),
    }
}

/// Flatten a payload into ordered display fields (type-specific first, then
/// custom fields), tagging each secret or not. Identical ordering to the CLI.
fn flatten(payload: &ItemPayload) -> Vec<Flat> {
    let mut out = Vec::new();
    match &payload.type_data {
        TypeData::Login { urls } => {
            if !urls.is_empty() {
                out.push(Flat {
                    name: "urls".into(),
                    value: urls.join(", "),
                    secret: false,
                });
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
            out.push(Flat {
                name: "key".into(),
                value: key.clone(),
                secret: false,
            });
            out.push(Flat {
                name: "secret".into(),
                value: secret.clone(),
                secret: true,
            });
            if !endpoint.is_empty() {
                out.push(Flat {
                    name: "endpoint".into(),
                    value: endpoint.clone(),
                    secret: false,
                });
            }
            if let Some(e) = expiry {
                out.push(Flat {
                    name: "expiry".into(),
                    value: e.to_string(),
                    secret: false,
                });
            }
            if let Some(r) = rotate_after {
                out.push(Flat {
                    name: "rotate_after".into(),
                    value: r.to_string(),
                    secret: false,
                });
            }
        }
        TypeData::EnvSet { entries } => {
            for e in entries {
                out.push(Flat {
                    name: e.key.clone(),
                    value: e.value.clone(),
                    secret: true,
                });
            }
        }
        TypeData::SshKey {
            algo,
            private_pem,
            public_openssh,
            fingerprint,
        } => {
            if !algo.is_empty() {
                out.push(Flat {
                    name: "algo".into(),
                    value: algo.clone(),
                    secret: false,
                });
            }
            out.push(Flat {
                name: "private_pem".into(),
                value: private_pem.clone(),
                secret: true,
            });
            if !public_openssh.is_empty() {
                out.push(Flat {
                    name: "public_openssh".into(),
                    value: public_openssh.clone(),
                    secret: false,
                });
            }
            if !fingerprint.is_empty() {
                out.push(Flat {
                    name: "fingerprint".into(),
                    value: fingerprint.clone(),
                    secret: false,
                });
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
            out.push(Flat {
                name: "secret_b32".into(),
                value: secret_b32.clone(),
                secret: true,
            });
            if !algo.is_empty() {
                out.push(Flat {
                    name: "algo".into(),
                    value: algo.clone(),
                    secret: false,
                });
            }
            if *digits != 0 {
                out.push(Flat {
                    name: "digits".into(),
                    value: digits.to_string(),
                    secret: false,
                });
            }
            if *period != 0 {
                out.push(Flat {
                    name: "period".into(),
                    value: period.to_string(),
                    secret: false,
                });
            }
            if !issuer.is_empty() {
                out.push(Flat {
                    name: "issuer".into(),
                    value: issuer.clone(),
                    secret: false,
                });
            }
            if !account.is_empty() {
                out.push(Flat {
                    name: "account".into(),
                    value: account.clone(),
                    secret: false,
                });
            }
        }
    }
    for f in &payload.fields {
        out.push(Flat {
            name: f.name.clone(),
            value: value_to_string(&f.value),
            secret: matches!(f.kind, FieldKind::Hidden),
        });
    }
    out
}

/// The value shown given `reveal`: raw, or the mask if secret and not revealed
/// (an empty value renders empty — nothing to mask). Matches the CLI.
fn shown(flat: &Flat, reveal: bool) -> String {
    if flat.secret && !reveal && !flat.value.is_empty() {
        MASK.to_string()
    } else {
        flat.value.clone()
    }
}

/// Flatten a payload into [`WireField`]s, masking secrets unless `reveal`.
/// Shared by [`item_to_wire`] and [`version_to_wire`].
fn wire_fields(payload: &ItemPayload, reveal: bool) -> Vec<WireField> {
    flatten(payload)
        .iter()
        .map(|f| WireField {
            name: f.name.clone(),
            value: shown(f, reveal),
            secret: f.secret,
        })
        .collect()
}

/// Render a full item to a [`WireItem`], masking secrets unless `reveal`.
#[must_use]
pub fn item_to_wire(item: &Item, reveal: bool) -> WireItem {
    WireItem {
        id: item.item_id.to_hyphenated(),
        title: item.payload.title.clone(),
        type_str: item.payload.type_data.type_str().to_string(),
        version: item.current_version,
        created_at: item.created_at,
        updated_at: item.updated_at,
        tags: item.payload.tags.clone(),
        favorite: item.payload.favorite,
        notes: item.payload.notes.clone(),
        fields: wire_fields(&item.payload, reveal),
    }
}

/// Render a version's payload (from history) to a [`WireItem`]. `version` and
/// `created_at` come from the [`lp_vault::VersionInfo`]; the item id is carried
/// separately (a version alone has no id).
#[must_use]
pub fn version_to_wire(
    id: String,
    version: i64,
    created_at: i64,
    payload: &ItemPayload,
    reveal: bool,
) -> WireItem {
    WireItem {
        id,
        title: payload.title.clone(),
        type_str: payload.type_data.type_str().to_string(),
        version,
        created_at,
        updated_at: created_at,
        tags: payload.tags.clone(),
        favorite: payload.favorite,
        notes: payload.notes.clone(),
        fields: wire_fields(payload, reveal),
    }
}

/// Render an item to a compact [`WireItemSummary`] (never any field value).
#[must_use]
pub fn item_to_summary(item: &Item) -> WireItemSummary {
    WireItemSummary {
        id: item.item_id.to_hyphenated(),
        title: item.payload.title.clone(),
        type_str: item.payload.type_data.type_str().to_string(),
        updated_at: item.updated_at,
        tags: item.payload.tags.clone(),
    }
}

/// Map a [`PasswordHealth`] verdict to its wire form. Metadata only — the
/// analyzed secret value is never part of either type (secret boundary).
#[must_use]
pub fn health_to_wire(h: &PasswordHealth) -> WirePasswordHealth {
    WirePasswordHealth {
        item_id: h.item_id.to_hyphenated(),
        title: h.title.clone(),
        field: h.field.clone(),
        length: h.length,
        entropy_bits: h.entropy_bits,
        strength: h.strength.as_str().to_string(),
        issues: h.issues.iter().map(|i| i.as_str().to_string()).collect(),
        reuse_group: h.reuse_group,
        age_days: h.age_days,
    }
}

/// The result of computing a TOTP code from a `totp` item: the code, seconds
/// remaining in the window, and the item's (non-secret) metadata. The base32
/// secret is decoded, used, and zeroized inside [`totp_code`] — it is never part
/// of this value.
pub struct TotpResult {
    /// The current zero-padded code.
    pub code: String,
    /// Whole seconds remaining in the current window.
    pub seconds_remaining: u32,
    /// The time step in seconds.
    pub period: u32,
    /// The digit count.
    pub digits: u32,
    /// The algorithm token (`SHA1` / `SHA256` / `SHA512`).
    pub algo: String,
}

/// Compute the current TOTP code for a `totp` item's payload.
///
/// Decodes the base32 secret, computes the code with [`lp_crypto::totp`], and
/// **zeroizes the decoded secret bytes** before returning — the secret never
/// leaves this function. Returns `Ok(None)` if the item is not a `totp` item (so
/// the caller can produce a clear "wrong type" usage error).
///
/// # Errors
///
/// A descriptive `String` if the secret is missing / not valid base32, or the
/// stored digits/period/algorithm are out of range.
pub fn totp_code(payload: &ItemPayload) -> Result<Option<TotpResult>, String> {
    use zeroize::Zeroize;

    let TypeData::Totp {
        secret_b32,
        algo,
        digits,
        period,
        ..
    } = &payload.type_data
    else {
        return Ok(None);
    };

    // RFC 6238 defaults for stored-zero / empty legacy fields.
    let digits = if *digits == 0 { 6 } else { *digits };
    let period = if *period == 0 { 30 } else { *period };
    let algo = lp_crypto::TotpAlgo::parse(algo)
        .map_err(|_| "item has an unknown TOTP algorithm".to_string())?;
    let digits_u8 =
        u8::try_from(digits).map_err(|_| "item TOTP digits out of range".to_string())?;

    let mut secret = lp_crypto::decode_base32(secret_b32.trim())
        .map_err(|_| "item TOTP secret is not valid base32".to_string())?;
    let result = lp_crypto::totp::code_now(&secret, algo, digits_u8, period);
    secret.zeroize();
    let (code, seconds_remaining) =
        result.map_err(|_| "could not compute TOTP code (bad parameters)".to_string())?;

    Ok(Some(TotpResult {
        code,
        seconds_remaining,
        period,
        digits,
        algo: algo.as_str().to_string(),
    }))
}

/// Resolve one field of an item to its plaintext value, for `ResolveField`.
///
/// Matches the CLI's reference-resolution rule: for an env-set, look the field
/// up as an entry key first (exact then case-insensitive); otherwise fall back
/// to the flattened display fields (exact then case-insensitive by name).
/// Returns `None` if no field matches.
#[must_use]
pub fn resolve_field(payload: &ItemPayload, field: &str) -> Option<String> {
    if let TypeData::EnvSet { entries } = &payload.type_data {
        if let Some(e) = entries.iter().find(|e| e.key == field) {
            return Some(e.value.clone());
        }
        if let Some(e) = entries.iter().find(|e| e.key.eq_ignore_ascii_case(field)) {
            return Some(e.value.clone());
        }
    }
    let flat = flatten(payload);
    if let Some(f) = flat.iter().find(|f| f.name == field) {
        return Some(f.value.clone());
    }
    if let Some(f) = flat.iter().find(|f| f.name.eq_ignore_ascii_case(field)) {
        return Some(f.value.clone());
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use lp_vault::payload::{EnvEntry, Field, ItemPayload};
    use serde_json::json;

    fn login() -> ItemPayload {
        let mut p = ItemPayload::new(TypeData::Login { urls: vec![] }, "GitHub");
        p.fields = vec![
            Field {
                name: "username".into(),
                kind: FieldKind::Text,
                value: json!("octocat"),
            },
            Field {
                name: "password".into(),
                kind: FieldKind::Hidden,
                value: json!("s3cr3t"),
            },
        ];
        p
    }

    #[test]
    fn masks_secret_unless_revealed() {
        let p = login();
        let flat = flatten(&p);
        let pw = flat.iter().find(|f| f.name == "password").unwrap();
        assert_eq!(shown(pw, false), MASK);
        assert_eq!(shown(pw, true), "s3cr3t");
    }

    #[test]
    fn resolve_field_prefers_env_entry_then_fields() {
        let p = ItemPayload::new(
            TypeData::EnvSet {
                entries: vec![EnvEntry {
                    key: "TOKEN".into(),
                    value: "sk_live".into(),
                }],
            },
            "env",
        );
        assert_eq!(resolve_field(&p, "TOKEN").as_deref(), Some("sk_live"));
        assert_eq!(resolve_field(&p, "token").as_deref(), Some("sk_live"));
        assert!(resolve_field(&p, "missing").is_none());
    }

    #[test]
    fn resolve_field_case_insensitive_fallback_on_login() {
        let p = login();
        assert_eq!(resolve_field(&p, "PASSWORD").as_deref(), Some("s3cr3t"));
    }
}
