//! The item payload model — the canonical plaintext body of every item version
//! (vault-format.md §4).
//!
//! This is the JSON object that gets serialized canonically ([`crate::canonical`])
//! and encrypted into `item_versions.payload_env`. Everything that could leak
//! content — title, notes, tags, favorite flag, folder membership, custom-field
//! names *and* values, item type, and all `type_data` — lives **here**, inside
//! the ciphertext, never as a plaintext column (vault-format.md §6, PRD §6.3).
//!
//! # Determinism
//!
//! The struct serializes through [`crate::canonical::to_canonical_vec`], so the
//! same logical payload always yields byte-identical bytes (required for AEAD
//! and the op signature). Field order in the struct is irrelevant — canonical
//! JSON sorts keys.
//!
//! # Secret hygiene
//!
//! [`ItemPayload`] holds decrypted secret values (passwords, private keys, TOTP
//! secrets). It deliberately has **no `Debug` derive that prints values**: the
//! manual [`Debug`] impl renders only the type and title-presence, never field
//! values, so an accidental `{:?}` in a log cannot leak a secret.

use serde::{Deserialize, Serialize};

/// The schema version of the payload body (`"v"` in the JSON; always `1`).
pub const PAYLOAD_VERSION: u32 = 1;

/// A custom field's display/handling kind (vault-format.md §4, PRD §4.1).
///
/// `hidden` is a UX hint (masked by default); it carries no crypto meaning —
/// the whole payload is encrypted regardless.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum FieldKind {
    /// Plain text, shown by default.
    Text,
    /// Secret text, masked by default in the UI.
    Hidden,
    /// A URL (used for autofill matching on `login` items).
    Url,
    /// A unix-millis timestamp (e.g. an expiry). Stored as an integer.
    Date,
}

/// A custom field: a name, a kind, and a value.
///
/// `value` is a [`serde_json::Value`] so a `date` field can carry an integer
/// while `text`/`hidden`/`url` carry strings — while still round-tripping
/// through the integers-only canonical form (no floats).
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Field {
    /// The field name (part of the ciphertext; a custom key for the payload).
    pub name: String,
    /// How the field should be displayed/handled.
    pub kind: FieldKind,
    /// The field value: a string for `text`/`hidden`/`url`, an integer
    /// (unix-millis) for `date`.
    pub value: serde_json::Value,
}

/// The item's secret type and its type-specific data (vault-format.md §4).
///
/// Serialized with an internal `type` tag (the JSON `"type"` string) and the
/// type-specific fields flattened alongside the common ones. The six MVP types
/// are modeled explicitly; the type-specific payload lives in [`TypeData`].
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum TypeData {
    /// A login: username/password/URL live in `fields`; extra autofill URLs here.
    Login {
        /// Additional URLs (beyond a primary `url` field) for autofill matching.
        #[serde(default)]
        urls: Vec<String>,
    },
    /// A secure note (Markdown in `notes`); no extra type data.
    Note {},
    /// An API key / token.
    ApiKey {
        /// The API key / identifier.
        #[serde(default)]
        key: String,
        /// The secret half.
        #[serde(default)]
        secret: String,
        /// The service endpoint.
        #[serde(default)]
        endpoint: String,
        /// Expiry as unix-millis, if known.
        #[serde(default)]
        expiry: Option<i64>,
        /// Rotation-reminder date as unix-millis, if set.
        #[serde(default)]
        rotate_after: Option<i64>,
    },
    /// An ordered `.env` bundle (PRD §4.8): a list of KEY=value entries whose
    /// order is preserved.
    EnvSet {
        /// The ordered entries.
        #[serde(default)]
        entries: Vec<EnvEntry>,
    },
    /// An SSH key pair. Private material is inside the encrypted payload.
    SshKey {
        /// Algorithm (e.g. `ed25519`, `rsa`).
        #[serde(default)]
        algo: String,
        /// The private key in PEM form.
        #[serde(default)]
        private_pem: String,
        /// The public key in OpenSSH form.
        #[serde(default)]
        public_openssh: String,
        /// The key fingerprint.
        #[serde(default)]
        fingerprint: String,
    },
    /// A TOTP secret (RFC 6238).
    Totp {
        /// The base32-encoded shared secret.
        #[serde(default)]
        secret_b32: String,
        /// The HMAC algorithm (e.g. `SHA1`, `SHA256`).
        #[serde(default)]
        algo: String,
        /// Number of digits in the generated code.
        #[serde(default)]
        digits: u32,
        /// Time step in seconds.
        #[serde(default)]
        period: u32,
        /// The issuer label.
        #[serde(default)]
        issuer: String,
        /// The account label.
        #[serde(default)]
        account: String,
    },
}

impl TypeData {
    /// The integer type code (vault-format.md §4 table). Used by op
    /// materialization and index filter tokens elsewhere; exposed for tests and
    /// future index integration.
    #[must_use]
    pub fn type_code(&self) -> u8 {
        match self {
            TypeData::Login { .. } => 1,
            TypeData::Note {} => 2,
            TypeData::ApiKey { .. } => 3,
            TypeData::EnvSet { .. } => 4,
            TypeData::SshKey { .. } => 5,
            TypeData::Totp { .. } => 6,
        }
    }

    /// The type's string tag (the JSON `"type"` value).
    #[must_use]
    pub fn type_str(&self) -> &'static str {
        match self {
            TypeData::Login { .. } => "login",
            TypeData::Note {} => "note",
            TypeData::ApiKey { .. } => "api_key",
            TypeData::EnvSet { .. } => "env_set",
            TypeData::SshKey { .. } => "ssh_key",
            TypeData::Totp { .. } => "totp",
        }
    }
}

/// One `KEY=value` entry in an [`TypeData::EnvSet`]. Order-significant.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct EnvEntry {
    /// The variable name.
    pub key: String,
    /// The variable value.
    pub value: String,
}

/// The full canonical item payload.
///
/// This is the object encrypted into `item_versions.payload_env`. The `#[serde]`
/// attributes make its JSON shape exactly the vault-format.md §4 model:
///
/// - `v` (always [`PAYLOAD_VERSION`]) is present and, being the last key
///   alphabetically among the top-level keys we emit, sorts to the end in
///   compact output — the spec's "first-by-sort" intent is satisfied by `v`
///   being *always present*; its lexical position is a canonical-JSON detail,
///   not a semantic one.
/// - the `type` tag and type-specific fields come from the flattened
///   [`TypeData`].
#[derive(Clone, PartialEq, Serialize, Deserialize)]
pub struct ItemPayload {
    /// Payload schema version. Always [`PAYLOAD_VERSION`].
    pub v: u32,
    /// The item type and its type-specific data (flattened into the object).
    #[serde(flatten)]
    pub type_data: TypeData,
    /// The item title.
    pub title: String,
    /// Free-form notes (Markdown for `note` items; optional for others).
    #[serde(default)]
    pub notes: String,
    /// Tags (many per item).
    #[serde(default)]
    pub tags: Vec<String>,
    /// Whether the item is favorited.
    #[serde(default)]
    pub favorite: bool,
    /// The folder this item belongs to, if any (single-level).
    #[serde(default)]
    pub folder_id: Option<String>,
    /// Custom fields (text/hidden/url/date).
    #[serde(default)]
    pub fields: Vec<Field>,
}

impl ItemPayload {
    /// Construct a minimal payload of the given type with a title, defaulting
    /// all other fields to empty. A convenience for callers and tests.
    #[must_use]
    pub fn new(type_data: TypeData, title: impl Into<String>) -> Self {
        Self {
            v: PAYLOAD_VERSION,
            type_data,
            title: title.into(),
            notes: String::new(),
            tags: Vec::new(),
            favorite: false,
            folder_id: None,
            fields: Vec::new(),
        }
    }

    /// Serialize to canonical JSON bytes (vault-format.md §4).
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error`] if serialization fails or a float sneaks in
    /// (forbidden by our schema; see [`crate::canonical`]).
    pub fn to_canonical(&self) -> crate::Result<Vec<u8>> {
        crate::canonical::to_canonical_vec(self)
    }

    /// Parse from canonical JSON bytes.
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error::Serialization`] if the bytes are not a valid
    /// payload.
    pub fn from_canonical(bytes: &[u8]) -> crate::Result<Self> {
        crate::canonical::from_canonical_slice(bytes)
    }
}

impl core::fmt::Debug for ItemPayload {
    /// Redacting Debug: prints the type and structural counts only, **never**
    /// field values, notes, or the title text (all secret-adjacent).
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ItemPayload")
            .field("v", &self.v)
            .field("type", &self.type_data.type_str())
            .field("title", &"<redacted>")
            .field("tags", &self.tags.len())
            .field("fields", &self.fields.len())
            .field("favorite", &self.favorite)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn sample_login() -> ItemPayload {
        let mut p = ItemPayload::new(
            TypeData::Login {
                urls: vec!["https://alt.example".into()],
            },
            "ACME prod DB",
        );
        p.tags = vec!["prod".into(), "db".into()];
        p.fields = vec![
            Field {
                name: "username".into(),
                kind: FieldKind::Text,
                value: json!("svc_acme"),
            },
            Field {
                name: "password".into(),
                kind: FieldKind::Hidden,
                value: json!("s3cr3t"),
            },
            Field {
                name: "expires".into(),
                kind: FieldKind::Date,
                value: json!(1_788_134_400_000_i64),
            },
        ];
        p
    }

    #[test]
    fn roundtrip_all_six_types() {
        let payloads = vec![
            sample_login(),
            ItemPayload::new(TypeData::Note {}, "a note"),
            ItemPayload::new(
                TypeData::ApiKey {
                    key: "AKIA".into(),
                    secret: "shh".into(),
                    endpoint: "https://api".into(),
                    expiry: Some(1_788_134_400_000),
                    rotate_after: None,
                },
                "api",
            ),
            ItemPayload::new(
                TypeData::EnvSet {
                    entries: vec![
                        EnvEntry {
                            key: "A".into(),
                            value: "1".into(),
                        },
                        EnvEntry {
                            key: "B".into(),
                            value: "2".into(),
                        },
                    ],
                },
                "env",
            ),
            ItemPayload::new(
                TypeData::SshKey {
                    algo: "ed25519".into(),
                    private_pem: "-----BEGIN-----".into(),
                    public_openssh: "ssh-ed25519 AAAA".into(),
                    fingerprint: "SHA256:xxx".into(),
                },
                "ssh",
            ),
            ItemPayload::new(
                TypeData::Totp {
                    secret_b32: "JBSWY3DPEHPK3PXP".into(),
                    algo: "SHA1".into(),
                    digits: 6,
                    period: 30,
                    issuer: "ACME".into(),
                    account: "me@acme".into(),
                },
                "totp",
            ),
        ];
        for p in payloads {
            let bytes = p.to_canonical().unwrap();
            let back = ItemPayload::from_canonical(&bytes).unwrap();
            assert_eq!(p, back);
            // Re-serializing the parsed value is byte-identical (determinism).
            assert_eq!(bytes, back.to_canonical().unwrap());
        }
    }

    #[test]
    fn type_codes_match_spec() {
        assert_eq!(TypeData::Login { urls: vec![] }.type_code(), 1);
        assert_eq!(TypeData::Note {}.type_code(), 2);
        assert_eq!(
            TypeData::ApiKey {
                key: String::new(),
                secret: String::new(),
                endpoint: String::new(),
                expiry: None,
                rotate_after: None
            }
            .type_code(),
            3
        );
        assert_eq!(TypeData::EnvSet { entries: vec![] }.type_code(), 4);
    }

    #[test]
    fn env_set_preserves_order() {
        let p = ItemPayload::new(
            TypeData::EnvSet {
                entries: vec![
                    EnvEntry {
                        key: "Z".into(),
                        value: "1".into(),
                    },
                    EnvEntry {
                        key: "A".into(),
                        value: "2".into(),
                    },
                ],
            },
            "env",
        );
        let back = ItemPayload::from_canonical(&p.to_canonical().unwrap()).unwrap();
        if let TypeData::EnvSet { entries } = back.type_data {
            assert_eq!(entries[0].key, "Z");
            assert_eq!(entries[1].key, "A");
        } else {
            panic!("wrong type");
        }
    }

    #[test]
    fn debug_never_prints_secret_values() {
        let p = sample_login();
        let dbg = format!("{p:?}");
        assert!(!dbg.contains("s3cr3t"));
        assert!(!dbg.contains("svc_acme"));
        assert!(!dbg.contains("ACME prod DB"));
        assert!(dbg.contains("<redacted>"));
    }

    #[test]
    fn json_shape_has_type_tag() {
        let p = ItemPayload::new(TypeData::Note {}, "n");
        let s = String::from_utf8(p.to_canonical().unwrap()).unwrap();
        assert!(s.contains(r#""type":"note""#));
        assert!(s.contains(r#""v":1"#));
    }
}
