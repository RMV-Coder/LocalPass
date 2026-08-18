//! The **masking choke point** for everything the MCP server renders.
//!
//! Structural, not conventional (the pattern LESSONS.md records for the GUI's
//! `model::item_view_masked`): an item leaves this module only as a
//! [`MaskedItem`], and the *only* way to build one is [`item_view_masked`],
//! which consumes the raw [`ItemView`] and **drops** every secret value. No
//! call site can forget to mask, because no call site is handed a serializable
//! type that still carries the value.
//!
//! The mask string is [`crate::output::MASK`], the same one `item get` prints,
//! so an agent sees exactly what a human sees in the terminal.

use serde::Serialize;

use crate::output::MASK;

/// One field as it comes **out of the vault** — value still raw.
///
/// Deliberately **not** `Serialize`: a raw view can never be written to the
/// wire by accident. It must go through [`item_view_masked`] first.
pub struct FieldView {
    /// The field name (`username`, `password`, an env-set entry key, …).
    pub name: String,
    /// The raw value.
    pub value: String,
    /// Whether the field is secret.
    pub secret: bool,
}

/// One item as it comes out of the vault — field values still raw.
///
/// Deliberately **not** `Serialize`; see [`FieldView`].
pub struct ItemView {
    /// Hyphenated item id.
    pub id: String,
    /// The item title.
    pub title: String,
    /// The item type string (`login`, `env_set`, …).
    pub type_str: String,
    /// The current version number.
    pub version: i64,
    /// Creation time (unix millis).
    pub created_at: i64,
    /// Last-update time (unix millis).
    pub updated_at: i64,
    /// Tags.
    pub tags: Vec<String>,
    /// Favorite flag.
    pub favorite: bool,
    /// Notes body.
    pub notes: String,
    /// Flattened display fields, values raw.
    pub fields: Vec<FieldView>,
}

/// One field as the MCP server renders it: a name, a secrecy flag, and a value
/// that is the mask whenever the field is secret.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct MaskedField {
    /// The field name.
    pub name: String,
    /// Whether the field is secret (and therefore masked).
    pub secret: bool,
    /// The mask for a secret field; the plain value for a non-secret one.
    pub value: String,
}

/// An item rendered for an MCP tool result. Constructible **only** via
/// [`item_view_masked`], so it can never carry a secret value.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct MaskedItem {
    /// Hyphenated item id.
    pub id: String,
    /// The item title.
    pub title: String,
    /// The item type string.
    #[serde(rename = "type")]
    pub type_str: String,
    /// The current version number.
    pub version: i64,
    /// Creation time (unix millis).
    pub created_at: i64,
    /// Last-update time (unix millis).
    pub updated_at: i64,
    /// Tags.
    pub tags: Vec<String>,
    /// Favorite flag.
    pub favorite: bool,
    /// Notes body.
    pub notes: String,
    /// Field names + secrecy flags; secret values are masked.
    pub fields: Vec<MaskedField>,
}

/// **The choke point.** Consume a raw [`ItemView`] and produce the only
/// serializable item shape the MCP server has, dropping every secret value.
///
/// A secret field's value is replaced by [`MASK`] — including when it is empty,
/// unlike `item get`'s renderer: an empty-vs-non-empty distinction is a (small)
/// oracle, and an agent has no use for it.
#[must_use]
pub fn item_view_masked(view: ItemView) -> MaskedItem {
    MaskedItem {
        id: view.id,
        title: view.title,
        type_str: view.type_str,
        version: view.version,
        created_at: view.created_at,
        updated_at: view.updated_at,
        tags: view.tags,
        favorite: view.favorite,
        notes: view.notes,
        fields: view
            .fields
            .into_iter()
            .map(|f| MaskedField {
                name: f.name,
                secret: f.secret,
                // `f.value` is moved only on the non-secret branch; on the
                // secret branch it is dropped here and never observed again.
                value: if f.secret { MASK.to_string() } else { f.value },
            })
            .collect(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn view() -> ItemView {
        ItemView {
            id: "018f-abc".into(),
            title: "Prod DB".into(),
            type_str: "login".into(),
            version: 3,
            created_at: 1,
            updated_at: 2,
            tags: vec!["db".into()],
            favorite: true,
            notes: "reachable from the bastion".into(),
            fields: vec![
                FieldView {
                    name: "username".into(),
                    value: "alice".into(),
                    secret: false,
                },
                FieldView {
                    name: "password".into(),
                    value: "hunter2-super-secret".into(),
                    secret: true,
                },
                FieldView {
                    name: "empty_secret".into(),
                    value: String::new(),
                    secret: true,
                },
            ],
        }
    }

    #[test]
    fn secret_values_are_replaced_by_the_mask() {
        let m = item_view_masked(view());
        let pw = m.fields.iter().find(|f| f.name == "password").unwrap();
        assert!(pw.secret);
        assert_eq!(pw.value, MASK);
    }

    #[test]
    fn non_secret_values_survive() {
        let m = item_view_masked(view());
        let user = m.fields.iter().find(|f| f.name == "username").unwrap();
        assert!(!user.secret);
        assert_eq!(user.value, "alice");
    }

    #[test]
    fn empty_secret_is_masked_too_no_length_oracle() {
        let m = item_view_masked(view());
        let e = m.fields.iter().find(|f| f.name == "empty_secret").unwrap();
        assert_eq!(e.value, MASK, "an empty secret must not be distinguishable");
    }

    #[test]
    fn field_names_and_metadata_are_preserved() {
        let m = item_view_masked(view());
        let names: Vec<&str> = m.fields.iter().map(|f| f.name.as_str()).collect();
        assert_eq!(names, ["username", "password", "empty_secret"]);
        assert_eq!(m.title, "Prod DB");
        assert_eq!(m.type_str, "login");
        assert_eq!(m.version, 3);
        assert!(m.favorite);
        assert_eq!(m.tags, ["db"]);
    }

    /// The property that actually matters, asserted at the **serialization
    /// boundary**: the JSON the agent would receive never contains the planted
    /// secret, even though the source view did.
    #[test]
    fn serialized_json_never_contains_a_planted_secret() {
        let m = item_view_masked(view());
        let json = serde_json::to_string(&m).unwrap();
        assert!(
            !json.contains("hunter2-super-secret"),
            "masked JSON leaked a secret: {json}"
        );
        assert!(json.contains("password"), "field NAME must survive: {json}");
    }
}
