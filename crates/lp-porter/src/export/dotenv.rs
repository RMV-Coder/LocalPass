//! dotenv export — one env-set item → `KEY=value` lines (PRD §4.8).
//!
//! This is the **library** serialization only. The CLI already owns the
//! `localpass env export` command (with its file/stdout, shell, and json
//! variants); this function exists so that command (and the porter) share one
//! dotenv renderer. It does not duplicate the CLI command.
//!
//! Values are emitted verbatim (no interpolation), one `KEY=value` per line, in
//! the env-set's stored order.

use lp_vault::ItemPayload;
use lp_vault::payload::{EnvEntry, TypeData};

use crate::error::{PorterError, Result};

/// Render an env-set item to dotenv `KEY=value\n` lines.
///
/// # Errors
///
/// [`PorterError::Other`] if `item` is not an env-set.
pub fn to_dotenv(item: &ItemPayload) -> Result<String> {
    match &item.type_data {
        TypeData::EnvSet { entries } => Ok(render(entries)),
        other => Err(PorterError::other(format!(
            "not an env-set item (type {})",
            other.type_str()
        ))),
    }
}

/// Render entries to `KEY=value\n` lines.
fn render(entries: &[EnvEntry]) -> String {
    let mut s = String::new();
    for e in entries {
        s.push_str(&e.key);
        s.push('=');
        s.push_str(&e.value);
        s.push('\n');
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn renders_key_equals_value_in_order() {
        let item = ItemPayload::new(
            TypeData::EnvSet {
                entries: vec![
                    EnvEntry {
                        key: "Z".into(),
                        value: "1".into(),
                    },
                    EnvEntry {
                        key: "A".into(),
                        value: "two words".into(),
                    },
                ],
            },
            "env",
        );
        assert_eq!(to_dotenv(&item).unwrap(), "Z=1\nA=two words\n");
    }

    #[test]
    fn non_env_set_errors() {
        let item = ItemPayload::new(TypeData::Note {}, "note");
        assert!(to_dotenv(&item).is_err());
    }
}
