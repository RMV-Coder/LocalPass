//! Canonical JSON serialization — a deterministic byte encoding for item
//! payloads (vault-format.md §4).
//!
//! # Why determinism matters
//!
//! The canonical bytes of an item payload feed AEAD (as `item_versions`
//! plaintext) and, inside the enclosing op, an Ed25519 signature
//! (sync-protocol.md §1). The *same logical item* must always produce the *same
//! bytes* on any device, or signatures and cross-device convergence break. This
//! module is that guarantee.
//!
//! # The rules (a pragmatic RFC 8785 / JCS profile)
//!
//! We serialize a [`serde_json::Value`] with:
//!
//! - **object member keys sorted** — `serde_json`'s `preserve_order` feature is
//!   *off*, so its `Map` is a [`std::collections::BTreeMap`] and iterates keys in
//!   sorted order. We serialize compactly, so the emitted key order is exactly
//!   the `BTreeMap` order.
//! - **no insignificant whitespace** — `serde_json::to_vec` (compact) emits none.
//! - **integers only** — our schema uses integers (unix-millis timestamps, enum
//!   codes, counts) and strings/bools/null/arrays; there are **no floats**, so
//!   the JCS number-canonicalization edge cases (exponent form, `-0`,
//!   ES6 `Number.prototype.toString`) never arise. This is enforced by a
//!   float-rejection pass run on every canonicalization.
//! - **strings UTF-8, serde_json escaping** — see the deviation note below.
//! - **top-level `"v"` present** — the payload model always includes `v: 1`.
//!
//! # Key-sort basis: a documented JCS deviation
//!
//! RFC 8785 sorts object keys by **UTF-16 code unit**. `BTreeMap<String, _>`
//! sorts by Rust's `str` `Ord`, i.e. by **UTF-8 byte sequence**, which is
//! equivalently ordered by **Unicode scalar value (code point)**. For the Basic
//! Multilingual Plane (all our field names, and any realistic user key) UTF-16
//! code-unit order and code-point order **coincide**, so the two agree. They can
//! diverge only for keys containing supplementary-plane characters (U+10000 and
//! above), where UTF-16 surrogate pairs (0xD800–0xDFFF units) sort *before* BMP
//! characters in the range U+E000–U+FFFF. LocalPass object keys are fixed schema
//! names plus user-defined custom-field `name`s; a supplementary-plane field
//! name is exotic but *possible*. We accept UTF-8/code-point order as our
//! canonical basis (documented here) because: (a) it is deterministic and stable
//! across every platform, which is the property AEAD/signatures actually need;
//! (b) `lp-vault` is the sole producer *and* consumer of these bytes within the
//! trust boundary, so there is no second independent JCS implementation that
//! must agree with us; and (c) restricting keys to the BMP would be a silent
//! data-loss footgun for legitimate Unicode field names. If a future interop
//! requirement forces strict RFC 8785, the only change is a custom serializer
//! that re-sorts sibling keys by UTF-16 units — the payload model and every
//! other layer are unaffected.
//!
//! # String-escaping note
//!
//! `serde_json` escapes exactly the JSON-mandatory characters (`"`, `\`, and C0
//! controls U+0000–U+001F, the last as `\u00XX` with lowercase hex) and emits
//! every other code point — including all non-ASCII — as raw UTF-8. RFC 8785
//! mandates the same minimal escaping with lowercase `\u` hex. This is therefore
//! JCS-conformant for strings; the determinism tests below pin it for non-ASCII
//! and control characters.

use serde::Serialize;
use serde_json::Value;

use crate::error::{Error, Result};

/// Serialize a value to canonical JSON bytes.
///
/// The value is first converted to a [`serde_json::Value`] (which normalizes
/// object keys into a sorted `BTreeMap`), checked to contain no floating-point
/// numbers, then compactly re-serialized. The result is deterministic: the same
/// logical value always yields byte-identical output.
///
/// # Errors
///
/// - [`Error::Serialization`] if the value cannot be represented as JSON.
/// - [`Error::Invalid`] if the value contains a floating-point number (our
///   schema forbids floats so the JCS number edge cases cannot arise).
pub fn to_canonical_vec<T: Serialize>(value: &T) -> Result<Vec<u8>> {
    // `to_value` moves everything into serde_json's Map (a BTreeMap, since
    // `preserve_order` is off), giving sorted keys for free.
    let v: Value = serde_json::to_value(value)?;
    assert_no_floats(&v)?;
    // Compact form: no whitespace, keys already sorted by the BTreeMap.
    let bytes = serde_json::to_vec(&v)?;
    Ok(bytes)
}

/// Parse canonical JSON bytes back into a deserializable type.
///
/// The inverse of [`to_canonical_vec`] for round-tripping stored payloads.
///
/// # Errors
///
/// Returns [`Error::Serialization`] if the bytes are not valid JSON for `T`.
pub fn from_canonical_slice<T: serde::de::DeserializeOwned>(bytes: &[u8]) -> Result<T> {
    Ok(serde_json::from_slice(bytes)?)
}

/// Reject any floating-point number anywhere in the value tree.
///
/// Our payload schema is integers-only (vault-format.md §4). Enforcing this
/// makes the "no float canonicalization edge cases" claim a checked invariant
/// rather than a hope: a float would otherwise let `serde_json`'s number
/// formatting (not guaranteed to match JCS's ES6 rule) into our canonical bytes.
fn assert_no_floats(v: &Value) -> Result<()> {
    match v {
        Value::Number(n) => {
            if n.is_f64() {
                Err(Error::Invalid(
                    "canonical JSON forbids floating-point numbers",
                ))
            } else {
                Ok(())
            }
        }
        Value::Array(items) => items.iter().try_for_each(assert_no_floats),
        Value::Object(map) => map.values().try_for_each(assert_no_floats),
        _ => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn keys_are_sorted_regardless_of_input_order() {
        let a = json!({ "b": 1, "a": 2, "c": 3 });
        let b = json!({ "c": 3, "a": 2, "b": 1 });
        assert_eq!(to_canonical_vec(&a).unwrap(), to_canonical_vec(&b).unwrap());
        assert_eq!(to_canonical_vec(&a).unwrap(), br#"{"a":2,"b":1,"c":3}"#);
    }

    #[test]
    fn no_insignificant_whitespace() {
        let v = json!({ "x": [1, 2], "y": { "z": 3 } });
        let bytes = to_canonical_vec(&v).unwrap();
        let s = String::from_utf8(bytes).unwrap();
        assert!(!s.contains(' '));
        assert!(!s.contains('\n'));
    }

    #[test]
    fn nested_objects_are_recursively_sorted() {
        let a = json!({ "outer": { "b": 1, "a": 2 } });
        let b = json!({ "outer": { "a": 2, "b": 1 } });
        assert_eq!(to_canonical_vec(&a).unwrap(), to_canonical_vec(&b).unwrap());
    }

    #[test]
    fn sorted_order_is_stable() {
        let v = json!({ "v": 1, "type": "note", "a": 0 });
        let s = String::from_utf8(to_canonical_vec(&v).unwrap()).unwrap();
        // Sorted order among {"a","type","v"} is a < type < v.
        assert_eq!(s, r#"{"a":0,"type":"note","v":1}"#);
    }

    #[test]
    fn non_ascii_strings_are_deterministic_and_raw_utf8() {
        // Same logical content, distinct construction paths -> identical bytes.
        // Uses \u{..} escapes in the SOURCE so no raw multibyte chars are typed.
        let accented = "caf\u{e9} \u{2014} \u{65e5}\u{672c}\u{8a9e} \u{20ac}";
        let lock = "\u{1f510}";
        let a = json!({ "name": accented, "emoji": lock });
        let mut b_src = String::new();
        b_src.push_str("{\"emoji\":\"");
        b_src.push_str(lock);
        b_src.push_str("\",\"name\":\"");
        b_src.push_str(accented);
        b_src.push_str("\"}");
        let b: Value = serde_json::from_str(&b_src).unwrap();
        let ba = to_canonical_vec(&a).unwrap();
        let bb = to_canonical_vec(&b).unwrap();
        assert_eq!(ba, bb);
        // Non-ASCII is emitted as raw UTF-8, not \u escapes.
        let s = String::from_utf8(ba).unwrap();
        assert!(s.contains("caf\u{e9}"));
        assert!(s.contains(lock));
    }

    #[test]
    fn control_chars_use_lowercase_u_escapes() {
        // Field value: 'a', NUL, SOH, TAB, LF, quote, backslash, 'b'.
        let value = "a\u{0000}\u{0001}\t\n\"\\b";
        let v = json!({ "s": value });
        let s = String::from_utf8(to_canonical_vec(&v).unwrap()).unwrap();
        // serde_json emits: {"s":"a \t\n\"\\b"} — every backslash below
        // is doubled in the Rust literal so the runtime string is that JSON text.
        let expected = "{\"s\":\"a\\u0000\\u0001\\t\\n\\\"\\\\b\"}";
        assert_eq!(s, expected);
    }

    #[test]
    fn floats_are_rejected() {
        let v = json!({ "x": 1.5 });
        assert!(matches!(to_canonical_vec(&v), Err(Error::Invalid(_))));
    }

    #[test]
    fn large_integers_are_preserved_not_floated() {
        // Unix-millis in 2026 (~1.75e12) and beyond must stay integers.
        let v = json!({ "t": 1_788_134_400_000_i64 });
        let s = String::from_utf8(to_canonical_vec(&v).unwrap()).unwrap();
        assert_eq!(s, r#"{"t":1788134400000}"#);
    }
}
