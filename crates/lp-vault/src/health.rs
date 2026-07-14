//! Offline password-health analysis — the "Watchtower" check.
//!
//! Flags **weak**, **short**, **common**, and **reused** passwords across a
//! vault's items. It runs entirely offline (no network, no HIBP): strength is a
//! character-class entropy estimate, and reuse is detected by grouping equal
//! secret values *in memory*.
//!
//! # Secret boundary
//!
//! The analysis reads decrypted secret values (it must, to judge them), but the
//! [`PasswordHealth`] records it returns carry **only metadata** — item id,
//! title, field name, length, an entropy estimate, issue flags, and a reuse
//! group id. **No secret value is ever placed in a returned record**, so the
//! report is safe to cross the daemon IPC boundary and reach the GUI/CLI. The
//! only place a value is touched is inside [`analyze`], as a borrowed `&str`
//! used to compute entropy and to key a reuse map that is dropped on return.

use std::collections::HashMap;

use crate::ids::ItemId;
use crate::payload::FieldKind;
use crate::vault::Item;

/// Entropy (bits) at/above which a password is no longer "weak".
const WEAK_BITS: f64 = 50.0;
/// Entropy (bits) boundaries for the coarse strength label.
const FAIR_BITS: f64 = 50.0;
const STRONG_BITS: f64 = 66.0;
const EXCELLENT_BITS: f64 = 100.0;
/// Passwords shorter than this are flagged as short.
const SHORT_LEN: usize = 8;
/// Milliseconds in a day (for the age estimate).
const MS_PER_DAY: i64 = 86_400_000;

/// A single problem (or note) about a password. Orthogonal — a password can be
/// both `Short` and `Reused`, for example.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HealthIssue {
    /// Fewer than 8 characters.
    Short,
    /// Low estimated entropy.
    Weak,
    /// Appears in the bundled common-password list.
    Common,
    /// The same value is used by another item in this vault.
    Reused,
}

impl HealthIssue {
    /// A stable lowercase token for wire/JSON/CLI use.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            HealthIssue::Short => "short",
            HealthIssue::Weak => "weak",
            HealthIssue::Common => "common",
            HealthIssue::Reused => "reused",
        }
    }
}

/// A coarse strength bucket for the per-password meter (matches the GUI's
/// `weak`/`fair`/`strong`/`excellent` styles).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Strength {
    /// Low entropy, or short/common — should be changed.
    Weak,
    /// Middling entropy — acceptable but not great.
    Fair,
    /// Good entropy.
    Strong,
    /// Very high entropy (e.g. a long generated password).
    Excellent,
}

impl Strength {
    /// A stable lowercase token for wire/JSON/CLI use.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Strength::Weak => "weak",
            Strength::Fair => "fair",
            Strength::Strong => "strong",
            Strength::Excellent => "excellent",
        }
    }
}

/// The health verdict for one secret (`Hidden`) field of one item. Contains **no
/// secret value** — only the metadata needed to render a report.
#[derive(Clone, Debug, PartialEq)]
pub struct PasswordHealth {
    /// The owning item.
    pub item_id: ItemId,
    /// The item title (for display).
    pub title: String,
    /// The secret field's name (e.g. `password`).
    pub field: String,
    /// The value's length in characters.
    pub length: usize,
    /// The estimated entropy in bits (character-class heuristic).
    pub entropy_bits: f64,
    /// The coarse strength bucket.
    pub strength: Strength,
    /// Any issues found (may be empty for a healthy password).
    pub issues: Vec<HealthIssue>,
    /// A group id shared by every item that reuses this exact value; `None` when
    /// the value is unique in the vault.
    pub reuse_group: Option<u32>,
    /// Days since the item was last updated (a rough "age" signal), if known.
    pub age_days: Option<i64>,
}

impl PasswordHealth {
    /// Whether this password has any flagged issue.
    #[must_use]
    pub fn has_issue(&self) -> bool {
        !self.issues.is_empty()
    }
}

/// Estimate password entropy (bits) from the character classes present:
/// `length * log2(pool)`, where `pool` sums the sizes of each class the string
/// uses. This is the standard rough upper bound — it does **not** discount for
/// dictionary words or patterns (the common-password list and the short check
/// catch the worst of those). Empty input is 0 bits.
#[must_use]
pub fn estimate_entropy_bits(pw: &str) -> f64 {
    if pw.is_empty() {
        return 0.0;
    }
    let mut pool: u32 = 0;
    if pw.chars().any(|c| c.is_ascii_lowercase()) {
        pool += 26;
    }
    if pw.chars().any(|c| c.is_ascii_uppercase()) {
        pool += 26;
    }
    if pw.chars().any(|c| c.is_ascii_digit()) {
        pool += 10;
    }
    if pw
        .chars()
        .any(|c| c.is_ascii_graphic() && !c.is_ascii_alphanumeric())
    {
        pool += 32; // ASCII punctuation/symbols
    }
    if pw.chars().any(|c| c == ' ') {
        pool += 1;
    }
    if !pw.is_ascii() {
        pool += 100; // a conservative bucket for any non-ASCII/unicode
    }
    let n = pw.chars().count() as f64;
    n * f64::from(pool.max(1)).log2()
}

/// Whether `pw` (case-insensitively) is in the bundled common-password list.
#[must_use]
pub fn is_common(pw: &str) -> bool {
    use std::sync::OnceLock;
    static SET: OnceLock<std::collections::HashSet<&'static str>> = OnceLock::new();
    let set = SET.get_or_init(|| {
        include_str!("common_passwords.txt")
            .lines()
            .map(str::trim)
            .filter(|l| !l.is_empty() && !l.starts_with('#'))
            .collect()
    });
    set.contains(pw.to_ascii_lowercase().as_str())
}

/// Map an entropy estimate + issues to a coarse strength bucket. A `Common` or
/// `Short` password is always `Weak` regardless of raw entropy.
fn strength_of(entropy_bits: f64, issues: &[HealthIssue]) -> Strength {
    if issues
        .iter()
        .any(|i| matches!(i, HealthIssue::Common | HealthIssue::Short))
    {
        return Strength::Weak;
    }
    if entropy_bits < FAIR_BITS {
        Strength::Weak
    } else if entropy_bits < STRONG_BITS {
        Strength::Fair
    } else if entropy_bits < EXCELLENT_BITS {
        Strength::Strong
    } else {
        Strength::Excellent
    }
}

/// Analyze the `Hidden` fields of `items` for password health, at reference time
/// `now_millis` (for the age estimate). Returns one [`PasswordHealth`] per secret
/// field, in item/field order. Reuse is detected *within this set* (typically one
/// vault) by grouping equal values.
///
/// The returned records carry no secret values (see the module secret-boundary
/// note). Passing the same `now_millis` to two runs over the same items yields
/// identical output (deterministic reuse-group ids by first occurrence).
#[must_use]
pub fn analyze(items: &[Item], now_millis: i64) -> Vec<PasswordHealth> {
    // First pass: one record per Hidden field, plus a borrowed value we use only
    // locally (for entropy already computed, and reuse grouping below).
    let mut records: Vec<PasswordHealth> = Vec::new();
    let mut values: Vec<&str> = Vec::new();
    let mut counts: HashMap<&str, usize> = HashMap::new();

    for item in items {
        for f in &item.payload.fields {
            if f.kind != FieldKind::Hidden {
                continue;
            }
            let Some(val) = f.value.as_str() else {
                continue;
            };
            if val.is_empty() {
                continue;
            }
            let length = val.chars().count();
            let entropy_bits = estimate_entropy_bits(val);
            let mut issues = Vec::new();
            if length < SHORT_LEN {
                issues.push(HealthIssue::Short);
            }
            let common = is_common(val);
            if common {
                issues.push(HealthIssue::Common);
            }
            if entropy_bits < WEAK_BITS && !common {
                issues.push(HealthIssue::Weak);
            }
            let age_days = Some((now_millis - item.updated_at).max(0) / MS_PER_DAY);
            *counts.entry(val).or_insert(0) += 1;
            values.push(val);
            records.push(PasswordHealth {
                item_id: item.item_id,
                title: item.payload.title.clone(),
                field: f.name.clone(),
                length,
                entropy_bits,
                strength: strength_of(entropy_bits, &issues),
                issues,
                reuse_group: None,
                age_days,
            });
        }
    }

    // Second pass: assign a stable reuse-group id to every value shared by more
    // than one field, in first-occurrence order.
    let mut next_group: u32 = 0;
    let mut assigned: HashMap<&str, u32> = HashMap::new();
    for (i, &val) in values.iter().enumerate() {
        if counts.get(val).copied().unwrap_or(0) > 1 {
            let gid = *assigned.entry(val).or_insert_with(|| {
                let g = next_group;
                next_group += 1;
                g
            });
            records[i].reuse_group = Some(gid);
            records[i].issues.push(HealthIssue::Reused);
        }
    }

    records
}

/// A compact summary of a health report (for headers / the CLI one-liner).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct HealthSummary {
    /// Total secret fields analyzed.
    pub total: usize,
    /// Fields flagged weak (low entropy).
    pub weak: usize,
    /// Fields flagged short.
    pub short: usize,
    /// Fields flagged as a common password.
    pub common: usize,
    /// Fields that reuse a value used elsewhere.
    pub reused: usize,
    /// Fields with at least one issue.
    pub flagged: usize,
}

/// Summarize a health report.
#[must_use]
pub fn summarize(report: &[PasswordHealth]) -> HealthSummary {
    let mut s = HealthSummary {
        total: report.len(),
        ..HealthSummary::default()
    };
    for r in report {
        if r.has_issue() {
            s.flagged += 1;
        }
        for issue in &r.issues {
            match issue {
                HealthIssue::Weak => s.weak += 1,
                HealthIssue::Short => s.short += 1,
                HealthIssue::Common => s.common += 1,
                HealthIssue::Reused => s.reused += 1,
            }
        }
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::payload::{Field, ItemPayload, TypeData};

    fn login_item(id_byte: u8, title: &str, password: &str, updated_at: i64) -> Item {
        let mut payload = ItemPayload::new(TypeData::Login { urls: vec![] }, title);
        payload.fields.push(Field {
            name: "password".into(),
            kind: FieldKind::Hidden,
            value: serde_json::json!(password),
        });
        Item {
            item_id: ItemId::from_bytes([id_byte; 16]),
            current_version: 1,
            created_at: 0,
            updated_at,
            payload,
        }
    }

    #[test]
    fn entropy_grows_with_length_and_classes() {
        let short = estimate_entropy_bits("abc");
        let longer = estimate_entropy_bits("abcdefghij");
        assert!(longer > short);
        // Adding classes widens the pool → more bits for the same length.
        assert!(estimate_entropy_bits("aaaaaaaa") < estimate_entropy_bits("aA1!aA1!"));
        assert_eq!(estimate_entropy_bits(""), 0.0);
    }

    #[test]
    fn common_password_is_detected_case_insensitively() {
        assert!(is_common("password"));
        assert!(is_common("PASSWORD"));
        assert!(is_common("123456"));
        assert!(!is_common("Zt9$k!mQ2wLx7&vB"));
    }

    #[test]
    fn flags_weak_short_and_common() {
        let items = [login_item(1, "Weak", "abc", 0)];
        let report = analyze(&items, 10 * MS_PER_DAY);
        assert_eq!(report.len(), 1);
        let r = &report[0];
        assert!(r.issues.contains(&HealthIssue::Short));
        assert!(r.issues.contains(&HealthIssue::Weak));
        assert_eq!(r.strength, Strength::Weak);
        assert_eq!(r.age_days, Some(10));
    }

    #[test]
    fn detects_reuse_and_groups_deterministically() {
        let items = [
            login_item(1, "A", "sameSecret123", 0),
            login_item(2, "B", "uniqueOne!$xZ", 0),
            login_item(3, "C", "sameSecret123", 0),
        ];
        let report = analyze(&items, 0);
        // A and C share a group; B has none.
        assert_eq!(report[0].reuse_group, Some(0));
        assert_eq!(report[2].reuse_group, Some(0));
        assert_eq!(report[1].reuse_group, None);
        assert!(report[0].issues.contains(&HealthIssue::Reused));
        assert!(report[2].issues.contains(&HealthIssue::Reused));
        // Deterministic across runs.
        let again = analyze(&items, 0);
        assert_eq!(report, again);
    }

    #[test]
    fn strong_unique_password_has_no_issues() {
        let items = [login_item(1, "Strong", "Zt9$k!mQ2wLx7&vB3nR#", 0)];
        let report = analyze(&items, 0);
        assert!(!report[0].has_issue(), "issues: {:?}", report[0].issues);
        assert!(matches!(
            report[0].strength,
            Strength::Strong | Strength::Excellent
        ));
    }

    #[test]
    fn summary_counts_issue_types() {
        let items = [
            login_item(1, "A", "abc", 0),                  // short + weak
            login_item(2, "B", "password", 0),             // common
            login_item(3, "C", "Zt9$k!mQ2wLx7&vB3nR#", 0), // healthy
        ];
        let report = analyze(&items, 0);
        let s = summarize(&report);
        assert_eq!(s.total, 3);
        assert!(s.weak >= 1);
        assert!(s.short >= 1);
        assert_eq!(s.common, 1);
        assert_eq!(s.flagged, 2);
    }
}
