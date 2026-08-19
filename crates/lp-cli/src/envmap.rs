//! Building the resolved child-process environment for `localpass run` and
//! rendering an env-set for `localpass env export`.
//!
//! # Layering & precedence (PRD §4.8)
//!
//! `run` composes variables from several sources, later ones overriding earlier
//! ones on a key conflict:
//!
//! 1. `--env-set <item>` — every entry of an env-set item (repeatable; each
//!    later set overrides earlier ones).
//! 2. `--env-file <path>` — dotenv lines whose values may be *references*
//!    (resolved) or literals (passed through). Repeatable, applied in flag order
//!    after all `--env-set`s.
//! 3. `-e KEY=<reference>` — ad-hoc single mappings, highest precedence.
//!
//! The composed map is then merged onto the inherited parent environment
//! (resolved vars win), unless `--no-inherit` restricts the base to a documented
//! minimal passthrough.
//!
//! # Order preservation
//!
//! We keep an insertion-ordered map so `env export` and diagnostics are
//! deterministic: first-seen order, with an override updating the value in place
//! (not moving the key).

/// An insertion-ordered string→string map. Small N (a handful to a few hundred
/// vars), so a `Vec` with linear upsert is simpler and plenty fast, and keeps
/// first-seen order for deterministic output.
#[derive(Debug, Default, Clone)]
pub struct OrderedEnv {
    entries: Vec<(String, String)>,
}

impl OrderedEnv {
    /// A new empty map.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Insert or overwrite `key`, preserving the key's original position on
    /// overwrite (later layers override earlier values, not order).
    pub fn set(&mut self, key: impl Into<String>, value: impl Into<String>) {
        let key = key.into();
        let value = value.into();
        if let Some(slot) = self.entries.iter_mut().find(|(k, _)| *k == key) {
            slot.1 = value;
        } else {
            self.entries.push((key, value));
        }
    }

    /// Iterate entries in insertion order.
    pub fn iter(&self) -> impl Iterator<Item = (&str, &str)> {
        self.entries.iter().map(|(k, v)| (k.as_str(), v.as_str()))
    }
}

/// Environment variable names carried through under `--no-inherit` so the child
/// can still function (find its interpreter, a temp dir, a home). Documented in
/// the `run` `--help`.
///
/// Kept deliberately small: enough for a program to run, nothing that typically
/// carries ambient credentials.
pub const MINIMAL_PASSTHROUGH: &[&str] = &[
    "PATH",
    "SYSTEMROOT", // Windows: required for most DLL loads
    "SYSTEMDRIVE",
    "WINDIR",
    "TEMP",
    "TMP",
    "TMPDIR",
    "HOME",
    "USERPROFILE",
    "COMSPEC", // Windows: cmd.exe path, needed for `cmd /c`
];

/// Build the base environment onto which resolved vars are layered.
///
/// - `inherit == true`: a snapshot of the whole parent environment, **minus**
///   [`crate::unlock::PASSWORD_ENV`] — the master password is LocalPass's own
///   credential channel and is never a child's business; a child running `env`
///   (or logging its environment) must not be able to disclose it.
/// - `inherit == false`: only [`MINIMAL_PASSTHROUGH`] names that are actually
///   set in the parent.
#[must_use]
pub fn base_env(inherit: bool) -> OrderedEnv {
    if inherit {
        return inherit_filtered(std::env::vars());
    }
    let mut env = OrderedEnv::new();
    for name in MINIMAL_PASSTHROUGH {
        if let Ok(val) = std::env::var(name) {
            env.set(*name, val);
        }
    }
    env
}

/// The inherit-mode filter: every `(name, value)` pair except
/// [`crate::unlock::PASSWORD_ENV`]. Split from [`base_env`] so the filter is
/// testable against a synthetic environment (the crate forbids `unsafe`, so
/// tests cannot plant real process-env vars; `tests/run_and_env.rs` proves the
/// live path end-to-end).
fn inherit_filtered<I: IntoIterator<Item = (String, String)>>(vars: I) -> OrderedEnv {
    let mut env = OrderedEnv::new();
    for (k, v) in vars {
        if k == crate::unlock::PASSWORD_ENV {
            continue;
        }
        env.set(k, v);
    }
    env
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Collect the map into `(key, value)` pairs in insertion order.
    fn pairs(e: &OrderedEnv) -> Vec<(String, String)> {
        e.iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    #[test]
    fn inherit_filter_strips_the_master_password() {
        let vars = vec![
            ("PATH".to_string(), "/usr/bin".to_string()),
            (
                crate::unlock::PASSWORD_ENV.to_string(),
                "hunter2-test-only".to_string(),
            ),
            ("APP_MODE".to_string(), "dev".to_string()),
        ];
        let env = inherit_filtered(vars);
        assert_eq!(
            pairs(&env),
            vec![
                ("PATH".to_string(), "/usr/bin".to_string()),
                ("APP_MODE".to_string(), "dev".to_string()),
            ],
            "LOCALPASS_PASSWORD must be stripped; everything else passes through in order"
        );
        // The minimal passthrough list never contained it either.
        assert!(!MINIMAL_PASSTHROUGH.contains(&crate::unlock::PASSWORD_ENV));
    }

    #[test]
    fn set_overwrites_in_place_preserving_order() {
        let mut e = OrderedEnv::new();
        e.set("A", "1");
        e.set("B", "2");
        e.set("A", "3"); // overwrite A; must not move it after B.
        assert_eq!(
            pairs(&e),
            vec![
                ("A".to_string(), "3".to_string()),
                ("B".to_string(), "2".to_string()),
            ]
        );
    }

    #[test]
    fn set_appends_new_keys() {
        let mut e = OrderedEnv::new();
        assert!(pairs(&e).is_empty());
        e.set("X", "y");
        assert_eq!(pairs(&e), vec![("X".to_string(), "y".to_string())]);
    }
}
