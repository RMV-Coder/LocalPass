//! `localpass health` — offline password-health audit (the "Watchtower" check).
//!
//! Flags **weak**, **short**, **common**, and **reused** passwords across a
//! vault. Runs entirely offline (no network / HIBP). **Never prints a secret
//! value** — only per-field metadata (title, field name, length, an entropy
//! estimate, and issue flags), mirroring the daemon's `PasswordHealth` boundary.

use std::path::Path;

use anyhow::{Result, bail};
use serde_json::json;

use crate::daemonctl::{self, Route};
use crate::error::{CliError, map_vault_error};
use crate::resolve;
use crate::unlock::{self, PasswordSource};

use lp_daemon::protocol::{Request, Response, WirePasswordHealth};

/// A print-ready health row — unifies the daemon wire type and the direct
/// `lp-vault` type. Carries no secret value.
struct Row {
    title: String,
    field: String,
    length: usize,
    entropy_bits: f64,
    strength: String,
    issues: Vec<String>,
    reuse_group: Option<u32>,
    age_days: Option<i64>,
}

impl Row {
    fn from_wire(w: WirePasswordHealth) -> Self {
        Self {
            title: w.title,
            field: w.field,
            length: w.length,
            entropy_bits: w.entropy_bits,
            strength: w.strength,
            issues: w.issues,
            reuse_group: w.reuse_group,
            age_days: w.age_days,
        }
    }

    fn from_vault(h: &lp_vault::health::PasswordHealth) -> Self {
        Self {
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
}

/// Run `localpass health` (daemon-first, direct fallback).
///
/// # Errors
///
/// Propagates unlock and storage failures; `CliError::Usage` if the vault is
/// unknown.
pub fn run(
    profile_dir: &Path,
    src: PasswordSource,
    no_daemon: bool,
    vault_ref: &str,
    json_out: bool,
) -> Result<()> {
    let rows: Vec<Row> = match daemonctl::route(profile_dir, no_daemon) {
        Route::Proxy(mut client) => {
            let resp = daemonctl::call(
                &mut client,
                &Request::PasswordHealth {
                    profile: profile_dir.display().to_string(),
                    vault: vault_ref.to_string(),
                },
            )?;
            daemonctl::check_error(&resp)?;
            let Response::PasswordHealth { entries } = resp else {
                bail!(CliError::internal(anyhow::anyhow!(
                    "unexpected daemon response: {}",
                    resp.kind()
                )));
            };
            entries.into_iter().map(Row::from_wire).collect()
        }
        Route::Direct => {
            let (session, _sk) = unlock::unlock(profile_dir, src)?;
            let vault = resolve::open_vault(&session, vault_ref)?;
            let report = vault.password_health().map_err(map_vault_error)?;
            report.iter().map(Row::from_vault).collect()
        }
    };

    if json_out {
        print_json(&rows);
    } else {
        print_human(&rows);
    }
    Ok(())
}

/// Count issues across the report (a field can have several).
fn count(rows: &[Row], token: &str) -> usize {
    rows.iter()
        .filter(|r| r.issues.iter().any(|i| i == token))
        .count()
}

fn print_human(rows: &[Row]) {
    let total = rows.len();
    let weak = count(rows, "weak");
    let short = count(rows, "short");
    let common = count(rows, "common");
    let reused = count(rows, "reused");
    let flagged = rows.iter().filter(|r| !r.issues.is_empty()).count();

    println!(
        "{total} password{} checked · {weak} weak · {reused} reused · {common} common · {short} short",
        if total == 1 { "" } else { "s" }
    );

    if flagged == 0 {
        println!("All passwords look healthy. \u{2713}");
        return;
    }

    println!();
    // Flagged fields, weakest first (lowest entropy), then by title.
    let mut flagged_rows: Vec<&Row> = rows.iter().filter(|r| !r.issues.is_empty()).collect();
    flagged_rows.sort_by(|a, b| {
        a.entropy_bits
            .partial_cmp(&b.entropy_bits)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then_with(|| a.title.cmp(&b.title))
    });
    for r in flagged_rows {
        let field = if r.field == "password" {
            String::new()
        } else {
            format!(" [{}]", r.field)
        };
        let age = match r.age_days {
            Some(d) if d >= 1 => format!(", {d}d old"),
            _ => String::new(),
        };
        println!(
            "  {:<28}{field}  {:<9} {:>5.0} bits, {} chars{age}  — {}",
            truncate(&r.title, 28),
            r.strength,
            r.entropy_bits,
            r.length,
            r.issues.join(", "),
        );
    }
    println!(
        "\nNo secret values are shown. Re-generate weak or reused passwords with `localpass generate`."
    );
}

fn print_json(rows: &[Row]) {
    let entries: Vec<_> = rows
        .iter()
        .map(|r| {
            json!({
                "title": r.title,
                "field": r.field,
                "length": r.length,
                "entropy_bits": r.entropy_bits,
                "strength": r.strength,
                "issues": r.issues,
                "reuse_group": r.reuse_group,
                "age_days": r.age_days,
            })
        })
        .collect();
    let summary = json!({
        "total": rows.len(),
        "weak": count(rows, "weak"),
        "short": count(rows, "short"),
        "common": count(rows, "common"),
        "reused": count(rows, "reused"),
        "flagged": rows.iter().filter(|r| !r.issues.is_empty()).count(),
    });
    let out = json!({ "summary": summary, "entries": entries });
    match serde_json::to_string_pretty(&out) {
        Ok(s) => println!("{s}"),
        Err(e) => eprintln!("error serializing health report: {e}"),
    }
}

/// Truncate a title to `max` chars with an ellipsis, for the aligned table.
fn truncate(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        s.to_string()
    } else {
        let mut out: String = s.chars().take(max.saturating_sub(1)).collect();
        out.push('\u{2026}');
        out
    }
}
