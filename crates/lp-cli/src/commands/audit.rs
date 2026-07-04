//! `localpass audit` — show the device-local audit log (PRD §4.9).
//!
//! # Routing
//!
//! Audit always unlocks **directly** (never proxied): the log lives in the
//! account store, reachable from any unlocked [`Session`] on this device, and the
//! MVP daemon protocol has no audit-read request. `--no-daemon` is a no-op here.
//!
//! # What prints
//!
//! Records print **oldest-first** (chronological — the natural reading order for
//! "what happened, in order", and the order the hash chain is built in). Each row
//! is `timestamp  kind  ids  detail`; a `--json` array carries the same fields in
//! a stable shape. The log holds only non-secret metadata (ids, kinds,
//! timestamps) — this command can never print a secret because there are none in
//! the log ([`lp_vault::audit`]).
//!
//! # `--verify`
//!
//! Re-runs [`Session::verify_audit_chain`], which checks per-device `seq`
//! gaplessness and every `prev_hash` link. On an intact chain it prints an OK line
//! and exits 0; on a tampered/reordered/deleted record it exits non-zero (exit 1)
//! with a clear message — the tamper-evidence the hash chain buys.

use std::path::Path;

use anyhow::{Result, bail};
use lp_vault::{AuditKind, AuditRecord, Session};
use serde_json::json;

use crate::cli::AuditArgs;
use crate::error::{CliError, map_vault_error};
use crate::timestamp::format_millis_utc;
use crate::unlock::{self, PasswordSource};

/// Run `localpass audit`.
///
/// # Errors
///
/// - [`CliError::Usage`] (exit 1) on a bad `--since`, or when `--verify` finds a
///   broken chain.
/// - [`CliError::Auth`] (exit 2) on a wrong master password / Secret Key.
pub fn run(profile_dir: &Path, src: PasswordSource, args: &AuditArgs) -> Result<()> {
    let (session, _sk) = unlock::unlock(profile_dir, src)?;

    if args.verify {
        return verify(&session);
    }

    let since_ms = match &args.since {
        Some(spec) => Some(parse_since(spec)?),
        None => None,
    };
    let records = match since_ms {
        Some(floor) => session.audit_since(floor).map_err(map_vault_error)?,
        None => session.audit_iter().map_err(map_vault_error)?,
    };

    if args.json {
        let arr: Vec<_> = records.iter().map(record_to_json).collect();
        println!("{}", serde_json::to_string_pretty(&arr)?);
    } else if records.is_empty() {
        println!("(no audit records)");
    } else {
        print_table(&records);
    }
    Ok(())
}

/// `--verify`: re-check the hash chain; exit 0 if intact, non-zero on tamper.
fn verify(session: &Session) -> Result<()> {
    match session.verify_audit_chain() {
        Ok(()) => {
            let n = session.audit_iter().map_err(map_vault_error)?.len();
            println!("audit chain OK ({n} record(s), hash chain and sequence intact)");
            Ok(())
        }
        Err(lp_vault::Error::ChainVerification(what)) => {
            // A broken chain is a usage-level failure surfaced with a clear,
            // non-zero exit — the tamper signal the log exists to provide.
            bail!(CliError::usage(format!(
                "audit chain verification FAILED: {what}"
            )))
        }
        Err(e) => Err(map_vault_error(e).into()),
    }
}

/// Parse `--since`: a suffixed duration (`7d`/`24h`/`30m`/`90s`) is relative
/// (`now - duration`); a bare integer is an absolute unix-millis timestamp.
fn parse_since(spec: &str) -> Result<i64> {
    let spec = spec.trim();
    if spec.is_empty() {
        bail!(CliError::usage("empty --since value"));
    }
    let (num_part, unit_ms): (&str, Option<i64>) = if let Some(n) = spec.strip_suffix('d') {
        (n, Some(24 * 60 * 60 * 1000))
    } else if let Some(n) = spec.strip_suffix('h') {
        (n, Some(60 * 60 * 1000))
    } else if let Some(n) = spec.strip_suffix('m') {
        (n, Some(60 * 1000))
    } else if let Some(n) = spec.strip_suffix('s') {
        (n, Some(1000))
    } else {
        // No unit suffix → an absolute unix-millis timestamp.
        (spec, None)
    };
    let value: i64 = num_part
        .trim()
        .parse()
        .map_err(|_| CliError::usage(format!("invalid --since value {spec:?}")))?;
    if value < 0 {
        bail!(CliError::usage("--since must not be negative"));
    }
    match unit_ms {
        // Relative duration back from now.
        Some(unit) => {
            let delta = value.saturating_mul(unit);
            Ok(now_millis().saturating_sub(delta))
        }
        // Absolute timestamp.
        None => Ok(value),
    }
}

/// Current unix-millis (best-effort).
fn now_millis() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| i64::try_from(d.as_millis()).unwrap_or(i64::MAX))
        .unwrap_or(0)
}

/// Render one record's referenced ids as a compact `k=v` string (hyphenated
/// UUIDs), or an empty string when the kind references none.
fn ids_string(kind: &AuditKind) -> String {
    let mut parts: Vec<String> = Vec::new();
    if let Some(item) = kind.item_id() {
        parts.push(format!("item={}", item.to_hyphenated()));
    }
    if let Some(vault) = kind.vault_id() {
        parts.push(format!("vault={}", vault.to_hyphenated()));
    }
    if let Some(peer) = kind.peer_device_id() {
        parts.push(format!("peer={}", peer.to_hyphenated()));
    }
    parts.join(" ")
}

/// A short human detail for a kind's extra fields (field name, export
/// format/count) — never a secret value.
fn detail_string(record: &AuditRecord) -> String {
    let mut bits: Vec<String> = Vec::new();
    match &record.kind {
        AuditKind::ItemSecretRead {
            field: Some(field), ..
        } => bits.push(format!("field={field}")),
        AuditKind::Export { format, item_count } => {
            bits.push(format!("format={format}"));
            bits.push(format!("items={item_count}"));
        }
        _ => {}
    }
    if let Some(d) = &record.detail {
        bits.push(d.clone());
    }
    bits.join(" ")
}

/// Print the `TIMESTAMP  KIND  IDS  DETAIL` table (oldest first).
fn print_table(records: &[AuditRecord]) {
    // Widest kind label, bounded, for a tidy column.
    let kind_w = records
        .iter()
        .map(|r| r.kind.label().len())
        .max()
        .unwrap_or(4)
        .clamp(4, 20);
    println!(
        "{:<17}  {:<kind_w$}  DETAILS",
        "TIMESTAMP",
        "KIND",
        kind_w = kind_w
    );
    for r in records {
        let ids = ids_string(&r.kind);
        let detail = detail_string(r);
        let trailer = [ids, detail]
            .into_iter()
            .filter(|s| !s.is_empty())
            .collect::<Vec<_>>()
            .join("  ");
        println!(
            "{:<17}  {:<kind_w$}  {}",
            format_millis_utc(r.timestamp),
            r.kind.label(),
            trailer,
            kind_w = kind_w
        );
    }
}

/// Build the stable `--json` object for one record. Ids are hyphenated UUIDs;
/// absent ids are `null`. No field ever carries a secret value.
fn record_to_json(r: &AuditRecord) -> serde_json::Value {
    json!({
        "seq": r.seq,
        "timestamp": r.timestamp,
        "device_id": r.device_id.to_hyphenated(),
        "kind": r.kind.label(),
        "item_id": r.kind.item_id().map(lp_vault::Id::to_hyphenated),
        "vault_id": r.kind.vault_id().map(lp_vault::Id::to_hyphenated),
        "peer_device_id": r.kind.peer_device_id().map(lp_vault::Id::to_hyphenated),
        "field": audit_field(&r.kind),
        "export_format": audit_export_format(&r.kind),
        "item_count": audit_item_count(&r.kind),
        "detail": r.detail,
    })
}

/// The revealed field name for an `ItemSecretRead`, else `None`.
fn audit_field(kind: &AuditKind) -> Option<&str> {
    match kind {
        AuditKind::ItemSecretRead { field, .. } => field.as_deref(),
        _ => None,
    }
}

/// The export format for an `Export`, else `None`.
fn audit_export_format(kind: &AuditKind) -> Option<&str> {
    match kind {
        AuditKind::Export { format, .. } => Some(format),
        _ => None,
    }
}

/// The item count for an `Export`, else `None`.
fn audit_item_count(kind: &AuditKind) -> Option<u64> {
    match kind {
        AuditKind::Export { item_count, .. } => Some(*item_count),
        _ => None,
    }
}
