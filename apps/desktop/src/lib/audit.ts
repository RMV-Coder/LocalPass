// SPDX-License-Identifier: MPL-2.0
// This file is part of the LocalPass desktop GUI. See ../../LICENSE.

// Pure display helpers for the Dev tab's audit viewer.
//
// THE NAME RULE (the reason this file exists): the audit log is PLAINTEXT on
// disk, so it stores item and vault IDs and never names — names are ciphertext
// everywhere else. Resolution from id to title therefore happens HERE, in the
// UI, at display time, against the unlocked session's own item lists. Nothing
// in this module ever travels back toward the log. No secret value passes
// through any of it either: an audit record carries field *names*, never values.

import type { AuditRecordView, ItemSummaryView, VaultView } from "./types";

/** Human label for an audit source token (`lp_vault::AuditSource::label`). An
 *  unrecognised or missing source renders as "Unknown" — a record written
 *  before caller attribution existed is honest about it rather than guessed at. */
export function sourceLabel(source: string | null | undefined): string {
  switch (source) {
    case "cli":
      return "CLI";
    case "gui":
      return "GUI";
    case "mcp":
      return "MCP";
    case "native_host":
      return "Browser";
    case "ssh_agent":
      return "SSH agent";
    case "daemon":
      return "Service";
    default:
      return "Unknown";
  }
}

/** Human label for an audit kind token (`lp_vault::AuditKind::label`). An
 *  unknown token (a newer core writing a kind this build predates) degrades to
 *  the raw token with underscores spaced out, rather than being hidden. */
export function kindLabel(kind: string): string {
  switch (kind) {
    case "unlock_success":
      return "Unlocked";
    case "unlock_failure":
      return "Failed unlock";
    case "item_secret_read":
      return "Secret revealed";
    case "item_create":
      return "Item created";
    case "item_update":
      return "Item edited";
    case "item_delete":
      return "Item deleted";
    case "item_restore":
      return "Version restored";
    case "export":
      return "Exported";
    case "vault_share":
      return "Vault shared";
    case "device_trust":
      return "Device trusted";
    case "pairing_mode_enabled":
      return "Pairing opened";
    case "pairing_mode_disabled":
      return "Pairing closed";
    case "access_denied":
      return "Refused";
    default:
      return kind.replace(/_/g, " ");
  }
}

/** Whether a kind should be rendered as a warning row (a refusal or a failed
 *  unlock — the two things an operator scans this log for). */
export function isAlarming(kind: string): boolean {
  return kind === "access_denied" || kind === "unlock_failure";
}

/** A short, recognisable form of a hyphenated uuid for the fallback display:
 *  the first group, e.g. "9f8e7d6c-…" -> "9f8e7d6c". A non-uuid-looking string
 *  is truncated to 8 characters. Empty/missing input yields "—". */
export function shortId(id: string | null | undefined): string {
  if (!id) return "—";
  const head = id.split("-")[0] ?? id;
  return head.slice(0, 8);
}

/** Build the id → title index the viewer resolves against, from the item lists
 *  of the vaults the unlocked session can see. Later entries win, but ids are
 *  unique across vaults so order is not load-bearing. */
export function titleIndex(lists: ItemSummaryView[][]): Map<string, string> {
  const map = new Map<string, string>();
  for (const list of lists) {
    for (const it of list) map.set(it.id, it.title);
  }
  return map;
}

/** Build the vault id → name index, from the vault list. */
export function vaultIndex(vaults: VaultView[]): Map<string, string> {
  return new Map(vaults.map((v) => [v.id, v.name]));
}

/** Resolve an item id to a title for display.
 *
 *  Returns the title when the item still exists in an unlocked vault; otherwise
 *  a short id, because the item was deleted/purged or lives in a vault this
 *  session cannot see. Never invents a name, and never asks the core for one. */
export function resolveItemTitle(
  itemId: string | null | undefined,
  index: Map<string, string>,
): string {
  if (!itemId) return "—";
  return index.get(itemId) ?? shortId(itemId);
}

/** Whether an item id resolved to a real title (used to style the fallback as
 *  a muted, monospaced id rather than a name). */
export function isResolved(
  itemId: string | null | undefined,
  index: Map<string, string>,
): boolean {
  return !!itemId && index.has(itemId);
}

/** The caller column: process name plus pid when both are known, the process
 *  name alone when there is no pid, and "—" when the record carries neither.
 *  Never a command line — the log does not store one. */
export function callerLabel(record: {
  process: string | null;
  pid: number | null;
}): string {
  if (record.process && record.pid != null) return `${record.process} (${record.pid})`;
  if (record.process) return record.process;
  if (record.pid != null) return `pid ${record.pid}`;
  return "—";
}

/** The one-line "what happened" summary for a row: the kind, plus the field
 *  name for a secret read and the refusal reason for a denial. Both are
 *  non-secret labels straight from the log. */
export function operationLabel(record: AuditRecordView): string {
  const base = kindLabel(record.kind);
  if (record.kind === "item_secret_read" && record.field) {
    return `${base} · ${record.field}`;
  }
  if (record.kind === "access_denied" && record.deny_reason) {
    return `${base} · ${record.deny_reason.replace(/_/g, " ")}`;
  }
  return base;
}

/** A compact local time for a log row: date only when it is not today,
 *  otherwise the time of day. Returns "—" for a missing/invalid timestamp.
 *  `now` is injectable so the boundary is testable. */
export function formatAuditTime(millis: number, now: Date = new Date()): string {
  if (!millis) return "—";
  const d = new Date(millis);
  if (Number.isNaN(d.getTime())) return "—";
  const sameDay =
    d.getFullYear() === now.getFullYear() &&
    d.getMonth() === now.getMonth() &&
    d.getDate() === now.getDate();
  return sameDay
    ? d.toLocaleTimeString(undefined, {
        hour: "2-digit",
        minute: "2-digit",
        second: "2-digit",
      })
    : d.toLocaleString(undefined, {
        month: "short",
        day: "2-digit",
        hour: "2-digit",
        minute: "2-digit",
      });
}
