// SPDX-License-Identifier: MPL-2.0
// This file is part of the LocalPass desktop GUI. See ../../LICENSE.

// Pure display helpers for the Dev tab's agent-fill arm control
// (docs/specs/agent-fill.md §7).
//
// Nothing here touches a secret: the arm window is described entirely by item
// IDS, item TITLES, and a remaining-seconds count. The daemon is the authority
// on both the window and its per-item scope — these helpers only shape what the
// user sees before and after they arm it.

import type { AgentFillTargetView, ItemSummaryView } from "./types";

/** The arm window's length, in seconds (agent-fill.md §7 — three minutes,
 *  matching pairing mode's precedent). Display only; the daemon sets the real
 *  deadline and this build never sends it. */
export const ARM_WINDOW_SECS = 180;

/** Format remaining seconds as `m:ss` for the live countdown. A null (or
 *  negative) count reads `0:00`, so a lapsed window never renders as blank. */
export function formatArmCountdown(secs: number | null): string {
  const s = Math.max(0, secs ?? 0);
  const m = Math.floor(s / 60);
  const r = s % 60;
  return `${m}:${r.toString().padStart(2, "0")}`;
}

/** The logins an arm window may be scoped to, from a vault's item summaries.
 *
 *  Only `login` items: a fill needs a username/password pair and a URL to match
 *  an origin against, which no other item type carries. Sorted by title
 *  (case-insensitively) so the picker is stable between loads. */
export function loginTargets(items: ItemSummaryView[]): AgentFillTargetView[] {
  return items
    .filter((i) => i.type_str === "login")
    .map((i) => ({ id: i.id, title: i.title }))
    .sort((a, b) => a.title.localeCompare(b.title, undefined, { sensitivity: "base" }));
}

/** Drop selected ids that are no longer offered (the user switched vaults, or an
 *  item was deleted in another pane). Keeps the picker's checked set from
 *  silently naming an item the user can no longer see — arming must cover only
 *  what was on screen. Preserves the order of `targets`. */
export function pruneSelection(
  selected: readonly string[],
  targets: readonly AgentFillTargetView[],
): string[] {
  const chosen = new Set(selected);
  return targets.filter((t) => chosen.has(t.id)).map((t) => t.id);
}

/** A one-line summary of what an armed window covers: "GitHub", "GitHub and 1
 *  other", "GitHub and 3 others". Empty selection yields an empty string —
 *  there is no such thing as an armed window covering nothing (§7), so callers
 *  must never render this as a state. */
export function scopeSummary(
  selected: readonly string[],
  targets: readonly AgentFillTargetView[],
): string {
  const ids = pruneSelection(selected, targets);
  if (ids.length === 0) return "";
  const byId = new Map(targets.map((t) => [t.id, t.title]));
  const first = byId.get(ids[0]) ?? "";
  const rest = ids.length - 1;
  if (rest === 0) return first;
  return `${first} and ${rest} other${rest === 1 ? "" : "s"}`;
}
