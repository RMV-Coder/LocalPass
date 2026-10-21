// SPDX-License-Identifier: MPL-2.0
// This file is part of the LocalPass desktop GUI. See ../../LICENSE.

// Two small, value-free activity signals.
//
// 1. `lastSeenBySource`: from audit records, when each surface (CLI, MCP, the
//    browser extension, the SSH agent, this app) last did something. Metadata
//    only; it answers the Developer page's "is the CLI / MCP in use?".
//
// 2. `onActivity` / `notifyActivity`: every daemon request except the passive
//    `Status` resets the idle auto-lock timer. The api layer calls
//    `notifyActivity` after such a request, so the app can re-read the
//    (passive) status and keep the "locks in …" countdown honest without ever
//    polling an active request itself.

import type { AuditRecordView } from "./types";

export function lastSeenBySource(records: AuditRecordView[]): Map<string, number> {
  const seen = new Map<string, number>();
  for (const r of records) {
    const src = r.source ?? "unknown";
    const prev = seen.get(src);
    if (prev === undefined || r.timestamp > prev) seen.set(src, r.timestamp);
  }
  return seen;
}

type Listener = () => void;
const listeners = new Set<Listener>();

export function onActivity(fn: Listener): () => void {
  listeners.add(fn);
  return () => {
    listeners.delete(fn);
  };
}

export function notifyActivity(): void {
  for (const fn of listeners) {
    try {
      fn();
    } catch {
      /* a listener's failure must not break the request that triggered it */
    }
  }
}
