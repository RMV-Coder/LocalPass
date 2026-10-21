// SPDX-License-Identifier: MPL-2.0
// This file is part of the LocalPass desktop GUI. See ../../LICENSE.

// The update check's state, shared by the Settings page and the sidebar's
// "Update" hint. Metadata only (version numbers and release notes). The check
// is one HTTPS request made by the Rust updater, and only when the user asks
// for it or has opted in to a check at start-up (prefs.getAutoUpdateCheck).

import { writable } from "svelte/store";
import { updateCheck } from "./api";
import type { UpdateInfoView } from "./types";

export interface UpdateState {
  checking: boolean;
  /** A newer release, or null when up to date / not checked yet. */
  available: UpdateInfoView | null;
  /** When the last check finished (ms), 0 if never. */
  checkedAt: number;
  error: string;
}

export const updates = writable<UpdateState>({
  checking: false,
  available: null,
  checkedAt: 0,
  error: "",
});

let inflight: Promise<void> | null = null;

/** Run one check (concurrent callers share it). Never rejects. */
export function checkForUpdates(): Promise<void> {
  if (inflight) return inflight;
  updates.update((s) => ({ ...s, checking: true, error: "" }));
  inflight = updateCheck()
    .then((available) => {
      updates.set({ checking: false, available, checkedAt: Date.now(), error: "" });
    })
    .catch((err) => {
      updates.update((s) => ({
        ...s,
        checking: false,
        checkedAt: Date.now(),
        error: typeof err === "string" ? err : "Could not check for updates.",
      }));
    })
    .finally(() => {
      inflight = null;
    });
  return inflight;
}
