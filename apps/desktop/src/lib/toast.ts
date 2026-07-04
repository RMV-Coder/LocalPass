// SPDX-License-Identifier: MPL-2.0
// This file is part of the LocalPass desktop GUI. See ../../LICENSE.

// A tiny toast for transient, non-secret feedback ("Copied to clipboard").
// Toast text is never a secret value — only status messages. Rendered into an
// aria-live region in App.svelte so screen readers announce it.

import { writable } from "svelte/store";

export interface Toast {
  id: number;
  message: string;
  kind: "ok" | "error";
}

export const toasts = writable<Toast[]>([]);

let nextId = 1;

/** Show a transient toast. Auto-dismisses after `ms`. */
export function toast(message: string, kind: "ok" | "error" = "ok", ms = 2000): void {
  const id = nextId++;
  toasts.update((list) => [...list, { id, message, kind }]);
  setTimeout(() => {
    toasts.update((list) => list.filter((t) => t.id !== id));
  }, ms);
}
