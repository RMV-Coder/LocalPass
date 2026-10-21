// SPDX-License-Identifier: MPL-2.0
// This file is part of the LocalPass desktop GUI. See ../../LICENSE.

// Per-device UI conveniences kept in localStorage: the theme override, the
// opt-in update check, and release notes carried across an update. Never a
// secret, never vault data. Storage can be unavailable (private mode, a
// locked-down WebView), so every access is wrapped and the app renders
// correctly with the defaults.

export type ThemePref = "system" | "light" | "dark";

function read(key: string): string | null {
  try {
    return globalThis.localStorage?.getItem(key) ?? null;
  } catch {
    return null;
  }
}

function write(key: string, value: string | null): void {
  try {
    if (value === null) globalThis.localStorage?.removeItem(key);
    else globalThis.localStorage?.setItem(key, value);
  } catch {
    /* a convenience, not a requirement */
  }
}

export function getThemePref(): ThemePref {
  const v = read("lp.theme");
  return v === "light" || v === "dark" ? v : "system";
}

/** Persist and apply a theme. "system" removes the override so the OS wins. */
export function setThemePref(pref: ThemePref): void {
  write("lp.theme", pref === "system" ? null : pref);
  applyTheme(pref);
}

export function applyTheme(pref: ThemePref = getThemePref()): void {
  const root = globalThis.document?.documentElement;
  if (!root) return;
  if (pref === "system") delete root.dataset.theme;
  else root.dataset.theme = pref;
}

/** Whether to look for an update when the app starts. Off by default: it is
 *  the app's only unprompted network request (PRD: offline first, no
 *  telemetry), so the user opts in. */
export function getAutoUpdateCheck(): boolean {
  return read("lp.autoUpdateCheck") === "1";
}

export function setAutoUpdateCheck(on: boolean): void {
  write("lp.autoUpdateCheck", on ? "1" : null);
}

/** Release notes saved just before installing an update, so the first launch
 *  of the new version can say what changed. Reading them clears them. */
export function takePendingNotes(): { version: string; notes: string } | null {
  const raw = read("lp.pendingNotes");
  if (!raw) return null;
  write("lp.pendingNotes", null);
  try {
    const v = JSON.parse(raw);
    return typeof v?.version === "string" && typeof v?.notes === "string" ? v : null;
  } catch {
    return null;
  }
}

export function savePendingNotes(version: string, notes: string): void {
  write("lp.pendingNotes", JSON.stringify({ version, notes }));
}
