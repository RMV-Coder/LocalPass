// SPDX-License-Identifier: MPL-2.0
// This file is part of the LocalPass desktop GUI. See ../../LICENSE.

// Small pure display helpers. No secrets flow through here — only metadata
// (timestamps, type strings) and the masking placeholder. Kept pure and
// dependency-free so they are trivially unit-testable (see format.test.ts).

/** The fixed-length mask shown for an un-revealed secret field. */
export const MASK = "••••••••";

/** Human label for an item type string (e.g. "api_key" -> "API key"). */
export function typeLabel(typeStr: string): string {
  switch (typeStr) {
    case "login":
      return "Login";
    case "note":
      return "Secure note";
    case "api_key":
      return "API key";
    case "env_set":
      return "Env set";
    case "ssh_key":
      return "SSH key";
    case "totp":
      return "TOTP";
    default:
      return humanizeKey(typeStr);
  }
}

/** Turn a snake_case / kebab-case key into sentence case for display
 *  ("secure_note" -> "Secure note"). Used as the fallback for unknown type
 *  strings so a raw identifier never leaks into the UI as-is. */
export function humanizeKey(key: string): string {
  const words = key.replace(/[_-]+/g, " ").trim();
  if (!words) return key;
  return words.charAt(0).toUpperCase() + words.slice(1);
}

/** Display labels for the BUILT-IN field names the backend emits for each item
 *  type (see src-tauri item_input.rs). Only exact matches are relabelled; any
 *  other (user-defined) field name is shown exactly as typed. */
const FIELD_LABELS: Record<string, string> = {
  username: "Username",
  password: "Password",
  url: "URL",
  secret: "Secret",
  endpoint: "Endpoint",
  private_pem: "Private key",
  public_openssh: "Public key",
  fingerprint: "Fingerprint",
  algo: "Algorithm",
};

/** Human label for an item field name. Env-set entries are variable NAMES the
 *  user will reference verbatim (`localpass://…/KEY`), so they are never
 *  rewritten; neither are unknown/custom field names. Display-only: the raw
 *  name is still what reveal/copy calls use. */
export function fieldLabel(name: string, typeStr: string): string {
  if (typeStr === "env_set") return name;
  return Object.prototype.hasOwnProperty.call(FIELD_LABELS, name) ? FIELD_LABELS[name] : name;
}

/** Format a unix-millis timestamp as a short local date-time. Returns "—" for
 *  a missing/zero value. */
export function formatTimestamp(millis: number): string {
  if (!millis) return "—";
  const d = new Date(millis);
  if (Number.isNaN(d.getTime())) return "—";
  return d.toLocaleString(undefined, {
    year: "numeric",
    month: "short",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
  });
}

/** Compact date for dense lists: the time of day for today, "Mon D" within
 *  the current year, otherwise "Mon D, YYYY". `now` is injectable for tests.
 *  Returns "—" for a missing/invalid value. Pair with `formatTimestamp` where
 *  the full date-time is needed. */
export function formatShortDate(millis: number, now: number = Date.now()): string {
  if (!millis) return "—";
  const d = new Date(millis);
  if (Number.isNaN(d.getTime())) return "—";
  const n = new Date(now);
  if (
    d.getFullYear() === n.getFullYear() &&
    d.getMonth() === n.getMonth() &&
    d.getDate() === n.getDate()
  ) {
    return d.toLocaleTimeString(undefined, { hour: "numeric", minute: "2-digit" });
  }
  if (d.getFullYear() === n.getFullYear()) {
    return d.toLocaleDateString(undefined, { month: "short", day: "numeric" });
  }
  return d.toLocaleDateString(undefined, { month: "short", day: "numeric", year: "numeric" });
}

/** ISO-8601 string for a `<time datetime>` attribute ("" when invalid). */
export function isoTimestamp(millis: number): string {
  if (!millis) return "";
  const d = new Date(millis);
  return Number.isNaN(d.getTime()) ? "" : d.toISOString();
}

/** Round entropy bits to one decimal for display. */
export function formatEntropy(bits: number): string {
  return `${bits.toFixed(1)} bits`;
}

/** A coarse strength band from entropy bits, for the generator meter and its
 *  aria label. Thresholds follow common guidance (≥128 excellent, ≥80 strong,
 *  ≥60 fair, else weak). */
export function strengthBand(bits: number): "weak" | "fair" | "strong" | "excellent" {
  if (bits >= 128) return "excellent";
  if (bits >= 80) return "strong";
  if (bits >= 60) return "fair";
  return "weak";
}

/** Format a byte count as a compact human size (B / KiB / MiB) — mirrors the
 *  CLI's `attach` table. Negative/NaN inputs render as "—". */
export function humanSize(bytes: number): string {
  if (!Number.isFinite(bytes) || bytes < 0) return "—";
  if (bytes >= 1024 * 1024) return `${(bytes / (1024 * 1024)).toFixed(1)} MiB`;
  if (bytes >= 1024) return `${(bytes / 1024).toFixed(1)} KiB`;
  return `${bytes} B`;
}

/** Group TOTP digits for readability: "123456" -> "123 456". Non-6/8 lengths
 *  are returned unchanged. */
export function groupTotp(code: string): string {
  if (code.length === 6) return `${code.slice(0, 3)} ${code.slice(3)}`;
  if (code.length === 8) return `${code.slice(0, 4)} ${code.slice(4)}`;
  return code;
}

/** Compact age for dense lists: "now", "5m", "3h", "2d" (under a week), then
 *  the short date. `now` is injectable for tests. "—" for a missing value. */
export function formatAge(millis: number, now: number = Date.now()): string {
  if (!millis) return "—";
  const diff = now - millis;
  if (!Number.isFinite(diff)) return "—";
  if (diff < 0) return formatShortDate(millis, now);
  const min = Math.floor(diff / 60_000);
  if (min < 1) return "now";
  if (min < 60) return `${min}m`;
  const h = Math.floor(min / 60);
  if (h < 24) return `${h}h`;
  const d = Math.floor(h / 24);
  if (d < 7) return `${d}d`;
  return formatShortDate(millis, now);
}

/** "3 minutes ago" / "2 days ago" for detail metadata, in the platform's own
 *  relative-time wording. Falls back to the short date past four weeks. */
export function formatAgo(millis: number, now: number = Date.now()): string {
  if (!millis) return "—";
  const diff = Math.max(0, now - millis);
  const rtf = new Intl.RelativeTimeFormat(undefined, { numeric: "auto" });
  const min = Math.round(diff / 60_000);
  if (min < 1) return "just now";
  if (min < 60) return rtf.format(-min, "minute");
  const h = Math.round(min / 60);
  if (h < 24) return rtf.format(-h, "hour");
  const d = Math.round(h / 24);
  if (d < 28) return rtf.format(-d, "day");
  return formatShortDate(millis, now);
}

/** The auto-lock countdown, coarse on purpose (it must not tick every second
 *  in the corner of the eye): "45 s" under a minute, then whole minutes, then
 *  "1 h 5 min". Zero, negative or NaN renders as "0 s". */
export function formatCountdown(secs: number): string {
  if (!Number.isFinite(secs) || secs <= 0) return "0 s";
  if (secs < 60) return `${Math.ceil(secs)} s`;
  const min = Math.ceil(secs / 60);
  if (min < 60) return `${min} min`;
  const h = Math.floor(min / 60);
  const rest = min % 60;
  return rest ? `${h} h ${rest} min` : `${h} h`;
}
