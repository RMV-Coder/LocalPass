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
      return typeStr;
  }
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
