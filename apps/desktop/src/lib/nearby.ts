// SPDX-License-Identifier: MPL-2.0
// This file is part of the LocalPass desktop GUI. See ../../LICENSE.

// "Sync with a nearby device" (docs/specs/lan-transport.md): the pure helpers
// the Devices screen uses — reading a scanned address QR and turning a session
// report into a sentence or two. Nothing here is secret: addresses, ids, vault
// names and counts.

import type { NearbyOutcomeView, NearbyReportView, PeerView } from "./types";

/** The QR payload prefix for a listen address (`LPNEAR1-192.168.1.20:47823`),
 *  so a scan can tell it apart from a device-identity QR (`LPDEV1-…`). Must
 *  match `NEARBY_QR_PREFIX` in src-tauri/src/commands.rs. */
export const NEARBY_QR_PREFIX = "LPNEAR1-";

const IPV4_PORT = /^(\d{1,3}(?:\.\d{1,3}){3})(?::(\d{1,5}))?$/;
const IPV6_BRACKETED = /^\[([0-9a-fA-F:.]+)\](?::(\d{1,5}))?$/;
const IPV6_BARE = /^[0-9a-fA-F:]*:[0-9a-fA-F:.]*$/;

/** Read a scanned QR as a nearby address. Accepts the prefixed payload the
 *  listener shows, or a bare `IP[:port]`. Returns the address, or `null` for
 *  anything else (a device-identity QR, a URL, a host name). The service checks
 *  the address again (local network only) before it connects. */
export function parseNearbyQr(content: string): string | null {
  let s = content.trim();
  if (s.startsWith(NEARBY_QR_PREFIX)) s = s.slice(NEARBY_QR_PREFIX.length);
  const v4 = IPV4_PORT.exec(s);
  if (v4) {
    const octetsOk = v4[1].split(".").every((o) => Number(o) <= 255);
    const portOk = v4[2] === undefined || (Number(v4[2]) > 0 && Number(v4[2]) <= 65535);
    return octetsOk && portOk ? s : null;
  }
  const v6 = IPV6_BRACKETED.exec(s);
  if (v6) {
    const portOk = v6[2] === undefined || (Number(v6[2]) > 0 && Number(v6[2]) <= 65535);
    return portOk ? s : null;
  }
  return IPV6_BARE.test(s) ? s : null;
}

/** Whether a scanned QR is a device identity rather than an address. */
export function isIdentityQr(content: string): boolean {
  return content.trim().startsWith("LPDEV1-");
}

/** The other device's display name: its label in the report, else in the
 *  trusted list, else a short id. */
export function nearbyPeerName(report: NearbyReportView, peers: PeerView[]): string {
  const label =
    report.peer_label?.trim() ||
    peers.find((p) => p.device_id === report.peer_device_id)?.label?.trim();
  return label || `device ${report.peer_device_id.slice(0, 8)}`;
}

function plural(n: number, one: string, many: string = `${one}s`): string {
  return `${n} ${n === 1 ? one : many}`;
}

/** One line per thing that happened, for the result area. Alarms are NOT
 *  included: the screen shows them in its alarm callout. */
export function summarizeNearby(report: NearbyReportView, peers: PeerView[]): string[] {
  const who = nearbyPeerName(report, peers);
  const lines = [`Synced with ${who}.`];
  for (const a of report.adopted) {
    lines.push(`Received the vault ${a.name || a.vault_id}.`);
  }
  if (report.shared.length) {
    lines.push(`Gave ${who} the key to ${plural(report.shared.length, "vault")}.`);
  }
  for (const v of report.vaults) {
    const parts: string[] = [];
    parts.push(v.received ? `received ${plural(v.received, "change")}` : "nothing new received");
    if (v.sent) parts.push(`sent ${plural(v.sent, "change")}`);
    if (v.pending) parts.push(`${v.pending} waiting`);
    if (v.files_received) parts.push(`${plural(v.files_received, "file")} received`);
    if (v.files_missing) parts.push(`${plural(v.files_missing, "file")} still missing`);
    lines.push(`${v.name || v.vault_id}: ${parts.join(", ")}.`);
  }
  if (report.vaults.length === 0 && report.adopted.length === 0) {
    lines.push("You have no vault in common yet. Give it one below.");
  }
  return lines;
}

/** How a listen window ended, in words. `null` for a window that synced (the
 *  caller shows the report instead). */
export function listenEndMessage(outcome: NearbyOutcomeView): string | null {
  switch (outcome.result) {
    case "synced":
      return null;
    case "expired":
      return "No trusted device connected in time.";
    case "stopped":
      return "Stopped waiting.";
    case "too_many_failures":
      return "Stopped waiting after repeated failed connection attempts.";
    default:
      return outcome.error ?? "The nearby sync failed.";
  }
}
