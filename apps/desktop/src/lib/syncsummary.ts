// SPDX-License-Identifier: MPL-2.0
// This file is part of the LocalPass desktop GUI. See ../../LICENSE.

// One-line sync health for the sidebar status strip and the Devices page.
// Pure: it reads the daemon's per-device sequence marks (public metadata, no
// secret) and says, in words, whether this device is in step with the shared
// folder.
//
// The marks mean: `channel_seq` is how far a device has PUBLISHED into the
// folder; `local_seq` is how far THIS device has APPLIED that device's ops. So
// for a peer, channel > local means changes are waiting here to be pulled; for
// this device, local > channel means local changes have not been pushed. What
// a peer has applied from us is not observable from here, so we never claim it.

import type { PeerView, SyncStatusView } from "./types";

export type SyncTone = "ok" | "warn" | "danger" | "idle";

export interface DeviceSync {
  device_id: string;
  name: string;
  is_self: boolean;
  trusted: boolean;
  /** Ops this device has published that we have not applied yet. */
  to_receive: number;
}

export interface SyncSummary {
  tone: SyncTone;
  headline: string;
  /** Local ops not yet published to the folder. */
  to_send: number;
  /** Ops waiting in the folder for this device, across all peers. */
  to_receive: number;
  devices: DeviceSync[];
}

/** A peer's display name: its trust label, else a short id. */
export function deviceName(deviceId: string, peers: PeerView[]): string {
  const label = peers.find((p) => p.device_id === deviceId)?.label?.trim();
  return label ? label : `Device ${deviceId.slice(0, 6)}`;
}

function plural(n: number, one: string, many = `${one}s`): string {
  return `${n} ${n === 1 ? one : many}`;
}

export function summarizeSync(status: SyncStatusView | null, peers: PeerView[]): SyncSummary {
  if (!status || !status.enrolled) {
    return { tone: "idle", headline: "Sync is not set up", to_send: 0, to_receive: 0, devices: [] };
  }
  const devices: DeviceSync[] = status.devices.map((d) => ({
    device_id: d.device_id,
    name: d.is_self ? "This device" : deviceName(d.device_id, peers),
    is_self: d.is_self,
    trusted: d.trusted,
    to_receive: d.is_self ? 0 : Math.max(0, d.channel_seq - d.local_seq),
  }));
  const self = status.devices.find((d) => d.is_self);
  const to_send = self ? Math.max(0, self.local_seq - self.channel_seq) : 0;
  const to_receive = devices.reduce((n, d) => n + d.to_receive, 0);
  const base = { to_send, to_receive, devices };

  if (status.alarms.length > 0) {
    return { ...base, tone: "danger", headline: "A device's changes were quarantined" };
  }
  if (devices.some((d) => !d.is_self && !d.trusted)) {
    return { ...base, tone: "warn", headline: "An untrusted device is writing to the folder" };
  }
  if (to_receive > 0) {
    const from = devices.filter((d) => d.to_receive > 0);
    const who = from.length === 1 ? from[0].name : plural(from.length, "device");
    return { ...base, tone: "warn", headline: `${plural(to_receive, "change")} to receive from ${who}` };
  }
  if (to_send > 0) {
    return { ...base, tone: "warn", headline: `${plural(to_send, "change")} not sent yet` };
  }
  const others = devices.filter((d) => !d.is_self).length;
  return {
    ...base,
    tone: "ok",
    headline: others ? `In sync with ${plural(others, "device")}` : "Up to date",
  };
}
