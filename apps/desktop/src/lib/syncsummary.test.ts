// SPDX-License-Identifier: MPL-2.0
// This file is part of the LocalPass desktop GUI. See ../../LICENSE.

import { describe, expect, it } from "vitest";
import { deviceName, summarizeSync } from "./syncsummary";
import type { PeerView, SyncDeviceView, SyncStatusView } from "./types";

const peers: PeerView[] = [
  { device_id: "phone-0001", fingerprint: "A1B2", label: "Pixel 8", verified_at: 1 },
  { device_id: "desk-0002", fingerprint: "C3D4", label: "  ", verified_at: 1 },
];

function status(devices: SyncDeviceView[], extra: Partial<SyncStatusView> = {}): SyncStatusView {
  return { enrolled: true, root: "/sync", devices, pending: 0, alarms: [], ...extra };
}
const self = (local: number, channel: number): SyncDeviceView => ({
  device_id: "self-0000",
  is_self: true,
  trusted: true,
  local_seq: local,
  channel_seq: channel,
});
const peer = (id: string, local: number, channel: number, trusted = true): SyncDeviceView => ({
  device_id: id,
  is_self: false,
  trusted,
  local_seq: local,
  channel_seq: channel,
});

describe("deviceName", () => {
  it("uses the trust label", () => {
    expect(deviceName("phone-0001", peers)).toBe("Pixel 8");
  });
  it("falls back to a short id for an unknown or blank-labelled device", () => {
    expect(deviceName("desk-0002", peers)).toBe("Device desk-0");
    expect(deviceName("zzzzzz-9", peers)).toBe("Device zzzzzz");
  });
});

describe("summarizeSync", () => {
  it("is idle when the vault is not enrolled (or status is missing)", () => {
    expect(summarizeSync(null, peers)).toMatchObject({ tone: "idle", headline: "Sync is not set up" });
    expect(summarizeSync({ ...status([]), enrolled: false }, peers).tone).toBe("idle");
  });

  it("says up to date when this device is alone in the folder", () => {
    expect(summarizeSync(status([self(5, 5)]), peers)).toMatchObject({
      tone: "ok",
      headline: "Up to date",
      to_send: 0,
      to_receive: 0,
    });
  });

  it("counts other devices when everything is applied", () => {
    const s = summarizeSync(status([self(5, 5), peer("phone-0001", 9, 9), peer("desk-0002", 2, 2)]), peers);
    expect(s).toMatchObject({ tone: "ok", headline: "In sync with 2 devices" });
    expect(s.devices.map((d) => d.name)).toEqual(["This device", "Pixel 8", "Device desk-0"]);
  });

  it("names the one device with changes waiting", () => {
    const s = summarizeSync(status([self(5, 5), peer("phone-0001", 7, 9)]), peers);
    expect(s).toMatchObject({ tone: "warn", headline: "2 changes to receive from Pixel 8", to_receive: 2 });
    expect(s.devices[1].to_receive).toBe(2);
  });

  it("aggregates across several devices", () => {
    const s = summarizeSync(status([self(1, 1), peer("phone-0001", 0, 1), peer("desk-0002", 0, 3)]), peers);
    expect(s.headline).toBe("4 changes to receive from 2 devices");
  });

  it("uses the singular for one change", () => {
    expect(summarizeSync(status([self(1, 1), peer("phone-0001", 0, 1)]), peers).headline).toBe(
      "1 change to receive from Pixel 8",
    );
  });

  it("reports local changes that were not pushed", () => {
    expect(summarizeSync(status([self(8, 5), peer("phone-0001", 3, 3)]), peers)).toMatchObject({
      tone: "warn",
      headline: "3 changes not sent yet",
      to_send: 3,
    });
  });

  it("prefers receiving over sending in the headline", () => {
    expect(summarizeSync(status([self(8, 5), peer("phone-0001", 1, 3)]), peers).headline).toMatch(/to receive/);
  });

  it("never reports negative counts when marks run ahead", () => {
    const s = summarizeSync(status([self(2, 9), peer("phone-0001", 9, 2)]), peers);
    expect(s.to_send).toBe(0);
    expect(s.to_receive).toBe(0);
    expect(s.tone).toBe("ok");
  });

  it("flags an untrusted writer above lag", () => {
    const s = summarizeSync(status([self(1, 1), peer("phone-0001", 0, 4), peer("rogue-01", 0, 1, false)]), peers);
    expect(s).toMatchObject({ tone: "warn", headline: "An untrusted device is writing to the folder" });
  });

  it("puts alarms above everything", () => {
    const s = summarizeSync(
      status([self(1, 1), peer("rogue-01", 0, 1, false)], { alarms: ["chain rollback from rogue-01"] }),
      peers,
    );
    expect(s).toMatchObject({ tone: "danger", headline: "A device's changes were quarantined" });
  });
});
