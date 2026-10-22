// SPDX-License-Identifier: MPL-2.0
// This file is part of the LocalPass desktop GUI. See ../../LICENSE.

import { describe, expect, it } from "vitest";
import {
  NEARBY_QR_PREFIX,
  isIdentityQr,
  listenEndMessage,
  nearbyPeerName,
  parseNearbyQr,
  summarizeNearby,
} from "./nearby";
import type { NearbyReportView, PeerView } from "./types";

const peers: PeerView[] = [
  { device_id: "phone-0001-aaaa", fingerprint: "A1B2", label: "Pixel 8", verified_at: 1 },
];

function report(extra: Partial<NearbyReportView> = {}): NearbyReportView {
  return {
    peer_device_id: "phone-0001-aaaa",
    peer_label: null,
    vaults: [],
    shared: [],
    adopted: [],
    alarms: [],
    ...extra,
  };
}

describe("parseNearbyQr", () => {
  it("reads the listener's prefixed payload", () => {
    expect(parseNearbyQr(`${NEARBY_QR_PREFIX}192.168.1.20:47823`)).toBe("192.168.1.20:47823");
    expect(parseNearbyQr(`${NEARBY_QR_PREFIX}[fd7a:115c::1]:47823`)).toBe("[fd7a:115c::1]:47823");
  });

  it("accepts a bare IP with or without a port", () => {
    expect(parseNearbyQr(" 100.101.102.103 ")).toBe("100.101.102.103");
    expect(parseNearbyQr("10.0.0.5:9000")).toBe("10.0.0.5:9000");
    expect(parseNearbyQr("fe80::1")).toBe("fe80::1");
  });

  it("refuses anything that is not an address", () => {
    expect(parseNearbyQr("LPDEV1-0011aabb")).toBeNull();
    expect(parseNearbyQr("https://example.com")).toBeNull();
    expect(parseNearbyQr("laptop.local:47823")).toBeNull();
    expect(parseNearbyQr("300.1.1.1")).toBeNull();
    expect(parseNearbyQr("10.0.0.5:0")).toBeNull();
    expect(parseNearbyQr("10.0.0.5:70000")).toBeNull();
    expect(parseNearbyQr("")).toBeNull();
  });

  it("tells an identity QR apart", () => {
    expect(isIdentityQr("LPDEV1-abc")).toBe(true);
    expect(isIdentityQr(`${NEARBY_QR_PREFIX}10.0.0.5`)).toBe(false);
  });
});

describe("summarizeNearby", () => {
  it("names the device from its label, the trusted list, or a short id", () => {
    expect(nearbyPeerName(report({ peer_label: "Laptop" }), peers)).toBe("Laptop");
    expect(nearbyPeerName(report(), peers)).toBe("Pixel 8");
    expect(nearbyPeerName(report({ peer_device_id: "abcdef0123456" }), [])).toBe("device abcdef01");
  });

  it("says what moved, per vault", () => {
    const lines = summarizeNearby(
      report({
        vaults: [
          {
            vault_id: "v1",
            name: "personal",
            sent: 1,
            received: 3,
            pending: 0,
            files_sent: 0,
            files_received: 2,
            files_missing: 1,
          },
        ],
      }),
      peers,
    );
    expect(lines).toEqual([
      "Synced with Pixel 8.",
      "personal: received 3 changes, sent 1 change, 2 files received, 1 file still missing.",
    ]);
  });

  it("reports shares both ways", () => {
    const lines = summarizeNearby(
      report({
        shared: ["v9"],
        adopted: [{ vault_id: "v3", name: "family" }],
        vaults: [
          {
            vault_id: "v3",
            name: "family",
            sent: 0,
            received: 7,
            pending: 0,
            files_sent: 0,
            files_received: 0,
            files_missing: 0,
          },
        ],
      }),
      peers,
    );
    expect(lines).toContain("Received the vault family.");
    expect(lines).toContain("Gave Pixel 8 the key to 1 vault.");
    expect(lines).toContain("family: received 7 changes.");
  });

  it("points at sharing when nothing is in common", () => {
    expect(summarizeNearby(report(), peers)).toEqual([
      "Synced with Pixel 8.",
      "You have no vault in common yet. Give it one below.",
    ]);
  });

  it("leaves alarms to the alarm callout", () => {
    const lines = summarizeNearby(report({ alarms: ["device x quarantined"] }), peers);
    expect(lines.join(" ")).not.toContain("quarantined");
  });
});

describe("listenEndMessage", () => {
  const end = (result: string, error: string | null = null) => ({
    role: "listen",
    result,
    error,
    report: null,
  });
  it("explains each way a window closes", () => {
    expect(listenEndMessage(end("synced"))).toBeNull();
    expect(listenEndMessage(end("expired"))).toMatch(/in time/);
    expect(listenEndMessage(end("stopped"))).toBe("Stopped waiting.");
    expect(listenEndMessage(end("too_many_failures"))).toMatch(/failed connection attempts/);
    expect(listenEndMessage(end("failed", "the vault locked"))).toBe("the vault locked");
  });
});
