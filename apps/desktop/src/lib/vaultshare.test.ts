// SPDX-License-Identifier: MPL-2.0
// This file is part of the LocalPass desktop GUI. See ../../LICENSE.

import { describe, expect, it } from "vitest";
import { adoptOutcome, folderUsedByAnotherDevice } from "./vaultshare";
import type { SyncAdoptView, SyncStatusView } from "./types";

function report(extra: Partial<SyncAdoptView> = {}): SyncAdoptView {
  return {
    adopted: [],
    applied_total: 0,
    alarms: [],
    untrusted_shares: 0,
    vault_folders: 1,
    shares_for_other_devices: 0,
    looks_like_vault_folder: false,
    ...extra,
  };
}

describe("adoptOutcome", () => {
  it("names what was added", () => {
    const o = adoptOutcome(report({ adopted: [{ vault_id: "v1", name: "Personal (shared)" }] }));
    expect(o.tone).toBe("ok");
    expect(o.title).toBe("Added Personal (shared).");
    expect(o.detail).toBe("Its items are on this device now.");
  });

  it("falls back to the id and mentions untrusted shares left behind", () => {
    const o = adoptOutcome(
      report({ adopted: [{ vault_id: "v1", name: "" }, { vault_id: "v2", name: "Work" }], untrusted_shares: 1 }),
    );
    expect(o.title).toBe("Added v1, Work.");
    expect(o.detail).toContain("Their items");
    expect(o.detail).toContain("1 other share came from a device this one does not trust yet");
  });

  it("asks for a fingerprint check when the sender is not trusted, without urging trust", () => {
    const o = adoptOutcome(report({ untrusted_shares: 1 }));
    expect(o.tone).toBe("warn");
    expect(o.title).toContain("does not trust yet");
    expect(o.detail).toContain("comparing the fingerprint");
    expect(o.detail).toContain("If you did not share anything, ignore this");
    expect(o.action).toBe("pair");
    expect(adoptOutcome(report({ untrusted_shares: 2 })).title).toMatch(/^2 vaults here were/);
  });

  it("explains a vault folder picked instead of the shared folder", () => {
    const o = adoptOutcome(report({ vault_folders: 0, looks_like_vault_folder: true }));
    expect(o.title).toBe("This is one vault's folder.");
    expect(o.action).toBeUndefined();
  });

  it("explains a folder with no LocalPass data", () => {
    const o = adoptOutcome(report({ vault_folders: 0 }));
    expect(o.title).toBe("There is no LocalPass data in this folder.");
    expect(o.detail).toContain("finished syncing");
  });

  it("explains shares addressed to another device", () => {
    expect(adoptOutcome(report({ shares_for_other_devices: 2 })).title).toBe(
      "The vaults here were shared with a different device.",
    );
  });

  it("says nothing was shared yet otherwise", () => {
    const o = adoptOutcome(report());
    expect(o.tone).toBe("info");
    expect(o.title).toBe("Nothing has been shared with this device in this folder yet.");
  });
});

describe("folderUsedByAnotherDevice", () => {
  const base: SyncStatusView = { enrolled: true, root: "/sync", devices: [], pending: 0, alarms: [] };
  const dev = (id: string, is_self: boolean, trusted: boolean) => ({
    device_id: id,
    is_self,
    trusted,
    local_seq: 1,
    channel_seq: 1,
  });

  it("is false with no status, only this device, or only untrusted writers", () => {
    expect(folderUsedByAnotherDevice(null)).toBe(false);
    expect(folderUsedByAnotherDevice({ ...base, devices: [dev("me", true, true)] })).toBe(false);
    expect(folderUsedByAnotherDevice({ ...base, devices: [dev("me", true, true), dev("x", false, false)] })).toBe(
      false,
    );
  });

  it("is true once a trusted peer has written there", () => {
    expect(folderUsedByAnotherDevice({ ...base, devices: [dev("me", true, true), dev("p", false, true)] })).toBe(true);
  });
});
