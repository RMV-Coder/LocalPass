// SPDX-License-Identifier: MPL-2.0
// This file is part of the LocalPass desktop GUI. See ../../LICENSE.

import { afterEach, describe, expect, it, vi } from "vitest";
import {
  CANCELLED_MESSAGE,
  describeAction,
  presenceAction,
  setPresencePrompt,
  withPresence,
} from "./presence";

afterEach(() => setPresencePrompt(null));

describe("presenceAction", () => {
  it("reads the request kind from a marked error", () => {
    expect(presenceAction("presence_required:UpdateItem")).toBe("UpdateItem");
    expect(presenceAction("create failed: presence_required:CreateItem")).toBe("CreateItem");
  });

  it("ignores every other error", () => {
    expect(presenceAction("the vault is locked")).toBeNull();
    expect(presenceAction(new Error("presence_required:X"))).toBeNull();
    expect(presenceAction(undefined)).toBeNull();
  });
});

describe("describeAction", () => {
  it("names known actions and falls back for others", () => {
    expect(describeAction("DeleteItem")).toBe("Deleting an item");
    expect(describeAction("Mystery")).toBe("This change");
  });
});

describe("withPresence", () => {
  it("passes a successful call straight through without prompting", async () => {
    const prompt = vi.fn();
    setPresencePrompt(prompt);
    await expect(withPresence(async () => 7, vi.fn())).resolves.toBe(7);
    expect(prompt).not.toHaveBeenCalled();
  });

  it("rethrows unrelated errors", async () => {
    setPresencePrompt(vi.fn());
    await expect(withPresence(() => Promise.reject("nope"), vi.fn())).rejects.toBe("nope");
  });

  it("confirms, then retries the call once", async () => {
    const call = vi
      .fn<() => Promise<string>>()
      .mockRejectedValueOnce("presence_required:CreateItem")
      .mockResolvedValueOnce("new-id");
    const confirm = vi.fn(async () => {});
    setPresencePrompt(async (action, submit) => {
      expect(action).toBe("CreateItem");
      await submit("pw");
      return true;
    });
    await expect(withPresence(call, confirm)).resolves.toBe("new-id");
    expect(confirm).toHaveBeenCalledWith("pw");
    expect(call).toHaveBeenCalledTimes(2);
  });

  it("does not retry when the dialog is cancelled", async () => {
    const call = vi.fn(() => Promise.reject("presence_required:DeleteItem"));
    setPresencePrompt(async () => false);
    await expect(withPresence(call, vi.fn())).rejects.toBe(CANCELLED_MESSAGE);
    expect(call).toHaveBeenCalledTimes(1);
  });

  it("refuses cleanly when no dialog is registered", async () => {
    await expect(
      withPresence(() => Promise.reject("presence_required:DeleteVault"), vi.fn()),
    ).rejects.toBe(CANCELLED_MESSAGE);
  });

  it("shares one dialog between concurrent calls", async () => {
    let release!: (ok: boolean) => void;
    const prompt = vi.fn(() => new Promise<boolean>((r) => (release = r)));
    setPresencePrompt(prompt);
    const make = () =>
      vi
        .fn<() => Promise<number>>()
        .mockRejectedValueOnce("presence_required:UpdateItem")
        .mockResolvedValueOnce(1);
    const a = withPresence(make(), vi.fn());
    const b = withPresence(make(), vi.fn());
    await Promise.resolve();
    await Promise.resolve();
    release(true);
    await expect(Promise.all([a, b])).resolves.toEqual([1, 1]);
    expect(prompt).toHaveBeenCalledTimes(1);
  });
});
