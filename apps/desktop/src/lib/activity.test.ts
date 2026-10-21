// SPDX-License-Identifier: MPL-2.0
// This file is part of the LocalPass desktop GUI. See ../../LICENSE.

import { describe, expect, it, vi } from "vitest";
import { lastSeenBySource, notifyActivity, onActivity } from "./activity";
import type { AuditRecordView } from "./types";

function rec(seq: number, source: string | null, timestamp: number): AuditRecordView {
  return {
    seq,
    timestamp,
    kind: "item_secret_read",
    item_id: null,
    vault_id: null,
    source,
    process: null,
    pid: null,
    field: null,
    deny_reason: null,
    detail: null,
  };
}

describe("lastSeenBySource", () => {
  it("keeps the latest timestamp per source regardless of order", () => {
    const seen = lastSeenBySource([rec(3, "cli", 300), rec(1, "cli", 900), rec(2, "mcp", 500)]);
    expect(seen.get("cli")).toBe(900);
    expect(seen.get("mcp")).toBe(500);
    expect(seen.has("native_host")).toBe(false);
  });

  it("files a record without attribution under 'unknown'", () => {
    expect(lastSeenBySource([rec(1, null, 42)]).get("unknown")).toBe(42);
  });

  it("is empty for no records", () => {
    expect(lastSeenBySource([]).size).toBe(0);
  });
});

describe("onActivity / notifyActivity", () => {
  it("calls every listener until it unsubscribes", () => {
    const a = vi.fn();
    const b = vi.fn();
    const offA = onActivity(a);
    const offB = onActivity(b);
    notifyActivity();
    offA();
    notifyActivity();
    expect(a).toHaveBeenCalledTimes(1);
    expect(b).toHaveBeenCalledTimes(2);
    offB();
  });

  it("a throwing listener does not stop the others", () => {
    const bad = vi.fn(() => {
      throw new Error("boom");
    });
    const good = vi.fn();
    const off1 = onActivity(bad);
    const off2 = onActivity(good);
    expect(() => notifyActivity()).not.toThrow();
    expect(good).toHaveBeenCalledTimes(1);
    off1();
    off2();
  });
});
