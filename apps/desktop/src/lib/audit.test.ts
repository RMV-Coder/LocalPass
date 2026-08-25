// SPDX-License-Identifier: MPL-2.0
// This file is part of the LocalPass desktop GUI. See ../../LICENSE.

import { describe, it, expect } from "vitest";
import {
  sourceLabel,
  kindLabel,
  isAlarming,
  shortId,
  titleIndex,
  vaultIndex,
  resolveItemTitle,
  isResolved,
  callerLabel,
  operationLabel,
  formatAuditTime,
} from "./audit";
import type { AuditRecordView, ItemSummaryView, VaultView } from "./types";

function record(over: Partial<AuditRecordView> = {}): AuditRecordView {
  return {
    seq: 1,
    timestamp: 1_700_000_000_000,
    kind: "item_secret_read",
    item_id: null,
    vault_id: null,
    source: null,
    process: null,
    pid: null,
    field: null,
    deny_reason: null,
    detail: null,
    ...over,
  };
}

function summary(id: string, title: string): ItemSummaryView {
  return { id, title, type_str: "login", updated_at: 0, tags: [] };
}

describe("sourceLabel", () => {
  it("maps every source token the core emits", () => {
    expect(sourceLabel("cli")).toBe("CLI");
    expect(sourceLabel("gui")).toBe("GUI");
    expect(sourceLabel("mcp")).toBe("MCP");
    expect(sourceLabel("native_host")).toBe("Browser");
    expect(sourceLabel("ssh_agent")).toBe("SSH agent");
    expect(sourceLabel("daemon")).toBe("Service");
  });
  it("does not guess at a missing or unknown source", () => {
    expect(sourceLabel(null)).toBe("Unknown");
    expect(sourceLabel(undefined)).toBe("Unknown");
    expect(sourceLabel("unknown")).toBe("Unknown");
    expect(sourceLabel("something_new")).toBe("Unknown");
  });
});

describe("kindLabel", () => {
  it("maps the known kinds", () => {
    expect(kindLabel("item_secret_read")).toBe("Secret revealed");
    expect(kindLabel("access_denied")).toBe("Refused");
    expect(kindLabel("pairing_mode_enabled")).toBe("Pairing opened");
    expect(kindLabel("agent_fill_mode_enabled")).toBe("Agent fill armed");
    expect(kindLabel("agent_fill_mode_disabled")).toBe("Agent fill closed");
  });
  it("degrades an unknown kind to a readable token rather than hiding it", () => {
    expect(kindLabel("brand_new_kind")).toBe("brand new kind");
  });
});

describe("isAlarming", () => {
  it("flags refusals and failed unlocks only", () => {
    expect(isAlarming("access_denied")).toBe(true);
    expect(isAlarming("unlock_failure")).toBe(true);
    expect(isAlarming("unlock_success")).toBe(false);
    expect(isAlarming("item_create")).toBe(false);
  });
});

describe("shortId", () => {
  it("takes the first uuid group", () => {
    expect(shortId("9f8e7d6c-1234-5678-9abc-def012345678")).toBe("9f8e7d6c");
  });
  it("truncates a non-uuid string", () => {
    expect(shortId("abcdefghijklmnop")).toBe("abcdefgh");
  });
  it("renders nothing as an em dash", () => {
    expect(shortId(null)).toBe("—");
    expect(shortId("")).toBe("—");
  });
});

describe("id resolution", () => {
  const index = titleIndex([
    [summary("id-a", "Prod DB"), summary("id-b", "GitHub")],
    [summary("id-c", "Staging token")],
  ]);

  it("indexes every vault's items", () => {
    expect(index.size).toBe(3);
    expect(index.get("id-c")).toBe("Staging token");
  });

  it("resolves a live item to its title", () => {
    expect(resolveItemTitle("id-a", index)).toBe("Prod DB");
    expect(isResolved("id-a", index)).toBe(true);
  });

  it("falls back to a short id when the item is gone or unresolvable", () => {
    expect(resolveItemTitle("dead1234-0000-0000-0000-000000000000", index)).toBe("dead1234");
    expect(isResolved("dead1234-0000-0000-0000-000000000000", index)).toBe(false);
  });

  it("renders a record with no item at all as an em dash", () => {
    expect(resolveItemTitle(null, index)).toBe("—");
    expect(isResolved(null, index)).toBe(false);
  });

  it("indexes vault names separately", () => {
    const vaults: VaultView[] = [{ id: "v1", name: "personal" }];
    expect(vaultIndex(vaults).get("v1")).toBe("personal");
    expect(vaultIndex(vaults).get("v2")).toBeUndefined();
  });
});

describe("callerLabel", () => {
  it("shows process and pid together", () => {
    expect(callerLabel({ process: "localpass.exe", pid: 4321 })).toBe("localpass.exe (4321)");
  });
  it("handles a process with no pid and a pid with no process", () => {
    expect(callerLabel({ process: "localpass", pid: null })).toBe("localpass");
    expect(callerLabel({ process: null, pid: 7 })).toBe("pid 7");
  });
  it("renders an empty attribution as an em dash", () => {
    expect(callerLabel({ process: null, pid: null })).toBe("—");
  });
});

describe("operationLabel", () => {
  it("appends the revealed field name (a name, never a value)", () => {
    expect(operationLabel(record({ kind: "item_secret_read", field: "password" }))).toBe(
      "Secret revealed · password",
    );
  });
  it("appends the refusal reason", () => {
    expect(operationLabel(record({ kind: "access_denied", deny_reason: "wrong_profile" }))).toBe(
      "Refused · wrong profile",
    );
  });
  it("leaves other kinds bare", () => {
    expect(operationLabel(record({ kind: "item_create" }))).toBe("Item created");
  });
  it("does not append a field for a kind that is not a secret read", () => {
    expect(operationLabel(record({ kind: "item_update", field: "password" }))).toBe("Item edited");
  });
});

describe("formatAuditTime", () => {
  const now = new Date(2026, 7, 23, 14, 0, 0);

  it("returns an em dash for a missing or invalid timestamp", () => {
    expect(formatAuditTime(0, now)).toBe("—");
    expect(formatAuditTime(Number.NaN, now)).toBe("—");
  });

  it("shows a time-of-day for today and includes seconds", () => {
    const earlierToday = new Date(2026, 7, 23, 9, 30, 15).getTime();
    const out = formatAuditTime(earlierToday, now);
    expect(out).not.toBe("—");
    expect(out).toMatch(/15/); // seconds are present — log rows can be same-minute
  });

  it("shows a date for anything that is not today", () => {
    const yesterday = new Date(2026, 7, 22, 9, 30, 0).getTime();
    const out = formatAuditTime(yesterday, now);
    expect(out).not.toBe("—");
    expect(out).not.toBe(formatAuditTime(new Date(2026, 7, 23, 9, 30, 0).getTime(), now));
  });
});
