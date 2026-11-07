// SPDX-License-Identifier: MPL-2.0
// This file is part of the LocalPass desktop GUI. See ../../LICENSE.

import { describe, expect, it } from "vitest";
import { agentHeadline, agentSessions, endReasonText } from "./agents";
import { operationLabel } from "./audit";
import type { AuditRecordView } from "./types";

let seq = 0;
function rec(kind: string, pid: number | null, timestamp: number, detail?: string): AuditRecordView {
  seq += 1;
  return {
    seq,
    timestamp,
    kind,
    item_id: null,
    vault_id: null,
    source: "mcp",
    process: "localpass",
    pid,
    field: null,
    deny_reason: null,
    detail: detail ?? null,
  };
}

describe("agentSessions", () => {
  it("pairs a connection, its tool calls, and its end", () => {
    const [s, ...rest] = agentSessions(
      [
        rec("agent_connected", 7, 100),
        rec("agent_tool_call", 7, 200, "list_items"),
        rec("agent_tool_call", 7, 300, "get_item:failed"),
        rec("agent_disconnected", 7, 400, "host_closed"),
      ],
      [],
    );
    expect(rest).toEqual([]);
    expect(s).toMatchObject({
      pid: 7,
      connectedAt: 100,
      endedAt: 400,
      endReason: "host_closed",
      live: false,
      toolCalls: 2,
      failedCalls: 1,
      lastTool: "get_item",
      lastToolAt: 300,
    });
  });

  it("does not depend on record order (the log arrives newest first)", () => {
    const records = [
      rec("agent_connected", 7, 100),
      rec("agent_disconnected", 7, 400, "connection_lost"),
    ];
    expect(agentSessions([...records].reverse(), [])[0]).toMatchObject({
      connectedAt: 100,
      endReason: "connection_lost",
    });
  });

  it("marks a running agent live, and lists it first", () => {
    const sessions = agentSessions(
      [
        rec("agent_connected", 7, 100),
        rec("agent_connected", 8, 200),
        rec("agent_disconnected", 8, 900, "host_closed"),
      ],
      [7],
    );
    expect(sessions.map((s) => [s.pid, s.live])).toEqual([
      [7, true],
      [8, false],
    ]);
  });

  it("says nothing was recorded when a connection has no end and is not running", () => {
    const [s] = agentSessions([rec("agent_connected", 7, 100)], []);
    expect(s).toMatchObject({ live: false, endedAt: null, endReason: null });
    expect(endReasonText(s.endReason)).toContain("No end was recorded");
  });

  it("closes an unended session when its pid connects again", () => {
    const sessions = agentSessions(
      [rec("agent_connected", 7, 100), rec("agent_connected", 7, 500)],
      [7],
    );
    expect(sessions.map((s) => [s.connectedAt, s.live])).toEqual([
      [500, true],
      [100, false],
    ]);
  });

  it("shows a live agent whose connection record aged out of the window", () => {
    const [s] = agentSessions([], [9]);
    expect(s).toMatchObject({ pid: 9, live: true, connectedAt: null });
  });

  it("keeps tool calls from a session whose start aged out", () => {
    const [s] = agentSessions([rec("agent_tool_call", 7, 300, "totp_code")], [7]);
    expect(s).toMatchObject({ live: true, connectedAt: null, toolCalls: 1, lastTool: "totp_code" });
  });

  it("ignores other records, and caps the list", () => {
    const records = [rec("unlock_success", 1, 50)];
    for (let i = 0; i < 8; i += 1) {
      records.push(rec("agent_connected", 100 + i, 1000 + i));
      records.push(rec("agent_disconnected", 100 + i, 2000 + i, "host_closed"));
    }
    const sessions = agentSessions(records, []);
    expect(sessions).toHaveLength(5);
    expect(sessions[0].pid).toBe(107);
  });
});

describe("agentHeadline", () => {
  const now = 1_000_000;

  it("names the last tool of a connected agent", () => {
    const sessions = agentSessions(
      [rec("agent_connected", 7, now - 5000), rec("agent_tool_call", 7, now - 2000, "get_item")],
      [7],
    );
    expect(agentHeadline(sessions, true, now)).toContain("(get_item)");
  });

  it("covers connected with no use, past use, and no use at all", () => {
    const idle = agentSessions([rec("agent_connected", 7, now - 5000)], [7]);
    expect(agentHeadline(idle, true, now)).toBe("Connected, no tools used yet");

    const past = agentSessions(
      [rec("agent_connected", 7, now - 5000), rec("agent_disconnected", 7, now - 2000, "host_closed")],
      [],
    );
    expect(agentHeadline(past, false, now)).toMatch(/^Last connected /);

    expect(agentHeadline([], false, now)).toBe("No agent has connected recently");
  });
});

describe("endReasonText", () => {
  it("explains every reason the daemon records", () => {
    for (const reason of ["host_closed", "connection_lost", "service_stopped"]) {
      expect(endReasonText(reason)).not.toContain("No end was recorded");
    }
  });
});

describe("operationLabel for agent records", () => {
  it("shows the tool and any failure, never more", () => {
    expect(operationLabel(rec("agent_tool_call", 7, 1, "list_items"))).toBe(
      "Agent tool call · list_items",
    );
    expect(operationLabel(rec("agent_tool_call", 7, 1, "list_items:failed"))).toBe(
      "Agent tool call · list_items · failed",
    );
  });

  it("shows why an agent left", () => {
    expect(operationLabel(rec("agent_disconnected", 7, 1, "connection_lost"))).toBe(
      "Agent disconnected · connection lost",
    );
  });
});
