// SPDX-License-Identifier: MPL-2.0
// This file is part of the LocalPass desktop GUI. See ../../LICENSE.

// AI-agent activity for the Developer page, derived from the audit log
// (mcp-server.md §7.2): who connected, what they used, and why they left. The
// log holds tool names and closed reason tokens only, so nothing here can carry
// a secret.

import { parseToolDetail } from "./audit";
import { formatAgo } from "./format";
import type { AuditRecordView } from "./types";

/** How many recent audit records the agent view reads. */
export const AGENT_RECORD_WINDOW = 500;

/** How many sessions the view lists. */
const MAX_SESSIONS = 5;

export interface AgentSession {
  /** A stable row key. */
  key: string;
  pid: number | null;
  /** `null` when the connection record is older than the window read. */
  connectedAt: number | null;
  /** `null` while it is live, or when no end was recorded. */
  endedAt: number | null;
  /** The closed token from the end record, or `null` if there was none. */
  endReason: string | null;
  live: boolean;
  toolCalls: number;
  failedCalls: number;
  lastTool: string | null;
  lastToolAt: number | null;
}

/** Why a session ended, for a person. */
export function endReasonText(reason: string | null): string {
  switch (reason) {
    case "host_closed":
      return "Closed by its AI tool: the session ended, or the server was restarted";
    case "connection_lost":
      return "Stopped without warning: the process was killed or crashed";
    case "service_stopped":
      return "The LocalPass service stopped, as it does for an update";
    default:
      return "No end was recorded: the service stopped abruptly, or the computer restarted";
  }
}

/** Sessions from audit records (in any order), newest first. A pid in `livePids`
 *  is running now, even if its connection record has aged out of the window. */
export function agentSessions(
  records: AuditRecordView[],
  livePids: number[],
  limit: number = MAX_SESSIONS,
): AgentSession[] {
  const finished: AgentSession[] = [];
  const open = new Map<number | null, AgentSession>();

  const start = (pid: number | null, at: number | null, seq: number): AgentSession => {
    const session: AgentSession = {
      key: `${pid ?? "?"}-${seq}`,
      pid,
      connectedAt: at,
      endedAt: null,
      endReason: null,
      live: false,
      toolCalls: 0,
      failedCalls: 0,
      lastTool: null,
      lastToolAt: null,
    };
    open.set(pid, session);
    return session;
  };

  const ordered = [...records].sort((a, b) => a.seq - b.seq);
  for (const r of ordered) {
    const pid = r.pid ?? null;
    if (r.kind === "agent_connected") {
      // A pid reused after an end that was never recorded: the old one is over.
      const stale = open.get(pid);
      if (stale) finished.push(stale);
      start(pid, r.timestamp, r.seq);
    } else if (r.kind === "agent_tool_call") {
      const session = open.get(pid) ?? start(pid, null, r.seq);
      const { tool, failed } = parseToolDetail(r.detail ?? "");
      session.toolCalls += 1;
      if (failed) session.failedCalls += 1;
      session.lastTool = tool || null;
      session.lastToolAt = r.timestamp;
    } else if (r.kind === "agent_disconnected") {
      const session = open.get(pid) ?? start(pid, null, r.seq);
      session.endedAt = r.timestamp;
      session.endReason = r.detail;
      finished.push(session);
      open.delete(pid);
    }
  }

  for (const session of open.values()) {
    session.live = session.pid !== null && livePids.includes(session.pid);
    finished.push(session);
  }
  for (const pid of livePids) {
    if (!finished.some((s) => s.live && s.pid === pid)) {
      finished.push({ ...start(pid, null, 0), live: true });
    }
  }

  const lastSeen = (s: AgentSession) => s.endedAt ?? s.lastToolAt ?? s.connectedAt ?? 0;
  return finished
    .sort((a, b) => Number(b.live) - Number(a.live) || lastSeen(b) - lastSeen(a))
    .slice(0, limit);
}

/** One line for the "AI agents" row. */
export function agentHeadline(sessions: AgentSession[], connected: boolean, now: number): string {
  const live = sessions.find((s) => s.live);
  if (connected) {
    if (live?.lastToolAt) return `Last used ${formatAgo(live.lastToolAt, now)} (${live.lastTool})`;
    return "Connected, no tools used yet";
  }
  const last = sessions[0];
  if (!last) return "No agent has connected recently";
  const when = last.endedAt ?? last.lastToolAt ?? last.connectedAt;
  return when ? `Last connected ${formatAgo(when, now)}` : "Connected earlier";
}
