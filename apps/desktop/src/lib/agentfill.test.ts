// SPDX-License-Identifier: MPL-2.0
// This file is part of the LocalPass desktop GUI. See ../../LICENSE.

import { describe, it, expect } from "vitest";
import {
  ARM_WINDOW_SECS,
  formatArmCountdown,
  loginTargets,
  pruneSelection,
  scopeSummary,
} from "./agentfill";
import type { AgentFillTargetView, ItemSummaryView } from "./types";

function item(id: string, title: string, type_str = "login"): ItemSummaryView {
  return { id, title, type_str, updated_at: 0, tags: [] };
}

function target(id: string, title: string): AgentFillTargetView {
  return { id, title };
}

describe("ARM_WINDOW_SECS", () => {
  it("is the spec's three minutes", () => {
    expect(ARM_WINDOW_SECS).toBe(180);
  });
});

describe("formatArmCountdown", () => {
  it("renders m:ss with a zero-padded seconds field", () => {
    expect(formatArmCountdown(180)).toBe("3:00");
    expect(formatArmCountdown(179)).toBe("2:59");
    expect(formatArmCountdown(61)).toBe("1:01");
    expect(formatArmCountdown(9)).toBe("0:09");
  });

  it("renders a lapsed or unknown window as 0:00, never blank", () => {
    expect(formatArmCountdown(0)).toBe("0:00");
    expect(formatArmCountdown(null)).toBe("0:00");
    expect(formatArmCountdown(-5)).toBe("0:00");
  });
});

describe("loginTargets", () => {
  it("keeps only login items", () => {
    const targets = loginTargets([
      item("1", "GitHub"),
      item("2", "Prod DB", "api_key"),
      item("3", "Notes", "note"),
      item("4", "Bank"),
    ]);
    expect(targets).toEqual([target("4", "Bank"), target("1", "GitHub")]);
  });

  it("sorts by title, case-insensitively", () => {
    const targets = loginTargets([
      item("1", "zoho"),
      item("2", "Apple"),
      item("3", "bitbucket"),
    ]);
    expect(targets.map((t) => t.title)).toEqual(["Apple", "bitbucket", "zoho"]);
  });

  it("carries no field values through — id and title only", () => {
    const targets = loginTargets([item("1", "GitHub")]);
    expect(Object.keys(targets[0]).sort()).toEqual(["id", "title"]);
  });

  it("handles an empty vault", () => {
    expect(loginTargets([])).toEqual([]);
  });
});

describe("pruneSelection", () => {
  const targets = [target("a", "Apple"), target("b", "Bank"), target("c", "Cloud")];

  it("drops ids that are no longer offered", () => {
    expect(pruneSelection(["a", "gone", "c"], targets)).toEqual(["a", "c"]);
  });

  it("returns ids in the targets' order, not the selection's", () => {
    expect(pruneSelection(["c", "a"], targets)).toEqual(["a", "c"]);
  });

  it("empties out when nothing survives", () => {
    expect(pruneSelection(["x", "y"], targets)).toEqual([]);
    expect(pruneSelection([], targets)).toEqual([]);
  });
});

describe("scopeSummary", () => {
  const targets = [target("a", "Apple"), target("b", "Bank"), target("c", "Cloud")];

  it("names a single item", () => {
    expect(scopeSummary(["b"], targets)).toBe("Bank");
  });

  it("counts the rest, singular and plural", () => {
    expect(scopeSummary(["a", "b"], targets)).toBe("Apple and 1 other");
    expect(scopeSummary(["a", "b", "c"], targets)).toBe("Apple and 2 others");
  });

  it("ignores ids that no longer resolve", () => {
    expect(scopeSummary(["a", "gone"], targets)).toBe("Apple");
  });

  it("is empty for an empty scope — there is no armed-but-empty window", () => {
    expect(scopeSummary([], targets)).toBe("");
    expect(scopeSummary(["gone"], targets)).toBe("");
  });
});
