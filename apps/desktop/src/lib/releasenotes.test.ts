// SPDX-License-Identifier: MPL-2.0
// This file is part of the LocalPass desktop GUI. See ../../LICENSE.

import { describe, expect, it } from "vitest";
import { cleanLine, parseReleaseNotes } from "./releasenotes";

describe("cleanLine", () => {
  it("drops GitHub's attribution tail", () => {
    expect(cleanLine("feat(gui): redesigned shell by @octo in https://github.com/o/r/pull/42")).toBe(
      "feat(gui): redesigned shell",
    );
    expect(cleanLine("chore: bump deps by @dependabot[bot] in https://github.com/o/r/pull/7")).toBe(
      "chore: bump deps",
    );
  });

  it("keeps link text but never the URL", () => {
    expect(cleanLine("see [the spec](https://example.com/spec) and https://evil.example/x")).toBe(
      "see the spec and",
    );
  });

  it("strips emphasis and code marks", () => {
    expect(cleanLine("**Breaking:** `localpass run` now __requires__ unlock")).toBe(
      "Breaking: localpass run now requires unlock",
    );
  });
});

describe("parseReleaseNotes", () => {
  it("parses GitHub's generated notes into headings and items", () => {
    const md = [
      "## What's Changed",
      "* feat(gui): redesigned shell by @octo in https://github.com/o/r/pull/42",
      "* fix(sync): clearer device status by @octo in https://github.com/o/r/pull/43",
      "",
      "",
      "**Full Changelog**: https://github.com/o/r/compare/desktop-v0.1.3...desktop-v0.1.4",
    ].join("\n");
    expect(parseReleaseNotes(md)).toEqual([
      { kind: "heading", text: "What's Changed" },
      { kind: "item", text: "feat(gui): redesigned shell" },
      { kind: "item", text: "fix(sync): clearer device status" },
    ]);
  });

  it("keeps plain paragraphs and dash bullets, skips comments and blanks", () => {
    expect(parseReleaseNotes("<!-- generated -->\r\nThanks!\r\n- one\r\n\r\n")).toEqual([
      { kind: "text", text: "Thanks!" },
      { kind: "item", text: "one" },
    ]);
  });

  it("returns nothing for empty notes", () => {
    expect(parseReleaseNotes("")).toEqual([]);
    expect(parseReleaseNotes("**Full Changelog**: https://x")).toEqual([]);
  });

  it("never produces markup: angle brackets stay as text", () => {
    const [b] = parseReleaseNotes("* <img src=x onerror=alert(1)>");
    expect(b).toEqual({ kind: "item", text: "<img src=x onerror=alert(1)>" });
  });
});
