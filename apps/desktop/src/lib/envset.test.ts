// SPDX-License-Identifier: MPL-2.0
// This file is part of the LocalPass desktop GUI. See ../../LICENSE.

import { describe, it, expect } from "vitest";
import { dotenvLine, formatDotenv, buildRunCommand } from "./envset";

describe("dotenvLine", () => {
  it("leaves a simple value unquoted", () => {
    expect(dotenvLine("FOO", "bar")).toBe("FOO=bar");
    expect(dotenvLine("URL", "postgres://u:p@h/db")).toBe("URL=postgres://u:p@h/db");
  });
  it("quotes values containing spaces", () => {
    expect(dotenvLine("MSG", "hello world")).toBe('MSG="hello world"');
  });
  it("quotes values containing a #", () => {
    expect(dotenvLine("PW", "p@ss#word")).toBe('PW="p@ss#word"');
  });
  it("escapes embedded double quotes and backslashes", () => {
    expect(dotenvLine("Q", 'a"b')).toBe('Q="a\\"b"');
    expect(dotenvLine("P", "a\\b c")).toBe('P="a\\\\b c"');
  });
});

describe("formatDotenv", () => {
  it("renders one KEY=value per line with a trailing newline", () => {
    const out = formatDotenv([
      { key: "A", value: "1" },
      { key: "B", value: "two words" },
    ]);
    expect(out).toBe('A=1\nB="two words"\n');
  });
  it("returns an empty string for no entries", () => {
    expect(formatDotenv([])).toBe("");
  });
  it("preserves order", () => {
    const out = formatDotenv([
      { key: "Z", value: "1" },
      { key: "A", value: "2" },
    ]);
    expect(out).toBe("Z=1\nA=2\n");
  });
});

describe("buildRunCommand", () => {
  it("omits --vault for the default personal vault", () => {
    expect(buildRunCommand("Dev", "personal", "npm run dev")).toBe(
      'localpass run --env-set Dev -- npm run dev',
    );
  });
  it("includes --vault for a non-default vault", () => {
    expect(buildRunCommand("Dev", "work", "npm run dev")).toBe(
      'localpass run --vault work --env-set Dev -- npm run dev',
    );
  });
  it("quotes a title or vault name containing spaces", () => {
    expect(buildRunCommand("My Env", "Team Vault", "npm run dev")).toBe(
      'localpass run --vault "Team Vault" --env-set "My Env" -- npm run dev',
    );
  });
  it("falls back to `npm run dev` when the command is blank", () => {
    expect(buildRunCommand("Dev", "personal", "   ")).toBe(
      "localpass run --env-set Dev -- npm run dev",
    );
  });
  it("passes an arbitrary dev command through after --", () => {
    expect(buildRunCommand("Dev", "personal", "pnpm start --port 3000")).toBe(
      "localpass run --env-set Dev -- pnpm start --port 3000",
    );
  });
  it("treats an empty vault name as default (no --vault)", () => {
    expect(buildRunCommand("Dev", "", "npm run dev")).toBe(
      "localpass run --env-set Dev -- npm run dev",
    );
  });
});
