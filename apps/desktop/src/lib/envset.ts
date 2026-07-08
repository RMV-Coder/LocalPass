// SPDX-License-Identifier: MPL-2.0
// This file is part of the LocalPass desktop GUI. See ../../LICENSE.

// Pure helpers for the env-set developer workflow: rendering revealed entries
// back to `.env` text (Part A2) and assembling the `localpass run` command
// (Part B). Kept dependency-free and pure so they are unit-tested in isolation
// (see envset.test.ts). NO secret persistence happens here — callers pass in
// values they already hold component-locally, and the returned strings are held
// component-locally too.

/** One `KEY=value` pair to render. */
export interface EnvPair {
  key: string;
  value: string;
}

/** Whether a dotenv value must be double-quoted to survive a round-trip: it
 *  contains whitespace, a `#`, a quote, or a `=` — or is empty and we want it
 *  visible. We quote conservatively (correctness over minimalism). */
function needsQuoting(value: string): boolean {
  return /[\s#"'=]/.test(value);
}

/** Render a single `KEY=value` dotenv line, double-quoting the value when it
 *  contains characters that would otherwise be ambiguous on re-parse. Inside the
 *  double quotes we backslash-escape `"` and `\` so the value round-trips. */
export function dotenvLine(key: string, value: string): string {
  if (!needsQuoting(value)) return `${key}=${value}`;
  const escaped = value.replace(/\\/g, "\\\\").replace(/"/g, '\\"');
  return `${key}="${escaped}"`;
}

/** Render an ordered list of entries to `.env` text (one `KEY=value` per line,
 *  trailing newline). */
export function formatDotenv(pairs: EnvPair[]): string {
  return pairs.map((p) => dotenvLine(p.key, p.value)).join("\n") + (pairs.length ? "\n" : "");
}

/** The default vault name; when the current vault is this, the run command omits
 *  `--vault` (it is the CLI's default). */
export const DEFAULT_VAULT = "personal";

/** Quote a value for a shell-like display command if it contains a space or a
 *  double quote, so a copy-pasted command survives. We wrap in double quotes and
 *  escape embedded `"`. Titles/commands here are NOT secret. */
function shellQuote(value: string): string {
  if (value.length === 0) return '""';
  if (!/[\s"]/.test(value)) return value;
  return `"${value.replace(/"/g, '\\"')}"`;
}

/** Assemble the `localpass run` command that injects an env-set's variables into
 *  a child process. `--vault "<name>"` is inserted only when `vaultName` is set
 *  and is not the default `personal` vault. `devCommand` is appended after `--`
 *  verbatim (falling back to `npm run dev` when blank). Contains NO secret — only
 *  the item title, the vault name, and the user's own command. */
export function buildRunCommand(
  itemTitle: string,
  vaultName: string,
  devCommand: string,
): string {
  const parts = ["localpass", "run"];
  if (vaultName && vaultName !== DEFAULT_VAULT) {
    parts.push("--vault", shellQuote(vaultName));
  }
  parts.push("--env-set", shellQuote(itemTitle));
  const cmd = devCommand.trim() || "npm run dev";
  parts.push("--", cmd);
  return parts.join(" ");
}
