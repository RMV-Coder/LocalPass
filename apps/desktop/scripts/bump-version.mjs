// SPDX-License-Identifier: MPL-2.0
// Bump the desktop app's version in the three places it lives:
//   package.json, src-tauri/tauri.conf.json, src-tauri/Cargo.toml
// (Cargo.lock follows automatically on the next cargo invocation.)
//
// Usage (chained in front of `tauri build` by the bundle scripts):
//   node scripts/bump-version.mjs           -> patch  (0.1.0 -> 0.1.1)
//   node scripts/bump-version.mjs minor     -> minor  (0.1.1 -> 0.2.0)
//   node scripts/bump-version.mjs major     -> major  (0.2.0 -> 1.0.0)
//
// tauri.conf.json is the source of truth for the current version. A growing
// version also makes the Windows MSI a real in-place upgrade (same
// UpgradeCode, higher ProductVersion) instead of a same-version collision
// that needs an uninstall first.
//
// The bump edits tracked files on purpose: commit the bump with the release.

import { readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const desktopDir = join(dirname(fileURLToPath(import.meta.url)), "..");

const KINDS = ["major", "minor", "patch"];
const kind = process.argv[2] ?? "patch";
if (!KINDS.includes(kind)) {
  console.error(`bump-version: unknown bump kind ${JSON.stringify(kind)}; use one of: ${KINDS.join(", ")}`);
  process.exit(1);
}

const confPath = join(desktopDir, "src-tauri", "tauri.conf.json");
const current = JSON.parse(readFileSync(confPath, "utf8")).version;
const m = /^(\d+)\.(\d+)\.(\d+)$/.exec(current);
if (!m) {
  console.error(`bump-version: current version ${JSON.stringify(current)} in tauri.conf.json is not plain semver`);
  process.exit(1);
}
let [major, minor, patch] = m.slice(1).map(Number);
if (kind === "major") { major += 1; minor = 0; patch = 0; }
else if (kind === "minor") { minor += 1; patch = 0; }
else { patch += 1; }
const next = `${major}.${minor}.${patch}`;

// Surgical replacements that preserve each file's formatting. Every pattern is
// anchored to the version KEY, never a bare match of the version string, so an
// unrelated dependency pinned to the same number can never be rewritten.
function replaceOnce(path, pattern, replacement) {
  const before = readFileSync(path, "utf8");
  const after = before.replace(pattern, replacement);
  if (after === before) {
    console.error(`bump-version: no version field matched in ${path}`);
    process.exit(1);
  }
  writeFileSync(path, after);
}

replaceOnce(
  join(desktopDir, "package.json"),
  /("version":\s*")\d+\.\d+\.\d+(")/,
  `$1${next}$2`,
);
replaceOnce(confPath, /("version":\s*")\d+\.\d+\.\d+(")/, `$1${next}$2`);
replaceOnce(
  join(desktopDir, "src-tauri", "Cargo.toml"),
  /(^version\s*=\s*")\d+\.\d+\.\d+(")/m,
  `$1${next}$2`,
);

console.log(`bump-version: ${current} -> ${next} (${kind})`);
