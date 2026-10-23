// SPDX-License-Identifier: MPL-2.0
// Build the `localpass-daemon` release binary and stage it as a Tauri sidecar
// (`externalBin`) so the installed desktop app ships the daemon beside itself.
//
// Tauri's externalBin expects the source file named with the host target triple
// (e.g. `localpass-daemon-x86_64-pc-windows-msvc.exe`); it strips the triple and
// places `localpass-daemon(.exe)` next to the app binary in the bundle, which is
// exactly what `daemon::ensure_running` (DaemonExe::Auto) looks for.
//
// Run via `npm run bundle` (which chains `tauri build` after this).

import { execFileSync } from "node:child_process";
import { copyFileSync, mkdirSync, readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const desktopDir = join(here, "..");
const repoRoot = join(desktopDir, "..", ".."); // apps/desktop -> repo root
const binariesDir = join(desktopDir, "src-tauri", "binaries");

function run(cmd, args, opts = {}) {
  return execFileSync(cmd, args, { encoding: "utf8", ...opts });
}

// 1) Host target triple (e.g. x86_64-pc-windows-msvc), from rustc.
const rustcVerbose = run("rustc", ["-vV"]);
const hostLine = rustcVerbose.split(/\r?\n/).find((l) => l.startsWith("host: "));
if (!hostLine) {
  throw new Error("could not determine the host target triple from `rustc -vV`");
}
const triple = hostLine.slice("host: ".length).trim();
const isWindows = triple.includes("windows");
const exeExt = isWindows ? ".exe" : "";

// 2) Build the daemon in release from the (excluded) core workspace. The app
//    version goes in as LOCALPASS_PRODUCT_VERSION, so on Windows the daemon
//    carries the same product name + version as the app (lp-daemon/build.rs):
//    release signing only signs files whose metadata matches the release.
const appVersion = JSON.parse(
  readFileSync(join(desktopDir, "src-tauri", "tauri.conf.json"), "utf8"),
).version;
console.log(`[sidecar] building localpass-daemon ${appVersion} (release) for ${triple} …`);
run("cargo", ["build", "-p", "lp-daemon", "--release"], {
  cwd: repoRoot,
  stdio: "inherit",
  env: { ...process.env, LOCALPASS_PRODUCT_VERSION: appVersion },
});

// 3) Stage it as the Tauri sidecar source (triple-suffixed).
const built = join(repoRoot, "target", "release", `localpass-daemon${exeExt}`);
const dest = join(binariesDir, `localpass-daemon-${triple}${exeExt}`);
mkdirSync(binariesDir, { recursive: true });
copyFileSync(built, dest);
console.log(`[sidecar] staged ${dest}`);
