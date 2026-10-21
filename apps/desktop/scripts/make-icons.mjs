// SPDX-License-Identifier: MPL-2.0
// This file is part of the LocalPass desktop GUI. See ../LICENSE.
//
// Regenerate every platform icon from the master SVGs in ../brand (DESIGN.md,
// "Platform icon pipeline"). One mark, rendered per platform:
//
//   brand/icon-manifest.json -> src-tauri/icons/* (Windows .ico, Linux PNGs,
//                               Windows Store logos, iOS) and, when the
//                               Android project exists, its adaptive icon
//   brand/mark-macos.svg     -> src-tauri/icons/icon.icns (Apple's 824/1024 inset)
//   brand/mark.svg           -> app-icon.png (1024px) and the extension icons
//
// Run with `npm run icons`. `tauri icon` rasterises SVG itself (resvg), so this
// needs no image tooling beyond the Tauri CLI already in devDependencies.

import { execSync } from "node:child_process";
import { copyFileSync, mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const app = join(dirname(fileURLToPath(import.meta.url)), "..");
const icons = join(app, "src-tauri", "icons");
const extensionIcons = join(app, "..", "extension", "icons");

function tauriIcon(args) {
  // `shell: true` because npx is a .cmd shim on Windows, which Node refuses to
  // spawn without a shell. Every argument here is a fixed path we built.
  execSync(`npx tauri icon ${args.map((a) => `"${a}"`).join(" ")}`, {
    cwd: app,
    stdio: "inherit",
    shell: true,
  });
}

const scratch = mkdtempSync(join(tmpdir(), "localpass-icons-"));
try {
  // 1. The full set, from the manifest (adaptive Android layers + iOS colour).
  tauriIcon([join(app, "brand", "icon-manifest.json")]);

  // 2. macOS wants the tile inset inside a transparent margin.
  const mac = join(scratch, "mac");
  tauriIcon([join(app, "brand", "mark-macos.svg"), "-o", mac]);
  copyFileSync(join(mac, "icon.icns"), join(icons, "icon.icns"));

  // 3. The 1024px source PNG, and the browser extension's sizes.
  const png = join(scratch, "png");
  tauriIcon([join(app, "brand", "mark.svg"), "-o", png, "--png", "16,32,48,128,1024"]);
  copyFileSync(join(png, "1024x1024.png"), join(app, "app-icon.png"));
  for (const size of [16, 32, 48, 128]) {
    copyFileSync(join(png, `${size}x${size}.png`), join(extensionIcons, `icon-${size}.png`));
  }
} finally {
  rmSync(scratch, { recursive: true, force: true });
}
