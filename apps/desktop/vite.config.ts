// SPDX-License-Identifier: MPL-2.0
// This file is part of the LocalPass desktop GUI. See ./LICENSE.

import { defineConfig } from "vite";
import { svelte } from "@sveltejs/vite-plugin-svelte";

// Vite config tuned for Tauri: a fixed dev port (referenced by
// tauri.conf.json's devUrl), no clearing of the terminal so Rust errors stay
// visible, and a strict, self-contained build (no remote origins) that emits to
// dist/ for the Tauri backend to embed.
//
// `TAURI_DEV_HOST` is set by `tauri android/ios dev`: the app on the device
// loads the UI over the LAN, so the dev server must bind to that host (not just
// localhost) and HMR must point back at it. Desktop `tauri dev` leaves the var
// unset and keeps the localhost binding.
const host = process.env.TAURI_DEV_HOST;

export default defineConfig({
  plugins: [svelte()],
  // Prevent Vite from obscuring Rust errors during `tauri dev`.
  clearScreen: false,
  server: {
    port: 1420,
    strictPort: true,
    host: host || "localhost",
    hmr: host ? { protocol: "ws", host, port: 1421 } : undefined,
    // Never let the Rust/Gradle build tree trigger a webview reload — the
    // Android build writes churn under src-tauri/gen during every rebuild.
    watch: { ignored: ["**/src-tauri/**"] },
  },
  // Produce a fully local bundle; no source maps of secrets, nothing external.
  build: {
    target: "esnext",
    outDir: "dist",
    emptyOutDir: true,
    sourcemap: false,
  },
});
