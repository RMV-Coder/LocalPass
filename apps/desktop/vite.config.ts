// SPDX-License-Identifier: MPL-2.0
// This file is part of the LocalPass desktop GUI. See ./LICENSE.

import { defineConfig } from "vite";
import { svelte } from "@sveltejs/vite-plugin-svelte";

// Vite config tuned for Tauri: a fixed dev port (referenced by
// tauri.conf.json's devUrl), no clearing of the terminal so Rust errors stay
// visible, and a strict, self-contained build (no remote origins) that emits to
// dist/ for the Tauri backend to embed.
export default defineConfig({
  plugins: [svelte()],
  // Prevent Vite from obscuring Rust errors during `tauri dev`.
  clearScreen: false,
  server: {
    port: 1420,
    strictPort: true,
    host: "localhost",
  },
  // Produce a fully local bundle; no source maps of secrets, nothing external.
  build: {
    target: "esnext",
    outDir: "dist",
    emptyOutDir: true,
    sourcemap: false,
  },
});
