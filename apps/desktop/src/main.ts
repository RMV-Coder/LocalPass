// SPDX-License-Identifier: MPL-2.0
// This file is part of the LocalPass desktop GUI. See ../LICENSE.

import { mount } from "svelte";
// JetBrains Mono (OFL-1.1), bundled locally: the CSP allows only same-origin
// fonts. Used for secret values, code and fingerprints (DESIGN.md).
import "@fontsource-variable/jetbrains-mono/wght.css";
import "./styles.css";
import App from "./App.svelte";
import { applyTheme } from "./lib/prefs";

// Apply a saved light/dark override before the first paint.
applyTheme();

const target = document.getElementById("app");
if (!target) {
  throw new Error("missing #app mount target");
}

const app = mount(App, { target });

export default app;
