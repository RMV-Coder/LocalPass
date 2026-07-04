// SPDX-License-Identifier: MPL-2.0
// This file is part of the LocalPass desktop GUI. See ../LICENSE.

import { mount } from "svelte";
import "./styles.css";
import App from "./App.svelte";

const target = document.getElementById("app");
if (!target) {
  throw new Error("missing #app mount target");
}

const app = mount(App, { target });

export default app;
