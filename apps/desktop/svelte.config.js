// SPDX-License-Identifier: MPL-2.0
// This file is part of the LocalPass desktop GUI. See ./LICENSE.

import { vitePreprocess } from "@sveltejs/vite-plugin-svelte";

export default {
  // Enables <script lang="ts"> in Svelte components.
  preprocess: vitePreprocess(),
};
