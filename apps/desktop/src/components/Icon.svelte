<!--
  SPDX-License-Identifier: MPL-2.0
  This file is part of the LocalPass desktop GUI. See ../../LICENSE.

  A tiny, self-contained stroke icon set (inline SVG, no icon font, no remote
  assets — the CSP forbids them). Icons inherit `currentColor`, so they follow
  the surrounding text color, including the active / muted states of the
  sidebar and the mobile tab bar in both themes. Always decorative:
  `aria-hidden`, the adjacent text label carries the meaning.
-->
<script lang="ts" module>
  export type IconName =
    | "items"
    | "generator"
    | "security"
    | "devices"
    | "dev"
    | "help"
    | "trash"
    | "chevron";
</script>

<script lang="ts">
  interface Props {
    name: IconName;
    size?: number;
  }
  let { name, size = 16 }: Props = $props();
</script>

<svg
  class="icon"
  width={size}
  height={size}
  viewBox="0 0 24 24"
  fill="none"
  stroke="currentColor"
  stroke-width="1.8"
  stroke-linecap="round"
  stroke-linejoin="round"
  aria-hidden="true"
  focusable="false"
>
  {#if name === "items"}
    <!-- key -->
    <circle cx="8" cy="15" r="4" />
    <path d="M10.8 12.2 20 3" />
    <path d="M16 7l3 3" />
    <path d="M18.5 4.5l2 2" />
  {:else if name === "generator"}
    <!-- die -->
    <rect x="3.5" y="3.5" width="17" height="17" rx="3" />
    <circle cx="8.5" cy="8.5" r="1" fill="currentColor" stroke="none" />
    <circle cx="15.5" cy="15.5" r="1" fill="currentColor" stroke="none" />
    <circle cx="12" cy="12" r="1" fill="currentColor" stroke="none" />
  {:else if name === "security"}
    <!-- shield with check -->
    <path d="M12 3l7.5 3v5.5c0 4.5-3.2 8.2-7.5 9.5-4.3-1.3-7.5-5-7.5-9.5V6L12 3z" />
    <path d="M8.8 12.2l2.2 2.2 4.2-4.4" />
  {:else if name === "devices"}
    <!-- laptop + phone -->
    <rect x="3" y="5" width="13" height="9" rx="1.5" />
    <path d="M1.5 18h15" />
    <rect x="18" y="9" width="4.5" height="10" rx="1" />
  {:else if name === "dev"}
    <!-- terminal prompt -->
    <rect x="3" y="4.5" width="18" height="15" rx="2" />
    <path d="M7 10l3 2.5L7 15" />
    <path d="M12.5 15h4.5" />
  {:else if name === "help"}
    <!-- question in circle -->
    <circle cx="12" cy="12" r="9" />
    <path d="M9.6 9.3a2.5 2.5 0 0 1 4.8.9c0 1.7-2.4 2.2-2.4 3.8" />
    <circle cx="12" cy="17" r="0.9" fill="currentColor" stroke="none" />
  {:else if name === "trash"}
    <path d="M4 7h16" />
    <path d="M9.5 7V4.5h5V7" />
    <path d="M6.5 7l1 12.5h9l1-12.5" />
  {:else if name === "chevron"}
    <path d="M9 6l6 6-6 6" />
  {/if}
</svg>

<style>
  .icon {
    flex: none;
    display: block;
  }
</style>
