<!--
  SPDX-License-Identifier: MPL-2.0
  This file is part of the LocalPass desktop GUI. See ../../LICENSE.

  The app's one icon family (inline SVG, no icon font, no remote assets — the
  CSP forbids them). 24-unit grid, 1.8 stroke, round caps and joins, so every
  glyph has the same weight next to the platform UI font. Icons inherit
  `currentColor`. Decorative by default (`aria-hidden`); the adjacent text or
  the button's aria-label carries the meaning.
-->
<script lang="ts" module>
  export type IconName =
    | "items"
    | "vault"
    | "generator"
    | "security"
    | "devices"
    | "dev"
    | "help"
    | "settings"
    | "more"
    | "trash"
    | "chevron"
    | "chevron-down"
    | "back"
    | "eye"
    | "eye-off"
    | "copy"
    | "check"
    | "lock"
    | "plus"
    | "search"
    | "x"
    | "refresh"
    | "sync"
    | "download"
    | "upload"
    | "paperclip"
    | "external"
    | "alert"
    | "info"
    | "agent"
    | "fingerprint"
    | "qr"
    | "camera"
    | "folder"
    | "star"
    | "edit"
    | "clock"
    | "type-login"
    | "type-note"
    | "type-api_key"
    | "type-env_set"
    | "type-ssh_key"
    | "type-totp";

  /** The icon for an item type string (falls back to the generic key). */
  export function typeIcon(typeStr: string): IconName {
    switch (typeStr) {
      case "login":
      case "note":
      case "api_key":
      case "env_set":
      case "ssh_key":
      case "totp":
        return `type-${typeStr}` as IconName;
      default:
        return "type-login";
    }
  }
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
  {#if name === "items" || name === "type-login"}
    <circle cx="8" cy="15" r="4" />
    <path d="M10.8 12.2 20 3M16 7l3 3M18.5 4.5l2 2" />
  {:else if name === "vault"}
    <rect x="3.5" y="4.5" width="17" height="15" rx="2.5" />
    <circle cx="12" cy="12" r="3.2" />
    <path d="M12 8.8V7.5M12 16.5v-1.3M15.2 12h1.3M7.5 12h1.3" />
  {:else if name === "generator"}
    <rect x="3.5" y="3.5" width="17" height="17" rx="3" />
    <circle cx="8.5" cy="8.5" r="1" fill="currentColor" stroke="none" />
    <circle cx="15.5" cy="15.5" r="1" fill="currentColor" stroke="none" />
    <circle cx="12" cy="12" r="1" fill="currentColor" stroke="none" />
  {:else if name === "security"}
    <path d="M12 3l7.5 3v5.5c0 4.5-3.2 8.2-7.5 9.5-4.3-1.3-7.5-5-7.5-9.5V6L12 3z" />
    <path d="M8.8 12.2l2.2 2.2 4.2-4.4" />
  {:else if name === "devices"}
    <rect x="3" y="5" width="13" height="9" rx="1.5" />
    <path d="M1.5 18h15" />
    <rect x="18" y="9" width="4.5" height="10" rx="1" />
  {:else if name === "dev" || name === "type-ssh_key"}
    <rect x="3" y="4.5" width="18" height="15" rx="2" />
    <path d="M7 10l3 2.5L7 15M12.5 15h4.5" />
  {:else if name === "help"}
    <circle cx="12" cy="12" r="9" />
    <path d="M9.6 9.3a2.5 2.5 0 0 1 4.8.9c0 1.7-2.4 2.2-2.4 3.8" />
    <circle cx="12" cy="17" r="0.9" fill="currentColor" stroke="none" />
  {:else if name === "settings"}
    <circle cx="12" cy="12" r="3" />
    <path
      d="M19.4 15a1.6 1.6 0 0 0 .3 1.8l.1.1a2 2 0 1 1-2.8 2.8l-.1-.1a1.6 1.6 0 0 0-1.8-.3 1.6 1.6 0 0 0-1 1.5V21a2 2 0 1 1-4 0v-.1a1.6 1.6 0 0 0-1-1.5 1.6 1.6 0 0 0-1.8.3l-.1.1a2 2 0 1 1-2.8-2.8l.1-.1a1.6 1.6 0 0 0 .3-1.8 1.6 1.6 0 0 0-1.5-1H3a2 2 0 1 1 0-4h.1a1.6 1.6 0 0 0 1.5-1 1.6 1.6 0 0 0-.3-1.8l-.1-.1a2 2 0 1 1 2.8-2.8l.1.1a1.6 1.6 0 0 0 1.8.3H9a1.6 1.6 0 0 0 1-1.5V3a2 2 0 1 1 4 0v.1a1.6 1.6 0 0 0 1 1.5 1.6 1.6 0 0 0 1.8-.3l.1-.1a2 2 0 1 1 2.8 2.8l-.1.1a1.6 1.6 0 0 0-.3 1.8V9a1.6 1.6 0 0 0 1.5 1H21a2 2 0 1 1 0 4h-.1a1.6 1.6 0 0 0-1.5 1z"
    />
  {:else if name === "more"}
    <circle cx="5" cy="12" r="1.5" fill="currentColor" stroke="none" />
    <circle cx="12" cy="12" r="1.5" fill="currentColor" stroke="none" />
    <circle cx="19" cy="12" r="1.5" fill="currentColor" stroke="none" />
  {:else if name === "trash"}
    <path d="M4 7h16M9.5 7V4.5h5V7M6.5 7l1 12.5h9l1-12.5" />
  {:else if name === "chevron"}
    <path d="M9 6l6 6-6 6" />
  {:else if name === "chevron-down"}
    <path d="M6 9l6 6 6-6" />
  {:else if name === "back"}
    <path d="M15 6l-6 6 6 6" />
  {:else if name === "eye"}
    <path d="M2.5 12s3.5-6.5 9.5-6.5S21.5 12 21.5 12s-3.5 6.5-9.5 6.5S2.5 12 2.5 12z" />
    <circle cx="12" cy="12" r="2.8" />
  {:else if name === "eye-off"}
    <path d="M10.6 5.6A9.7 9.7 0 0 1 12 5.5c6 0 9.5 6.5 9.5 6.5a17 17 0 0 1-2.6 3.4M6.6 6.6C4 8.3 2.5 12 2.5 12s3.5 6.5 9.5 6.5a9.4 9.4 0 0 0 5.4-1.6" />
    <path d="M9.9 9.9a2.8 2.8 0 0 0 4.2 4.2M3 3l18 18" />
  {:else if name === "copy"}
    <rect x="8.5" y="8.5" width="12" height="12" rx="2" />
    <path d="M15.5 8.5V5.5a2 2 0 0 0-2-2h-8a2 2 0 0 0-2 2v8a2 2 0 0 0 2 2h3" />
  {:else if name === "check"}
    <path d="M5 12.5l4.5 4.5L19 7.5" />
  {:else if name === "lock"}
    <rect x="5" y="10.5" width="14" height="10" rx="2" />
    <path d="M8 10.5V8a4 4 0 0 1 8 0v2.5" />
  {:else if name === "plus"}
    <path d="M12 5v14M5 12h14" />
  {:else if name === "search"}
    <circle cx="11" cy="11" r="6.5" />
    <path d="M20 20l-4.2-4.2" />
  {:else if name === "x"}
    <path d="M6 6l12 12M18 6L6 18" />
  {:else if name === "refresh"}
    <path d="M20 11a8 8 0 0 0-14.6-4.5L4 8M4 13a8 8 0 0 0 14.6 4.5L20 16" />
    <path d="M4 4v4h4M20 20v-4h-4" />
  {:else if name === "sync"}
    <path d="M4 12a8 8 0 0 1 13.7-5.7L20 8.5M20 12a8 8 0 0 1-13.7 5.7L4 15.5" />
    <path d="M20 4v4.5h-4.5M4 20v-4.5h4.5" />
  {:else if name === "download"}
    <path d="M12 4v11M7 10.5l5 5 5-5M5 20h14" />
  {:else if name === "upload"}
    <path d="M12 16V5M7 9.5l5-5 5 5M5 20h14" />
  {:else if name === "paperclip"}
    <path d="M20 11.5l-7.8 7.8a5 5 0 0 1-7.1-7.1l8.5-8.5a3.3 3.3 0 0 1 4.7 4.7l-8.5 8.5a1.7 1.7 0 0 1-2.4-2.4L15 6.9" />
  {:else if name === "external"}
    <path d="M14 4h6v6M20 4l-9 9M18 14v5a1 1 0 0 1-1 1H5a1 1 0 0 1-1-1V7a1 1 0 0 1 1-1h5" />
  {:else if name === "alert"}
    <path d="M10.3 4.2 2.7 17.5a2 2 0 0 0 1.7 3h15.2a2 2 0 0 0 1.7-3L13.7 4.2a2 2 0 0 0-3.4 0z" />
    <path d="M12 9.5v4" />
    <circle cx="12" cy="16.8" r="0.9" fill="currentColor" stroke="none" />
  {:else if name === "info"}
    <circle cx="12" cy="12" r="9" />
    <path d="M12 11v5" />
    <circle cx="12" cy="7.8" r="0.9" fill="currentColor" stroke="none" />
  {:else if name === "agent"}
    <rect x="4.5" y="8" width="15" height="11" rx="3" />
    <path d="M12 8V5M9.5 13h.01M14.5 13h.01M2 12.5v2M22 12.5v2" />
    <circle cx="12" cy="4" r="1" />
  {:else if name === "fingerprint"}
    <path d="M7 4.6A9 9 0 0 1 20.4 9M3.6 9.5A9 9 0 0 1 5 6.8" />
    <path d="M12 7a5 5 0 0 1 5 5c0 2.2-.3 4.3-1 6.2M7 12a5 5 0 0 1 2.4-4.3" />
    <path d="M7.2 15.4c.5-1 .8-2.2.8-3.4a4 4 0 0 1 8 0c0 1.2-.1 2.4-.3 3.5" />
    <path d="M12 12c0 3.3-1 6.3-2.8 8.6M4.2 14.8A13 13 0 0 0 4 12" />
  {:else if name === "qr"}
    <rect x="3.5" y="3.5" width="7" height="7" rx="1" />
    <rect x="13.5" y="3.5" width="7" height="7" rx="1" />
    <rect x="3.5" y="13.5" width="7" height="7" rx="1" />
    <path d="M13.5 13.5h3v3M20.5 13.5v.01M13.5 20.5h.01M17 20.5h3.5V17" />
  {:else if name === "camera"}
    <path d="M4 7.5h3l1.8-2.5h6.4L17 7.5h3a1.5 1.5 0 0 1 1.5 1.5v9a1.5 1.5 0 0 1-1.5 1.5H4A1.5 1.5 0 0 1 2.5 18V9A1.5 1.5 0 0 1 4 7.5z" />
    <circle cx="12" cy="13" r="3.5" />
  {:else if name === "folder"}
    <path d="M3.5 6.5a2 2 0 0 1 2-2h4l2 2.5h7a2 2 0 0 1 2 2v8.5a2 2 0 0 1-2 2h-13a2 2 0 0 1-2-2z" />
  {:else if name === "star"}
    <path d="M12 3.8l2.5 5.1 5.6.8-4 3.9.9 5.6-5-2.6-5 2.6.9-5.6-4-3.9 5.6-.8z" />
  {:else if name === "edit"}
    <path d="M4 20h4L19 9a2.8 2.8 0 0 0-4-4L4 16z" />
    <path d="M13.5 6.5l4 4" />
  {:else if name === "clock" || name === "type-totp"}
    <circle cx="12" cy="13" r="7.5" />
    <path d="M12 9.5V13l2.5 1.5M9.5 2.5h5" />
  {:else if name === "type-note"}
    <path d="M6 3.5h8.5l3.5 3.5v13.5H6z" />
    <path d="M14.5 3.5V7H18M9 12h6M9 15.5h4" />
  {:else if name === "type-api_key"}
    <path d="M8 7L3 12l5 5M16 7l5 5-5 5" />
  {:else if name === "type-env_set"}
    <rect x="4" y="3.5" width="16" height="17" rx="2" />
    <path d="M8 8.5h8M8 12h8M8 15.5h5" />
  {/if}
</svg>

<style>
  .icon {
    flex: none;
    display: block;
  }
</style>
