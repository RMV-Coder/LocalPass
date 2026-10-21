<!--
  SPDX-License-Identifier: MPL-2.0
  This file is part of the LocalPass desktop GUI. See ../../LICENSE.

  The LocalPass mark, "Keyhole-L" (DESIGN.md "Brand mark"): a keyhole whose
  slot kicks right into an L, cut from a rounded tile. The same geometry as
  ../../brand/mark.svg, inlined so the keyhole can turn: `turned` rotates it a
  quarter about the keyhole's centre, which is the unlock motion (and turning
  back is the lock). Decorative by default; pass `label` when the mark stands
  alone and must be announced.
-->
<script lang="ts">
  interface Props {
    size?: number;
    /** "tile" = brass tile, ink keyhole (the app icon). "inverse" = ink tile,
     *  brass keyhole, for small lockups on light surfaces. */
    variant?: "tile" | "inverse";
    /** The keyhole is turned a quarter (unlocked). Animated by CSS. */
    turned?: boolean;
    label?: string;
  }
  let { size = 24, variant = "tile", turned = false, label }: Props = $props();

  const tile = $derived(variant === "tile" ? "var(--mk-accent)" : "var(--mk-ink)");
  const hole = $derived(variant === "tile" ? "var(--mk-ink)" : "var(--mk-accent)");
</script>

<svg
  class="mark"
  class:turned
  width={size}
  height={size}
  viewBox="0 0 100 100"
  role={label ? "img" : undefined}
  aria-label={label}
  aria-hidden={label ? undefined : "true"}
  focusable="false"
>
  <rect width="100" height="100" rx="23" fill={tile} />
  <g class="keyhole" fill={hole}>
    <circle cx="46" cy="41" r="13.5" />
    <path
      d="M40.5 41V71.2a2.8 2.8 0 0 0 2.8 2.8H64.7a2.8 2.8 0 0 0 2.8-2.8V65.8a2.8 2.8 0 0 0-2.8-2.8H51.5V41z"
    />
  </g>
</svg>

<style>
  .mark {
    display: block;
    flex: none;
  }
  /* Turn about the keyhole's circle, like a key in a cylinder. */
  .keyhole {
    transform-box: view-box;
    transform-origin: 46px 41px;
    transition: transform 520ms var(--ease-turn);
  }
  .turned .keyhole {
    transform: rotate(-90deg);
  }
</style>
