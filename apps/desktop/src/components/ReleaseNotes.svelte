<!--
  SPDX-License-Identifier: MPL-2.0
  This file is part of the LocalPass desktop GUI. See ../../LICENSE.

  Release notes as plain text blocks (lib/releasenotes.ts). Text only: no
  HTML from the notes is ever rendered, and links are not followed.
-->
<script lang="ts">
  import { parseReleaseNotes } from "../lib/releasenotes";

  interface Props {
    notes: string;
  }
  let { notes }: Props = $props();

  const blocks = $derived(parseReleaseNotes(notes));
</script>

{#if blocks.length === 0}
  <p class="faint">No release notes.</p>
{:else}
  <div class="rn">
    {#each blocks as b, i (i)}
      {#if b.kind === "heading"}
        <p class="h">{b.text}</p>
      {:else if b.kind === "item"}
        <p class="li">{b.text}</p>
      {:else}
        <p>{b.text}</p>
      {/if}
    {/each}
  </div>
{/if}

<style>
  .rn {
    display: grid;
    gap: 3px;
    font-size: 13px;
    line-height: 1.5;
    overflow-wrap: anywhere;
  }
  .h {
    font-weight: 600;
    margin-top: 4px;
  }
  .h:first-child {
    margin-top: 0;
  }
  .li {
    position: relative;
    padding-left: 14px;
  }
  .li::before {
    content: "";
    position: absolute;
    left: 3px;
    top: 0.65em;
    width: 4px;
    height: 4px;
    border-radius: 50%;
    background: var(--text-faint);
  }
</style>
