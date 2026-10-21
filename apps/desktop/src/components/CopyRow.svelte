<!--
  SPDX-License-Identifier: MPL-2.0
  This file is part of the LocalPass desktop GUI. See ../../LICENSE.

  One field row whose surface is the copy action (DESIGN.md "Click to copy"):
  the label + value are a real <button>, so it is focusable and announced
  with its value. Pointer hover says "Click to copy"; a click (or Enter /
  Space) runs `copy` and confirms in place for ~1.6s. Secret rows get one
  more control beside it, the eye, which toggles the reveal without copying
  (a sibling, never nested: a button's children are presentational to
  assistive tech). The row
  never fetches a value itself: the parent's `copy` / `onToggleReveal` do,
  through the gesture-gated reveal path.
-->
<script lang="ts">
  import type { Snippet } from "svelte";
  import Icon from "./Icon.svelte";

  interface Props {
    label: string;
    /** The text shown. For a hidden secret pass the mask. */
    display: string;
    /** Render `display` in the UI font rather than mono (prose values). */
    plain?: boolean;
    secret?: boolean;
    revealed?: boolean;
    revealBusy?: boolean;
    /** Copy the value. Resolve to "native" when the copy is history-excluded
     *  and auto-cleared, "webview" for a plain copy, null on failure, or
     *  undefined when nothing happened (e.g. a cancelled save dialog). */
    copy: () => Promise<"native" | "webview" | null | undefined>;
    /** The confirmation word ("Copied", "Saved"). */
    done?: string;
    onToggleReveal?: () => void;
    /** Extra trailing controls (e.g. a TOTP ring). */
    trailing?: Snippet;
    /** Replaces the value line entirely (e.g. the TOTP code). */
    value?: Snippet;
    hint?: string;
    /** A quiet line under the value (e.g. a file size). */
    meta?: string;
  }
  let {
    label,
    display,
    plain = false,
    secret = false,
    revealed = false,
    revealBusy = false,
    copy,
    onToggleReveal,
    trailing,
    value,
    hint = "Click to copy",
    meta,
    done = "Copied",
  }: Props = $props();

  let phase = $state<"idle" | "busy" | "copied" | "failed">("idle");
  let note = $state("");
  let timer: ReturnType<typeof setTimeout> | undefined;

  async function run() {
    if (phase === "busy") return;
    phase = "busy";
    const via = await copy();
    clearTimeout(timer);
    if (via === undefined) {
      phase = "idle";
      return;
    }
    if (via === null) {
      phase = "failed";
      note = `${done === "Copied" ? "Copy" : "Save"} failed`;
    } else {
      phase = "copied";
      note = via === "native" && secret ? `${done} · clears in 30s` : done;
    }
    timer = setTimeout(() => (phase = "idle"), 1600);
  }

  $effect(() => () => clearTimeout(timer));
</script>

<div class="copy-row" class:copied={phase === "copied"}>
  <button type="button" class="cr-main" onclick={run}>
    <span class="main">
      <span class="k">{label}</span>
      {#if value}
        {@render value()}
      {:else if secret && !revealed}
        <span class="v masked" aria-hidden="true">{display}</span>
        <span class="sr-only">hidden</span>
      {:else}
        <span class="v" class:plain>{display}</span>
      {/if}
      {#if meta}<span class="meta">{meta}</span>{/if}
    </span>
    <span class="copy-hint" class:fail={phase === "failed"} aria-live="polite">
      {#if phase === "copied"}
        <Icon name="check" size={14} /> {note}
      {:else if phase === "failed"}
        <Icon name="alert" size={14} /> {note}
      {:else}
        {hint}
      {/if}
    </span>
  </button>
  {#if trailing || (secret && onToggleReveal)}
    <span class="acts">
      {#if trailing}{@render trailing()}{/if}
      {#if secret && onToggleReveal}
        <button
          type="button"
          class="icon-btn"
          aria-label={revealed ? `Hide ${label}` : `Reveal ${label}`}
          aria-pressed={revealed}
          title={revealed ? "Hide" : "Reveal"}
          disabled={revealBusy}
          onclick={onToggleReveal}
        >
          <Icon name={revealed ? "eye-off" : "eye"} size={18} />
        </button>
      {/if}
    </span>
  {/if}
</div>

<style>
  .main {
    min-width: 0;
  }
  .meta {
    display: block;
    font-size: 12px;
    color: var(--text-faint);
  }
  .copy-hint.fail {
    opacity: 1;
    color: var(--danger);
  }
</style>
