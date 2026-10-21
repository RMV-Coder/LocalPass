<!--
  SPDX-License-Identifier: MPL-2.0
  This file is part of the LocalPass desktop GUI. See ../../LICENSE.

  The generator. Password (length + symbols) and passphrase (word count +
  separator), computed by the Rust backend. The result is the page's hero:
  click it to copy, regenerate with the button or by changing an option. The
  generated secret is held only in `result` (component-local) and cleared when
  the component is torn down (leaving the tab) — never a store.
-->
<script lang="ts">
  import { generatePassword, generatePassphrase } from "../lib/api";
  import type { GeneratedView } from "../lib/types";
  import { copySecretVia } from "../lib/clipboard";
  import { formatEntropy, strengthBand } from "../lib/format";
  import Icon from "./Icon.svelte";

  type Mode = "password" | "passphrase";
  let mode = $state<Mode>("password");

  let length = $state(20);
  let symbols = $state(true);
  let words = $state(5);
  let separator = $state("-");

  let result = $state<GeneratedView | null>(null);
  let error = $state("");
  let busy = $state(false);
  let copied = $state<"" | "native" | "webview">("");
  let copyTimer: ReturnType<typeof setTimeout> | undefined;

  let seq = 0;
  async function generate() {
    const mine = ++seq;
    busy = true;
    error = "";
    try {
      const next =
        mode === "password"
          ? await generatePassword(length, symbols)
          : await generatePassphrase(words, separator);
      if (mine === seq) result = next;
    } catch (err) {
      if (mine === seq) {
        result = null;
        error = typeof err === "string" ? err : "Generation failed.";
      }
    } finally {
      if (mine === seq) busy = false;
    }
  }

  async function copy() {
    if (!result) return;
    const via = await copySecretVia(result.secret);
    if (!via) {
      error = "Copy failed.";
      return;
    }
    copied = via;
    clearTimeout(copyTimer);
    copyTimer = setTimeout(() => (copied = ""), 1600);
  }

  // Regenerate whenever an option changes (and once on open).
  $effect(() => {
    void mode;
    void length;
    void symbols;
    void words;
    void separator;
    const t = setTimeout(generate, 60);
    return () => clearTimeout(t);
  });

  const band = $derived(result ? strengthBand(result.entropy_bits) : "weak");
  const meterPct = $derived(result ? Math.min(100, (result.entropy_bits / 128) * 100) : 0);
  const BAND_LABEL = { weak: "Weak", fair: "Fair", strong: "Strong", excellent: "Excellent" };

  // Clear the generated secret when leaving the generator.
  $effect(() => () => {
    clearTimeout(copyTimer);
    result = null;
  });
</script>

<div class="page gen">
  <div class="page-head">
    <h2>Generator</h2>
    <div class="seg" role="tablist" aria-label="Kind">
      <button role="tab" aria-selected={mode === "password"} onclick={() => (mode = "password")}>Password</button>
      <button role="tab" aria-selected={mode === "passphrase"} onclick={() => (mode = "passphrase")}>Passphrase</button>
    </div>
  </div>

  <div class="output" class:copied={!!copied}>
    <button class="out-val" onclick={copy} disabled={!result} aria-label="Copy generated value">
      <span class="val" class:dim={busy}>{result?.secret ?? " "}</span>
      <span class="out-hint" aria-live="polite">
        {#if copied}<Icon name="check" size={14} /> Copied{copied === "native" ? " · clears in 30s" : ""}{:else}Click to copy{/if}
      </span>
    </button>
    <button class="icon-btn regen" onclick={generate} aria-label="Generate another" title="Generate another" disabled={busy}>
      <Icon name="refresh" size={18} />
    </button>
  </div>

  {#if result}
    <div class="strength">
      <div class="meter {band}" aria-hidden="true"><span style={`width:${meterPct}%`}></span></div>
      <p class="hint" aria-live="polite">
        <strong class="band {band}">{BAND_LABEL[band]}</strong> · {formatEntropy(result.entropy_bits)} of entropy
      </p>
    </div>
  {/if}

  {#if error}
    <div class="error" role="alert">{error}</div>
  {/if}

  <div class="opts">
    {#if mode === "password"}
      <div class="set-row">
        <label for="len" class="t">Length</label>
        <div class="slider">
          <input id="len" type="range" min="8" max="64" bind:value={length} />
          <span class="num">{length}</span>
        </div>
      </div>
      <div class="set-row">
        <div>
          <div class="t">Symbols</div>
          <div class="d">Some sites reject them; turn off if a site complains.</div>
        </div>
        <label class="switch"><input type="checkbox" bind:checked={symbols} aria-label="Include symbols" /><span></span></label>
      </div>
    {:else}
      <div class="set-row">
        <label for="words" class="t">Words</label>
        <div class="slider">
          <input id="words" type="range" min="3" max="12" bind:value={words} />
          <span class="num">{words}</span>
        </div>
      </div>
      <div class="set-row">
        <label for="sep" class="t">Separator</label>
        <input id="sep" type="text" class="mono sep" maxlength="3" bind:value={separator} />
      </div>
    {/if}
  </div>
</div>

<style>
  .gen {
    max-width: 640px;
  }
  .output {
    display: flex;
    align-items: stretch;
    gap: 6px;
    margin-top: 4px;
  }
  .out-val {
    flex: 1;
    min-width: 0;
    display: grid;
    gap: 6px;
    padding: 18px 18px 12px;
    border: 1px solid var(--border-strong);
    border-radius: var(--radius-lg);
    background: var(--bg-content);
    color: var(--text);
    text-align: left;
    cursor: pointer;
    transition: background-color var(--dur-fast) ease, border-color var(--dur-fast) ease;
  }
  .out-val:hover:not(:disabled) {
    background: var(--bg-hover);
  }
  .copied .out-val {
    border-color: var(--success);
  }
  .val {
    font-family: var(--mono);
    font-size: 20px;
    line-height: 1.45;
    overflow-wrap: anywhere;
    min-height: 1.45em;
    transition: opacity var(--dur-fast) ease;
  }
  .val.dim {
    opacity: 0.55;
  }
  .out-hint {
    display: inline-flex;
    align-items: center;
    gap: 5px;
    font-size: 12px;
    color: var(--text-faint);
  }
  .copied .out-hint {
    color: var(--success);
  }
  .regen {
    align-self: center;
  }
  .strength {
    margin-top: 12px;
  }
  .meter {
    height: 4px;
    border-radius: 999px;
    background: var(--border);
    overflow: hidden;
  }
  .meter > span {
    display: block;
    height: 100%;
    transition: width var(--dur) var(--ease-out);
  }
  .meter.weak > span {
    background: var(--danger);
  }
  .meter.fair > span {
    background: var(--warning);
  }
  .meter.strong > span,
  .meter.excellent > span {
    background: var(--success);
  }
  .band.weak {
    color: var(--danger);
  }
  .band.fair {
    color: var(--warning);
  }
  .band.strong,
  .band.excellent {
    color: var(--success);
  }
  .opts {
    margin-top: 22px;
    border-top: 1px solid var(--border);
  }
  .slider {
    display: flex;
    align-items: center;
    gap: 12px;
    width: min(280px, 55%);
  }
  .slider .num {
    min-width: 2.5ch;
    text-align: right;
    font-weight: 600;
  }
  .sep {
    width: 72px;
    text-align: center;
  }
</style>
