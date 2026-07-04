<!--
  SPDX-License-Identifier: MPL-2.0
  This file is part of the LocalPass desktop GUI. See ../../LICENSE.

  The generator. Password (length slider + symbol toggle) and passphrase (word
  count) via the Rust backend; entropy meter; copy button. The generated secret
  is held only in `result` (component-local) and cleared when the component is
  torn down (leaving the tab) — never a store.
-->
<script lang="ts">
  import { generatePassword, generatePassphrase } from "../lib/api";
  import type { GeneratedView } from "../lib/types";
  import { copyToClipboard } from "../lib/clipboard";
  import { formatEntropy, strengthBand } from "../lib/format";
  import { toast } from "../lib/toast";

  type Mode = "password" | "passphrase";
  let mode = $state<Mode>("password");

  // Password options.
  let length = $state(20);
  let symbols = $state(true);

  // Passphrase options.
  let words = $state(5);
  let separator = $state("-");

  let result = $state<GeneratedView | null>(null);
  let error = $state("");
  let busy = $state(false);

  async function generate() {
    busy = true;
    error = "";
    try {
      result =
        mode === "password"
          ? await generatePassword(length, symbols)
          : await generatePassphrase(words, separator);
    } catch (err) {
      result = null;
      error = typeof err === "string" ? err : "Generation failed.";
    } finally {
      busy = false;
    }
  }

  async function copy() {
    if (!result) return;
    const ok = await copyToClipboard(result.secret);
    toast(ok ? "Copied to clipboard" : "Copy failed", ok ? "ok" : "error");
  }

  const band = $derived(result ? strengthBand(result.entropy_bits) : "weak");
  const meterPct = $derived(result ? Math.min(100, (result.entropy_bits / 128) * 100) : 0);

  // Clear the generated secret when leaving the generator.
  $effect(() => () => {
    result = null;
  });
</script>

<div class="detail">
  <h2>Generator</h2>

  <div class="toolbar" role="tablist" aria-label="Generator mode" style="margin-bottom:1rem">
    <button
      class="btn {mode === 'password' ? 'btn-primary' : ''}"
      role="tab"
      aria-selected={mode === "password"}
      onclick={() => (mode = "password")}
    >
      Password
    </button>
    <button
      class="btn {mode === 'passphrase' ? 'btn-primary' : ''}"
      role="tab"
      aria-selected={mode === "passphrase"}
      onclick={() => (mode = "passphrase")}
    >
      Passphrase
    </button>
  </div>

  {#if mode === "password"}
    <div class="field-group">
      <label for="len">Length: {length}</label>
      <input id="len" type="range" min="8" max="64" bind:value={length} />
    </div>
    <div class="field-group">
      <label style="display:flex;align-items:center;gap:0.5em;font-weight:400">
        <input type="checkbox" bind:checked={symbols} />
        Include symbols
      </label>
    </div>
  {:else}
    <div class="field-group">
      <label for="words">Words: {words}</label>
      <input id="words" type="range" min="3" max="12" bind:value={words} />
    </div>
    <div class="field-group">
      <label for="sep">Separator</label>
      <input id="sep" type="text" maxlength="3" bind:value={separator} style="max-width:100px" />
    </div>
  {/if}

  <button class="btn btn-primary" onclick={generate} disabled={busy}>
    {busy ? "Generating…" : "Generate"}
  </button>

  {#if error}
    <div class="error" role="alert">{error}</div>
  {/if}

  {#if result}
    <div class="gen-output">
      <div class="val" aria-label="Generated secret" style="user-select:all">
        {result.secret}
      </div>
      <button class="btn" onclick={copy} aria-label="Copy generated secret">Copy</button>
    </div>
    <div class="meter {band}" aria-hidden="true">
      <span style={`width:${meterPct}%`}></span>
    </div>
    <p class="hint" aria-live="polite">
      Entropy: {formatEntropy(result.entropy_bits)} — <strong>{band}</strong>
    </p>
  {/if}
</div>
