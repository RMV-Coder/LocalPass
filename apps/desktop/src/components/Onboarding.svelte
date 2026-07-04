<!--
  SPDX-License-Identifier: MPL-2.0
  This file is part of the LocalPass desktop GUI. See ../../LICENSE.

  First-run onboarding (zero-terminal). Two steps:
    1. Choose a master password (+ confirm), min 10 chars, inline validation.
    2. Emergency Kit — the Secret Key is shown ONCE (component-local state,
       cleared when leaving this step / component), with the no-recovery
       doctrine, a Copy button, and a "I have saved my Secret Key" checkbox that
       gates Continue.

  The password lives only in component-local vars and is cleared right after the
  create call returns. The Secret Key lives only in `kit` and is wiped on
  continue and on teardown — never a store, never persisted in JS.
-->
<script lang="ts">
  import { createAccount } from "../lib/api";
  import type { CreatedAccount } from "../lib/types";
  import { copyToClipboard } from "../lib/clipboard";
  import { toast } from "../lib/toast";

  interface Props {
    /** Called once onboarding is complete (the daemon holds the unlocked
     *  session already; the parent refreshes into the Vault). */
    onDone: () => void;
  }
  let { onDone }: Props = $props();

  const MIN_LEN = 10;

  let password = $state("");
  let confirm = $state("");
  let error = $state("");
  let busy = $state(false);

  // The Emergency Kit, present only after a successful create. Holds the Secret
  // Key — component-local, cleared on continue/teardown.
  let kit = $state<CreatedAccount | null>(null);
  let saved = $state(false); // "I have saved my Secret Key" checkbox

  const tooShort = $derived(password.length > 0 && password.length < MIN_LEN);
  const mismatch = $derived(confirm.length > 0 && confirm !== password);
  const canSubmit = $derived(
    password.length >= MIN_LEN && confirm === password && !busy,
  );

  async function submit(e: Event) {
    e.preventDefault();
    if (!canSubmit) return;
    busy = true;
    error = "";
    try {
      const created = await createAccount(password, confirm);
      // Clear the password material from JS the instant the call returns.
      password = "";
      confirm = "";
      kit = created;
    } catch (err) {
      password = "";
      confirm = "";
      error = typeof err === "string" ? err : "Could not create the account.";
    } finally {
      busy = false;
    }
  }

  async function copyKey() {
    if (!kit) return;
    const ok = await copyToClipboard(kit.secret_key);
    toast(ok ? "Secret Key copied" : "Copy failed", ok ? "ok" : "error");
  }

  function continueToVault() {
    // Wipe the Secret Key from component state before leaving.
    kit = null;
    saved = false;
    onDone();
  }

  // Defensive: wipe the Secret Key if the component is ever torn down while the
  // kit is still shown.
  $effect(() => () => {
    kit = null;
  });
</script>

<div class="center">
  <div class="card" style="max-width:520px">
    <div class="brand">
      <div class="logo" aria-hidden="true">L</div>
      <div>
        <h1>Welcome to LocalPass</h1>
        <p class="muted" style="margin:0">Fully local. Offline. Yours.</p>
      </div>
    </div>

    {#if !kit}
      <!-- Step 1: choose a master password. -->
      <h2 style="margin-top:0">Create your account</h2>
      <p class="muted">
        Choose a master password. There is no cloud reset — this password plus
        your Secret Key are the only way into your data, so pick something strong
        and memorable.
      </p>
      <form onsubmit={submit} novalidate>
        <div class="field-group">
          <label for="ob-password">Master password</label>
          <!-- svelte-ignore a11y_autofocus -->
          <input
            id="ob-password"
            type="password"
            autocomplete="new-password"
            bind:value={password}
            autofocus
            aria-describedby="ob-password-hint"
            aria-invalid={tooShort ? "true" : undefined}
            disabled={busy}
          />
          <p class="hint" id="ob-password-hint">
            At least {MIN_LEN} characters.
            {#if tooShort}<span class="mono" style="color:var(--danger)"
                >{MIN_LEN - password.length} more needed.</span
              >{/if}
          </p>
        </div>

        <div class="field-group">
          <label for="ob-confirm">Confirm master password</label>
          <input
            id="ob-confirm"
            type="password"
            autocomplete="new-password"
            bind:value={confirm}
            aria-invalid={mismatch ? "true" : undefined}
            aria-describedby={mismatch ? "ob-confirm-err" : undefined}
            disabled={busy}
          />
          {#if mismatch}
            <p class="hint" id="ob-confirm-err" style="color:var(--danger)">
              The passwords do not match.
            </p>
          {/if}
        </div>

        {#if error}
          <div class="error" role="alert">{error}</div>
        {/if}

        <button
          class="btn btn-primary"
          type="submit"
          disabled={!canSubmit}
          style="width:100%"
        >
          {busy ? "Creating account…" : "Create account"}
        </button>
      </form>
    {:else}
      <!-- Step 2: Emergency Kit — the Secret Key is shown ONCE. -->
      <h2 style="margin-top:0">Save your Emergency Kit</h2>
      <p class="muted">
        This is your <strong>Secret Key</strong> — a second factor mixed into
        your master password. Print it or save it offline <strong>now</strong>.
        You will not see it again.
      </p>

      <div class="field-group">
        <label id="sk-label" for="sk-value">Secret Key</label>
        <div class="gen-output">
          <div
            id="sk-value"
            class="val"
            aria-labelledby="sk-label"
            style="user-select:all"
          >
            {kit.secret_key}
          </div>
          <button class="btn" onclick={copyKey} aria-label="Copy Secret Key">
            Copy
          </button>
        </div>
        <p class="hint">
          Profile: <span class="mono">{kit.profile}</span>
        </p>
      </div>

      <div class="error" role="note" style="color:var(--text);background:var(--bg-hover);border-color:var(--border)">
        <strong>There is NO cloud reset and NO recovery service.</strong>
        If you lose your master password <strong>and</strong> this Secret Key
        <strong>and</strong> all your devices, your data is gone forever. That is
        the design.
      </div>

      <div class="field-group" style="margin-top:1rem">
        <label style="display:flex;align-items:center;gap:0.5em;font-weight:400">
          <input type="checkbox" bind:checked={saved} />
          I have saved my Secret Key somewhere safe.
        </label>
      </div>

      <button
        class="btn btn-primary"
        onclick={continueToVault}
        disabled={!saved}
        style="width:100%"
      >
        Continue
      </button>
    {/if}
  </div>
</div>
