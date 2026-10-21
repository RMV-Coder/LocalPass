<!--
  SPDX-License-Identifier: MPL-2.0
  This file is part of the LocalPass desktop GUI. See ../../LICENSE.

  First-run onboarding (zero-terminal). Two steps:
    1. Choose a master password (+ confirm), min 10 chars, inline validation.
    2. Emergency Kit — the Secret Key is shown ONCE (component-local state,
       cleared when leaving this step / component), with the no-recovery
       doctrine, a copy action, and a "I have saved my Secret Key" checkbox
       that gates Continue.

  The password lives only in component-local vars and is cleared right after
  the create call returns. The Secret Key lives only in `kit` and is wiped on
  continue and on teardown — never a store, never persisted in JS.
-->
<script lang="ts">
  import { createAccount } from "../lib/api";
  import type { CreatedAccount } from "../lib/types";
  import { copySecretVia } from "../lib/clipboard";
  import { toast } from "../lib/toast";
  import Mark from "./Mark.svelte";
  import Icon from "./Icon.svelte";

  interface Props {
    /** Called once onboarding is complete (the daemon holds the unlocked
     *  session already; the parent refreshes into the Vault). */
    onDone: () => void;
  }
  let { onDone }: Props = $props();

  const MIN_LEN = 10;

  let password = $state("");
  let confirm = $state("");
  let show = $state(false);
  let error = $state("");
  let busy = $state(false);

  // The Emergency Kit, present only after a successful create. Holds the Secret
  // Key — component-local, cleared on continue/teardown.
  let kit = $state<CreatedAccount | null>(null);
  let saved = $state(false); // "I have saved my Secret Key" checkbox
  let copied = $state(false);

  const tooShort = $derived(password.length > 0 && password.length < MIN_LEN);
  const mismatch = $derived(confirm.length > 0 && confirm !== password);
  const canSubmit = $derived(password.length >= MIN_LEN && confirm === password && !busy);

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
    const via = await copySecretVia(kit.secret_key);
    if (!via) {
      toast("Copy failed", "error");
      return;
    }
    copied = true;
    setTimeout(() => (copied = false), 1600);
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
  <div class="ob">
    <Mark size={56} />

    {#if !kit}
      <h1>Set up LocalPass</h1>
      <p class="lead">
        Your vault lives on this device, encrypted. Choose a master password: it and
        your Secret Key are the only way in. There is no reset.
      </p>
      <form onsubmit={submit} novalidate>
        <div class="field-group">
          <label for="ob-password">Master password</label>
          <div class="input-affix">
            <!-- svelte-ignore a11y_autofocus -->
            <input
              id="ob-password"
              type={show ? "text" : "password"}
              autocomplete="new-password"
              spellcheck="false"
              bind:value={password}
              autofocus
              aria-describedby="ob-password-hint"
              aria-invalid={tooShort ? "true" : undefined}
              disabled={busy}
            />
            <button
              type="button"
              class="icon-btn"
              aria-label={show ? "Hide passwords" : "Show passwords"}
              aria-pressed={show}
              onclick={() => (show = !show)}
            >
              <Icon name={show ? "eye-off" : "eye"} size={18} />
            </button>
          </div>
          <p class="hint" id="ob-password-hint" class:warn={tooShort}>
            {tooShort ? `${MIN_LEN - password.length} more characters needed` : `At least ${MIN_LEN} characters`}
          </p>
        </div>

        <div class="field-group">
          <label for="ob-confirm">Confirm master password</label>
          <input
            id="ob-confirm"
            type={show ? "text" : "password"}
            autocomplete="new-password"
            spellcheck="false"
            bind:value={confirm}
            aria-invalid={mismatch ? "true" : undefined}
            aria-describedby={mismatch ? "ob-confirm-err" : undefined}
            disabled={busy}
          />
          {#if mismatch}
            <p class="hint warn" id="ob-confirm-err">The passwords do not match.</p>
          {/if}
        </div>

        {#if error}
          <div class="error" role="alert">{error}</div>
        {/if}

        <button class="btn btn-primary btn-block" type="submit" disabled={!canSubmit}>
          {busy ? "Creating your vault…" : "Create vault"}
        </button>
      </form>
    {:else}
      <h1>Save your Secret Key</h1>
      <p class="lead">
        It is mixed into your master password. You need both to unlock on a new
        device. You will not see it again, so store it offline now.
      </p>

      <button type="button" class="copy-row key" class:copied onclick={copyKey} aria-label="Copy Secret Key">
        <span>
          <span class="k">Secret Key</span>
          <span class="v">{kit.secret_key}</span>
        </span>
        <span class="acts">
          <span class="copy-hint">
            {#if copied}<Icon name="check" size={14} /> Copied{:else}<Icon name="copy" size={14} /> Copy{/if}
          </span>
        </span>
      </button>

      <div class="callout warn" role="note">
        <span class="icon"><Icon name="alert" size={16} /></span>
        <span>
          <strong>No recovery.</strong> Lose your master password, this Secret Key and
          every device, and the data is gone. That is the design.
        </span>
      </div>

      <label class="check confirm">
        <input type="checkbox" bind:checked={saved} />
        <span>I have saved my Secret Key somewhere safe.</span>
      </label>

      <button class="btn btn-primary btn-block" onclick={continueToVault} disabled={!saved}>
        Open my vault
      </button>
    {/if}
  </div>
</div>

<style>
  .ob {
    width: min(400px, 100%);
    display: grid;
    justify-items: center;
    text-align: center;
  }
  h1 {
    font-size: 22px;
    margin: 18px 0 6px;
  }
  .lead {
    color: var(--text-muted);
    font-size: 13.5px;
    margin-bottom: 22px;
    max-width: 36ch;
  }
  form,
  .copy-row,
  .callout,
  .confirm {
    width: 100%;
    text-align: left;
  }
  .hint.warn {
    color: var(--warning);
  }
  .key {
    background: var(--bg-hover);
    margin-bottom: 4px;
  }
  .key .copy-hint {
    opacity: 1;
  }
  .confirm {
    margin: 14px 0 16px;
    font-size: 13.5px;
  }
</style>
