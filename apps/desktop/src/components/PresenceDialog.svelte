<!--
  SPDX-License-Identifier: MPL-2.0
  This file is part of the LocalPass desktop GUI. See ../LICENSE.

  The master-password dialog for the human-presence check (mcp-server.md §7).
  While an AI agent is connected, a change or consent request needs a person to
  confirm first; `lib/presence.ts` opens this dialog through the prompt it
  registers here, and retries the request once confirmed. The password lives in
  a component-local variable, is cleared the moment the check returns, and is
  never stored.
-->
<script lang="ts">
  import { describeAction, setPresencePrompt } from "../lib/presence";

  type Open = {
    action: string;
    submit: (password: string) => Promise<void>;
    resolve: (ok: boolean) => void;
  };

  let open = $state<Open | null>(null);
  let password = $state("");
  let error = $state<string | null>(null);
  let busy = $state(false);
  let input: HTMLInputElement | undefined = $state();

  $effect(() => {
    setPresencePrompt(
      (action, submit) =>
        new Promise<boolean>((resolve) => {
          error = null;
          password = "";
          open = { action, submit, resolve };
        }),
    );
    return () => setPresencePrompt(null);
  });

  $effect(() => {
    if (open) input?.focus();
  });

  function close(ok: boolean) {
    const current = open;
    open = null;
    password = "";
    error = null;
    current?.resolve(ok);
  }

  async function confirm(e: Event) {
    e.preventDefault();
    if (!open || busy || password.length === 0) return;
    busy = true;
    try {
      await open.submit(password);
      password = "";
      close(true);
    } catch (err) {
      password = "";
      error = typeof err === "string" ? err : "Could not check the password.";
      input?.focus();
    } finally {
      busy = false;
    }
  }
</script>

{#if open}
  <div
    class="modal-overlay"
    role="button"
    tabindex="-1"
    aria-label="Cancel"
    onclick={() => close(false)}
    onkeydown={(e) => { if (e.key === "Escape") close(false); }}
  >
    <div
      class="modal-card"
      role="dialog"
      tabindex="-1"
      aria-modal="true"
      aria-labelledby="presence-title"
      aria-describedby="presence-why"
      onclick={(e) => e.stopPropagation()}
      onkeydown={(e) => { if (e.key === "Escape") close(false); }}
    >
      <h2 id="presence-title" class="modal-title">Confirm it's you</h2>
      <p id="presence-why" class="muted">
        An AI agent is connected to LocalPass. {describeAction(open.action)} needs
        your master password, so a program the agent started can't make it on its own.
      </p>
      <form onsubmit={confirm} novalidate>
        <div class="field-group">
          <label for="presence-password">Master password</label>
          <input
            id="presence-password"
            type="password"
            autocomplete="current-password"
            bind:this={input}
            bind:value={password}
            aria-invalid={error ? "true" : undefined}
            aria-describedby={error ? "presence-error" : undefined}
            disabled={busy}
          />
        </div>
        {#if error}
          <div class="error" id="presence-error" role="alert">{error}</div>
        {/if}
        <p class="hint">Approved changes need no password again for 5 minutes.</p>
        <div class="modal-actions">
          <button type="button" class="btn" onclick={() => close(false)} disabled={busy}>
            Cancel
          </button>
          <button class="btn btn-primary" type="submit" disabled={busy || password.length === 0}>
            {busy ? "Checking…" : "Confirm"}
          </button>
        </div>
      </form>
    </div>
  </div>
{/if}
