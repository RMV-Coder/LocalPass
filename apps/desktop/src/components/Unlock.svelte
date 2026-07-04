<!--
  SPDX-License-Identifier: MPL-2.0
  This file is part of the LocalPass desktop GUI. See ../../LICENSE.

  The unlock screen. Handles the locked, no-daemon, wrong-profile, and error
  states. The password is kept in a component-local variable, sent to the
  backend's `unlock` command, and cleared immediately after (never a store).
-->
<script lang="ts">
  import { unlock as unlockApi } from "../lib/api";
  import type { SessionState } from "../lib/types";

  interface Props {
    session: SessionState;
    onUnlocked: (s: SessionState) => void;
    onRefresh: () => void;
  }
  let { session, onUnlocked, onRefresh }: Props = $props();

  let password = $state("");
  let error = $state("");
  let busy = $state(false);
  let passwordInput: HTMLInputElement | undefined = $state();

  async function submit(e: Event) {
    e.preventDefault();
    if (busy || password.length === 0) return;
    busy = true;
    error = "";
    try {
      const next = await unlockApi(password);
      // Clear the password from JS the instant the call returns, win or lose.
      password = "";
      if (next.state === "unlocked") {
        onUnlocked(next);
      } else if (next.state === "error") {
        error = next.message;
      } else if (next.state === "no_daemon") {
        error = "The LocalPass daemon stopped. Start it and try again.";
      } else {
        error = "Unlock did not succeed. Check your master password.";
      }
    } catch (err) {
      password = "";
      error = typeof err === "string" ? err : "Unlock failed.";
    } finally {
      busy = false;
      passwordInput?.focus();
    }
  }
</script>

<div class="center">
  <div class="card">
    <div class="brand">
      <div class="logo" aria-hidden="true">L</div>
      <div>
        <h1>LocalPass</h1>
        <p class="muted" style="margin:0">Fully local. Offline. Yours.</p>
      </div>
    </div>

    {#if session.state === "no_daemon"}
      <h2 style="margin-top:0">No daemon running</h2>
      <p class="muted">
        The desktop app talks to the LocalPass daemon. Start it from a terminal,
        then reconnect:
      </p>
      <p class="mono" style="background:var(--bg-hover);padding:0.6em;border-radius:6px">
        localpass daemon start
      </p>
      <button class="btn btn-primary" onclick={onRefresh} disabled={busy}>
        Reconnect
      </button>
    {:else if session.state === "wrong_profile"}
      <h2 style="margin-top:0">Different profile</h2>
      <p class="muted">
        A daemon is running but serving a different profile:
      </p>
      <p class="mono" style="background:var(--bg-hover);padding:0.6em;border-radius:6px">
        {session.expected}
      </p>
      <p class="muted">Stop that daemon (or point this app at that profile).</p>
      <button class="btn" onclick={onRefresh} disabled={busy}>Reconnect</button>
    {:else}
      <form onsubmit={submit} novalidate>
        <div class="field-group">
          <label for="master-password">Master password</label>
          <!-- svelte-ignore a11y_autofocus -->
          <input
            id="master-password"
            type="password"
            autocomplete="current-password"
            bind:this={passwordInput}
            bind:value={password}
            autofocus
            aria-describedby={error ? "unlock-error" : undefined}
            aria-invalid={error ? "true" : undefined}
            disabled={busy}
          />
          {#if session.state === "locked" && session.profile}
            <p class="hint">Profile: <span class="mono">{session.profile}</span></p>
          {/if}
        </div>

        {#if error}
          <div class="error" id="unlock-error" role="alert">{error}</div>
        {/if}

        <button
          class="btn btn-primary"
          type="submit"
          disabled={busy || password.length === 0}
          style="width:100%"
        >
          {busy ? "Unlocking…" : "Unlock"}
        </button>
      </form>
      <p class="hint" style="margin-top:1rem">
        The Secret Key is read on this device. Lost password + Secret Key = no
        recovery (by design).
      </p>
    {/if}
  </div>
</div>
