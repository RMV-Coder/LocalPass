<!--
  SPDX-License-Identifier: MPL-2.0
  This file is part of the LocalPass desktop GUI. See ../LICENSE.

  App root. Fetches the session state and routes: unlocked -> Vault, everything
  else -> Unlock (which itself renders the locked / no-daemon / wrong-profile
  guidance). Hosts the top bar (with a Lock button) and the aria-live toast
  region. No secret state lives here.
-->
<script lang="ts">
  import { ensureService, status as statusApi, lock as lockApi } from "./lib/api";
  import type { SessionState } from "./lib/types";
  import Unlock from "./components/Unlock.svelte";
  import Vault from "./components/Vault.svelte";
  import Onboarding from "./components/Onboarding.svelte";
  import { toasts } from "./lib/toast";

  let session = $state<SessionState | null>(null);
  let loading = $state(true);
  // True only for the very first load, while the background service starts.
  let starting = $state(true);

  // On launch, start the background service if needed (the GUI is a client and
  // cannot hold keys itself). After that, plain status refreshes are enough.
  async function boot() {
    loading = true;
    try {
      session = await ensureService();
    } catch (err) {
      session = { state: "error", message: typeof err === "string" ? err : "Backend error." };
    } finally {
      starting = false;
      loading = false;
    }
  }

  async function refresh() {
    loading = true;
    try {
      session = await statusApi();
    } catch (err) {
      session = { state: "error", message: typeof err === "string" ? err : "Backend error." };
    } finally {
      loading = false;
    }
  }

  function onUnlocked(s: SessionState) {
    session = s;
  }

  // After onboarding the daemon already holds the unlocked session; refresh
  // status to route into the Vault.
  async function onOnboarded() {
    await refresh();
  }

  async function doLock() {
    try {
      session = await lockApi();
    } catch {
      await refresh();
    }
  }

  $effect(() => {
    boot();
  });
</script>

<svelte:head>
  <title>LocalPass</title>
</svelte:head>

{#if loading && !session}
  <div class="center">
    <p class="muted">{starting ? "Starting the LocalPass service…" : "Connecting…"}</p>
  </div>
{:else if session && session.state === "unlocked"}
  <header class="topbar">
    <div class="left">
      <span class="logo" aria-hidden="true"
        style="width:24px;height:24px;border-radius:6px;background:var(--accent);color:var(--accent-text);display:grid;place-items:center;font-weight:800;font-size:0.8rem"
      >L</span>
      LocalPass
      <span class="muted" style="font-weight:400">
        · {session.vault_count} vault{session.vault_count === 1 ? "" : "s"}
      </span>
    </div>
    <div class="right">
      {#if session.idle_remaining_secs !== null}
        <span class="muted sr-only" aria-live="off">
          Auto-locks in {session.idle_remaining_secs}s
        </span>
      {/if}
      <button class="btn btn-small" onclick={doLock}>Lock</button>
    </div>
  </header>
  <Vault />
{:else if session && session.state === "no_account"}
  <Onboarding onDone={onOnboarded} />
{:else if session}
  <Unlock {session} {onUnlocked} onRefresh={refresh} />
{/if}

<!-- aria-live region: copy/reveal feedback announced to screen readers. -->
<div aria-live="polite" aria-atomic="true">
  {#each $toasts as t (t.id)}
    <div class="toast" role="status">{t.message}</div>
  {/each}
</div>
