<!--
  SPDX-License-Identifier: MPL-2.0
  This file is part of the LocalPass desktop GUI. See ../LICENSE.

  App root. Fetches the session state and routes: unlocked -> Vault, no
  account -> Onboarding, everything else -> Unlock (which also renders the
  no-daemon / wrong-profile guidance). Owns the lock moment (DESIGN.md
  "Motion"): Unlock turns the keyhole before handing over; on lock the vault
  drops away and the unlock screen returns with the keyhole turned, then turns
  it back. The vault is locked FIRST and animated after, so security never
  waits on motion. No secret state lives here.
-->
<script lang="ts">
  import { ensureService, status as statusApi, lock as lockApi } from "./lib/api";
  import type { SessionState } from "./lib/types";
  import { onActivity } from "./lib/activity";
  import { getAutoUpdateCheck, takePendingNotes } from "./lib/prefs";
  import { checkForUpdates } from "./lib/updates";
  import Unlock from "./components/Unlock.svelte";
  import Vault from "./components/Vault.svelte";
  import Onboarding from "./components/Onboarding.svelte";
  import PresenceDialog from "./components/PresenceDialog.svelte";
  import Mark from "./components/Mark.svelte";
  import Icon from "./components/Icon.svelte";
  import ReleaseNotes from "./components/ReleaseNotes.svelte";
  import { toasts } from "./lib/toast";

  let session = $state<SessionState | null>(null);
  let loading = $state(true);
  // True only for the very first load, while the background service starts.
  let starting = $state(true);

  // Lock-moment state. `leaving` fades the vault out; `returnTurned` makes the
  // next unlock screen mount with its keyhole turned so it can turn back.
  let leaving = $state(false);
  let returnTurned = $state(false);

  // When the vault will auto-lock (ms since epoch), from the passive status.
  let lockDeadline = $state<number | null>(null);

  // Notes saved before an update was installed, shown once after unlock.
  let whatsNew = $state<{ version: string; notes: string } | null>(null);

  const reduced = () => globalThis.matchMedia?.("(prefers-reduced-motion: reduce)").matches;
  const pause = (ms: number) => new Promise((r) => setTimeout(r, reduced() ? 0 : ms));

  /** Take a new session state. Leaving the unlocked state plays the exit. */
  async function apply(next: SessionState) {
    const wasUnlocked = session?.state === "unlocked";
    if (next.state === "unlocked") {
      lockDeadline =
        next.idle_remaining_secs === null ? null : Date.now() + next.idle_remaining_secs * 1000;
      session = next;
      return;
    }
    lockDeadline = null;
    if (wasUnlocked) {
      leaving = true;
      await pause(170);
      returnTurned = true;
      leaving = false;
    }
    session = next;
  }

  // On launch, start the background service if needed (the GUI is a client and
  // cannot hold keys itself). After that, plain status refreshes are enough.
  async function boot() {
    loading = true;
    try {
      await apply(await ensureService());
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
      await apply(await statusApi());
    } catch (err) {
      session = { state: "error", message: typeof err === "string" ? err : "Backend error." };
    } finally {
      loading = false;
    }
  }

  function onUnlocked(s: SessionState) {
    returnTurned = false;
    void apply(s);
    const notes = takePendingNotes();
    if (notes) whatsNew = notes;
    if (getAutoUpdateCheck()) void checkForUpdates();
  }

  async function onOnboarded() {
    await refresh();
  }

  async function doLock() {
    // Lock first; the motion is decoration on an already-locked vault.
    let next: SessionState;
    try {
      next = await lockApi();
    } catch {
      next = await statusApi().catch(() => ({ state: "no_daemon" }) as SessionState);
    }
    await apply(next);
  }

  $effect(() => {
    boot();
  });

  // Fall back to the unlock screen when the daemon's idle auto-lock fires:
  // schedule a status refresh for the moment the current idle window expires.
  // `Status` is PASSIVE server-side (it does not reset the idle timer), so this
  // observation cannot postpone the auto-lock it is watching for.
  $effect(() => {
    if (lockDeadline === null) return;
    const t = setTimeout(refresh, Math.max(0, lockDeadline - Date.now()) + 2000);
    return () => clearTimeout(t);
  });

  // Every active request resets the idle timer in the daemon. Re-read the
  // passive status shortly after a burst of them so the countdown restarts.
  $effect(() => {
    let t: ReturnType<typeof setTimeout> | undefined;
    const off = onActivity(() => {
      if (session?.state !== "unlocked") return;
      clearTimeout(t);
      t = setTimeout(() => {
        if (session?.state === "unlocked") refresh();
      }, 700);
    });
    return () => {
      off();
      clearTimeout(t);
    };
  });

  // Re-check on window focus/visibility: a laptop that slept past the timeout
  // should show the unlock screen the moment the user comes back.
  $effect(() => {
    const onWake = () => {
      if (session?.state === "unlocked" && document.visibilityState === "visible") {
        refresh();
      }
    };
    window.addEventListener("focus", onWake);
    document.addEventListener("visibilitychange", onWake);
    return () => {
      window.removeEventListener("focus", onWake);
      document.removeEventListener("visibilitychange", onWake);
    };
  });
</script>

<svelte:head>
  <title>LocalPass</title>
</svelte:head>

{#if loading && !session}
  <div class="center" aria-busy="true">
    <div class="boot">
      <Mark size={56} />
      <p class="muted">{starting ? "Starting LocalPass…" : "Connecting…"}</p>
    </div>
  </div>
{:else if session && session.state === "unlocked"}
  <div class="vault-stage" class:leaving>
    <Vault {session} {lockDeadline} onLock={doLock} onVaultsChanged={refresh} />
  </div>
{:else if session && session.state === "no_account"}
  <Onboarding onDone={onOnboarded} />
{:else if session}
  <Unlock {session} {onUnlocked} onRefresh={refresh} startTurned={returnTurned} />
{/if}

<PresenceDialog />

{#if whatsNew}
  <div
    class="modal-overlay"
    role="button"
    tabindex="-1"
    aria-label="Close"
    onclick={() => (whatsNew = null)}
    onkeydown={(e) => {
      if (e.key === "Escape") whatsNew = null;
    }}
  >
    <div
      class="modal-card whats-new"
      role="dialog"
      tabindex="-1"
      aria-modal="true"
      aria-labelledby="wn-title"
      onclick={(e) => e.stopPropagation()}
      onkeydown={(e) => {
        if (e.key === "Escape") whatsNew = null;
      }}
    >
      <h2 id="wn-title" class="modal-title">Updated to {whatsNew.version}</h2>
      <div class="notes"><ReleaseNotes notes={whatsNew.notes} /></div>
      <div class="modal-actions">
        <!-- svelte-ignore a11y_autofocus -->
        <button class="btn btn-primary" autofocus onclick={() => (whatsNew = null)}>Done</button>
      </div>
    </div>
  </div>
{/if}

<!-- aria-live region: copy/reveal feedback announced to screen readers. -->
<div class="toast-region" aria-live="polite" aria-atomic="true">
  {#each $toasts as t (t.id)}
    <div class="toast" class:error={t.kind === "error"} role="status">
      <Icon name={t.kind === "error" ? "alert" : "check"} size={15} />
      <span>{t.message}</span>
    </div>
  {/each}
</div>

<style>
  .boot {
    display: grid;
    justify-items: center;
    gap: 14px;
  }
  .vault-stage {
    flex: 1 1 auto;
    min-height: 0;
    display: flex;
    flex-direction: column;
    animation: vault-in 280ms var(--ease-out);
    transition:
      opacity 160ms ease-in,
      transform 160ms ease-in;
  }
  .vault-stage.leaving {
    opacity: 0;
    transform: translateY(8px);
  }
  @keyframes vault-in {
    from {
      opacity: 0;
      transform: translateY(10px);
    }
  }
  .whats-new {
    max-width: 520px;
  }
  .notes {
    max-height: 50vh;
    overflow: auto;
  }
</style>
