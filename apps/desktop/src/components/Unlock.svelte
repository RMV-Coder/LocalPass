<!--
  SPDX-License-Identifier: MPL-2.0
  This file is part of the LocalPass desktop GUI. See ../../LICENSE.

  The unlock screen. Handles the locked, no-daemon, wrong-profile, and error
  states. The password is kept in a component-local variable, sent to the
  backend's `unlock` command, and cleared immediately after (never a store).
  Windows Hello unlock (when set up) never brings the password into the
  webview: the backend unseals and unlocks itself.

  The lock moment (DESIGN.md "Motion"): a successful unlock turns the keyhole a
  quarter, then hands over to the vault. After a lock the screen mounts with
  the keyhole turned (`startTurned`) and turns it back.
-->
<script lang="ts">
  import { unlock as unlockApi, helloStatus, helloUnlock } from "../lib/api";
  import type { HelloStatusView, SessionState } from "../lib/types";
  import Mark from "./Mark.svelte";
  import Icon from "./Icon.svelte";

  interface Props {
    session: SessionState;
    onUnlocked: (s: SessionState) => void;
    onRefresh: () => void;
    /** Mount with the keyhole turned (we just locked) and turn it back. */
    startTurned?: boolean;
  }
  let { session, onUnlocked, onRefresh, startTurned = false }: Props = $props();

  let password = $state("");
  let show = $state(false);
  let capsLock = $state(false);
  let error = $state("");
  let busy = $state(false);
  let passwordInput: HTMLInputElement | undefined = $state();
  // svelte-ignore state_referenced_locally
  let turned = $state(startTurned);
  let hello = $state<HelloStatusView | null>(null);

  const reduced = () => globalThis.matchMedia?.("(prefers-reduced-motion: reduce)").matches;
  const pause = (ms: number) => new Promise((r) => setTimeout(r, reduced() ? 0 : ms));

  // Returning from a lock: let the turned keyhole paint, then turn it back.
  $effect(() => {
    if (!turned) return;
    const raf = requestAnimationFrame(() => requestAnimationFrame(() => (turned = false)));
    return () => cancelAnimationFrame(raf);
  });

  $effect(() => {
    if (session.state !== "locked") return;
    helloStatus()
      .then((h) => (hello = h))
      .catch(() => (hello = null));
  });

  /** Play the turn, then hand the unlocked session to the app. */
  async function finish(next: SessionState) {
    turned = true;
    await pause(560);
    onUnlocked(next);
  }

  function explain(next: SessionState): string {
    if (next.state === "error") return next.message;
    if (next.state === "no_daemon") return "The LocalPass service isn't running. Reconnect to start it.";
    // Locked/other: the daemon is up but the session isn't, almost always a
    // wrong password (the backend auto-starts the service before unlock).
    return "Incorrect master password or Secret Key.";
  }

  async function submit(e: Event) {
    e.preventDefault();
    if (busy || password.length === 0) return;
    busy = true;
    error = "";
    try {
      const next = await unlockApi(password);
      // Clear the password from JS the instant the call returns, win or lose.
      password = "";
      show = false;
      if (next.state === "unlocked") {
        await finish(next);
        return;
      }
      error = explain(next);
    } catch (err) {
      // The backend rejects with a plain, secret-free string.
      password = "";
      error = typeof err === "string" ? err : "Could not reach the LocalPass service. Try reconnecting.";
    } finally {
      busy = false;
    }
    passwordInput?.focus();
  }

  async function withHello() {
    if (busy) return;
    busy = true;
    error = "";
    try {
      const next = await helloUnlock();
      if (next.state === "unlocked") {
        await finish(next);
        return;
      }
      error = explain(next);
    } catch (err) {
      const msg = typeof err === "string" ? err : "Windows Hello did not unlock LocalPass.";
      if (!/cancel/i.test(msg)) error = msg;
      // A stale enrolment (e.g. the master password changed) is removed by the
      // backend; re-read so the button disappears.
      helloStatus()
        .then((h) => (hello = h))
        .catch(() => {});
    } finally {
      busy = false;
    }
  }

  function onKey(e: KeyboardEvent) {
    capsLock = e.getModifierState?.("CapsLock") ?? false;
  }
</script>

<div class="center">
  <div class="unlock">
    <Mark size={72} {turned} />
    <h1 class="word">LocalPass</h1>

    {#if session.state === "no_daemon"}
      <p class="sub">The background service isn't running.</p>
      <p class="muted body">It normally starts on its own. To start it by hand:</p>
      <div class="code-block cmd"><code>localpass daemon start</code></div>
      <button class="btn btn-primary btn-block" onclick={onRefresh} disabled={busy}>Reconnect</button>
    {:else if session.state === "wrong_profile"}
      <p class="sub">Another profile is open</p>
      <p class="muted body">A LocalPass service is already running for a different profile:</p>
      <div class="code-block cmd"><code class="wrap-anywhere">{session.expected}</code></div>
      <p class="muted body">Stop that service, or open this app with that profile.</p>
      <button class="btn btn-block" onclick={onRefresh} disabled={busy}>Reconnect</button>
    {:else if session.state === "error"}
      <p class="sub">Something went wrong</p>
      <div class="error" role="alert">{session.message}</div>
      <button class="btn btn-block" onclick={onRefresh} disabled={busy}>Try again</button>
    {:else}
      <p class="sub" aria-live="polite">{turned && busy ? "Unlocked" : busy ? "Unlocking…" : "Locked"}</p>
      <form onsubmit={submit} novalidate>
        <label class="sr-only" for="master-password">Master password</label>
        <div class="input-affix">
          <!-- svelte-ignore a11y_autofocus -->
          <input
            id="master-password"
            class="pw"
            type={show ? "text" : "password"}
            autocomplete="current-password"
            spellcheck="false"
            placeholder="Master password"
            bind:this={passwordInput}
            bind:value={password}
            onkeydown={onKey}
            onkeyup={onKey}
            autofocus
            aria-describedby={error ? "unlock-error" : capsLock ? "caps-note" : undefined}
            aria-invalid={error ? "true" : undefined}
            disabled={busy}
          />
          <button
            type="button"
            class="icon-btn"
            aria-label={show ? "Hide password" : "Show password"}
            aria-pressed={show}
            onclick={() => (show = !show)}
            disabled={busy}
          >
            <Icon name={show ? "eye-off" : "eye"} size={18} />
          </button>
        </div>
        {#if capsLock && !error}
          <p class="hint caps" id="caps-note"><Icon name="alert" size={13} /> Caps Lock is on</p>
        {/if}
        {#if error}
          <div class="error" id="unlock-error" role="alert">{error}</div>
        {/if}
        <button class="btn btn-primary btn-block" type="submit" disabled={busy || password.length === 0}>
          Unlock
        </button>
      </form>

      {#if hello?.enrolled}
        <div class="or" aria-hidden="true">or</div>
        <button class="btn btn-block" onclick={withHello} disabled={busy}>
          <Icon name="fingerprint" size={18} />
          Unlock with Windows Hello
        </button>
      {/if}
    {/if}
  </div>
</div>

<style>
  .unlock {
    width: min(340px, 100%);
    display: grid;
    justify-items: center;
    text-align: center;
  }
  .word {
    font-size: 22px;
    margin-top: 16px;
  }
  .sub {
    color: var(--text-muted);
    font-size: 13px;
    margin: 3px 0 22px;
  }
  .body {
    font-size: 13px;
    margin-bottom: 10px;
  }
  form {
    width: 100%;
    display: grid;
    gap: 10px;
  }
  .pw {
    height: 40px;
    font-size: 15px;
  }
  .pw[type="password"] {
    font-family: var(--mono);
    letter-spacing: 0.1em;
  }
  .pw::placeholder {
    font-family: var(--font);
    letter-spacing: 0;
  }
  .caps {
    display: flex;
    align-items: center;
    gap: 5px;
    margin: -4px 0 0;
    color: var(--warning);
    justify-self: start;
  }
  .error {
    text-align: left;
    margin: 0;
    width: 100%;
  }
  .cmd {
    width: 100%;
    margin-bottom: 14px;
    text-align: left;
  }
  .or {
    display: flex;
    align-items: center;
    gap: 10px;
    width: 100%;
    margin: 14px 0;
    color: var(--text-faint);
    font-size: 12px;
  }
  .or::before,
  .or::after {
    content: "";
    flex: 1;
    height: 1px;
    background: var(--border);
  }
</style>
