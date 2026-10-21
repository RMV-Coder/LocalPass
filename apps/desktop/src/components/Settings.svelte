<!--
  SPDX-License-Identifier: MPL-2.0
  This file is part of the LocalPass desktop GUI. See ../../LICENSE.

  Settings: how this device unlocks (Windows Hello), appearance, updates
  (check, release notes, install + restart), and About (version, profile).

  SECRET BOUNDARY: turning Windows Hello on asks for the master password once.
  It goes straight to the backend, which checks it with the service and seals
  it on this device under a Windows Hello key (TPM-backed). It is cleared from
  this component the moment the call returns and never comes back.

  NETWORK: the update check is the app's only outbound request. It runs when
  the user presses the button, or at start-up only if they opted in.
-->
<script lang="ts">
  import { appInfo, helloStatus, helloEnable, helloDisable, updateInstall } from "../lib/api";
  import type { AppInfoView, HelloStatusView } from "../lib/types";
  import {
    getThemePref,
    setThemePref,
    getAutoUpdateCheck,
    setAutoUpdateCheck,
    savePendingNotes,
    type ThemePref,
  } from "../lib/prefs";
  import { updates, checkForUpdates } from "../lib/updates";
  import { formatAgo } from "../lib/format";
  import { copyToClipboard } from "../lib/clipboard";
  import { toast } from "../lib/toast";
  import Icon from "./Icon.svelte";
  import Mark from "./Mark.svelte";
  import ReleaseNotes from "./ReleaseNotes.svelte";

  interface Props {
    onOpenHelp?: () => void;
  }
  let { onOpenHelp }: Props = $props();

  let info = $state<AppInfoView | null>(null);
  let hello = $state<HelloStatusView | null>(null);
  let theme = $state<ThemePref>(getThemePref());
  let autoCheck = $state(getAutoUpdateCheck());

  $effect(() => {
    appInfo()
      .then((i) => (info = i))
      .catch(() => (info = null));
    refreshHello();
  });

  function refreshHello() {
    helloStatus()
      .then((h) => (hello = h))
      .catch(() => (hello = null));
  }

  function pickTheme(t: ThemePref) {
    theme = t;
    setThemePref(t);
  }

  // --- Windows Hello ---
  let enrolling = $state(false); // the password prompt is open
  let helloPassword = $state("");
  let helloBusy = $state(false);
  let helloError = $state("");

  async function toggleHello(on: boolean) {
    helloError = "";
    if (on) {
      enrolling = true;
      return;
    }
    helloBusy = true;
    try {
      await helloDisable();
      toast("Windows Hello unlock is off", "ok");
    } catch (err) {
      helloError = typeof err === "string" ? err : "Could not turn Windows Hello off.";
    } finally {
      helloBusy = false;
      refreshHello();
    }
  }

  async function confirmEnroll(e: Event) {
    e.preventDefault();
    if (helloBusy || !helloPassword) return;
    helloBusy = true;
    helloError = "";
    try {
      await helloEnable(helloPassword);
      helloPassword = "";
      enrolling = false;
      toast("Windows Hello can now unlock LocalPass", "ok");
    } catch (err) {
      helloPassword = "";
      const msg = typeof err === "string" ? err : "Could not turn Windows Hello on.";
      if (!/cancel/i.test(msg)) helloError = msg;
    } finally {
      helloBusy = false;
      refreshHello();
    }
  }

  function cancelEnroll() {
    helloPassword = "";
    enrolling = false;
    helloError = "";
  }

  // --- Updates ---
  let installing = $state(false);
  let confirmInstall = $state(false);
  let installError = $state("");

  function setAuto(on: boolean) {
    autoCheck = on;
    setAutoUpdateCheck(on);
  }

  async function install() {
    const u = $updates.available;
    if (!u || installing) return;
    installing = true;
    installError = "";
    // Keep the notes so the first launch of the new version can show them.
    savePendingNotes(u.version, u.notes);
    try {
      await updateInstall();
    } catch (err) {
      installError = typeof err === "string" ? err : "The update could not be installed.";
      installing = false;
      confirmInstall = false;
    }
  }

  async function copyProfile() {
    if (!info) return;
    const ok = await copyToClipboard(info.profile);
    toast(ok ? "Path copied" : "Copy failed", ok ? "ok" : "error");
  }

  const desktop = $derived(!info || ["windows", "macos", "linux"].includes(info.platform));
</script>

<div class="page settings">
  <div class="page-head"><h2>Settings</h2></div>

  <!-- ===================== Unlock ===================== -->
  {#if info?.platform === "windows"}
    <section class="section first">
      <h3>Unlock</h3>
      <div class="set-row">
        <div>
          <div class="t"><Icon name="fingerprint" size={15} /> Windows Hello</div>
          <div class="d">
            {#if hello?.supported === false}
              Set up a PIN, fingerprint or face in Windows Settings › Accounts › Sign-in options first.
            {:else}
              Unlock with your PIN, fingerprint or face instead of typing the master password.
            {/if}
          </div>
        </div>
        <label class="switch">
          <input
            type="checkbox"
            checked={hello?.enrolled ?? false}
            disabled={!hello?.supported || helloBusy || enrolling}
            onchange={(e) => toggleHello(e.currentTarget.checked)}
            aria-label="Unlock with Windows Hello"
          />
          <span></span>
        </label>
      </div>
      {#if enrolling}
        <form class="enroll" onsubmit={confirmEnroll}>
          <label for="hello-pw" class="label">Confirm your master password to turn it on</label>
          <div class="enroll-row">
            <!-- svelte-ignore a11y_autofocus -->
            <input
              id="hello-pw"
              type="password"
              class="mono"
              autocomplete="current-password"
              bind:value={helloPassword}
              autofocus
              disabled={helloBusy}
            />
            <button class="btn btn-primary" type="submit" disabled={helloBusy || !helloPassword}>
              {helloBusy ? "Waiting for Windows Hello…" : "Turn on"}
            </button>
            <button class="btn btn-quiet" type="button" onclick={cancelEnroll} disabled={helloBusy}>Cancel</button>
          </div>
          <p class="hint">
            The password is sealed on this device under a key only Windows Hello can use. It is never
            synced, and turning this off deletes it.
          </p>
        </form>
      {/if}
      {#if helloError}<div class="error" role="alert">{helloError}</div>{/if}
    </section>
  {/if}

  <!-- ===================== Appearance ===================== -->
  <section class="section" class:first={info?.platform !== "windows"}>
    <h3>Appearance</h3>
    <div class="set-row">
      <div>
        <div class="t">Theme</div>
        <div class="d">System follows your device's light or dark setting.</div>
      </div>
      <div class="seg" role="group" aria-label="Theme">
        <button aria-pressed={theme === "system"} onclick={() => pickTheme("system")}>System</button>
        <button aria-pressed={theme === "light"} onclick={() => pickTheme("light")}>Light</button>
        <button aria-pressed={theme === "dark"} onclick={() => pickTheme("dark")}>Dark</button>
      </div>
    </div>
  </section>

  <!-- ===================== Updates ===================== -->
  <section class="section">
    <h3>Updates</h3>
    {#if !desktop}
      <p class="body muted">Install new versions from the releases page or your app store.</p>
    {:else}
      <div class="set-row">
        <div>
          <div class="t">LocalPass {info?.version ?? ""}</div>
          <div class="d" aria-live="polite">
            {#if $updates.checking}
              Checking GitHub for a newer release…
            {:else if $updates.error}
              <span class="bad">{$updates.error}</span>
            {:else if $updates.available}
              Version {$updates.available.version} is available.
            {:else if $updates.checkedAt}
              Up to date · checked {formatAgo($updates.checkedAt)}
            {:else}
              Not checked yet.
            {/if}
          </div>
        </div>
        {#if $updates.available}
          <button class="btn btn-primary" onclick={() => (confirmInstall = true)} disabled={installing}>
            <Icon name="download" size={15} /> Install {$updates.available.version}
          </button>
        {:else}
          <button class="btn" onclick={() => checkForUpdates()} disabled={$updates.checking}>
            <Icon name="refresh" size={15} /> Check for updates
          </button>
        {/if}
      </div>

      {#if $updates.available}
        <div class="notes-box">
          <div class="notes-head">
            <span class="strong">What's new in {$updates.available.version}</span>
            {#if $updates.available.date_ms}<span class="faint">{new Date($updates.available.date_ms).toLocaleDateString()}</span>{/if}
          </div>
          <div class="notes"><ReleaseNotes notes={$updates.available.notes} /></div>
        </div>
      {/if}
      {#if installError}<div class="error" role="alert">{installError}</div>{/if}

      <div class="set-row">
        <div>
          <div class="t">Check when LocalPass unlocks</div>
          <div class="d">Sends one request to GitHub. Nothing about you or your vault is included.</div>
        </div>
        <label class="switch">
          <input type="checkbox" checked={autoCheck} onchange={(e) => setAuto(e.currentTarget.checked)} aria-label="Check for updates automatically" />
          <span></span>
        </label>
      </div>
    {/if}
  </section>

  <!-- ===================== Help + About ===================== -->
  <section class="section">
    <h3>Help and about</h3>
    <button class="set-row link-row" onclick={() => onOpenHelp?.()}>
      <span>
        <span class="t">Help and keyboard shortcuts</span>
      </span>
      <Icon name="chevron" size={16} />
    </button>
    <div class="set-row about">
      <Mark size={36} />
      <div class="about-text">
        <div class="t">LocalPass {info?.version ?? ""}</div>
        <div class="d">Open source. The app is MPL-2.0, the core is AGPL-3.0. github.com/RMV-Coder/LocalPass</div>
      </div>
    </div>
    {#if info}
      <div class="set-row">
        <div class="profile">
          <div class="t">Profile folder</div>
          <code class="d wrap-anywhere">{info.profile}</code>
        </div>
        <button class="icon-btn" onclick={copyProfile} aria-label="Copy profile folder path" title="Copy path">
          <Icon name="copy" size={16} />
        </button>
      </div>
    {/if}
  </section>
</div>

{#if confirmInstall && $updates.available}
  <div
    class="modal-overlay"
    role="button"
    tabindex="-1"
    aria-label="Cancel"
    onclick={() => { if (!installing) confirmInstall = false; }}
    onkeydown={(e) => { if (e.key === "Escape" && !installing) confirmInstall = false; }}
  >
    <div
      class="modal-card"
      role="dialog"
      tabindex="-1"
      aria-modal="true"
      aria-labelledby="up-title"
      onclick={(e) => e.stopPropagation()}
      onkeydown={(e) => { if (e.key === "Escape" && !installing) confirmInstall = false; }}
    >
      <h2 id="up-title" class="modal-title">Install LocalPass {$updates.available.version}?</h2>
      <p class="muted">
        LocalPass checks the download's signature, locks your vault, stops its background
        service, installs, and opens again. Windows may ask for permission to install.
      </p>
      <div class="modal-actions">
        <button class="btn" onclick={() => (confirmInstall = false)} disabled={installing}>Not now</button>
        <!-- svelte-ignore a11y_autofocus -->
        <button class="btn btn-primary" onclick={install} disabled={installing} autofocus>
          {installing ? "Downloading…" : "Install and restart"}
        </button>
      </div>
    </div>
  </div>
{/if}

<style>
  .settings {
    max-width: 680px;
  }
  .section.first {
    margin-top: 0;
  }
  .section > h3 {
    font-size: 12px;
    font-weight: 500;
    color: var(--text-muted);
    font-family: var(--font);
    margin-bottom: 2px;
  }
  .t {
    display: flex;
    align-items: center;
    gap: 7px;
  }
  .t :global(.icon) {
    color: var(--text-muted);
  }
  .bad {
    color: var(--danger);
  }
  .enroll {
    padding: 4px 0 12px;
  }
  .enroll-row {
    display: flex;
    gap: 6px;
    flex-wrap: wrap;
  }
  .enroll-row input {
    flex: 1 1 200px;
  }
  .notes-box {
    margin: 2px 0 10px;
    padding: 12px 14px;
    border-radius: var(--radius);
    background: var(--bg-hover);
  }
  .notes-head {
    display: flex;
    justify-content: space-between;
    gap: 10px;
    margin-bottom: 6px;
    font-size: 13px;
  }
  .notes {
    max-height: 240px;
    overflow: auto;
  }
  .body {
    font-size: 13px;
    padding: 6px 0;
  }
  .link-row {
    width: 100%;
    border: 0;
    background: none;
    color: inherit;
    text-align: left;
    cursor: pointer;
    border-radius: var(--radius);
  }
  .link-row:hover {
    color: var(--accent);
  }
  .about {
    justify-content: flex-start;
  }
  .about-text,
  .profile {
    min-width: 0;
  }
  .profile code {
    display: block;
    font-size: 12px;
  }
</style>
