<!--
  SPDX-License-Identifier: MPL-2.0
  This file is part of the LocalPass desktop GUI. See ../../LICENSE.

  Devices & Sync. Link a second machine (or a friend) and sync a vault entirely
  from the GUI — the sync engine (lp-sync) runs in the daemon; this screen is a
  thin client over it.

  SECURITY BOUNDARY: nothing here is a secret. A device's identity string and
  fingerprint are PUBLIC (public keys + a hash). Trusting a device is the
  security-critical step: the user MUST compare the pasted device's fingerprint
  against what the other device shows, and confirm it (the "fingerprints match"
  checkbox gates the Trust button). The confirmed fingerprint is passed to the
  backend, which re-checks it against the identity string and refuses on a
  mismatch — the checkbox is a usability aid, not the security control. The
  vault-key share is sealed inside the daemon/engine; this screen only ever names
  a device id. Sync alarms (quarantine/tamper) are surfaced prominently below the
  Pull button, never swallowed.
-->
<script lang="ts">
  import {
    exportIdentity,
    listPeers,
    trustDevice,
    syncSetup,
    syncPush,
    syncPull,
    syncStatus,
    shareVaultToDevice,
    syncAdopt,
  } from "../lib/api";
  import type {
    DeviceIdentityView,
    PeerView,
    SyncStatusView,
    VaultView,
  } from "../lib/types";
  import { previewFingerprint } from "../lib/api";
  import { copyToClipboard } from "../lib/clipboard";
  import { formatTimestamp } from "../lib/format";
  import { toast } from "../lib/toast";

  interface Props {
    /** The vaults from the parent, so the user can pick which vault to sync. */
    vaults: VaultView[];
    /** The currently-selected vault id (defaults the sync/share pickers). */
    selectedVault: string;
  }
  let { vaults, selectedVault }: Props = $props();

  // This device's identity (public).
  let identity = $state<DeviceIdentityView | null>(null);
  let identityError = $state("");

  // Trusted peers.
  let peers = $state<PeerView[]>([]);
  let peersError = $state("");

  // Trust-a-device form.
  let pasted = $state("");
  let trustLabel = $state("");
  let confirmed = $state(false); // "fingerprints match" checkbox
  let trustBusy = $state(false);
  let trustError = $state("");

  // The fingerprint parsed from the pasted string, shown so the user knows what
  // to compare. The backend derives it (the fingerprint algorithm lives in one
  // place — lp-sync — and is never reimplemented in JS); it is a PUBLIC value.
  // Crucially, this is only for display: `trust_device` independently re-derives
  // and re-checks the fingerprint against the identity string server-side, so a
  // wrong or stale preview can never widen trust.
  let parsedFingerprint = $state<string | null>(null);
  let parsedInvalid = $state(false);
  const canTrust = $derived(parsedFingerprint !== null && confirmed && !trustBusy);

  // Whenever the pasted string changes, re-derive its fingerprint (and force the
  // "matches" checkbox back off, so the confirmation is re-affirmed per string).
  let previewSeq = 0;
  $effect(() => {
    const s = pasted.trim();
    confirmed = false;
    parsedFingerprint = null;
    parsedInvalid = false;
    if (!s) return;
    const seq = ++previewSeq;
    previewFingerprint(s)
      .then((fp) => {
        if (seq !== previewSeq) return; // a newer input superseded this one
        parsedFingerprint = fp;
      })
      .catch(() => {
        if (seq !== previewSeq) return;
        parsedInvalid = true;
      });
  });

  // Sync-a-vault panel. The vault pickers default to the parent's selection
  // (set once on mount; the user can then change them independently).
  let syncVault = $state("");
  let syncDir = $state("");
  let syncBusy = $state(false);
  let syncError = $state("");
  let syncResult = $state(""); // human summary of the last push/pull
  let alarms = $state<string[]>([]); // surfaced prominently
  let status = $state<SyncStatusView | null>(null);

  // Share-a-vault panel.
  let shareVault = $state("");
  let sharePeer = $state("");
  let shareBusy = $state(false);
  let shareError = $state("");

  // Adopt panel.
  let adoptDir = $state("");
  let adoptBusy = $state(false);
  let adoptError = $state("");
  let adoptResult = $state("");

  async function loadIdentity() {
    identityError = "";
    try {
      identity = await exportIdentity();
    } catch (err) {
      identityError = typeof err === "string" ? err : "Could not read this device's identity.";
    }
  }

  async function loadPeers() {
    peersError = "";
    try {
      peers = await listPeers();
    } catch (err) {
      peersError = typeof err === "string" ? err : "Could not list trusted devices.";
    }
  }

  async function copyIdentity() {
    if (!identity) return;
    const ok = await copyToClipboard(identity.identity_string);
    toast(ok ? "Identity copied" : "Copy failed", ok ? "ok" : "error");
  }

  async function submitTrust(e: Event) {
    e.preventDefault();
    if (!canTrust || parsedFingerprint === null) return;
    trustBusy = true;
    trustError = "";
    try {
      // Pass the confirmed fingerprint so the backend re-checks it server-side.
      await trustDevice(pasted.trim(), parsedFingerprint, trustLabel.trim() || null);
      toast("Device trusted", "ok");
      pasted = "";
      trustLabel = "";
      confirmed = false;
      await loadPeers();
    } catch (err) {
      trustError = typeof err === "string" ? err : "Could not trust the device.";
    } finally {
      trustBusy = false;
    }
  }

  async function doSetup() {
    if (!syncVault || !syncDir.trim() || syncBusy) return;
    syncBusy = true;
    syncError = "";
    syncResult = "";
    try {
      await syncSetup(syncVault, syncDir.trim());
      syncResult = "Enrolled for sync.";
      await refreshStatus();
    } catch (err) {
      syncError = typeof err === "string" ? err : "Setup failed.";
    } finally {
      syncBusy = false;
    }
  }

  async function doPush() {
    if (!syncVault || syncBusy) return;
    syncBusy = true;
    syncError = "";
    syncResult = "";
    try {
      const r = await syncPush(syncVault);
      syncResult = `Pushed ${r.segments_written} segment(s); ${r.published} device chain(s).`;
      await refreshStatus();
    } catch (err) {
      syncError = typeof err === "string" ? err : "Push failed.";
    } finally {
      syncBusy = false;
    }
  }

  async function doPull() {
    if (!syncVault || syncBusy) return;
    syncBusy = true;
    syncError = "";
    syncResult = "";
    alarms = [];
    try {
      const r = await syncPull(syncVault);
      alarms = r.alarms;
      const bits = [`Applied ${r.applied}`, `${r.pending} pending`];
      if (r.key_imported) bits.push("imported a shared vault key");
      syncResult = bits.join(", ") + ".";
      await refreshStatus();
    } catch (err) {
      syncError = typeof err === "string" ? err : "Pull failed.";
    } finally {
      syncBusy = false;
    }
  }

  async function refreshStatus(vaultId: string = syncVault) {
    if (!vaultId) return;
    try {
      status = await syncStatus(vaultId);
      alarms = status.alarms.length ? status.alarms : alarms;
    } catch {
      status = null;
    }
  }

  async function doShare() {
    if (!shareVault || !sharePeer || shareBusy) return;
    shareBusy = true;
    shareError = "";
    try {
      await shareVaultToDevice(shareVault, sharePeer);
      toast("Vault shared to the device", "ok");
    } catch (err) {
      shareError = typeof err === "string" ? err : "Share failed.";
    } finally {
      shareBusy = false;
    }
  }

  async function doAdopt() {
    if (!adoptDir.trim() || adoptBusy) return;
    adoptBusy = true;
    adoptError = "";
    adoptResult = "";
    alarms = [];
    try {
      const r = await syncAdopt(adoptDir.trim());
      alarms = r.alarms;
      if (r.adopted.length === 0) {
        adoptResult = "No vaults were shared to this device in that folder.";
      } else {
        const names = r.adopted.map((a) => a.name || a.vault_id).join(", ");
        adoptResult = `Adopted ${r.adopted.length} vault(s) (${names}); applied ${r.applied_total} op(s).`;
      }
    } catch (err) {
      adoptError = typeof err === "string" ? err : "Adopt failed.";
    } finally {
      adoptBusy = false;
    }
  }

  // On mount: default the pickers to the parent's selected vault (or the first
  // vault), load this device's identity + the trusted peers, and read status.
  $effect(() => {
    const fallback = selectedVault || vaults[0]?.id || "";
    syncVault = fallback;
    shareVault = fallback;
    loadIdentity();
    loadPeers();
    refreshStatus(fallback);
  });
</script>

<div class="detail devices">
  <h2>Devices &amp; Sync</h2>
  <p class="muted" style="margin-top:-0.4rem">
    Link a second machine (or a friend) and sync a vault. Both machines watch the
    same shared folder; LocalPass encrypts everything, so the folder itself is
    untrusted.
  </p>

  <!-- This device -->
  <section class="panel" aria-labelledby="this-device-h">
    <h3 id="this-device-h">This device</h3>
    {#if identityError}
      <div class="error" role="alert">{identityError}</div>
    {:else if identity}
      <p class="muted">Share this identity with your other device, then trust it there.</p>
      <div class="field-group">
        <span class="label" id="id-str-label">Identity string</span>
        <div class="gen-output">
          <div class="val mono" aria-labelledby="id-str-label" style="user-select:all;word-break:break-all">
            {identity.identity_string}
          </div>
          <button class="btn" onclick={copyIdentity} aria-label="Copy identity string">Copy</button>
        </div>
      </div>
      <p class="hint">
        Fingerprint: <strong class="mono fp">{identity.fingerprint}</strong>
        <br />
        The other device must show this <em>exact</em> fingerprint before you trust each other.
      </p>
    {:else}
      <p class="muted">Loading…</p>
    {/if}
  </section>

  <!-- Trust a device (security-critical) -->
  <section class="panel" aria-labelledby="trust-h">
    <h3 id="trust-h">Trust a device</h3>
    <p class="muted">
      Paste the other device's identity string. Then compare the fingerprint
      below against what that device shows — they must match <strong>exactly</strong>.
      Confirm the match to enable Trust. Never trust a device whose fingerprint
      you have not compared out-of-band.
    </p>
    <form onsubmit={submitTrust}>
      <div class="field-group">
        <label for="paste-id">Other device's identity string</label>
        <textarea
          id="paste-id"
          rows="3"
          bind:value={pasted}
          placeholder="LPDEV1-…"
          autocomplete="off"
          spellcheck="false"
          class="mono"
          style="width:100%;resize:vertical"
          aria-describedby="paste-id-fp"
          aria-invalid={parsedInvalid ? "true" : undefined}
        ></textarea>
      </div>

      <div id="paste-id-fp" aria-live="polite">
        {#if parsedInvalid}
          <div class="error" role="alert">
            That is not a valid device identity string (check for a copy/paste error).
          </div>
        {:else if parsedFingerprint}
          <div class="fp-compare">
            <span class="label">Fingerprint to compare</span>
            <strong class="mono fp big">{parsedFingerprint}</strong>
          </div>
          <label class="confirm">
            <input type="checkbox" bind:checked={confirmed} />
            This fingerprint <strong>matches exactly</strong> what the other device shows.
          </label>
        {/if}
      </div>

      <div class="field-group">
        <label for="trust-label">Label (optional)</label>
        <input
          id="trust-label"
          type="text"
          bind:value={trustLabel}
          placeholder="e.g. laptop"
          autocomplete="off"
          style="max-width:280px"
        />
      </div>

      {#if trustError}
        <div class="error" role="alert">{trustError}</div>
      {/if}

      <button class="btn btn-primary" type="submit" disabled={!canTrust}>
        {trustBusy ? "Trusting…" : "Trust this device"}
      </button>
    </form>
  </section>

  <!-- Trusted devices -->
  <section class="panel" aria-labelledby="trusted-h">
    <h3 id="trusted-h">Trusted devices</h3>
    {#if peersError}
      <div class="error" role="alert">{peersError}</div>
    {:else if peers.length === 0}
      <p class="empty">No trusted devices yet.</p>
    {:else}
      <ul class="peer-list">
        {#each peers as p (p.device_id)}
          <li>
            <div class="peer-main">
              <span class="peer-label">{p.label || "(unlabeled)"}</span>
              <span class="mono fp">{p.fingerprint}</span>
            </div>
            <span class="muted peer-when">trusted {formatTimestamp(p.verified_at)}</span>
          </li>
        {/each}
      </ul>
    {/if}
  </section>

  <!-- Sync a vault -->
  <section class="panel" aria-labelledby="sync-h">
    <h3 id="sync-h">Sync a vault</h3>
    <p class="muted">
      Point this vault at a shared folder (e.g. a synced Dropbox/OneDrive folder,
      or a USB drive). Setup once, then Push to publish and Pull to receive.
    </p>
    <div class="field-group">
      <label for="sync-vault">Vault</label>
      <select id="sync-vault" bind:value={syncVault} onchange={() => refreshStatus()}>
        {#each vaults as v (v.id)}
          <option value={v.id}>{v.name}</option>
        {/each}
      </select>
    </div>
    <div class="field-group">
      <label for="sync-dir">Shared folder path</label>
      <input
        id="sync-dir"
        type="text"
        bind:value={syncDir}
        placeholder="C:\Users\you\Dropbox\localpass-sync"
        autocomplete="off"
        spellcheck="false"
        class="mono"
      />
    </div>
    <div class="btn-row">
      <button class="btn" onclick={doSetup} disabled={syncBusy || !syncVault || !syncDir.trim()}>
        Setup
      </button>
      <button class="btn btn-primary" onclick={doPush} disabled={syncBusy || !syncVault}>
        Push
      </button>
      <button class="btn btn-primary" onclick={doPull} disabled={syncBusy || !syncVault}>
        Pull
      </button>
    </div>

    {#if syncError}
      <div class="error" role="alert">{syncError}</div>
    {/if}
    {#if syncResult}
      <p class="hint" role="status" aria-live="polite">{syncResult}</p>
    {/if}

    {#if alarms.length}
      <div class="alarm" role="alert" aria-live="assertive">
        <strong>⚠ Sync alarms — do not ignore.</strong>
        A peer's history failed verification (possible tampering or rollback).
        The offending device's changes were quarantined, not applied.
        <ul>
          {#each alarms as a (a)}
            <li class="mono">{a}</li>
          {/each}
        </ul>
      </div>
    {/if}

    {#if status && status.enrolled}
      <div class="status-block">
        <p class="hint">
          Sync folder: <span class="mono">{status.root ?? "(none)"}</span> · Pending: {status.pending}
        </p>
        {#if status.devices.length}
          <table class="sync-table">
            <thead>
              <tr><th>Device</th><th>Local</th><th>Channel</th><th>Trust</th></tr>
            </thead>
            <tbody>
              {#each status.devices as d (d.device_id)}
                <tr>
                  <td class="mono">{d.device_id.slice(0, 8)}…</td>
                  <td>{d.local_seq}</td>
                  <td>{d.channel_seq}</td>
                  <td>
                    {#if d.is_self}this device{:else if d.trusted}trusted{:else}<span class="untrusted">UNTRUSTED</span>{/if}
                  </td>
                </tr>
              {/each}
            </tbody>
          </table>
        {/if}
      </div>
    {/if}
  </section>

  <!-- Share a vault to a device -->
  <section class="panel" aria-labelledby="share-h">
    <h3 id="share-h">Share a vault to a device</h3>
    <p class="muted">
      Send this vault's key to a trusted device via the shared folder (set the
      folder up in "Sync a vault" first). The key is sealed to the recipient — it
      never leaves LocalPass in the clear.
    </p>
    <div class="field-group">
      <label for="share-vault">Vault</label>
      <select id="share-vault" bind:value={shareVault}>
        {#each vaults as v (v.id)}
          <option value={v.id}>{v.name}</option>
        {/each}
      </select>
    </div>
    <div class="field-group">
      <label for="share-peer">Recipient device</label>
      <select id="share-peer" bind:value={sharePeer}>
        <option value="" disabled>Choose a trusted device…</option>
        {#each peers as p (p.device_id)}
          <option value={p.device_id}>{p.label || p.fingerprint}</option>
        {/each}
      </select>
    </div>
    {#if shareError}
      <div class="error" role="alert">{shareError}</div>
    {/if}
    <button class="btn btn-primary" onclick={doShare} disabled={shareBusy || !shareVault || !sharePeer}>
      {shareBusy ? "Sharing…" : "Share vault"}
    </button>
  </section>

  <!-- Adopt shared vaults -->
  <section class="panel" aria-labelledby="adopt-h">
    <h3 id="adopt-h">Adopt shared vaults from a folder</h3>
    <p class="muted">
      On the receiving device: scan a shared folder for vaults shared to you,
      import them, and pull their items.
    </p>
    <div class="field-group">
      <label for="adopt-dir">Shared folder path</label>
      <input
        id="adopt-dir"
        type="text"
        bind:value={adoptDir}
        placeholder="C:\Users\you\Dropbox\localpass-sync"
        autocomplete="off"
        spellcheck="false"
        class="mono"
      />
    </div>
    {#if adoptError}
      <div class="error" role="alert">{adoptError}</div>
    {/if}
    {#if adoptResult}
      <p class="hint" role="status" aria-live="polite">{adoptResult}</p>
    {/if}
    <button class="btn btn-primary" onclick={doAdopt} disabled={adoptBusy || !adoptDir.trim()}>
      {adoptBusy ? "Adopting…" : "Adopt shared vaults"}
    </button>
  </section>
</div>

<style>
  .panel {
    border: 1px solid var(--border);
    border-radius: 10px;
    padding: 1rem 1.1rem;
    margin: 1rem 0;
  }
  .panel h3 {
    margin: 0 0 0.5rem;
  }
  .label {
    display: block;
    font-size: 0.85rem;
    font-weight: 600;
    margin-bottom: 0.3rem;
  }
  .fp {
    letter-spacing: 0.04em;
  }
  .fp.big {
    font-size: 1.1rem;
  }
  .fp-compare {
    background: var(--bg-hover);
    border: 1px solid var(--border);
    border-radius: 8px;
    padding: 0.6rem 0.8rem;
    margin: 0.5rem 0;
  }
  .confirm {
    display: flex;
    align-items: flex-start;
    gap: 0.5em;
    font-weight: 400;
    margin: 0.5rem 0 0.8rem;
  }
  .peer-list {
    list-style: none;
    margin: 0;
    padding: 0;
  }
  .peer-list li {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 1rem;
    padding: 0.5rem 0;
    border-bottom: 1px solid var(--border);
  }
  .peer-list li:last-child {
    border-bottom: none;
  }
  .peer-main {
    display: flex;
    flex-direction: column;
    gap: 0.15rem;
  }
  .peer-label {
    font-weight: 600;
  }
  .peer-when {
    font-size: 0.8rem;
    white-space: nowrap;
  }
  .btn-row {
    display: flex;
    gap: 0.5rem;
    flex-wrap: wrap;
    margin-top: 0.3rem;
  }
  .alarm {
    border: 1px solid var(--danger);
    background: color-mix(in srgb, var(--danger) 10%, transparent);
    border-radius: 8px;
    padding: 0.7rem 0.9rem;
    margin: 0.8rem 0;
  }
  .alarm ul {
    margin: 0.4rem 0 0;
    padding-left: 1.2rem;
  }
  .status-block {
    margin-top: 0.8rem;
  }
  .sync-table {
    width: 100%;
    border-collapse: collapse;
    font-size: 0.85rem;
    margin-top: 0.4rem;
  }
  .sync-table th,
  .sync-table td {
    text-align: left;
    padding: 0.3rem 0.5rem;
    border-bottom: 1px solid var(--border);
  }
  .untrusted {
    color: var(--danger);
    font-weight: 700;
  }
  textarea.mono,
  input.mono,
  .val.mono {
    font-family: var(--mono, ui-monospace, monospace);
  }
</style>
