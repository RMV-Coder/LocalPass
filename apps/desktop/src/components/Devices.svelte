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
    identityQrSvg,
    isMobile,
    listPeers,
    trustDevice,
    setPairingMode,
    pairingModeSecs,
    syncSetup,
    syncPush,
    syncPull,
    syncStatus,
    shareVaultToDevice,
    syncAdopt,
    syncDirPickerAvailable,
    pickSyncDir,
    listPendingDevices,
  } from "../lib/api";
  import type {
    DeviceIdentityView,
    PeerView,
    PendingDeviceView,
    SyncStatusView,
    VaultView,
  } from "../lib/types";
  import { previewFingerprint } from "../lib/api";
  import CameraScan from "./CameraScan.svelte";
  import { copyToClipboard } from "../lib/clipboard";
  import { formatTimestamp } from "../lib/format";
  import { toast } from "../lib/toast";
  import { summarizeSync } from "../lib/syncsummary";
  import { adoptOutcome, folderUsedByAnotherDevice, type Outcome } from "../lib/vaultshare";
  import Icon from "./Icon.svelte";

  interface Props {
    /** The vaults from the parent, so the user can pick which vault to sync. */
    vaults: VaultView[];
    /** The currently-selected vault id (defaults the sync/share pickers). */
    selectedVault: string;
    /** Called after adopting shared vaults, so the parent can refresh its vault
     *  list and session-derived state (e.g. the header vault count). */
    onVaultsChanged?: () => void;
    /** Called after any sync action, so the sidebar status can refresh. */
    onSyncChanged?: () => void;
  }
  let { vaults, selectedVault, onVaultsChanged, onSyncChanged }: Props = $props();

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

  // --- Pending devices (device-pairing.md §5, the typing-free pairing path) ---
  // Devices that announced themselves in the shared folder but are not yet
  // trusted. The announce channel is UNTRUSTED (§5.2): this list is only a
  // discovery hint. "Use for trust" fills the identity box exactly as a paste
  // would — the fingerprint compare + pairing-mode gate still apply, unchanged.
  let pending = $state<PendingDeviceView[]>([]);
  let pendingError = $state("");
  let pendingBusy = $state(false);

  // Share-a-vault panel. A share travels through the vault's OWN sync folder,
  // so the panel shows that folder (and refuses to share before there is one).
  let shareVault = $state("");
  let sharePeer = $state("");
  let shareBusy = $state(false);
  let shareError = $state("");
  let shareStatus = $state<SyncStatusView | null>(null);
  /** The last successful share, for the next-steps checklist. */
  let shareDone = $state<{ vault: string; device: string; folder: string } | null>(null);

  // Adopt panel.
  let adoptDir = $state("");
  let adoptBusy = $state(false);
  let adoptError = $state("");
  let adoptResult = $state<Outcome | null>(null);

  // --- Folder picking (Android) ---
  // On Android, scoped storage means a shared folder can only be reached through
  // the system picker: it hands back a `content://` tree URI, and there is no
  // path a user could type that would work. So on that platform we replace the
  // path text box with a Choose folder button; everywhere else the text box IS
  // the right gesture (type it, or paste it from a file manager). The backend
  // decides which, so the rule lives in one place.
  let canPickDir = $state(false);
  $effect(() => {
    syncDirPickerAvailable()
      .then((v) => (canPickDir = v))
      .catch(() => (canPickDir = false));
  });

  /** Run the picker and fill `target`'s field. Cancelling leaves it untouched. */
  async function chooseFolder(target: "sync" | "adopt") {
    try {
      const dir = await pickSyncDir();
      if (dir === null) return; // cancelled
      if (target === "sync") syncDir = dir;
      else adoptDir = dir;
    } catch (err) {
      const msg = typeof err === "string" ? err : "Could not open the folder picker.";
      if (target === "sync") syncError = msg;
      else adoptError = msg;
    }
  }

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

  // --- Scan a peer's pairing QR (device-pairing.md §3.3/§3.4) ---
  // `mobile` (answered by the backend from cfg(mobile), never a user-agent
  // sniff) selects the scan backend: the native camera plugin on Android/iOS,
  // the webcam via getUserMedia (the CameraScan modal) on desktop. Either way a
  // scan only FILLS the identity box — trust still needs the fingerprint compare.
  let mobile = $state(false);
  let scanBusy = $state(false);
  let scanError = $state("");
  let showCamera = $state(false); // desktop webcam modal open

  // Dispatch the Scan button to the right backend for this platform.
  function startScan() {
    scanError = "";
    if (mobile) {
      doScan();
    } else {
      showCamera = true;
    }
  }

  // Desktop: the CameraScan modal decoded a QR. Same effect as a paste.
  function onCameraDetected(data: string) {
    showCamera = false;
    pasted = data; // → fingerprint preview re-runs, confirmation resets
  }

  async function loadIsMobile() {
    try {
      mobile = await isMobile();
    } catch {
      mobile = false; // no scanner is the safe assumption
    }
  }

  // A scan is ONLY a transport for the identity string: it fills the same box a
  // paste would, and nothing more. The `pasted` effect above then re-derives the
  // fingerprint and forces `confirmed` back off, so the user must still compare
  // it against the other device's screen before Trust enables. There is
  // deliberately no path from "decoded successfully" to "trusted" (§3.3) — a QR
  // image forwarded through a chat app is exactly as substitutable as the string.
  async function doScan() {
    if (scanBusy) return;
    scanBusy = true;
    scanError = "";
    try {
      const { scan, Format, checkPermissions, requestPermissions } = await import(
        "@tauri-apps/plugin-barcode-scanner"
      );
      let perm = await checkPermissions();
      if (perm !== "granted") {
        perm = await requestPermissions();
      }
      if (perm !== "granted") {
        scanError = "Camera access is needed to scan a QR code.";
        return;
      }
      const result = await scan({ windowed: false, formats: [Format.QRCode] });
      const content = result?.content?.trim();
      if (!content) {
        scanError = "Nothing was scanned.";
        return;
      }
      pasted = content; // → fingerprint preview re-runs, confirmation resets
    } catch (err) {
      // A user-cancelled scan is not an error worth shouting about.
      const msg = typeof err === "string" ? err : ((err as Error)?.message ?? "");
      if (!/cancel/i.test(msg)) {
        scanError = msg || "Could not scan a QR code.";
      }
    } finally {
      scanBusy = false;
    }
  }

  // --- Pairing QR (device-pairing.md §3) ---
  // The QR carries the same public identity string as the box above; it is a
  // transport for it, never a shortcut around the fingerprint check.
  let showQr = $state(false);
  let qrSvg = $state("");
  let qrError = $state("");

  // Rendered by the Rust backend, so it goes into an <img> via a data: URI
  // (the CSP allows `img-src 'self' data:`) rather than {@html} — no markup is
  // ever injected into the vault UI.
  const qrDataUri = $derived(
    qrSvg ? `data:image/svg+xml;utf8,${encodeURIComponent(qrSvg)}` : "",
  );

  async function toggleQr() {
    // The QR is gated on pairing mode (§4): showing this device's QR is only
    // allowed inside the deliberate pairing window. The identity STRING stays
    // always visible (it is public) — only the QR is gated.
    if (!pairingActive) return;
    showQr = !showQr;
    if (!showQr || qrSvg) return; // fetched once, then cached
    qrError = "";
    try {
      qrSvg = await identityQrSvg();
    } catch (err) {
      qrError = typeof err === "string" ? err : "Could not render the QR code.";
    }
  }

  // --- Pairing mode (device-pairing.md §4) ---
  // A time-boxed (3-minute) window that must be ON for the daemon to accept
  // trusting a NEW device (and to show this device's QR). Off by default; the
  // backend enforces the window server-side and audits the toggle. The daemon is
  // the single source of truth for the remaining time — we fetch it on mount and
  // after each toggle, then tick it down locally so the countdown reads smoothly
  // and flips to OFF at zero.
  let pairingSecs = $state<number | null>(null);
  let pairingBusy = $state(false);
  let pairingError = $state("");
  const pairingActive = $derived(pairingSecs !== null && pairingSecs > 0);

  /** Format the remaining seconds as `m:ss` for the countdown. */
  function formatCountdown(secs: number | null): string {
    const s = Math.max(0, secs ?? 0);
    const m = Math.floor(s / 60);
    const r = s % 60;
    return `${m}:${r.toString().padStart(2, "0")}`;
  }

  async function refreshPairing() {
    try {
      pairingSecs = await pairingModeSecs();
    } catch (err) {
      pairingError = typeof err === "string" ? err : "Could not read pairing mode.";
    }
  }

  async function enablePairing() {
    if (pairingBusy) return;
    pairingBusy = true;
    pairingError = "";
    try {
      await setPairingMode(true);
      await refreshPairing();
    } catch (err) {
      pairingError = typeof err === "string" ? err : "Could not enable pairing mode.";
    } finally {
      pairingBusy = false;
    }
  }

  async function disablePairing() {
    if (pairingBusy) return;
    pairingBusy = true;
    pairingError = "";
    try {
      await setPairingMode(false);
      await refreshPairing();
      showQr = false; // the QR is gated on the window (§4)
    } catch (err) {
      pairingError = typeof err === "string" ? err : "Could not turn off pairing mode.";
    } finally {
      pairingBusy = false;
    }
  }

  // Local 1-second countdown. While active it ticks the displayed seconds down;
  // at zero it re-syncs with the daemon (the authority on expiry) and hides the
  // QR, so the control flips to OFF exactly when the window closes.
  $effect(() => {
    const id = setInterval(() => {
      if (pairingSecs === null) return;
      if (pairingSecs <= 1) {
        pairingSecs = null;
        showQr = false;
        void refreshPairing();
      } else {
        pairingSecs -= 1;
      }
    }, 1000);
    return () => clearInterval(id);
  });

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
      syncResult = "This vault now syncs through that folder.";
      setupOpen = false;
      await refreshStatus();
      // Setup writes this device's announce and surfaces any peers already in
      // the folder as pending devices (device-pairing.md §5).
      await refreshPending();
    } catch (err) {
      syncError = typeof err === "string" ? err : "Setup failed.";
    } finally {
      syncBusy = false;
      onSyncChanged?.();
    }
  }

  async function doPush() {
    if (!syncVault || syncBusy) return;
    syncBusy = true;
    syncError = "";
    syncResult = "";
    try {
      const r = await syncPush(syncVault);
      syncResult = r.segments_written
        ? `Sent ${r.segments_written} change set${r.segments_written === 1 ? "" : "s"}.`
        : "Nothing new to send.";
      await refreshStatus();
      // A push refreshes this device's announce; re-scan for any new peers.
      await refreshPending();
    } catch (err) {
      syncError = typeof err === "string" ? err : "Push failed.";
    } finally {
      syncBusy = false;
      onSyncChanged?.();
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
      syncResult = receivedLine(r.applied, r.pending, r.key_imported);
      await refreshStatus();
    } catch (err) {
      syncError = typeof err === "string" ? err : "Pull failed.";
    } finally {
      syncBusy = false;
      onSyncChanged?.();
    }
  }

  /** Re-scan the shared folder's `pairing/` list (device-pairing.md §5). Gated
   *  on a configured folder; an empty folder just clears the list. Untrusted
   *  (§5.2) — it only populates the list, never pins. */
  async function refreshPending(dir: string = syncDir) {
    const d = dir.trim();
    if (!d) {
      pending = [];
      pendingError = "";
      return;
    }
    pendingBusy = true;
    pendingError = "";
    try {
      pending = await listPendingDevices(d);
    } catch (err) {
      pendingError = typeof err === "string" ? err : "Could not list pending devices.";
      pending = [];
    } finally {
      pendingBusy = false;
    }
  }

  /** "Use for trust": drop a pending device's identity string into the trust box.
   *  This reuses the existing `pasted` effect — it re-derives the fingerprint and
   *  resets the confirm checkbox — so the user still compares the fingerprint and
   *  confirms exactly as today. It never auto-trusts (device-pairing.md §5.2). */
  function usePendingForTrust(identityString: string) {
    pasted = identityString;
  }

  async function refreshStatus(vaultId: string = syncVault) {
    if (!vaultId) return;
    try {
      status = await syncStatus(vaultId);
      alarms = status.alarms.length ? status.alarms : alarms;
      if (status.enrolled && status.root && !syncDir.trim()) {
        syncDir = status.root;
        void refreshPending(status.root);
      }
      // Receiving usually uses the folder this device already syncs through.
      if (status.enrolled && status.root && !adoptDir.trim()) adoptDir = status.root;
      if (vaultId === shareVault) shareStatus = status;
    } catch {
      status = null;
    }
  }

  /** The share vault's sync status: which folder a share would go through,
   *  and whether any other device has used that folder. */
  async function refreshShareStatus(vaultId: string = shareVault) {
    if (!vaultId) {
      shareStatus = null;
      return;
    }
    try {
      shareStatus = await syncStatus(vaultId);
    } catch {
      shareStatus = null;
    }
  }

  async function doShare() {
    if (!shareVault || !sharePeer || shareBusy) return;
    shareBusy = true;
    shareError = "";
    shareDone = null;
    try {
      await shareVaultToDevice(shareVault, sharePeer);
      const peer = peers.find((p) => p.device_id === sharePeer);
      shareDone = {
        vault: vaults.find((v) => v.id === shareVault)?.name ?? "the vault",
        device: peer?.label?.trim() || "the other device",
        folder: shareStatus?.root ?? "",
      };
    } catch (err) {
      shareError = typeof err === "string" ? err : "Share failed.";
    } finally {
      shareBusy = false;
    }
  }

  /** Open the sync-folder panel for the vault being shared. */
  function setUpShareVault() {
    syncVault = shareVault;
    void refreshStatus(shareVault);
    setupOpen = true;
  }

  async function doAdopt() {
    if (!adoptDir.trim() || adoptBusy) return;
    adoptBusy = true;
    adoptError = "";
    adoptResult = null;
    alarms = [];
    try {
      const r = await syncAdopt(adoptDir.trim());
      alarms = r.alarms;
      adoptResult = adoptOutcome(r);
      if (r.adopted.length > 0) onVaultsChanged?.(); // refresh the parent vault list + header count
    } catch (err) {
      adoptError = typeof err === "string" ? err : "Adopt failed.";
    } finally {
      adoptBusy = false;
    }
  }

  /** "Received 3 changes." plus what is still waiting. */
  function receivedLine(applied: number, waiting: number, keyImported: boolean): string {
    const bits = [applied ? `Received ${applied} change${applied === 1 ? "" : "s"}` : "Nothing new to receive"];
    if (waiting) bits.push(`${waiting} waiting for a vault key`);
    if (keyImported) bits.push("imported a shared vault key");
    return bits.join(", ") + ".";
  }

  /** Sync now: publish this device's changes, then merge everyone else's. */
  async function doSyncNow() {
    if (!syncVault || syncBusy) return;
    syncBusy = true;
    syncError = "";
    syncResult = "";
    alarms = [];
    try {
      const pushed = await syncPush(syncVault);
      const pulled = await syncPull(syncVault);
      alarms = pulled.alarms;
      const sent = pushed.segments_written
        ? `Sent ${pushed.segments_written} change set${pushed.segments_written === 1 ? "" : "s"}. `
        : "";
      syncResult = sent + receivedLine(pulled.applied, pulled.pending, pulled.key_imported);
      await refreshStatus();
      await refreshPending();
    } catch (err) {
      syncError = typeof err === "string" ? err : "Sync failed.";
    } finally {
      syncBusy = false;
      onSyncChanged?.();
    }
  }

  const summary = $derived(summarizeSync(status, peers));
  const deviceSync = $derived(new Map(summary.devices.map((d) => [d.device_id, d])));
  let setupOpen = $state(false);
  let pairOpen = $state(false);

  // On mount: default the pickers to the parent's selected vault (or the first
  // vault), load this device's identity + the trusted peers, and read status.
  $effect(() => {
    const fallback = selectedVault || vaults[0]?.id || "";
    syncVault = fallback;
    shareVault = fallback;
    loadIdentity();
    loadIsMobile();
    loadPeers();
    refreshPairing();
    refreshStatus(fallback);
    refreshPending();
  });

  // The share panel's vault: look up its folder whenever it changes.
  $effect(() => {
    const v = shareVault;
    shareDone = null;
    void refreshShareStatus(v);
  });

  const shareVaultName = $derived(vaults.find((v) => v.id === shareVault)?.name ?? "this vault");
</script>

<div class="page devices">
  <div class="page-head">
    <div>
      <h2>Devices and sync</h2>
      <p class="sub">Your devices share an encrypted folder. The folder is never trusted.</p>
    </div>
    <div class="actions">
      {#if vaults.length > 1}
        <label class="sr-only" for="sync-vault">Vault</label>
        <select id="sync-vault" class="vault-pick" bind:value={syncVault} onchange={() => refreshStatus()}>
          {#each vaults as v (v.id)}
            <option value={v.id}>{v.name}</option>
          {/each}
        </select>
      {/if}
      {#if status?.enrolled}
        <button class="btn btn-primary" onclick={doSyncNow} disabled={syncBusy || !syncVault}>
          <Icon name="sync" size={15} /> {syncBusy ? "Syncing…" : "Sync now"}
        </button>
      {/if}
    </div>
  </div>

  {#if alarms.length}
    <div class="callout danger" role="alert" aria-live="assertive">
      <span class="icon"><Icon name="alert" size={16} /></span>
      <div>
        <strong>A device's history failed verification.</strong> Possible tampering or a
        rollback. Its changes were quarantined, not applied. Do not ignore this.
        <ul class="alarm-list">
          {#each alarms as a (a)}<li class="mono">{a}</li>{/each}
        </ul>
      </div>
    </div>
  {/if}

  <!-- ===================== Status ===================== -->
  <section class="status-head" aria-live="polite">
    <span class="dot big {summary.tone === 'ok' ? 'ok' : summary.tone === 'danger' ? 'danger' : summary.tone === 'warn' ? 'warn' : ''}"></span>
    <div class="status-text">
      <p class="headline">{status?.enrolled ? summary.headline : "This vault is not syncing yet"}</p>
      {#if status?.enrolled}
        <p class="detail-line">
          Folder <code class="wrap-anywhere">{status.root ?? "(none)"}</code>{#if status.pending}
            · {status.pending} waiting for a vault key{/if}
        </p>
        {#if peers.length > 0 && !folderUsedByAnotherDevice(status)}
          <p class="detail-line warn-line">
            No other device has used this folder yet. Make sure your other devices sync it too
            (Syncthing, OneDrive, Dropbox, a network drive), not a folder that exists only on this
            computer.
          </p>
        {/if}
      {:else}
        <p class="detail-line">Pick a shared folder (Dropbox, OneDrive, Syncthing, a USB drive) to keep this vault in step across devices.</p>
      {/if}
      {#if syncResult}<p class="detail-line ok-line" role="status">{syncResult}</p>{/if}
      {#if syncError}<div class="error" role="alert">{syncError}</div>{/if}
    </div>
    {#if !status?.enrolled}
      <button class="btn" onclick={() => (setupOpen = true)}>Set up sync</button>
    {/if}
  </section>

  <!-- ===================== Devices ===================== -->
  <section class="section">
    <div class="section-head">
      <h3>Devices</h3>
      <button class="btn btn-sm btn-quiet accent" onclick={() => (pairOpen = true)}>
        <Icon name="plus" size={14} /> Add a device
      </button>
    </div>
    {#if peersError}
      <div class="error" role="alert">{peersError}</div>
    {/if}
    <ul class="plain-list device-list">
      <li>
        <span class="dev-ico"><Icon name="devices" size={18} /></span>
        <span class="dev-main">
          <span class="dev-name">This device</span>
          {#if identity}<span class="dev-fp mono">{identity.fingerprint}</span>{/if}
        </span>
        <span class="badge">You</span>
      </li>
      {#each peers as p (p.device_id)}
        {@const ds = deviceSync.get(p.device_id)}
        <li>
          <span class="dev-ico"><Icon name="devices" size={18} /></span>
          <span class="dev-main">
            <span class="dev-name">{p.label || "Unnamed device"}</span>
            <span class="dev-fp mono">{p.fingerprint}</span>
          </span>
          {#if !status?.enrolled}
            <span class="faint dev-when">Trusted {formatTimestamp(p.verified_at)}</span>
          {:else if !ds}
            <span class="badge" title="This device has not written to this vault's folder">Not in this folder</span>
          {:else if ds.to_receive > 0}
            <span class="badge warn">{ds.to_receive} to receive</span>
          {:else}
            <span class="badge ok">Up to date</span>
          {/if}
        </li>
      {/each}
      {#each summary.devices.filter((d) => !d.is_self && !d.trusted) as d (d.device_id)}
        <li>
          <span class="dev-ico"><Icon name="alert" size={18} /></span>
          <span class="dev-main">
            <span class="dev-name">Unknown device</span>
            <span class="dev-fp mono">{d.device_id.slice(0, 12)}…</span>
          </span>
          <span class="badge danger">Untrusted</span>
        </li>
      {/each}
    </ul>
    {#if peers.length === 0}
      <p class="hint">No other devices yet. Add one to sync or share a vault with it.</p>
    {/if}
  </section>

  <!-- ===================== Add a device (pairing) ===================== -->
  <details class="disclosure" bind:open={pairOpen}>
    <summary>
      <Icon name="qr" size={16} /> Add a device
      {#if pairingActive}<span class="sum-meta">· pairing open <span class="mono">{formatCountdown(pairingSecs)}</span></span>{/if}
      <span class="chev"><Icon name="chevron" size={14} /></span>
    </summary>
    <div class="body">
      <!-- Pairing mode (device-pairing.md §4): a deliberate, time-boxed (3-min)
           window that must be ON to trust a NEW device or to show this device's
           QR. Off by default; turning it off never affects an already-trusted
           device or any sync. The backend enforces it regardless of this UI. -->
      <ol class="steps">
        <li>
          <div class="step-head">
            <span class="step-t">Open pairing on both devices</span>
            {#if pairingActive}
              <span class="badge accent">Open · <span class="mono">{formatCountdown(pairingSecs)}</span></span>
              <button class="btn btn-sm btn-quiet" onclick={disablePairing} disabled={pairingBusy}>Close</button>
            {:else}
              <button class="btn btn-sm" onclick={enablePairing} disabled={pairingBusy}>
                {pairingBusy ? "…" : "Open for 3 minutes"}
              </button>
            {/if}
          </div>
          <p class="hint">New devices can only be trusted while it is open. It closes by itself.</p>
          {#if pairingError}<div class="error" role="alert">{pairingError}</div>{/if}
        </li>

        <li>
          <div class="step-head"><span class="step-t">Show this device to the other one</span></div>
          {#if identityError}
            <div class="error" role="alert">{identityError}</div>
          {:else if identity}
            <!-- Pairing QR: scanning it in person is a far stronger channel than
                 pasting the string through a chat app (device-pairing.md §1.2).
                 Gated on pairing mode (§4); the string stays visible (public). -->
            <div class="share-row">
              {#if showQr && pairingActive && qrDataUri}
                <div class="qr-plate">
                  <img src={qrDataUri} alt="QR code containing this device's identity" />
                </div>
              {/if}
              <div class="share-main">
                <div class="toolbar">
                  <button class="btn btn-sm" onclick={toggleQr} aria-expanded={showQr} disabled={!pairingActive}>
                    <Icon name="qr" size={14} /> {showQr ? "Hide QR code" : "Show QR code"}
                  </button>
                  <button class="btn btn-sm" onclick={copyIdentity}><Icon name="copy" size={14} /> Copy identity</button>
                </div>
                {#if qrError}<div class="error" role="alert">{qrError}</div>{/if}
                <p class="hint">
                  The other device must show this fingerprint:
                  <strong class="mono fp">{identity.fingerprint}</strong>
                </p>
                {#if !pairingActive}<p class="hint">Open pairing to show the QR code.</p>{/if}
              </div>
            </div>
          {:else}
            <p class="muted">Loading…</p>
          {/if}
        </li>

        <li>
          <div class="step-head"><span class="step-t">Trust the other device</span></div>
          <!-- Scanning only FILLS the identity box, exactly as a paste would, and
               re-arms the fingerprint confirmation. It never trusts on its own
               (device-pairing.md §3.3). -->
          <div class="toolbar">
            <button type="button" class="btn btn-sm" onclick={startScan} disabled={scanBusy}>
              <Icon name="camera" size={14} /> {scanBusy ? "Scanning…" : "Scan its QR code"}
            </button>
            <span class="faint">or paste its identity below</span>
          </div>
          {#if scanError}<div class="error" role="alert">{scanError}</div>{/if}

          <form onsubmit={submitTrust} class="trust-form">
            <label for="paste-id" class="label">Its identity</label>
            <textarea
              id="paste-id"
              rows="2"
              bind:value={pasted}
              placeholder="LPDEV1-…"
              autocomplete="off"
              spellcheck="false"
              class="mono"
              aria-describedby="paste-id-fp"
              aria-invalid={parsedInvalid ? "true" : undefined}
            ></textarea>

            <div id="paste-id-fp" aria-live="polite">
              {#if parsedInvalid}
                <div class="error" role="alert">That is not a device identity. Check for a copy or paste error.</div>
              {:else if parsedFingerprint}
                <div class="fp-compare">
                  <span class="label">Compare with the other device's screen</span>
                  <strong class="mono fp big">{parsedFingerprint}</strong>
                </div>
                <label class="check confirm">
                  <input type="checkbox" bind:checked={confirmed} />
                  <span>It matches <strong>exactly</strong> what the other device shows.</span>
                </label>
              {/if}
            </div>

            <div class="trust-row">
              <div>
                <label for="trust-label" class="label">Name (optional)</label>
                <input id="trust-label" type="text" bind:value={trustLabel} placeholder="e.g. Pixel 8" autocomplete="off" />
              </div>
              <button class="btn btn-primary" type="submit" disabled={!canTrust}>
                {trustBusy ? "Trusting…" : "Trust device"}
              </button>
            </div>
            {#if !pairingActive && parsedFingerprint}
              <p class="hint">Open pairing first; the service refuses new devices while it is closed.</p>
            {/if}
            {#if trustError}<div class="error" role="alert">{trustError}</div>{/if}
          </form>
          <p class="hint">
            Then do the same on the other device, so each one trusts the other. Syncing and
            sharing a vault both need that.
          </p>

          <!-- Pending devices (device-pairing.md §5): devices that announced
               themselves in the shared folder. UNTRUSTED (§5.2): "Use" only
               fills the identity box; the compare + pairing gate still apply. -->
          {#if syncDir.trim() || pending.length}
            <div class="pending">
              <div class="section-head">
                <span class="label" style="margin:0">Seen in the sync folder</span>
                <button class="icon-btn sm" onclick={() => refreshPending()} disabled={pendingBusy || !syncDir.trim()} aria-label="Look again">
                  <Icon name="refresh" size={14} />
                </button>
              </div>
              {#if pendingError}
                <div class="error" role="alert">{pendingError}</div>
              {:else if pending.length === 0}
                <p class="hint">No new devices have announced themselves there.</p>
              {:else}
                <ul class="plain-list">
                  {#each pending as d (d.device_id)}
                    <li>
                      <span class="dev-main">
                        <span class="dev-name">{d.label || `Device ${d.device_id.slice(0, 8)}`}</span>
                        <span class="dev-fp mono">{d.fingerprint} · announced {formatTimestamp(d.announced_at)}</span>
                      </span>
                      <button class="btn btn-sm" onclick={() => usePendingForTrust(d.identity_string)}>Use</button>
                    </li>
                  {/each}
                </ul>
                <p class="hint">Listed here is not proof. You still compare the fingerprint.</p>
              {/if}
            </div>
          {/if}
        </li>
      </ol>
    </div>
  </details>

  <!-- ===================== Sync folder ===================== -->
  <details class="disclosure" bind:open={setupOpen}>
    <summary>
      <Icon name="folder" size={16} /> Sync folder
      <span class="sum-meta">{status?.enrolled ? "· set up" : "· not set up"}</span>
      <span class="chev"><Icon name="chevron" size={14} /></span>
    </summary>
    <div class="body">
      <label for="sync-dir" class="label">{canPickDir ? "Shared folder" : "Shared folder path"}</label>
      <div class="dir-row">
        <input
          id="sync-dir"
          type="text"
          bind:value={syncDir}
          placeholder={canPickDir ? "No folder chosen yet" : "C:\\Users\\you\\Dropbox\\localpass-sync"}
          autocomplete="off"
          spellcheck="false"
          class="mono"
          readonly={canPickDir}
        />
        {#if canPickDir}
          <button class="btn" onclick={() => chooseFolder("sync")}>Choose…</button>
        {/if}
      </div>
      <div class="toolbar" style="margin-top:8px">
        <button class="btn btn-primary" onclick={doSetup} disabled={syncBusy || !syncVault || !syncDir.trim()}>
          Use this folder for {vaults.find((v) => v.id === syncVault)?.name ?? "this vault"}
        </button>
        {#if status?.enrolled}
          <button class="btn btn-quiet" onclick={doPush} disabled={syncBusy || !syncVault} title="Publish this device's changes only">Send only</button>
          <button class="btn btn-quiet" onclick={doPull} disabled={syncBusy || !syncVault} title="Receive other devices' changes only">Receive only</button>
        {/if}
      </div>
    </div>
  </details>

  <!-- ===================== Share ===================== -->
  <details class="disclosure">
    <summary>
      <Icon name="upload" size={16} /> Share a vault with a device
      <span class="chev"><Icon name="chevron" size={14} /></span>
    </summary>
    <div class="body">
      <p class="hint" style="margin-top:0">
        Sends the vault's key, sealed to that device, through the vault's sync folder. The other
        device then receives it from the same folder.
      </p>
      <div class="share-grid">
        <div>
          <label for="share-vault" class="label">Vault</label>
          <select id="share-vault" bind:value={shareVault}>
            {#each vaults as v (v.id)}<option value={v.id}>{v.name}</option>{/each}
          </select>
        </div>
        <div>
          <label for="share-peer" class="label">Device</label>
          <select id="share-peer" bind:value={sharePeer}>
            <option value="" disabled>Choose a trusted device…</option>
            {#each peers as p (p.device_id)}<option value={p.device_id}>{p.label || p.fingerprint}</option>{/each}
          </select>
        </div>
        <button
          class="btn btn-primary"
          onclick={doShare}
          disabled={shareBusy || !shareVault || !sharePeer || !shareStatus?.enrolled}
        >
          {shareBusy ? "Sharing…" : "Share"}
        </button>
      </div>
      {#if peers.length === 0}
        <p class="hint">Add the other device first (Add a device above), on both devices.</p>
      {/if}
      {#if shareStatus && !shareStatus.enrolled}
        <div class="toolbar note">
          <span>{shareVaultName} does not sync through a folder yet, so there is nothing to send the key through.</span>
          <button class="btn btn-sm" onclick={setUpShareVault}>Set up its sync folder</button>
        </div>
      {:else if shareStatus?.enrolled}
        <p class="hint">
          Goes through <code class="wrap-anywhere">{shareStatus.root}</code>
        </p>
        {#if peers.length > 0 && !folderUsedByAnotherDevice(shareStatus)}
          <p class="hint warn-line">
            No other device has used this folder yet. Check that the other device syncs it too;
            a folder that exists only on this computer never reaches it.
          </p>
        {/if}
      {/if}
      {#if shareError}<div class="error" role="alert">{shareError}</div>{/if}
      {#if shareDone}
        <div class="next-steps" role="status">
          <p><strong>Shared {shareDone.vault} with {shareDone.device}.</strong> Next, on {shareDone.device}:</p>
          <ol>
            <li>
              Trust this device, if it does not yet. Its fingerprint is
              <strong class="mono">{identity?.fingerprint ?? "shown above"}</strong>.
            </li>
            <li>
              Wait until {#if shareDone.folder}<code class="wrap-anywhere">{shareDone.folder}</code>{:else}the folder{/if}
              has synced there.
            </li>
            <li>Open Devices, then Receive vaults shared with this device, and choose that same folder.</li>
          </ol>
        </div>
      {/if}
    </div>
  </details>

  <!-- ===================== Adopt ===================== -->
  <details class="disclosure">
    <summary>
      <Icon name="download" size={16} /> Receive vaults shared with this device
      <span class="chev"><Icon name="chevron" size={14} /></span>
    </summary>
    <div class="body">
      <p class="hint" style="margin-top:0; margin-bottom:10px">
        Choose the folder the other device shared through, as it appears on this device. Both
        devices must trust each other first.
        {#if identity}On the sharing device, pick the device with this fingerprint:
          <strong class="mono">{identity.fingerprint}</strong>{/if}
      </p>
      <label for="adopt-dir" class="label">{canPickDir ? "Shared folder" : "Shared folder path"}</label>
      <div class="dir-row">
        <input
          id="adopt-dir"
          type="text"
          bind:value={adoptDir}
          placeholder={canPickDir ? "No folder chosen yet" : "C:\\Users\\you\\Dropbox\\localpass-sync"}
          autocomplete="off"
          spellcheck="false"
          class="mono"
          readonly={canPickDir}
        />
        {#if canPickDir}
          <button class="btn" onclick={() => chooseFolder("adopt")}>Choose…</button>
        {/if}
        <button class="btn btn-primary" onclick={doAdopt} disabled={adoptBusy || !adoptDir.trim()}>
          {adoptBusy ? "Looking…" : "Receive"}
        </button>
      </div>
      {#if adoptError}<div class="error" role="alert">{adoptError}</div>{/if}
      {#if adoptResult}
        <div class="outcome {adoptResult.tone}" role="status">
          <p class="outcome-t">{adoptResult.title}</p>
          <p>{adoptResult.detail}</p>
          {#if adoptResult.action === "pair"}
            <button class="btn btn-sm" onclick={() => (pairOpen = true)}>Open Add a device</button>
          {/if}
        </div>
      {/if}
    </div>
  </details>
</div>

<!-- Desktop webcam scanner. Decoding fills the identity box; it never trusts. -->
{#if showCamera}
  <CameraScan onDetected={onCameraDetected} onClose={() => (showCamera = false)} />
{/if}

<style>
  .devices {
    max-width: 760px;
  }
  .vault-pick {
    width: auto;
    max-width: 180px;
  }
  .alarm-list {
    margin: 6px 0 0;
    padding-left: 18px;
  }
  .status-head {
    display: flex;
    align-items: flex-start;
    gap: 14px;
    padding: 16px 18px;
    border-radius: var(--radius-lg);
    background: var(--bg-hover);
  }
  .dot.big {
    width: 10px;
    height: 10px;
    margin-top: 7px;
  }
  .status-text {
    flex: 1;
    min-width: 0;
  }
  .headline {
    font-family: var(--font-display);
    font-size: 16px;
    font-weight: 600;
  }
  .detail-line {
    margin-top: 3px;
    font-size: 12.5px;
    color: var(--text-muted);
  }
  .detail-line code {
    font-size: 12px;
  }
  .ok-line {
    color: var(--success);
  }
  .warn-line {
    color: var(--warning);
  }
  /* What Receive found, and what to do next. */
  .outcome,
  .next-steps,
  .note {
    margin-top: 10px;
    padding: 10px 12px;
    border-radius: var(--radius);
    border: 1px solid var(--border);
    font-size: 13px;
  }
  .outcome p,
  .next-steps p {
    margin: 0;
  }
  .outcome p + p,
  .outcome p + .btn {
    margin-top: 4px;
  }
  .outcome .btn {
    margin-top: 8px;
  }
  .outcome-t {
    font-weight: 600;
  }
  .outcome.ok {
    border-color: color-mix(in srgb, var(--success) 40%, var(--border));
  }
  .outcome.warn {
    background: var(--warning-tint);
    border-color: color-mix(in srgb, var(--warning) 40%, var(--border));
  }
  .next-steps ol {
    margin: 6px 0 0;
    padding-left: 20px;
    display: grid;
    gap: 4px;
  }
  .note {
    justify-content: space-between;
    flex-wrap: wrap;
    gap: 8px;
  }
  .device-list .dev-ico {
    color: var(--text-muted);
  }
  .dev-main {
    flex: 1;
    min-width: 0;
    display: grid;
  }
  .dev-name {
    font-weight: 600;
    overflow-wrap: anywhere;
  }
  .dev-fp {
    font-size: 12px;
    color: var(--text-muted);
    overflow-wrap: anywhere;
  }
  .dev-when {
    font-size: 12px;
    white-space: nowrap;
  }
  .fp {
    letter-spacing: 0.04em;
  }
  .fp.big {
    display: block;
    font-size: 17px;
    margin-top: 2px;
  }
  .steps {
    margin: 0;
    padding-left: 20px;
    display: grid;
    gap: 18px;
  }
  .steps > li::marker {
    color: var(--text-faint);
    font-weight: 600;
  }
  .step-head {
    display: flex;
    align-items: center;
    gap: 8px;
    flex-wrap: wrap;
    min-height: 28px;
  }
  .step-t {
    font-weight: 600;
    margin-right: 4px;
  }
  .share-row {
    display: flex;
    gap: 16px;
    align-items: flex-start;
    flex-wrap: wrap;
    margin-top: 6px;
  }
  .share-main {
    flex: 1;
    min-width: 220px;
  }
  /* The QR plate stays light in every theme on purpose: a scanner needs the
     quiet zone light to detect the symbol at all, so we never invert it. */
  .qr-plate {
    padding: 10px;
    background: #fff;
    border-radius: 8px;
    border: 1px solid var(--border);
  }
  .qr-plate img {
    display: block;
    width: 200px;
    height: auto;
    max-width: 100%;
  }
  .trust-form {
    margin-top: 10px;
  }
  .fp-compare {
    margin: 10px 0 6px;
    padding: 10px 12px;
    border-radius: var(--radius);
    background: var(--accent-tint);
  }
  .fp-compare .label {
    margin: 0;
  }
  .confirm {
    margin: 6px 0 10px;
  }
  .trust-row {
    display: flex;
    align-items: flex-end;
    gap: 8px;
    margin-top: 10px;
    flex-wrap: wrap;
  }
  .trust-row > div {
    flex: 1 1 200px;
  }
  .pending {
    margin-top: 16px;
    padding-top: 10px;
    border-top: 1px solid var(--border);
  }
  .dir-row {
    display: flex;
    gap: 6px;
    align-items: center;
  }
  .dir-row input {
    flex: 1;
    min-width: 0;
  }
  .share-grid {
    display: grid;
    grid-template-columns: minmax(0, 1fr) minmax(0, 1fr) auto;
    gap: 8px;
    align-items: end;
  }
  @media (max-width: 719px) {
    .share-grid {
      grid-template-columns: 1fr;
    }
    .dir-row {
      flex-wrap: wrap;
    }
    .status-head {
      flex-wrap: wrap;
    }
  }
</style>
