<!--
  SPDX-License-Identifier: MPL-2.0
  This file is part of the LocalPass desktop GUI. See ../../LICENSE.

  Receive by QR code (qr-transport.md §4, §9, §10.4): optionally show this
  device's "what I have" code, then film the other device's stream until the
  bundle is complete, then import it.

  SECURITY: this component only passes the raw bytes the camera read to the
  backend. The backend checks every frame before keeping it, the daemon checks
  the rebuilt bundle's hash, adopts a vault key only if a TRUSTED device signed
  it for this device, and runs every change through the same verifier as the
  sync folder. A forged stream is refused there, not here; the report says so.
-->
<script lang="ts">
  import {
    qrHaveCode,
    qrReceiveCancel,
    qrReceiveFinish,
    qrReceiveFrames,
    qrReceiveProgress,
    qrReceiveStart,
  } from "../lib/api";
  import type { QrHaveView, QrImportView, QrProgressView } from "../lib/types";
  import { CodeCollector, drawMatrix, progressFraction } from "../lib/qrstream";
  import { copyToClipboard } from "../lib/clipboard";
  import QrCamera from "./QrCamera.svelte";
  import Icon from "./Icon.svelte";

  interface Props {
    onClose: () => void;
    /** Called after an import that adopted a vault. */
    onVaultsChanged?: () => void;
    /** Called after any import. */
    onSyncChanged?: () => void;
  }
  let { onClose, onVaultsChanged, onSyncChanged }: Props = $props();

  type Step = "intro" | "code" | "scan" | "importing" | "done";
  let step = $state<Step>("intro");
  let have = $state<QrHaveView | null>(null);
  let error = $state("");
  let progress = $state<QrProgressView | null>(null);
  let report = $state<QrImportView | null>(null);
  let codeCanvas: HTMLCanvasElement | undefined = $state();

  const collector = new CodeCollector(64);
  let flushTimer: ReturnType<typeof setInterval> | undefined;
  let flushing = false;

  async function showCode() {
    error = "";
    try {
      have = await qrHaveCode([]);
      step = "code";
    } catch (e) {
      error = String(e);
    }
  }

  $effect(() => {
    if (step === "code" && have && codeCanvas) {
      const size = Math.min(360, window.innerWidth - 64);
      codeCanvas.width = size;
      codeCanvas.height = size;
      const ctx = codeCanvas.getContext("2d");
      if (ctx) drawMatrix(ctx, have.qr, size);
    }
  });

  async function startScan() {
    error = "";
    progress = null;
    await qrReceiveStart();
    step = "scan";
    clearInterval(flushTimer);
    // Hand codes to the backend a few times a second; also lets the backend
    // run its stall / overall timeouts when nothing arrives.
    flushTimer = setInterval(flush, 200);
  }

  async function flush() {
    if (flushing || step !== "scan") return;
    flushing = true;
    try {
      const batch = collector.drain();
      progress = batch.length ? await qrReceiveFrames(batch) : await qrReceiveProgress();
      if (progress.complete) await finish();
      else if (progress.failed) stopScan();
    } catch (e) {
      error = String(e);
      stopScan();
    } finally {
      flushing = false;
    }
  }

  function onCode(bytes: Uint8ClampedArray) {
    collector.add(bytes);
  }

  function stopScan() {
    clearInterval(flushTimer);
    flushTimer = undefined;
  }

  async function finish() {
    stopScan();
    step = "importing";
    try {
      report = await qrReceiveFinish();
      step = "done";
      if (report.adopted.length) onVaultsChanged?.();
      onSyncChanged?.();
    } catch (e) {
      // The bundle stays in the backend: a locked vault can be unlocked and
      // the import retried without filming the stream again.
      error = String(e);
      step = "done";
    }
  }

  async function retryImport() {
    error = "";
    await finish();
  }

  async function close() {
    stopScan();
    await qrReceiveCancel().catch(() => {});
    onClose();
  }

  $effect(() => () => {
    stopScan();
    void qrReceiveCancel().catch(() => {});
  });

  const fraction = $derived(progress ? progressFraction(progress.received, progress.needed) : 0);
  const applied = $derived(report ? report.vaults.reduce((n, v) => n + v.applied, 0) : 0);
  const pending = $derived(report ? report.vaults.reduce((n, v) => n + v.pending, 0) : 0);
  const missingBlobs = $derived(report ? report.vaults.reduce((n, v) => n + v.blobs_missing, 0) : 0);
</script>

<div
  class="modal-overlay"
  role="button"
  tabindex="-1"
  aria-label="Close"
  onclick={close}
  onkeydown={(e) => { if (e.key === "Escape") close(); }}
>
  <div
    class="modal-card qr-card"
    role="dialog"
    tabindex="-1"
    aria-modal="true"
    aria-labelledby="qr-recv-title"
    onclick={(e) => e.stopPropagation()}
    onkeydown={(e) => { if (e.key === "Escape") close(); }}
  >
    <h2 id="qr-recv-title" class="modal-title">Receive by QR code</h2>

    {#if step === "intro"}
      <p class="muted">
        The other device plays a moving QR code; this device films it. No network is used.
      </p>
      <ol class="steps-plain">
        <li>
          <strong>Show this device's code</strong> (recommended): the other device scans it
          once, then sends only what this device lacks.
        </li>
        <li>Start the stream on the other device (Send by QR) and point this camera at it.</li>
      </ol>
      {#if error}<div class="error" role="alert">{error}</div>{/if}
      <div class="modal-actions">
        <button class="btn" onclick={startScan}>Skip — receive everything</button>
        <button class="btn btn-primary" onclick={showCode}>
          <Icon name="qr" size={14} /> Show this device's code
        </button>
      </div>
    {:else if step === "code" && have}
      <p class="muted">
        On the other device, choose <strong>Send by QR → Scan its code</strong> and point it here.
      </p>
      <div class="plate"><canvas bind:this={codeCanvas} aria-label="This device's what-I-have code"></canvas></div>
      <p class="hint">
        Lists {have.vaults} vault{have.vaults === 1 ? "" : "s"} and how far each device's changes
        go — ids and counters only, nothing secret.
        <button class="btn btn-sm btn-quiet" onclick={() => have && copyToClipboard(have.text)}>
          <Icon name="copy" size={13} /> Copy as text
        </button>
      </p>
      <div class="modal-actions">
        <button class="btn" onclick={close}>Cancel</button>
        <button class="btn btn-primary" onclick={startScan}>
          <Icon name="camera" size={14} /> Next: film the stream
        </button>
      </div>
    {:else if step === "scan"}
      <!-- QrCamera shows its own camera errors. -->
      <QrCamera {onCode} />
      <div
        class="bar"
        role="progressbar"
        aria-valuemin="0"
        aria-valuemax="100"
        aria-valuenow={Math.round(fraction * 100)}
        aria-label="Received"
      >
        <span style="width: {fraction * 100}%"></span>
      </div>
      <p class="status-line" aria-live="polite">
        {#if !progress?.locked}
          Waiting for the stream…
        {:else}
          {progress.received} of about {progress.needed} pieces
          ({Math.round(progress.bundle_len / 1024)} KB)
        {/if}
        {#if progress && progress.invalid + progress.other_transfer > 0}
          <span class="faint">· ignored {progress.invalid + progress.other_transfer} other codes</span>
        {/if}
      </p>
      {#if progress?.failed}
        <div class="error" role="alert">
          {progress.failed}. Start again, and keep the camera on the stream.
        </div>
      {/if}
      {#if error}<div class="error" role="alert">{error}</div>{/if}
      <div class="modal-actions">
        <button class="btn" onclick={close}>Cancel</button>
        {#if progress?.failed}
          <button class="btn btn-primary" onclick={startScan}>Start again</button>
        {/if}
      </div>
    {:else if step === "importing"}
      <p class="muted">Checking and applying what arrived…</p>
    {:else if step === "done"}
      {#if report}
        {#if report.alarms.length}
          <div class="callout danger" role="alert">
            <span class="icon"><Icon name="alert" size={16} /></span>
            <div>
              <strong>Some of what arrived failed verification and was not applied.</strong>
              <ul class="alarm-list">
                {#each report.alarms as a (a)}<li class="mono">{a}</li>{/each}
              </ul>
            </div>
          </div>
        {/if}
        <p class="headline">
          <Icon name="check" size={15} />
          {applied} change{applied === 1 ? "" : "s"} applied
          {#if report.adopted.length}· {report.adopted.length} vault{report.adopted.length === 1 ? "" : "s"} added{/if}
        </p>
        <ul class="plain">
          {#each report.vaults as v (v.vault_id)}
            <li>
              <strong>{v.name || v.vault_id.slice(0, 8)}</strong>: {v.applied} applied{#if v.skipped}, {v.skipped} already here{/if}{#if v.pending}, {v.pending} waiting for earlier changes{/if}{#if v.blobs_stored}, {v.blobs_stored} attachment{v.blobs_stored === 1 ? "" : "s"}{/if}
            </li>
          {/each}
        </ul>
        <p class="hint">
          From {report.sender_trusted ? report.sender_label || "a trusted device" : "a device this one does not trust"}
          (as the code claims — every change was checked against the devices you trust).
          {#if report.for_another_device}It was made for another device.{/if}
          {#if pending}Some changes need earlier ones first; they apply after the next sync.{/if}
          {#if missingBlobs}{missingBlobs} attachment{missingBlobs === 1 ? "" : "s"} did not travel; they arrive with the next folder or nearby sync.{/if}
          {#if report.not_held.length}{report.not_held.length} vault{report.not_held.length === 1 ? " is" : "s are"} not on this device and were skipped.{/if}
        </p>
      {:else if error}
        <div class="error" role="alert">{error}</div>
      {/if}
      <div class="modal-actions">
        {#if !report && error}
          <button class="btn" onclick={retryImport}>Try the import again</button>
        {/if}
        <button class="btn btn-primary" onclick={close}>Done</button>
      </div>
    {/if}
  </div>
</div>

<style>
  .qr-card {
    max-width: 520px;
  }
  .steps-plain {
    margin: 8px 0 0;
    padding-left: 1.2rem;
  }
  .plate {
    display: grid;
    place-items: center;
    background: #fff;
    border-radius: 8px;
    padding: 8px;
    margin: 10px 0;
  }
  .bar {
    height: 8px;
    border-radius: 4px;
    background: var(--border);
    overflow: hidden;
    margin-top: 10px;
  }
  .bar span {
    display: block;
    height: 100%;
    background: var(--accent);
    transition: width 200ms linear;
  }
  .status-line {
    margin: 6px 0 0;
  }
  .headline {
    display: flex;
    gap: 6px;
    align-items: center;
    font-weight: 600;
  }
  .plain {
    list-style: none;
    padding: 0;
    margin: 6px 0;
  }
</style>
