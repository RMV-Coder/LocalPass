<!--
  SPDX-License-Identifier: MPL-2.0
  This file is part of the LocalPass desktop GUI. See ../../LICENSE.

  Send by QR code (qr-transport.md §3, §10.4): pick what to send, optionally
  scan the receiver's "what I have" code, then play the stream full-screen.

  SECURITY: everything shown is ciphertext and sync metadata — what the sync
  folder holds. The backend builds the bundle (through the daemon), encodes
  and renders each frame; this component only draws the matrices. A scanned
  "what I have" code is unauthenticated: it can only change WHICH ops are
  sent, its device id may pre-select a trusted device (the user still
  confirms), and it never causes a share by itself.
-->
<script lang="ts">
  import { untrack } from "svelte";
  import {
    qrDefaultCodeSize,
    qrHaveParse,
    qrSendFrames,
    qrSendStart,
    qrSendStop,
    type QrCodeSize,
  } from "../lib/api";
  import type { PeerView, QrHaveInfo, QrSendView, VaultView } from "../lib/types";
  import {
    FrameFeed,
    MAX_FPS,
    MIN_FPS,
    clampFps,
    drawMatrix,
    estimateSeconds,
    formatDuration,
    type QrMatrix,
  } from "../lib/qrstream";
  import QrCamera from "./QrCamera.svelte";
  import Icon from "./Icon.svelte";

  interface Props {
    vaults: VaultView[];
    peers: PeerView[];
    /** "share" opens with the share options expanded. */
    mode: "sync" | "share";
    onClose: () => void;
  }
  let { vaults, peers, mode, onClose }: Props = $props();

  // --- Options ---------------------------------------------------------------
  // Initial choices only; the user changes them from here.
  // Sharing starts with only the shared vault: the other device cannot use
  // the rest until it holds their keys too.
  let picked = $state<string[]>(untrack(() => (mode === "share" ? [] : vaults.map((v) => v.id))));
  let shareOn = $state(untrack(() => mode === "share"));
  let sharePeer = $state("");
  let shareVault = $state("");
  let attachments = $state(false);
  let codeSize = $state<QrCodeSize>("large");
  qrDefaultCodeSize()
    .then((s) => (codeSize = s))
    .catch(() => {});
  let have = $state<QrHaveInfo | null>(null);
  let haveText = $state("");
  let scanning = $state(false);
  let haveError = $state("");
  let busy = $state(false);
  let error = $state("");

  $effect(() => {
    if (!shareVault && vaults.length) shareVault = vaults[0].id;
    if (!sharePeer && peers.length) sharePeer = peers[0].device_id;
  });

  function peerLabel(id: string): string {
    const p = peers.find((p) => p.device_id === id);
    return p ? p.label || "Unnamed device" : "a device this one does not trust";
  }

  async function acceptHave(code: { bytes?: number[]; text?: string }) {
    haveError = "";
    try {
      const info = await qrHaveParse(code);
      have = info;
      haveText = info.text;
      scanning = false;
      // Pre-select the device it names, if trusted. The user still confirms.
      if (peers.some((p) => p.device_id === info.device_id)) sharePeer = info.device_id;
    } catch (e) {
      haveError = String(e);
    }
  }

  function onHaveScanned(bytes: Uint8ClampedArray) {
    if (have) return;
    void acceptHave({ bytes: Array.from(bytes) });
  }

  // --- Playing ---------------------------------------------------------------
  let send = $state<QrSendView | null>(null);
  let fps = $state(8);
  let paused = $state(false);
  let shown = $state(0);
  let canvasEl: HTMLCanvasElement | undefined = $state();
  let size = $state(320);
  let feed: FrameFeed | null = null;
  let timer: ReturnType<typeof setTimeout> | undefined;
  let wakeLock: { release: () => Promise<void> } | null = null;

  async function start() {
    error = "";
    busy = true;
    try {
      const shareList = shareOn && shareVault ? [shareVault] : [];
      const view = await qrSendStart({
        vaults: picked,
        have: have?.text ?? null,
        peer: shareOn ? sharePeer || null : null,
        share: shareList,
        attachments,
        codeSize,
      });
      send = view;
      fps = view.fps;
      feed = new FrameFeed((s, c) => qrSendFrames(s, c));
      await feed.refill();
      // Keep the screen on while playing, where the platform allows it.
      try {
        const wl = (navigator as Navigator & {
          wakeLock?: { request: (t: string) => Promise<{ release: () => Promise<void> }> };
        }).wakeLock;
        wakeLock = (await wl?.request("screen")) ?? null;
      } catch {
        wakeLock = null;
      }
      resize();
      tick();
    } catch (e) {
      error = String(e);
    } finally {
      busy = false;
    }
  }

  function resize() {
    // As large as the screen allows: bigger modules read from further away.
    size = Math.max(160, Math.floor(Math.min(window.innerWidth, window.innerHeight - 120)));
  }

  function draw(m: QrMatrix) {
    const ctx = canvasEl?.getContext("2d");
    if (ctx && canvasEl) {
      canvasEl.width = size;
      canvasEl.height = size;
      drawMatrix(ctx, m, size);
    }
  }

  function tick() {
    clearTimeout(timer);
    if (!send || !feed) return;
    if (!paused) {
      const m = feed.next();
      if (m) {
        draw(m);
        shown = feed.shown;
      }
    }
    timer = setTimeout(tick, 1000 / fps);
  }

  function setFps(n: number) {
    fps = clampFps(n);
  }

  async function stop() {
    clearTimeout(timer);
    send = null;
    feed = null;
    await wakeLock?.release().catch(() => {});
    wakeLock = null;
    await qrSendStop().catch(() => {});
  }

  async function close() {
    await stop();
    onClose();
  }

  $effect(() => {
    const onResize = () => resize();
    window.addEventListener("resize", onResize);
    return () => {
      window.removeEventListener("resize", onResize);
      clearTimeout(timer);
      void qrSendStop().catch(() => {});
    };
  });

  const eta = $derived(send ? estimateSeconds(send.frames_needed, fps) : 0);
  const totalOps = $derived(send ? send.summary.vaults.reduce((n, v) => n + v.ops, 0) : 0);
</script>

{#if send}
  <!-- Full-screen player. -->
  <div class="player" role="dialog" aria-modal="true" aria-label="Sending by QR code">
    <canvas bind:this={canvasEl} width={size} height={size} class="qr" aria-label="Animated QR code"></canvas>
    <div class="player-bar">
      <span class="mono">Frame {shown}</span>
      <span class="faint">
        The other device needs about {send.frames_needed} · {formatDuration(eta)} at {fps}/s (estimate)
      </span>
      <span class="spacer"></span>
      <button class="btn btn-sm" onclick={() => setFps(fps - 1)} disabled={fps <= MIN_FPS} aria-label="Slower">−</button>
      <span class="mono">{fps}/s</span>
      <button class="btn btn-sm" onclick={() => setFps(fps + 1)} disabled={fps >= MAX_FPS} aria-label="Faster">+</button>
      <button class="btn btn-sm" onclick={() => (paused = !paused)}>{paused ? "Resume" : "Pause"}</button>
      <button class="btn btn-sm btn-primary" onclick={close}>Done</button>
    </div>
    <p class="player-note faint">
      {totalOps} change{totalOps === 1 ? "" : "s"} in {send.summary.vaults.length} vault{send.summary.vaults.length === 1 ? "" : "s"}{#if send.summary.shared.length}
        · shares {send.summary.shared.length} vault key with {peerLabel(send.summary.recipient ?? "")}{/if}{#if send.summary.blobs}
        · {send.summary.blobs} attachment{send.summary.blobs === 1 ? "" : "s"}{/if}.
      Keep it playing until the other device says it is done. Missed frames do not matter.
    </p>
  </div>
{:else}
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
      aria-labelledby="qr-send-title"
      onclick={(e) => e.stopPropagation()}
      onkeydown={(e) => { if (e.key === "Escape") close(); }}
    >
      <h2 id="qr-send-title" class="modal-title">
        {mode === "share" ? "Share a vault by QR code" : "Send by QR code"}
      </h2>
      <p class="muted">
        This device plays a moving QR code; the other device films it. No network is used.
        Only devices that already trust each other can use what is sent.
      </p>

      <fieldset class="group">
        <legend>{mode === "share" ? "Also send changes for" : "Vaults to send"}</legend>
        {#each vaults as v (v.id)}
          <label class="check">
            <input type="checkbox" value={v.id} bind:group={picked} />
            {v.name}
          </label>
        {/each}
      </fieldset>

      <fieldset class="group">
        <legend>The other device's code (recommended)</legend>
        {#if have}
          <p class="ok-line">
            <Icon name="check" size={14} /> Code from {peerLabel(have.device_id)} — lists
            {have.vaults} vault{have.vaults === 1 ? "" : "s"}. Only what it lacks will be sent.
            <button class="btn btn-sm btn-quiet" onclick={() => { have = null; haveText = ""; }}>Clear</button>
          </p>
        {:else if scanning}
          <!-- QrCamera shows its own camera errors. -->
          <QrCamera onCode={onHaveScanned} sampleSize={900} />
          <button class="btn btn-sm" onclick={() => (scanning = false)}>Stop scanning</button>
        {:else}
          <p class="hint">
            On the other device choose Receive by QR and show its code. Without it, everything is sent.
          </p>
          <div class="row">
            <button class="btn btn-sm" onclick={() => (scanning = true)}>
              <Icon name="camera" size={14} /> Scan its code
            </button>
            <input
              class="mono grow"
              placeholder="or paste LPHAVE1-…"
              bind:value={haveText}
              onchange={() => haveText.trim() && acceptHave({ text: haveText })}
            />
          </div>
        {/if}
        {#if haveError}<div class="error" role="alert">{haveError}</div>{/if}
      </fieldset>

      <fieldset class="group">
        <legend>
          <label class="check">
            <input type="checkbox" bind:checked={shareOn} /> Also hand over a vault key
          </label>
        </legend>
        {#if shareOn}
          {#if peers.length === 0}
            <p class="hint">Trust the other device first (Devices → Add a device).</p>
          {:else}
            <label for="qr-share-vault">Vault</label>
            <select id="qr-share-vault" bind:value={shareVault}>
              {#each vaults as v (v.id)}<option value={v.id}>{v.name}</option>{/each}
            </select>
            <label for="qr-share-peer">For device</label>
            <select id="qr-share-peer" bind:value={sharePeer}>
              {#each peers as p (p.device_id)}<option value={p.device_id}>{p.label || "Unnamed device"}</option>{/each}
            </select>
            <p class="hint">
              The key is sealed to that device and signed by this one; no other device can use it.
            </p>
          {/if}
        {/if}
      </fieldset>

      <label for="qr-size">Code size</label>
      <select id="qr-size" bind:value={codeSize}>
        <option value="large">Large — a phone camera films this screen</option>
        <option value="small">Small — a laptop webcam films this screen</option>
      </select>

      <label class="check">
        <input type="checkbox" bind:checked={attachments} />
        Include attachments (slow — a QR code moves only a few kilobytes a second)
      </label>

      {#if error}<div class="error" role="alert">{error}</div>{/if}
      <div class="modal-actions">
        <button class="btn" onclick={close}>Cancel</button>
        <button
          class="btn btn-primary"
          onclick={start}
          disabled={busy || (picked.length === 0 && !shareOn) || (shareOn && !sharePeer)}
        >
          {busy ? "Preparing…" : "Start"}
        </button>
      </div>
    </div>
  </div>
{/if}

<style>
  .qr-card {
    max-width: 520px;
  }
  .qr-card > label[for="qr-size"] {
    display: block;
    margin-top: 12px;
  }
  .qr-card > .check {
    margin-top: 10px;
  }
  .group {
    border: 1px solid var(--border);
    border-radius: 8px;
    padding: 8px 12px 10px;
    margin: 12px 0 0;
  }
  .group legend {
    padding: 0 4px;
    font-weight: 600;
  }
  .row {
    display: flex;
    gap: 8px;
    align-items: center;
    flex-wrap: wrap;
  }
  .grow {
    flex: 1;
    min-width: 0;
  }
  .ok-line {
    display: flex;
    gap: 6px;
    align-items: center;
    flex-wrap: wrap;
  }
  .player {
    position: fixed;
    inset: 0;
    z-index: 200;
    background: #fff;
    color: #111;
    display: flex;
    flex-direction: column;
    align-items: center;
    justify-content: center;
    padding: env(safe-area-inset-top) 8px env(safe-area-inset-bottom);
  }
  .qr {
    image-rendering: pixelated;
  }
  .player-bar {
    display: flex;
    gap: 8px;
    align-items: center;
    flex-wrap: wrap;
    width: min(100%, 720px);
    padding: 8px 0 0;
  }
  .spacer {
    flex: 1;
  }
  .player-note {
    width: min(100%, 720px);
    margin: 4px 0 0;
    font-size: 0.85rem;
    color: #555;
  }
</style>
