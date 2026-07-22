<!--
  SPDX-License-Identifier: MPL-2.0
  This file is part of the LocalPass desktop GUI. See ../../LICENSE.

  Desktop webcam QR scanner (device-pairing.md §3). The mobile scanner is a
  native camera plugin (Android/iOS only); this is its desktop counterpart, so a
  laptop can scan the phone's pairing QR instead of pasting the string.

  SECURITY: this only ever decodes the PUBLIC identity string (device id +
  public keys + CRC) — no secret is involved, which is why decoding in the
  webview is fine here. Detecting a code does NOT trust anything: it fills the
  same identity box a paste would, and the out-of-band fingerprint comparison
  still gates trusting (§3.3). The decode is a standard QR-format read (jsQR),
  not a reimplementation of any LocalPass algorithm, so it introduces no second,
  divergent implementation of a security primitive.
-->
<script lang="ts">
  // jsQR (~140 KB) is dynamically imported when the scanner opens, so it never
  // ships in the initial bundle and never loads on mobile (which renders the
  // native plugin instead of this component).
  type JsQR = typeof import("jsqr").default;
  let decode: JsQR | null = null;

  interface Props {
    /** Called with the decoded string once a QR is read. */
    onDetected: (data: string) => void;
    /** Called when the user cancels or the camera cannot be used. */
    onClose: () => void;
  }
  let { onDetected, onClose }: Props = $props();

  let videoEl: HTMLVideoElement | undefined = $state();
  let error = $state("");
  let starting = $state(true);

  let stream: MediaStream | null = null;
  let raf = 0;
  let done = false;
  // One offscreen canvas reused for every frame we sample.
  const canvas = document.createElement("canvas");

  function stop() {
    done = true;
    if (raf) cancelAnimationFrame(raf);
    raf = 0;
    stream?.getTracks().forEach((t) => t.stop());
    stream = null;
  }

  function cancel() {
    stop();
    onClose();
  }

  // Sample the current video frame and try to decode a QR from it.
  function tick() {
    if (done) return;
    const v = videoEl;
    if (v && v.readyState === v.HAVE_ENOUGH_DATA && v.videoWidth > 0) {
      // Cap the sampled size: a QR decodes fine at ~640px and it keeps each
      // frame cheap.
      const scale = Math.min(1, 640 / v.videoWidth);
      const w = Math.round(v.videoWidth * scale);
      const h = Math.round(v.videoHeight * scale);
      canvas.width = w;
      canvas.height = h;
      const ctx = canvas.getContext("2d", { willReadFrequently: true });
      if (ctx) {
        ctx.drawImage(v, 0, 0, w, h);
        const img = ctx.getImageData(0, 0, w, h);
        const code = decode?.(img.data, w, h, { inversionAttempts: "dontInvert" });
        if (code && code.data) {
          const data = code.data.trim();
          stop();
          onDetected(data);
          return;
        }
      }
    }
    raf = requestAnimationFrame(tick);
  }

  async function start() {
    starting = true;
    error = "";
    if (!navigator.mediaDevices?.getUserMedia) {
      error = "This device has no camera access available.";
      starting = false;
      return;
    }
    try {
      // Load the decoder (once) before we start sampling frames.
      decode ??= (await import("jsqr")).default;
      stream = await navigator.mediaDevices.getUserMedia({
        video: { facingMode: "environment" },
        audio: false,
      });
      if (done) {
        // Cancelled while the permission prompt was open.
        stream.getTracks().forEach((t) => t.stop());
        return;
      }
      if (videoEl) {
        videoEl.srcObject = stream;
        await videoEl.play().catch(() => {});
      }
      starting = false;
      raf = requestAnimationFrame(tick);
    } catch (err) {
      const name = (err as { name?: string })?.name ?? "";
      error =
        name === "NotAllowedError"
          ? "Camera access was denied. Allow the camera to scan, or paste the string instead."
          : name === "NotFoundError"
            ? "No camera was found on this device."
            : "Could not start the camera.";
      starting = false;
    }
  }

  $effect(() => {
    start();
    return stop; // stop the camera when the modal unmounts
  });
</script>

<div
  class="modal-overlay"
  role="button"
  tabindex="-1"
  aria-label="Cancel scanning"
  onclick={cancel}
  onkeydown={(e) => { if (e.key === "Escape") cancel(); }}
>
  <div
    class="modal-card"
    role="dialog"
    tabindex="-1"
    aria-modal="true"
    aria-labelledby="cam-scan-title"
    onclick={(e) => e.stopPropagation()}
    onkeydown={(e) => { if (e.key === "Escape") cancel(); }}
  >
    <h2 id="cam-scan-title" class="modal-title">Scan the other device's QR</h2>
    {#if error}
      <div class="error" role="alert">{error}</div>
    {:else}
      <p class="muted">
        Point your webcam at the QR shown in LocalPass on the other device.
      </p>
      <div class="cam-frame">
        <!-- svelte-ignore a11y_media_has_caption -->
        <video bind:this={videoEl} playsinline muted></video>
        {#if starting}<div class="cam-status">Starting camera…</div>{/if}
      </div>
      <p class="hint">
        Scanning only reads the public identity string — you’ll still compare the
        fingerprint before trusting.
      </p>
    {/if}
    <div class="modal-actions">
      <button type="button" class="btn" onclick={cancel}>Cancel</button>
    </div>
  </div>
</div>

<style>
  .cam-frame {
    position: relative;
    margin-top: 0.75rem;
    background: #000;
    border-radius: 8px;
    overflow: hidden;
    aspect-ratio: 4 / 3;
  }
  .cam-frame video {
    display: block;
    width: 100%;
    height: 100%;
    object-fit: cover;
  }
  .cam-status {
    position: absolute;
    inset: 0;
    display: grid;
    place-items: center;
    color: #fff;
    font-size: 0.9rem;
  }
</style>
