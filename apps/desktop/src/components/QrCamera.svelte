<!--
  SPDX-License-Identifier: MPL-2.0
  This file is part of the LocalPass desktop GUI. See ../../LICENSE.

  Continuous camera QR reader for "Sync by QR code" (qr-transport.md §10.4).
  The same loop on desktop (webcam) and Android (the WebView's camera: the
  page's camera request becomes the app's CAMERA permission through the
  WebView's WebChromeClient). jsQR decodes; no proprietary detector (ML Kit,
  BarcodeDetector) is used.

  SECURITY: this only reads raw bytes off the screen in front of the camera
  and hands them up. It interprets nothing: the Rust backend checks every
  frame (size, magic, version, CRC) and every "what I have" code before using
  it. What it reads is ciphertext and sync metadata, never a secret.
-->
<script lang="ts">
  import { DecodePool, decoderCount, type DecoderLike } from "../lib/qrstream";

  // Decoding is what limits a QR stream on a phone (qr-transport.md §12), so
  // it runs in workers: the page stays responsive and a multi-core phone
  // examines about twice the frames. jsQR on the main thread is the fallback
  // where a worker cannot start.
  type JsQR = typeof import("jsqr").default;
  let decode: JsQR | null = null;
  let pool: DecodePool | null = null;

  interface Props {
    /** Called with each decoded code's raw bytes (byte mode, as jsQR read it). */
    onCode: (bytes: Uint8ClampedArray) => void;
    /** Called when the camera cannot be used. */
    onError?: (message: string) => void;
    /** Largest side, in pixels, of the square sampled from the middle of the
     *  picture. Larger reads denser codes but costs more per frame. */
    sampleSize?: number;
  }
  let { onCode, onError, sampleSize = 720 }: Props = $props();

  let videoEl: HTMLVideoElement | undefined = $state();
  let error = $state("");
  let starting = $state(true);
  /** Frames sampled per second, for the status line. */
  let rate = $state(0);

  let stream: MediaStream | null = null;
  let done = false;
  let raf = 0;
  let sampled = 0;
  let rateTimer: ReturnType<typeof setInterval> | undefined;
  const canvas = document.createElement("canvas");

  function stop() {
    done = true;
    pool?.close();
    pool = null;
    if (raf) cancelAnimationFrame(raf);
    raf = 0;
    if (rateTimer) clearInterval(rateTimer);
    stream?.getTracks().forEach((t) => t.stop());
    stream = null;
  }

  function schedule() {
    if (done || !videoEl) return;
    const v = videoEl as HTMLVideoElement & {
      requestVideoFrameCallback?: (cb: () => void) => number;
    };
    // One decode per new camera frame where the browser can tell us; else per
    // display frame.
    if (v.requestVideoFrameCallback) v.requestVideoFrameCallback(tick);
    else raf = requestAnimationFrame(tick);
  }

  function tick() {
    if (done) return;
    const v = videoEl;
    if (v && v.readyState >= 2 && v.videoWidth > 0) {
      // The middle square of the picture, where the user aims the code.
      const side = Math.min(v.videoWidth, v.videoHeight);
      const sx = (v.videoWidth - side) / 2;
      const sy = (v.videoHeight - side) / 2;
      const w = Math.round(Math.min(side, sampleSize));
      if (canvas.width !== w) {
        canvas.width = w;
        canvas.height = w;
      }
      const ctx = canvas.getContext("2d", { willReadFrequently: true });
      if (ctx && pool) {
        // Only grab a frame when a worker can take it.
        if (pool.idle) {
          ctx.drawImage(v, sx, sy, side, side, 0, 0, w, w);
          pool.offer(w, w, ctx.getImageData(0, 0, w, w).data);
          sampled++;
        }
      } else if (ctx && decode) {
        ctx.drawImage(v, sx, sy, side, side, 0, 0, w, w);
        const img = ctx.getImageData(0, 0, w, w);
        const code = decode(img.data, w, w, { inversionAttempts: "dontInvert" });
        sampled++;
        if (code && code.binaryData.length) onCode(Uint8ClampedArray.from(code.binaryData));
      }
    }
    schedule();
  }

  function startPool(): DecodePool | null {
    try {
      const workers: DecoderLike[] = [];
      for (let i = 0; i < decoderCount(navigator.hardwareConcurrency); i++) {
        workers.push(
          new Worker(new URL("../lib/qrworker.ts", import.meta.url), { type: "module" }),
        );
      }
      return new DecodePool(workers, (bytes) => onCode(Uint8ClampedArray.from(bytes)));
    } catch {
      return null;
    }
  }

  async function start() {
    starting = true;
    error = "";
    if (!navigator.mediaDevices?.getUserMedia) {
      error = "This device has no camera access available.";
      starting = false;
      onError?.(error);
      return;
    }
    try {
      pool = startPool();
      if (!pool) decode ??= (await import("jsqr")).default;
      stream = await navigator.mediaDevices.getUserMedia({
        video: {
          facingMode: "environment",
          width: { ideal: 1280 },
          height: { ideal: 720 },
          frameRate: { ideal: 30 },
        },
        audio: false,
      });
      if (done) {
        stream.getTracks().forEach((t) => t.stop());
        return;
      }
      // Keep refocusing: the code on the other screen is close and moves.
      const track = stream.getVideoTracks()[0];
      const caps = (track.getCapabilities?.() ?? {}) as { focusMode?: string[] };
      if (caps.focusMode?.includes("continuous")) {
        await track
          .applyConstraints({ advanced: [{ focusMode: "continuous" } as MediaTrackConstraintSet] })
          .catch(() => {});
      }
      if (videoEl) {
        videoEl.srcObject = stream;
        await videoEl.play().catch(() => {});
      }
      starting = false;
      rateTimer = setInterval(() => {
        rate = sampled;
        sampled = 0;
      }, 1000);
      schedule();
    } catch (err) {
      const name = (err as { name?: string })?.name ?? "";
      error =
        name === "NotAllowedError"
          ? "Camera access was denied. Allow the camera to receive by QR code."
          : name === "NotFoundError"
            ? "No camera was found on this device."
            : "Could not start the camera.";
      starting = false;
      onError?.(error);
    }
  }

  $effect(() => {
    start();
    return stop;
  });
</script>

{#if error}
  <div class="error" role="alert">{error}</div>
{:else}
  <div class="cam-frame">
    <!-- svelte-ignore a11y_media_has_caption -->
    <video bind:this={videoEl} playsinline muted></video>
    <div class="aim" aria-hidden="true"></div>
    {#if starting}<div class="cam-status">Starting camera…</div>{/if}
  </div>
  <p class="faint cam-rate" aria-live="off">{starting ? "" : `Looking ${rate}× a second`}</p>
{/if}

<style>
  .cam-frame {
    position: relative;
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
  /* The sampled square: aim the code inside it. */
  .aim {
    position: absolute;
    top: 50%;
    left: 50%;
    height: 100%;
    aspect-ratio: 1;
    transform: translate(-50%, -50%);
    border: 2px solid rgba(255, 255, 255, 0.6);
    border-radius: 4px;
    pointer-events: none;
  }
  .cam-status {
    position: absolute;
    inset: 0;
    display: grid;
    place-items: center;
    color: #fff;
    font-size: 0.9rem;
  }
  .cam-rate {
    margin: 0.25rem 0 0;
    font-size: 0.8rem;
  }
</style>
