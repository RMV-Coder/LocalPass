// SPDX-License-Identifier: MPL-2.0
// This file is part of the LocalPass desktop GUI. See ../../LICENSE.

// Sync by QR code — the webview's share of the work (qr-transport.md §10.4).
//
// The webview renders and samples; the Rust backend decides. Everything here
// is presentation and plumbing: drawing module matrices the backend rendered,
// pacing the player, and batching the raw bytes jsQR read off the camera. No
// frame is interpreted here — the backend checks every one (size, magic,
// version, CRC) before keeping it.

/** One QR code from the backend: `width × width` modules, packed 4 per hex
 *  digit, most significant bit first, dark = 1. */
export interface QrMatrix {
  esi: number;
  width: number;
  bits: string;
}

/** Whether module `i` (row-major) is dark. */
export function moduleAt(m: QrMatrix, i: number): boolean {
  const nibble = parseInt(m.bits[i >> 2] ?? "0", 16);
  return (nibble & (8 >> (i & 3))) !== 0;
}

/** The quiet zone QR requires around a code, in modules. */
export const QUIET_ZONE = 4;

/** Pixels per module for a code drawn into a `size`-pixel square, quiet zone
 *  included. Whole pixels only: fractional modules blur and decode worse. */
export function pixelsPerModule(width: number, size: number): number {
  return Math.max(1, Math.floor(size / (width + 2 * QUIET_ZONE)));
}

/** Draw `m` dark-on-light into a `size`-pixel square at the canvas origin.
 *  Always dark on light, whatever the theme: inverted codes defeat many
 *  decoders, and the quiet zone must stay light. */
export function drawMatrix(ctx: CanvasRenderingContext2D, m: QrMatrix, size: number): void {
  const px = pixelsPerModule(m.width, size);
  const drawn = px * (m.width + 2 * QUIET_ZONE);
  const off = Math.floor((size - drawn) / 2) + QUIET_ZONE * px;
  ctx.fillStyle = "#ffffff";
  ctx.fillRect(0, 0, size, size);
  ctx.fillStyle = "#000000";
  for (let y = 0; y < m.width; y++) {
    for (let x = 0; x < m.width; x++) {
      if (moduleAt(m, y * m.width + x)) ctx.fillRect(off + x * px, off + y * px, px, px);
    }
  }
}

/** The frame rates the player offers. The default is the backend's. */
export const MIN_FPS = 3;
export const MAX_FPS = 15;

export function clampFps(fps: number): number {
  return Math.min(MAX_FPS, Math.max(MIN_FPS, Math.round(fps)));
}

/** A rough "about how long" for the receiver to collect `needed` frames when
 *  it catches `catchRate` of what is shown. Labelled as an estimate in the UI;
 *  the real rate depends on the camera (qr-transport.md §12). */
export function estimateSeconds(needed: number, fps: number, catchRate = 0.7): number {
  if (needed <= 0 || fps <= 0) return 0;
  return Math.ceil(needed / (fps * Math.max(0.05, catchRate)));
}

export function formatDuration(secs: number): string {
  if (secs < 60) return `${secs} s`;
  const m = Math.floor(secs / 60);
  const s = secs % 60;
  return s ? `${m} min ${s} s` : `${m} min`;
}

/** Fraction done, 0..1, for a progress bar. */
export function progressFraction(received: number, needed: number): number {
  if (needed <= 0) return 0;
  return Math.min(1, received / needed);
}

/** Feeds the player: keeps a buffer of upcoming frames ahead of the display,
 *  fetching the next batch from the backend before it runs dry. Frames go out
 *  in ESI order — source symbols, then repair symbols — and never repeat, so
 *  every frame a camera catches is new information. */
export class FrameFeed {
  private buffer: QrMatrix[] = [];
  private nextEsi = 0;
  private inflight: Promise<void> | null = null;
  shown = 0;

  constructor(
    private readonly fetch: (start: number, count: number) => Promise<QrMatrix[]>,
    private readonly batch = 32,
    private readonly lowWater = 12,
  ) {}

  /** Make sure a fetch is running when the buffer is low. */
  refill(): Promise<void> {
    if (this.inflight || this.buffer.length >= this.lowWater) return this.inflight ?? Promise.resolve();
    const start = this.nextEsi;
    this.nextEsi += this.batch;
    this.inflight = this.fetch(start, this.batch)
      .then((frames) => {
        this.buffer.push(...frames);
      })
      .finally(() => {
        this.inflight = null;
      });
    return this.inflight;
  }

  /** The next frame to show, or null when the buffer is empty (the caller
   *  keeps the previous frame on screen and tries again next tick). */
  next(): QrMatrix | null {
    const f = this.buffer.shift() ?? null;
    if (f) this.shown++;
    void this.refill();
    return f;
  }

  get buffered(): number {
    return this.buffer.length;
  }
}

/** Collects what the camera decodes and hands it to the backend in batches.
 *  A camera at 30 frames per second sees each code on screen several times in
 *  a row; those repeats are dropped here so the backend gets each code once
 *  (it would drop them anyway — this only saves bridge traffic). */
export class CodeCollector {
  private pending: number[][] = [];
  private last = "";
  seen = 0;
  repeats = 0;

  constructor(private readonly maxBatch = 32) {}

  /** Add one decoded code's raw bytes. Returns whether it was new. */
  add(bytes: ArrayLike<number>): boolean {
    this.seen++;
    const key = keyOf(bytes);
    if (key === this.last) {
      this.repeats++;
      return false;
    }
    this.last = key;
    this.pending.push(Array.from(bytes));
    if (this.pending.length > this.maxBatch) this.pending.shift();
    return true;
  }

  /** Take everything collected since the last drain. */
  drain(): number[][] {
    const out = this.pending;
    this.pending = [];
    return out;
  }

  get size(): number {
    return this.pending.length;
  }
}

/** A cheap identity for a code: its length and a hash of its bytes. Equal
 *  codes always match; the rare false match only drops one sighting of a
 *  frame, which the fountain code makes up for. */
function keyOf(bytes: ArrayLike<number>): string {
  const n = bytes.length;
  let h = n;
  for (let i = 0; i < n; i++) h = (Math.imul(h, 31) + bytes[i]) | 0;
  return `${n}:${h}`;
}

/** A decoder worker as the pool sees it: a real `Worker`, or a fake in tests. */
export interface DecoderLike {
  postMessage(message: unknown, transfer: Transferable[]): void;
  onmessage: ((e: MessageEvent) => void) | null;
  terminate(): void;
}

/** What a decoder worker answers (see `qrworker.ts`). */
export interface DecodeAnswer {
  id: number;
  bytes: number[] | null;
  ms: number;
}

/** Spreads camera frames over a few decoder workers, one frame in flight per
 *  worker. Decoding is what limits a QR stream on a phone, so two workers on
 *  a multi-core phone roughly double the frames examined per second, and the
 *  page stays responsive. A frame offered while every worker is busy is
 *  skipped: the camera offers a newer one a few milliseconds later. */
export class DecodePool {
  private readonly busy: boolean[];
  private nextId = 1;
  decoded = 0;
  skipped = 0;
  totalMs = 0;

  constructor(
    private readonly workers: DecoderLike[],
    onCode: (bytes: number[]) => void,
  ) {
    this.busy = workers.map(() => false);
    workers.forEach((w, i) => {
      w.onmessage = (e: MessageEvent) => {
        this.busy[i] = false;
        const answer = e.data as DecodeAnswer;
        this.decoded++;
        this.totalMs += answer.ms;
        if (answer.bytes && answer.bytes.length) onCode(answer.bytes);
      };
    });
  }

  /** Whether a worker is free to take a frame. */
  get idle(): boolean {
    return this.busy.includes(false);
  }

  /** Offer a frame (its buffer is transferred, not copied). Returns whether a
   *  worker took it. */
  offer(width: number, height: number, data: Uint8ClampedArray): boolean {
    const i = this.busy.indexOf(false);
    if (i < 0) {
      this.skipped++;
      return false;
    }
    this.busy[i] = true;
    this.workers[i].postMessage({ id: this.nextId++, width, height, data }, [data.buffer]);
    return true;
  }

  /** Mean decode time so far, in milliseconds. */
  get meanMs(): number {
    return this.decoded ? this.totalMs / this.decoded : 0;
  }

  close(): void {
    this.workers.forEach((w) => w.terminate());
  }
}

/** How many decoder workers to run: two where there are cores to spare, one
 *  otherwise. */
export function decoderCount(cores: number | undefined): number {
  return (cores ?? 1) >= 4 ? 2 : 1;
}
