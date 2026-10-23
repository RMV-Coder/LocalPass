// SPDX-License-Identifier: MPL-2.0
// This file is part of the LocalPass desktop GUI. See ../../LICENSE.

import { describe, expect, it } from "vitest";
import {
  CodeCollector,
  DecodePool,
  FrameFeed,
  decoderCount,
  type DecoderLike,
  MAX_FPS,
  MIN_FPS,
  QUIET_ZONE,
  clampFps,
  estimateSeconds,
  formatDuration,
  moduleAt,
  pixelsPerModule,
  progressFraction,
  type QrMatrix,
} from "./qrstream";

function matrix(esi: number, width = 21, bits = "f".repeat(Math.ceil((21 * 21) / 4))): QrMatrix {
  return { esi, width, bits };
}

describe("moduleAt", () => {
  it("reads four modules per hex digit, most significant bit first", () => {
    const m: QrMatrix = { esi: 0, width: 2, bits: "a" }; // 1010
    expect([0, 1, 2, 3].map((i) => moduleAt(m, i))).toEqual([true, false, true, false]);
  });
  it("treats modules past the data as light", () => {
    expect(moduleAt({ esi: 0, width: 3, bits: "f" }, 8)).toBe(false);
  });
});

describe("pixelsPerModule", () => {
  it("fits the code and its quiet zone in whole pixels", () => {
    // Version 15: 77 modules + 8 quiet = 85; 850 px → 10 px each.
    expect(pixelsPerModule(77, 850)).toBe(10);
    expect(pixelsPerModule(77, 849)).toBe(9);
    expect((77 + 2 * QUIET_ZONE) * pixelsPerModule(77, 600)).toBeLessThanOrEqual(600);
  });
  it("never goes below one pixel", () => {
    expect(pixelsPerModule(177, 50)).toBe(1);
  });
});

describe("player pacing", () => {
  it("clamps the frame rate to the offered range", () => {
    expect(clampFps(0)).toBe(MIN_FPS);
    expect(clampFps(99)).toBe(MAX_FPS);
    expect(clampFps(7.6)).toBe(8);
  });
  it("estimates the time from frames needed, rate and catch rate", () => {
    expect(estimateSeconds(70, 10, 0.7)).toBe(10);
    expect(estimateSeconds(0, 10)).toBe(0);
    expect(estimateSeconds(10, 0)).toBe(0);
    expect(formatDuration(45)).toBe("45 s");
    expect(formatDuration(120)).toBe("2 min");
    expect(formatDuration(125)).toBe("2 min 5 s");
  });
  it("reports progress as a fraction capped at 1", () => {
    expect(progressFraction(0, 0)).toBe(0);
    expect(progressFraction(50, 100)).toBe(0.5);
    expect(progressFraction(130, 100)).toBe(1);
  });
});

describe("FrameFeed", () => {
  it("shows frames in ESI order, never repeating, fetching ahead in batches", async () => {
    const calls: Array<[number, number]> = [];
    const feed = new FrameFeed(
      async (start, count) => {
        calls.push([start, count]);
        return Array.from({ length: count }, (_, i) => matrix(start + i));
      },
      4,
      2,
    );
    await feed.refill();
    const seen: number[] = [];
    for (let i = 0; i < 10; i++) {
      const f = feed.next();
      if (f) seen.push(f.esi);
      await Promise.resolve();
      await Promise.resolve();
    }
    expect(seen).toEqual([...seen].sort((a, b) => a - b));
    expect(new Set(seen).size).toBe(seen.length);
    expect(seen[0]).toBe(0);
    expect(feed.shown).toBe(seen.length);
    // Batches are contiguous and do not overlap.
    calls.forEach(([start], i) => expect(start).toBe(i * 4));
  });

  it("keeps one fetch in flight at a time", async () => {
    let inflight = 0;
    let maxInflight = 0;
    let release: () => void = () => {};
    const feed = new FrameFeed(
      (start, count) => {
        inflight++;
        maxInflight = Math.max(maxInflight, inflight);
        return new Promise((resolve) => {
          release = () => {
            inflight--;
            resolve(Array.from({ length: count }, (_, i) => matrix(start + i)));
          };
        });
      },
      8,
      4,
    );
    const first = feed.refill();
    feed.refill();
    feed.refill();
    expect(maxInflight).toBe(1);
    release();
    await first;
    expect(feed.buffered).toBe(8);
  });

  it("returns null rather than blocking when the buffer is empty", () => {
    const feed = new FrameFeed(() => new Promise(() => {}));
    expect(feed.next()).toBeNull();
    expect(feed.shown).toBe(0);
  });
});

describe("CodeCollector", () => {
  it("drops a code seen again in a row, keeps it when it comes back later", () => {
    const c = new CodeCollector();
    expect(c.add([1, 2, 3])).toBe(true);
    expect(c.add([1, 2, 3])).toBe(false);
    expect(c.add([4, 5])).toBe(true);
    expect(c.add([1, 2, 3])).toBe(true);
    expect(c.drain()).toEqual([[1, 2, 3], [4, 5], [1, 2, 3]]);
    expect(c.repeats).toBe(1);
    expect(c.seen).toBe(4);
  });

  it("drains once and starts empty again", () => {
    const c = new CodeCollector();
    c.add(Uint8ClampedArray.from([9, 9]));
    expect(c.size).toBe(1);
    expect(c.drain()).toEqual([[9, 9]]);
    expect(c.drain()).toEqual([]);
  });

  it("bounds what it holds between drains, keeping the newest", () => {
    const c = new CodeCollector(3);
    for (let i = 0; i < 10; i++) c.add([i]);
    expect(c.drain()).toEqual([[7], [8], [9]]);
  });
});

/** A fake decoder worker: records what it was given; answers on demand. */
class FakeWorker implements DecoderLike {
  onmessage: ((e: MessageEvent) => void) | null = null;
  received: Array<{ id: number; width: number; transferred: number }> = [];
  terminated = false;
  postMessage(message: unknown, transfer: Transferable[]): void {
    const m = message as { id: number; width: number };
    this.received.push({ id: m.id, width: m.width, transferred: transfer.length });
  }
  answer(bytes: number[] | null, ms = 10): void {
    const id = this.received[this.received.length - 1]?.id ?? 0;
    this.onmessage?.({ data: { id, bytes, ms } } as MessageEvent);
  }
  terminate(): void {
    this.terminated = true;
  }
}

describe("DecodePool", () => {
  it("gives each worker one frame at a time and skips frames while all are busy", () => {
    const a = new FakeWorker();
    const b = new FakeWorker();
    const codes: number[][] = [];
    const pool = new DecodePool([a, b], (c) => codes.push(c));
    const frame = () => new Uint8ClampedArray(4);
    expect(pool.offer(1, 1, frame())).toBe(true);
    expect(pool.offer(1, 1, frame())).toBe(true);
    expect(pool.idle).toBe(false);
    expect(pool.offer(1, 1, frame())).toBe(false);
    expect(pool.skipped).toBe(1);
    expect(a.received).toHaveLength(1);
    expect(b.received).toHaveLength(1);
    // The pixel buffer is transferred, not copied.
    expect(a.received[0].transferred).toBe(1);

    a.answer([1, 2, 3], 40);
    expect(pool.idle).toBe(true);
    b.answer(null, 60);
    expect(codes).toEqual([[1, 2, 3]]);
    expect(pool.decoded).toBe(2);
    expect(pool.meanMs).toBe(50);
    // Ids are distinct across workers.
    expect(a.received[0].id).not.toBe(b.received[0].id);
  });

  it("ignores empty answers and terminates its workers on close", () => {
    const w = new FakeWorker();
    const codes: number[][] = [];
    const pool = new DecodePool([w], (c) => codes.push(c));
    pool.offer(1, 1, new Uint8ClampedArray(4));
    w.answer([]);
    expect(codes).toEqual([]);
    pool.close();
    expect(w.terminated).toBe(true);
  });

  it("runs two decoders where there are cores to spare", () => {
    expect(decoderCount(8)).toBe(2);
    expect(decoderCount(4)).toBe(2);
    expect(decoderCount(2)).toBe(1);
    expect(decoderCount(undefined)).toBe(1);
  });
});
