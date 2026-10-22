// SPDX-License-Identifier: MPL-2.0
// This file is part of the LocalPass desktop GUI. See ../../LICENSE.

// A jsQR decoder off the main thread (qr-transport.md §12: decoding is the
// bottleneck of a QR stream, ~90–200 ms a frame on a phone). The page posts a
// RGBA frame; the worker answers with the raw bytes of the code it
// found, or null. It interprets nothing — the Rust backend checks every frame.

import jsQR from "jsqr";

export interface DecodeRequest {
  id: number;
  width: number;
  height: number;
  data: Uint8ClampedArray;
}

export interface DecodeResult {
  id: number;
  bytes: number[] | null;
  ms: number;
}

self.onmessage = (e: MessageEvent<DecodeRequest>) => {
  const { id, width, height, data } = e.data;
  const t0 = performance.now();
  const code = jsQR(data, width, height, { inversionAttempts: "dontInvert" });
  const out: DecodeResult = {
    id,
    bytes: code && code.binaryData.length ? Array.from(code.binaryData) : null,
    ms: performance.now() - t0,
  };
  (self as unknown as Worker).postMessage(out);
};
