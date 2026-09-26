// SPDX-License-Identifier: MPL-2.0
// This file is part of the LocalPass desktop GUI. See ../../LICENSE.

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const copySecretNative = vi.fn<(text: string) => Promise<void>>();
vi.mock("./api", () => ({ copySecretNative: (text: string) => copySecretNative(text) }));

import { copySecret, copyToClipboard } from "./clipboard";

const writeText = vi.fn<(text: string) => Promise<void>>();

beforeEach(() => {
  copySecretNative.mockReset();
  writeText.mockReset();
  writeText.mockResolvedValue(undefined);
  vi.stubGlobal("navigator", { clipboard: { writeText } });
});

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("copySecret", () => {
  it("uses the native command (history-excluded, auto-cleared) when it is available", async () => {
    copySecretNative.mockResolvedValue(undefined);
    await expect(copySecret("hunter2-password")).resolves.toBe(true);
    expect(copySecretNative).toHaveBeenCalledWith("hunter2-password");
    expect(writeText).not.toHaveBeenCalled();
  });

  it("falls back to the webview clipboard where there is no native one (mobile)", async () => {
    copySecretNative.mockRejectedValue("native clipboard unavailable on this platform");
    await expect(copySecret("482913")).resolves.toBe(true);
    expect(writeText).toHaveBeenCalledWith("482913");
  });

  it("reports failure when both paths fail", async () => {
    copySecretNative.mockRejectedValue("no native clipboard");
    writeText.mockRejectedValue(new Error("denied"));
    vi.stubGlobal("document", undefined);
    await expect(copySecret("x-secret")).resolves.toBe(false);
  });
});

describe("copyToClipboard (non-secret copies)", () => {
  it("never touches the native secret command", async () => {
    await expect(copyToClipboard("localpass run --env-set app -- npm run dev")).resolves.toBe(true);
    expect(writeText).toHaveBeenCalledTimes(1);
    expect(copySecretNative).not.toHaveBeenCalled();
  });
});
