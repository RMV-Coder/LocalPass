// SPDX-License-Identifier: MPL-2.0
// This file is part of the LocalPass desktop GUI. See ../../LICENSE.

import { describe, it, expect } from "vitest";
import {
  typeLabel,
  formatTimestamp,
  formatEntropy,
  strengthBand,
  groupTotp,
  humanSize,
  MASK,
} from "./format";

describe("typeLabel", () => {
  it("maps known types to friendly labels", () => {
    expect(typeLabel("login")).toBe("Login");
    expect(typeLabel("api_key")).toBe("API key");
    expect(typeLabel("ssh_key")).toBe("SSH key");
    expect(typeLabel("totp")).toBe("TOTP");
  });
  it("passes unknown types through unchanged", () => {
    expect(typeLabel("mystery")).toBe("mystery");
  });
});

describe("formatTimestamp", () => {
  it("returns an em dash for zero/missing", () => {
    expect(formatTimestamp(0)).toBe("—");
  });
  it("formats a real timestamp to a non-empty string", () => {
    const s = formatTimestamp(1_700_000_000_000);
    expect(s).not.toBe("—");
    expect(s.length).toBeGreaterThan(0);
  });
});

describe("formatEntropy", () => {
  it("renders one decimal with a bits suffix", () => {
    expect(formatEntropy(128)).toBe("128.0 bits");
    expect(formatEntropy(75.16)).toBe("75.2 bits");
  });
});

describe("strengthBand", () => {
  it("bands entropy per thresholds", () => {
    expect(strengthBand(40)).toBe("weak");
    expect(strengthBand(60)).toBe("fair");
    expect(strengthBand(80)).toBe("strong");
    expect(strengthBand(128)).toBe("excellent");
    expect(strengthBand(256)).toBe("excellent");
  });
});

describe("groupTotp", () => {
  it("groups 6 digits as 3+3", () => {
    expect(groupTotp("123456")).toBe("123 456");
  });
  it("groups 8 digits as 4+4", () => {
    expect(groupTotp("12345678")).toBe("1234 5678");
  });
  it("leaves other lengths unchanged", () => {
    expect(groupTotp("1234567")).toBe("1234567");
  });
});

describe("MASK", () => {
  it("is a non-empty fixed placeholder with no real characters", () => {
    expect(MASK.length).toBeGreaterThan(0);
    expect(/[a-zA-Z0-9]/.test(MASK)).toBe(false);
  });
});

describe("humanSize", () => {
  it("renders bytes under 1 KiB as B", () => {
    expect(humanSize(0)).toBe("0 B");
    expect(humanSize(512)).toBe("512 B");
    expect(humanSize(1023)).toBe("1023 B");
  });
  it("renders KiB with one decimal", () => {
    expect(humanSize(1024)).toBe("1.0 KiB");
    expect(humanSize(1536)).toBe("1.5 KiB");
  });
  it("renders MiB with one decimal", () => {
    expect(humanSize(1024 * 1024)).toBe("1.0 MiB");
    expect(humanSize(5 * 1024 * 1024)).toBe("5.0 MiB");
  });
  it("renders invalid/negative sizes as em-dash", () => {
    expect(humanSize(-1)).toBe("—");
    expect(humanSize(Number.NaN)).toBe("—");
  });
});
