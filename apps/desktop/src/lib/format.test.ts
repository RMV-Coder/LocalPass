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
  humanizeKey,
  fieldLabel,
  formatShortDate,
  isoTimestamp,
} from "./format";

describe("typeLabel", () => {
  it("maps known types to friendly labels", () => {
    expect(typeLabel("login")).toBe("Login");
    expect(typeLabel("api_key")).toBe("API key");
    expect(typeLabel("ssh_key")).toBe("SSH key");
    expect(typeLabel("totp")).toBe("TOTP");
  });
  it("maps the backend's note type", () => {
    expect(typeLabel("note")).toBe("Secure note");
    expect(typeLabel("env_set")).toBe("Env set");
  });
  it("humanizes unknown types instead of showing the raw key", () => {
    expect(typeLabel("mystery")).toBe("Mystery");
    expect(typeLabel("secure_note")).toBe("Secure note");
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

describe("humanizeKey", () => {
  it("converts snake/kebab case to sentence case", () => {
    expect(humanizeKey("credit_card")).toBe("Credit card");
    expect(humanizeKey("wifi-network")).toBe("Wifi network");
  });
  it("returns the input unchanged when there is nothing to show", () => {
    expect(humanizeKey("")).toBe("");
    expect(humanizeKey("__")).toBe("__");
  });
});

describe("fieldLabel", () => {
  it("relabels built-in field names", () => {
    expect(fieldLabel("username", "login")).toBe("Username");
    expect(fieldLabel("url", "login")).toBe("URL");
    expect(fieldLabel("private_pem", "ssh_key")).toBe("Private key");
    expect(fieldLabel("secret", "api_key")).toBe("Secret");
  });
  it("never rewrites env-set variable names", () => {
    expect(fieldLabel("url", "env_set")).toBe("url");
    expect(fieldLabel("DATABASE_URL", "env_set")).toBe("DATABASE_URL");
  });
  it("leaves custom field names exactly as typed", () => {
    expect(fieldLabel("Recovery PIN", "login")).toBe("Recovery PIN");
    expect(fieldLabel("toString", "login")).toBe("toString");
  });
});

describe("formatShortDate", () => {
  const now = new Date(2026, 8, 26, 15, 0).getTime(); // Sep 26, 2026 15:00 local

  it("returns an em dash for zero/invalid", () => {
    expect(formatShortDate(0, now)).toBe("—");
    expect(formatShortDate(Number.NaN, now)).toBe("—");
  });
  it("shows only the time for today", () => {
    const s = formatShortDate(new Date(2026, 8, 26, 8, 41).getTime(), now);
    expect(s).toMatch(/41/);
    expect(s).not.toMatch(/2026/);
    expect(s).not.toMatch(/Sep/);
  });
  it("shows month and day (no year) within the current year", () => {
    const s = formatShortDate(new Date(2026, 5, 28, 9, 0).getTime(), now);
    expect(s).toMatch(/28/);
    expect(s).not.toMatch(/2026/);
    expect(s).not.toMatch(/:/);
  });
  it("includes the year for older dates", () => {
    const s = formatShortDate(new Date(2025, 11, 31, 9, 0).getTime(), now);
    expect(s).toMatch(/2025/);
  });
});

describe("isoTimestamp", () => {
  it("produces an ISO string or empty", () => {
    expect(isoTimestamp(0)).toBe("");
    expect(isoTimestamp(Number.NaN)).toBe("");
    expect(isoTimestamp(1_700_000_000_000)).toBe("2023-11-14T22:13:20.000Z");
  });
});
