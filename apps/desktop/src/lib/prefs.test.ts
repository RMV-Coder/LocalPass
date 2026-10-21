// SPDX-License-Identifier: MPL-2.0
// This file is part of the LocalPass desktop GUI. See ../../LICENSE.

import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { vi } from "vitest";
import {
  applyTheme,
  getAutoUpdateCheck,
  getThemePref,
  savePendingNotes,
  setAutoUpdateCheck,
  setThemePref,
  takePendingNotes,
} from "./prefs";

/** A minimal in-memory localStorage. */
function memoryStorage() {
  const m = new Map<string, string>();
  return {
    getItem: (k: string) => (m.has(k) ? m.get(k)! : null),
    setItem: (k: string, v: string) => void m.set(k, String(v)),
    removeItem: (k: string) => void m.delete(k),
    dump: () => Object.fromEntries(m),
  };
}

let store: ReturnType<typeof memoryStorage>;
let root: { dataset: Record<string, string> };

beforeEach(() => {
  store = memoryStorage();
  root = { dataset: {} };
  vi.stubGlobal("localStorage", store);
  vi.stubGlobal("document", { documentElement: root });
});

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("theme", () => {
  it("defaults to following the system", () => {
    expect(getThemePref()).toBe("system");
  });

  it("stores and applies an override", () => {
    setThemePref("dark");
    expect(store.dump()).toEqual({ "lp.theme": "dark" });
    expect(root.dataset.theme).toBe("dark");
    expect(getThemePref()).toBe("dark");
  });

  it("'system' removes the override and the attribute", () => {
    setThemePref("light");
    setThemePref("system");
    expect(store.dump()).toEqual({});
    expect(root.dataset.theme).toBeUndefined();
  });

  it("ignores a corrupted value", () => {
    store.setItem("lp.theme", "neon");
    expect(getThemePref()).toBe("system");
  });

  it("applyTheme without an argument applies the saved preference", () => {
    store.setItem("lp.theme", "light");
    applyTheme();
    expect(root.dataset.theme).toBe("light");
  });

  it("works with the defaults when storage throws (private mode)", () => {
    vi.stubGlobal("localStorage", {
      getItem: () => {
        throw new Error("denied");
      },
      setItem: () => {
        throw new Error("denied");
      },
      removeItem: () => {
        throw new Error("denied");
      },
    });
    expect(getThemePref()).toBe("system");
    expect(() => setThemePref("dark")).not.toThrow();
    expect(root.dataset.theme).toBe("dark");
    expect(getAutoUpdateCheck()).toBe(false);
  });
});

describe("auto update check", () => {
  it("is off by default and can be turned on and off", () => {
    expect(getAutoUpdateCheck()).toBe(false);
    setAutoUpdateCheck(true);
    expect(getAutoUpdateCheck()).toBe(true);
    setAutoUpdateCheck(false);
    expect(getAutoUpdateCheck()).toBe(false);
    expect(store.dump()).toEqual({});
  });
});

describe("pending release notes", () => {
  it("round-trips once, then is gone", () => {
    savePendingNotes("0.2.0", "* new shell");
    expect(takePendingNotes()).toEqual({ version: "0.2.0", notes: "* new shell" });
    expect(takePendingNotes()).toBeNull();
  });

  it("drops malformed or mistyped data", () => {
    store.setItem("lp.pendingNotes", "{not json");
    expect(takePendingNotes()).toBeNull();
    store.setItem("lp.pendingNotes", JSON.stringify({ version: 2, notes: [] }));
    expect(takePendingNotes()).toBeNull();
    expect(store.dump()).toEqual({});
  });
});
