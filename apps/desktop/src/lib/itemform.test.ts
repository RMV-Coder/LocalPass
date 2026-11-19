// SPDX-License-Identifier: MPL-2.0
// This file is part of the LocalPass desktop GUI. See ../../LICENSE.

import { describe, it, expect } from "vitest";
import { seedCustomFields, typeFieldValue, envKeys } from "./itemform";
import type { FieldView } from "./types";

const f = (name: string, value: string, secret = false, custom = false): FieldView => ({
  name,
  value,
  secret,
  custom,
});

describe("seedCustomFields", () => {
  it("seeds only custom fields, in order", () => {
    const fields = [
      f("username", "alice"),
      f("password", "", true),
      f("Recovery email", "a@example.com", false, true),
      f("PIN", "", true, true),
    ];
    expect(seedCustomFields(fields)).toEqual([
      { name: "Recovery email", value: "a@example.com", secret: false },
      { name: "PIN", value: "", secret: true },
    ]);
  });

  it("never carries a secret value into the form", () => {
    expect(seedCustomFields([f("PIN", "leaked", true, true)])).toEqual([
      { name: "PIN", value: "", secret: true },
    ]);
  });

  it("returns no rows for an item without custom fields", () => {
    expect(seedCustomFields([f("username", "alice")])).toEqual([]);
  });
});

describe("typeFieldValue", () => {
  it("ignores a custom field sharing a built-in name", () => {
    const fields = [f("algo", "my note", false, true), f("algo", "ed25519")];
    expect(typeFieldValue(fields, "algo")).toBe("ed25519");
  });
  it("ignores secret fields and handles a missing item", () => {
    expect(typeFieldValue([f("password", "x", true)], "password")).toBe("");
    expect(typeFieldValue(undefined, "username")).toBe("");
  });
});

describe("envKeys", () => {
  it("excludes custom fields from the env variable names", () => {
    const fields = [f("API_URL", "u"), f("TOKEN", "", true), f("Owner", "ops", false, true)];
    expect(envKeys(fields)).toEqual(["API_URL", "TOKEN"]);
  });
});
