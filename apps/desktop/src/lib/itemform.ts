// SPDX-License-Identifier: MPL-2.0
// This file is part of the LocalPass desktop GUI. See ../../LICENSE.

// Pure helpers that seed the add/edit item form from an existing item's
// (masked) field list. Kept out of the component so they are unit-testable.

import type { CustomFieldInput, FieldView } from "./types";

/**
 * The item's user-defined custom fields as editable form rows.
 *
 * Secret custom fields arrive masked (empty value) and are seeded blank: on
 * save a blank secret row PRESERVES the stored value server-side (matched by
 * name), so the user can keep, replace, or remove each one.
 */
export function seedCustomFields(fields: FieldView[]): CustomFieldInput[] {
  return fields
    .filter((f) => f.custom)
    .map((f) => ({ name: f.name, value: f.secret ? "" : f.value, secret: f.secret }));
}

/**
 * The value of a non-secret field the item TYPE defines (e.g. a login's
 * `username`), ignoring custom fields that happen to share the name.
 */
export function typeFieldValue(fields: FieldView[] | undefined, name: string): string {
  return fields?.find((f) => f.name === name && !f.secret && !f.custom)?.value ?? "";
}

/**
 * An env-set's variable names: its type-defined fields only, so the item's
 * custom fields are not mistaken for (and saved back as) env variables.
 */
export function envKeys(fields: FieldView[]): string[] {
  return fields.filter((f) => !f.custom).map((f) => f.name);
}
