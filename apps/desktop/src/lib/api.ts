// SPDX-License-Identifier: MPL-2.0
// This file is part of the LocalPass desktop GUI. See ../../LICENSE.

// Typed wrappers over the Tauri command bridge. This is the ONLY place the
// webview reaches the Rust backend; every function name matches a
// `#[tauri::command]` in src-tauri/src/commands.rs.
//
// SECRET BOUNDARY (mirrors the Rust side): `status`, `listVaults`, `listItems`,
// `getItem`, and `search` never carry a secret value. `revealField`, `totp`, and
// the generators are the only calls that return a secret — always driven by an
// explicit user gesture in the UI, and the returned value is held only in a
// component-local variable, never a store, and cleared on navigation.

import { invoke } from "@tauri-apps/api/core";
import type {
  GeneratedView,
  ItemSummaryView,
  ItemView,
  SessionState,
  TotpView,
  VaultView,
} from "./types";

/** Current lock/availability state. Never rejects for the "no daemon" case —
 *  that is a normal state returned in the payload. */
export function status(): Promise<SessionState> {
  return invoke<SessionState>("status");
}

/** Unlock with the master password. The password is passed straight through and
 *  is not retained anywhere in JS beyond this call's argument. */
export function unlock(password: string): Promise<SessionState> {
  return invoke<SessionState>("unlock", { password });
}

/** Lock now. */
export function lock(): Promise<SessionState> {
  return invoke<SessionState>("lock");
}

/** Vaults for the sidebar. */
export function listVaults(): Promise<VaultView[]> {
  return invoke<VaultView[]>("list_vaults");
}

/** Items in a vault (masked; no secret values). */
export function listItems(vault: string): Promise<ItemSummaryView[]> {
  return invoke<ItemSummaryView[]>("list_items", { vault });
}

/** One item, masked (secret field values omitted). */
export function getItem(vault: string, id: string): Promise<ItemView> {
  return invoke<ItemView>("get_item", { vault, id });
}

/** Reveal exactly ONE secret field's value (explicit gesture only). */
export function revealField(vault: string, id: string, field: string): Promise<string> {
  return invoke<string>("reveal_field", { vault, id, field });
}

/** Search within a vault (masked; no secret values). */
export function search(vault: string, query: string): Promise<ItemSummaryView[]> {
  return invoke<ItemSummaryView[]>("search", { vault, query });
}

/** Live TOTP code for a totp item (the secret stays in the daemon). */
export function totp(vault: string, id: string): Promise<TotpView> {
  return invoke<TotpView>("totp", { vault, id });
}

/** Generate a random-character password (computed in Rust). */
export function generatePassword(length: number, symbols: boolean): Promise<GeneratedView> {
  return invoke<GeneratedView>("generate_password", { length, symbols });
}

/** Generate an EFF-wordlist passphrase (computed in Rust). */
export function generatePassphrase(words: number, separator: string): Promise<GeneratedView> {
  return invoke<GeneratedView>("generate_passphrase", { words, separator });
}
