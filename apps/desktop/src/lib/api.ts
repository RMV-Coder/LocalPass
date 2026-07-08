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
  AttachmentSavedView,
  AttachmentView,
  CreatedAccount,
  DeviceIdentityView,
  EnvEntryView,
  GeneratedView,
  ItemSummaryView,
  ItemView,
  NewItemInput,
  PeerView,
  SessionState,
  SyncAdoptView,
  SyncPullView,
  SyncPushView,
  SyncStatusView,
  TotpView,
  VaultView,
} from "./types";

/** Start the LocalPass background service if it isn't running, then report the
 *  session state. The UI calls this on launch so a first-run user never has to
 *  start a daemon by hand. Never rejects for the "no daemon" case. */
export function ensureService(): Promise<SessionState> {
  return invoke<SessionState>("ensure_service");
}

/** Current lock/availability state. Never rejects for the "no daemon" case —
 *  that is a normal state returned in the payload. */
export function status(): Promise<SessionState> {
  return invoke<SessionState>("status");
}

/** Create a brand-new account (onboarding). The password + confirm are passed
 *  straight through and not retained in JS beyond this call's arguments. On
 *  success returns the Secret Key ONCE (for the Emergency Kit) — the caller holds
 *  it in component-local state and clears it on navigation, never a store. */
export function createAccount(password: string, confirm: string): Promise<CreatedAccount> {
  return invoke<CreatedAccount>("create_account", { password, confirm });
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

/** Create a new vault by name; resolves to the new vault id. */
export function createVault(name: string): Promise<string> {
  return invoke<string>("create_vault", { name });
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

/** Parse pasted raw `.env` text into ordered KEY=value entries (computed in
 *  Rust, mirroring the canonical dotenv rules). Not a secret with respect to the
 *  daemon: the text is no more sensitive than the entries it becomes and never
 *  leaves the app. */
export function parseDotenv(text: string): Promise<EnvEntryView[]> {
  return invoke<EnvEntryView[]>("parse_dotenv", { text });
}

/** Create a new item in a vault. Returns the new item's id. Secret values in
 *  `input` flow straight to the daemon; the response carries only the id. */
export function createItem(vault: string, input: NewItemInput): Promise<string> {
  return invoke<string>("create_item", { vault, input });
}

/** Update an existing item. Unrevealed secret fields left undefined in `input`
 *  are preserved server-side. Resolves with no value on success. */
export function updateItem(vault: string, id: string, input: NewItemInput): Promise<void> {
  return invoke<void>("update_item", { vault, id, input });
}

/** Move an item to the trash (30-day retention). */
export function deleteItem(vault: string, id: string): Promise<void> {
  return invoke<void>("delete_item", { vault, id });
}

// --- Devices & Sync ------------------------------------------------------
//
// Every call here is SECRET-FREE. Device identity strings + fingerprints are
// public (public keys + a hash). The vault-key share is sealed inside the
// daemon/engine; `shareVaultToDevice` only names a device id. Sync alarms
// (quarantine/tamper) come back as strings for the UI to surface prominently.

/** Parse a pasted LPDEV1 identity string and return its fingerprint, for the
 *  user to compare out-of-band before trusting. Display-only and PUBLIC — the
 *  daemon re-checks the fingerprint when trusting, so this cannot widen trust.
 *  Rejects for a malformed string. */
export function previewFingerprint(identityString: string): Promise<string> {
  return invoke<string>("preview_fingerprint", { identityString });
}

/** This device's public identity (id, LPDEV1 string, fingerprint) to hand to
 *  another device. Nothing here is a secret. */
export function exportIdentity(): Promise<DeviceIdentityView> {
  return invoke<DeviceIdentityView>("export_identity");
}

/** The trusted peer devices (label / fingerprint / when). All public. */
export function listPeers(): Promise<PeerView[]> {
  return invoke<PeerView[]>("list_peers");
}

/** Trust a peer from its identity string, AFTER the user confirmed its
 *  fingerprint out-of-band. `expectedFingerprint` is the confirmed value; the
 *  daemon re-checks it against the identity string and refuses on a mismatch or
 *  an empty confirmation. There is no auto-trust. */
export function trustDevice(
  identityString: string,
  expectedFingerprint: string,
  label: string | null,
): Promise<PeerView> {
  return invoke<PeerView>("trust_device", {
    identityString,
    expectedFingerprint,
    label,
  });
}

/** Enroll a vault for file-based sync under the shared folder `dir`. */
export function syncSetup(vault: string, dir: string): Promise<void> {
  return invoke<void>("sync_setup", { vault, dir });
}

/** Publish this device's ops for a vault to the shared folder. */
export function syncPush(vault: string): Promise<SyncPushView> {
  return invoke<SyncPushView>("sync_push", { vault });
}

/** Verify + merge peers' ops for a vault. Any alarms are returned for the UI. */
export function syncPull(vault: string): Promise<SyncPullView> {
  return invoke<SyncPullView>("sync_pull", { vault });
}

/** Per-device sync status for a vault (seq marks + pending/quarantine). */
export function syncStatus(vault: string): Promise<SyncStatusView> {
  return invoke<SyncStatusView>("sync_status", { vault });
}

/** Seal a vault's key to a trusted peer device (sealed inside the daemon). */
export function shareVaultToDevice(vault: string, deviceId: string): Promise<void> {
  return invoke<void>("share_vault_to_device", { vault, deviceId });
}

/** Adopt vaults shared to this device from a folder, then pull each. */
export function syncAdopt(dir: string): Promise<SyncAdoptView> {
  return invoke<SyncAdoptView>("sync_adopt", { dir });
}

// --- Attachments ---------------------------------------------------------
//
// PATH-BASED, no blob bytes cross the command boundary. `addAttachment` passes
// a SOURCE file path the daemon reads itself; `getAttachment` passes a DEST file
// path the daemon writes itself. The attachment plaintext therefore NEVER enters
// the webview — a STRONGER boundary than `revealField` (whose value does reach
// JS). Only paths + metadata (id / filename / size) cross these calls.

/** Attach a file to an item. `sourcePath` is the file the user picked in the
 *  native open dialog; the daemon reads it and stores it encrypted. Pass `null`
 *  for `filename` to derive it from the source's base name. Returns the new
 *  attachment (no blob bytes; `size` is filled by a follow-up `listAttachments`). */
export function addAttachment(
  vault: string,
  item: string,
  sourcePath: string,
  filename: string | null = null,
): Promise<AttachmentView> {
  return invoke<AttachmentView>("add_attachment", {
    vault,
    item,
    sourcePath,
    filename,
  });
}

/** List an item's attachments (id / filename / size each). No blob bytes. */
export function listAttachments(vault: string, item: string): Promise<AttachmentView[]> {
  return invoke<AttachmentView[]>("list_attachments", { vault, item });
}

/** Save (decrypt to disk) one attachment. `destPath` is the destination the user
 *  picked in the native save dialog; the daemon writes the plaintext there
 *  itself — the bytes never enter the webview. Rejects (with a message) if the
 *  file exists and `force` is false; the caller re-calls with `force = true`
 *  after confirming an overwrite. */
export function getAttachment(
  vault: string,
  item: string,
  id: string,
  destPath: string,
  force: boolean,
): Promise<AttachmentSavedView> {
  return invoke<AttachmentSavedView>("get_attachment", {
    vault,
    item,
    id,
    destPath,
    force,
  });
}

/** Remove one attachment by id. */
export function deleteAttachment(vault: string, item: string, id: string): Promise<void> {
  return invoke<void>("delete_attachment", { vault, item, id });
}
