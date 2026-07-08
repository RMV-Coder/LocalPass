// SPDX-License-Identifier: MPL-2.0
// This file is part of the LocalPass desktop GUI. See ../../LICENSE.

// The view-model shapes the Rust commands return. These mirror the Rust
// `model.rs` types exactly (serde snake_case tags / field names).

export type SessionState =
  | { state: "unlocked"; vault_count: number; profile: string; idle_remaining_secs: number | null }
  | { state: "locked"; profile: string }
  | { state: "no_daemon" }
  | { state: "no_account"; profile: string }
  | { state: "wrong_profile"; expected: string }
  | { state: "error"; message: string };

/** The result of a successful account creation — the Secret Key crosses to the
 *  webview here ONCE for the Emergency Kit (component-local, cleared on nav). */
export interface CreatedAccount {
  secret_key: string;
  profile: string;
  vault_count: number;
}

/** One custom field the item form supplies. */
export interface CustomFieldInput {
  name: string;
  value: string;
  secret: boolean;
}

/** One env-set entry the item form supplies. */
export interface EnvEntryInput {
  key: string;
  value: string;
}

/** The typed item-form payload sent to `create_item` / `update_item`. Secret
 *  string fields are optional: an edit leaving one undefined preserves the
 *  current (unrevealed) value server-side. */
export interface NewItemInput {
  type_str: string;
  title: string;
  notes?: string;
  tags?: string[];
  favorite?: boolean;
  username?: string | null;
  password?: string | null;
  url?: string | null;
  api_key?: string | null;
  env_entries?: EnvEntryInput[];
  ssh_algo?: string | null;
  ssh_private_pem?: string | null;
  ssh_public_openssh?: string | null;
  ssh_fingerprint?: string | null;
  totp_secret_b32?: string | null;
  totp_algo?: string | null;
  totp_digits?: number | null;
  totp_period?: number | null;
  totp_issuer?: string | null;
  totp_account?: string | null;
  custom_fields?: CustomFieldInput[];
}

export interface VaultView {
  id: string;
  name: string;
}

export interface ItemSummaryView {
  id: string;
  title: string;
  type_str: string;
  updated_at: number;
  tags: string[];
}

export interface FieldView {
  name: string;
  /** Empty string for a secret field in the masked view. */
  value: string;
  secret: boolean;
}

export interface ItemView {
  id: string;
  title: string;
  type_str: string;
  version: number;
  created_at: number;
  updated_at: number;
  tags: string[];
  favorite: boolean;
  notes: string;
  fields: FieldView[];
}

export interface TotpView {
  code: string;
  seconds_remaining: number;
  period: number;
  digits: number;
  algo: string;
}

export interface GeneratedView {
  secret: string;
  entropy_bits: number;
}

/** This device's public identity for the Devices screen. Everything here is
 *  PUBLIC (public keys + a hash) — safe to display and copy, never a secret. */
export interface DeviceIdentityView {
  device_id: string;
  identity_string: string;
  fingerprint: string;
}

/** A trusted peer device row. All fields public. */
export interface PeerView {
  device_id: string;
  fingerprint: string;
  label: string | null;
  verified_at: number;
}

export interface SyncPushView {
  published: number;
  segments_written: number;
}

/** The outcome of a pull. `alarms` are secret-free strings surfaced prominently
 *  by the UI — quarantine/tamper events are never swallowed. */
export interface SyncPullView {
  applied: number;
  pending: number;
  key_imported: boolean;
  alarms: string[];
}

export interface SyncDeviceView {
  device_id: string;
  is_self: boolean;
  trusted: boolean;
  local_seq: number;
  channel_seq: number;
}

export interface SyncStatusView {
  enrolled: boolean;
  root: string | null;
  devices: SyncDeviceView[];
  pending: number;
  alarms: string[];
}

export interface AdoptedVaultView {
  vault_id: string;
  name: string;
}

export interface SyncAdoptView {
  adopted: AdoptedVaultView[];
  applied_total: number;
  alarms: string[];
}
