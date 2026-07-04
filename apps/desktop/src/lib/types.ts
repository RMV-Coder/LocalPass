// SPDX-License-Identifier: MPL-2.0
// This file is part of the LocalPass desktop GUI. See ../../LICENSE.

// The view-model shapes the Rust commands return. These mirror the Rust
// `model.rs` types exactly (serde snake_case tags / field names).

export type SessionState =
  | { state: "unlocked"; vault_count: number; profile: string; idle_remaining_secs: number | null }
  | { state: "locked"; profile: string }
  | { state: "no_daemon" }
  | { state: "wrong_profile"; expected: string }
  | { state: "error"; message: string };

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
