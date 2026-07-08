// SPDX-License-Identifier: MPL-2.0
// This file is part of the LocalPass desktop GUI. See apps/desktop/LICENSE.

//! # LocalPass desktop GUI backend (`localpass-desktop`)
//!
//! A Tauri 2 backend that is a **thin daemon client** (PRD §6.5, §7.1). The
//! webview renders and requests; **all secret handling stays here in Rust**. The
//! complete bridge is the small set of `#[tauri::command]` functions in
//! [`commands`], which return the masked view models in [`model`]. Secret values
//! reach the webview only through [`commands::reveal_field`] / [`commands::totp`]
//! (explicit gesture) and the generator; they are never persisted in JS stores.
//!
//! This crate lives in its **own workspace** (see `Cargo.toml`'s empty
//! `[workspace]`) so the AGPL core's `cargo test/clippy --workspace` never build
//! the MPL GUI (PRD §5.6). It reaches the core only via the `lp-daemon` path
//! dependency — as a client, exactly like the CLI and the native-messaging host.

pub mod commands;
pub mod daemon;
pub mod generate;
pub mod item_input;
pub mod model;
mod wordlist;

/// Build and run the Tauri application.
///
/// Registers the command handlers and starts the event loop. The
/// `mobile_entry_point` attribute lets the same entry serve a future mobile
/// target; on desktop it is a no-op wrapper.
#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .invoke_handler(tauri::generate_handler![
            commands::ensure_service,
            commands::status,
            commands::create_account,
            commands::unlock,
            commands::lock,
            commands::list_vaults,
            commands::create_vault,
            commands::list_items,
            commands::get_item,
            commands::reveal_field,
            commands::search,
            commands::totp,
            commands::generate_password,
            commands::generate_passphrase,
            commands::create_item,
            commands::update_item,
            commands::delete_item,
        ])
        .run(tauri::generate_context!())
        .expect("error while running the LocalPass desktop application");
}
