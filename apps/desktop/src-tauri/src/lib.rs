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
pub mod dotenv;
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
        // Native file/save pickers for attachments (choosing a source file to
        // attach and a destination to save a download). The plugin hands the
        // backend only PATHS; the attachment plaintext never enters the webview.
        .plugin(tauri_plugin_dialog::init())
        .setup(|app| {
            // On mobile there is no daemon — the app process *is* the vault (see
            // `daemon.rs`). Point the in-process backend at the Android
            // app-private data dir by setting `LOCALPASS_PROFILE`, so
            // `daemon::resolve_profile` (used by both the in-process state and
            // `account_exists`) resolves there. Desktop uses `ProjectDirs`.
            #[cfg(mobile)]
            {
                use tauri::Manager;
                if let Ok(dir) = app.path().app_data_dir() {
                    std::fs::create_dir_all(&dir).ok();
                    // SAFETY: single-threaded app setup, before any command runs.
                    unsafe { std::env::set_var("LOCALPASS_PROFILE", &dir) };
                }
            }
            #[cfg(not(mobile))]
            let _ = app;
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            commands::ensure_service,
            commands::status,
            commands::create_account,
            commands::unlock,
            commands::lock,
            commands::list_vaults,
            commands::create_vault,
            commands::delete_vault,
            commands::list_items,
            commands::password_health,
            commands::get_item,
            commands::reveal_field,
            commands::search,
            commands::totp,
            commands::generate_password,
            commands::generate_passphrase,
            commands::parse_dotenv,
            commands::create_item,
            commands::update_item,
            commands::delete_item,
            commands::preview_fingerprint,
            commands::export_identity,
            commands::list_peers,
            commands::trust_device,
            commands::sync_setup,
            commands::sync_push,
            commands::sync_pull,
            commands::sync_status,
            commands::share_vault_to_device,
            commands::sync_adopt,
            commands::add_attachment,
            commands::list_attachments,
            commands::get_attachment,
            commands::delete_attachment,
        ])
        .run(tauri::generate_context!())
        .expect("error while running the LocalPass desktop application");
}
