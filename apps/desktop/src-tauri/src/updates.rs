// SPDX-License-Identifier: MPL-2.0
// This file is part of the LocalPass desktop GUI. See apps/desktop/LICENSE.

//! # In-app updates (desktop)
//!
//! A thin layer over the official `tauri-plugin-updater`:
//!
//! 1. [`update_check`] fetches the signed feed (`latest.json` on the newest
//!    GitHub release; see `.github/workflows/desktop-release.yml`) and reports
//!    whether it names a newer version, with its release notes. This is the
//!    app's only outbound request, and it runs only when the user asks or has
//!    opted in to a check at unlock.
//! 2. [`update_install`] downloads the installer, **verifies its minisign
//!    signature** against the public key compiled into `tauri.conf.json`
//!    (PRD §8 T10), and runs it. Just before the installer takes over, the
//!    `on_before_exit` hook locks the vault and stops the background service,
//!    because the installer has to replace that service's executable (Windows
//!    refuses to overwrite a running .exe). The installer relaunches the app,
//!    and the new app starts the new service on its own (`ensure_service`).
//!
//! Nothing here touches a secret. The release notes are untrusted text that the
//! webview renders as plain text only. See `docs/updates.md`.

use crate::model::UpdateInfoView;

/// The update found by the last check, held until the user installs it.
#[cfg(not(any(target_os = "android", target_os = "ios")))]
#[derive(Default)]
pub struct PendingUpdate(pub std::sync::Mutex<Option<tauri_plugin_updater::Update>>);

/// Mobile has no in-app updater; the state exists so registration is uniform.
#[cfg(any(target_os = "android", target_os = "ios"))]
#[derive(Default)]
pub struct PendingUpdate;

/// Lock the vault, clear any copied secret, and stop the background service so
/// its files can be replaced. Best-effort: a service that is already gone is
/// exactly what we want.
#[cfg(not(any(target_os = "android", target_os = "ios")))]
pub fn stop_service_for_update() {
    use lp_daemon::protocol::Request;
    crate::clipboard::clear_on_lock();
    lp_daemon::presence::clear_grant();
    let _ = crate::daemon::call(&Request::Lock);
    let _ = crate::daemon::call(&Request::Shutdown);
}

/// Ask the feed whether a newer signed release exists; remember it for
/// [`update_install`].
#[cfg(not(any(target_os = "android", target_os = "ios")))]
#[tauri::command]
pub async fn update_check(
    app: tauri::AppHandle,
    pending: tauri::State<'_, PendingUpdate>,
) -> Result<Option<UpdateInfoView>, String> {
    use tauri_plugin_updater::UpdaterExt;
    let updater = app
        .updater_builder()
        .on_before_exit(stop_service_for_update)
        .build()
        .map_err(|e| format!("Updates are not available in this build: {e}"))?;
    let found = updater
        .check()
        .await
        .map_err(|e| format!("Could not check for updates: {e}"))?;
    let info = found.as_ref().map(|u| UpdateInfoView {
        version: u.version.clone(),
        current_version: u.current_version.clone(),
        notes: u.body.clone().unwrap_or_default(),
        date_ms: u.date.map(|d| d.unix_timestamp().saturating_mul(1000)),
    });
    *pending
        .0
        .lock()
        .map_err(|_| "update state unavailable".to_string())? = found;
    Ok(info)
}

/// Download, verify and install the update found by [`update_check`], then
/// restart. On Windows the process exits inside the install step (after the
/// `on_before_exit` hook) and the installer relaunches the app.
#[cfg(not(any(target_os = "android", target_os = "ios")))]
#[tauri::command]
pub async fn update_install(
    app: tauri::AppHandle,
    pending: tauri::State<'_, PendingUpdate>,
) -> Result<(), String> {
    let update = pending
        .0
        .lock()
        .map_err(|_| "update state unavailable".to_string())?
        .take()
        .ok_or_else(|| "Check for updates first.".to_string())?;
    update
        .download_and_install(|_, _| {}, || {})
        .await
        .map_err(|e| format!("The update could not be installed: {e}"))?;
    // macOS / Linux replace the bundle in place and return here.
    stop_service_for_update();
    app.restart();
}

#[cfg(any(target_os = "android", target_os = "ios"))]
const ON_MOBILE: &str = "Install new versions from the releases page or your app store.";

/// Mobile: no in-app updater.
#[cfg(any(target_os = "android", target_os = "ios"))]
#[tauri::command]
pub async fn update_check() -> Result<Option<UpdateInfoView>, String> {
    Err(ON_MOBILE.into())
}

/// Mobile: no in-app updater.
#[cfg(any(target_os = "android", target_os = "ios"))]
#[tauri::command]
pub async fn update_install() -> Result<(), String> {
    Err(ON_MOBILE.into())
}
