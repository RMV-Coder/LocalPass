#![forbid(unsafe_code)]
//! Registering (and unregistering) the native-messaging host with browsers.
//!
//! For a browser to launch `localpass-native-host`, it needs a **native-messaging
//! host manifest**: a small JSON file naming the host (`com.localpass.host`), the
//! absolute path to this binary, `"type": "stdio"`, and the allowlist of
//! extensions permitted to connect (`allowed_origins` for Chrome/Chromium,
//! `allowed_extensions` for Firefox). Where the browser looks for that manifest
//! differs by OS and browser:
//!
//! - **Windows:** the manifest is a JSON file on disk *and* a registry value
//!   under `HKCU\Software\<vendor>\NativeMessagingHosts\com.localpass.host` whose
//!   default value is the manifest's path. Chromium reads
//!   `HKCU\Software\Google\Chrome\NativeMessagingHosts\...`; Firefox reads
//!   `HKCU\Software\Mozilla\NativeMessagingHosts\...`.
//! - **macOS / Linux:** no registry — the browser reads the manifest from a
//!   well-known per-user directory (see [`manifest_dir`]).
//!
//! # Extension id placeholder
//!
//! LocalPass has no published extension id yet, so the manifest uses a documented
//! placeholder ([`PLACEHOLDER_CHROME_EXTENSION_ID`] /
//! [`PLACEHOLDER_FIREFOX_EXTENSION_ID`]), overridable with `--extension-id`. The
//! placeholder is intentionally obvious; a real install passes the published id.
//! The allowlist is the browser-enforced gate on *which* extension may talk to
//! the host, so it must be set correctly for the real extension before shipping.
//!
//! # What this module does and does not touch
//!
//! [`build_manifest`] and the manifest-shape helpers are pure and unit-tested.
//! [`register`]/[`unregister`] perform the filesystem writes and, on Windows, the
//! registry writes. Nothing here reads or writes any secret — a native-messaging
//! manifest is entirely non-sensitive configuration.

use std::path::{Path, PathBuf};

use serde::Serialize;

use crate::error::{Error, Result};

/// The native-messaging host name both browsers key on. Fixed by the extension.
pub const HOST_NAME: &str = "com.localpass.host";

/// The placeholder **Chrome** extension origin baked into a manifest until the
/// real extension is published. Chrome `allowed_origins` entries are of the form
/// `chrome-extension://<32-char-id>/`. The id here is the obvious all-`a`
/// placeholder; override with `--extension-id`.
pub const PLACEHOLDER_CHROME_EXTENSION_ID: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

/// The placeholder **Firefox** extension id (an addon id — an email-like or
/// UUID-in-braces string). Override with `--extension-id`.
pub const PLACEHOLDER_FIREFOX_EXTENSION_ID: &str = "localpass@localpass.dev";

/// Which browser family a registration targets.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Browser {
    /// Chrome / Chromium family (uses `allowed_origins`, `chrome-extension://…`).
    Chrome,
    /// Firefox (uses `allowed_extensions`, an addon id).
    Firefox,
}

impl Browser {
    /// A short lowercase token for messages/paths.
    #[must_use]
    pub fn token(self) -> &'static str {
        match self {
            Browser::Chrome => "chrome",
            Browser::Firefox => "firefox",
        }
    }
}

/// The native-messaging manifest, serialized to the JSON the browser expects.
///
/// Exactly one of `allowed_origins` (Chrome) / `allowed_extensions` (Firefox) is
/// present; `serde` skips the `None` one so the emitted JSON matches each
/// browser's schema.
#[derive(Debug, Serialize, PartialEq, Eq)]
pub struct Manifest {
    /// The host name (`com.localpass.host`).
    pub name: String,
    /// A human description.
    pub description: String,
    /// Absolute path to the `localpass-native-host` binary.
    pub path: String,
    /// Always `"stdio"`.
    #[serde(rename = "type")]
    pub kind: String,
    /// Chrome allowlist: `chrome-extension://<id>/` origins.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub allowed_origins: Option<Vec<String>>,
    /// Firefox allowlist: extension (addon) ids.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub allowed_extensions: Option<Vec<String>>,
}

/// Build the manifest for `browser`, pointing at `host_binary`, allowlisting
/// `extension_id` (a bare id; Chrome wraps it into a `chrome-extension://…/`
/// origin, Firefox uses it verbatim).
#[must_use]
pub fn build_manifest(browser: Browser, host_binary: &Path, extension_id: &str) -> Manifest {
    let common_name = HOST_NAME.to_string();
    let description = "LocalPass browser autofill native-messaging host \
        (fill-scoped bridge to the LocalPass daemon)."
        .to_string();
    let path = host_binary.display().to_string();
    match browser {
        Browser::Chrome => Manifest {
            name: common_name,
            description,
            path,
            kind: "stdio".into(),
            allowed_origins: Some(vec![format!("chrome-extension://{extension_id}/")]),
            allowed_extensions: None,
        },
        Browser::Firefox => Manifest {
            name: common_name,
            description,
            path,
            kind: "stdio".into(),
            allowed_origins: None,
            allowed_extensions: Some(vec![extension_id.to_string()]),
        },
    }
}

/// The default placeholder extension id for `browser` when none is supplied.
#[must_use]
pub fn default_extension_id(browser: Browser) -> &'static str {
    match browser {
        Browser::Chrome => PLACEHOLDER_CHROME_EXTENSION_ID,
        Browser::Firefox => PLACEHOLDER_FIREFOX_EXTENSION_ID,
    }
}

/// The per-user directory a browser reads native-messaging manifests from on the
/// current OS. On Windows the manifest path is arbitrary (the registry points at
/// it); we use a stable per-user LocalPass config dir. On macOS/Linux the browser
/// scans a fixed directory, returned here.
///
/// # Errors
///
/// [`Error::NoConfigDir`] if the platform config/home directory cannot be
/// resolved.
pub fn manifest_dir(browser: Browser) -> Result<PathBuf> {
    #[cfg(windows)]
    {
        // Windows: the file location is our choice; the registry key is the
        // pointer the browser follows. Keep manifests under %APPDATA%\localpass\
        // native-messaging\<browser>\.
        let base = std::env::var_os("APPDATA")
            .map(PathBuf::from)
            .ok_or(Error::NoConfigDir)?;
        Ok(base
            .join("localpass")
            .join("native-messaging")
            .join(browser.token()))
    }
    #[cfg(target_os = "macos")]
    {
        let home = std::env::var_os("HOME")
            .map(PathBuf::from)
            .ok_or(Error::NoConfigDir)?;
        let sub = match browser {
            Browser::Chrome => "Library/Application Support/Google/Chrome/NativeMessagingHosts",
            Browser::Firefox => "Library/Application Support/Mozilla/NativeMessagingHosts",
        };
        Ok(home.join(sub))
    }
    #[cfg(all(unix, not(target_os = "macos")))]
    {
        // Linux/BSD: Chromium reads ~/.config/google-chrome/NativeMessagingHosts;
        // Firefox reads ~/.mozilla/native-messaging-hosts.
        let home = std::env::var_os("HOME")
            .map(PathBuf::from)
            .ok_or(Error::NoConfigDir)?;
        let path = match browser {
            Browser::Chrome => home
                .join(".config")
                .join("google-chrome")
                .join("NativeMessagingHosts"),
            Browser::Firefox => home.join(".mozilla").join("native-messaging-hosts"),
        };
        Ok(path)
    }
}

/// The full path of the manifest file for `browser`.
///
/// # Errors
///
/// [`Error::NoConfigDir`] if the manifest directory cannot be resolved.
pub fn manifest_path(browser: Browser) -> Result<PathBuf> {
    Ok(manifest_dir(browser)?.join(format!("{HOST_NAME}.json")))
}

/// The outcome of a [`register`]/[`unregister`] call, for user-facing reporting.
#[derive(Debug, Clone)]
pub struct Registration {
    /// Which browser.
    pub browser: Browser,
    /// The manifest file written/removed.
    pub manifest_path: PathBuf,
    /// The registry key touched (Windows only), for the report.
    pub registry_key: Option<String>,
    /// The extension id allowlisted.
    pub extension_id: String,
    /// Whether the extension id was the built-in placeholder (a warning cue).
    pub used_placeholder: bool,
}

/// Register the host for `browser`, pointing at `host_binary` and allowlisting
/// `extension_id` (or the placeholder if `None`). Writes the manifest file and,
/// on Windows, the `HKCU\...\NativeMessagingHosts\com.localpass.host` registry
/// value pointing at it.
///
/// # Errors
///
/// [`Error::Io`] on a filesystem failure, [`Error::Registry`] on a Windows
/// registry failure, or [`Error::NoConfigDir`] if the target directory cannot be
/// resolved.
pub fn register(
    browser: Browser,
    host_binary: &Path,
    extension_id: Option<&str>,
) -> Result<Registration> {
    let path = manifest_path(browser)?;
    let mut reg = write_manifest_at(browser, host_binary, extension_id, &path)?;
    reg.registry_key = os::write_registry(browser, &path)?;
    Ok(reg)
}

/// Write the manifest for `browser` to `manifest_path` (creating parents),
/// without touching the registry. The registry step is layered on top by
/// [`register`]; separating it keeps the pure filesystem write unit-testable
/// against an arbitrary path.
///
/// # Errors
///
/// [`Error::Io`] on a filesystem failure or [`Error::Serde`] on a serialization
/// failure.
pub fn write_manifest_at(
    browser: Browser,
    host_binary: &Path,
    extension_id: Option<&str>,
    manifest_path: &Path,
) -> Result<Registration> {
    let used_placeholder = extension_id.is_none();
    let extension_id = extension_id
        .unwrap_or_else(|| default_extension_id(browser))
        .to_string();
    let manifest = build_manifest(browser, host_binary, &extension_id);
    let json = serde_json::to_string_pretty(&manifest).map_err(Error::Serde)?;

    if let Some(parent) = manifest_path.parent() {
        std::fs::create_dir_all(parent).map_err(Error::Io)?;
    }
    std::fs::write(manifest_path, json.as_bytes()).map_err(Error::Io)?;

    Ok(Registration {
        browser,
        manifest_path: manifest_path.to_path_buf(),
        registry_key: None,
        extension_id,
        used_placeholder,
    })
}

/// Unregister the host for `browser`: remove the manifest file and, on Windows,
/// delete the registry value. Missing artifacts are not an error (idempotent).
///
/// # Errors
///
/// [`Error::Io`] on a filesystem failure other than "not found",
/// [`Error::Registry`] on a Windows registry failure, or [`Error::NoConfigDir`].
pub fn unregister(browser: Browser) -> Result<Registration> {
    let path = manifest_path(browser)?;
    match std::fs::remove_file(&path) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(Error::Io(e)),
    }
    let registry_key = os::delete_registry(browser)?;
    Ok(Registration {
        browser,
        manifest_path: path,
        registry_key,
        extension_id: String::new(),
        used_placeholder: false,
    })
}

/// The registry sub-path (under HKCU) a browser reads for native-messaging hosts.
#[must_use]
pub fn registry_subkey(browser: Browser) -> String {
    let vendor = match browser {
        Browser::Chrome => "Google\\Chrome",
        Browser::Firefox => "Mozilla",
    };
    format!("Software\\{vendor}\\NativeMessagingHosts\\{HOST_NAME}")
}

// --- Platform registry effects -------------------------------------------------

#[cfg(windows)]
mod os {
    use super::{Browser, Result, registry_subkey};
    use crate::error::Error;
    use crate::winreg;
    use std::path::Path;

    /// Write `HKCU\<subkey>` default value = the manifest path. Returns the full
    /// key string for the report.
    pub fn write_registry(browser: Browser, manifest_path: &Path) -> Result<Option<String>> {
        let subkey = registry_subkey(browser);
        winreg::set_hkcu_default(&subkey, &manifest_path.display().to_string())
            .map_err(|e| Error::Registry(e.to_string()))?;
        Ok(Some(format!("HKCU\\{subkey}")))
    }

    /// Delete `HKCU\<subkey>` (idempotent: absent is fine).
    pub fn delete_registry(browser: Browser) -> Result<Option<String>> {
        let subkey = registry_subkey(browser);
        winreg::delete_hkcu_key(&subkey).map_err(|e| Error::Registry(e.to_string()))?;
        Ok(Some(format!("HKCU\\{subkey}")))
    }
}

#[cfg(not(windows))]
mod os {
    use super::{Browser, Result};
    use std::path::Path;

    /// No registry on non-Windows: the manifest file alone is the registration.
    pub fn write_registry(_browser: Browser, _manifest_path: &Path) -> Result<Option<String>> {
        Ok(None)
    }

    /// No registry on non-Windows.
    pub fn delete_registry(_browser: Browser) -> Result<Option<String>> {
        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn chrome_manifest_shape() {
        let m = build_manifest(
            Browser::Chrome,
            &PathBuf::from("/opt/localpass/localpass-native-host"),
            "abcd",
        );
        let json = serde_json::to_value(&m).unwrap();
        assert_eq!(json["name"], HOST_NAME);
        assert_eq!(json["type"], "stdio");
        assert_eq!(json["path"], "/opt/localpass/localpass-native-host");
        assert_eq!(json["allowed_origins"][0], "chrome-extension://abcd/");
        // Firefox key must be absent for Chrome.
        assert!(json.get("allowed_extensions").is_none());
    }

    #[test]
    fn firefox_manifest_shape() {
        let m = build_manifest(
            Browser::Firefox,
            &PathBuf::from("/opt/localpass/localpass-native-host"),
            "localpass@localpass.dev",
        );
        let json = serde_json::to_value(&m).unwrap();
        assert_eq!(json["name"], HOST_NAME);
        assert_eq!(json["type"], "stdio");
        assert_eq!(json["allowed_extensions"][0], "localpass@localpass.dev");
        // Chrome key must be absent for Firefox.
        assert!(json.get("allowed_origins").is_none());
    }

    #[test]
    fn default_extension_ids_are_placeholders() {
        assert_eq!(
            default_extension_id(Browser::Chrome),
            PLACEHOLDER_CHROME_EXTENSION_ID
        );
        assert_eq!(
            default_extension_id(Browser::Firefox),
            PLACEHOLDER_FIREFOX_EXTENSION_ID
        );
    }

    #[test]
    fn registry_subkeys_are_under_hkcu_native_messaging_hosts() {
        assert_eq!(
            registry_subkey(Browser::Chrome),
            "Software\\Google\\Chrome\\NativeMessagingHosts\\com.localpass.host"
        );
        assert_eq!(
            registry_subkey(Browser::Firefox),
            "Software\\Mozilla\\NativeMessagingHosts\\com.localpass.host"
        );
    }

    #[test]
    fn write_manifest_at_creates_file_with_expected_contents() {
        // Write to a temp path directly (no process-env mutation, no registry).
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("com.localpass.host.json");
        let host = PathBuf::from(if cfg!(windows) {
            "C:\\Program Files\\LocalPass\\localpass-native-host.exe"
        } else {
            "/opt/localpass/localpass-native-host"
        });

        let reg = write_manifest_at(Browser::Chrome, &host, Some("myextid"), &path).unwrap();
        assert!(reg.manifest_path.exists());
        assert!(!reg.used_placeholder);
        assert_eq!(reg.extension_id, "myextid");
        let contents = std::fs::read_to_string(&reg.manifest_path).unwrap();
        assert!(contents.contains("com.localpass.host"));
        assert!(contents.contains("chrome-extension://myextid/"));
        assert!(contents.contains("\"type\": \"stdio\""));
    }

    #[test]
    fn write_manifest_at_uses_placeholder_when_no_id() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("firefox.json");
        let host = PathBuf::from("/opt/localpass/localpass-native-host");
        let reg = write_manifest_at(Browser::Firefox, &host, None, &path).unwrap();
        assert!(reg.used_placeholder);
        assert_eq!(reg.extension_id, PLACEHOLDER_FIREFOX_EXTENSION_ID);
        let contents = std::fs::read_to_string(&reg.manifest_path).unwrap();
        assert!(contents.contains(PLACEHOLDER_FIREFOX_EXTENSION_ID));
        assert!(contents.contains("allowed_extensions"));
    }

    #[test]
    fn manifest_paths_end_in_host_json() {
        // manifest_path resolves without error on this platform and ends in the
        // host json file name (the directory itself depends on env, but the file
        // name is fixed).
        for b in [Browser::Chrome, Browser::Firefox] {
            if let Ok(p) = manifest_path(b) {
                assert!(p.ends_with("com.localpass.host.json"));
            }
        }
    }
}
