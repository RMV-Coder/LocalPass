//! `localpass browser register|unregister` — browser autofill native-messaging
//! host registration (PRD §4.7 / §6.7).
//!
//! Writes (or removes) the Chrome/Firefox native-messaging host manifest — the
//! JSON that names `com.localpass.host`, the path to the installed
//! `localpass-native-host` binary, `"type": "stdio"`, and the extension
//! allowlist — to the correct per-OS location, plus the `HKCU` registry value on
//! Windows. The heavy lifting (manifest shape, path resolution, registry) lives
//! in [`lp_native_host::register`]; this command owns only argument handling,
//! host-binary resolution, and user-facing reporting.
//!
//! No unlock is required: registration is non-sensitive configuration and touches
//! no vault or key material.

use std::path::PathBuf;

use anyhow::{Result, anyhow};

use lp_native_host::register::{self, Browser, Registration};

use crate::cli::BrowserCommand;
use crate::error::CliError;

/// Run a `localpass browser ...` subcommand.
///
/// # Errors
///
/// [`CliError::Internal`] on a filesystem/registry failure writing or removing a
/// manifest, or [`CliError::Usage`] if the host binary cannot be located.
pub fn run(command: &BrowserCommand) -> Result<()> {
    match command {
        BrowserCommand::Register {
            chrome,
            firefox,
            all,
            extension_id,
            host_path,
        } => register_cmd(
            *chrome,
            *firefox,
            *all,
            extension_id.as_deref(),
            host_path.clone(),
        ),
        BrowserCommand::Unregister {
            chrome,
            firefox,
            all,
        } => unregister_cmd(*chrome, *firefox, *all),
    }
}

/// Resolve which browsers a command targets. With no explicit flag, defaults to
/// all supported browsers (the friendly default). `--all` forces all.
fn targets(chrome: bool, firefox: bool, all: bool) -> Vec<Browser> {
    if all || (!chrome && !firefox) {
        return vec![Browser::Chrome, Browser::Firefox];
    }
    let mut v = Vec::new();
    if chrome {
        v.push(Browser::Chrome);
    }
    if firefox {
        v.push(Browser::Firefox);
    }
    v
}

/// Locate the `localpass-native-host` binary: the explicit `--host-path`, else a
/// sibling of the current `localpass` executable (how an installer lays them out
/// side by side), else a bare-name fallback that resolves via `PATH` at launch.
fn resolve_host_binary(explicit: Option<PathBuf>) -> Result<PathBuf> {
    if let Some(p) = explicit {
        if !p.exists() {
            return Err(CliError::usage(format!(
                "no native-messaging host binary at {}",
                p.display()
            ))
            .into());
        }
        return Ok(p);
    }
    #[cfg(windows)]
    let name = "localpass-native-host.exe";
    #[cfg(not(windows))]
    let name = "localpass-native-host";

    if let Ok(mut cur) = std::env::current_exe() {
        cur.pop();
        let sibling = cur.join(name);
        if sibling.exists() {
            return Ok(sibling);
        }
    }
    // Fall back to the bare name. The browser resolves it via the manifest path
    // literally, so warn the user this is unqualified.
    eprintln!(
        "warning: could not find {name} next to this binary; \
         writing the manifest with a bare name — pass --host-path <PATH> to pin \
         the absolute path the browser will launch."
    );
    Ok(PathBuf::from(name))
}

/// `browser register`.
fn register_cmd(
    chrome: bool,
    firefox: bool,
    all: bool,
    extension_id: Option<&str>,
    host_path: Option<PathBuf>,
) -> Result<()> {
    let host_binary = resolve_host_binary(host_path)?;
    let browsers = targets(chrome, firefox, all);

    for browser in browsers {
        let reg = register::register(browser, &host_binary, extension_id)
            .map_err(|e| CliError::internal(anyhow!("registering {}: {e}", browser.token())))?;
        report_register(&reg);
    }
    println!();
    println!("The extension talks to LocalPass over native messaging (no localhost port).");
    println!("Install the LocalPass browser extension, then use autofill on an explicit gesture.");
    Ok(())
}

/// `browser unregister`.
fn unregister_cmd(chrome: bool, firefox: bool, all: bool) -> Result<()> {
    for browser in targets(chrome, firefox, all) {
        let reg = register::unregister(browser)
            .map_err(|e| CliError::internal(anyhow!("unregistering {}: {e}", browser.token())))?;
        println!("Unregistered {} ({}).", browser.token(), display_path(&reg));
        if let Some(key) = &reg.registry_key {
            println!("  Removed registry key: {key}");
        }
    }
    Ok(())
}

/// Print a clear registration report, including the placeholder warning.
fn report_register(reg: &Registration) {
    println!(
        "Registered {} → {}",
        reg.browser.token(),
        reg.manifest_path.display()
    );
    if let Some(key) = &reg.registry_key {
        println!("  Registry key: {key}");
    }
    println!("  Allowlisted extension id: {}", reg.extension_id);
    if reg.used_placeholder {
        println!(
            "  NOTE: this is a PLACEHOLDER extension id. Re-run with \
             --extension-id <ID> once you have the published extension id, \
             or the browser will refuse the connection."
        );
    }
}

/// The manifest path string for a report line.
fn display_path(reg: &Registration) -> String {
    reg.manifest_path.display().to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_flag_targets_all_browsers() {
        assert_eq!(
            targets(false, false, false),
            vec![Browser::Chrome, Browser::Firefox]
        );
        assert_eq!(
            targets(false, false, true),
            vec![Browser::Chrome, Browser::Firefox]
        );
    }

    #[test]
    fn explicit_flags_select_browsers() {
        assert_eq!(targets(true, false, false), vec![Browser::Chrome]);
        assert_eq!(targets(false, true, false), vec![Browser::Firefox]);
        assert_eq!(
            targets(true, true, false),
            vec![Browser::Chrome, Browser::Firefox]
        );
    }
}
