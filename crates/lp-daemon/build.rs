//! Windows version metadata for the release daemon.
//!
//! The desktop installers ship this binary beside the app, and release signing
//! (SignPath, see `CODE_SIGNING.md`) only signs files whose product name and
//! version match the release. So when — and only when — a release build sets
//! `LOCALPASS_PRODUCT_VERSION` (the app version; `apps/desktop/scripts/
//! prepare-sidecar.mjs` does), this embeds a VERSIONINFO resource: product
//! "LocalPass", that version, and a file description.
//!
//! Every other build (development, tests, CI, non-Windows targets) is
//! untouched: no resource, no resource compiler needed.

fn main() {
    println!("cargo:rerun-if-env-changed=LOCALPASS_PRODUCT_VERSION");
    let Ok(version) = std::env::var("LOCALPASS_PRODUCT_VERSION") else {
        return;
    };
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("windows") {
        return;
    }
    let numeric = numeric_version(&version);
    let mut res = winresource::WindowsResource::new();
    res.set("ProductName", "LocalPass")
        .set("FileDescription", "LocalPass background service")
        .set("CompanyName", "localpass")
        .set("ProductVersion", &version)
        .set("FileVersion", &version)
        .set("OriginalFilename", "localpass-daemon.exe")
        .set("LegalCopyright", "LocalPass contributors, AGPL-3.0-only")
        .set_version_info(winresource::VersionInfo::PRODUCTVERSION, numeric)
        .set_version_info(winresource::VersionInfo::FILEVERSION, numeric);
    if let Err(e) = res.compile() {
        // A release build asked for metadata, so a missing resource compiler
        // must not pass silently: the signing step would reject the file.
        panic!("could not embed the Windows version resource: {e}");
    }
}

/// `major.minor.patch` packed as the 64-bit VERSIONINFO number (16 bits each,
/// build 0). Non-numeric or missing parts count as 0.
fn numeric_version(v: &str) -> u64 {
    let mut parts = v
        .split(['.', '-', '+'])
        .take(3)
        .map(|p| p.parse::<u64>().unwrap_or(0).min(0xFFFF));
    let major = parts.next().unwrap_or(0);
    let minor = parts.next().unwrap_or(0);
    let patch = parts.next().unwrap_or(0);
    (major << 48) | (minor << 32) | (patch << 16)
}
