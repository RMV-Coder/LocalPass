//! `localpass device export-identity|trust` — device pairing groundwork
//! (sync-protocol.md §6, Part D). Full live mDNS/SAS pairing is a later wave;
//! these commands exchange identity strings out-of-band and pin the peer's keys.

use std::io::{IsTerminal, Write};
use std::path::Path;

use anyhow::{Result, bail};
use serde_json::json;

use crate::cli::DeviceCommand;
use crate::error::CliError;
use crate::unlock::{self, PasswordSource};

use lp_sync::identity::DeviceIdentity;

/// Run a `localpass device ...` subcommand.
///
/// # Errors
///
/// Propagates unlock and storage failures.
pub fn run(profile_dir: &Path, src: PasswordSource, command: &DeviceCommand) -> Result<()> {
    let (session, _sk) = unlock::unlock(profile_dir, src)?;
    match command {
        DeviceCommand::ExportIdentity { json } => export_identity(&session, *json),
        DeviceCommand::Trust {
            identity,
            label,
            fingerprint,
        } => trust(
            &session,
            identity,
            label.as_deref(),
            fingerprint.as_deref(),
            src,
        ),
    }
}

/// `device export-identity` — print this device's identity string + fingerprint.
fn export_identity(session: &lp_vault::Session, json_out: bool) -> Result<()> {
    let info = session.device_public_identity();
    let identity = DeviceIdentity::from(info);
    let string = identity.to_export_string();
    let fingerprint = identity.fingerprint();

    if json_out {
        println!(
            "{}",
            serde_json::to_string_pretty(&json!({
                "device_id": info.device_id.to_hyphenated(),
                "identity": string,
                "fingerprint": fingerprint,
            }))?
        );
    } else {
        println!("Device id:   {}", info.device_id.to_hyphenated());
        println!("Identity:    {string}");
        println!("Fingerprint: {fingerprint}");
        println!();
        println!("Share the identity string with your other device, then run there:");
        println!("  localpass device trust <identity> --fingerprint {fingerprint}");
    }
    Ok(())
}

/// `device trust` — pin a peer's keys after confirming its fingerprint.
fn trust(
    session: &lp_vault::Session,
    identity_str: &str,
    label: Option<&str>,
    fingerprint: Option<&str>,
    src: PasswordSource,
) -> Result<()> {
    let identity = DeviceIdentity::from_export_string(identity_str)
        .map_err(|e| CliError::usage(format!("bad identity string: {e}")))?;
    let fp = identity.fingerprint();

    // Confirm the fingerprint: --fingerprint for non-interactive, else prompt.
    match fingerprint {
        Some(candidate) => {
            if !identity.fingerprint_matches(candidate) {
                bail!(CliError::usage(format!(
                    "fingerprint mismatch: you provided {candidate:?} but the identity's is {fp:?}"
                )));
            }
        }
        None => confirm_fingerprint(&identity.device_id, &fp, src)?,
    }

    session
        .trust_peer_device(
            &identity.device_id,
            &identity.ed25519_pub,
            &identity.x25519_pub,
            label,
        )
        .map_err(crate::error::map_vault_error)?;
    println!(
        "trusted device {} (fingerprint {fp})",
        identity.device_id.to_hyphenated()
    );
    Ok(())
}

/// Interactively show the fingerprint and require the user to type 'yes'.
fn confirm_fingerprint(
    device_id: &lp_vault::DeviceId,
    fingerprint: &str,
    src: PasswordSource,
) -> Result<()> {
    if src.no_input {
        bail!(CliError::usage(
            "refusing to trust a device under --no-input without --fingerprint <fp> confirmation"
        ));
    }
    if !std::io::stdin().is_terminal() {
        bail!(CliError::usage(
            "not a terminal; confirm non-interactively with --fingerprint <fp>"
        ));
    }
    println!("About to trust device {}", device_id.to_hyphenated());
    println!("Its fingerprint is:  {fingerprint}");
    println!("Confirm this EXACTLY matches what the other device shows.");
    print!("Trust this device? [type 'yes'] ");
    std::io::stdout().flush()?;
    let mut line = String::new();
    std::io::stdin().read_line(&mut line)?;
    if !line.trim().eq_ignore_ascii_case("yes") {
        bail!(CliError::usage("aborted (you did not type 'yes')"));
    }
    Ok(())
}
