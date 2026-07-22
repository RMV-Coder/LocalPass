#![forbid(unsafe_code)]
//! Device-pairing + vault-sync request handlers (sync-protocol.md §5/§6/§7).
//!
//! These are the daemon-side wrappers around the fully-built [`lp_sync`] engine
//! and [`lp_vault::Session`]'s pairing API. The daemon exposes the engine to its
//! clients (the desktop GUI) so a user can link a second device and sync a vault
//! entirely from the GUI — the daemon reimplements **none** of the sync logic.
//!
//! # No secret crosses this surface
//!
//! Device identity strings and fingerprints are **public** (public keys + a
//! BLAKE3 hash). The shared VaultKey is sealed *inside* the engine
//! ([`lp_sync::engine::share_vault_to_device`] / the pull-side unseal), so it
//! never appears in a request or response as plaintext — a `ShareVaultToDevice`
//! request names only a (public) device id. Sync alarms (quarantine/tamper) are
//! rendered to secret-free strings and surfaced, never swallowed.
//!
//! # Fingerprint confirmation is enforced here
//!
//! `trust_device` re-checks the caller-supplied `expected_fingerprint`
//! against the fingerprint it computes from the parsed identity string, and
//! refuses on a mismatch or an empty confirmation. This makes the out-of-band
//! fingerprint comparison a server-side invariant — the UI checkbox is a
//! usability aid, not the security control.
//!
//! # The channel backend is injected, not assumed
//!
//! Every sync handler takes the `&dyn StoreFactory` held by
//! [`crate::engine::State`] and passes it straight to [`lp_sync::engine`]. The
//! daemon's default is the filesystem channel; a host whose user-picked sync
//! root is not a filesystem path supplies its own factory
//! ([`crate::engine::State::set_store_factory`]) without this module changing.
//! The `dir` strings below are the host's **opaque** roots — passed through
//! verbatim, never path-normalized.

use std::collections::BTreeSet;

use lp_sync::engine;
use lp_sync::identity::DeviceIdentity;
use lp_sync::store::StoreFactory;
use lp_vault::ids::{DeviceId, Id};
use lp_vault::{Session, Vault};

use crate::protocol::{Response, WireAdoptedVault, WirePeer, WirePendingDevice, WireSyncDevice};

/// Build a usage-style (non-auth, secret-free) error response.
fn usage(message: impl Into<String>) -> Response {
    Response::Error {
        auth: false,
        message: message.into(),
    }
}

/// Map an [`lp_sync::Error`] to a secret-free daemon error response. Mirrors the
/// CLI's `map_sync_error`: no variant of `lp_sync::Error` carries a secret (op
/// payloads stay ciphertext; a decrypt failure surfaces as a signature alarm or
/// a `Vault(DecryptionFailed)`), so `{e}` is safe to render.
pub(crate) fn map_sync_error(e: lp_sync::Error) -> Response {
    usage(format!("sync error: {e}"))
}

/// Parse a hyphenated/simple UUID device-id string into a [`DeviceId`].
fn parse_device_id(s: &str) -> Result<DeviceId, Response> {
    let hex: String = s.chars().filter(|c| *c != '-').collect();
    if hex.len() != 32 || !hex.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(usage("invalid device id (expected a hyphenated UUID)"));
    }
    let mut bytes = [0u8; 16];
    for (i, b) in bytes.iter_mut().enumerate() {
        *b = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16)
            .map_err(|_| usage("invalid device id (bad hex)"))?;
    }
    Ok(Id::from_bytes(bytes))
}

/// Render a batch of sync quarantines to secret-free alarm strings. Each
/// [`lp_sync::Quarantine`]'s `Display` names the device + seq + alarm reason
/// (never a plaintext value; see `lp_sync::error`).
fn render_alarms(quarantines: &[lp_sync::error::Quarantine]) -> Vec<String> {
    quarantines
        .iter()
        .map(|q| {
            format!(
                "device {} quarantined at seq {} — {}",
                q.device_id.to_hyphenated(),
                q.seq,
                q.alarm
            )
        })
        .collect()
}

/// [`crate::protocol::Request::ExportIdentity`]: this device's public identity.
pub(crate) fn export_identity(session: &Session) -> Result<Response, Response> {
    let info = session.device_public_identity();
    let identity = DeviceIdentity::from(info);
    Ok(Response::DeviceIdentity {
        device_id: info.device_id.to_hyphenated(),
        identity_string: identity.to_export_string(),
        fingerprint: identity.fingerprint(),
    })
}

/// [`crate::protocol::Request::ListPeers`]: the trusted peers, each with the
/// fingerprint computed from its pinned public keys.
pub(crate) fn list_peers(session: &Session) -> Result<Response, Response> {
    let peers = session
        .peer_devices()
        .map_err(|e| usage(format!("could not read trusted devices: {e}")))?;
    let wire = peers
        .into_iter()
        .map(|p| {
            // Compute the peer's fingerprint from its pinned public keys — the
            // exact value the peer would print via export-identity, so the user
            // can cross-check the trusted list against a device on hand.
            let identity = DeviceIdentity {
                device_id: p.device_id,
                ed25519_pub: p.ed25519_pub,
                x25519_pub: p.x25519_pub,
            };
            WirePeer {
                device_id: p.device_id.to_hyphenated(),
                fingerprint: identity.fingerprint(),
                label: p.label,
                verified_at: p.verified_at,
            }
        })
        .collect();
    Ok(Response::Peers { peers: wire })
}

/// [`crate::protocol::Request::TrustDevice`]: parse the identity string,
/// **enforce** the fingerprint confirmation, then pin the peer's keys.
///
/// Security-critical: `expected_fingerprint` MUST be non-empty and equal the
/// fingerprint computed from the parsed identity, or the trust is refused. This
/// is the server-side re-check of the out-of-band confirmation — never
/// auto-trust.
pub(crate) fn trust_device(
    session: &Session,
    identity_string: &str,
    expected_fingerprint: &str,
    label: Option<&str>,
) -> Result<Response, Response> {
    let identity = DeviceIdentity::from_export_string(identity_string)
        .map_err(|_| usage("invalid device identity string"))?;
    let fingerprint = identity.fingerprint();

    // Enforce the fingerprint confirmation server-side. An empty confirmation is
    // refused outright (the caller MUST have shown + confirmed the fingerprint).
    if expected_fingerprint.trim().is_empty() {
        return Err(usage(
            "fingerprint confirmation required — do not trust a device without \
             comparing its fingerprint out-of-band",
        ));
    }
    if !identity.fingerprint_matches(expected_fingerprint) {
        return Err(usage(
            "fingerprint mismatch — do not trust; the confirmed fingerprint does \
             not match the identity string",
        ));
    }

    session
        .trust_peer_device(
            &identity.device_id,
            &identity.ed25519_pub,
            &identity.x25519_pub,
            label,
        )
        .map_err(|e| usage(format!("could not trust the device: {e}")))?;

    Ok(Response::PeerTrusted {
        device_id: identity.device_id.to_hyphenated(),
        fingerprint,
        label: label.map(str::to_string),
    })
}

/// Write (or refresh) this device's channel announce at the sync `root`
/// (`device-pairing.md` §5.1), **best-effort**.
///
/// The announce is advisory (§5.2): it only lets a peer pointed at the same
/// folder surface this device as a *pending* entry — it never pins anything. So
/// a failure here must **not** fail the setup/push that triggered it; pairing
/// still works via QR/paste, and a missing announce just means this device does
/// not auto-appear as pending. Every error is therefore captured and ignored.
///
/// Label is `None` for now: a device self-name is a future nicety; the
/// fingerprint (derived from the identity string) is the real identifier.
///
/// `announced_at` uses the daemon-appropriate wall clock
/// ([`lp_vault::db::now_millis`], the same source the audit log stamps with),
/// coerced to the announce's `u64` millis.
fn write_self_announce(session: &Session, root: &str, factory: &dyn StoreFactory) {
    let identity = DeviceIdentity::from(session.device_public_identity());
    let announced_at = u64::try_from(lp_vault::db::now_millis()).unwrap_or(0);
    // Best-effort: open the channel and write; swallow any error (§5.2 advisory).
    if let Ok(store) = factory.open(root) {
        lp_sync::announce::write_announce(store.as_ref(), &identity, None, announced_at).ok();
    }
}

/// [`crate::protocol::Request::SyncSetup`]: enroll a vault under a shared dir.
pub(crate) fn sync_setup(
    session: &Session,
    vault: &Vault<'_>,
    dir: &str,
    factory: &dyn StoreFactory,
) -> Result<Response, Response> {
    engine::setup(session, vault.vault_id(), dir, factory).map_err(map_sync_error)?;
    // Announce this device on the shared channel (§5.1) so a peer pointed at the
    // same folder can pick it up as a pending device with no typing. Best-effort
    // (§5.2 — advisory), so it never fails the enrollment.
    write_self_announce(session, dir, factory);
    Ok(Response::Ok {
        message: Some("enrolled for sync".into()),
    })
}

/// [`crate::protocol::Request::SyncPush`]: publish this device's ops.
pub(crate) fn sync_push(
    session: &Session,
    vault: &Vault<'_>,
    factory: &dyn StoreFactory,
) -> Result<Response, Response> {
    let report = engine::push(session, vault, factory).map_err(map_sync_error)?;
    // Refresh this device's announce (bumps `announced_at`) on the enrolled root
    // (§5.1). Best-effort (§5.2 — advisory): a failure never fails the push.
    if let Ok(Some(root)) = engine::enrolled_root(session, vault.vault_id()) {
        write_self_announce(session, &root, factory);
    }
    Ok(Response::SyncPushed {
        published: report.published.len(),
        segments_written: report.segments_written,
    })
}

/// [`crate::protocol::Request::SyncPull`]: verify + merge peers' ops.
pub(crate) fn sync_pull(
    session: &Session,
    vault: &Vault<'_>,
    factory: &dyn StoreFactory,
) -> Result<Response, Response> {
    let report = engine::pull(session, vault, factory).map_err(map_sync_error)?;
    Ok(Response::SyncPulled {
        applied: report.applied,
        pending: report.pending,
        key_imported: report.key_imported,
        alarms: render_alarms(&report.quarantines),
    })
}

/// [`crate::protocol::Request::SyncStatus`]: per-device seq marks + counts.
pub(crate) fn sync_status(
    session: &Session,
    vault: &Vault<'_>,
    factory: &dyn StoreFactory,
) -> Result<Response, Response> {
    let st = engine::status(session, vault, factory).map_err(map_sync_error)?;
    let devices = st
        .devices
        .into_iter()
        .map(|d| WireSyncDevice {
            device_id: d.device_id.to_hyphenated(),
            is_self: d.is_self,
            trusted: d.trusted,
            local_seq: d.local_seq,
            channel_seq: d.channel_seq,
        })
        .collect();
    Ok(Response::SyncStatus {
        enrolled: st.enrolled,
        root: st.root,
        devices,
        pending: st.pending,
        alarms: render_alarms(&st.quarantines),
    })
}

/// [`crate::protocol::Request::ShareVaultToDevice`]: seal this vault's key to a
/// trusted peer via the channel. The seal happens inside the engine; only a
/// (public) device id is named here.
pub(crate) fn share_vault_to_device(
    session: &Session,
    vault: &Vault<'_>,
    device_id: &str,
    factory: &dyn StoreFactory,
) -> Result<Response, Response> {
    let peer = parse_device_id(device_id)?;
    engine::share_vault_to_device(session, vault.vault_id(), &peer, factory)
        .map_err(map_sync_error)?;
    Ok(Response::Ok {
        message: Some("vault shared to the device".into()),
    })
}

/// [`crate::protocol::Request::SyncAdopt`]: import vaults shared to this device
/// from `dir`, then pull each so its items materialize.
pub(crate) fn sync_adopt(
    session: &Session,
    dir: &str,
    factory: &dyn StoreFactory,
) -> Result<Response, Response> {
    let adopted = engine::adopt(session, dir, factory).map_err(map_sync_error)?;

    // Resolve names (best-effort) and pull each adopted vault so its items land.
    let names = session.list_vaults().unwrap_or_default();
    let mut wire = Vec::with_capacity(adopted.len());
    let mut applied_total = 0usize;
    let mut alarms = Vec::new();
    for vault_id in adopted {
        let name = names
            .iter()
            .find(|(id, _)| *id == vault_id)
            .map_or_else(String::new, |(_, n)| n.clone());
        let vault = session
            .open_vault(vault_id)
            .map_err(|e| usage(format!("could not open an adopted vault: {e}")))?;
        let report = engine::pull(session, &vault, factory).map_err(map_sync_error)?;
        applied_total += report.applied;
        alarms.extend(render_alarms(&report.quarantines));
        wire.push(WireAdoptedVault {
            vault_id: vault_id.to_hyphenated(),
            name,
        });
    }

    Ok(Response::SyncAdopted {
        adopted: wire,
        applied_total,
        alarms,
    })
}

/// [`crate::protocol::Request::ListPendingDevices`]: the announced-but-untrusted
/// devices under `dir`'s `pairing/` folder (`device-pairing.md` §5).
///
/// Lists the announces (§5.1), then **filters out** (a) this device's own id and
/// (b) every already-trusted peer id, so only genuinely-pending devices remain.
/// Each survivor is rendered with its fingerprint (derived from the parsed
/// identity string) for the out-of-band compare.
///
/// The channel is untrusted (§5.2): this only populates a list — the user still
/// confirms the fingerprint and trusts via [`trust_device`], which is unchanged.
/// An empty/unopenable/not-enrolled `dir` yields an empty list, never an error
/// (the GUI calls this whenever a folder is set).
pub(crate) fn list_pending_devices(
    session: &Session,
    dir: &str,
    factory: &dyn StoreFactory,
) -> Result<Response, Response> {
    // An empty or unopenable root is simply "nothing pending" — not an error.
    if dir.trim().is_empty() {
        return Ok(Response::PendingDevices {
            devices: Vec::new(),
        });
    }
    let Ok(store) = factory.open(dir) else {
        return Ok(Response::PendingDevices {
            devices: Vec::new(),
        });
    };
    // A read failure on the untrusted channel is likewise "nothing pending".
    let Ok(announces) = lp_sync::announce::list_announces(store.as_ref()) else {
        return Ok(Response::PendingDevices {
            devices: Vec::new(),
        });
    };

    // Filter set: this device's own id + every already-trusted peer id.
    let self_id = *session.device_public_identity().device_id.as_bytes();
    let trusted: BTreeSet<[u8; 16]> = session
        .peer_devices()
        .map_err(|e| usage(format!("could not read trusted devices: {e}")))?
        .into_iter()
        .map(|p| *p.device_id.as_bytes())
        .collect();

    let mut devices = Vec::new();
    for a in announces {
        let id_bytes = *a.device_id.as_bytes();
        if id_bytes == self_id || trusted.contains(&id_bytes) {
            continue;
        }
        // Derive the fingerprint from the (already-validated) identity string.
        let Ok(identity) = DeviceIdentity::from_export_string(&a.identity) else {
            continue;
        };
        devices.push(WirePendingDevice {
            device_id: a.device_id.to_hyphenated(),
            identity_string: a.identity,
            fingerprint: identity.fingerprint(),
            label: a.label,
            announced_at: a.announced_at,
        });
    }
    Ok(Response::PendingDevices { devices })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_device_id_accepts_hyphenated_uuid() {
        let id = Id::new();
        let parsed = parse_device_id(&id.to_hyphenated()).ok().unwrap();
        assert_eq!(parsed, id);
    }

    #[test]
    fn parse_device_id_rejects_garbage() {
        assert!(parse_device_id("not-a-uuid").is_err());
        assert!(parse_device_id("").is_err());
    }
}
