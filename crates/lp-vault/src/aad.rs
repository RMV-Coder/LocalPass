//! AAD (Additional Authenticated Data) construction — the fixed cross-crate
//! encoding from `LESSONS.md`.
//!
//! Every ciphertext blob in LocalPass binds an AAD string that is reconstructed
//! at decrypt time and never stored on disk (vault-format.md §2/§3). The
//! encoding is a **fixed contract** (LESSONS.md 2026-07-04):
//!
//! - components are joined by a single `|` (U+007C);
//! - purpose **labels** appear verbatim (e.g. `localpass/v1/wrap/item-key`);
//! - **ids** (UUIDs) are rendered as 32-char **lowercase hex, no hyphens**;
//! - **integers** (versions, generations, seq) are **decimal ASCII**.
//!
//! The whole thing is UTF-8. Because ids and integers have fixed, delimiter-free
//! renderings and the `|` separator never appears inside a component, the
//! joined string is unambiguous without length-prefix framing.
//!
//! This module is the single source of truth for those strings, so the AAD used
//! by the account store and the vault file can never drift apart. Each helper
//! corresponds to exactly one row in the vault-format.md §2/§3 AAD tables.

use crate::ids::Id;

/// Render a 16-byte id as 32 lowercase hex chars with no hyphens (AAD contract).
#[must_use]
pub fn id_hex(id: &Id) -> String {
    let mut s = String::with_capacity(32);
    for b in id.as_bytes() {
        // Two lowercase hex nibbles per byte; no separators.
        s.push(char::from_digit((b >> 4) as u32, 16).unwrap());
        s.push(char::from_digit((b & 0x0f) as u32, 16).unwrap());
    }
    s
}

// --- Account-store AADs (vault-format.md §2) -------------------------------

/// `wrapped_account_key.envelope` — wrapped under the MUK.
#[must_use]
pub fn account_key() -> Vec<u8> {
    b"localpass/v1/wrap/account-key".to_vec()
}

/// `device_identity.ed25519_priv_env` — wrapped under the AccountKey.
#[must_use]
pub fn device_ed25519(device_id: &Id) -> Vec<u8> {
    join(&["localpass/v1/wrap/device-ed25519", &id_hex(device_id)])
}

/// `device_identity.x25519_priv_env` — wrapped under the AccountKey.
#[must_use]
pub fn device_x25519(device_id: &Id) -> Vec<u8> {
    join(&["localpass/v1/wrap/device-x25519", &id_hex(device_id)])
}

/// `vault_registry.name_env` — wrapped under the AccountKey.
#[must_use]
pub fn vault_name(vault_id: &Id) -> Vec<u8> {
    join(&["localpass/v1/meta/vault-name", &id_hex(vault_id)])
}

/// `vault_registry.wrapped_vault_key` — wrapped under the AccountKey.
#[must_use]
pub fn vault_key(vault_id: &Id) -> Vec<u8> {
    join(&["localpass/v1/wrap/vault-key", &id_hex(vault_id)])
}

/// `settings.value_env` — wrapped under the AccountKey.
#[must_use]
pub fn setting(key: &str) -> Vec<u8> {
    join(&["localpass/v1/meta/setting", key])
}

// --- Cross-device key-share AADs (PRD §4.5, sync keys/ channel) ------------

/// A VaultKey sealed to a peer device's X25519 key for cross-device sharing.
/// Binds the vault AND the intended recipient so a sealed key cannot be
/// replayed for a different vault or presented to a different device.
#[must_use]
pub fn share_vault_key(vault_id: &Id, recipient_device: &Id) -> Vec<u8> {
    join(&[
        "localpass/v1/share/vault-key",
        &id_hex(vault_id),
        &id_hex(recipient_device),
    ])
}

/// The vault's display name sealed alongside the shared VaultKey (the peer
/// needs it for its own registry entry; names are never plaintext on the
/// sync channel).
#[must_use]
pub fn share_vault_name(vault_id: &Id, recipient_device: &Id) -> Vec<u8> {
    join(&[
        "localpass/v1/share/vault-name",
        &id_hex(vault_id),
        &id_hex(recipient_device),
    ])
}

// --- Vault-file AADs (vault-format.md §3) ----------------------------------

/// `wrapped_keys.envelope` — ItemKey wrapped under the VaultKey.
#[must_use]
pub fn item_key(vault_id: &Id, item_id: &Id, version: i64) -> Vec<u8> {
    join(&[
        "localpass/v1/wrap/item-key",
        &id_hex(vault_id),
        &id_hex(item_id),
        &version.to_string(),
    ])
}

/// `item_versions.payload_env` — canonical payload encrypted under the ItemKey.
#[must_use]
pub fn item_payload(vault_id: &Id, item_id: &Id, version: i64) -> Vec<u8> {
    join(&[
        "localpass/v1/item/payload",
        &id_hex(vault_id),
        &id_hex(item_id),
        &version.to_string(),
    ])
}

/// `folders.name_env` — folder name encrypted under the VaultKey.
#[must_use]
pub fn folder_name(vault_id: &Id, folder_id: &Id) -> Vec<u8> {
    join(&[
        "localpass/v1/meta/folder-name",
        &id_hex(vault_id),
        &id_hex(folder_id),
    ])
}

/// `attachments.wrapped_key_env` — the per-attachment key wrapped under the
/// owning item's ItemKey (vault-format.md §3).
#[must_use]
pub fn attachment_key(vault_id: &Id, attachment_id: &Id) -> Vec<u8> {
    join(&[
        "localpass/v1/wrap/attachment-key",
        &id_hex(vault_id),
        &id_hex(attachment_id),
    ])
}

/// `attachments.filename_env` — the attachment filename sealed under the owning
/// item's ItemKey (vault-format.md §3).
#[must_use]
pub fn attachment_name(vault_id: &Id, attachment_id: &Id) -> Vec<u8> {
    join(&[
        "localpass/v1/meta/attachment-name",
        &id_hex(vault_id),
        &id_hex(attachment_id),
    ])
}

/// The on-disk attachment blob — ciphertext encrypted under the per-attachment
/// key (vault-format.md §3). Binds the vault + attachment id so a blob cannot be
/// relocated to a different attachment or vault.
#[must_use]
pub fn attachment_blob(vault_id: &Id, attachment_id: &Id) -> Vec<u8> {
    join(&[
        "localpass/v1/attachment/blob",
        &id_hex(vault_id),
        &id_hex(attachment_id),
    ])
}

/// `ops.payload_env` — op payload encrypted under the VaultKey.
#[must_use]
pub fn op_payload(vault_id: &Id, op_id: &Id) -> Vec<u8> {
    join(&["localpass/v1/op/payload", &id_hex(vault_id), &id_hex(op_id)])
}

/// `index_segments.payload_env` — an index segment encrypted under the IndexKey
/// (vault-format.md §3; search-index.md §1). Binding `generation` means a stale
/// segment ciphertext cannot be replayed as current: the AEAD tag fails against
/// the current generation's AAD.
#[must_use]
pub fn index_segment(vault_id: &Id, segment_id: i64, generation: u64) -> Vec<u8> {
    join(&[
        "localpass/v1/index/segment",
        &id_hex(vault_id),
        &segment_id.to_string(),
        &generation.to_string(),
    ])
}

/// Join AAD components with a single `|` and return UTF-8 bytes.
fn join(parts: &[&str]) -> Vec<u8> {
    parts.join("|").into_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn id_hex_is_32_lowercase_no_hyphens() {
        let id = Id::from_bytes([0xAB; 16]);
        let hex = id_hex(&id);
        assert_eq!(hex.len(), 32);
        assert_eq!(hex, "abababababababababababababababab");
        assert!(!hex.contains('-'));
        assert_eq!(hex, hex.to_lowercase());
    }

    #[test]
    fn components_join_with_single_pipe() {
        let v = Id::from_bytes([0x11; 16]);
        let i = Id::from_bytes([0x22; 16]);
        let aad = String::from_utf8(item_payload(&v, &i, 7)).unwrap();
        assert_eq!(
            aad,
            "localpass/v1/item/payload|11111111111111111111111111111111|22222222222222222222222222222222|7"
        );
    }

    #[test]
    fn integers_are_decimal_ascii() {
        let v = Id::from_bytes([0u8; 16]);
        let i = Id::from_bytes([0u8; 16]);
        let aad = String::from_utf8(item_key(&v, &i, 123)).unwrap();
        assert!(aad.ends_with("|123"));
    }

    #[test]
    fn attachment_aads_are_distinct_and_well_formed() {
        let v = Id::from_bytes([0x11; 16]);
        let a = Id::from_bytes([0x22; 16]);
        let key = String::from_utf8(attachment_key(&v, &a)).unwrap();
        let name = String::from_utf8(attachment_name(&v, &a)).unwrap();
        let blob = String::from_utf8(attachment_blob(&v, &a)).unwrap();
        assert_eq!(
            key,
            "localpass/v1/wrap/attachment-key|11111111111111111111111111111111|22222222222222222222222222222222"
        );
        assert_eq!(
            name,
            "localpass/v1/meta/attachment-name|11111111111111111111111111111111|22222222222222222222222222222222"
        );
        assert_eq!(
            blob,
            "localpass/v1/attachment/blob|11111111111111111111111111111111|22222222222222222222222222222222"
        );
        // The three purposes must never collide with one another.
        assert_ne!(attachment_key(&v, &a), attachment_name(&v, &a));
        assert_ne!(attachment_key(&v, &a), attachment_blob(&v, &a));
        assert_ne!(attachment_name(&v, &a), attachment_blob(&v, &a));
        // Different attachment id → different AAD (anti-cut-and-paste).
        let a2 = Id::from_bytes([0x33; 16]);
        assert_ne!(attachment_key(&v, &a), attachment_key(&v, &a2));
    }

    #[test]
    fn distinct_rows_yield_distinct_aad() {
        let v = Id::from_bytes([1u8; 16]);
        let i = Id::from_bytes([2u8; 16]);
        // Same item, different version → different AAD (anti-cut-and-paste).
        assert_ne!(item_payload(&v, &i, 1), item_payload(&v, &i, 2));
        // Different vault, same item/version → different AAD.
        let v2 = Id::from_bytes([9u8; 16]);
        assert_ne!(item_payload(&v, &i, 1), item_payload(&v2, &i, 1));
    }
}
