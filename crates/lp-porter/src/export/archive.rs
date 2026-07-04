//! The **age-encrypted archive** — LocalPass's recoverable exit hatch (PRD §6.9).
//!
//! # Format (documented, so users are never locked in)
//!
//! Layered, outermost first:
//!
//! 1. **age** binary encryption, passphrase (scrypt) recipient. The bytes begin
//!    with the age v1 header `age-encryption.org/v1`, so the standalone `age`
//!    tool decrypts them: `age -d archive.age > archive.tar`.
//! 2. A **tar** archive containing a single entry, [`ARCHIVE_ENTRY`]
//!    (`vault.json`): `tar -xf archive.tar` yields `vault.json`.
//! 3. A **JSON** document ([`Archive`]): `{ format, exported_at, vaults: [ {
//!    name, items: [ <ItemPayload> ] } ] }`.
//!
//! So recovery with *only* third-party tools is:
//! `age -d archive.age | tar -xO vault.json` → the plaintext item JSON. That is
//! the entire point: LocalPass's death does not trap the user's data.
//!
//! # Crypto boundary
//!
//! This module uses the `age` crate directly — a **foreign format**, not
//! LocalPass envelope crypto (see the crate docs). It never touches `lp-crypto`.
//!
//! # Passphrase hygiene
//!
//! The passphrase arrives as [`zeroize::Zeroizing<String>`] and is wrapped in
//! `age`'s `SecretString` (itself zeroizing). We never log it, never include it
//! in an error, and never distinguish "wrong passphrase" from "corrupt archive"
//! on decrypt (no oracle) — both collapse to [`PorterError::ArchiveDecrypt`].

use std::io::{Read, Write};

use lp_vault::ItemPayload;
use zeroize::Zeroizing;

use crate::error::{PorterError, Result};
use crate::model::{ARCHIVE_ENTRY, ARCHIVE_FORMAT, Archive, ArchiveVault};

/// Serialize `vaults` into an [`Archive`], tar it, and age-encrypt it with
/// `passphrase`. Returns the archive bytes (age binary format).
///
/// `exported_at` is a unix-millis timestamp stored in the header (informational).
///
/// # Errors
///
/// - [`PorterError::Json`] if the items fail to serialize (should not happen for
///   valid payloads).
/// - [`PorterError::ArchiveEncrypt`] / [`PorterError::Io`] on a tar or age
///   failure.
pub fn encrypt_archive(
    vaults: &[(String, Vec<ItemPayload>)],
    exported_at: i64,
    passphrase: &Zeroizing<String>,
) -> Result<Vec<u8>> {
    // 1. JSON body.
    let archive = Archive::new(
        exported_at,
        vaults
            .iter()
            .map(|(name, items)| ArchiveVault {
                name: name.clone(),
                items: items.clone(),
            })
            .collect(),
    );
    let json = serde_json::to_vec(&archive)?;

    // 2. tar with a single `vault.json` entry. Hold the tar bytes in a zeroizing
    //    buffer since they are plaintext secrets until the age layer wraps them.
    let tar_bytes = build_tar(&json)?;

    // 3. age-encrypt (passphrase / scrypt recipient).
    let secret = age::secrecy::SecretString::from(passphrase.as_str().to_owned());
    let encryptor = age::Encryptor::with_user_passphrase(secret);
    let mut out = Vec::new();
    let mut writer = encryptor
        .wrap_output(&mut out)
        .map_err(|_| PorterError::ArchiveEncrypt)?;
    writer
        .write_all(&tar_bytes)
        .map_err(|_| PorterError::ArchiveEncrypt)?;
    writer.finish().map_err(|_| PorterError::ArchiveEncrypt)?;
    Ok(out)
}

/// Build a tar archive holding `json` as the single [`ARCHIVE_ENTRY`] entry.
fn build_tar(json: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    let mut buf = Zeroizing::new(Vec::new());
    {
        let mut builder = tar::Builder::new(&mut *buf);
        let mut header = tar::Header::new_gnu();
        header.set_size(json.len() as u64);
        header.set_mode(0o600);
        header.set_cksum();
        builder
            .append_data(&mut header, ARCHIVE_ENTRY, json)
            .map_err(PorterError::Io)?;
        builder.finish().map_err(PorterError::Io)?;
    }
    Ok(buf)
}

/// Decrypt an age archive produced by [`encrypt_archive`] (or by the standalone
/// `age` tool over the same tar+JSON body) and parse the [`Archive`].
///
/// # Errors
///
/// - [`PorterError::ArchiveDecrypt`] on a wrong passphrase **or** any corruption
///   (the two are indistinguishable — no oracle).
/// - [`PorterError::Malformed`] if the decrypted body is not our tar+JSON shape
///   or the format tag does not match.
pub fn decrypt_archive(bytes: &[u8], passphrase: &Zeroizing<String>) -> Result<Archive> {
    // 1. age decrypt.
    let decryptor = age::Decryptor::new(bytes).map_err(|_| PorterError::ArchiveDecrypt)?;
    let secret = age::secrecy::SecretString::from(passphrase.as_str().to_owned());
    let identity = age::scrypt::Identity::new(secret);
    let mut reader = decryptor
        .decrypt(std::iter::once(&identity as &dyn age::Identity))
        .map_err(|_| PorterError::ArchiveDecrypt)?;
    let mut tar_bytes = Zeroizing::new(Vec::new());
    reader
        .read_to_end(&mut tar_bytes)
        .map_err(|_| PorterError::ArchiveDecrypt)?;

    // 2. untar the single vault.json entry.
    let json = extract_entry(&tar_bytes)?;

    // 3. parse + validate the format tag.
    let archive: Archive = serde_json::from_slice(&json)?;
    if archive.format != ARCHIVE_FORMAT {
        return Err(PorterError::malformed(
            "archive",
            format!("unexpected format tag (want {ARCHIVE_FORMAT})"),
        ));
    }
    Ok(archive)
}

/// Pull the [`ARCHIVE_ENTRY`] bytes out of a tar buffer.
fn extract_entry(tar_bytes: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    let mut ar = tar::Archive::new(tar_bytes);
    for entry in ar.entries().map_err(PorterError::Io)? {
        let mut entry = entry.map_err(PorterError::Io)?;
        let path = entry.path().map_err(PorterError::Io)?;
        if path.to_string_lossy() == ARCHIVE_ENTRY {
            let mut json = Zeroizing::new(Vec::new());
            entry.read_to_end(&mut json).map_err(PorterError::Io)?;
            return Ok(json);
        }
    }
    Err(PorterError::malformed(
        "archive",
        format!("tar has no {ARCHIVE_ENTRY} entry"),
    ))
}

/// The age v1 binary header magic. The first bytes of any [`encrypt_archive`]
/// output; exposed so callers/tests can assert standalone-age compatibility.
pub const AGE_MAGIC: &[u8] = b"age-encryption.org/v1";

#[cfg(test)]
mod tests {
    use super::*;
    use lp_vault::payload::{EnvEntry, TypeData};
    use lp_vault::{FieldKind, ItemPayload};

    fn pass() -> Zeroizing<String> {
        Zeroizing::new("correct horse battery staple".to_string())
    }

    fn sample_vaults() -> Vec<(String, Vec<ItemPayload>)> {
        let mut login = ItemPayload::new(TypeData::Login { urls: vec![] }, "GitHub");
        crate::import::add_hidden(&mut login, "password", "gh_secret_value");
        let env = ItemPayload::new(
            TypeData::EnvSet {
                entries: vec![EnvEntry {
                    key: "API".into(),
                    value: "xyz".into(),
                }],
            },
            "dev env",
        );
        vec![("personal".to_string(), vec![login, env])]
    }

    #[test]
    fn archive_begins_with_age_magic() {
        let bytes = encrypt_archive(&sample_vaults(), 123, &pass()).unwrap();
        // Standalone-age compatibility: the binary header magic must be present.
        assert!(
            bytes.starts_with(AGE_MAGIC),
            "archive does not start with age v1 magic"
        );
    }

    #[test]
    fn roundtrip_preserves_items_and_secrets() {
        let bytes = encrypt_archive(&sample_vaults(), 999, &pass()).unwrap();
        let archive = decrypt_archive(&bytes, &pass()).unwrap();
        assert_eq!(archive.format, ARCHIVE_FORMAT);
        assert_eq!(archive.exported_at, 999);
        assert_eq!(archive.vaults.len(), 1);
        assert_eq!(archive.vaults[0].name, "personal");
        let items = &archive.vaults[0].items;
        assert_eq!(items.len(), 2);
        assert_eq!(items[0].title, "GitHub");
        // The secret survived the round-trip.
        let pw = items[0]
            .fields
            .iter()
            .find(|f| f.name == "password")
            .unwrap();
        assert_eq!(pw.kind, FieldKind::Hidden);
        assert_eq!(pw.value, "gh_secret_value");
    }

    #[test]
    fn wrong_passphrase_fails_without_oracle() {
        let bytes = encrypt_archive(&sample_vaults(), 1, &pass()).unwrap();
        let wrong = Zeroizing::new("not the passphrase".to_string());
        let err = decrypt_archive(&bytes, &wrong).unwrap_err();
        assert!(matches!(err, PorterError::ArchiveDecrypt));
    }

    #[test]
    fn corrupt_archive_fails_cleanly_no_panic() {
        let mut bytes = encrypt_archive(&sample_vaults(), 1, &pass()).unwrap();
        // Flip bytes in the body.
        let n = bytes.len();
        for b in &mut bytes[n / 2..] {
            *b ^= 0xff;
        }
        let err = decrypt_archive(&bytes, &pass()).unwrap_err();
        assert!(matches!(err, PorterError::ArchiveDecrypt));
    }

    #[test]
    fn garbage_input_is_clean_error() {
        let err = decrypt_archive(b"not an age file at all", &pass()).unwrap_err();
        assert!(matches!(err, PorterError::ArchiveDecrypt));
    }
}
