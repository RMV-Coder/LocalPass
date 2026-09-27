//! Vault-key shares must come from a device the recipient pinned.
//!
//! The sync folder is untrusted (sync-protocol.md §8), and a device's public
//! identity is public by design. Before shares were signed, anyone who could
//! write the folder and knew the recipient's identity could plant a vault key
//! of their choosing (or swap a genuine one before adoption); items the victim
//! then saved there were encrypted to the attacker's key.
//!
//! Three real profiles: A (trusted by B), M (never trusted by B), and B. Real
//! `AccountStore::create` runs the Argon2id KDF, so everything shares one test.

use lp_sync::engine;
use lp_sync::store::FsStoreFactory;
use lp_vault::{AccountStore, Error};

#[test]
fn only_shares_signed_by_a_pinned_device_are_adopted() {
    let dir_a = tempfile::tempdir().unwrap();
    let (session_a, _) = AccountStore::create(dir_a.path(), "pw-device-a").unwrap();
    let dir_b = tempfile::tempdir().unwrap();
    let (session_b, _) = AccountStore::create(dir_b.path(), "pw-device-b").unwrap();
    let dir_m = tempfile::tempdir().unwrap();
    let (session_m, _) = AccountStore::create(dir_m.path(), "pw-attacker").unwrap();

    let ident_a = session_a.device_public_identity();
    let ident_b = session_b.device_public_identity();
    // A and B trust each other (the fingerprint ceremony).
    session_a
        .trust_peer_device(
            &ident_b.device_id,
            &ident_b.ed25519_pub,
            &ident_b.x25519_pub,
            Some("b"),
        )
        .unwrap();
    session_b
        .trust_peer_device(
            &ident_a.device_id,
            &ident_a.ed25519_pub,
            &ident_a.x25519_pub,
            Some("a"),
        )
        .unwrap();
    // M only knows B's PUBLIC identity (public by design). B never trusts M.
    session_m
        .trust_peer_device(
            &ident_b.device_id,
            &ident_b.ed25519_pub,
            &ident_b.x25519_pub,
            Some("victim"),
        )
        .unwrap();

    let root = tempfile::tempdir().unwrap();
    let root_str = root.path().to_string_lossy().to_string();

    // A shares a genuine vault to B.
    let genuine = session_a.create_vault("genuine").unwrap();
    engine::setup(&session_a, genuine, &root_str, &FsStoreFactory).unwrap();
    engine::share_vault_to_device(&session_a, genuine, &ident_b.device_id, &FsStoreFactory)
        .unwrap();

    // M plants a vault whose key M chose, addressed to B, in the same folder.
    let planted = session_m.create_vault("looks-legit").unwrap();
    engine::setup(&session_m, planted, &root_str, &FsStoreFactory).unwrap();
    engine::share_vault_to_device(&session_m, planted, &ident_b.device_id, &FsStoreFactory)
        .unwrap();

    // --- adopt: the genuine share is adopted, the planted one refused --------
    let report = engine::adopt_report(&session_b, &root_str, &FsStoreFactory).unwrap();
    assert_eq!(report.adopted, vec![genuine], "only A's vault is adopted");
    assert_eq!(
        report.rejected.len(),
        1,
        "M's share is refused: {:?}",
        report.rejected
    );
    assert_eq!(report.rejected[0].0, planted);
    assert!(
        report.rejected[0].1.contains("not trusted"),
        "the reason names the untrusted sender: {}",
        report.rejected[0].1
    );
    let b_vaults: Vec<_> = session_b
        .list_vaults()
        .unwrap()
        .into_iter()
        .map(|(id, _)| id)
        .collect();
    assert!(b_vaults.contains(&genuine));
    assert!(!b_vaults.contains(&planted), "nothing from M was imported");

    // The plain `adopt` wrapper agrees, and a re-run is a clean no-op for the
    // adopted vault while M's share stays refused.
    let again = engine::adopt_report(&session_b, &root_str, &FsStoreFactory).unwrap();
    assert!(again.adopted.is_empty());
    assert_eq!(again.rejected.len(), 1);

    // --- blob-level checks ------------------------------------------------------
    let second = session_a.create_vault("second").unwrap();
    let peer_b = session_a.peer_device(&ident_b.device_id).unwrap().unwrap();
    let blob = session_a.share_vault_key_to_peer(&second, &peer_b).unwrap();
    assert_eq!(&blob[..4], b"LPS2", "new shares are the signed format");

    // Old, unsigned format (the same sealed segments without magic, sender and
    // signature) is refused.
    let legacy = &blob[4 + 16..blob.len() - 64];
    let err = session_b
        .import_shared_vault_key(&second, legacy)
        .unwrap_err();
    assert!(
        matches!(err, Error::Invalid(msg) if msg.contains("unsigned")),
        "{err}"
    );

    // A flipped signature bit fails verification.
    let mut tampered = blob.clone();
    *tampered.last_mut().unwrap() ^= 0x01;
    let err = session_b
        .import_shared_vault_key(&second, &tampered)
        .unwrap_err();
    assert!(matches!(err, Error::DecryptionFailed), "{err}");

    // A's valid signature is bound to the vault id: replaying the blob under a
    // different vault id fails.
    let other_vault = session_a.create_vault("other").unwrap();
    let err = session_b
        .import_shared_vault_key(&other_vault, &blob)
        .unwrap_err();
    assert!(matches!(err, Error::DecryptionFailed), "{err}");

    // And the untampered blob imports fine.
    assert!(session_b.import_shared_vault_key(&second, &blob).unwrap());
}
