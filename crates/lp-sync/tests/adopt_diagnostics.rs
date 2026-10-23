//! When adopt finds nothing for this device, its report says why: the folder
//! holds no LocalPass data, the user picked one vault's folder instead of the
//! sync root, or the folder's shares are addressed to a different device.
//!
//! Real profiles run the Argon2id KDF (~1s each), so this is one test.

use lp_sync::engine;
use lp_sync::store::FsStoreFactory;
use lp_vault::AccountStore;

#[test]
fn an_empty_adopt_explains_what_the_folder_holds() {
    let dir_a = tempfile::tempdir().unwrap();
    let (session_a, _) = AccountStore::create(dir_a.path(), "pw-device-a").unwrap();
    let dir_b = tempfile::tempdir().unwrap();
    let (session_b, _) = AccountStore::create(dir_b.path(), "pw-device-b").unwrap();
    let dir_c = tempfile::tempdir().unwrap();
    let (session_c, _) = AccountStore::create(dir_c.path(), "pw-device-c").unwrap();

    let ident_a = session_a.device_public_identity();
    let ident_b = session_b.device_public_identity();
    // A and B trust each other; C trusts A too, but A shares only to B.
    for (session, peer) in [
        (&session_a, &ident_b),
        (&session_b, &ident_a),
        (&session_c, &ident_a),
    ] {
        session
            .trust_peer_device(&peer.device_id, &peer.ed25519_pub, &peer.x25519_pub, None)
            .unwrap();
    }

    let root = tempfile::tempdir().unwrap();
    let root_str = root.path().to_string_lossy().to_string();
    let vault = session_a.create_vault("shared").unwrap();
    engine::setup(&session_a, vault, &root_str, &FsStoreFactory).unwrap();
    engine::share_vault_to_device(&session_a, vault, &ident_b.device_id, &FsStoreFactory).unwrap();

    // C looks in the right folder, but the share is for B.
    let c = engine::adopt_report(&session_c, &root_str, &FsStoreFactory).unwrap();
    assert!(c.adopted.is_empty());
    assert!(c.untrusted_sender.is_empty() && c.rejected.is_empty());
    assert_eq!(c.vault_folders, 1);
    assert_eq!(c.shares_for_other_devices, 1, "the share addressed to B");
    assert!(!c.looks_like_vault_folder);

    // B picks the vault's own folder instead of the sync root.
    let vault_dir = root.path().join(vault.to_hyphenated());
    let inner =
        engine::adopt_report(&session_b, &vault_dir.to_string_lossy(), &FsStoreFactory).unwrap();
    assert!(inner.adopted.is_empty());
    assert_eq!(inner.vault_folders, 0);
    assert!(inner.looks_like_vault_folder);

    // A folder with no LocalPass data at all.
    let empty = tempfile::tempdir().unwrap();
    let none =
        engine::adopt_report(&session_b, &empty.path().to_string_lossy(), &FsStoreFactory).unwrap();
    assert_eq!(none.vault_folders, 0);
    assert!(!none.looks_like_vault_folder);

    // And from the sync root, B adopts it.
    let b = engine::adopt_report(&session_b, &root_str, &FsStoreFactory).unwrap();
    assert_eq!(b.adopted, vec![vault]);
    assert_eq!(b.shares_for_other_devices, 0);
}
